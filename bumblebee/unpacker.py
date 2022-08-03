import os
from time import time
import sys
import lzw
import hashlib
import argparse
import traceback
import csv 

from pathlib import Path
from types import MethodType
from binascii import hexlify, unhexlify
from unicorn.x86_const import *

import speakeasy.winenv.arch as e_arch
repo_root = Path(os.path.realpath(__file__)).parent.parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)
from utils import *

sys.path.append(os.path.join(repo_root, 'speakeasy-unpacker'))
print(os.path.join(repo_root, 'speakeasy-unpacker'))
from unpack import Unpacker

#import faulthandler
#faulthandler.enable()


def parse_args():
    usage = "unpack.py [OPTION]... [FILES]..."
    parser = argparse.ArgumentParser(description=usage)
    parser.add_argument("-C", "--config", action="store", default=None,
      help="config file. Defaults to config.yml in same dir as unpack.py")
    parser.add_argument("-r", "--reg", dest='trace_regs', help="Dump register values with trace option", action='store_true', default=False)
    parser.add_argument("-t", "--trace", help="Enable full trace", action='store_true', default=False)
    parser.add_argument("-T", "--timeout", help="timeout", default=None, type=int)
    parser.add_argument("-d", "--dump", dest='dump_dir', help="directory to dump memory regions and logs to", default=None)
    parser.add_argument("-E", "--export", help="If file is a dll run only dllmain and specified export, otherwise default to all exports", action='store', default=None)
    parser.add_argument("-c", "--csv", help="append data about unpacked files to csv", action='store', default=None)
    #parser.add_argument("-y", "--yara", help="Report new yara results from dumped files", default=False, action="store_true")
    parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    parser.add_argument('files', nargs='*')
    return parser.parse_args()

def lzw_decompress(ciphertext, width):
    return b''.join(lzw.decompress(ciphertext, width))


def ignore_read_errors(self, emu, address, size, value, ctx):
    #Just map some memory into place
    emu.mem_map(size, address)
    return True

def read_csv(path):
    if not path or not os.path.exists(path):
        return {}
    processed = {}
    fieldnames = ['extracted_md5', 'extracted_compile_time', 'extracted_arch', 'parent_md5', 'parent_compile_time', 'child_arch', 'xor_key', 'lzw width', 'yara_matches']
    with open(path, 'r') as fp:
        reader = csv.DictReader(fp, fieldnames=fieldnames)
        next(reader, None)  # skip the headers
        for row in reader:
            processed[row['parent_md5']] = True
    return processed


class Block:
    def __init__(self, rva, data, xor_key, sub_key, bits):
        self.rva = rva
        self.data = data
        self.xor_key = xor_key
        self.sub_key = sub_key
        self.bits = bits
        self.plaintext = None
        self.decrypt()

    def decrypt(self):
        self.plaintext = bytearray(len(self.data))
        for i in range(len(self.data)):
            self.plaintext[i] = (self.data[i] - self.sub_key) % 0x100
            self.plaintext[i] = (self.plaintext[i] ^ self.xor_key) # & 0x1F

        self.pack_bits()

    def pack_bits(self):
        data = [b & (2**self.bits -1) for b in self.plaintext]
        bits = ''.join([f'{b:0{self.bits}b}' for b in data])
        self.plaintext = bytearray([int(bits[i:i+8],2) for i in range(0,len(bits),8)])

    def __repr__(self):
        return f'RVA: 0x{self.rva:08X}, size: 0x{len(self.data):08X}, xor key: 0x{self.xor_key:02X}, sub key: 0x{self.sub_key:02X}, bits: {self.bits}, ciphertext: {hexlify(self.data[:8])}... plaintext: {hexlify(self.plaintext[:8])}...'
        
    def __str__(self):
        return self.__repr__()
                
class BumbleBeeUnpacker(Unpacker):
    
    def __init__(self, path, config_path, **kwargs):
        super(BumbleBeeUnpacker, self).__init__(path, config_path, **kwargs)
        self.blocks = []
        self.carved_pes = []
        self.functions = {}
        self.md5 = hashlib.md5(self.data).hexdigest()
        self.logger = logging.getLogger(f'Unpacker.{self.md5}')
        if not self.set_export():
            self.logger.warning(f'Failed to find last export function. Defaulting to calling all of them')



    def set_export(self):
        """
        Samples have a variable number of junk exported functions, but the one we care about always looks like this at it's entry (for x64):
        00007FFEA598A7EC | 48:83EC 28                         | sub rsp,28                                          *only present sometimes
        00007FFEB8FF7B44 | B9 0E9E7CCF                        | mov ecx,CF7C9E0E
        00007FFEB8FF7B49 | E9 529FFEFF                        | jmp 06f4384757e9fb909e83bd8a71213a27.7FFEB8FE1AA0

        """
        if self.export:
            return
        try:
            if self.arch == e_arch.ARCH_X86:
                last = self.pe.DIRECTORY_ENTRY_EXPORT.symbols[0]
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name.decode() == 'DllInstall':
                        self.export = exp.name.decode()
                        return True
                    if exp.name.decode() == 'DllRegisterServer':
                        self.export = exp.name.decode()
                        return True
                    if exp.ordinal > last.ordinal:
                        last = exp
                self.export = last.name.decode()
                self.logger.info(f'Using export: {self.export}')
                return True
            else:
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    entry = self.pe.get_offset_from_rva(exp.address)
                    if self.data[entry] == 0xB9 and self.data[entry+5] in  [0xE8, 0xE9] or self.data[entry+4] == 0xB9 and self.data[entry+9] in [0xE8, 0xE9]:
                        self.export = exp.name.decode()
                        self.logger.info(f'Using export: {self.export}')
                        return True
                return False
                
        except Exception as e:
            print(traceback.format_exc())


    def run(self, begin=None, end=None, timeout=0, count=0):
        self.apply_patches()

        module = self.load_module(self.path)

        # since we're nop'ing out some long running functions, we may run into read errors later 
        # when accessing pointers allocated/written by the patched functions. We need to patch this to ignore the read errors
        self.emu._handle_invalid_read = MethodType(ignore_read_errors, self.emu)

        self.emu.timeout = self.timeout
        self.emu.started = time()
        self.emu.max_api_count = 10**6
        self.emu.api_counts = {}
        self.emu.api_log_max = 100
 
        try:
            #DllMain should be called first
            try:
                self.logger.info('Calling DllMain')
                self.run_module(module)
            except Exception as e:
                self.logger.error('DllMain crashed: {}'.format(e))
                self.logger.warning(traceback.format_exc())
            # Set up some args for the export
            args = [0,1,0,0,0,0,0,0]
            if self.export:
                exports = [exp for exp in module.get_exports() if exp.name == self.export]
            else:
                exports = module.get_exports()

            if not exports:
                self.logger.error(f'Unable to find export {self.export}')
                return
            for exp in exports:
                try:
                    self.logger.info('Calling Export {}: {:08X}'.format(exp.name, exp.address))
                    self.call(exp.address, args)
                except Exception as e:
                    self.logger.error('Program Crashed: {}'.format(e))
                    self.logger.warning(traceback.format_exc())
                    continue

        except Exception as e:
            self.logger.error('Program Crashed: {}'.format(e))
            self.logger.error(traceback.format_exc())


    def write_csv(self, path):

        if not path:
            return
        block_info = [str(block) for block in self.blocks]
        if not os.path.exists(path):
            with open(path, 'w') as fp:
                writer = csv.writer(fp)
                writer.writerow(['extracted_md5', 'extracted_compile_time', 'extracted_arch', 'parent_md5', 'parent_compile_time', 'child_arch', 'xor_key', 'lzw width', 'yara_matches'])
        with open(path, 'a') as fp:
            writer = csv.writer(fp)
            for pe in self.carved_pes:
                yara_matches = filter_matches(self.yarascan(pe['data']), 'dummy name')
                if self.arch == e_arch.ARCH_X86:
                    parent_arch = 'x86'
                else:
                    parent_arch = 'x64'

                _pe = pefile.PE(data=pe['data']) 
                if self.arch == e_arch.ARCH_X86:
                    parent_arch = 'x64'
                else:
                    parent_arch = 'x86'
                if self.pe.FILE_HEADER.Machine == 0x014c:
                    child_arch = "x86"
                if self.pe.FILE_HEADER.Machine == 0x8664:
                    child_arch = "x64" 
                try:
                    parent_compile = get_compile_time(self.pe)
                except Exception as e:
                    self.logger.error(f'Failed to get compilation time for self: {e}')
                    parent_compile = 'unknown'
                try:

                    child_compile = get_compile_time(_pe)
                except Exception as e:
                    self.logger.error(f'Failed to get compilation time for child file: {e}')
                    child_compile = 'unknown'
                pe_md5 = hashlib.md5(pe['data']).hexdigest()
                writer.writerow([pe_md5, child_compile, child_arch, self.md5, parent_compile, parent_arch, hexlify(self.key).decode(), self.lzw_width, yara_matches])
    
    def yarascan(self, data):
        if self.yara_rules:
            matches = self.yara_rules.match(data=data)
            matches = [match for match in self.yara_rules.match(data=data) if match.rule not in self.initial_matches] 
            return matches
                

    def dump(self, data):
        found_pe = False
        self.carved_pes = carve(data, match_at_start=True)
        path = os.path.join(self.dump_dir, f'{self.md5}.dmp')
        self.logger.info(f'writing output to {path}')
        with open(path, 'wb') as fp:
            fp.write(data)
        if self.carved_pes:
            self.logger.info(f'Found {len(self.carved_pes)} PE files')
        for pe in self.carved_pes:
            md5 = hashlib.md5(pe['data']).hexdigest()
            path = os.path.join(self.dump_dir, f'{md5}_{pe["offset"]:X}-{pe["offset"]+len(pe["data"]):X}.{pe["ext"]}')
            self.logger.info(f'[!]\tDumping carved PE file to {path}')
            found_pe = True
            with open(path, 'wb') as fp:
                fp.write(pe["data"])
        

    def extract_payload(self):
        self.logger.info(f'Extracting payload from {len(self.blocks)} blocks')
        ct = b''
        for block in self.blocks:
            self.logger.debug(block)
            ct += block.plaintext

        self.key, self.lzw_width = self.get_key_and_width(self.blocks[0].plaintext)
        
        payload = lzw_decompress(xor(ct, self.key), self.lzw_width)
        
        self.dump(payload)
        
        

    def get_key_and_width(self, data, min_bits=18, max_bits=24):
        #map lzw bits to compressed LZW blob
        known_plaintexts =  {
                                16: [unhexlify('004D005A0090000000030000010500040105000000FF00FF010500B80108010E0040010E01110112011301140111001800010105000E001F00BA000E000000B4')],
                                18:[unhexlify('00134005A0024000000000C0000004140004004140000003FC00FF0041400B800420010E00100010E0044401120044C011400444002800004010500038001F00'),unhexlify('00134005A0024000000000C0000004140004004140000003FC00FF0041400B800420010E00100010E0044401120044C011400444002000004010500038001F00'),unhexlify('00134005A0024000000000C0000004140004004140000003FC00FF0041400B800420010E00100010E0044401120044C011400444002800004010500038001F00'),unhexlify('00134005A0024000000000C0000004140004004140000003FC00FF0041400B800420010E00100010E0044401120044C011400444001800004010500038001F00')],
                                20: [unhexlify('0004D0005A0009000000000030000000105000040010500000000FF000FF00105000B8001080010E000400010E00111001120011300114001110003000001001')]
                            } 
        for k,v in known_plaintexts.items():
            l = []
            for pt in v:
                for i in range(0x10, len(pt)+1, 0x10):
                    l.append(pt[:i])
            known_plaintexts[k] = [bytearray(pt) for pt in list(set(l))]#list(set(l))


        for width, known_list in known_plaintexts.items():
            for known in known_list:
                key = xor(known, data[:len(known)])
                self.logger.debug(f'Potential key associated with {width} bit LZW EXE: {hexlify(key)}')
                decrypted = xor(data, key)
                try:
                    self.logger.debug(f'Attempt LZW decompression with 0x{width:02X} bit width')
                    #res = b''.join(lzw.decompress(decrypted, width))
                    res = lzw_decompress(decrypted, width)
                    if res.startswith(b'MZ') and b"This program cannot be run" in res and len(res) < 5*1024**2:
                        self.logger.debug(f'Successfully decompressed with bit width 0x{width:02X}')
                        return key, width
                except Exception as e:
                    import traceback
                    self.logger.debug('Failed to decompress with key {hexlify(key)} and {width} bit LZW: {e}')
                    self.logger.debug(traceback.format_exc())
        raise Exception(f'Failed to LZW decompress data: {hexlify(data[:0x20])}')

    def read_args(self, args):
        """
        x64:
        size, bits, xor_key, sub_key, offset are usually in that order, but where those args start varies 


        Examples:
            [6443745408, 11122, 1136, 5, 22, 147, 6442465396, 6443745408]
            [0x84D0', '0x1AD7', '0x157A', '0x12AD', '0x2A0', '0x100000005', '0x2D', '0x93', '0x18001C5E0', '0x180012EB1]
            ['0x4C14', '0x84D0', '0x960', '0x5', '0x848E', '0x100004D59', '0x18001BB00', '0x180000000', '0x4CAE', '0x403C']
        x86:
            order: size, bits, xor_key, sub_key, offset
        Examples:
            ['0x1550', '0xFA0', '0x6', '0xA5', '0x29', '0x10024BD8', '0x4560', '0x0', '0x132F', '0x139B']

        some other samples (06f4384757e9fb909e83bd8a71213a27) have order:
            size, bits, xor_key, sub_key
        Examples:
            ['0xC78', '0xEA8', '0xC37', '0xD14', '0x84D0', '0xDD4', '0xE40', '0x5', '0xC22', '0xA49']
            '0xA15', '0x12C9', '0x84D0', '0x124A', '0x180', '0x5', '0xCC', '0x61', '0x18001A8D0', '0x0', '0x4E4', '0x180006500'
            '0xEFA', '0x921', '0x10001C368', '0x4', '0x1217', '0x17D0', '0x180112370', '0x14B2'
        """
        for i in range(0, len(args)-4):
            size, bits, xor_key, sub_key, offset = args[i:i+5]
            bits = bits & 0xFF
            xor_key = xor_key & 0xFF
            sub_key = sub_key & 0xFF
            size = size & 0xFFFFFFFF
            #self.logger.critical(f'size: 0x{size:X}, bits: {bits}, xor_key: 0x{xor_key:X}, sub_key: {sub_key:X}, ct_rva: 0x{offset:08X}') 
            #self.logger.critical(f'0x{self.pe.OPTIONAL_HEADER.ImageBase:X}-0x{self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.SizeOfImage:X}')
            if offset > self.pe.OPTIONAL_HEADER.ImageBase and offset < self.pe.OPTIONAL_HEADER.ImageBase + self.pe.OPTIONAL_HEADER.SizeOfImage and \
            bits >= 1 and bits <= 8 and size < 0x1000000 and size >= 0x100:
                as_hex = [f'0x{arg:X}' for arg in args]
                #self.logger.critical(as_hex)
                return size, bits, xor_key, sub_key, offset
        as_hex = [f'0x{arg:X}' for arg in args]
        raise Exception(f'Unable to decrypt_block args from: {as_hex}')


    def decrypt_block_cb(self, **kwargs):
        #self.trace_regs = True
        #self.start_trace()
        emu = kwargs['emu']
        regs = emu.get_register_state() 
        #rtn = self.mem_read(section.start, section.size)

        conv = e_arch.CALL_CONV_STDCALL
        args = emu.get_func_argv(conv, 20)
        size, bits, xor_key, sub_key, ct_rva = self.read_args(args)

        #self.logger.debug(f'ciphertext at RVA 0x{ct_rva:08X}')
        try:
            offset = self.pe.get_offset_from_rva(ct_rva - self.pe.OPTIONAL_HEADER.ImageBase)
            data = self.data[offset:offset+size]
        except Exception as e:
            self.logger.error(f'Failed to get ciphertext at 0x{offset:08X}')
            return
        
        ret = emu.get_ret_address()
        block = Block(ct_rva, data, xor_key, sub_key, bits)
        self.logger.info(f'BLOCK: {block}, called from 0x{ret:08X}')
        self.blocks.append(block)

        #self.logger.critical(f'decrypt_block called. args: {argv}, ret: {ret}')

    def key_derivation_cb(self, **kwargs):
        #self.logger.critical(f'key derivation called. kwargs: {kwargs}')
        pass

    def find_all_functions(self):
        """ 
            scan all executable sections for call references
        """
        text_section = None
        for section in self.pe.sections:
            #self.logger.critical(f'{section.name}: {section.Characteristics:08X} {section.Characteristics & 0x20000000:08X}')
            if (section.Characteristics & 0x20000000): #executable
                raw_start = section.PointerToRawData
                raw_end = raw_start + section.SizeOfRawData
                va_start = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                va_end = self.pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress + section.Misc_VirtualSize
                

                self.logger.debug(f'Scanning for functions in section {section.name} from 0x{raw_start:X}-0x{raw_end:X}')
                call = re.compile(rb'\xE8(?P<offset>....)', re.DOTALL)
                for match in call.finditer(self.data[raw_start:raw_end]):
                    offset = int.from_bytes(match.group('offset'), byteorder='little', signed=True)
                    unsigned = int.from_bytes(match.group('offset'), byteorder='little')
                    #self.logger.info(f'*** Offset: 0x{offset:08X}, unsigned: 0x{unsigned:08X}')
                    try:
                        function_raw = match.start() + 5 + offset + raw_start
                        #self.logger.info(f'0x{function_raw:08X}')
                        function_va =  self.pe.OPTIONAL_HEADER.ImageBase + self.pe.get_rva_from_offset(function_raw)
                        #self.logger.debug(f'Match: 0x{match.start():08X}, Function: VA: 0x{function_va:08X}, raw: 0x{function_raw:08X}, va_start: {va_start+1:08X}, va_end: 0x{va_end:08X}')
                        #self.logger.debug(f'function_raw: 0x{function_raw:08X}, raw_start: 0x{raw_start:08X}, raw_end: 0x{raw_end:08X}')
                        valid_prologue = re.compile(rb'[\x40-\x4F]?([\x89\x8b\x50-\x57\x83]|\x85[\xC8-\xCF])')
                        entry = self.data[function_raw:function_raw+3]
                        if function_va >= va_start and function_va <= va_end and function_raw >= raw_start and function_raw <= raw_end and valid_prologue.search(entry):
                            #self.logger.debug(f'Found function at 0x{function_va:08X}')
                            self.functions[function_va] = function_raw
                    except Exception as e:
                        #self.logger.debug(traceback.format_exc())
                        pass

    def get_function(self, func_va):
        minimum = 0xFFFFFFFF
        rtn = None
        for va, raw in self.functions.items():
            dist = func_va - va# func_va - va
            #self.logger.info(f'func_va: 0x{func_va:08X}, va: 0x{va:08X}, raw: 0x{raw:08X} 0x{dist:08X}')
            if dist > 0 and dist < minimum:
                minimum = dist
                rtn = va, raw
        if rtn:
            self.logger.debug(f'Closest function to {func_va:08X}: VA: {rtn[0]:08X} RAW: {rtn[1]:08X}')
            return rtn
        else:
            self.logger.debug(f'Failed to find function closest to 0x{func_va:08X} in {self.functions}')
        return None, None
            

    def PATCH_BUMBLEBEE(self):
        self.find_all_functions()

        if self.arch == e_arch.ARCH_X86:
            regex_dict =self.patch_x86()
        else:
            regex_dict = self.patch_x64()


        for name, d in regex_dict.items():
            patched = False
            for regex in d['re']:
                #self.logger.debug(f'{name}: {regex.pattern}')
                cb = d['cb']
                patch = d['patch']
                matches = [match for match in regex.finditer(self.data)]
                if len(matches) == 0:
                    continue
                if len(matches) > 1:
                    self.logger.warning(f'Found more than one match ({len(matches)}) for {name} function. Patching all of them')
                for match in matches:
                    if 'patch' in match.groupdict():
                        # if the regex defines a patch group, place the patch there
                        patch_loc = match.start('patch')    
                        prepatch = match.group('patch')
                        
                        #prepatch = self.data[patch_loc:patch_loc+len(patch)]

                        #patch = b'\x90'*(len(prepatch) - len(patch)) + patch
                        patch = b'\x90'*len(prepatch)


                        self.data = self.data[:patch_loc] + patch + self.data[patch_loc + len(patch):] 
                        self.logger.info(f'Applied patch to {name} at raw: 0x{patch_loc:08X}, {hexlify(prepatch)}->{hexlify(patch)}')
    
                        patched = True
                         
                    else:
                        # otherwise put the patch at the start of the function
                        bp = self.pe.OPTIONAL_HEADER.ImageBase + self.pe.get_rva_from_offset(match.start())
                        #self.logger.critical(f'Looking for function closest to 0x{match.start():08X}, VA: {bp:08X}') 
                        va, raw = self.get_function(bp)
                        self.logger.debug(f'get_func({bp:08X}) = {va:08X}, {raw:08X}')

                        prepatch = self.data[raw:raw+len(patch)]
                        self.data = self.data[:raw] + patch + self.data[raw + len(patch):] 
                        
                        self.add_breakpoint(va, cb) 
                        self.logger.info(f'Applied patch to {name} at 0x{va:08X}(raw: 0x{raw:08X}), {hexlify(prepatch)}->{hexlify(patch)}')
                        patched = True
                        #self.logger.critical(f'{hexlify(self.data[0x15834:0x15844])}')
                #break
            if not patched:
                if d['required']:
                    raise Exception(f'Failed to find {name} function. Unable to decrypt')
                self.logger.warning(f'Failed to patch {name} function. May take longer than normal')



    def patch_x86(self):
        """
        decrypt_block:
        715CC0B0 < | 83EC 18                  | sub esp,18
        715CC0B3   | 53                       | push ebx
        715CC0B4   | 55                       | push ebp
        715CC0B5   | 56                       | push esi
        ...
        715CC0F4   | 8A0C07                   | mov cl,byte ptr ds:[edi+eax]
        715CC0F7   | 8B42 18                  | mov eax,dword ptr ds:[edx+18]
        715CC0FA   | 2A4C24 3C                | sub cl,byte ptr ss:[esp+3C]
        715CC0FE   | 03C7                     | add eax,edi
        715CC100   | 324C24 38                | xor cl,byte ptr ss:[esp+38]
        715CC104   | 880C30                   | mov byte ptr ds:[eax+esi],cl

        key_derivation:
            715CBC50 < | 51                       | push ecx
            715CBC51   | 8B4C24 14                | mov ecx,dword ptr ss:[esp+14]
            715CBC55   | 8B5424 0C                | mov edx,dword ptr ss:[esp+C]
            715CBC59   | 53                       | push ebx
            715CBC5A   | 55                       | push ebp
            715CBC5B   | 56                       | push esi
            ...
            715CBDE9   | 8B3C82                   | mov edi,dword ptr ds:[edx+eax*4]                                                               |
            ...
            715CBDEE   | D3CF                     | ror edi,cl                                                                                     |
            ...
            715CBDF7   | 013C82                   | add dword ptr ds:[edx+eax*4],edi                                                               |
            ...
            715CBDF7   | 013C82                   | add dword ptr ds:[edx+eax*4],edi                                                               |
            ...
            715CBE18   | 99                       | cdq                                                                                            |
            715CBE19   | F7F9                     | idiv ecx                                                                                       |
            ...
            715CBE28   | 99                       | cdq                                                                                            |
            715CBE29   | F7F9                     | idiv ecx                                                                                       |
            ...
            715CBE49   | 8D1488                   | lea edx,dword ptr ds:[eax+ecx*4]                                                               |
        """
        #regex = br'\x83\xEC[\x10\x14\x18\x1C\x20\x24\x28\x2C]([\x50-\x57]){2,}.{,512}?'
        #prologue = br'((\x83\xEC[\x10\x14\x18\x1C\x20\x24\x28\x2C]|[\x50-\x57]|\x8B[\x44\x4C\x54\x5C\x6C\x74\x7C]\x24[\x04-\x40]){4,}|\xC3{2,}\x83\xEC[\x10\x14\x18\x1C\x20\x24\x28\x2C]).{,1024}?'
        #prologue = br'([\x50-\x57]*(\x83\xEC[\x10\x14\x18\x1C\x20\x24\x28\x2C])|\xCC(?P<start>[\x50-\x57]*\x83\xEC[\x10\x14\x18\x1C\x20\x24\x28\x2C])|\xCC([\x50-\x57]|\x8B[\x44\x4C\x54\x5C\x6C\x74\x7C]\x24[\x04-\x40]){3,}).{,512}?'

        #regex = prologue
        regex = br'\x8A[\x04\x0C\x14\x1C][\x00-\x3F].{,8}?'
        regex += br'\x2A([\x44\x4C\x54\x5C]\x24.|[\x84\x8C\x94\x9C]\x24....).{,8}?'
        regex += br'\x32([\x44\x4C\x54\x5C]\x24.|[\x84\x8C\x94\x9C]\x24....).{,8}?'
        block_decrypt_re = re.compile(regex, re.DOTALL)

        #regex = prologue
        regex = br'\x8B[\x04\x0C\x14\x1C\x24\x2C\x34\x3C][\x80-\xBF].{,64}?' #mov <reg32>,dword ptr ds:[<reg32> + <reg32>*4]
        regex += br'\x01[\x04\x0C\x14\x1C\x24\x2C\x34\x3C][\x80-\xBF].{,64}?' #add [<reg32>+<reg32>*4], <reg32?
        regex += br'\xD3[\xE0-\xE7].{,64}?' # shl <reg32>, cl
        regex += br'\xD3[\xE8-\xEF].{,64}?' # shr <reg32>, cl
        regex += br'[\x0B\x09][\xC0-\xFF]' # or <reg32>, <reg32>
        key_derivation_re = re.compile(regex, re.DOTALL)

        #regex = prologue
        regex = br'\x8B[\x04\x0C\x14\x1C\x24\x2C\x34\x3C][\x80-\xBF].{,64}?' # mov <reg32>,dword ptr ds:[<reg32> + <reg32>*4]
        regex += br'\xD3[\xC8-\xCF].{,128}?'                                  # ror
        regex += br'[\x01\x31][\x04\x0C\x14\x1C\x24\x2C\x34\x3C][\x80-\xBF].{,128}?' # add [<reg32>+<reg32>*4], <reg32?
        regex += br'\x99.{,8}?[\x40-\x4F]?\xF7[\xB8-\xBF\xF8-\xFF].{,64}?'         # cdq; idiv
        regex += br'\x99.{,8}?[\x40-\x4F]?\xF7[\xB8-\xBF\xF8-\xFF]'                 # cdq; idiv
        key_derivation_re2 = re.compile(regex, re.DOTALL)
        
        """
            715C7043 <00 | 55                       | push ebp                                                                                       |
            715C7044     | 8BEC                     | mov ebp,esp                                                                                    |
            715C7046     | 8B45 08                  | mov eax,dword ptr ss:[ebp+8]                                                                   |
            715C7049     | 85C0                     | test eax,eax                                                                                   |
            715C704B     | 74 12                    | je 00041d53ee3dc702bc2f7d59b5836834b6bba957efd799d2633792c8cf6986fe_p15.715C705F               |
            715C704D     | 8B4D 10                  | mov ecx,dword ptr ss:[ebp+10]                                                                  |
            715C7050     | 85C9                     | test ecx,ecx                                                                                   |
            715C7052     | 74 0B                    | je 00041d53ee3dc702bc2f7d59b5836834b6bba957efd799d2633792c8cf6986fe_p15.715C705F               |
            715C7054     | 8A55 0C                  | mov dl,byte ptr ss:[ebp+C]                                                                     |
            715C7057     | 8810                     | mov byte ptr ds:[eax],dl                                                                       |
            715C7059     | 40                       | inc eax                                                                                        |
            715C705A     | 83E9 01                  | sub ecx,1                                                                                      |
            715C705D     | 75 F8                    | jne 00041d53ee3dc702bc2f7d59b5836834b6bba957efd799d2633792c8cf6986fe_p15.715C7057              |
            715C705F     | 5D                       | pop ebp                                                                                        |
            715C7060     | C3                       | ret                                                                                            |
        """
        #busyloop_re = re.compile(rb'[\x40-\x47].{,16}?\x88[\x00-\x3F].{,8}?\xFF[\xC0-\xC7]{,4}?[\x70-\x7F][\xD0-\xFA]')
        busyloop_re = re.compile(rb'\x55.{,8}?\x8B\xEC.{,32}\x88[\x00-\x3F].{,8}?[\x40-\x47].{,8}?\x83[\xE8-\xEF]\x01')
        regexes = {
                    'block_decrypt': {'re': [block_decrypt_re], 'cb': self.decrypt_block_cb, 'required': True, 'patch': b'\x33\xC0\xC3\x90'}, 
                    'key_derivation': {'re': [key_derivation_re, key_derivation_re2], 'cb': self.key_derivation_cb, 'required': True, 'patch': b'\x33\xC0\xC3'},
                    'busyloop': {'re': [busyloop_re], 'cb': None, 'required': False, 'patch':  b'\x33\xC0\xC3\x90'}
                    }
        return regexes

    
    def patch_x64(self):
        """
        decrypt_block:
        00007FFEA6A5959C | 44:894424 18             | mov dword ptr ss:[rsp+18],r8d                                                           |
        00007FFEA6A595A1 | 53                       | push rbx                                                                                |
        00007FFEA6A595A2 | 55                       | push rbp                                                                                |
        00007FFEA6A595A3 | 56                       | push rsi                                                                                |
        00007FFEA6A595A4 | 57                       | push rdi                                                                                |
        00007FFEA6A595A5 | 41:54                    | push r12                                                                                |
        00007FFEA6A595A7 | 41:55                    | push r13                                                                                |
        00007FFEA6A595A9 | 41:56                    | push r14                                                                                |
        00007FFEA6A595AB | 41:57                    | push r15                                                                                |
        ...
        00007FFEA6A59649 | 43:8A0C37                | mov cl,byte ptr ds:[r15+r14]                                                            |
        00007FFEA6A5964D | 2A4C24 70                | sub cl,byte ptr ss:[rsp+70]                                                             |
        00007FFEA6A59651 | 324C24 68                | xor cl,byte ptr ss:[rsp+68]                                                             |
        00007FFEA6A59655 | 49:8B43 78               | mov rax,qword ptr ds:[r11+78]                                                           |
        00007FFEA6A59659 | 41:880C06                | mov byte ptr ds:[r14+rax],cl                                                            |
    
        key_derivation
        <same prologue as above>
        0000000180004E3F | 47:8B0C9E                     | mov r9d,dword ptr ds:[r14+r11*4]        | -
        0000000180004E61 | 44:2AC2                       | sub r8b,dl                              |
        ...
        0000000180004E6D | 45:8BC1                       | mov r8d,r9d                             | -
        0000000180004E70 | 41:D3E0                       | shl r8d,cl                              | -
        ...
        0000000180004E87 | 41:D3E9                       | shr r9d,cl                              |
        0000000180004E8A | 45:0BC1                       | or r8d,r9d                              |
        ...
        0000000180004E97 | 47:8B049E                     | mov r8d,dword ptr ds:[r14+r11*4]        |
        0000000180004E9B | 47:89049E                     | mov dword ptr ds:[r14+r11*4],r8d        |

        00007FFEB8FC2940 | 44:8B0482                          | mov r8d,dword ptr ds:[rdx+rax*4]                                                          |
        ...
        00007FFEB8FC2948 | 41:D3C8                            | ror r8d,cl                                                                                |
        ...
        00007FFEB8FC295C | 44:010482                          | add dword ptr ds:[rdx+rax*4],r8d                                                          |
        ...
        00007FFEB8FC2969 | 99                                 | cdq                                                                                       |
        00007FFEB8FC296A | 41:F7BF A8040000                   | idiv dword ptr ds:[r15+4A8]                                                               |
        ...
        00007FFEB8FC29BA | 99                                 | cdq                                                                                       |
        00007FFEB8FC29BB | 41:F7BF A8040000                   | idiv dword ptr ds:[r15+4A8]                                                               |
        """
        #regex = br'((?P<rex>[\x44-\x4C\x66])?\x89[\x44\x4C\x54\x5C\x64\x6C\x74\x7C]\x24[\x08-\x78]){1,}(\x41?[\x50-\x57]){2,}.{,512}?'
        regex = br'\x8A[\x04\x0C\x14\x1C][\x00-\x3F].{,12}?'
        regex += br'\x2A([\x44\x4C\x54\x5C]\x24.|[\x84\x8C\x94\x9C]\x24....).{,12}?'
        regex += br'\x32([\x44\x4C\x54\x5C]\x24.|[\x84\x8C\x94\x9C]\x24....).{,12}?'
        regex += br'\x88[\x04\x0C\x14\x1C][\x00-\x3F]'
        block_decrypt_re = re.compile(regex, re.DOTALL)

        """
            00007FFEA75B5D58 | 41:D3C8                            | ror r8d,cl                                                  |
            ...
            00007FFEA75B5D64 | 44:8B0488                          | mov r8d,dword ptr ds:[rax+rcx*4]                            |
            ...
            00007FFEA75B5D86 | 44:010488                          | add dword ptr ds:[rax+rcx*4],r8d                            |
            00007FFEA75B5D8A | 3B93 18060000                      | cmp edx,dword ptr ds:[rbx+618]                              | PATCH HERE?
            00007FFEA75B5D90 | 0F8C 48FEFFFF                      | jl bdc4a82bda16e5c8617ab3004da2acd3.7FFEA75B5BDE            |


            0000000180005048 | 41:D3E9                       | shr r9d,cl                              |
            000000018000504B | 45:0BC1                       | or r8d,r9d                              |
            ...
            0000000180005050 | 46:8B0496                     | mov r8d,dword ptr ds:[rsi+r10*4]        |
            ...
            000000018000505D | 46:890496                     | mov dword ptr ds:[rsi+r10*4],r8d        |
            ...
            000000018000506C | 3BBB 88010000                 | cmp edi,dword ptr ds:[rbx+188]          |
            0000000180005072 | 0F8C AFFCFFFF                 | jl bumblebee_eli.180004D27              |

            00007FFEBD7A7CDB | 41:D3C8                     | ror r8d,cl                                                                       | rol(pre_key[i],e)
            ...
            00007FFEBD7A7CE7 | 44:8B0488                   | mov r8d,dword ptr ds:[rax+rcx*4]                                                 |
            00007FFEBD7A7CEB | 48:638E 0C060000            | movsxd rcx,dword ptr ds:[rsi+60C]                                                |
            ...
            00007FFEBD7A7CFC | 44:010488                   | add dword ptr ds:[rax+rcx*4],r8d                                                 | xor_key[j] = rotated_pre_key
            00007FFEBD7A7D00 | 44:3B8E 00060000            | cmp r9d,dword ptr ds:[rsi+600]                                                   | j > 0x3CD631?
            00007FFEBD7A7D07 | 0F8C F2FDFFFF               | jl 578b4d18f6691014537377140a57738703c129b7f48ea8a256917a58902f2bfe_p10.7FFEBD7A |
        """

        #regex = br'((?P<rex>[\x44-\x4C\x66])?\x89[\x44\x4C\x54\x5C\x64\x6C\x74\x7C]\x24[\x08-\x78]){1,}(\x41?[\x50-\x57]){2,}.{,512}?'
        regex = br'\x8B[\x04\x0C\x14\x1C\x24\x2C\x34\x3C][\x80-\xBF].{,64}?' #mov <reg32>,dword ptr ds:[<reg64> + <reg64>*4]
        regex += br'\xD3[\xE0-\xE7].{,64}?' # shl <reg32>, cl
        regex += br'\xD3[\xE8-\xEF].{,64}?' # shr <reg32>, cl
        #regex += br'[\x0B\x09][\xC0-\xFF]' # or <reg32>, <reg32>
        regex += br'[\x0B\x09][\xC0-\xFF].{,128}?' # or <reg32>, <reg32>
        regex += br'(?P<patch>[\x40-\x4F]?\x3B[\x80-\xBF].[\x01-\x0F]\x00\x00\x0F\x8C..\xFF\xFF)'
        
        key_derivation_re = re.compile(regex, re.DOTALL)

        regex = br'\x8B[\x04\x0C\x14\x1C\x24\x2C\x34\x3C][\x80-\xBF].{,64}?'    #mov <reg32>,dword ptr ds:[<reg64> + <reg64>*4]
        regex += br'\xD3[\xC8-\xCF].{,192}?'                                    #ror
        regex += br'\x99.{,8}?[\x40-\x4F]?\xF7[\xB8-\xBF\xF8-\xFF].{,128}?'           # cdq;idiv
        regex += br'\x99.{,8}?[\x40-\x4F]?\xF7[\xB8-\xBF\xF8-\xFF].{,128}?'           # cdq:idiv
        regex += br'(?P<patch>[\x40-\x4F]?\x3B[\x80-\xBF]\x24?.[\x01-\x0F]\x00\x00\x0F\x8C..\xFF\xFF.{,384}?\x3B[\x80-\xBF]\x24?.[\x01-\x0F]\x00\x00\x0F[\x8C\x82]..\xFF\xFF)'
        key_derivation_re2 = re.compile(regex, re.DOTALL)

        """
            00007FFEA73F22D7 | 41:321400                          | xor dl,byte ptr ds:[r8+rax]                                 |
            ...
            00007FFEA73F22E2 | 41:881400                          | mov byte ptr ds:[r8+rax],dl                                 |
            ...
            00007FFEA73F2341 | 48:F7F1                            | div rcx                                                     |
            ...
            00007FFEA73F235D | 49:63C1                            | movsxd rax,r9d                                              |
            00007FFEA73F2360 | 48:3BC1                            | cmp rax,rcx                                                 | NOT GETTING PATCHED?
            00007FFEA73F2363 | 0F82 04FFFFFF                      | jb bdc4a82bda16e5c8617ab3004da2acd3.7FFEA73F226D            |
        """
        regex = br'[\x40-\x4F]\x32[\x04\x0C\x14\x1C\x24\x2C\x34\x3C][\x00-\x3C].{,128}?'
        regex += br'\xF7\xF1.{,64}?'
        regex += br'(?P<patch>[\x40-\x4F]?\x3B[\xC0-\xFF].{,8}?\x0F[\x8C\x82]..\xFF\xFF)'
        key_derivation_re3 = re.compile(regex, re.DOTALL)
        
        """
            00000001800029A4 | 48:85C9                       | test rcx,rcx                            |
            00000001800029A7 | 74 10                         | je bumblebee_eli.1800029B9              |
            00000001800029A9 | 45:85C0                       | test r8d,r8d                            |
            00000001800029AC | 74 0B                         | je bumblebee_eli.1800029B9              |
            00000001800029AE | 8811                          | mov byte ptr ds:[rcx],dl                |
            00000001800029B0 | 48:FFC1                       | inc rcx                                 |
            00000001800029B3 | 41:83C0 FF                    | add r8d,FFFFFFFF                        |
            00000001800029B7 | 75 F5                         | jne bumblebee_eli.1800029AE             |
            00000001800029B9 | C3                            | ret                                     |
        """

        busyloop_re = re.compile(rb'[\x40-\x47]?.{,16}?\x88[\x00-\x3F].{,8}?\xFF[\xC0-\xC7]{,4}?[\x70-\x7F][\xD0-\xFA]')

        """
        00007FFEA73E32E6 | 49:B9 0101010101010101             | mov r9,101010101010101                                      |
        00007FFEA73E32F0 | 4C:0FAFCA                          | imul r9,rdx                                                 |
        """
        clear_buf_re = re.compile(rb'\x01\x01\x01\x01\x01\x01\x01\x01.\x0F\xAF',re.DOTALL)
        regexes = {
                    'block_decrypt': {'re': [block_decrypt_re], 'cb': self.decrypt_block_cb, 'required': True, 'patch': b'\x33\xC0\xC3\x90\x90\x90'}, 
                    'key_derivation': {'re': [key_derivation_re, key_derivation_re2, key_derivation_re3], 'cb': self.key_derivation_cb, 'required': True, 'patch': b'\x90'},
                    'busyloop': {'re': [busyloop_re], 'cb': None, 'required': False, 'patch': b'\x33\xC0\xC3\x90\x90\x90'},
                    'clear_buf': {'re': [clear_buf_re], 'cb': None, 'required': False, 'patch': b'\x33\xC0\xC3'}
                    }
        return regexes



if __name__ == "__main__":
    options = parse_args()
    configure_logger(options.verbose)

    """
    import signal
    crashed = False
    def sig_handler(signum, frame):
        global unpacker
        print('sigsegv :|')
        unpacker.extract_payload()

    signal.signal(signal.SIGSEGV, sig_handler)
    """
    already_read = read_csv(options.csv)

    for arg in options.files:
        for path in recursive_all_files(arg):
            #TODO Fix. Shouldn't read/hash twice 
            with open(path, 'rb') as fp:
                md5 = hashlib.md5(fp.read()).hexdigest()
            if md5 in already_read:
                print(f'Skipping {path}. Already processed previously')
                continue

            unpacker = BumbleBeeUnpacker(path=path, config_path=options.config, **vars(options))
            try:
                unpacker.run()
                unpacker.extract_payload()
                unpacker.write_csv(options.csv)
            except Exception as e:
                unpacker.logger.error(f'Exception emulating {path}:{e}\n{traceback.format_exc()}')
                            
