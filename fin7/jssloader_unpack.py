#!/usr/bin/env python3
import logging
import traceback
import os
import re
import sys
import pefile
from binascii import hexlify, unhexlify
from argparse import ArgumentParser
from pathlib import Path

repo_root = Path(os.path.realpath(__file__)).parent.parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)
from utils import *

def parse_args():
    usage = "unpack.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument("-o", "--out", action="store", default=None,
      help="Path to dump unpacked file to")
    arg_parser.add_argument("-s", "--strings", action="store_true", default=False,
      help="print decrypted strings")
    arg_parser.add_argument('files', nargs='+')
    return arg_parser.parse_args()

def configure_logger(log_level):
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], 
            format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s')

class Unpacker:

    def __init__(self):
        self.logger = logging.getLogger('JSSLoader Unpacker')
        self.path = None
        self.functions = {} # maps offset to length
        self.strings = {}

    def to_va(self, addr):
        """
            Mostly just used for debug printing virtual addresses to follow along in a debugger
        """
        rva = self.pe.get_rva_from_offset(addr)
        if not rva:
            raise Exception(f'Unable to get rva from addr 0x{addr:08X}')
        return rva + self.pe.OPTIONAL_HEADER.ImageBase 
        
    def unpack(self, path, output=None, print_strings=False):
        self.path = path
        with open(self.path, 'rb') as fp:
            self.data = fp.read()
        self.pe = pefile.PE(self.path, fast_load=False)
        if not output:
            self.output = path + '.unpacked'
        else:
            self.output = output
        
        try:
            self.functions = self.parse_functions()
        except Exception as e:
            self.logger.critical('Failed to parse encrypted function pointer list. Unable to continue')
            return False
        self.remove_xor_func()
        self.password = self.get_password()
        self.logger.info(f'xor passphrase: {hexlify(self.password)}')
        self.decrypt_functions()
        self.replace_calls()

        if print_strings:
            self.decrypt_strings()
            self.dump_strings()

        self.dump()
        
        
    def parse_functions(self):
        """
            The entrypoint looks like this:
            00401000 | B9 00100000              | mov ecx,1000                                         |
            00401005 | 33C0                     | xor eax,eax                                          |
            00401007 | E8 18010000              | call birdwatch.401124                                |
        
            Immediately following the call instruction there is an array of words representing the
            length of each encrypted function. We parse that array of lengths to build a list of function
            pointers and sizes for later decryption.
        """
        functions = {}
        regex = re.compile(br'[\xB8-\xBF]\x00\x10\x00\x00\x33\xC0\xE8....', re.DOTALL)
        match = regex.search(self.data)
        if not match:
            raise Exception('Failed to find function length array. Unable to continue')
        #self.length_array = self.pe.get_rva_from_offset
        fptr = match.span()[1]
        lptr = fptr
        self.logger.debug(f'function length array at raw offset 0x{fptr:08X}')
        self.logger.debug(f'function length array at VA 0x{self.to_va(fptr):08X}')

        length = int.from_bytes(self.data[lptr:lptr+2], byteorder='little')
        idx = 1
        while length:
            fptr += length
            lptr += 2
            self.logger.debug(f'Function: 0x{fptr:08X}, Length: 0x{length:08X}')
            length = int.from_bytes(self.data[lptr:lptr+2], byteorder='little')
            functions[fptr] = {'length': length, 'idx': idx}
            idx += 1 
        return functions

    def get_password(self):
        """ 
            xor passphrase is located 0x152 bytes after the last function pointer.
        """
        addr = max(self.functions) + 0x152 #seems hard coded. May need to write a regex to extract the offset dynamically if future samples differ
        password = self.data[addr:addr+0x7F].split(b'\x00')[0][:-4]
        return password
        
    def decrypt_functions(self):
        """ 
            Now that we have a list of functions (self.functions) and the xor passphrase,
            use that to replace each function with the decrypted equivalent
        """
        data = bytearray(self.data)
        pw = bytearray(self.password)
        for addr, d in self.functions.items():
            length = d['length']
            #self.logger.debug(f'Unpacking 0x{length:08X} byte function 0x{addr:08X}')
            self.logger.debug(f'Unpacking 0x{length:08X} byte function 0x{self.to_va(addr):08X}')
            res = xor(data[addr:addr+length], pw)
            self.logger.debug(f'Before: {hexlify(data[addr:addr+length])} After: {hexlify(res)}')
            data[addr:addr+length] = res
        self.data = bytes(data)
            
    def dump(self):
        self.logger.critical(f'Dumping unpacked file to {self.output}')
        with open(self.output, 'wb') as fp:
            fp.write(self.data)

    def remove_xor_func(self):
        """
        The function responsible for xor decrypting other functions shows up in the function list, but is always unencrypted. We need to identify it so we
        can skip this already decrypted function
            00403F6D | 8A0430                   | mov al,byte ptr ds:[eax+esi]                         | password[j]
            00403F70 | 8A21                     | mov ah,byte ptr ds:[ecx]                             | encrypted_function[i]
            00403F72 | 03F7                     | add esi,edi                                          | edi:ptr1
            00403F74 | 32C4                     | xor al,ah                                            |
            00403F76 | 8801                     | mov byte ptr ds:[ecx],al                             | ecx:decrypt_xor(*arg2, *func_struct, func_offset)
            00403F78 | 58                       | pop eax                                              |
            00403F79 | 59                       | pop ecx                                              | ecx:decrypt_xor(*arg2, *func_struct, func_offset)
            00403F7A | 03CF                     | add ecx,edi                                          | ecx:decrypt_xor(*arg2, *func_struct, func_offset), edi:ptr1
        """
        regex = re.compile(rb'\x8A[\x04\x0C\x14\x1C\x24\x2C\x34\x3C][\x00-\x3F].{,8}\x8A[\x00-\x3F].{,8}\x32[\xC0-\xFF]', re.DOTALL)
        match = None
        for addr, d in self.functions.items():
            length = d['length']
            if regex.search(self.data[addr:addr+length]):
                self.logger.debug(f'Found match at 0x{self.to_va(addr):08X}')
                match = addr
        if not match:
            self.logger.error('Failed to identify xor function. Results may be corrupted')
        else:
            self.logger.info(f'Removing xor function 0x{self.to_va(match):08X} from set of functions to decrypt (already decrypted at start)')
            del self.functions[match]
        """
            One last patch. We need to find the code that decrypts the "decryption" function, and nop it out since we've already decrypted it
            Then "main" is started by calling the decryption wrapper func by register (ecx below, func idx: 4). We replace that with a call directly to main
            00401186 | 8BC4                       | mov eax,esp                             |
            00401188 | 8928                       | mov dword ptr ds:[eax],ebp              |
            0040118A | C740 04 36000000           | mov dword ptr ds:[eax+4],36             | 36:'6'
            00401191 | 50                         | push eax                                |
            00401192 | FFD1                       | call ecx                                |
            00401194 | 8B4C24 08                  | mov ecx,dword ptr ss:[esp+8]            |
            00401198 | 8969 0A                    | mov dword ptr ds:[ecx+A],ebp            |
            0040119B | 83C4 10                    | add esp,10                              |
            0040119E | 6A 04                      | push 4                                  |
            004011A0 | FFD1                       | call ecx                                |
            004011A2 | 83EC 14                    | sub esp,14                              |
        """
        regex = re.compile(rb'\x8B\xC4.{,16}(?P<decrypt_decryption_func>[\x50-\x57]\xFF[\xD0-\xD7]).{,16}\x6A(?P<main_func_num>[\x01-\x7F])(?P<call_main>\xFF[\xD0-\xD7])', re.DOTALL)
        match = regex.search(self.data)
        if not match:
            self.logger.error('Failed to find call that decrypts function decryptor. Unpacked sample will not run correctly!')
        else:
            func_idx = int.from_bytes(match.group('main_func_num'), byteorder='little')
            func_addr = self.get_func_by_idx(func_idx)
            self.logger.info(f'Found call to main. function offset: 0x{func_idx:02X} addr: 0x{self.to_va(func_addr):08X}')
            new_offset = int.to_bytes(func_addr - (match.start()+5), signed=True, length=4, byteorder='little')
            patch = b'\xE8' + new_offset + b'\x90'*(match.end()-match.start()-5)
            self.logger.info(f'main patch: before: {hexlify(self.data[match.start():match.end()])} after: {hexlify(patch)}')
            self.data = self.data[:match.start()] + patch + self.data[match.end():]

    def get_func_by_idx(self, idx):
        for addr, d in self.functions.items():
            if d['idx'] == idx:
                return addr
        self.logger.error(f'Failed to find function {idx}')
        return None

    def replace_calls(self):
        """
            Find the "wrapper" function responsible for finding a target function, decrypting it, calling it, and reencrypting it. 
            Once found, we identify all calls to that wrapper function and replace them with calls directly to the decrypted versions

            a few different ways of identifying the function responsible for decrypting, calling, and reencrypting functions:
            00403EC1 | BA 28000000              | mov edx,28                                                                        | edx:EntryPoint, 28:'('
            00403EC6 | F7E2                     | mul edx                                                                           | edx:EntryPoint
        
            00403EC8 | 8D95 00040000            | lea edx,dword ptr ss:[ebp+400]                                                    | edx:EntryPoint
        """
        decryption_regex = re.compile(rb'(\x8D[\x80-\xBF]\x00\x04\x00\x00|[\xB8-\xBF]\x28\x00\x00\x00\xF7[\xE0-\xE7])', re.DOTALL)
        decryption_func = None
        for addr, d in self.functions.items():
            length = d['length']
            if decryption_regex.search(self.data[addr:addr+length]):
                decryption_func = addr
                break
        if decryption_func:
                self.logger.info(f'Found decryption function 0x{self.to_va(addr):08X}')
        else:
            self.logger.error('Failed to find decryption function. Unable to replace calls with replacements directly to decrypted functions')
            return
                
        """
            00401299 | 6A 0A                    | push A                                                                            |
            0040129B | E8 602B0000              | call 91ae7d316b081acf783a2127b5611c17.exe.403E00                                  |
        """
        regex = re.compile(rb'(\x6A(?P<num>[\x01-\x7F])|\x68(?P<long_num>.\x00\x00\x00))\xE8(?P<offset>..(\xFF\xFF|\x00\x00))', re.DOTALL)
        for match in regex.finditer(self.data):
            offset = int.from_bytes(match.group('offset'), signed=True, byteorder='little')
            try:
                va = self.to_va(match.span()[1])
            except Exception as e:
                self.logger.debug(f'Failed to patch 0x{match.start():08X}: {e}')
                continue
            call_addr = match.span()[1] + offset
            if call_addr == decryption_func:
                if match.group('num'):
                    func_idx = int.from_bytes(match.group('num'), byteorder='little')
                else:
                    func_idx = int.from_bytes(match.group('long_num'), byteorder='little')
                func_addr = self.get_func_by_idx(func_idx)
                self.logger.debug(f'Found wrapped call to function 0x{func_idx:02X} at 0x{self.to_va(match.start()):08X}. Replacing with call directly to 0x{self.to_va(func_addr):08X}')
                new_offset = int.to_bytes(func_addr - (match.span()[1]), signed=True, length=4, byteorder='little')
                if match.group('num'):
                    self.data = self.data[:match.start()] + b'\x90\x90\xE8' + new_offset + self.data[match.span()[1]:]
                else:
                    self.data = self.data[:match.start()] + b'\x90\x90\x90\x90\x90\xE8' + new_offset + self.data[match.span()[1]:]


    def decrypt_string(self, string):
        """
            The strings are decrypted by grabbing two bytes of ciphertext at time, swapping them, and subtracting 1 from
            one byte and adding 1 to the other. Easier to show by example:
            Ciphertext: "BCDE" -> "DAFC"
        """
        string = bytearray(string)
        res = bytearray(len(string))
        for i in range(0, len(string)-1,2):
            res[i] = string[i+1]+1
            res[i+1] = string[i]-1
        if len(string)%2 == 1:
            res[-1] = string[-1] - 2
        return bytes(res)

    def decrypt_strings(self):
        """
            Identify the following code block which contains a pointer to the first encrypted string (0x407A70 in this case)
            The encrypted strings are just null separated and accessed by index
            00404A38 | B9 707A4000                | mov ecx,bw3.407A70                      | 
            00404A3D | EB 08                      | jmp bw3.404A47                          |
            00404A3F | 8039 00                    | cmp byte ptr ds:[ecx],0                 |
            00404A42 | 8D49 01                    | lea ecx,dword ptr ds:[ecx+1]            |
            00404A45 | 75 F8                      | jne bw3.404A3F                          |
            00404A47 | 4A                         | dec edx                                 |
            00404A48 | 75 F5                      | jne bw3.404A3F                          |
        """
        regex = re.compile(rb'[\xB8-\xBF](?P<rva>..\x40\x00).{,16}[\x70-\x7F][\xD0-\xFC][\x48-\x4F][\x70-\x7F][\xD0-\xFC]', re.DOTALL)
        match = regex.search(self.data)
        if match:
            va = int.from_bytes(match.group('rva'), byteorder='little')
            self.logger.debug(f'match: {hexlify(match.group())} string table VA: 0x{va:08X}')
            strings_addr = self.pe.get_offset_from_rva(int.from_bytes(match.group('rva'), byteorder='little') - self.pe.OPTIONAL_HEADER.ImageBase)
            self.logger.info(f'Found encrypted string array at 0x{self.to_va(strings_addr):08X}')
        else:
            self.logger.error('Unable to find encrypted string table')

        length = self.data[strings_addr:].find(b'\x00\x00')
        idx = 1
        for string in self.data[strings_addr:strings_addr+length].split(b'\x00'):
            addr = self.data.find(string)
            if len(string) > 1:
                self.strings[idx] = {'value': string, 'addr': addr, 'decrypted': self.decrypt_string(string)}
            idx += 1
        # I'd like to go through and patch all of the calls that decrypt and load these strings to be direct references to them to ease analysis, but
        # it seems like it will be quite a bit harder than the decrypt function patching, so I'll save that for a later exercise

    def dump_strings(self):
        print('Strings:')
        print('Index    Decrypted String')
        for idx, d in self.strings.items():
            try:
                print(f'{idx:02X}        {d["value"].decode():60} {d["decrypted"].decode()}')
            except:
                try:
                    print(f'{idx:02X}        {hexlify(d["value"]):60} {d["decrypted"]}')
                except:
                    print(f'Failed to display string {idx:02X}')

        
if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    unpacker = Unpacker()
    for path in options.files:
        unpacker.logger.info(f'Processing {path}')
        try:
            unpacker.unpack(path, output=options.out, print_strings=options.strings)
        except Exception as e:
            print(traceback.format_exc())
            
