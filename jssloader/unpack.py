#!/usr/bin/env python3
import json
import hashlib
import logging
import traceback
import os
import re
import sys
import pefile
from binascii import hexlify, unhexlify
from argparse import ArgumentParser
from pprint import pprint
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

    def to_va(self, addr):
        return self.pe.get_rva_from_offset(addr)+self.pe.OPTIONAL_HEADER.ImageBase 
        
    def unpack(self, path, output=None):
        self.path = path
        with open(self.path, 'rb') as fp:
            self.data = fp.read()
        self.pe = pefile.PE(self.path, fast_load=False)
        if not output:
            self.output = path + '.unpacked'
        else:
            self.output = output
        
        if not self.find_struct():
            return False
        self.functions = self.parse_functions()
        self.remove_xor_func()
        self.password = self.get_password()
        self.logger.info(f'xor passphrase: {hexlify(self.password)}')
        self.unpack_functions()
        self.replace_calls()
        self.dump()
        
        
    def find_struct(self):
        """
            00401000 | B9 00100000              | mov ecx,1000                                         |
            00401005 | 33C0                     | xor eax,eax                                          |
            00401007 | E8 18010000              | call birdwatch.401124                                |
        """
        regex = re.compile(br'[\xB8-\xBF]\x00\x10\x00\x00\x33\xC0\xE8....', re.DOTALL)
        match = regex.search(self.data)
        if not match:
            self.logger.critical('Failed to find function length array. Unable to continue')
            return None
        #self.length_array = self.pe.get_rva_from_offset
        self.length_array_raw = match.span()[1]
        self.length_array_va = self.pe.get_rva_from_offset(self.length_array_raw)
        self.logger.debug(f'function length array at raw offset 0x{self.length_array_raw:08X}')
        self.logger.debug(f'function length array at VA 0x{self.length_array_va:08X}')
        return True

    def parse_functions(self):
        functions = {}
        fptr = self.length_array_raw
        lptr = self.length_array_raw
        length = int.from_bytes(self.data[lptr:lptr+2], byteorder='little')
        idx = 1
        while length:
            fptr += length
            lptr += 2
            self.logger.info(f'Function: 0x{fptr:08X}, Length: 0x{length:08X}')
            length = int.from_bytes(self.data[lptr:lptr+2], byteorder='little')
            functions[fptr] = {'length': length, 'idx': idx}
            idx += 1 

        return functions

    def get_password(self):
        addr = max(self.functions) + 0x152 #seems hard coded. May need to write a regex to extract the offset and size dynamically if future samples differ
        return self.data[addr:addr+0x3E]
        
    def unpack_functions(self):
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
            self.logger.critical(f'main patch: before: {hexlify(self.data[match.start():match.end()])} after: {hexlify(patch)}')
            self.data = self.data[:match.start()] + patch + self.data[match.end():]
            self.logger.critical('Patched call to main')

    def get_func_by_idx(self, idx):
        for addr, d in self.functions.items():
            if d['idx'] == idx:
                return addr
        self.logger.error(f'Failed to find function {idx}')
        return None

    def replace_calls(self):
        """
            a few different ways of identifying the function responsible for decrypting, calling, and reencrypting functions
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
            self.logger.debug(f'Match end: 0x{self.to_va(match.span()[1]):08X} Offset: 0x{offset:08X}')
            call_addr = match.span()[1] + offset
            if call_addr == decryption_func:
                if match.group('num'):
                    func_idx = int.from_bytes(match.group('num'), byteorder='little')
                else:
                    func_idx = int.from_bytes(match.group('long_num'), byteorder='little')
                func_addr = self.get_func_by_idx(func_idx)
                self.logger.debug(f'Found call to decryption function 0x{func_idx:02X} at 0x{self.to_va(match.start()):08X}. Replacing with call directly to 0x{self.to_va(func_addr):08X}')
                new_offset = int.to_bytes(func_addr - (match.span()[1]), signed=True, length=4, byteorder='little')
                if match.group('num'):
                    self.data = self.data[:match.start()] + b'\x90\x90\xE8' + new_offset + self.data[match.span()[1]:]
                else:
                    self.data = self.data[:match.start()] + b'\x90\x90\x90\x90\x90\xE8' + new_offset + self.data[match.span()[1]:]

        
if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    unpacker = Unpacker()
    for path in options.files:
        unpacker.logger.info(f'Processing {path}')
        try:
            unpacker.unpack(path, output=options.out)
        except Exception as e:
            print(traceback.format_exc())
            
