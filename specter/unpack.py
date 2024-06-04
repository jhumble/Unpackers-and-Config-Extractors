#!/usr/bin/env python3
import xtea
import hashlib
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
    arg_parser.add_argument("-d", "--dump", dest="dump_dir", action="store", default=None,
      help="Dump path for unpacked payloads")
    arg_parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument('files', nargs='+')
    return arg_parser.parse_args()

def configure_logger(log_level):
    log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'unpacker.log')
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], 
                        format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s',
                        handlers=[
                            logging.FileHandler(log_file, 'a'),
                            logging.StreamHandler()
                        ])

class Unpacker:
    def __init__(self, dump=None):
        self.logger = logging.getLogger('Unpacker')
        self.path = None
        self.potential_keys = []
        self.dump=dump
        """
            00007FF61D7018C8 | 4C:8D05 31271300         | lea r8,qword ptr ds:[7FF61D834000]                                | 00007FF61D834000:"pg"
            00007FF61D7018CF | 48:8D9424 E0010000       | lea rdx,qword ptr ss:[rsp+1E0]                                    | qword from resource
            00007FF61D7018D7 | B9 20000000              | mov ecx,20                                                        | 20:' '
            00007FF61D7018DC | E8 5F9A0900              | call <learncomtoolkit.xtea>                                       |
        """
        self.regex = re.compile(b'\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D](?P<key_offset>....).{,16}\xB9\x20\x00\x00\x00.{,16}', re.DOTALL)

    def dump_path(self, data):
        fname = hashlib.md5(data).hexdigest()
        self.logger.debug(f'Beginning of file: {hexlify(data[:32]).decode()}')
        try:
            pe = pefile.PE(data=data)
            if pe.is_dll():
                fname += '.dll'
            elif pe.is_driver(): 
                fname += '.sys'
            else:
                fname += '.exe'
        except:
            #print(traceback.format_exc())
            #exit()
            if self.data[:2] == b'\xd0\xcf':
                fname += '.ole'
            else:
                fname += '.bin'

        if not self.dump:
            #dump file back to path it originated from
            #print(os.path.basename(self.path))
            return os.path.join(os.path.dirname(self.path), fname)
        else:
            os.makedirs(self.dump, exist_ok=True)
            return os.path.join(self.dump, fname)


    def decrypt(self, const, data):
        #make a copy
        result = data[:]
        for i in range(0, len(data), 4):
            x = int.from_bytes(result[i:i+4], byteorder='little', signed=False)
            x = ((x+i) & 0xFFFFFFFF)
            x ^= ((const+i) & 0xFFFFFFFF)
            result[i:i+4] = x.to_bytes(4, byteorder='little', signed=False)
        return result

    def decrypt_ciphertext(self, ciphertext, resource_name):
        """
            Find the key for the provided ciphertext and attempt to decrypt it
            Dump to the configured path
        """
        self.logger.debug(f'Decrypting {hexlify(ciphertext[:32])}')
        
        # Make length a multiple of 4. I think XTEA should pad with nulls, but he malware just truncates 
        ciphertext = ciphertext[:-(len(ciphertext)%8)]
        for key in self.potential_keys:
            self.logger.debug(f'Attempting to decrypt with key {hexlify(key)}')
            x = xtea.new(key, mode=xtea.MODE_ECB, endian='<')
            unpacked_data = x.decrypt(ciphertext)
            with open('/tmp/test.bin', 'wb') as fp:
                fp.write(unpacked_data[3:])
            self.logger.debug(f'decrypted data: {hexlify(unpacked_data[:160])}')
            
            #self.logger.debug(f'decrypted resource: {hexlify(unpacked_data[:0x176])}')
            results = carve(unpacked_data)
            if b'MZ' in unpacked_data[:32]:
                index = unpacked_data[:32].index(b'MZ')
                results.append({'data': unpacked_data[index:], 'offset': index, 'ext': '.shellcode'})
            
            if results:
                self.logger.critical(f'Successfully carved {len(results)} file(s) with key {{{hexlify(key).decode()}}} from resource {resource_name}')
                for result in results:
                    data = result['data']  
                    dump_path = self.dump_path(data)
                    with open(dump_path, 'wb') as fp:
                        self.logger.critical(f'Dumping to {dump_path}')
                        fp.write(data)
                return True
                    


    def unpack(self, path, dump=None):
        self.path = path
        self.pe = pefile.PE(self.path, fast_load=False)
        with open(path, 'rb') as fp:
            self.data = fp.read()

        #collect all possible XTEA keys
        for match in self.regex.finditer(self.data):
            offset = int.from_bytes(match.group('key_offset'), byteorder='little', signed=True) 
            self.logger.debug(f'Potential key accessed at raw addr 0x{match.start():08X}, offset: 0x{offset:08X}')
            rva = self.pe.get_rva_from_offset(match.start()+6) + offset
            self.logger.debug(f'Potential key RVA: 0x{rva:08X}')
            raw_offset = self.pe.get_offset_from_rva(rva)
            self.logger.debug(f'Potential key raw offset: 0x{raw_offset:08X}')
            key = self.data[raw_offset:raw_offset+16]
            self.logger.debug(f'Potential key: {{{hexlify(key)}}}')
            self.potential_keys.append(key)

        #Find resource
        for name, _id, resdata in iter_resources(self.pe):
            resname = f'{name}/{_id}'
            reslength = len(resdata)  - 4 #First dword is payload length, remove from size
            e = entropy(resdata)
            self.logger.debug(f'Processing resource {name}/{_id} length: 0x{len(resdata):08X}, entropy: {e:2.2f}')
            if len(resdata) > 0x4000 and e > 4: 
                if self.decrypt_ciphertext(resdata, resname):
                    return True
                
        self.logger.error("Failed to find resource containing encrypted PE file")
        return 
        

        # Find the addition key. Solving seems to be a better method as long as the 0x24242424 prefix is constant
        # If that fails to prove correct I may need build this method back in as a backup
        """
        for match in self.regex.finditer(self.data):
            try:
                const1 = int.from_bytes(match.group('const'), byteorder='little')
                self.logger.debug(f'const1: 0x{const1:08X}')
                rva = int.from_bytes(match.group('offset'), byteorder='little')
                self.logger.debug(f'RVA: 0x{rva:08X}')
                raw_offset = self.pe.get_offset_from_rva(rva - self.pe.OPTIONAL_HEADER.ImageBase)
                self.logger.debug(f'raw offset: 0x{raw_offset:08X}')
                const2 = int.from_bytes(self.data[raw_offset:raw_offset+4], byteorder='little')
                self.logger.debug(f'const2: 0x{const2:08X}')
            except:
                continue
        """

        
if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    unpacker = Unpacker(options.dump_dir)
    for arg in options.files:
        for path in recursive_all_files(arg):
            unpacker.logger.critical(f'Processing {path}')
            try:
                unpacker.unpack(path)
            except Exception as e:
                print(f'Exception processing {path}:')
                print(traceback.format_exc())
            
