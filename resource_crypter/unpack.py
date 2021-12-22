#!/usr/bin/env python3
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
from rc4 import CustomRC4
from utils import *

def parse_args():
    usage = "unpack.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument("-d", "--dump", dest="dump_dir", action="store", default=None,
      help="Dump path for unpacked payloads")
    arg_parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument('-y', '--yara', action='store_true', default=False, 
        help='Only unpack files matching the yara rule Classification_Resource_Crypter.yar')
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

class Decryptor:

    def __init__(self, dump=None):
        self.logger = logging.getLogger('Resource Crypter Unpacker')
        self.unpacked_pe = None
        self.unpacked = None
        self.config = []
        self.c2s = []
        self.decrypted_strings = {}
        self.path = None
        self.unpacker = None
        self.potential_keys = []
        self.dump=dump
        """
            021D7AA0 | 8B15 60BC1D02            | mov edx,dword ptr ds:[<const_one>]      |
            021D7AA6 | 81C2 8AA50800            | add edx,8A58A                           |
            021D7AAC | 0315 4CBC1D02            | add edx,dword ptr ds:[<j>]              | 021DBC4C:"ªl@"
        """
        self.regex = re.compile(b'\x8B.(?P<offset>....)\x81[\xC0-\xC3\xC4-\xC7](?P<const>....)')

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
            print(traceback.format_exc())

            exit()
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

    def block_copy(self, data, bs, skip):
        result = bytearray()
        for i in range(len(data)//bs):
            #print(f'copying from {i*(bs+skip):X} to {i*(bs+skip)+bs:X}')
            result += data[i*(bs+skip):i*(bs+skip)+bs]
        return result
        
    
    def solve(self, ciphertext):
        # In all observed packed Hancitor and Qakbot samples so far, the plaintext begins with ~40 bytes of 0x24
        dword = int.from_bytes(ciphertext[0:4], byteorder='little')
        yield 0x24242424 ^ dword
        yield 0x50746547 ^ dword
        

    def decrypt(self, const, data):
        #make a copy
        result = data[:]
        #dwords = data_to_dwords(data)
        #for i in range(len(dwords)):
        for i in range(0, len(data), 4):
            # read dword
            #print(f'i = {i:08X};', end='')
            x = int.from_bytes(result[i:i+4], byteorder='little', signed=False)
            #print(f'X = {x:08X};', end='')
            x = ((x+i) & 0xFFFFFFFF)
            x ^= ((const+i) & 0xFFFFFFFF)
            #print(f'const = {((const+i) & 0xFFFFFFFF):08X};', end='')
            #print(f'res = {x:08X};')
            result[i:i+4] = x.to_bytes(4, byteorder='little', signed=False)
        return result

    def decrypt_ciphertext(self, ciphertext, resource_name, bs=None, skip=None):
        """
            Find the key for the provided ciphertext and attempt to decrypt it
            Dump to the configured path
        """
        for const in self.solve(ciphertext):
            for match in self.regex.finditer(self.data):
                #self.logger.debug(f'Attempting to decrypt with add key 0x{const:08X}')
                unpacked_data = self.decrypt(const, ciphertext)
                #self.logger.debug(f'decrypted resource: {hexlify(unpacked_data[:0x176])}')
                results = carve(unpacked_data)
                if results:
                    if bs:
                        self.logger.critical(f'Successfully unpacked {len(results)} file(s) block size: 0x{bs:02X}, skip: 0x{skip:02X}, add: 0x{const:08X} from resource {resource_name}')
                    else:
                        self.logger.critical(f'Successfully carved {len(results)} file(s) with add 0x{const:08X}')
                    for result in results:
                        carved_pe = result['data']  
                        self.unpacked_pe = pefile.PE(data=carved_pe, fast_load=False) 
                        self.unpacked = carved_pe
                        dump_path = self.dump_path(carved_pe)
                        with open(dump_path, 'wb') as fp:
                            self.logger.critical(f'Dumping to {dump_path}')
                            fp.write(carved_pe)
                    return True


            
        

    def unpack(self, path, dump=None):
        self.path = path
        self.pe = pefile.PE(self.path, fast_load=False)
        with open(path, 'rb') as fp:
            self.data = fp.read()

        #Find resource

        for name, _id, resdata in iter_resources(self.pe):
            """
            if (int.from_bytes(resdata[:4], byteorder='little') < len(resdata) and
                    int.from_bytes(resdata[:4], byteorder='little') < len(resdata) + 0x200):
            """
            resname = f'{name}/{_id}'
            #self.logger.debug(f'Processing resource {name}/{_id} length: {len(resdata):08X}')
            size = int.from_bytes(resdata[:4], byteorder='little')
            try:
                ratio = size/len(resdata)
            except ZeroDivisionError:
                continue
            if size + 4 == len(resdata):
                self.logger.info(f'Found resource potentially containing encrypted PE: {name}/{_id}')
                return self.decrypt_ciphertext(resdata[4:], resname)
            #elif ratio > .75 and ratio < 1.33:
            #    self.logger.info(f'Found resource containing encrypted PE: {name}/{_id} size ratio: {ratio}')
            #    self.decrypt_ciphertext(resdata[4:])
            #elif size < len(resdata) + 0x400:
            elif ratio > .20 and ratio < 1:
                """
                    in some samples a58567fe17db5d4ee201dfeaa2466e06
                    the resource is copied over in blocks ignoring a few bytes of dead space between blocks
                    In this sample 0x7B bytes from the resource are copied, then 3 are skipped
                    We can determine the ratio of copy/skip by comparing the resource's actual size to the size
                    specified in the first 4 bytes
                """
                for frac in nearest_fractions(len(resdata), size, max_fractions=100): # Only try the 100 best approximations
                    block_size = frac.denominator
                    skip = frac.numerator - block_size
                    for i in range(1,255):
                        if block_size*i > 0x100:
                            break
                        self.logger.debug(f'Trying block copy with block size 0x{block_size*i:02X} and skip 0x{skip*i:02X}')
                        ciphertext = self.block_copy(resdata[4:], block_size*i, skip*i)
                        if self.decrypt_ciphertext(ciphertext, resname,  bs=block_size*i, skip=skip*i):
                            return True
                else:
                    pass
                    #self.logger.debug(f'Skipping resource {name}/{_id}')
                
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
    decryptor = Decryptor(options.dump_dir)
    if options.yara:
        import yara
        rule_path = os.path.join(repo_root, 'resource_crypter', 'Classification_Resource_Crypter.yar')
        rule = yara.compile(rule_path)
    for arg in options.files:
        for path in recursive_all_files(arg):
            if options.yara:
                if not rule.match(path):
                    decryptor.logger.info(f'Skipping {path} - did not match {rule_path}')
                    continue
            decryptor.logger.critical(f'Processing {path}')
            try:
                decryptor.unpack(path)
            except Exception as e:
                print(f'Exception processing {path}:')
                print(traceback.format_exc())
            
