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
from utils import *
from lznt1 import decompress

def parse_args():
    usage = "unpack.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument("-d", "--dump", dest="dump_dir", action="store", default='unpacked',
      help="Dump path for unpacked payloads")
    arg_parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument('-s', '--skip', dest='skip', action='store_true', default=False,
        help='Skip hardcoded block check (const 0xEA79A5C6)')
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

class Block:
    def __init__(self, data):
        self.data = data
        

class Decryptor:
    def __init__(self, dump=None, skip_strict=False):
        self.logger = logging.getLogger('IDAT Unpacker')
        self.skip_strict=skip_strict
        self.unpacked_pe = None
        self.unpacked = None
        self.config = []
        self.c2s = []
        self.decrypted_strings = {}
        self.path = None
        self.unpacker = None
        self.potential_keys = []
        self.dump=dump
        self.regex = re.compile(b'(?P<block_size>....)IDAT(?P<checksum>....)')

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
        with open(path, 'rb') as fp:
            self.data = fp.read()

        payload = bytearray()
        first_block = True
        for match in self.regex.finditer(self.data):
            block_size = int.from_bytes(match.group('block_size'), byteorder='big')

            if first_block:
                block_data = self.data[match.start()+8:match.start()+block_size+8]
                print(hexlify(block_data[:0x20]))
                if not self.skip_strict:
                    checksum = int.from_bytes(match.group('checksum'), byteorder='little')
                    if checksum != 0xEA79A5C6:
                        self.logger.warning(f'Found block with incorrect checksum of 0x{checksum:08X}. Ignoring and searching for next block. Ignore checksum with -s option')
                        continue
                self.logger.info(f'Found header block at 0x{match.start():08X}, size: 0x{block_size:08X}')
                self.logger.debug(f'Appending {hexlify(block_data[:0x20]).decode()}...{hexlify(block_data[-0x20:]).decode()}')
                payload += block_data
            else:
                block_data = self.data[match.start()+8:match.start()+block_size+8]
                self.logger.debug(f'Found block at 0x{match.start():08X}, size: 0x{block_size:08X}')
                self.logger.debug(f'Appending {hexlify(block_data[:0x20]).decode()}...{hexlify(block_data[-0x20:]).decode()}')
                payload += block_data
                
            first_block = False

        self.logger.info(f'Encrypted data size: 0x{len(payload):08X}')
        key = bytearray(payload[0x04:0x08])
        size = int.from_bytes(payload[0x08:0x0C], byteorder='little')
        self.logger.info(f'Xor key: {hexlify(key).decode()}, size: 0x{size:08X}')
        payload = payload[0x10:]
        if size < len(payload):
            payload = payload[:size]
        
        self.logger.debug(f'Compressed Payload: {hexlify(payload[:0x20]).decode()}...')
        decrypted_data = xor(payload, key)
        payload = decompress(bytes(decrypted_data), length_check=False)
        self.logger.info(f'Decompressed data: {hexlify(payload[:0x80]).decode()}...')
             
        dump_path = self.dump_path(payload)
        self.logger.critical(f'Dumping payload to {dump_path}')
        with open(dump_path, 'wb') as fp:
            fp.write(payload)
            


        
if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    decryptor = Decryptor(options.dump_dir, options.skip)
    for arg in options.files:
        for path in recursive_all_files(arg):
            decryptor.logger.critical(f'Processing {path}')
            try:
                decryptor.unpack(path)
            except Exception as e:
                print(f'Exception processing {path}:')
                print(traceback.format_exc())
            
