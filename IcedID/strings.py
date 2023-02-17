#!/usr/bin/env python3
import hashlib
import logging
import traceback
import os
import re
import sys
from binascii import hexlify, unhexlify
from argparse import ArgumentParser
from pathlib import Path

repo_root = Path(os.path.realpath(__file__)).parent.parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)
from utils import *

def parse_args():
    usage = "strings.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
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

class IcedIDStringExtractor:

    def __init__(self):
        self.logger = logging.getLogger('IcedIDStringExtractor')
        self.decrypted_strings = {}
        self.regex = re.compile(b'([^\x00].|.[^\x00])\x00\x00')
        self.strings = []


    def parse_strings(self, offset, min_entries=40, max_strlen=2**16-1):
        entries = 0
        strings = []
        while True:
            length = int.from_bytes(self.data[offset:offset+4], byteorder='little')
            if length > max_strlen or offset+length > len(self.data) or length < 1:
                if len(strings) >= min_entries:
                    self.strings =  strings
                    return True
                else:
                    return False    
            #key = bytearray(self.data[offset+4:offset+8]) # I think this is what the author intended but they screwed up and only use the first byte
            key = bytearray(self.data[offset+4:offset+5])
            ciphertext = bytearray(self.data[offset+8:offset+8+length][::-1])
            self.logger.debug('Entry #{entries}: Ciphertext: {hexlify(ciphertext)}, Key: {key:08X}')
            strings.append({'ciphertext': ciphertext, 'key': key, 'offset': offset, 'plaintext': bytearray(len(ciphertext))})
            offset = offset + length + 8
            
        

    def extract(self, path):
        self.path = path
        with open(path, 'rb') as fp:
            self.data = fp.read()
        for match in self.regex.finditer(self.data):
            if self.parse_strings(match.start()):
                for string in self.strings:
                    string['plaintext'] = bytearray([string['key'][0] ^ x for x in string['ciphertext']])
                    try:
                        print(string['plaintext'].decode())
                    except:
                        print(string['plaintext'])
                return


        
if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    extractor = IcedIDStringExtractor()
    for arg in options.files:
        for path in recursive_all_files(arg):
            extractor.logger.critical(f'Processing {path}')
            try:
                extractor.extract(path)
            except Exception as e:
                print(f'Exception processing {path}:')
                print(traceback.format_exc())
            
