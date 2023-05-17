#!/usr/bin/env python3
import hashlib
import logging
import traceback
import os
import re
import sys
import base64
from binascii import hexlify, unhexlify
from argparse import ArgumentParser
from pathlib import Path
from urllib.parse import unquote_to_bytes
from pprint import pprint

repo_root = Path(os.path.realpath(__file__)).parent.parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)
from utils import *
from rc4 import CustomRC4

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




class TrueBotStringExtractor:

    def __init__(self):
        self.logger = logging.getLogger('TrueBotStringExtractor')
        """
            716FC2CF | 50                       | push eax                                                      |
            716FC2D0 | 57                       | push edi                                                      |
            716FC2D1 | FF75 C4                  | push dword ptr ss:[ebp-3C]                                    |
            716FC2D4 | 68 981E7171              | push eef48d1b50a6d56106b8bae8f7c50d6c.71711E98                | 71711E98:"OumaOyIuRymuZyOi"
            716FC2D9 | E8 F261FDFF              | call eef48d1b50a6d56106b8bae8f7c50d6c.716D24D0                |
        """
        self.rc4_key_regex = re.compile(b'\x68(?P<va>..([\x40-\x4F]\x00|[\x00-\x0F]\x10)).{,5}(\xE8|\xFF\x15)', re.DOTALL)
        self.b64_regex = re.compile(b'[a-zA-Z0-9+/]{6,}={0,2}')
        self.valid_string = re.compile(b'^[\x20-\x7E]*$')
        self.strings = {}


    def read_string(self, offset, minimum=8):
        try:
            rtn = bytearray()
            i = 0
            while self.data[offset+i] >= 0x20 and self.data[offset+i] < 0x7F:
                rtn.append(self.data[offset+i])
                i += 1
            if len(rtn) >= 8:
                return rtn
        except Exception as e:
            self.logger.debug(f'Failed to read string at 0x{offset:08X}: {e}')
        return False
        
    def get_base64_strings(self):
        for match in self.b64_regex.finditer(self.data):
            try:
                string = base64.b64decode(match.group()) 
                if self.valid_string.match(string):
                    s = unquote_to_bytes(string)
                    self.strings[s] = {'original': match.group(), 'encrypted': unquote_to_bytes(string)}
            except Exception as e:
                self.logger.debug(f'Failed to base64 decode potential string {match.group()}: {e}')


        
    def possible_rc4_keys(self):
        for match in self.rc4_key_regex.finditer(self.data):
            va = int.from_bytes(match.group('va'), byteorder='little')
            raw = self.pe.get_offset_from_rva(va - self.pe.OPTIONAL_HEADER.ImageBase)
            pw = self.read_string(raw, 8)
            if pw and 0x20 not in pw:
                self.logger.debug(f'Found potential password: {pw}')
                yield pw
        

    def extract(self, path):
        self.path = path
        with open(path, 'rb') as fp:
            self.data = fp.read()
        self.pe = pefile.PE(data=self.data, fast_load=False)  
        self.get_base64_strings()
        self.logger.info(f'Found {len(self.strings)} base64 strings')
        for pw in self.possible_rc4_keys():
            decrypter = CustomRC4(pw)
            for key, string in self.strings.items():
                if 'decrypted' not in string:
                    self.logger.debug(f'Attmpting to decrypt {string} with {pw}')
                    s = decrypter.decrypt(string['encrypted'])
                    if self.valid_string.match(s):
                        try:
                            string['decrypted'] = s.decode()
                            string['encryption_key'] = pw
                        except Exception as e:
                            self.logger.warning('Failed to decode {s}: {e}')
                    #print(string)
                 
    def print_output(self):
        header = False
        for key, string in self.strings.items():
            if 'decrypted' in string:
                if not header:
                    print(self.path)
                    header = True
                #print(f'\t{string["decrypted"].decode()}\tRC4 key: {string["encryption_key"]}\tOriginal)
                print(f'\t{string}')
        
if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    extractor = TrueBotStringExtractor()
    for arg in options.files:
        for path in recursive_all_files(arg):
            extractor.logger.info(f'Processing {path}')
            try:
                header = False
                extractor.extract(path)
                extractor.print_output()
            except Exception as e:
                print(f'Exception processing {path}:')
                print(traceback.format_exc())
            
