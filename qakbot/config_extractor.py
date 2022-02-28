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
from rc4 import CustomRC4
from utils import *

def parse_args():
    usage = "config_extractor.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument("-o", "--out", action="store", default=None,
      help="Path to dump json configuration to")
    arg_parser.add_argument("-s", "--strings", action="store_true", default=None,
      help="Write decrypted strings to stdout")
    arg_parser.add_argument("-b", "--brute-strings", dest='brute', action="store_true", default=False,
      help="Try all decrypted strings as passphrases for decrypting C2 data")
    arg_parser.add_argument('files', nargs='+')
    return arg_parser.parse_args()

def configure_logger(log_level):
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], 
            format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s')

class ConfigExtractor:

    def __init__(self):
        self.logger = logging.getLogger('Qakbot/Hancitor Packer Config Extractor')
        self.config = {'config' : {}, 'c2 info': {'c2 list': []}, 'decrypted_strings': {}}
        self.config['decrypted_strings'] = {}
        self.path = None

        
    def extract(self, path, brute=False):
        self.path = path
        # Some variants (afa3e64cc7630942151d414d3fe472a6 -- unpacked from 10ec9ebbb3af2ca6181f33d358cfb8a6) seem to 
        # have misspelled passwords (Sha1("\\System32\\WindowsPowerShel1\\v1.0\\powershel1.exe")) and require the brute option to decrypt.
        self.brute = brute
        with open(self.path, 'rb') as fp:
            self.data = fp.read()
        self.pe = pefile.PE(self.path, fast_load=False)
        extractor.decrypt_strings()
        extractor.extract_config()
        
    def decrypt_strings(self):
        """
            char* decrypt(int string_offset):

            100095A8 | 51                       | push ecx                                                 | ecx:key
            100095A9 | 51                       | push ecx                                                 | ecx:key
            100095AA | 68 F8E30110              | push <98140e5672de3f7c9239b112d0a2bf63.key>              | key
            100095AF | BA 4C0E0000              | mov edx,E4C                                              | length
            100095B4 | B9 A8D50110              | mov ecx,<98140e5672de3f7c9239b112d0a2bf63.ciphertext>    | ciphertext
            100095B9 | E8 CEEEFFFF              | call 98140e5672de3f7c9239b112d0a2bf63.1000848C           | decrypt(ciphertext, len(ciphertext), key, string_offset, string_offset)
            100095BE | 83C4 0C                  | add esp,C                                                |
            100095C1 | C3                       | ret                                                      |

            10001018 68 98 fe 02 10       PUSH       ciphertext                                       = 9Eh
            1000101d 68 35 04 00 00       PUSH       0x435                                            ciphertext length
            10001022 68 f8 fe 02 10       PUSH       key                                              = C2h
            10001027 e8 e8 90 00 00       CALL       decrypt_string                                   undefined * decrypt_string(char 


            Get key length from inside decrypt function:
            100084A5 | C745 10 5A000000         | mov dword ptr ss:[ebp+10],5A                             | hardcoded key length
            100084AC | 33D2                     | xor edx,edx                                              | edx:ciphertext
            100084AE | 8BC6                     | mov eax,esi                                              |
            100084B0 | F775 10                  | div dword ptr ss:[ebp+10]                                | i%len(key)

            Another variant: 5feb80d07f349065626dc31cf9e19424b5a38fabdcd8b487e1be0b4d34bd2972 
            1000a144 6a 5a           PUSH       0x5a
            1000a146 8b c1           MOV        EAX,ECX
            1000a148 5b              POP        EBX
            1000a149 f7 f3           DIV        EBX

            Old variant:
            004065A0 | 68 98B84000              | push <ba505ad08b0cc2ca037d5349a1076be57 | ciphertext
            004065A5 | BE 3B370000              | mov esi,373B                            | ciphertext_length
            004065AA | E8 52BEFFFF              | call ba505ad08b0cc2ca037d5349a1076be579 |
            004065AF | 59                       | pop ecx                                 |
            004065B0 | A3 94064100              | mov dword ptr ds:[410694],eax           | 
            004065B5 | 85C0                     | test eax,eax                            | 
            004065B7 | 75 07                    | jne ba505ad08b0cc2ca037d5349a1076be579e |
            004065B9 | B8 CC064100              | mov eax,ba505ad08b0cc2ca037d5349a1076be | 
            004065BE | EB 65                    | jmp ba505ad08b0cc2ca037d5349a1076be579e |
            004065C0 | BE 3A370000              | mov esi,373A                            |
            004065C5 | 8BCB                     | mov ecx,ebx                             |
            004065C7 | 3BDE                     | cmp ebx,esi                             |
            004065C9 | 73 1C                    | jae ba505ad08b0cc2ca037d5349a1076be579e |
            004065CB | 8BD1                     | mov edx,ecx                             |
            004065CD | 83E2 3F                  | and edx,3F                              |
            004065D0 | 8A92 30014100            | mov dl,byte ptr ds:[edx+410130]         | key at 0x410130

        """
        decrypt_regex = re.compile(br'\x68(?P<key_offset>....)\xBA(?P<ciphertext_length>....)\xB9(?P<ciphertext_offset>....)\xE8(?P<decrypt_function>....)\x83\xC4\x0C\xC3', re.DOTALL | re.MULTILINE)
        decrypt_regex2 = re.compile(br'\x68(?P<key_offset>....)\x68(?P<ciphertext_length>....)\x68(?P<ciphertext_offset>....)\xE8(?P<decrypt_function>....)\x83\xC4\x0C\xC3', re.DOTALL | re.MULTILINE)
        decrypt_regex3 = re.compile(br'\x68(?P<ciphertext_offset>....)[\xB8-\xBF](?P<ciphertext_length>....).{,64}\x83[\xE0-\xE7](?P<key_length>\x3F).{,8}\x8A[\x90-\x97](?P<key_offset>....)', re.DOTALL | re.MULTILINE)
        #decrypt_regex3 = re.compile(br'\x68(?P<ciphertext_offset>....)[\xB8-\xBF](?P<ciphertext_length>....).{,320}\x83[\xE0-\xE7]', re.DOTALL | re.MULTILINE)
        key_regex = re.compile(br'\xC7\x45.(?P<key_length>....).{,32}\xF7\x75')
        key_regex2 = re.compile(br'\x6A(?P<key_length>.).{,8}[\x58-\x5F].{,8}\xF7[\xF0-\xF3\xF5-\xF7]')
        

        matches = list(decrypt_regex.finditer(self.data)) + list(decrypt_regex2.finditer(self.data)) + list(decrypt_regex3.finditer(self.data))
        if not matches:
            self.logger.error('Failed to find string decryption function')
            return False
        
        for match in matches:
            try:
                rva = int.from_bytes(match.group('ciphertext_offset'), byteorder='little')
                ciphertext_offset = self.pe.get_offset_from_rva(rva - self.pe.OPTIONAL_HEADER.ImageBase)
                ciphertext_length = int.from_bytes(match.group("ciphertext_length"), byteorder='little')
                ciphertext = self.data[ciphertext_offset:ciphertext_offset+ciphertext_length]
                
                try:
                    key_length = int.from_bytes(match.group('key_length'), byteorder='little') + 1
                    key_rva = int.from_bytes(match.group('key_offset'), byteorder='little')
                    key_offset = self.pe.get_offset_from_rva(key_rva - self.pe.OPTIONAL_HEADER.ImageBase)
                    key = self.data[key_offset:key_offset+key_length] 
                    self.logger.debug(f'xor key: {hexlify(key).decode()}')
                    self.parse_strings(ciphertext, key, op_and=True)
                    return True
                    
                except (KeyError, IndexError) as e:
                    key = None

                function_relative = int.from_bytes(match.group('decrypt_function'), byteorder='little', signed=True)
                self.logger.debug(f'function relative offset: 0x{function_relative:08X}')
                function_offset = match.start() + 20 + function_relative # Adding 20 accounts for the 16 bytes of the pattern before the function relative offset, and the 4 bytes of offset
                function_rva = self.pe.get_rva_from_offset(function_offset)
                self.logger.debug(f'Function RVA: 0x{function_rva:08X}')
                self.logger.debug(f'Found potential decrypt function at RVA 0x{function_rva:08X}. Ciphertext at RVA 0x{rva:08X} RAW: 0x{ciphertext_offset:08X} of length 0x{ciphertext_length:04X}: {hexlify(ciphertext[:32]).decode()}...')

                search = self.data[function_offset:function_offset+0x80] # search 0x80 bytes into the function for key length
                for key_match in list(key_regex.finditer(search)) + list(key_regex2.finditer(search)):
                    key_length = int.from_bytes(key_match.group('key_length'), byteorder='little')
                    key_rva = int.from_bytes(match.group('key_offset'), byteorder='little')
                    key_offset = self.pe.get_offset_from_rva(key_rva - self.pe.OPTIONAL_HEADER.ImageBase)
                    
                    key = self.data[key_offset:key_offset+key_length] 
                    self.logger.debug(f'xor key: {hexlify(key).decode()}')
                    self.parse_strings(ciphertext, key)

            except Exception as e:
                self.logger.error(e)
                self.logger.error(traceback.format_exc())
        
    def parse_strings(self, ciphertext, key, op_and=False):
        ciphertext = bytearray(ciphertext)
        key = bytearray(key)
        string = bytearray()
        for i in range(len(ciphertext)):
            if op_and:
                c = ciphertext[i] ^ key[i&(len(key)-1)]
            else:
                c = ciphertext[i] ^ key[i%len(key)]
            if c == 0:
                try:
                    self.config['decrypted_strings'][i - len(string)] = string.decode()
                except:
                    self.config['decrypted_strings'][i - len(string)] = string
                string = bytearray()
            else:
                string.append(c)
        
    def extract_config(self):
        for name, _id, data in iter_resources(self.pe):
            #print(f'{offset:08X} {len(data):08X}')
            if len(data) > 0x10 and len(data) < 0x60:
                # Probably config
                self.logger.debug(f'Found possible config resource {name}/{_id}, length: {len(data):08X}')
                try:
                    res, string = self.decrypt_resource(data)
                    if res:
                        if string:
                            self.config['config']['extraction method'] = f'Decrypted config from resource {name}/{_id} with RC4 key: Sha1("{string.decode()}")' 
                        else:
                            self.config['c2 info']['extraction method'] = f'Extracted from resource {name}/{_id} with first 20 bytes'
                    else:
                        self.logger.error(f'Failed to decrypt resource {name}/{_id}')
                except Exception as e:
                    self.logger.error(f'Exception processing config resource: {e}')
            elif len(data) > 0x60:
                try:
                    self.logger.debug(f'Found possible C2 resource {name}/{_id}, length: {len(data):08X}')
                    res, string = self.decrypt_resource(data)
                    if res:
                        if string:
                            self.logger.info(f'Decrypted C2 info from resource {name}/{_id} with RC4 key: Sha1("{string.decode()}")')
                            self.config['c2 info']['extraction method'] = f'Decrypted config from resource {name}/{_id} with RC4 key: Sha1("{string.decode()}")' 
                        else:
                            self.config['c2 info']['extraction method'] = f'Extracted from resource {name}/{_id} with first 20 bytes'
                    else:
                        self.logger.error(f'Failed to decrypt resource {name}/{_id}')
                except Exception as e:
                    self.logger.error(f'Exception processing C2 resource: {e}')
                    print(traceback.format_exc())

    def decrypt_resource(self, data):
        # Method 1: decrypt with first 20 bytes of resource
        res = CustomRC4(data[:20]).decrypt(data[20:])
        QBOT_HEADER = b'\x61\x6c\xd3\x1a\x00\x00\x00\x01' 
        BRIEFLZ_HEADER = b'\x62\x6C\x7A\x1A\x00\x00\x00\x01'
        if QBOT_HEADER in res:
            self.logger.critical('Old version. Use https://github.com/dark0pcodes/qbot_helper to extract')
            return False, None
        if self.parse_resource(res):
            return True, None
        # Newer method: https://seguranca-informatica.pt/a-taste-of-the-latest-release-of-qakbot/
        # TODO uncomment to try all other decrypted strings as passphrases
        if self.brute:
            string_list = ['\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'] + list(self.config['decrypted_strings'].values())
        else:
            string_list = ['\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']

        for string in string_list:
            try:
                string = string.encode('ascii')
            except Exception as e:
                self.logger.error(f'Failed to decrypt using {string}: {e}')
                continue
            self.logger.debug(f'Attempt to decrypt with passphrase {string}: {hexlify(string)}')
            res = CustomRC4(hashlib.sha1(string).digest()).decrypt(data)
            if self.parse_resource(res):
                self.logger.info(f'Decrypted config with key Sha1("{string.decode()}")')
                return True, string

        return False, None

    def parse_resource(self, data):
        # Method 1: decrypt with first 20 bytes of resource
        mapping = { '10': 'Botnet id',
                    '11': 'number of hardcoded C2s',
                    '2' : 'Date of Qbot install in HH:MM:ss-dd/mm/yyyy',
                    '3' : 'campaign id',
                    '50': 'unknown field 50',
                    '5' : 'victim network shares',
                    '38': 'last victim call to C2 (unix time)',
                    '45': 'C2 IP',
                    '46': 'C2 port',
                    '39': 'Victim external ip',
                    '43': 'Time of record (Unix time)',
                    '49': 'unknown field 49'}
        # config
        try:
            if b'10=' in data or b'3=' in data:
                raw_config = data[20:].decode().split('\x0d\x0a')
                self.logger.debug(f'Raw config: {raw_config}')
                for opt in raw_config:
                    if opt:
                        parts = opt.split('=')
                        key = parts[0]
                        val = '='.join(parts[1:])
                        description = mapping.get(key, '')
                        self.config['config'][key] = {'description': description, 'value': val}
                return True
            # c2 list TODO: This seems prone to potentially miss odd configs without https
            elif b'\x01\xBB\x01' in data:
                raw_config = data[20:]
                for i in range(len(raw_config)//7):
                    c2 = bytearray(raw_config[i*7:i*7+7])
                    port = int.from_bytes(c2[-2:], byteorder='big')
                    ip = f'{c2[1]}.{c2[2]}.{c2[3]}.{c2[4]}:{port}'
                    self.config['c2 info']['c2 list'].append(ip)
                return True
        except UnicodeDecodeError:
            self.logger.debug('Failed to parse resource')
            return False

        
if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    extractor = ConfigExtractor()
    for path in options.files:
        extractor.logger.info(f'Processing {path}')
        try:
            extractor.extract(path, brute=options.brute)
            if options.out:
                extractor.logger.critical(f'Writing config to {options.out}')
                with open(options.out, 'w') as fp:
                    json.dump(extractor.config, fp)
            if options.strings:
                pprint(extractor.config)
            else:
                pprint({k:v for (k,v) in extractor.config.items() if k != 'decrypted_strings'})
        except Exception as e:
            print(traceback.format_exc())
            
