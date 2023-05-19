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
    usage = "unpack.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument("-d", "--dump", dest="dump_dir", action="store", default=None,
      help="Dump path for unpacked payloads")
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

class TruebotUnpacker:

    def __init__(self, dump_dir=None):
        self.logger = logging.getLogger('Truebot/Silence Unpacker')
        """
            10001D06 | 8B55 F8                  | mov edx,dword ptr ss:[ebp-8]                                   |
            10001D09 | 0FB602                   | movzx eax,byte ptr ds:[edx]                                    | *ciphertext
            10001D0C | 0FB64D FF                | movzx ecx,byte ptr ss:[ebp-1]                                  |
            10001D10 | 33C1                     | xor eax,ecx                                                    |
            10001D12 | 8B55 F8                  | mov edx,dword ptr ss:[ebp-8]                                   |
            10001D15 | 2B55 08                  | sub edx,dword ptr ss:[ebp+8]                                   |
            10001D18 | 0FB6CA                   | movzx ecx,dl                                                   |
            10001D1B | 83E1 18                  | and ecx,18                                                     |
            10001D1E | 33C1                     | xor eax,ecx                                                    | eax ^= (i & mask)
            10001D20 | 8B55 F8                  | mov edx,dword ptr ss:[ebp-8]                                   |
            10001D23 | 8802                     | mov byte ptr ds:[edx],al                                       | pt[i] = x
        """
        self.mask_regexes = []
        self.ct_regexes = []
        #self.mask_regexes.append(re.compile(b'\x8A[\x04\x0C\x14\x1C][\x00-\x3F].{,64}\x34(?P<mask>.).{,32}\x80[\xE0-\xE3](?P=mask).{,64}\x32[\x00-\x1F].{,64}\x32[\xC0-\xFF].{,64}\x88[\x00-\x1F]'))
        #self.mask_regexes.append(re.compile(b'\x0F\xB6[\x00-\x3F].{,64}[\x31\x33][\xC0-\xFF].{,64}\x0F\xB6[\x00-\x3F].{,64}\x83[\xE0-\xE7](?P<mask>.).{,64}[\x31\x33][\xC0-\xFF].{,64}\x88[\x00-\x1F]', re.DOTALL))
        self.mask_regexes.append(re.compile(rb'(\x0F\xB6|\x8A[\x04\x0C\x14\x1C][\x00-\x3F]).{,256}(\x81[\xF0-\xF7]|\x34|\x35)(?P<mask>.).{,256}([\x80-\x81\x83][\xE0-\xE3]|\x25)(?P=mask)', re.DOTALL))
        self.mask_regexes.append(re.compile(rb'([\x80-\x81\x83][\xE0-\xE3]|\x25|\x24)(?P<mask>.).{,12}(\x88|\x30)[\x00-\x1F]', re.DOTALL)) 
        #self.mask_regexes.append(re.compile(b'
        self.ct_regexes.append(re.compile(br'\x68(?P<ciphertext_length>..[\x01-\x0F]\x00).{,5}\x68(?P<rva_ciphertext>..([\x40-\x47]\x00|[\x00-\x0F]\x10))(\xE8|\xFF\x15)'))
        """
            6DCA1787 | BA B00C0500              | mov edx,50CB0                           | 50CB0:L"ms-win-core-win32k-fulluserbase-l1-1-0"
            6DCA178C | 50                       | push eax                                |
            6DCA178D | 83EC 0C                  | sub esp,C                               |
            6DCA1790 | B9 A019CE6D              | mov ecx,55d1480cd023b74f10692c689b56e7f | ecx:EntryPoint
            6DCA1795 | 68 6020CA6D              | push 55d1480cd023b74f10692c689b56e7fd6c |
            6DCA179A | 68 F015CA6D              | push 55d1480cd023b74f10692c689b56e7fd6c |
            6DCA179F | E8 3C090000              | call 55d1480cd023b74f10692c689b56e7fd6c |
        """
        # fastcall args to a function
        self.ct_regexes.append(re.compile(br'\xBA(?P<ciphertext_length>..[\x01-\x0F]\x00).{,32}\xB9(?P<rva_ciphertext>..([\x40-\x47]\x00|[\x00-\x0F]\x10)).{,16}(\xE8|\xFF\x15)',re.DOTALL))
        #self.ct_regexes.append(re.compile(br'[\xB8-\xBB](?P<rva_ciphertext>..([\x40-\x47]\x00|[\x00-\x0F]\x10)).{,32}\x81[\xF8-\xFF](?P<ciphertext_length>..[\x01-\x0F]\x00)',re.DOTALL))
        self.ct_regexes.append(re.compile(br'[\xB8-\xBB](?P<rva_ciphertext>..([\x40-\x47]\x00|[\x00-\x0F]\x10)).{,32}\x81[\xF8-\xFF](?P<ciphertext_end>..([\x40-\x47]\x00|[\x00-\x0F]\x10))',re.DOTALL))
        self.pw_regex = re.compile(br'\x68(?P<rva_pw>..([\x40-\x47]\x00|[\x00-\x0F]\x10))', re.DOTALL)
        self.dump_dir = dump_dir
        
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
        except Exception as e:
            self.logger.info('Failed to identify proper extension. Defaulting to .bin')
            if self.data[:2] == b'\xd0\xcf':
                fname += '.ole'
            else:
                fname += '.bin'

        if not self.dump_dir:
            #dump file back to path it originated from
            #print(os.path.basename(self.path))
            return os.path.join(os.path.dirname(self.path), fname)
        else:
            os.makedirs(self.dump_dir, exist_ok=True)
            return os.path.join(self.dump_dir, fname)

    def find_ciphertext(self):
        """
            71621A66 | 68 50B70500              | push 5B750                              |
            71621A6B | 68 18BA6471              | push <092910024190a2521f21658be849c4ac9 |
            71621A70 | E8 12F6FFFF              | call 092910024190a2521f21658be849c4ac9a |
        """

        for regex in self.ct_regexes:
            for match in regex.finditer(self.data):
                rva = int.from_bytes(match.group('rva_ciphertext'), byteorder='little')
                ciphertext_raw = self.pe.get_offset_from_rva(rva - self.pe.OPTIONAL_HEADER.ImageBase)
                self.logger.debug(f'ciphertext RVA: 0x{rva:08X}, raw address: 0x{ciphertext_raw:08X}')
                if 'ciphertext_length' in match.groupdict():
                    length = int.from_bytes(match.group('ciphertext_length'), byteorder='little')
                else:
                    rva = int.from_bytes(match.group('ciphertext_end'), byteorder='little')
                    raw_offset = self.pe.get_offset_from_rva(rva - self.pe.OPTIONAL_HEADER.ImageBase)
                    length = raw_offset - ciphertext_raw
                    if length < 0x10000 or length > 0xF0000:
                        self.logger.debug(f'Failed to parse ciphertext length from {match.groupdict()}')
                        continue
                yield ciphertext_raw, length
    
    def decrypt(self, ciphertext, pw, mask):
        if (ciphertext[0] ^ (0%len(pw) & mask) ^ mask ^ pw[0%len(pw)]) != 0x4D:
            raise Exception('Failed to decrypt')
        if (ciphertext[1] ^ (1%len(pw) & mask) ^ mask ^ pw[1%len(pw)]) != 0x5A:
            raise Exception('Failed to decrypt')
        plaintext = bytearray(len(ciphertext))
        for i in range(0, len(ciphertext)):
            x = ciphertext[i] ^ (i & mask) ^ mask ^ pw[i%len(pw)]
            #self.logger.debug(f'0: 0x{i:08X}: 0x{ciphertext[i]:02X}(ct[i]) ^ 0x{mask:08X}(mask) ^ 0x{pw[i%len(pw)]:02X} ^ {i%len(pw) & mask:08X}(x) = 0x{x:02X}')
            plaintext[i] = x
        
        #This will throw an exception if we haven't decrypted properly
        pe = pefile.PE(data=plaintext, fast_load=False)  

        return plaintext
    
        

    def find_passphrase(self, start, window=256):
        # There should be a push ref to the passphrase shortly before the decryption code
        self.logger.debug(f'searching {len(self.data[start-window:start])} bytes for passphrase in 0x{start-window:08X}-{start:08x}')
        for match in self.pw_regex.finditer(self.data[start-window:start]):
            rva = int.from_bytes(match.group('rva_pw'), byteorder='little')
            try:
                pw_raw_addr = self.pe.get_offset_from_rva(rva - self.pe.OPTIONAL_HEADER.ImageBase)
                self.logger.debug(f'Potential password RVA: 0x{rva:08X}, raw addr: 0x{pw_raw_addr:08X}')
                pw = bytearray()
                i = 0
                while self.data[pw_raw_addr+i] >= 0x20 and self.data[pw_raw_addr+i] < 0x7F:
                    pw.append(self.data[pw_raw_addr+i])
                    i += 1
                if len(pw) >= 8:
                    yield pw
            except Exception as e:
                self.logger.debug(f'Failed to parse potential passphrase at {match.start():08X}')
                continue

    def unpack(self, path, brute_mask=False):
        self.path = path
        self.pe = pefile.PE(self.path, fast_load=False)  
        with open(path, 'rb') as fp:
            self.data = fp.read()
        possible_masks = []
        for mask_regex in self.mask_regexes:
            for match in mask_regex.finditer(self.data):
                val = int.from_bytes(match.group('mask'), byteorder='little')
                if val not in [mask['mask'] for mask in possible_masks]:
                    possible_masks.append({'mask': int.from_bytes(match.group('mask'), byteorder='little'), 'start': match.start(), 'window': 256})
        self.logger.debug('Possible masks: ' + str([i["mask"] for i in possible_masks]))
        if len(possible_masks) == 0 or brute_mask == True:
            possible_masks = []
            self.logger.info('Failed to find mask. Trying all...')
            for i in range(0, 256):
                possible_masks.append({'mask': i, 'start': len(self.data), 'window': len(self.data)})

        for ct_addr, ctlen in self.find_ciphertext():
            self.logger.debug(f'Potential ciphertext found at 0x{ct_addr:08X}, length: 0x{ctlen:08X}') 
            ciphertext = self.data[ct_addr:ct_addr+ctlen]
            for item in possible_masks:
                pws = list(self.find_passphrase(item['start'], item['window']))
                self.logger.debug(f'Found {len(pws)} possible RC4 passphrases')
                for pw in pws:
                    self.logger.debug(f'Potential passphrase: {pw}')
                    try:
                        plaintext = self.decrypt(ciphertext, pw, item['mask'])
                    except Exception as e:
                        self.logger.debug(f'Failed to decrypt with pw {pw} and mask 0x{item["mask"]:02X}: {e}')
                        continue
                    try:
                        self.logger.info(f'Successfully decrypted payload with passphrase {pw} and mask {item["mask"]:02X}: {plaintext[:0x40]}...')
                        path = self.dump_path(plaintext)
                        self.logger.info(f'Dumping payload to {path}')
                        with open(path, 'wb') as fp:
                            print(f'Decrypted payload at 0x{ct_addr:08X} with password {pw.decode()} and mask 0x{item["mask"]:02X}. Dumping to {path}')
                            fp.write(plaintext)
                        return True
                    except Exception as e:
                        self.logger.error(e)
                        #self.logger.debug(traceback.format_exc())
            

if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    unpacker = TruebotUnpacker(options.dump_dir)
    for arg in options.files:
        for path in recursive_all_files(arg):
            unpacker.logger.info(f'Processing {path}')
            try:
                if not  unpacker.unpack(path):
                    unpacker.logger.warning('Failed to unpack on first pass. Brute forcing all possible masks...')
                    unpacker.unpack(path, True)
            except Exception as e:
                print(f'Exception processing {path}:')
                print(traceback.format_exc())
            
