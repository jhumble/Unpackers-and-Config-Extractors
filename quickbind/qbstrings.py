from binascii import hexlify, unhexlify
from Crypto.Cipher import ARC4
from argparse import ArgumentParser
from pathlib import Path
import logging
import os
import re
import sys
import pefile

repo_root = Path(os.path.realpath(__file__)).parent.parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)
from utils import *

def parse_args():
    usage = "qbstrings.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument("-a", "--all", action="store_true", default=False,
      help="Attempt to dump all strings rather than just valid utf-16 strings. Will have some FPs")
    arg_parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    arg_parser.add_argument('files', nargs='+')
    return arg_parser.parse_args()

class QB_ENC_STR:
    def __init__(self, raw_bytes, req_wide=True):
        self.ciphertext_length = struct.unpack('<L', raw_bytes[:4])[0]
        self.key = raw_bytes[4:8]
        self.ciphertext = raw_bytes[8:]
        self.plaintext = b''
        self.decrypt()

    def decrypt(self):
        rc4 = ARC4.new(self.key)
        self.plaintext = rc4.decrypt(self.ciphertext)
    
    def check_wide(self):
        for i in range(len(self.plaintext)//2):
            if self.plaintext[i*2+1] != 0:
                return False
        return True

    def __repr__(self):
        try:
            return f'W"{self.plaintext.decode("utf-16le")}"'
        except Exception as e:
            try:
                return f'"{self.plaintext.decode()}"'
            except:
                return f'{{{hexlify(self.plaintext)}}}'


class QuickBindStrings:
    def __init__(self, path, wide_only=True):
        self.logger = logging.getLogger('QuickBind String Decryptor')
        self.wide_only = wide_only
        self.path = path
        with open(path, 'rb') as fp:
            self.data = fp.read()
        self.pe = pefile.PE(data=self.data)
        # 00007FF7B4654920 | 48:8D0D F9270100         | lea rcx,qword ptr ds:[<str_UA>]                    | rcx:L"185.49.70.98"
        self.ref_regex = re.compile(rb'\x48\x8D\x0D(?P<offset>...\x00)')

    def read_enc_string(self, offset):
        try:
            length = int.from_bytes(self.data[offset:offset+4], byteorder='little')
            key = self.data[offset+4:offset+8]
            ciphertext = self.data[offset+8:offset+8+length]
            end_offset = offset + length + 8
            if length > 1 and length < 0x400 and self.data[end_offset] == 0 and entropy(ciphertext) > 3:
                return QB_ENC_STR(self.data[offset:offset+8+length])
        except Exception as e:
            import traceback
            print(f'[!]\t{e}\n\t{traceback.format_exc()}')
            return None

    def dump_strings(self):
        for match in self.ref_regex.finditer(self.data):
            instr_offset = int.from_bytes(match.group('offset'), byteorder='little', signed=True)
            self.logger.debug(f'Instruction offset: 0x{instr_offset:08X}')
            rva = self.pe.get_rva_from_offset(match.start()) + 7 + instr_offset
            self.logger.debug(f'RVA: 0x{rva:08X}')
            offset = self.pe.get_offset_from_rva(rva)
            self.logger.debug(f'Offset: 0x{offset:08X}')
            qb_str = self.read_enc_string(offset)
            if qb_str:
                if not self.wide_only or self.wide_only and qb_str.check_wide():
                    print(f'\t0x{offset:08X}: {qb_str}')

def read_raw_struct(data, offset):
    #print(hexlify(data[offset:offset+0x20]))
    try:
        length = int.from_bytes(data[offset:offset+4], byteorder='little')
        key = data[offset+4:offset+8]
        ciphertext = data[offset+8:offset+8+length]
        end_offset = offset + length + 8
        if length > 1 and length < 0x400 and data[end_offset] == 0 and entropy(ciphertext) > 3:
            return QB_ENC_STR(data[offset:offset+8+length])
    except Exception as e:
        import traceback
        print(f'[!]\t{e}\n\t{traceback.format_exc()}')
        return None


def main():
    options = parse_args()
    configure_logger(options.verbose)

    for arg in options.files:
        parser = QuickBindStrings(arg, not options.all)
        print(arg)
        parser.dump_strings()

if __name__ == '__main__':
    main()
