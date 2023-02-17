import sys
import os
from pathlib import Path
from hashlib import md5
from argparse import ArgumentParser

repo_root = Path(os.path.realpath(__file__)).parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)

from utils import *

def parse_args():
    usage = "unpack.py [OPTION]... [FILES]..."
    arg_parser = ArgumentParser(description=usage)
    arg_parser.add_argument('-z', '--zero', action='store_true', default=False, 
        help='Also extract this file itself (trims appended data)')
    arg_parser.add_argument('files', nargs='+')
    return arg_parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    for path in args.files:
        with open(path, 'rb') as fp:
            data = fp.read()
        for pe in carve(data, match_at_start=args.zero):

            path = md5(pe['data']).hexdigest() + '.' + pe['ext'] 
            with open(path, 'wb') as fp:
                print(f'Found {pe["ext"]} at 0x{pe["offset"]:08X}. Writing to {path}')
                fp.write(pe['data'])

