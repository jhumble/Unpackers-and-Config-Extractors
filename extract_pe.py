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

if __name__ == '__main__':
    options = parse_args()
    configure_logger(options.verbose)
    for path in options.files:
        with open(path, 'rb') as fp:
            data = fp.read()
        for pe in carve(data, match_at_start=options.zero):

            path = md5(pe['data']).hexdigest() + '.' + pe['ext'] 
            with open(path, 'wb') as fp:
                print(f'Found {pe["ext"]} at 0x{pe["offset"]:08X}. Writing to {path}')
                fp.write(pe['data'])

