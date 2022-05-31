import sys
import os
from pathlib import Path
from hashlib import md5


repo_root = Path(os.path.realpath(__file__)).parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)

from utils import *

if __name__ == '__main__':
    for arg in sys.argv[1:]:
        with open(arg, 'rb') as fp:
            data = fp.read()
        for pe in carve(data):

            path = md5(pe['data']).hexdigest() + '.' + pe['ext'] 
            with open(path, 'wb') as fp:
                print(f'Found {pe["ext"]} at 0x{pe["offset"]:08X}. Writing to {path}')
                fp.write(pe['data'])

