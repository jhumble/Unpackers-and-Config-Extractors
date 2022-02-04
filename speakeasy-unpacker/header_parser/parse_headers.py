import re
import json
import os
import sys
from pathlib import Path

repo_root = Path(os.path.realpath(__file__)).parent.parent.parent.absolute()
lib = os.path.join(repo_root, 'lib')
sys.path.append(lib)

from utils import *

def main():
    func_to_args = {}
    header_paths = recursive_all_files('winapi', 'h')
    regex = re.compile(r'WINAPI.*?(?P<name>[0-9A-Za-z_]+)\((?P<args>[^)]*)\)')
    for path in header_paths:
        try:
            with open(path, 'r') as fp:
                lines = fp.read().splitlines()
            for line in lines:
                match = regex.search(line)
                if match:
                    func_to_args[match.group('name')] = match.group('args').count(',') + 1
                    #print(match.groupdict())
        except Exception as e:
            print(f'[!]\tParsing failed on {path}: {e}')
    with open('winfuncs.json', 'w') as fp:
        json.dump(func_to_args, fp)

if __name__ == '__main__':
    main()
