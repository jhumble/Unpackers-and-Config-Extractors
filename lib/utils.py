import sys
import os
import fractions
import datetime
import re
import struct
import pefile
import logging
import yara
import logging
import numpy as np
from hashlib import md5
from time import time, sleep
from multiprocessing import Pool, cpu_count
from binascii import hexlify

def configure_logger(log_level):
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], 
            format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s')

def get_compile_time(pe):
    ts = int(pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split()[0], 16)
    utc_time = datetime.datetime.utcfromtimestamp(ts)
    t_delta = (datetime.datetime.today() - utc_time).days
    return utc_time.strftime(f"%Y-%m-%dT%H:%M:%S")

def rol(dword, i):
    return ((dword << i) & 0xffffffff) | (dword >> (32-i) ) 

def ror(dword, i):
    return rol(dword, 32-i)

def xor(plaintext, key):
    rtn = bytearray(len(plaintext))
    for i in range(len(plaintext)):
        rtn[i] = plaintext[i] ^ key[i%len(key)]
    return rtn

def get_section(path, section_name):
    with open(path, 'rb') as fp:
        data = fp.read()

    pe = pefile.PE(path)
    for section in pe.sections:
        if section_name in section.Name:
            return pe.get_data(section.VirtualAddress, section.SizeOfRawData)

    raise Exception(f'Failed to find section {section_name}')


def nearest_fractions(a,b, max_fractions=10, window=10000, step=.05):
    found = []
    for i in range(0, window):
        try:
            frac = fractions.Fraction((a+step*i)/b).limit_denominator(0xFF)
            if frac not in found:
                found.append(frac)
            frac = fractions.Fraction((a-step*i)/b).limit_denominator(0xFF)
            if frac not in found:
                found.append(frac)
            if len(found) >= max_fractions:
                #print(f'Fractions nearest to (a/b) = {found}')
                return list(found)
        except ZeroDivisionError:
            continue
    #print(f'Fractions nearest to (a/b) = {found}')
    return list(found)


def data_to_dwords(data):
    if len(data)%4 != 0:
        data = data[:-(len(data)%4)]
    fmt = '<' + 'I'*(len(data)//4)
    return struct.unpack(fmt, data)

def get_section_as_dwords(path, section_name):
    data = get_section(path, section_name)
    fmt = '<' + 'I'*(len(data)//4)
    return struct.unpack(fmt, data)

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i+n]

def recursive_all_files(directory, ext_filter=None):
    all_files = []
    dir_content = []
    ret = []

    if os.path.isfile(directory):
        dir_content = [directory]
    else:
        try:
            dir_content = os.listdir(directory)
        except Exception as e:
            return []

    for f in dir_content:
        if os.path.isdir(directory):
            rel_path = os.path.join(directory,f)
        else:
            rel_path = f
        if os.path.isfile(rel_path):
            all_files.append(rel_path)
        elif f == '.' or f == '..':
            pass
        else:
            all_files += recursive_all_files(rel_path,ext_filter)

    for f in all_files:
        if (ext_filter is None or os.path.splitext(f)[1] == '.%s' % ext_filter):
            ret.append(f)
    return ret

def carve(buf, match_at_start=False):
    logger = logging.getLogger('PE Carver')
    found = []
    for i in [match.start() for match in re.finditer(b'MZ', buf)]:
        if i == 0 and not match_at_start: # Ignore matches at offset 0 (regular PE files)
            continue
        logger.debug(f'MZ at {i:08X}')
        pe_offset = i + int.from_bytes(buf[i+0x3C:i+0x3C+4], byteorder='little')
        if pe_offset + 1 > len(buf):
            logger.debug(f'PE offset ({pe_offset:08X}) falls outside of buffer')
            continue
        logger.debug(f'PE header at {pe_offset:08X}: {hexlify(buf[pe_offset:pe_offset+2])}')
        if buf[pe_offset] == 0x50 and buf[pe_offset+1] == 0x45: # "PE"
            logger.debug(f'Found potential PE header at 0x{i:08X}. DOS: {hexlify(buf[i:i+0x3C+4])}, PE: {hexlify(buf[pe_offset:pe_offset+0x40])}')
            try:
                pe = pefile.PE(data=buf[i:])
            except:
                continue
            #print(f'Found PE file at offset 0x{i:X}')
            found.append({'offset': i, 'data': pe.trim(), 'ext': get_ext(pe) })
    return found


def get_ext(pe):
    # https://github.com/MalwareLu/tools/blob/master/pe-carv.py
    'returns ext of the file type using pefile'
    if pe.is_dll() == True:
        return 'dll'
    if pe.is_driver() == True:
        return 'sys'
    if pe.is_exe() == True:
        return 'exe'
    else:
        return 'bin'

def iter_resources(pe):
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if rsrc.name:
                name = f'{rsrc.name}/{entry.name}'
            else:
                name = entry.name
            offset = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            #print(f'{size:08X}')
            if entry.directory.entries[0].name:
                _id = entry.directory.entries[0].name
            else:
                _id = '0x{:X}'.format(entry.directory.entries[0].id)
            #print(f'{offset:08X} {size:08X}')
            data = bytearray(pe.get_memory_mapped_image()[offset:offset+size])
            #print(f'Found resource {name}/{_id}, length: {len(data):08X}')
            yield name, _id, data


def human_size(nbytes):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    if nbytes == 0: return '0 B'
    i = 0
    while nbytes >= 1024 and i < len(suffixes)-1:
        nbytes /= 1024.
        i += 1
    f = ('%s' % float('%.3g' % nbytes)).rstrip('0').rstrip('.')
    return '%s %s' % (f, suffixes[i])

def compile_rule(rulefile, include_compiled=False):
    try:
        key = os.path.splitext(os.path.split(rulefile)[1])[0]
        start = time()
        rule = yara.compile(filepaths={key: rulefile})
        rtn = {'key': key, 'rulefile': rulefile, 'compile_time': time() - start}
        if include_compiled:
            rtn['rule'] = rule
        return rtn
    except Exception as e:
        print('rule %s failed to compile! Error: %s' % (rulefile, e))
    return None

def test_compile(file_list, individual_rules=False):
    rtn = {}
    # Can't use a pool since we can't pickle the compiled rule objects to send across the queue
    if individual_rules:
        for f in file_list:
            compiled = compile_rule(f, include_compiled=True)
            if compiled:
                rtn[compiled['key']] = compiled
    
    else:
        pool = Pool(4)
        results = pool.map(compile_rule, file_list)
        for item in results:
            if item:
                rtn[item['key']] = item['rulefile']
    return rtn

def rules_hash(file_list):
    rtn = {}
    to_hash = ""
    for path in sorted(file_list):
        to_hash += '%s%s' % (os.path.basename(path),str(os.path.getmtime(path)))
    return md5(to_hash.encode()).hexdigest() 

def build_rules(signature_dir, profile_rules=False):
    logger = logging.getLogger('Yara Compiler')
    file_list = recursive_all_files(signature_dir,'yar')
    _hash = rules_hash(file_list)
    if profile_rules:
        return test_compile(file_list, individual_rules=True)
    path = os.path.join('/tmp/', '%s.py3.cyar' % (_hash))
    if os.path.isfile(path):
        logger.debug('Up to date compiled rules already exist at %s. Using those' % (path))
        return yara.load(path)

    start = time()
    rulefile_paths = test_compile(file_list)
    elapsed = time() - start
    logger.debug('Test compiled %s rules in %s seconds.' % (len(rulefile_paths), round(elapsed,2)))

    start = time()
    try:
        compiled_rules = yara.compile(filepaths=rulefile_paths)
    except Exception as e:
        logger.error('Exception compiling rules: %s' % (e))
    elapsed = time() - start
    try:
        compiled_rules.save(path)
        os.chmod(path, 0o666)
    except Exception as e:
        logger.debug('Failed to save compiled rules %s: %s' % (path,e))
    compiled_size = os.stat(path).st_size

    logger.debug('Compiled %s rules in %s seconds.' % (len(rulefile_paths), round(elapsed,2)))
    logger.debug('Compiled rule size is %s' % (human_size(compiled_size,)))
    return compiled_rules

def substring_sieve(string_list, string_list2=None):
    """
        1 arg: remove any string that is a substring of any other
        2 args: remove any string form list1 that is a substring of any string in list 2
    """
    if not string_list2:
        string_list.sort(key=lambda s: len(s), reverse=True)
        out = []
        for s in string_list:
            if not any([s in o for o in out]):
                out.append(s)
        return out
    else:
        out = []
        for s in string_list:
            if not any([s in o for o in string_list2]):
                out.append(s)
        return out
        
def spaced_hex(data):
    return b' '.join(hexlify(data)[i:i + 2] for i in range(0, len(hexlify(data)), 2)).decode('utf-8')

class colors:
    if sys.stdout.isatty():
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
    else:
        HEADER = ''
        BLUE = ''
        GREEN = ''
        YELLOW = ''
        RED = ''
        ENDC = ''
        BOLD = ''
        UNDERLINE = ''


def dump_regs(emu):
    regs = emu.get_register_state()

    if not hasattr(dump_regs, 'regs'):
        dump_regs.regs = regs

    rtn = ''

    # build string in order
    for reg, val in regs.items():
        #val = '{}: {}    '.format(reg.upper(), regs[reg])
        val = f'{reg.upper()}: {dump_regs.regs[reg]} -> {regs[reg]}'

        if regs[reg] != dump_regs.regs[reg] and reg != 'rip' and reg != 'eip':
            rtn += colors.RED + val + colors.ENDC
        #rtn += val
        #else:
        #    rtn += val

    dump_regs.regs = regs

    return rtn

#filter yara matches according to filters defined in metadata
def filter_matches(matches, fname):
    rtn = [match for match in matches if not filter_match(match, fname)]
    #print(f'{[m.rule for m in matches]} -> {[m.rule for m in rtn]}')
    return rtn

def filter_match(match, fname):
    for key in ['file_name', 'full_path']:
        if key in match.meta:
            #print(f'Filtering "{fname}" on {key}')
            passed = False         
            for search in match.meta[key].lower().split(','):
                negate = False
                if search.startswith('!'):
                    search = search[1:]
                    negate = True
                if 'sub:' in search:
                    ns = search.replace('sub:', '')
                    #print(f'sub Filtering "{fname}" on {key} with substring {ns}')
                    if ns in fname.lower() and not negate or (not ns in fname.lower() and negate):
                        passed = True
                else:
                    if search == fname.lower() and not negate or (search != fname.lower() and negate):
                        passed = True
            if not passed:
                #print(f'meta filtered {fname} on {key}')
                return True

    if 'file_ext' in match.meta:
        passed = False
        for search in match.meta['file_ext'].lower().split(','):
            negate = False
            if search.startswith('!'):
                search = search[1:]
                negate = True
            if fname.lower().endswith(search) and not negate or (not fname.lower().endswith(search) and negate):
                passed = True
        if not passed:
            #print(f'meta filtered {fname} on file_ext')
            return True
    return False
