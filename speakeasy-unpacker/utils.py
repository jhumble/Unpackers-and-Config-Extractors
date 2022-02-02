import logging
import os
import fractions
import re
import struct
import pefile

def configure_logger(log_level):
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3) #clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level], 
            format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s')

def rol(dword, i):
    return ((dword << i) & 0xffffffff) | (dword >> (32-i) ) 

def ror(dword, i):
    return rol(dword, 32-i)

def get_section(path, section_name):
    with open(path, 'rb') as fp:
        data = fp.read()

    pe = pefile.PE(path)
    for section in pe.sections:
        if section_name in section.Name:
            return pe.get_data(section.VirtualAddress, section.SizeOfRawData)

    raise Exception(f'Failed to find section {section_name}')


def nearest_fractions(a,b, max_fractions=10, window=10000, step=.1):
    found = set()
    for i in range(0, window):
        try:
            frac = fractions.Fraction((a+step*i)/b).limit_denominator(0xFF)
            if frac not in found:
                found.add(frac)
            frac = fractions.Fraction((a-step*i)/b).limit_denominator(0xFF)
            if frac not in found:
                found.add(frac)
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

def carve(buf):
    found = []
    for i in [match.start() for match in re.finditer(b'MZ', buf)]:
        if i == 0: # Ignore matches at offset 0 (regular PE files)
            continue
        try:
            pe = pefile.PE(data=buf[i:])
        except:
            continue
        #print(f'Found PE file at offset 0x{i:X}')
        found.append({'offset': i, 'data': pe.trim(), 'ext': get_ext(pe) })
    return found

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



# https://stackoverflow.com/questions/5081657/how-do-i-prevent-a-c-shared-library-to-print-on-stdout-in-python
import os
import sys
from contextlib import contextmanager

@contextmanager
def stdout_redirected(to=os.devnull):
    '''
    import os

    with stdout_redirected(to=filename):
        print("from Python")
        os.system("echo non-Python applications are also supported")
    '''
    fd = sys.stdout.fileno()

    ##### assert that Python and C stdio write using the same file descriptor
    ####assert libc.fileno(ctypes.c_void_p.in_dll(libc, "stdout")) == fd == 1

    def _redirect_stdout(to):
        sys.stdout.close() # + implicit flush()
        os.dup2(to.fileno(), fd) # fd writes to 'to' file
        sys.stdout = os.fdopen(fd, 'w') # Python writes to fd

    with os.fdopen(os.dup(fd), 'w') as old_stdout:
        with open(to, 'w') as file:
            _redirect_stdout(to=file)
        try:
            yield # allow code to be run with the redirected stdout
        finally:
            _redirect_stdout(to=old_stdout) # restore stdout.
                                            # buffering and flags such as
                                            # CLOEXEC may be different


