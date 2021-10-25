import os
import fractions
import re
import struct
import pefile

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

def carve(buf):
    length = 0
    SECTION_SIZE = 0x28
    #print 'Searching %s byte buf for PE files' % (len(buf))
    found = []

    for i in [match.start() for match in re.finditer(b'MZ', buf)]:
        if i > len(buf) - 0x400: #1KB minimum
            continue
        #print 'Found MZ @ %x' % (i)
        pe_offset = struct.unpack('<L', buf[i+0x3c:i+0x3c+4])[0]
        #print 'PE OFFSET = %x' % (pe_offset)
        # PE header is typically within 1kb of the MZ header. We'll allow for 16MB which should
        # allow plenty of room for oddly formatted PE files
        HEADER = i + pe_offset
        #print 'POSSIBLE PE HEADER = %x' % (HEADER)
        
        if (HEADER +0x100) <= len(buf) and pe_offset > 0 and pe_offset < 0x1000000:
            if buf[HEADER] == ord('P') and buf[HEADER+1] == ord('E'):
                #print 'PE HEADER = 0x%x' % (HEADER)
                num_sections = struct.unpack('<H', buf[HEADER + 0x06:HEADER+0x06+2])[0]
                if num_sections < 1 or num_sections > 1000:
                    #print 'Invalid number of sections'
                    continue
                #print 'NUMBER OF SECTIONS: 0x%x' % (num_sections)
                SECTIONS = HEADER + 0xF8
                #print 'SECTIONS structure at 0x%x' % (SECTIONS)
                last_section = SECTIONS+(num_sections-1)*SECTION_SIZE
                #print 'LAST SECTION at 0x%x' % (last_section)
                raw_loc = struct.unpack('<L', buf[last_section + 0x14:last_section+ 0x14 + 4])[0]
                #print 'RAW LOCATION = 0x%x' % (raw_loc)
                raw_size = struct.unpack('<L', buf[last_section + 0x10:last_section+ 0x10 + 4])[0]
                #print 'RAW SIZE = 0x%x' % (raw_size)
                end_of_last_section = i + raw_loc + raw_size
                if end_of_last_section <= len(buf):
                    #found.append({'start': i, 'end': end_of_last_section, 'data': buf[i:end_of_last_section]})
                    found.append({'offset': i, 'data': buf[i:end_of_last_section]})

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

