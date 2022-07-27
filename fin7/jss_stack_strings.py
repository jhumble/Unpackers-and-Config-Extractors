import regex as re
import sys
from binascii import hexlify



def extract(data):
    # Finds a sequence of stloc.0-3 or stloc.s ops that store 1-4 bytes in byte string to local vars. We'll save the strings and local vars for reconstruction later
    str_regex = re.compile(br'((\x20(?P<str>[\x00\x20-\x7E]{4})|\x1F(?P<str>[\x00\x20-\x7E])).{,16}?\x28[\x01-\x40]\x00\x00[\x01-\xFF](?P<var_idx>\x13[\x04-\x20]|[\x0A-\x0D])){3,}')

    rtn = []
    for match in str_regex.finditer(data):
        #print(hexlify(data[match.start():match.end()]))
        try:
            id_to_str = {}
            for i in range(0, len(match.captures('str'))):
                var_idx = match.captures('var_idx')[i]
                if len(var_idx) == 1: #stloc.0 - stloc.3
                    id_to_str[int.from_bytes(var_idx, byteorder='little') - 0x0A] = match.captures('str')[i]
                else:   # 2 byte form - stloc.s
                    id_to_str[var_idx[1]] = match.captures('str')[i]
            #print(id_to_str)
            # Build a regex to find the reconstruct function, will look like F(bytearray3, bytearray2, ... etc)
            # by grabbing the order the parameters are passed we can rebuild the string
            order_regex = re.compile(br'(([\x16-\x1E]|\x1F[\x09-\x10])(?P<idx>\x11[\x04-\x20]|[\x06-\x09])\xA2.{,4}){' + str(len(id_to_str)).encode() + b',}')
            order_match = order_regex.search(data[match.end():match.end()+100])

            order = []
            for i in range(0, len(order_match.captures('idx'))):
                order_idx = order_match.captures('idx')[i]
                if len(order_idx) == 1: #stloc.0 - stloc.3
                    order.append(int.from_bytes(order_idx, byteorder='little') - 0x06)
                else:   # 2 byte form - stloc.s
                    order.append(order_idx[1])

            #rebuild the string
            s = ""
            for idx in order:
                try:
                    s+= id_to_str[idx].decode()
                except Exception as e:
                    #print(f'Exception: {e}')
                    pass
            
            rtn.append({'offset': match.start(), 'string': s})
            #print(f'0x{match.start():08X}: "{s}"')
        except Exception as e:
            print(f'Failed to parse match: {match.groupdict()}: {e}')
            import traceback
            print(traceback.format_exc())
    return rtn


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        with open(arg, 'rb') as fp:
            data = fp.read()
        strings = extract(data)
        if strings:
            print(f'{arg}:')
            for string in strings:
                print(f'\t0x{string["offset"]:08X}:\t{string["string"]}')

