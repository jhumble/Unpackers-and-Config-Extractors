import re
import sys
import pefile
from binascii import hexlify


code = """
00007FFD57E01E70 | 45:33C0                  | xor r8d,r8d                                                    |
00007FFD57E01E73 | 48:8905 06240000         | mov qword ptr ds:[7FFD57E04280],rax                            |
00007FFD57E01E7A | 4C:8D0D 5F220000         | lea r9,qword ptr ds:[<ciphertext1>]                                   | ciphertext
00007FFD57E01E81 | 4C:8BD0                  | mov r10,rax                                                    |
00007FFD57E01E84 | 48:8BC8                  | mov rcx,rax                                                    |
00007FFD57E01E87 | 4C:8D1D 72E1FFFF         | lea r11,qword ptr ds:[<pe_load_addr>]                          | r11:pe_load_addr
00007FFD57E01E8E | 4D:2BD1                  | sub r10,r9                                                     | r9:ciphertext1
00007FFD57E01E91 | BB 43082184              | mov ebx,84210843                                               |
00007FFD57E01E96 | 41:8D78 01               | lea edi,qword ptr ds:[r8+1]                                    |
00007FFD57E01E9A | 49:63C0                  | movsxd rax,r8d                                                 |
00007FFD57E01E9D | 42:8A8418 C0400000       | mov al,byte ptr ds:[rax+r11+40C0]                              | key at load_addr + 0x40C0
00007FFD57E01EA5 | 41:3201                  | xor al,byte ptr ds:[r9]                                        | r9:ciphertext1
00007FFD57E01EA8 | 43:88440A 01             | mov byte ptr ds:[r10+r9+1],al                                  |
00007FFD57E01EAD | 4C:03CF                  | add r9,rdi                                                     | r9:ciphertext1
00007FFD57E01EB0 | 41:FFC0                  | inc r8d                                                        |
00007FFD57E01EB3 | 8BC3                     | mov eax,ebx                                                    |
00007FFD57E01EB5 | 41:F7E8                  | imul r8d                                                       |
00007FFD57E01EB8 | 41:03D0                  | add edx,r8d                                                    |
00007FFD57E01EBB | C1FA 04                  | sar edx,4                                                      |
00007FFD57E01EBE | 8BC2                     | mov eax,edx                                                    |
00007FFD57E01EC0 | C1E8 1F                  | shr eax,1F                                                     | ciphertext size
00007FFD57E01EC3 | 03D0                     | add edx,eax                                                    |
00007FFD57E01EC5 | 6BC2 1F                  | imul eax,edx,1F                                                | ciphertext size
"""

pattern = re.compile(rb'\x4C?\x8D[\x05\x0D\x15\x1D\x2D\x35\x3D](?P<ciphertext_offset>....).{,64}\x8A[\x84\x8C\x94\x9C].(?P<key_offset>..\x00\x00).{,64}\x6B[\xC0-\xFF](?P<ciphertext_length>.)', re.DOTALL)

with open(sys.argv[1], 'rb') as fp:
    data = fp.read()
pe = pefile.PE(data=data)

for match in pattern.finditer(data):
    #read encrypted config
    match_rva = pe.get_rva_from_offset(match.span('ciphertext_offset')[0])
    print(f'ciphertext va: 0x{match_rva:08X}')
    ciphertext_rva = match_rva + int.from_bytes(match.group('ciphertext_offset'), byteorder='little') + 4 #capture group starts at the offset part of the instr which is 4 bytes
    print(f'ciphertext rva: 0x{ciphertext_rva:08X}')
    ciphertext_raw_offset = pe.get_offset_from_rva(ciphertext_rva)
    print(f'ciphertext offset: 0x{ciphertext_raw_offset:08X}')

    ciphertext_length = int.from_bytes(match.group('ciphertext_length'), byteorder='little')
    print(f'Ciphertext length: 0x{ciphertext_length:08X}')

    ciphertext = bytearray(data[ciphertext_raw_offset:ciphertext_raw_offset+ciphertext_length])
    print(f'Key: {hexlify(ciphertext)}')
    
    #read key
    key_rva = int.from_bytes(match.group('key_offset'), byteorder='little')
    print(f'key rva: 0x{key_rva:08X}')
    key_raw_offset = pe.get_offset_from_rva(key_rva)
    print(f'key raw addr: 0x{key_raw_offset:08X}') 
    
    #Just guess a length for now and trim it later
    key = bytearray(data[key_raw_offset:key_raw_offset+0x80])


    #xor decrypt the config
    config = bytearray([key[i] ^ ciphertext[i%len(ciphertext)] for i in range(len(key))])
    config = bytes(config).split(b'\x00')[0].decode('ascii')
    ips = config.split('|')

    #decrypt the other blob at beginning of data section:
    port = '???'
    for section in pe.sections:
        if b'.data' in section.Name:
            data_section = bytearray(pe.get_data(section.VirtualAddress, section.SizeOfRawData))
            blob = data_section[:0x80]
            blob = bytearray([blob[i] ^ key[i%len(ciphertext)] for i in range(len(blob))])
            #idk what else is in here, but port is the first WORD
            port = int.from_bytes(blob[:2], byteorder='big')
    print('CONFIG:')
    print([ip + ':' + str(port) for ip in ips])
        

