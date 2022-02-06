from binascii import hexlify, unhexlify

class CustomRC4:
    def __init__(self, key, size=0x100):
        self.key = key
        self.S = bytearray(size)
        self.KSA()
        
    
    def KSA(self):
        for i in range(len(self.S)):
            self.S[i] = i%0x100
        j = 0
        for i in range(len(self.S)):
            j = (j + self.S[i] + self.key[i % len(self.key)]) % len(self.S) # different mod needed?
            #print(f'Swapping s[j={j:02X}]and s[i={i:02X}]')
            self.S[i], self.S[j] = self.S[j], self.S[i] #swap    
        #print(hexlify(self.S[:0x400]))

    def decrypt(self, ciphertext):
        rtn = bytearray(len(ciphertext))
        j = 0
        _i = 0
        for i in range(0,len(ciphertext)):
            _i = (_i + 1)% len(self.S)
            _i = _i % 0x100
            j = ((j + self.S[_i]) % len(self.S)) % 0x100
            self.S[_i], self.S[j] = self.S[j], self.S[_i]
            #print(f'after swap: self.S[{_i:02X}] = {self.S[_i]:02X}, self.S[{j:02X}] = {self.S[j]:02X}')
            idx = (self.S[_i] +  self.S[j]) % len(self.S)
            k = self.S[idx % 0x100]
            rtn[i] = ciphertext[i] ^ k
            #print(f'j: 0x{j:08X} k: 0x{k:02X} ciphertext[{i:X}] = {ciphertext[i]:X} pt[{i:X}]: {rtn[i]:X}')
        return rtn

