from ghidra.program.model.listing import CodeUnit

from ghidra.program.model.lang import Register
from ghidra.program.model.scalar import Scalar
from binascii import hexlify
from ghidra.program.model.symbol import SourceType

import struct

def non_self_xor(ins):
    if 'xor' in ins.getMnemonicString().lower() and ins.getRegister(0) and ins.getRegister(1) and ins.getRegister(0) != ins.getRegister(1):
        return True
    return False

def store_byte(ins):
    if ins.getMnemonicString().lower() == 'movzx':
        return True

def halve(s):
    a = s[len(s)/2:]
    b = s[:len(s)/2]
    return a,b

def process_func(func, name=None):
    stack_const = None
    xor = False
    store_byte = False
    ciphertext = bytearray(100)

    entryPoint = func.getEntryPoint()
    instructions = listing.getInstructions(func.getBody(), True)
    for inst in instructions:
        #print "%08X: %s" % (inst.getAddress().getOffset(), inst.toString())
        if inst.getMnemonicString().lower() == 'mov' and inst.getOperandRefType(0).isWrite():
            op1 = inst.getOpObjects(0)
            op2 = inst.getOpObjects(1)
            # print('op2 types: %s' % ([str(type(item)) for item in op2]))
            if len(op1) == 2 and isinstance(op1[0], Register) and isinstance(op1[1], Scalar) and len(op2) == 1 and isinstance(op2[0], Scalar):
                offset = op1[1].getUnsignedValue()
                size = op2[0].bitLength()/8
                ciphertext[offset:offset+size] = struct.pack('<I', op2[0].getUnsignedValue()) 
            
        #print(inst.getInputObjects())
        if non_self_xor(inst):
            #print "%08X: %s" % (inst.getAddress().getOffset(), inst.toString())
            xor = True

    if xor: 
        import re
        regex = re.compile('([^\x00][^\x00]){3,}')
        for match in regex.finditer(ciphertext):
            a, b = halve(bytearray(match.group()))
            plaintext = bytearray(len(a))
            for i in range(0, len(a)):
                plaintext[i] = a[i] ^ b[i]
            print("%s: xor: %s, ciphertext: %s" % (name, xor, hexlify(ciphertext[:32])))
            print(plaintext)

listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True) # True mean iterate forward
for func in funcs:
    #print('Processing %s' % (func.getName()))
    process_func(func, func.getName()) 
