import "pe"
import "math"

rule Classification_Resource_Crypter {

    meta:
        tlp = "green"
        author = "Jeremy Humble"
        date = "02/05/2021"
        description = "Observed being used to pack qakbot (a5856...), hancitor (559e5...), vidar (00473...), SquirrelWaffle (1c4d9...), TA505's Clop (3dff3...), Cobalt Strike Beacon (4c20de...) and likely others"
        hashes = "a58567fe17db5d4ee201dfeaa2466e06, 559e5048af99fae5c81b86555bdf99bb, 0047329ce9da9c0a23d033b97d91cd22, 1c4d98b8f4088fcd0acfad86d3dd66a2, 3dff3fb8daaa1669952b773fa4da5934, 4c20dee427c4e5f9ac9fdfaaeb480773"
    /*
        Leverage the weak "encryption" of the PE file embedded in resource

        Each dword of the encrypted resource is xor'd with a 4 byte key that is actually only 16 or 20 bits

        This leaves the high 12 bits of ciphertext unencrypted. Since we also know that the decrypted data
        always begins with "GetProcAddress", We know the "P" and half of the "t" will be in cleartext
        Same with "A" and part of "c", and so on.         
        
        In older variants the known plaintext is several bytes of 0x24. We leverage that in the same way in the second block of the condition

        00643A15 | 8B45 D4                  | mov eax,dword ptr ss:[ebp-2C]                   | *ciphertext
        00643A18 | 8918                     | mov dword ptr ds:[eax],ebx                      | ciphertext[i] += i
        00643A1A | 6A 00                    | push 0                                          |
        00643A1C | E8 0F2EFAFF              | call <JMP.&GetStretchBltMode>                   | junk, returns 0
        00643A21 | 8BD8                     | mov ebx,eax                                     | ebx = 0
        00643A23 | 8B45 C8                  | mov eax,dword ptr ss:[ebp-38]                   | key = 0x475
        00643A26 | 0345 A8                  | add eax,dword ptr ss:[ebp-58]                   | key += 0x8AEB3
        00643A29 | 2D 29090000              | sub eax,929                                     | key -= 0x929
        00643A2E | 0345 E4                  | add eax,dword ptr ss:[ebp-1C]                   | key += i
        00643A31 | 03D8                     | add ebx,eax                                     | ebx = 
        00643A33 | 6A 00                    | push 0                                          |
        00643A35 | E8 F62DFAFF              | call <JMP.&GetStretchBltMode>                   |
        00643A3A | 2BD8                     | sub ebx,eax                                     | nop
        00643A3C | 8B45 D4                  | mov eax,dword ptr ss:[ebp-2C]                   | *ciphertext
        00643A3F | 3118                     | xor dword ptr ds:[eax],ebx                      | ciphertext[i] ^= (i+const) (i = 0x0C, const = 0x8AA0B)
    */

    condition:
        for any i in (0..pe.number_of_resources - 1):
        (
            pe.resources[i].length > 0x4000 and                                 // resource large enough to contain encrypted PE file
            uint32(pe.resources[i].offset) > 0x4000 and                         // encoded length large enough to contain encrypted PE
            uint32(pe.resources[i].offset) <= pe.resources[i].length and        // encoded length <= size of this resource
            (
                uint32(pe.resources[i].offset+4) & 0xFFF00000 == 0x50700000 and // 4 bits of "t" and "P"
                uint32(pe.resources[i].offset+8) & 0xFFF00000 == 0x41600000 and // 4 bits of "r" and "A"
                uint32(pe.resources[i].offset+0x0C) & 0xFFF00000 == 0x65700000  // 4 bits of "r" and "e"
            ) or
            (
                uint32(pe.resources[i].offset+4) & 0xFFF00000 == 0x24200000 and 
                uint32(pe.resources[i].offset+8) & 0xFFF00000 == 0x24200000 and
                uint32(pe.resources[i].offset+0x0C) & 0xFFF00000 == 0x24200000
            )
        )
        /*
            TODO: Add additional detection around compile time
            Out of over a thousand samples from VT, every single one 
            was compiled 1992-06-20 or 1992-06-19 
        */
        
}
