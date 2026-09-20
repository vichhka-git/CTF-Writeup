#!/usr/bin/env python3
"""
Solver for Containment Key Validator crackme.

Algorithm (from disassembly):
  - Input length must be 0x11 = 17 chars
  - edx starts at 0xa7 (from mov $0xffffffa7, %edx -> byte = 0xa7)
  - esi starts at 0
  - For i in 0..16:
      al = input[i]
      al = ROL8(al, 3)
      dl ^= sbox[al]     (sbox at 0x4020e0, 256 bytes)
      dl += (esi & 0xff)  (but esi is added to edx as 32-bit; we care about low byte)
      compare dl with expected[i]  (expected at 0x4020c0)
      esi += 0x1f

After validation, the flag is derived by XOR-ing input chars with data at 0x4020a0
using a modular index pattern (division by 17 to get index mod 17).
"""

# Expected bytes at 0x4020c0 (17 bytes)
expected = bytes([
    0x9a, 0x9c, 0x4c, 0x86, 0x16, 0xe8, 0x24, 0x46,
    0xcc, 0x8d, 0x45, 0x1e, 0x76, 0x8a, 0xba, 0xce,
    0x7c
])

# S-box at 0x4020e0 (256 bytes)
sbox_data = bytes([
    0x12, 0xf7, 0xb4, 0x18, 0x34, 0x46, 0xaf, 0xe1,
    0xa1, 0x17, 0x23, 0x4d, 0xa3, 0x5d, 0xf9, 0x8b,
    0x9f, 0x16, 0x95, 0xe0, 0x0c, 0xc9, 0xce, 0x00,
    0xe4, 0x2e, 0x24, 0x71, 0x67, 0x3e, 0xbb, 0x7e,
    0x86, 0xa4, 0x65, 0x40, 0xc2, 0x3b, 0x36, 0x84,
    0x2c, 0xa6, 0x0f, 0x7c, 0x48, 0x5e, 0x91, 0x06,
    0xbf, 0x0a, 0x7d, 0x38, 0xe5, 0x20, 0x93, 0xf8,
    0xa0, 0x25, 0x02, 0xcc, 0xc8, 0x73, 0xb3, 0x5f,
    0x39, 0x6e, 0xf5, 0xc7, 0x5c, 0x4f, 0x26, 0x97,
    0x77, 0x98, 0xfe, 0x10, 0x59, 0x7b, 0x9e, 0xc0,
    0x99, 0x2b, 0xd2, 0x14, 0x9d, 0x15, 0x6b, 0x4b,
    0xd1, 0xf6, 0x8c, 0xdf, 0x90, 0x9c, 0x50, 0x28,
    0xbd, 0x62, 0x41, 0x05, 0x7f, 0x89, 0x37, 0xfc,
    0xae, 0x82, 0xac, 0x9a, 0xe6, 0x51, 0x0e, 0x3c,
    0x94, 0xf1, 0x5b, 0x83, 0xfa, 0xc1, 0x45, 0x13,
    0x32, 0xfd, 0xd0, 0x5a, 0x72, 0x87, 0xb7, 0xb0,
    0x08, 0xba, 0x49, 0x74, 0x61, 0xd5, 0xb5, 0x09,
    0x6a, 0x2a, 0x69, 0xda, 0x0d, 0xde, 0xcf, 0xb2,
    0xf0, 0x75, 0x92, 0x96, 0xea, 0xdd, 0x8e, 0x31,
    0xbe, 0x1c, 0xd3, 0x8f, 0x79, 0xe3, 0x44, 0xed,
    0x8a, 0xe7, 0x80, 0xab, 0x63, 0x85, 0x70, 0xa7,
    0x52, 0x03, 0xa8, 0x76, 0x64, 0xb6, 0xb8, 0xb1,
    0xe2, 0x43, 0x1e, 0x53, 0x21, 0xef, 0xec, 0x9b,
    0x35, 0x55, 0x3d, 0x1b, 0xdc, 0xeb, 0x0b, 0xca,
    0x01, 0x56, 0x47, 0x1a, 0xd7, 0xcd, 0xd8, 0x66,
    0x3a, 0x42, 0x81, 0xdb, 0x07, 0xd6, 0x4a, 0xb9,
    0x2d, 0x2f, 0xe8, 0x7a, 0x8d, 0x60, 0xc5, 0x33,
    0xaa, 0x88, 0x22, 0x11, 0xcb, 0xfb, 0x3f, 0xd9,
    0x27, 0x57, 0x1d, 0xc6, 0xff, 0x19, 0xad, 0x4e,
    0x6f, 0xf3, 0xf4, 0xe9, 0xc3, 0x29, 0xee, 0xd4,
    0xa5, 0x54, 0xbc, 0xa2, 0x6c, 0x68, 0x78, 0xf2,
    0xc4, 0x4c, 0x30, 0x6d, 0xa9, 0x1f, 0x04, 0x58,
])

def rol8(val, n):
    """Rotate left 8-bit value by n bits"""
    val &= 0xff
    return ((val << n) | (val >> (8 - n))) & 0xff

def ror8(val, n):
    """Rotate right 8-bit value by n bits"""
    val &= 0xff
    return ((val >> n) | (val << (8 - n))) & 0xff

# Build inverse S-box: for each byte value b, sbox[b] = v => inv_sbox[v] = b
# Actually we need: given the needed sbox output, find the input index
# sbox is indexed by ROL8(char, 3), so we need to find which ROL8(char,3) value
# gives us the needed XOR value

# Solve character by character
# State: dl starts at 0xa7, esi starts at 0
dl = 0xa7
esi = 0
code = []

for i in range(17):
    target = expected[i]
    # We need: (dl ^ sbox[rol8(ch, 3)] + esi) & 0xff == target
    # First compute what (dl ^ sbox[rot_ch]) needs to be before adding esi:
    # (dl ^ sbox[rot_ch] + esi) & 0xff == target
    # So dl ^ sbox[rot_ch] == (target - esi) & 0xff
    needed_xor_result = (target - esi) & 0xff
    # sbox[rot_ch] == dl ^ needed_xor_result
    needed_sbox_val = dl ^ needed_xor_result

    # Find rot_ch such that sbox[rot_ch] == needed_sbox_val
    found = False
    for rot_ch in range(256):
        if sbox_data[rot_ch] == needed_sbox_val:
            # rot_ch = ROL8(ch, 3), so ch = ROR8(rot_ch, 3)
            ch = ror8(rot_ch, 3)
            if 0x20 <= ch <= 0x7e:  # printable ASCII
                code.append(ch)
                # Update dl for next iteration
                dl = (dl ^ sbox_data[rot_ch]) & 0xff
                dl = (dl + esi) & 0xff
                found = True
                break
    if not found:
        # Try all rot_ch values including non-printable results
        for rot_ch in range(256):
            if sbox_data[rot_ch] == needed_sbox_val:
                ch = ror8(rot_ch, 3)
                code.append(ch)
                dl = (dl ^ sbox_data[rot_ch]) & 0xff
                dl = (dl + esi) & 0xff
                found = True
                break
    if not found:
        print(f"Failed at position {i}")
        break
    
    esi = (esi + 0x1f) & 0xffffffff  # esi is 32-bit but we care about low byte for add

clearance_code = bytes(code)
print(f"Clearance code: {clearance_code}")
print(f"Clearance code (hex): {clearance_code.hex()}")

# Now derive the flag
# The flag derivation loop (at 0x40116c):
# - Prints "ACCESS GRANTED.\nContainment token: "
# - For rbx from 0 to 0x1a (27 iterations, 0x1b = 27):
#   - rax = rbx
#   - mul rbp (rbp = 0xf0f0f0f0f0f0f0f1) - this is division by 17
#   - rax = rdx >> 4 (i.e., rbx / 17)
#   - rdx = rdx & ~0xf, then rdx + rax => effectively floor(rbx/17)*17... 
#   - Actually let me re-read: rdx = (rbx * 0xf0f0f0f0f0f0f0f1) >> 64, 
#     then and $0xfffffffffffffff0 => rdx & ~0xf, shr $4 => rax = rdx>>4,
#     add rax,rdx... 
#   Let me just compute: this computes rbx % 17
#   rax = rbx
#   mul rbp => rdx:rax = rbx * 0xf0f0f0f0f0f0f0f1
#   rax = rdx >> 4  (high 64 bits >> 4)  
#   rdx = (rdx & ~0xf)  # rdx & 0xfffffffffffffff0
#   Wait, let me re-read:
#   401192: mul %rbp          => rdx = high(rbx * rbp)
#   401195: mov %rdx,%rax     => rax = rdx
#   401198: and $0xfffffffffffffff0,%rdx  => rdx = rdx & ~0xf
#   40119c: shr $0x4,%rax     => rax = rax >> 4
#   4011a0: add %rax,%rdx     => rdx = (rdx & ~0xf) + (rax >> 4)
#   Hmm actually:
#   rdx = high64(rbx * 0xf0f0f0f0f0f0f0f1) 
#   rax = rdx >> 4 = floor(rbx / 17) approximately
#   rdx_masked = rdx & ~0xf
#   rdx_final = rdx_masked + rax
#   Wait, that's: rdx = (rdx & ~0xf) + (rdx >> 4) which is rdx * (16+1)/16... 
#   Actually 0xf0f0f0f0f0f0f0f1 = 2^64 - (2^64-1)/17 + 1? Let me just compute rbx % 17.
#   
#   rax = rbx - rdx_final  (4011aa: sub %rdx,%rax where rax=rbx from 4011a3)
#   Then movzbl 0x10(%rsp, %rax, 1) => input[rax] where rax = rbx % 17
#   XOR with 0x40209f + rbx+1 => data at 0x4020a0[rbx]
#   
# Actually from: 
#   4011a3: mov %rbx,%rax      => rax = rbx (original loop counter)
#   4011a6: add $0x1,%rbx      => rbx++ (for next iteration, but rbx WAS i before increment)
#   4011aa: sub %rdx,%rax      => rax = original_rbx - rdx_final = i - floor(i*magic) 
#   4011ad: movzbl 0x10(%rsp,%rax,1)  => char at input[rax]  (rax = i % 17)
#   4011b2: xor 0x40209f(%rbx),%dil   => XOR with byte at 0x40209f + new_rbx = 0x4020a0 + original_i
# So: flag_char[i] = input[i % 17] ^ xor_table[i]  for i = 0..26 (27 chars)

# The magic constant 0xf0f0f0f0f0f0f0f1 for unsigned division:
# Let's verify: this is indeed for division by 17
# 2^64 / 17 = 0x0F0F0F0F0F0F0F0F.xxx, and 0xf0f0f0f0f0f0f0f1 is different...
# Actually the mul instruction gives rdx = high 64 bits of (rax * 0xf0f0f0f0f0f0f0f1)
# 0xf0f0f0f0f0f0f0f1 = 0x10000000000000000 - 0x0f0f0f0f0f0f0f0f = 
#   17361641481138401521 decimal
# 2^64 / 17 ≈ 1085102592571150095.06
# Hmm let me just trust that this computes i % 17 and verify.

# XOR table at 0x4020a0 (27 bytes)
xor_table = bytes([
    0x31, 0x58, 0x33, 0x23, 0x48, 0x3d, 0x4f, 0x60,
    0x2a, 0x6f, 0x4b, 0x78, 0x00, 0x3d, 0x4f, 0x6c,
    0x5a, 0x3c, 0x6b, 0x27, 0x2a, 0x44, 0x7e, 0x58,
    0x3e, 0x36, 0x4d
])

# Let me verify the modular arithmetic by just computing i % 17
def compute_index(i):
    """Compute i % 17 using the binary's magic division"""
    magic = 0xf0f0f0f0f0f0f0f1
    product = i * magic
    rdx = (product >> 64) & 0xffffffffffffffff
    rax = rdx >> 4
    rdx_masked = rdx & 0xfffffffffffffff0
    rdx_final = (rdx_masked + rax) & 0xffffffffffffffff
    result = i - rdx_final
    return result

# Verify
for i in range(27):
    assert compute_index(i) == i % 17, f"Mismatch at {i}: {compute_index(i)} vs {i % 17}"

print("\nFlag derivation:")
flag_chars = []
for i in range(27):
    idx = i % 17
    ch = clearance_code[idx] ^ xor_table[i]
    flag_chars.append(ch)
    
flag = bytes(flag_chars)
print(f"Flag: {flag}")
