import struct

with open("/home/john/Desktop/E0F_CTF/rev_Braided_Reality/braided_reality", "rb") as f:
    data = f.read()

# 1. Solve first 16 bytes via Stage 1 GF(2) linear system
eq_bytes = data[0x20c0 : 0x20c0 + 128 * 16]
target_bits_bytes = data[0x28c0 : 0x28c0 + 16]

matrix = []
target = []

for i in range(128):
    m0, m1 = struct.unpack("<QQ", eq_bytes[i*16 : (i+1)*16])
    row = []
    for b in range(64):
        row.append((m0 >> b) & 1)
    for b in range(64):
        row.append((m1 >> b) & 1)
    
    byte_idx = i >> 3
    bit_idx = i & 7
    t_bit = (target_bits_bytes[byte_idx] >> bit_idx) & 1
    
    matrix.append(row)
    target.append(t_bit)

n = 128
aug = [matrix[i] + [target[i]] for i in range(n)]

row = 0
for col in range(n):
    pivot = None
    for r in range(row, n):
        if aug[r][col] == 1:
            pivot = r
            break
    if pivot is None:
        continue
    aug[row], aug[pivot] = aug[pivot], aug[row]
    
    for r in range(n):
        if r != row and aug[r][col] == 1:
            for c in range(col, n + 1):
                aug[r][c] ^= aug[row][c]
    row += 1

solution1 = [aug[i][n] for i in range(n)]
first_half = bytearray(16)
for i in range(128):
    byte_idx = i // 8
    bit_idx = i % 8
    first_half[byte_idx] |= (solution1[i] << bit_idx)

flag_prefix = bytes(first_half)
print(f"Stage 1 solved: {flag_prefix.decode()}")

# 2. Stage 2 VM analysis
expected_R0, expected_R1 = struct.unpack("<QQ", data[0x49c4 : 0x49c4 + 16])

salt = data[0x20b0 : 0x20c0]
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
MASK64 = 0xffffffffffffffff

h = FNV_OFFSET
for b in flag_prefix:
    h = ((h ^ b) * FNV_PRIME) & MASK64
for b in salt:
    h = ((h ^ b) * FNV_PRIME) & MASK64

bytecode_enc = data[0x28d4 : 0x28d4 + 0x20f0]
MUL_CONST = 0x2545f4914f6cdd1d

state = h
decrypted_instructions = []

for instr_idx in range(len(bytecode_enc) // 16):
    chunk = bytecode_enc[instr_idx*16 : (instr_idx+1)*16]
    dec = bytearray(16)
    for byte_idx in range(16):
        rdx = (state ^ (state >> 12)) & MASK64
        rax = (rdx ^ ((rdx << 25) & MASK64)) & MASK64
        state = (rax ^ (rax >> 27)) & MASK64
        keystream_byte = (((state * MUL_CONST) & MASK64) >> 56) & 0xff
        dec[byte_idx] = chunk[byte_idx] ^ keystream_byte
    decrypted_instructions.append(bytes(dec))

def rol64(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64

def run_vm(input_bytes):
    regs = [0] * 8
    
    def get_bit(bit_idx):
        byte_idx = bit_idx // 8
        b_in_byte = bit_idx % 8
        return (input_bytes[byte_idx] >> b_in_byte) & 1

    for inst in decrypted_instructions:
        op = inst[0]
        ra = inst[1]
        rb = inst[2]
        imm32 = struct.unpack("<I", inst[4:8])[0]
        imm64 = struct.unpack("<Q", inst[8:16])[0]
        
        if op == 0x91: # CLEAR
            regs[ra] = 0
        elif op == 0x2d: # LOAD_INPUT
            val = struct.unpack("<Q", input_bytes[imm32:imm32+8])[0]
            regs[ra] = val
        elif op == 0xe7: # XOR_REG
            regs[ra] ^= regs[rb]
        elif op == 0x4b: # ROL_REG
            regs[ra] = rol64(regs[rb], imm32)
        elif op == 0xc3: # AND_IMM
            regs[ra] = regs[rb] & imm64
        elif op == 0x78: # XOR_IMM
            regs[ra] ^= imm64
        elif op == 0xa6: # BIT_XOR_MASK
            if get_bit(imm32):
                regs[ra] ^= imm64
        elif op == 0x5a: # HALT
            break
            
    return regs[0], regs[1]

zero_input = bytearray(32)
zero_input[:16] = flag_prefix
base_r0, base_r1 = run_vm(zero_input)

target_r0 = expected_R0 ^ base_r0
target_r1 = expected_R1 ^ base_r1

matrix2 = []
target_vector = []

for b in range(64):
    target_vector.append((target_r0 >> b) & 1)
for b in range(64):
    target_vector.append((target_r1 >> b) & 1)

for j in range(128):
    test_input = bytearray(zero_input)
    byte_idx = (128 + j) // 8
    bit_idx = (128 + j) % 8
    test_input[byte_idx] |= (1 << bit_idx)
    
    r0, r1 = run_vm(test_input)
    diff_r0 = r0 ^ base_r0
    diff_r1 = r1 ^ base_r1
    
    col = []
    for b in range(64):
        col.append((diff_r0 >> b) & 1)
    for b in range(64):
        col.append((diff_r1 >> b) & 1)
    matrix2.append(col)

A = [[matrix2[col][row] for col in range(128)] for row in range(128)]

n = 128
aug = [A[i] + [target_vector[i]] for i in range(n)]

row = 0
for col in range(n):
    pivot = None
    for r in range(row, n):
        if aug[r][col] == 1:
            pivot = r
            break
    if pivot is None:
        continue
    aug[row], aug[pivot] = aug[pivot], aug[row]
    
    for r in range(n):
        if r != row and aug[r][col] == 1:
            for c in range(col, n + 1):
                aug[r][c] ^= aug[row][c]
    row += 1

print(f"Stage 2 Matrix rank: {row}")
solution2 = [aug[i][n] for i in range(n)]

second_half = bytearray(16)
for i in range(128):
    byte_idx = i // 8
    bit_idx = i % 8
    second_half[byte_idx] |= (solution2[i] << bit_idx)

full_inner = flag_prefix + bytes(second_half)
flag = "e0f{" + full_inner.decode() + "}"
print(f"Stage 2 solved: {bytes(second_half).decode()}")
print(f"FLAG: {flag}")
