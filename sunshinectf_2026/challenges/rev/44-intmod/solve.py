def rol(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & 0xffffffffffffffff

def ror(x, n):
    n &= 63
    return ((x >> n) | (x << (64 - n))) & 0xffffffffffffffff

MASK = 0xffffffffffffffff

with open("agent_workspace/combined_trace.txt") as f:
    lines = f.readlines()

pairs = []
curr_op5 = {}
for line in lines:
    if "op=5" in line:
        parts = line.split()
        rC = int(parts[5].split("=")[1])
        imm = int(parts[7].split("=")[1], 16)
        base = imm & 0xffffffff
        offset = (imm >> 32) & 0xffffffff
        curr_op5[rC] = (base, offset)
    elif "op=6" in line:
        parts = line.split()
        rC = int(parts[5].split("=")[1])
        imm = int(parts[7].split("=")[1], 16)
        base, offset = curr_op5[rC]
        target = (imm + offset) % 65521
        pairs.append((base % 65521, target))

P = 65521
N = 40
matrix = []
for base, target in pairs:
    row = [pow(base, j, P) for j in range(N)]
    row.append(target)
    matrix.append(row)

for col in range(N):
    pivot_row = None
    for r in range(col, N):
        if matrix[r][col] % P != 0:
            pivot_row = r
            break
    matrix[col], matrix[pivot_row] = matrix[pivot_row], matrix[col]
    inv = pow(matrix[col][col], -1, P)
    for j in range(col, N + 1):
        matrix[col][j] = (matrix[col][j] * inv) % P
    for r in range(N):
        if r != col and matrix[r][col] != 0:
            factor = matrix[r][col]
            for j in range(col, N + 1):
                matrix[r][j] = (matrix[r][j] - factor * matrix[col][j]) % P

sol = bytes([matrix[r][N] for r in range(N)])
regs = [int.from_bytes(sol[i*8:(i+1)*8], "little") for i in range(5)]

vm_steps = {}
for line in lines:
    if line.startswith("VM "):
        parts = line.split()
        step_num = int(parts[1].rstrip(":"))
        if step_num < 45:
            op = int(parts[2].split("=")[1])
            rA = int(parts[3].split("=")[1])
            rB = int(parts[4].split("=")[1])
            shift = int(parts[6].split("=")[1])
            imm = int(parts[7].split("=")[1], 16)
            vm_steps[step_num] = (op, rA, rB, shift, imm)

jit_ops = {
    0: ("xor", 2, 0),
    1: ("ror", 4, 45),
    2: ("add", 3, 0, 13),
    3: ("mul", 1, 0xc2b2ae3d27d4eb4f),
    4: ("swap", 0, 1),
    5: ("xor", 3, 1),
    6: ("ror", 0, 53),
    7: ("add", 4, 2, 43),
    8: ("mul", 3, 0x85ebca77c2b2ae63),
    9: ("swap", 3, 2),
    10: ("xor", 1, 2),
    11: ("ror", 4, 27),
    12: ("add", 0, 2, 5),
    13: ("mul", 1, 0x94d049bb133111eb),
    14: ("swap", 1, 2),
    15: ("xor", 3, 4),
    16: ("ror", 2, 55),
    17: ("add", 2, 0, 23),
    18: ("mul", 4, 0xd6e8feb86659fd93),
    19: ("swap", 4, 0),
    20: ("xor", 0, 1),
    21: ("ror", 2, 57),
    22: ("add", 3, 4, 11),
    23: ("mul", 1, 0xe7037ed1a0b428db),
    24: ("swap", 1, 4),
    25: ("xor", 3, 0),
    26: ("ror", 1, 47),
    27: ("add", 2, 1, 19),
    28: ("mul", 3, 0x589965cc75374cc3),
    29: ("swap", 3, 1),
    30: ("xor", 1, 4),
    31: ("ror", 2, 51),
    32: ("add", 1, 0, 3),
    33: ("mul", 4, 0xeb44accab455d165),
    34: ("swap", 4, 0),
    35: ("xor", 0, 3),
    36: ("ror", 4, 43),
    37: ("add", 0, 3, 27),
    38: ("mul", 4, 0xc6bc279692b5c323),
    39: ("swap", 4, 3),
    40: ("xor", 3, 4),
    41: ("ror", 2, 29),
    42: ("add", 2, 4, 45),
    43: ("mul", 3, 0xbbe0563303a4615f),
    44: ("swap", 3, 4)
}

def invert_jit(op_tuple):
    kind = op_tuple[0]
    if kind == "xor":
        rA, rB = op_tuple[1], op_tuple[2]
        regs[rA] ^= regs[rB]
    elif kind == "ror":
        rA, amt = op_tuple[1], op_tuple[2]
        regs[rA] = rol(regs[rA], amt)
    elif kind == "add":
        rA, rB, amt = op_tuple[1], op_tuple[2], op_tuple[3]
        regs[rA] = (regs[rA] - rol(regs[rB], amt)) & MASK
    elif kind == "mul":
        rA, imm = op_tuple[1], op_tuple[2]
        inv = pow(imm, -1, 1 << 64)
        regs[rA] = (regs[rA] * inv) & MASK
    elif kind == "swap":
        rA, rB = op_tuple[1], op_tuple[2]
        regs[rA], regs[rB] = regs[rB], regs[rA]

def invert_vm(step_num):
    op, rA, rB, shift, imm = vm_steps[step_num]
    if op == 0:
        regs[rA] = (regs[rA] - rol(regs[rB], shift)) & MASK
    elif op == 1:
        regs[rA] = regs[rA] ^ rol(regs[rB], shift)
    elif op == 2:
        inv_imm = pow(imm, -1, 1 << 64)
        regs[rA] = (regs[rA] * inv_imm) & MASK
    elif op == 3:
        regs[rA] = ror(regs[rA], shift)
    elif op == 4:
        regs[rA], regs[rB] = regs[rB], regs[rA]

for i in range(44, -1, -1):
    invert_jit(jit_ops[i])
    invert_vm(i)

res = b"".join(r.to_bytes(8, "little") for r in regs)
print("Flag:", res[:33].decode())
