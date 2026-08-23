import struct

def rol(val, shift, bits=64):
    shift %= bits
    return ((val << shift) | (val >> (bits - shift))) & ((1 << bits) - 1)

def ror(val, shift, bits=64):
    shift %= bits
    return ((val >> shift) | (val << (bits - shift))) & ((1 << bits) - 1)

def S(seed):
    seed = (seed + 0x9e3779b97f4a7c15) & 0xffffffffffffffff
    z = seed
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9 & 0xffffffffffffffff
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb & 0xffffffffffffffff
    z = (z ^ (z >> 31)) & 0xffffffffffffffff
    return seed, z

def Mask(arg0, arg1):
    seed = (0x6a09e667f3bcc909 ^ ((arg0 + 1) * 0xbb67ae8584caa73b)) & 0xffffffffffffffff
    res = 0
    for j in range(arg1 + 1):
        seed, res = S(seed)
    return res

# 1. Target(2)
v_hex = "d15b0fe4397ac281fca718d50e439b6291e23d6a805cf4170d6eb714f32859cabe790268c4dfa135628cd3a5194b70ee513cf068d2a74e196fd823ea04591cb7e56c97a13b0fd8429b704ad52fc1638e7a18de436c9b25f0b4f25e39d081c76a1a3798d0b5d607eccf1956dacda8bf518c514d6c3ce2315894ed6f14d1b9257b85ad1635242a0944abe90ead32767c97fb06ac74815e32d96b5ef329dac187403148d75c02f916abd56fb29018ace4736b42fae831d7590cce97410df38a25b6"
v_bytes = bytes.fromhex(v_hex)[:192]

V = []
for row in range(4):
    r = []
    for col in range(6):
        val = struct.unpack('<Q', v_bytes[(row*6 + col)*8 : (row*6 + col + 1)*8])[0]
        r.append(val)
    V.append(r)

def Target(arg0):
    target = []
    for i in range(6):
        t = V[arg0][i] ^ Mask(arg0, i)
        target.append(t)
    return target

# 2. Seed()
def get_seed():
    seed = 0x243f6a8885a308d3
    attrs = [
        ("trace.child", 0x19e7a05b3cd24861),
        ("trace.parent", 0x8f31c2d47a695be0),
        ("trace.return", 0xd4b6f9082173ca5e)
    ]
    attrs.sort(key=lambda x: x[0])
    for k, v in attrs:
        seed = (rol(seed ^ v, 17) + 0xbb67ae8584caa73b) & 0xffffffffffffffff
    return seed

# 3. Tape()
class Inst:
    def __init__(self, op, a, b, r0, r1, x, y):
        self.op = op
        self.a = a
        self.b = b
        self.r0 = r0
        self.r1 = r1
        self.x = x
        self.y = y

def gen_tape():
    tape = []
    seed = get_seed()
    loc2 = 0x87095df77a5e5f10
    for i in range(104):
        seed, loc4 = S(seed)
        seed, s1 = S(seed)
        loc5 = s1 | 1
        seed, s2 = S(seed)
        loc6 = s2 | 1
        
        a = (loc4 >> 5) % 6
        b = (a + 1 + ((loc4 >> 13) % 5)) % 6
        op = (loc4 ^ rol(loc2, i & 63)) % 6
        r0 = ((loc4 >> 22) & 63) + 1
        r1 = ((loc4 >> 45) & 63) + 1
        x = loc5
        y = loc6
        
        tape.append(Inst(op, a, b, r0, r1, x, y))
        loc2 = rol(((loc2 ^ loc4) + 0xd1b54a32d192ed03) & 0xffffffffffffffff, (loc4 >> 59) + 1)
    return tape

def modinv(a, m=1<<64):
    return pow(a, -1, m)

def invert_op(lanes, inst):
    if inst.op == 0: # A
        lanes[inst.a] = (lanes[inst.a] - rol(lanes[inst.b], inst.r0) - inst.x) & 0xffffffffffffffff
    elif inst.op == 1: # B
        lanes[inst.a] = lanes[inst.a] ^ rol(lanes[inst.b], inst.r0) ^ inst.x
    elif inst.op == 2: # C
        lanes[inst.a] = ror(lanes[inst.a], inst.r0)
    elif inst.op == 3: # D
        inv_x = modinv(inst.x, 1<<64)
        lanes[inst.a] = (lanes[inst.a] * inv_x) & 0xffffffffffffffff
    elif inst.op == 4: # E
        lanes[inst.a], lanes[inst.b] = lanes[inst.b], lanes[inst.a]
    elif inst.op == 5: # F
        lanes[inst.b] = lanes[inst.b] ^ rol(lanes[inst.a], inst.r1) ^ inst.y
        lanes[inst.a] = (lanes[inst.a] - rol(lanes[inst.b], inst.r0) - inst.x) & 0xffffffffffffffff

target = Target(2)

lanes = [0] * 6
for i in range(6):
    val = ror(target[i], i * 11 + 7) ^ 0x6a09e667f3bcc909
    idx = (i * 5 + 1) % 6
    lanes[idx] = val

tape = gen_tape()

for inst in reversed(tape):
    invert_op(lanes, inst)

for i in range(6):
    lanes[i] ^= rol((0x3c6ef372fe94f82b + i * 0xbb67ae8584caa73b) & 0xffffffffffffffff, i * 9 + 3)

buf = bytearray()
for i in range(5):
    buf += struct.pack('<Q', lanes[i])

flag_bytes = bytearray(36)
seed = 0x1e285bbfdbd791ca
for i in range(36):
    seed, rand_val = S(seed)
    rand_byte = (rand_val >> 56) & 0xff
    loc6 = (i * 5 + 7) % 36
    flag_bytes[i] = buf[loc6] ^ rand_byte

flag = "e0f{" + flag_bytes.decode('ascii') + "}"
print("FLAG:", flag)
