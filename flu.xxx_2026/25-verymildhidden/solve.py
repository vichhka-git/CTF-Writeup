#!/usr/bin/env python3
"""VM emulator + per-char solver for VeryMildHidden. Writes input.txt."""
import collections
d = open('chall', 'rb').read()
code = d[0x2080:0x2518]          # bytecode (.rodata), 4-byte insns until 0xff

def exec_block(ops, x, mem):
    v = x
    for op, a, b, c in ops:
        if   op == 0x6: v = (v + b) & 0xff
        elif op == 0x7: v ^= b
        elif op == 0x1: mem[a] = b
        elif op == 0x4: v = (v - mem[b]) & 0xff
        elif op == 0x2: mem[a] = mem[b]
        elif op == 0x3: v = (v + mem[b]) & 0xff
        elif op == 0x5: v ^= mem[b]
        elif op == 0xa: mem[a] |= mem[b]
    return v

ins, i = [], 0
while code[i] != 0xff:
    ins.append(tuple(code[i:i+4])); i += 4
blocks, cur = [], []
for t in ins:                    # each read starts a block
    if t[0] == 0x8:
        cur = []; blocks.append(cur)
    cur.append(t)

M, flag = collections.defaultdict(int), []
for blk in blocks:
    sols = [x for x in range(256)
            if exec_block(blk, x, collections.defaultdict(int, M)) == 0]
    assert len(sols) == 1, sols
    flag.append(sols[0]); exec_block(blk, sols[0], M)

flag = ''.join(map(chr, flag))
assert len(flag) == 55 and M[7] == 0
open('input.txt', 'w').write(flag)
print(flag)
