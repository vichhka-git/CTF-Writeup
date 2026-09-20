#!/usr/bin/env python3
"""
Reproducible solver for CSAW CTF 2026 - Rev: Machine Head (ID: 34)

Binary: masterkey (stripped 64-bit ELF)
Architecture: Custom bytecode interpreter / VM checking a 53-character flag.

VM Specifications:
- 8 internal byte registers (reg[0..7]), initialized to 0.
- 3 bytes per instruction: (opcode, arg1, arg2)
- Opcodes:
    0x91: LOAD_INPUT reg[arg1] = input[arg2]
    0x24: ADD_IMM    reg[arg1] = (reg[arg1] + arg2) & 0xff
    0x6d: ADD_REG    reg[arg1] = (reg[arg1] + reg[arg2]) & 0xff
    0x7a: XOR_IMM    reg[arg1] ^= arg2
    0x4e: XOR_REG    reg[arg1] ^= reg[arg2]
    0x1d: MUL_IMM    reg[arg1] = (reg[arg1] * arg2) & 0xff
    0xb2: ROL_IMM    reg[arg1] = rol8(reg[arg1], arg2)
    0xa7: ASSERT_EQ  assert reg[arg1] == arg2 (sets success flag to 0 if false)
    0xe0: HALT       exits with success if all assertions held

Solution Approach:
The VM verifies input[0..52] in strictly sequential order. For each index i, a sequence
of operations transforms input[i] and reg[1], checks it against a target value via ASSERT_EQ,
and updates a rolling state in reg[1].
Because each character has only 256 possible byte values, we solve character i in [0..52]
step-by-step by testing 0..255, finding the matching byte, and updating the VM state.
"""

import sys
from pathlib import Path

CHALLENGE_DIR = Path(__file__).resolve().parent.parent
BINARY_PATH = CHALLENGE_DIR / "files" / "masterkey"

def rol8(val, n):
    n = n % 8
    return ((val << n) | (val >> (8 - n))) & 0xff

def solve():
    if not BINARY_PATH.exists():
        raise FileNotFoundError(f"Binary not found at {BINARY_PATH}")

    with open(BINARY_PATH, "rb") as f:
        data = f.read()

    # Bytecode starts at offset 0x2040 in the binary (.rodata)
    bc = data[0x2040:]

    # Parse instructions
    instrs = []
    idx = 0
    while idx < len(bc):
        op = bc[idx]
        if op == 0xe0:
            instrs.append((op, 0, 0))
            break
        if idx + 2 >= len(bc):
            break
        arg1 = bc[idx+1]
        arg2 = bc[idx+2]
        instrs.append((op, arg1, arg2))
        idx += 3

    regs = [0] * 8
    flag = bytearray(53)

    ip = 0
    # First instruction initializes reg[1]
    op, a1, a2 = instrs[ip]
    if op == 0x7a and a1 == 1:
        regs[1] ^= a2
        ip += 1

    for char_idx in range(53):
        start_ip = ip
        start_regs = list(regs)
        found_byte = None

        for cand in range(256):
            test_regs = list(start_regs)
            cur_ip = start_ip
            assert_passed = False

            while cur_ip < len(instrs):
                op, a1, a2 = instrs[cur_ip]
                if op == 0x91: # LOAD_INPUT
                    test_regs[a1] = cand if a2 == char_idx else flag[a2]
                elif op == 0x24: # ADD_IMM
                    test_regs[a1] = (test_regs[a1] + a2) & 0xff
                elif op == 0x6d: # ADD_REG
                    test_regs[a1] = (test_regs[a1] + test_regs[a2]) & 0xff
                elif op == 0x7a: # XOR_IMM
                    test_regs[a1] ^= a2
                elif op == 0x4e: # XOR_REG
                    test_regs[a1] ^= test_regs[a2]
                elif op == 0x1d: # MUL_IMM
                    test_regs[a1] = (test_regs[a1] * a2) & 0xff
                elif op == 0xb2: # ROL_IMM
                    test_regs[a1] = rol8(test_regs[a1], a2)
                elif op == 0xa7: # ASSERT_EQ
                    if test_regs[a1] == a2:
                        assert_passed = True
                    cur_ip += 1
                    break
                cur_ip += 1

            if assert_passed:
                found_byte = cand
                break

        if found_byte is None:
            raise RuntimeError(f"Failed to find byte for index {char_idx}")

        flag[char_idx] = found_byte

        # Advance state to next character
        cur_ip = start_ip
        while cur_ip < len(instrs):
            op, a1, a2 = instrs[cur_ip]
            if op == 0x91:
                if a2 > char_idx:
                    break
                regs[a1] = flag[a2]
            elif op == 0x24:
                regs[a1] = (regs[a1] + a2) & 0xff
            elif op == 0x6d:
                regs[a1] = (regs[a1] + regs[a2]) & 0xff
            elif op == 0x7a:
                regs[a1] ^= a2
            elif op == 0x4e:
                regs[a1] ^= regs[a2]
            elif op == 0x1d:
                regs[a1] = (regs[a1] * a2) & 0xff
            elif op == 0xb2:
                regs[a1] = rol8(regs[a1], a2)
            elif op == 0xa7:
                pass
            elif op == 0xe0:
                break
            cur_ip += 1

        ip = cur_ip

    flag_str = flag.decode("utf-8")
    print(f"Flag: {flag_str}")
    return flag_str

if __name__ == "__main__":
    solve()
