#!/usr/bin/env python3
"""Two Worlds, One Heart -- recover the 40-byte input.

The same bytes at 0x401600 are executed twice:
  * as 32-bit code (CS=0x23) -> validates input[0:20]
  * as 64-bit code (CS=0x33, entered via Heaven's Gate in sub_4016B3)
    -> validates input[20:40]
`48 85 C0` is `dec eax; test eax,eax` in 32-bit (branch not taken) but
`test rax,rax` in 64-bit (branch taken), which selects the two halves.
Both chains are rol(x ^ prev) == const, so both invert directly.
"""
import struct

M32 = (1 << 32) - 1
M64 = (1 << 64) - 1


def ror(v, n, bits):
    mask = (1 << bits) - 1
    v &= mask
    return ((v >> n) | (v << (bits - n))) & mask


# ---- 32-bit world ("he speaks 32"): five dwords, chained ----
he = [
    (0x1337C0DE, 0xCDBD7302),
    (0xCDBD7302, 0x30833D2E),
    (0x30833D2E, 0xB310EA05),
    (0xB310EA05, 0xDEF1B433),
    (0xDEF1B433, 0x1C3B640E),
]
first = b"".join(struct.pack("<I", ror(t, 11, 32) ^ k) for k, t in he)

# ---- 64-bit world ("she speaks 64"): qword, qword, dword ----
rax = ror(0x87326027C52B7005, 0x13, 64) ^ 0x5A33C0D313379090
rcx = ror(0x7E6E88ADD6EBC7E2, 0x1D, 64) ^ 0x87326027C52B7005
edx = ror(0x5E929579, 0x0D, 32) ^ (0x7E6E88ADD6EBC7E2 & M32)
second = struct.pack("<Q", rax) + struct.pack("<Q", rcx) + struct.pack("<I", edx)

flag = first + second
assert len(flag) == 40, len(flag)
print(flag.decode())
