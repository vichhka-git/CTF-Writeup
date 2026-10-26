#!/usr/bin/env python3
"""IL2FLAG solver: recover the flag statically from il2flag.exe + global-metadata.dat.

Program.Main is control-flow flattened into a chain of 34 dispatchers. Each
dispatcher reads the next input byte through a global cursor helper (RVA
0x437af0), bounds-checks it against 0xff and jumps through a 256-entry table of
ImageBase-relative targets indexed by the character. Every case stub resolves a
single il2cpp string literal through a metadata-usage slot and compares
`literal.Length` (Il2CppString+0x10) with an immediate. A mismatch throws, so the
accepted character at each stage is the table index whose literal has exactly
that length.

Metadata usage token (decoder at RVA 0x96dd0):
    kind  = (token >> 29) - 1
    index = (token >> 1) & 0x0FFFFFFF
kind 3 is a string literal: bytes are data[off[i]:off[i+1]], where the boundary
table lives at global-metadata.dat + hdr[2] and the blob at hdr[5].
"""
import struct
import sys

import capstone
import pefile

EXE = sys.argv[1] if len(sys.argv) > 1 else "il2flag.exe"
MDP = sys.argv[2] if len(sys.argv) > 2 else "Data/Metadata/global-metadata.dat"
ENTRY, GETCHAR = 0x3018C0, 0x437AF0

pe = pefile.PE(EXE, fast_load=True)
IB = pe.OPTIONAL_HEADER.ImageBase
data = open(EXE, "rb").read()
secs = [(s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData), s.PointerToRawData)
        for s in pe.sections]


def foff(rva):
    for va, sz, pr in secs:
        if va <= rva < va + sz:
            return pr + (rva - va)
    return None


def gb(rva, n):
    o = foff(rva)
    return data[o:o + n] if o is not None else b""


def u32(r):
    return struct.unpack("<I", gb(r, 4))[0]


def u64(r):
    return struct.unpack("<Q", gb(r, 8))[0]


cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

MD = open(MDP, "rb").read()
H = struct.unpack_from("<32I", MD, 0)
OFFT, DATA = H[2], H[5]


def lit(i):
    a, b = struct.unpack_from("<II", MD, OFFT + i * 4)
    return MD[DATA + a:DATA + b]


def utf16len(s):
    try:
        u = s.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return sum(2 if ord(c) > 0xFFFF else 1 for c in u)


def find_table(rva):
    """Locate the 256-entry switch table: the `mov ecx, [.. + rax*4]` that follows
    the call to the character cursor."""
    seen = False
    for i in cs.disasm(gb(rva, 0x60), IB + rva):
        if i.mnemonic == "call" and i.op_str == hex(IB + GETCHAR):
            seen = True
        if seen and i.mnemonic == "mov" and "rax*4" in i.op_str and i.op_str.startswith("ecx,"):
            return int(i.op_str.split("+ ")[-1].rstrip("]"), 16)


def stub(rva, depth=0):
    """Return (usage_slot_rva, compared_length, targets) for one case stub."""
    slot = imm = None
    tg = []
    ins = list(cs.disasm(gb(rva, 0x50), IB + rva))
    for k, x in enumerate(ins):
        if x.mnemonic == "mov" and x.op_str.startswith("rax, qword ptr [rip"):
            nx = ins[k + 1] if k + 1 < len(ins) else None
            if nx and nx.mnemonic == "cmp" and "rax + 0x10" in nx.op_str:
                slot = x.address + x.size + int(x.op_str.split("rip + ")[1].rstrip("]"), 16) - IB
                imm = int(nx.op_str.split(", ")[-1], 16)
        if x.mnemonic in ("jmp", "call") and x.op_str.startswith("0x"):
            t = int(x.op_str, 16) - IB
            tg.append(t)
            if x.mnemonic == "jmp":
                if slot is None and depth < 3:
                    s2, i2, t2 = stub(t, depth + 1)
                    if s2 is not None:
                        slot, imm = s2, i2
                    tg += t2
                break
        if x.mnemonic == "ret":
            break
    return slot, imm, tg


flag, cur, seen, stage = "", ENTRY, set(), 0
while cur and cur not in seen:
    seen.add(cur)
    tbl = find_table(cur)
    if tbl is None:
        break
    acc, nxt = [], {}
    for c in range(256):
        slot, imm, tg = stub(u32(tbl + 4 * c))
        if slot is not None:
            s = lit((u64(slot) >> 1) & 0x0FFFFFFF)
            if utf16len(s) == imm:
                acc.append((c, s))
        for x in tg:
            if x != cur and find_table(x):
                nxt[x] = nxt.get(x, 0) + 1
    # The real literals are random alphanumerics; length collisions carry control bytes.
    best = [(c, s) for c, s in acc if 32 <= c < 127 and s.isalnum()]
    ch = chr(best[0][0]) if len(best) == 1 else "?"
    flag += ch
    print("stage %2d  dispatcher=%#-9x accepted=%r  literal=%r" %
          (stage, cur, ch, best[0][1] if len(best) == 1 else None))
    stage += 1
    cur = max(nxt, key=nxt.get) if nxt else None

print("\nFLAG: " + flag)
