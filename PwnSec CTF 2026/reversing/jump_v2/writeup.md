# jump_v2 Writeup

## Summary
`jump_v2` is an x86_64 Linux challenge where the flag is literally the input line: on success, the parent prints `pwnsec{<input>}`.
The overall verification chain consists of:
1. Input (<= 48 bytes) is ChaCha20 encrypted and written to a 48-byte placeholder in an embedded child ELF (`0x5463a0`).
2. The child ELF runs inside a `memfd_create` container and installs 14 stacked BPF seccomp filters.
3. The child passes 14 dwords via syscalls `0x1337..0x1344` where `0x1337` passes length 0x30, `0x1338..0x1343` pass 12 transformed dwords, and `0x1344` passes a checksum dword.
4. Filter matching logic: `((arg0 ^ k1) + k2) & mask == k3`. Several masks had 0 bits (20 ambiguous bits total). We resolved the exact 12 target dwords using meet-in-the-middle against the 13th checksum syscall.
5. Inverted the child's 3 transformation stages:
   - Stage 3: Inverted single-round shift/bswap element-wise transformation (`0x49b666`).
   - Stage 2: Inverted 8-round Feistel permutation over three independent 16-byte blocks (`0x420e19`).
   - Stage 1: Inverted 12-round AES-NI / `pshufb` Feistel network over three 128-bit SIMD registers using `aesdeclast` / `aesimc` and inverse permutation masks (`0x401050`).
6. Recovered raw input by XORing recovered placeholder bytes with ChaCha20 keystream.

Flag: `pwnsec{hi_astra_i_believe_you_can_jump_4c6a05cc40f5d4cb}`
