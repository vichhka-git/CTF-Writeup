# Sunshine CTF 2026 Writeup: Print Print Revolution

- **Category:** Pwn
- **ID:** 5
- **Points / Solves:** 483 pts / 120 solves
- **Connection:** `nc chal.sunshinectf.games 26002`
- **Flag:** `sun{cust0m_fmtstr_n0_t00ls_4ll0wed}`

---

## Challenge

> The arcade's score printer has been spitting out strange tickets all week. Step up to the renderer and see what it's really printing.
> 
> Files:
> * [revolution](https://sunshinectf.games/files/cc3135/revolution)

---

## Summary

The binary imports no `printf`. Its hand-rolled format renderer implements an undocumented `%w`
that performs `*arg[N] = arg[N+1]` — a direct arbitrary write, with no `%n` involved.

## Solution

`checksec` shows no canary and no PIE, and the only libc imports are `read`, `write`, `strlen`,
`strcspn`, `setvbuf`. There is no `printf` at all, yet the program interprets format specifiers —
so the renderer is hand-written.

Probing it: `%x`/`%p` print varargs, `%s` dereferences one, `%%` emits a literal `%`, and `%n` is
*not* implemented (it prints `n`). Reading the renderer reveals the extra specifier:

```c
if (spec == 'w') {                 // "%N$w"
    ptr = getarg(N);
    val = getarg(N + 1);
    *ptr = val;                    // arbitrary 8-byte write
}
```

The template buffer **is** the vararg area: positional index 6 maps to buffer offset 0, so index
`n` reads offset `(n-6)*8`. Both operands are therefore attacker-chosen — `%8$w` with the target in
bytes 16..23 and the value in bytes 24..31.

With no PIE and only Partial RELRO, `.got.plt` is writable at a fixed address. `%s` on a GOT slot
leaks the resolved libc pointer (`strlen` stops at the null high bytes, yielding exactly the 6 real
bytes), which gives the libc base; one `%w` then swaps `strcspn@got` for `system`. `main` already
runs `v5[strcspn(v5, "\n")] = 0` on every line with `rdi` pointing at the buffer, so the next line
sent is executed as a command.

**Two traps worth recording.** `strcspn`'s own resolved address has a null low byte, so `%s` cannot
leak it. And `strlen`/`strcspn` are ifunc-dispatched to SIMD variants, so their GOT slots do not
match the generic symbol — resolving a base from them yields a non-page-aligned answer. `read` and
`write` are plain syscall wrappers and resolve honestly; requiring two independent slots to agree on
one page-aligned base is what confirmed the remote libc.

## Ruled Out

- ROP: there is no `syscall` gadget and no `/bin/sh` string in the binary.
- Stack overflow: `read` is bounded to 511 bytes into a 536-byte buffer.

## Files

- `files/revolution`
