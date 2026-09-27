# Sunshine CTF 2026 Writeup: IntMod

- **Category:** RE
- **ID:** 44
- **Points / Solves:** 482 pts / 121 solves
- **Flag:** `sun{I_L0v3_Int3rrupts&SelfMod!!!}`

---

## Challenge

> "IntMod?? Do you mean integer modulus??" "No. I do not mean that." "Then what, pretell, could it mean?" "Just put the agent on the ghidra dawg"
> 
> Author: Bradley Fernandez
> 
> Flag format: sun{flag_content}

---

## Summary

A VM built out of signal handlers (`SIGILL`/`SIGTRAP`/`SIGFPE`) interleaved with self-modifying
JIT code; the final check is a 40x40 Vandermonde system mod 65521.

## Solution

"IntMod" is *interrupts and self-modifying code*, not integer modulus.

The binary runs a custom virtual machine on CPU registers R8-R12, driven entirely through signal
handlers, interleaved with dynamically generated single-stepped x86-64 instructions. The 33-byte
flag is padded to 40 bytes (five `uint64` registers) and pushed through **45 rounds** of alternating
VM ARX operations and JIT instructions.

At step 45 the 40 bytes are checked against 40 polynomial evaluations modulo 65521 (`0xfff1`).
Solving that 40x40 Vandermonde system over GF(65521) recovers the transformed bytes, and because
every ARX and JIT step is reversible, inverting the 45 rounds returns the original flag.

## Ruled Out

- Plain modular arithmetic: the title is a pun, not a hint about the maths.
- GDB: it collides with the program's own `SIGTRAP` single-stepping. An `LD_PRELOAD` bridge hooking
  VM execution and JIT generation worked cleanly instead.

## Files

- `files/intmod`
