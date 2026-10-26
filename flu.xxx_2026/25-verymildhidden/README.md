# VeryMildHidden

**Category:** rev · **Points:** 63 · **Solves:** 215 · **Author:** J6K

## Challenge

An extensionless 14 KB file that reads one line and answers `Correct!` or
`Wrong...`. There is no obvious string comparison in it — the comparison is a
tiny virtual machine: the program in `.rodata` is a bytecode interpreter loop,
and the flag is the input the bytecode accepts.

## TL;DR

`chall` is a stripped x86-64 PIE that runs a 4-byte-instruction VM over a 1 KB
byte array. The bytecode is 55 near-identical blocks; every block reads one more
character into `mem[0]`, mangles it with three immediate arithmetic operations
and ORs the result into a mismatch accumulator `mem[7]`. The blocks do not
communicate, so each character can be brute-forced in isolation against its own
block: 55 × 256 emulated steps recover the flag.

## Files

| file | description |
|---|---|
| `25-chall` | ELF 64-bit LSB PIE, x86-64, stripped, 14 464 B || `solve.py` | bytecode emulator + per-block brute force; writes `input.txt` |

Tools: `python3` only for the solve; any disassembler (`objdump`, Ghidra) to
read the interpreter. To run the handout: Linux, or Docker
(`--platform linux/amd64`) on Apple silicon.

## Analysis

### The interpreter

`objdump -d -M intel 25-chall` puts everything in one function starting at
`0x1120`:

* `0x1120` prints `Input: ` and reads with `fgets(buf, 0x40, stdin)`; `strcspn`
  strips the newline. The buffer lives at `0x4030`.
* `rbx` is initialised to `0x2080`, the start of the bytecode in `.rodata`; the
  VM's register file `mem[]` is the eight `.bss` bytes at `0x4048`, i.e.
  `mem[0]..mem[7]` — only `mem[0]` (input scratch) and `mem[7]` (accumulator)
  matter here.
* The dispatch loop fetches four bytes `op, a, b, c`, uses `op` as an index into
  a 14-entry jump table at `0x2040`, and the handlers index `mem[]` with `a` /
  `b`:

| op | handler | meaning |
|---|---|---|
| `0x01` | `0x138f` | `mem[a] = b` (immediate) |
| `0x02` | `0x1363` | `mem[a] = mem[b]` |
| `0x03` | `0x1350` | `mem[a] += mem[b]` |
| `0x04` | `0x132a` | `mem[a] -= mem[b]` |
| `0x05` | `0x1314` | `mem[a] ^= mem[b]` |
| `0x06` | `0x1340` | `mem[a] += b` |
| `0x07` | `0x1307` | `mem[a] ^= b` |
| `0x08` | `0x12d3` | `mem[a] = next input byte` (0 past the end) |
| `0x09` | `0x12a9` | `putchar(mem[a])` |
| `0x0a` | `0x1284` | `mem[a] \|= mem[b]` |
| `0x0b` | `0x1215` | `jmp (c << 8) \| b` |
| `0x0c` | `0x1275` | `jnz mem[a]` |
| `0x0d` | `0x1204` | `jz mem[a]` |
| `0xff` | `0x1237` | `halt` |

Arithmetic is byte-wide. The program only ever uses `0x01`, `0x04`, `0x06`,
`0x07`, `0x08` and `0x0a` — no jumps, no output.

### The check

After the VM stops, `main` compares the input length against `0x37` (55) and
`mem[7]` against zero (`0x123f`, the branch to the `Correct!` `puts`). The
bytecode explains the accumulator: it begins with `01 07 00 00`
(`mem[7] = 0`), and every input character contributes one block that ends in
`0a 07 00 00` (`mem[7] |= mem[0]`). Since a bitwise OR only stays zero when every
operand is zero, the flag has to make each block compute `mem[0] == 0`.

The first block is

```
08 00 00 00   mem[0] = in()      ; x
06 00 13 00   mem[0] += 0x13
07 00 77 00   mem[0] ^= 0x77
07 00 0e 00   mem[0] ^= 0x0e
0a 07 00 00   mem[7] |= mem[0]
```

which is satisfied by `x = (0x77 ^ 0x0e) - 0x13 = 0x66 = 'f'`. The other 54
blocks are the same shape — a read, three immediate operations, the OR — some
with six instructions when a temporary such as `mem[1] = 0x5e` is needed. Two
facts make the whole thing trivial:

* no block reads `mem[7]` or any cell another block writes, so the blocks are
  independent, and
* subtracting/xoring immediates is a bijection on `0x00..0xff`, so each block has
  exactly one accepted character.

## Solution

### 1. Emulate the bytecode block by block

`solve.py` takes the bytecode image from `.rodata` (`0x2080..0x2518`, 293
instructions up to the `0xff`), splits it at every `0x08` (each split starts with
the read into `mem[0]`), and for every block tries all 256 characters, keeping the
one that leaves `mem[0] == 0`. The persistent `mem[]` is threaded through the
blocks so the length/accumulator assertions are real checks, not decoration.

```bash
cp ../25-chall chall        # handout file -> working copy
python3 solve.py
```

```
flag{M4yb3_w3_c4n_74k3_0n_3v3n_70ugh3r_ch4113ng3$_n0w?}
```

The solver asserts the two conditions the binary checks (`len(flag) == 55` and
`mem[7] == 0`) and writes `input.txt` for the next step.

### 2. Confirm against the real binary

```bash
docker run --rm -i --platform linux/amd64 -v "$PWD":/w -w /w debian:bookworm-slim \
    sh -c 'chmod +x chall; ./chall < input.txt'
```

```
Input: Correct!
```

A mutation of the input takes the other branch (`Input: Wrong...`), so the 55
characters are all pinned.

## Flag

```
flag{M4yb3_w3_c4n_74k3_0n_3v3n_70ugh3r_ch4113ng3$_n0w?}
```

## Notes

The interpreter's unused instructions (`jmp`, `jnz`, `jz`, `putchar`, register
moves) are dead code for this input — the 55-block linear program never branches.
A hand solve is also feasible: each block is
`((x ⊕ k1 ⊕ k2) ± k3) = 0`, so `x` falls out of the immediates directly, which is
what the exhaustive loop recomputes.
