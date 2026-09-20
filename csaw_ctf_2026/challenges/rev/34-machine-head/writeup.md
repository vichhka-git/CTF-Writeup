# CSAW CTF Quals 2026 - Machine Head (Rev, ID 34)

## Challenge Information
- **Name:** Machine Head
- **Category:** Rev
- **ID:** 34
- **Points:** 132
- **Author:** WubberDuckkie
- **Flag:** `csaw{cl1mb1ng_th3_v1rtu4l_st4ck_0n3_0pc0d3_4t_4_t1m3}`

## Description
> Every lock in the building answers to one key. We burned the checker into a little machine of our own design — it speaks a language you won't find in any disassembler's opcode table.
> 
> Give it the master key and it'll tell you.

## Analysis & Reverse Engineering

### 1. Binary Overview
- Stripped 64-bit ELF executable (`masterkey`).
- `main` function is at virtual address `0x10c0`.
- It validates `argc == 2` and checks `strlen(argv[1]) == 0x35` (53 characters).
- It allocates an 8-byte register bank `reg[0..7]` on the stack, initializes register state `reg[1] = 0x3c`, and sets a success flag register `r8d = 1`.
- It then executes a custom bytecode sequence located at offset `0x2040` (`.rodata`).

### 2. Custom Virtual Machine Architecture
Each instruction is exactly 3 bytes: `(opcode, arg1, arg2)`.
Disassembling the interpreter loop reveals 8 core instructions:

| Opcode | Mnemonic | Operation |
|--------|----------|-----------|
| `0x91` | `LOAD_INPUT` | `reg[arg1] = input[arg2]` |
| `0x24` | `ADD_IMM` | `reg[arg1] = (reg[arg1] + arg2) & 0xff` |
| `0x6d` | `ADD_REG` | `reg[arg1] = (reg[arg1] + reg[arg2]) & 0xff` |
| `0x7a` | `XOR_IMM` | `reg[arg1] ^= arg2` |
| `0x4e` | `XOR_REG` | `reg[arg1] ^= reg[arg2]` |
| `0x1d` | `MUL_IMM` | `reg[arg1] = (reg[arg1] * arg2) & 0xff` |
| `0xb2` | `ROL_IMM` | `reg[arg1] = rol8(reg[arg1], arg2)` |
| `0xa7` | `ASSERT_EQ` | `if (reg[arg1] != arg2) r8d = 0` |
| `0xe0` | `HALT` | if `r8d != 0` print success message and return 0 |

### 3. Execution Pattern & Solution
Disassembly of the 638 instructions (1914 bytes of bytecode) reveals that:
- There are no control-flow branches (no jumps).
- The bytecode validates `input[0]` through `input[52]` in strictly sequential order.
- For each character `input[i]`:
  1. `input[i]` is loaded and combined with intermediate values and `reg[1]` using arithmetic, rotations, and XORs.
  2. The result is compared against a constant with `ASSERT_EQ`.
  3. `reg[1]` is updated with a hash of `input[i]` (`reg[1] = rol((reg[1] + input[i]) & 0xff, 3) ^ 0x9e`).
- Since each character has only 256 possible byte values and only depends on previously confirmed characters and `reg[1]`, the flag can be solved sequentially in milliseconds.

Testing all 256 candidate bytes for positions `0` to `52` recovers the full master key:
`csaw{cl1mb1ng_th3_v1rtu4l_st4ck_0n3_0pc0d3_4t_4_t1m3}`

Executing `./masterkey 'csaw{cl1mb1ng_th3_v1rtu4l_st4ck_0n3_0pc0d3_4t_4_t1m3}'` confirms:
`Correct! That's the master key.`
