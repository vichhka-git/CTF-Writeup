# The Lock Box

**Category:** Reverse engineering · **Points:** 200 · **Flag:** `CSCTF{06_ash_hawk_road_at_garrisoned_38318f}`

## What the handout gives you

A zip archive containing one Linux x86-64 binary representing an Ash gate unit:

- `lockbox` (14,472 bytes, ELF 64-bit LSB PIE executable, dynamically linked, stripped, BuildID `dc06f8854d964ff91ab45f573cec939661ecabf7`).

## Walkthrough

1. **Locate the entry point and initialization functions.**
   Running `objdump -d lockbox` or inspecting section headers shows standard glibc startup. The `.init_array` section at offset `0x3db8` contains a pointer to function `0x10e0` / `0x1120`, which executes as an ELF constructor before `main`.

2. **Analyze the constructor validation logic.**
   The constructor function at `0x1120` reads `argv[1]` from the initial stack layout passed through `0x10(%rbp)`. At `0x114c`, it compares the length of `argv[1]` against `0x2c` (44 bytes). If the length does not match 44 bytes, it skips the validation loop and returns immediately.

3. **Trace the 44-byte state transformation.**
   When `argv[1]` is 44 bytes, the constructor executes a transformation loop from offset `0x1178` to `0x11a2`:
   - Counter `rax` iterates from 0 to 43.
   - Accumulator `esi` starts at `0x5b`.
   - Rotation count `ecx` starts at 1 and increases by 3 on each iteration (`addl $0x3, %ecx`).
   - For character index `i`, input byte `dl = argv[1][i]` is XORed with `esi`: `dl ^= esi`.
   - The value is bitwise rotated left: `rolb %cl, %dl`.
   - A byte from static table 1 at offset `0x224d` (indexed by `i & 7`) is added: `dl += table1[i & 7]`.
   - The result is compared against static table 2 at offset `0x2255`: `cmpb table2[i], dl`.
   - State register `esi` updates by adding index `i` and the target byte `dl`: `esi += i + dl`.

4. **Observe the global unlock variable.**
   At offset `0x11a4`, the constructor tests whether all 44 byte comparisons matched. If every byte matched, it stores `0x5a` into the global variable at offset `0x4014`. If any comparison failed, it stores `0x17`.

5. **Identify the decoy inside `main`.**
   Decompiling `main` at offset `0x11c0` shows a check for an argument string matching `"open"`. When supplied, `main` executes a separate 33-byte loop comparing input against an XOR table at offset `0x2200`. However, after that check, `main` unconditionally reads `[0x4014]` at `0x1291`:
   - `cmpl $0x5a, 0x4014(%rip)`
   - If equal, it jumps to `0x1353` and prints the success message `"Gate unlocked: coalition transit cleared."`
   - If not equal, it prints `"Gate locked: authorization rejected"`.
   The 33-byte routine inside `main` never modifies `0x4014`. The gate only unlocks if the constructor at `0x1120` wrote `0x5a` during startup.

6. **Invert the constructor loop.**
   Every operation in the 44-byte loop is reversible:
   - For each index `i` from 0 to 43, read target byte `dl = table2[i]`.
   - Subtract `table1[i & 7]`: `dl = (dl - table1[i & 7]) & 0xff`.
   - Rotate right by `(1 + 3 * i) & 7` bits: `dl = ror8(dl, (1 + 3 * i) & 7)`.
   - XOR with `esi & 0xff` to recover input byte `argv[1][i] = dl ^ (esi & 0xff)`.
   - Update `esi = (esi + i + table2[i]) & 0xffffffff`.
   Extracting the 8 bytes from `0x224d` and 44 bytes from `0x2255` and running this inverse loop yields the ASCII string.

## Answer

Inverting the transformation produces the accepted 44-character argument:
`CSCTF{06_ash_hawk_road_at_garrisoned_38318f}`

Passing this phrase directly to the binary unlocks the gate:
`./lockbox 'CSCTF{06_ash_hawk_road_at_garrisoned_38318f}'`

## Notes

The `"open"` command check inside `main` is a red herring. It leads to a dead-end 33-byte check that cannot set `[0x4014]` to `0x5a`. The true validation executes exclusively inside the ELF constructor before `main` runs.
