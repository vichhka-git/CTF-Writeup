# Black Thunk Writeup

## Summary

`black-thunk.exe` is a stripped GHC/Haskell Windows PE. The title and description point at Haskell thunks/laziness: the flag is not present as one static string. The program checks the input shape, lazily builds transformed values, and compares the result against static 32-bit constants.

Flag:

```text
e0f{thunks_hide_where_strict_minds_wont_look}
```

## Recon

Basic strings identify the runtime and the visible program behavior:

```text
answer>
accepted
rejected
e0f{
work\Main.hs
main:Main.Gate
stg_*
```

The binary is a PE32+ GHC executable. Static inspection of the main cluster showed:

```text
0x14024d54b  loads the e0f{ string closure
0x14024d7a9  checks printable payload bytes
0x14024db16  compares a length against 0x28
0x14024dd09  compares accumulated check words
0x14024de7b  accepted path
0x14024dea4  rejected path
```

The useful shape is therefore:

```text
e0f{<40 printable bytes>}
```

## Dynamic Trace

Running the program under Wine confirms normal behavior:

```sh
printf 'AAAA\n' | wine black-thunk.exe
# answer> rejected
```

I used Wine's GDB bridge to break inside the main Haskell-generated code and log key values. The helper script `extract_cmp.py` starts the program on a FIFO, attaches with `winedbg --gdb`, sets breakpoints, then releases controlled input.

For a valid-length input:

```sh
python3 artifacts/extract_cmp.py --exact 'e0f{AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA}'
```

The trace shows five repeated 8-byte blocks. Each block enters code that matches XTEA:

```text
delta = 0x9e3779b9
32 rounds
key index from sum & 3
key index from (sum >> 11) & 3
```

The static target ciphertext words are:

```python
[
    (0x1B091B13, 0xDE7CB151),
    (0x12EF2C85, 0xC51BEF8F),
    (0xCDA3E579, 0xBA8825C9),
    (0xAFB73975, 0xCD920DFA),
    (0xF9C7B73E, 0x90292538),
]
```

The traced per-block XTEA keys are:

```python
[
    [0xDD49804D, 0x34977E4D, 0x8FE8249E, 0xE854AAE6],
    [0xF0BAC219, 0x5708189B, 0x4FEC05BF, 0xFED2AFE5],
    [0x04937FE7, 0x8695EFE2, 0x32B6F39B, 0x2377D59A],
    [0xBD51750E, 0x45F94F25, 0xF4E1EAA1, 0x8239EE94],
    [0x96994594, 0xC69BC73E, 0x552C1D11, 0xC8814CB4],
]
```

## Recovering The Payload

Decrypting the first target block with XTEA gives a pre-XTEA value. The binary XORs payload words with a chaining state before encryption. For the first block, the state is recovered from the all-`A` trace:

```text
observed_pre_for_A ^ 0x41414141 = state
```

Then:

```text
payload_words = xtea_decrypt(ciphertext, key) ^ state
```

That yields:

```text
thunks_h
```

The later block states depend on the previous correct plaintext, so recovery is iterative:

1. Fill unknown bytes with `A`.
2. Trace the pre-XTEA words for the next block.
3. XOR out the `A` words to get that block's chain state.
4. XTEA-decrypt the static ciphertext.
5. XOR with the chain state to get the real 8-byte chunk.

The chunks are:

```text
thunks_h
ide_wher
e_strict
_minds_w
ont_look
```

Payload:

```text
thunks_hide_where_strict_minds_wont_look
```

## Solve

The final offline solver is `solve.py`:

```sh
python3 solve.py
```

Output:

```text
e0f{thunks_hide_where_strict_minds_wont_look}
```

## Verification

```sh
flag='e0f{thunks_hide_where_strict_minds_wont_look}'
printf '%s\n' "$flag" | wine black-thunk.exe
```

Output:

```text
answer> accepted
```
