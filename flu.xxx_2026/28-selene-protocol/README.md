# Selene.Protocol.v1.1-LNR

**Category:** rev · **Points:** 82 · **Solves:** 101 · **Author:** kunte_

## Challenge

A scene-style release: `setup.exe`, a `Crack/` directory with a `winmm.dll` proxy
and a licensing DLL (source included), plus the usual `.nfo` / `.diz` / `.sfv`.
The release notes say the store client is "emulated in full", but the setup
errors out and the crack was written for v1.0. The task is to make it run — the
game prints the flag once its store client accepts the install.

## Files

| file | description |
|---|---|
| `setup.exe` | 4 722 688 B installer, carries the game in PE sections `.lnr0` / `.lnr1` |
| `Crack/winmm.dll`, `Crack/winmm.txt` | DLL proxy: forwards `timeGetTime`, then loads every name listed in `winmm.txt` |
| `Crack/licensefix64.dll`, `Crack/src/` | v1.0 store-client emulator (`ILicense002`), C source + Makefile + Dockerfile |
| `lnr-selene.nfo`, `FILE_ID.DIZ` | release notes: "proper or nothing" |

Tools: `python3` (the solver only uses `struct` and `zlib`), any x86-64
disassembler, optionally mingw-w64 to rebuild the crack.

## TL;DR

Three layers:

1. `setup.exe` decrypts `.lnr0` with ChaCha20 in a key-rolling mode. The 32-byte
   key is 16 ASCII bytes plus 16 bytes from an FNV-1a loop — and the shipped
   binary *jumps over that loop*, which is why the installer fails.
   Restore/derive the key and `.lnr0` becomes an `LNR1` archive holding
   `selene.exe`.
2. `selene.exe` validates a 32-byte license blob that the v1.0 crack cannot
   produce (v1.1 asks for `ILicense004`, `QueryVersion > 2` and a 40-byte blob).
   The check runs in a self-debugging parent that services eight `int3` traps and
   compares `mixer3(blob)` against values derived from `crc32(.text)`.
3. Invert `mixer3` to get the blob, then XOR the 38-byte buffer at
   `0x14000f2a0` with `ChaCha20(blob)`.

## Analysis

### The installer's payload

`setup.exe` sections: `.text` VA `0x1000` raw `0x400`, `.rdata` VA `0x8000` raw
`0x5800`, `.lnr0` VA `0xa000` vsize `0x99e20` raw `0x6c00`, `.lnr1` VA `0xa4000`
vsize `0x397460` raw `0xa0c00`. `.lnr0` is the encrypted game, `.lnr1` is extra
data that is never needed here.

`.rdata` at VA `0x140008850` holds `LNRPKG1066proper` immediately followed by the
ChaCha constant `expand 32-byte k`. The routine at `0x140003ca0` builds the key:

```asm
0x140003cb0  mov  rax, [rip + 0x4b99]     ; "LNRPKG1066"
0x140003cb7  mov  rdx, [rip + 0x4b9a]     ; "proper" + 2 bytes
0x140003cbe  mov  [rcx], rax
0x140003cc1  mov  [rcx + 8], rdx          ; key[0:16] = "LNRPKG1066proper"
0x140003cc5  jmp  0x140003d3d             ; skips the derivation below
0x140003cca  mov  dword [rbp - 4], 0x811c9dc5
0x140003cd8  jmp  0x140003d37             ; for (i = 0; i < 16; i++)
0x140003cda  ...
0x140003ced  xor  [rbp - 4], eax          ; h ^= material[i]
0x140003cf3  imul eax, eax, 0x1000193     ; h *= 0x01000193
0x140003cff  shr  eax, 0xd                ; ext[i] = ((h >> 13) ^ (h >> 5)
0x140003d07  shr  eax, 5                  ;           ^ (i * 0x3b)) & 0xff
0x140003d2f  xor  edx, ecx
0x140003d31  mov  [rax], dl               ; key[16 + i] = ext[i]
```

The `jmp` is five bytes (`e9 73 00 00 00`) at file offset `0x30c5`
(`RVA 0x3cc5 → 0x3cc5 - 0x1000 + 0x400`). With the jump in place the key's upper
half stays zero, the payload decrypts to noise and the installer errors out —
exactly the symptom in the challenge text.

The payload cipher (function at `0x140003d50`) is ChaCha20 with a twist: each
64-byte block uses `ChaCha20_block(key, ctr = 0, nonce = 0)` and afterwards the
key is rolled:

```
for each 64-byte block:
    ks = ChaCha20_block(key, ctr = 0, nonce = 0)
    out ^= ks
    key ^= ks[0:32]
```

A one-shot ChaCha20 decryption with a fixed key therefore fails after the first
block; the keystream itself has to be generated block by block.

For `LNRPKG1066proper` the derived extension is
`aa3a61f536db8dbbc51a03bbb3a0ee81`, so the full key is
`4c4e52504b473130363670726f706572 aa3a61f5…a0ee81`. Decrypting 630 304 bytes of
`.lnr0` yields a single-member archive:

```
4c 4e 52 31  01 00 00 00  0a 00 00 00  73 65 6c 65 6e 65 2e 65 78 65
"LNR1"       version 1     count 10    "selene.exe"
00 9e 09 00  4d 5a ...
size 630272  "MZ" payload
```

The layout is `magic[4]`, `u32 version`, `u32 count` (10, decorative — there is
one member), `char name[10]`, `u32 size`, then the payload at offset `0x1a`.
`selene.exe` is a 630 272-byte PE with ImageBase `0x140000000`.

### Why the shipped crack cannot finish the job

`winmm.dll` is a proxy that forwards `timeGetTime` to the real DLL and then
`LoadLibrary`s every name in `winmm.txt`, so `licensefix64.dll` is resident before
the game looks for the store client. The shipped source emulates
`ILicense002` with three slots: `QueryVersion → 2`, `IsLicensed → 1`,
`GetOwner → "LUNARIS"`.

v1.1 asks for `ILicense004` (falling back to `ILicense003`), requires
`QueryVersion > 2` and requests a **40-byte license blob** through a fourth slot.
The v1.0 emulator answers version 2 without a blob, the game reports that the
license interface is too old, and it never reaches the code that validates the
install. Rebuilding the emulator with the right version is necessary but not
sufficient: the 32-byte blob has to be *correct*, and it can be computed from the
binary without ever running the game.

### The self-debugging license gate

`selene.exe` re-executes itself as `selene.exe -child` under
`DEBUG_ONLY_THIS_PROCESS` and services eight breakpoints, at VAs
`0x140002d8c`, `0x140002d92`, `0x140002d98`, `0x140002d9e`, `0x140002da4`,
`0x140002daa`, `0x140002db0`, `0x140002db6`. The table at `0x140013380` holds
eight 16-byte records `{int3 RVA, continuation RVA, reject RVA, index}`, with the
reject target `0x140002cbd` (`"license blob rejected"`). On each trap the parent
takes the child's `EAX` and compares it with `fcn.140003020(index)`.

The license structure passed in is `{u32 magic = 0x1067, u32 version = 1,
u8 blob[32]}`, and the child computes the 8-word `mixer3` of `blob`. Working
backwards from the eight compared values gives, per word:

```
expected[i] = rotl(crc32(text), 3*i) ^ (C[i] ^ ((i + 1) * 0x9e3779b9))
```

`crc32(text)` is the CRC-32 of the raw `.text` section (`VA 0x1000`, raw
`0x400`, size `0xd000` → `0xadf77919`) and `C` is the eight dwords at VA
`0x14000f358` (file offset `0xd958`):

```
1973a94c ce811b63 f9415bcd a9bd5ca8 3d2bc309 767bf471 0dfa969a add73b59
```

which yields

```
2ab3a9ec 9d5420dc 5e39708d 3f928917 5daf394b 7fbbf8dc ba187548 7f59487e
```

`mixer3` is an ARX permutation over eight 32-bit words, three identical rounds:

```
r0 += r1;  r3 = rotl(r3 ^ r0, 11);  r2 += r3;  r1 = rotl(r1 ^ r2, 7)
r4 += r5;  r7 = rotl(r7 ^ r4, 13);  r6 += r7;  r5 = ror(r5 ^ r6, 15)
swap(r0, r4)
```

Everything is invertible, so `blob = inv_mixer3(expected)`:

```
f1026546 9dcd5010 0e66eb17 d83e659f 32284e46 5e568616 27afe6e1 51023b0f
```

### From the blob to the flag

The success path checks that the buffer it derives looks like a flag (byte 4 is
`{`) and prints it. That buffer is 38 bytes at VA `0x14000f2a0` (file `0xd8a0`):

```
fd5a1da6 b594ae58 aab46d77 c763538c d325c42a 2ae5d6ce 23605321 f40b4112
a5b94548 70b5
```

and it is decrypted with the blob as a ChaCha20 key, `ctr = 0`, `nonce = 0`.
So the license blob is the key and the license blob is what the v1.0 crack never
had.

## Solution

1. Extract the release, drop the solver next to `setup.exe` and run it:

   ```bash
   unzip 28-Selene.Protocol.v1.1-LNR.zip
   cd Selene.Protocol.v1.1-LNR
   cp ../solve.py .
   python3 solve.py setup.exe
   ```

   It reproduces the key derivation, decrypts `.lnr0`, writes `selene.exe`, reads
   `crc32(.text)` and the constant table, inverts `mixer3` and decrypts the
   38-byte buffer:

   ```
   archive: 630304 bytes, member b'selene.exe', 630272 bytes -> selene.exe
   crc32(.text) = adf77919
   license blob = f10265469dcd50100e66eb17d83e659f32284e465e56861627afe6e151023b0f
   flag = flag{n0_m0r3_nuk3z_th15_0n3_1z_pr0p3r}
   ```

2. Optional: undo the sabotage in a copy of the installer, so the shipped setup
   derives the real key itself. The five-byte jump at offset `0x30c5` becomes five
   NOPs:

   ```bash
   cp setup.exe setup_fixed.exe
   printf '\x90\x90\x90\x90\x90' | dd of=setup_fixed.exe bs=1 seek=$((0x30c5)) conv=notrunc
   ```

   The FNV loop underneath is intact, so with the jump removed the installer
   computes the same extension as `solve.py` (`aa3a61f5…a0ee81`) and decrypts
   `.lnr0` correctly. The `license blob = …` line printed by `solve.py` is the
   blob a v1.1 emulator has to return.

3. To actually *run* the release, add the missing fourth vtable slot to the crack
   (`requestBlob(iface, out, 40)` returning the 32-byte blob above with
   `QueryVersion = 3`) and install as usual: `setup.exe`, then copy
   `winmm.dll`, `winmm.txt` and the rebuilt DLL next to `selene.exe`. The game
   prints the flag once the blob is accepted. This step is not needed to recover
   the flag — step 1 does it statically.

## Flag

```
flag{n0_m0r3_nuk3z_th15_0n3_1z_pr0p3r}
```

## Notes

- Order matters: `blob` is *derived from* `selene.exe` (`crc32` of `.text` plus a
  constant table), so patching `selene.exe` invalidates the blob. Do not patch the
  game before computing `crc32(.text)`.
- The installer patch is at file offset `0x30c5` (RVA `0x3cc5`). It only disables
  a jump; the FNV loop below it is intact, which is why recomputing the key
  offline is enough.
- `mixer3` uses `ror` for the `r5` step and `rol` everywhere else; getting that
  wrong breaks the inverse even though the forward direction still looks
  plausible. The solver asserts `mixer3(inv_mixer3(x)) == x` on the real data.
- PE parsing pitfalls worth knowing: `pefile.get_data()` takes an RVA while
  `SectionStructure.get_data()` returns raw file bytes; `va2off` must subtract the
  ImageBase before matching section VAs.
- `.lnr1` and the rest of `.rdata` are never touched by the flag path.
