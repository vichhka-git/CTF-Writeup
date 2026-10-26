# IL2FLAG

**Category:** rev · **Points:** 80 · **Solves:** 106 · **Author:** LukeFZ

## Challenge

A Unity IL2CPP build with its metadata "sawed in half". The handout is a Windows
player directory:

| file | size |
|---|---|
| `il2flag.exe` | 11 384 728 B |
| `baselib.dll` | 111 016 B |
| `Data/Metadata/global-metadata.dat` | 3 284 976 B |
| `Data/Resources/mscorlib.dll-resources.dat` | 373 956 B |

The flag is still entered at runtime, so whatever the metadata damage was, the
check must still be intact somewhere.

## TL;DR

`global-metadata.dat` was overwritten everywhere except the literals the checker
touches, so a normal IL2CPP dump is impossible. But `Program.Main` is
control-flow-flattened into 34 sequential dispatcher blocks, and every
`(stage, character)` case stub only compares the *length* of one string literal
against `0xa`. Resolving all 256 usage slots per stage and keeping the character
whose literal is exactly 10 UTF-16 units long recovers the flag, 34 characters in
a row, without executing anything.

## Files

| file | description |
|---|---|
| `il2flag.exe` | x86-64 PE, IL2CPP-compiled managed code (ImageBase `0x140000000`) |
| `baselib.dll` | Unity engine side; not needed for the solve |
| `Data/Metadata/global-metadata.dat` | damaged IL2CPP metadata; literal tables survived |
| `Data/Resources/mscorlib.dll-resources.dat` | BCL resources; not needed |
| `solve.py` | static solver: walks the dispatcher chain, decodes literals |

Tools: `python3`, `pip install pefile capstone` (tested with capstone 5,
pefile 2024.x). Any disassembler works for the analysis.

## Analysis

### What survives in the metadata

`global-metadata.dat` normally starts with the magic `0xFAB11BAF` and a version
word. Here the first eight bytes are `a38b03ee 3d1e1053` — the header was
scrambled too. Reading it as 32 little-endian `int32` values, a few fields still
make sense and agree with each other:

```
$ python3 - <<'EOF'
import struct
md = open('Data/Metadata/global-metadata.dat','rb').read()
print(' '.join(hex(x) for x in struct.unpack_from('<32I', md, 0)[:8]))
EOF
0xee038ba3 0x3d1e1053 0x20c 0xd4bc 0x352f 0xd6c8 0x31d67 0xb5685f7
```

`hdr[2] = 0x20c` is the literal boundary table, `hdr[5] = 0xd6c8` the literal
blob that follows it, `hdr[4] = 0x352f` = 13 615 boundary entries (exactly the gap
between the two regions divided by 4) and `hdr[6] = 0x31d67` = 204 135 blob bytes.
Literals are slice pairs into the blob:

```
literal i = blob[ off[i] : off[i+1] ]          # UTF-8
```

The rest is damage: sampling a 4 KB window in the middle of the file shows about
63% non-printable bytes, where real IL2CPP metadata is dominated by identifier
strings. The type, method and field tables are gone, so rebuilding the metadata
(Il2CppDumper and friends) is a dead end.

Only the boundary entries the checker actually resolves survived. Most pairs read
from the table are nonsense, but the ones used by the flag comparison are intact —
for example entry 2 versus entry 13399 (the literal used by stage 0 for `'f'`):

```
$ python3 - <<'EOF'
import struct
md = open('Data/Metadata/global-metadata.dat','rb').read()
h = struct.unpack_from('<32I', md, 0)
off, data = h[2], h[5]
for i in (2, 13399):
    a, b = struct.unpack_from('<II', md, off + 4*i)
    print('entry', i, a, b, 'len', b - a, repr(md[data+a:data+b][:24]))
EOF
entry 2 1 1776959961 len 1776959960 b'\t\t\t=\xf3\xf5\xb2hrh\x85E\x0e1u"\x82+\xf8&\xa9\x9d\xabe'
entry 13399 201599 201609 len 10 b'zAXaYoUz37'
```

Of the 8 670 of the 8 704 slot entries that carry a literal compare, only 156
still point at a plausible pair, and exactly 35 of those yield a printable
ten-byte literal. The accepted character of each stage is one of them.

### The flattened checker

The managed entry point lands in `Program.Main` at RVA `0x3018c0`, the first of a
chain of 34 nearly identical blocks. Stage 0 is:

```asm
0x1403018f5  xor  ecx, ecx
0x1403018f7  call 0x140437af0            ; next input character
0x1403018fc  cmp  eax, 0xff
0x140301901  ja   0x140305102            ; out-of-range: throw
0x140301907  lea  rdx, [rip - 0x30190e]  ; rdx = ImageBase
0x14030190e  cdqe
0x140301910  mov  ecx, [rdx + rax*4 + 0x305144]
0x140301917  add  rcx, rdx
0x14030191a  jmp  rcx
```

`0x437af0` is a global cursor helper (a `MoveNext`/`Current` pair that ignores its
argument, which is why every caller passes `ecx = 0`); it hands back the next
byte of the input. The 256-entry table at RVA `0x305144` holds ImageBase-relative
32-bit offsets, so the character selects a ~56-byte case stub. Each stage has its
own table and its own set of stubs. A case stub for `'f'` (stage 0) looks like:

```asm
0x140302f6c  cmp   byte ptr [rip + 0x72d1f1], 0
0x140302f73  jne   0x140302f88
0x140302f75  lea   rcx, [rip + 0x68e47c]
0x140302f7c  call  0x140089c60           ; initialize the usage slot (once)
0x140302f88  mov   rax, qword ptr [rip + 0x68e469]   ; Il2CppString*
0x140302f8f  cmp   dword ptr [rax + 0x10], 0xa
0x140302f93  jne   0x140304fed           ; throw
0x140302f99  xor   ecx, ecx
0x140302f9f  jmp   0x14030a550           ; next stage
```

`rax` is an `Il2CppString*`: object header (klass, monitor) at `+0x00`, the
string length in **UTF-16 code units** at `+0x10`, the UTF-8 payload at `+0x14`.
So the stub checks `literal.Length == 10` — it never compares the text.

On mismatch the stub jumps to a shared block (`0x304fed`) that calls the
IL2CPP throw helper at `0x43e8c0`. On success it falls through into the next
dispatcher. Nothing is printed and no branch depends on the literal's content,
which makes the check invertible by pure static analysis.

### Resolving a usage slot

The `mov rax, [rip+...]` in a stub reads a global that the initializer
(`0x89c60` → `0x1050c0`) fills from an IL2CPP metadata-usage token. The decoder at
`0x96dd0` interprets the 64-bit token as:

```
kind  = (token >> 29) - 1
index = (token >> 1) & 0x0FFFFFFF
```

`kind == 3` is a string literal, in which case `index` selects the boundary pair
in the literal offset table. That is all that is needed: for each of the 34
stages, decode the 256 stubs, compute each literal's UTF-16 length, and keep the
characters whose literal is 10 units long.

## Solution

### 1. Run the solver

```bash
unzip 11-IL2FLAG.zip -d il2flag && cd il2flag
cp ../solve.py .
python3 -m pip install pefile capstone
python3 solve.py            # defaults: il2flag.exe, Data/Metadata/global-metadata.dat
```

`solve.py` finds each dispatcher table, decodes all 256 case stubs, follows the
chain by majority vote over the stub targets, and prints the accepted character
per stage:

```
stage  0  dispatcher=0x3018c0  accepted='f'  literal=b'zAXaYoUz37'
stage  1  dispatcher=0x30a550  accepted='l'  literal=b'zUDUIolpHl'
stage  2  dispatcher=0x3104f0  accepted='a'  literal=b'CE7xf82fuD'
stage  3  dispatcher=0x319180  accepted='g'  literal=b'DwOxzoMP6t'
stage  4  dispatcher=0x394c80  accepted='{'  literal=b'iDJfhLV0Za'
...
stage 12  dispatcher=0x3cfd40  accepted='k'  literal=b'hF63tcAHTn'
...
stage 33  dispatcher=0x3806d0  accepted='}'  literal=b'8kADN9G8qI'

FLAG: flag{im_thinking_miku_miku_ooeeoo}
```

The chain has exactly as many stages as the flag has characters, and the
`flag{`/`}` characters land on stages 0–4 and 33, which is a good structural
sanity check.

### 2. Handle the length collisions

Stage 9 has a second alphanumeric 10-byte literal (`Octb7jI8kt`) at table index
255, but that entry can never be reached: the dispatcher rejects `eax > 0xff`
*before* the table lookup, so index 255 never dispatches.

Stages 12 and 24 have several table entries whose literal is 10 units long, e.g.
stage 12 also resolves `wiywjG\x1cQUK` and `ub92d#\x87\xf7\xfag`, stage 24 also
resolves `ThMQR\x18\x00)zs` and five more. Those decoys carry control bytes, so
requiring a printable alphanumeric literal leaves exactly one candidate per stage;
both stages still resolve to `k`, so the flag does not depend on the filter.

## Flag

```
flag{im_thinking_miku_miku_ooeeoo}
```

## Notes

- No Windows environment is needed: the binary is never executed. Only `pefile`
  (section mapping) and `capstone` (instruction decoding) are used.
- The table load is the reliable anchor for a stage: `mov ecx, [rdx + rax*4 + X]`
  right after the call to `0x437af0`. Table RVAs differ per stage, and the case
  stubs are compact — parsing the next ~0x50 bytes after each target is enough.
- The metadata damage is targeted: only headers 2/5 (table, blob) and the boundary
  pairs for the 34 flag literals survived intact. Recovering the flag therefore
  needs no metadata repair, only decoding of the usage slots the stubs already
  reference.
