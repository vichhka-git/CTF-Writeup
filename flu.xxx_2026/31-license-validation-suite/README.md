# LIcense Validation Suite

**Category:** rev · **Points:** 65 · **Solves:** 197 · **Author:** niaroc

## Challenge

A stripped ELF asks for a license key and prints `[SUCCESS] Key verified!` or
`[ERROR] Invalid license key, potential fraud has been detected`. The key
generator is right there in the binary — but it mixes in the result of a
`ptrace(PTRACE_TRACEME)` call, so the bytes it compares against depend on whether
the process is being traced.

## TL;DR

The program builds a 26-byte key in an `mmap`ed RWX page from a 26-byte seed
table in `.rodata`, using `r8d` as an additive constant. `r8d` is computed from
`ptrace(PTRACE_TRACEME)`: `0x37` when the call returns 0 (normal untraced
process) and `0x91` when it returns −1 (any tracer, or a host that does not
implement `ptrace`). Re-implementing the 26-iteration loop for `r8d = 0x37`
yields the flag directly, and patching the `ptrace` call to return 0 makes the
unmodified key comparison accept it. Under `gdb` the same result is reached by
overwriting `r8d` after the detection code.

## Files

| file | description |
|---|---|
| `31-License_Validation_Suite` | ELF 64-bit LSB PIE, x86-64, stripped, 14 472 B |
| `keygen.py` | pure-static reimplementation of the key derivation |

Tools: `python3` for the keygen, `gdb` for the dynamic route, `objdump`/Ghidra
for the listing. The binary is 64-bit (the arithmetic inside is 32-bit) and needs
only libc.

## Analysis

### Key generation

Everything lives in one function at `0x1249`, called from `main` at `0x140c`.
The first useful call is `mmap` at `0x1289` — `size 0x1000`, `PROT_READ|WRITE|
EXEC`, `MAP_PRIVATE|ANONYMOUS` — and its return value is kept in `rbx` as the key
buffer.

Then comes the tracer check:

```
12af:  mov    eax,0
12b4:  call   1130 <ptrace@plt>
12b9:  neg    rax
12bc:  sbb    r8b,r8b
12bf:  and    r8d,0x5a
12d2:  add    r8d,0x37
```

`PTRACE_TRACEME` returns 0 when it succeeds and −1 otherwise, so `r8d` becomes
`0x37` (untraced) or `0x91` (traced). The value is not a flag check — it is a
key-derivation parameter, which is why the binary "works" under a debugger but
rejects the flag there.

The derivation itself is 26 iterations (`0x12dd..0x1303`), `rdx = 0..25`,
`esi = 17*rdx`, `eax` carrying over between iterations and seeded with
`0xffffffa5`, `r9` pointing at the 26-byte seed table at `0x2120`:

```
30 be cd e9 1b 0b 32 d2 75 1f cc 41 19 af 4c e9 8c 40 ab d2 6d 3a 9e 01 6a d4
```

Per iteration:

```
edi = r8d + 17*rdx
ecx = eax*31            (shl 5, sub eax)
eax = edi + ecx
al  = rol(al, 3)
al ^= seed[rdx]
eax ^= 0xffffffc7
buf[rdx] = al
```

`0x1305` NUL-terminates the 26 bytes. Nothing else touches the buffer before the
comparison, so re-running those 26 iterations for either `r8d` value reproduces
the expected key exactly.

### Comparison

The prompt is `printf("Enter License Key: ")` at `0x1309`; `fgets(rsp, 0x80,
stdin)` at `0x132e`, newline stripped by `strcspn` (`0x1349`), `strlen` at
`0x1355`. `0x135a` compares the length against `0x1a` (26) and `setne` loads the
"length is wrong" bit into `bpl`; the loop at `0x136a` ORs `buf[i] ^ input[i]`
into `ebp`. A single nonzero byte anywhere fails, so the flag is exactly the
generated key — there is no second check on top of it.

## Solution

### 1. Re-derive the key with `r8d = 0x37`

`keygen.py` emulates the loop with 32-bit wrapping and the byte-wide
rotate/XOR, for both `r8d` values:

```bash
python3 keygen.py
```

```
untraced (r8d=0x37): flag{GDB_Runtime_Insights}
traced   (r8d=0x91): 930285d0f45f36817744b0620752e0abf949b8f52eb92ab73fcd
```

The `0x91` string is the key a *traced* run compares against — 26 bytes of
hex-looking garbage, and the intended decoy: it authenticates only when the
process is under a debugger, never on a normal run.

### 2. Verify against the binary with the `ptrace` result forced

A native, untraced Linux process gets 0 from `PTRACE_TRACEME`, i.e. `r8d = 0x37`.
Docker on Apple silicon cannot provide that (see Notes), so make the call return
0 unconditionally: five bytes at `0x12b4` become `xor eax,eax; nop; nop; nop`,
which is exactly the state a normal run is in.

```bash
printf 'flag{GDB_Runtime_Insights}' > flagkey.bin
python3 - <<'EOF'
d = bytearray(open('31-License_Validation_Suite','rb').read())
assert d[0x12b4:0x12b9] == bytes.fromhex('e877feffff')
d[0x12b4:0x12b9] = bytes.fromhex('31c0909090')       # xor eax,eax; nop*3
open('LVS_ptrace0','wb').write(d)
EOF
chmod +x LVS_ptrace0
./LVS_ptrace0 < flagkey.bin
```

```
==================================================
            License Validation Suite
==================================================

Enter License Key: [SUCCESS] Key verified!
```

One changed character prints the other verdict, so the comparison is live:

```bash
printf 'flag{GDB_Runtime_Insightz}' > bad.bin && ./LVS_ptrace0 < bad.bin
```

```
Enter License Key: [ERROR] Invalid license key, potential fraud has been detected
```

### 3. Same thing under `gdb`

On a host where `gdb` can attach, no patching is needed — the traced path returns
−1 and sets `r8d = 0x91`, which is precisely the value to undo:

```bash
gdb -q ./31-License_Validation_Suite
(gdb) break *0x12d6            # seed table is loaded, r8d already computed
(gdb) run < flagkey.bin
(gdb) set $r8d = 0x37          # pretend the ptrace call returned 0
(gdb) break *0x1305            # after the 26-iteration loop
(gdb) continue
(gdb) x/26cb $rbx              # the generated key
(gdb) continue                 # comparison runs with the untraced key
```

Without the `set $r8d = 0x37` line the dump shows the `0x91` bytes from step 1
and the program rejects the input. The `set` is the whole trick: the detection
result is only ever added into the derivation.

## Flag

```
flag{GDB_Runtime_Insights}
```

## Notes

Why Docker/emulation shows the decoy: inside a container on an Apple-silicon
host the binary runs under Rosetta, and `ptrace` there is not implemented —
`PTRACE_TRACEME` returns −1 (`Function not implemented`), exactly as it does under
a real tracer. So `r8d = 0x91`, the generated key is the hex-looking one, and the
flag is rejected. `gdb` cannot attach in that environment either
(`warning: Could not trace the inferior process`), which is why step 2 patches the
call instead of tracing it. On a native x86-64 Linux host no workaround is needed
at all: the binary runs untraced, so `r8d = 0x37` and the flag is accepted
directly; step 3 is the debugger route, which needs a real `ptrace` and therefore
could not be exercised in an emulated container here.
