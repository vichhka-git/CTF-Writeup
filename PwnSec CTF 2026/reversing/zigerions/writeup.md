# Zigerions (`Pickle_Riiiiick`) — Reverse Engineering (Hard, 33 solves)

**Flag:** `psctf{U_sh0u1dvebeen_@_g@m3r_0rHighIQ!}`  (note the `psctf{}` format, not `pwnsec{}`)

> *"life is what but a maze with no wrong answers"* — and in Rick and Morty the Zigerions
> trap Rick in a **simulation**. Four nested containers, each a different platform.

## Layer 1 — a Windows PyInstaller bundle inside a Linux ELF
`file` says 43MB static Linux ELF, not stripped — but the strings say otherwise:
`python310.dll`, `Failed to pre-initialize embedded python interpreter!`,
`Could not allocate memory for DYLIB_PYTHON structure.` That is the **PyInstaller**
bootloader, and the bundled binaries are `.dll`/`.pyd` — a *Windows* bundle carried inside a
*Linux* executable. That is the "chaotic mind".

The MEI cookie is at offset **6290383** of 43434736, i.e. with ~37MB of data *after* it, so
`pyinstxtractor`'s "the archive ends at EOF" assumption does not hold (and it isn't installed
here anyway). Locate the archive from the cookie instead:

```
overlayPos = cookiePos + 88 - lengthofPackage      = 1055456
tocPos     = overlayPos + toc                      = 6289455   (928 bytes)
```

23 TOC entries, including the user script `stub` and `PYZ.pyz` (95 modules). PyInstaller
strips the 16-byte `.pyc` header from `s`/`m`/`M` entries, so it must be re-added — with the
**right** magic: Python 3.10 is `3439` → `6f 0d 0d 0a` (using 3.11's `e7 0d 0d 0a` makes
`xdis` fail with a confusing `'NoneType' object is not iterable`).

## Layer 2 — stub.pyc
No 3.10 decompiler on the box, so `xdis` (`pip install xdis`, then `op_imports['3.10']`) gives
the constants and bytecode directly:

```python
XOR_KEY = (165, 60, 255, 0, 85, 170)          # a5 3c ff 00 55 aa
MARKER  = b'<<<PAYLOAD_START>>>'
```

plus `junk_validate_system`, `junk_check_platform`, `anti_debug_check` (IsDebuggerPresent),
and `show_fake_error` ("Wubba Lubba Dub Dub") — all decoys. `main()`:

```python
self_data   = open(sys.argv[0], 'rb').read()
rest        = self_data.split(MARKER, 1)[1]
payload_len = struct.unpack('<I', rest[:4])[0]        # 5591040
payload     = unscramble(rest[4:4+payload_len])       # -> tmp_*.exe, run, delete
```

and the disassembly of `unscramble` shows the twist — a repeating-key XOR **followed by a
full reversal** (`BUILD_SLICE` with `None, None, -1`):

```python
def unscramble(data):
    temp = bytearray(len(data))
    for i, b in enumerate(data):
        temp[i] = b ^ XOR_KEY[i % len(XOR_KEY)]
    return bytes(temp[::-1])
```

The key was guessable before decompiling: the bytes right after the marker are
`a5 3c ff 00 55 aa` repeating, which is the key XORed against a run of zeros.

Result: a 5591040-byte **PE32+**.

## Layer 3 — VMProtect, and why it does not need unpacking
`diec` reports MinGW + VMProtect 3.2–3.5, and the section table confirms it: `.text`,
`.rdata`, `.idata` … all have zero raw size, with a 5.5MB `.vmp1`. GUI subsystem.

Unpacking VMProtect is unnecessary — just let it run. Under `wine` it emits
`fixme:ntdll:enum_firmware_info SYSTEM_FIRMWARE_TABLE_INFORMATION` (VMProtect's anti-VM
probe) and exits silently, but `WINEDEBUG=+relay` shows it still does its job first:
12 × `CreateFileW`, 14 × `WriteFile`, and two interesting drops in `%TEMP%`:

```
AURA.gb      <- a Game Boy ROM: the "maze with no wrong answers"
svchost      <- the real payload
```

`AURA.gb` is deleted on exit; `svchost` survives.

## Layer 4 — an ELF with no code
`svchost` is a 5.6KB **non-stripped** Linux ELF built from `chal.c` that has **no `.text`
section at all** — only `.rodata` and `.data`, holding five objects:

| symbol | size | contents |
|---|---|---|
| `__3` | 16 | `M68K_AES_FLAGKEY` — the AES-128 key |
| `__2` | 11 | `00 01 02 04 08 10 20 40 80 1b 36` — AES Rcon |
| `__1` | 256 | AES **inverse** S-box (`52 09 6a d5 …`) |
| `__0` | 256 | AES forward S-box (`63 7c 77 7b …`) |
| `__4` | 48 | ciphertext, three blocks |

So the binary is not a program to reverse — it is an AES-128 key/ciphertext pair with its
tables. ECB decrypt:

```
674e0e33...6c0d35b3  ->  psctf{U_sh0u1dvebeen_@_g@m3r_0rHighIQ!}  + 9 bytes PKCS#7
```

The `M68K` in the key name and the `AURA.gb` drop are the joke: you were *meant* to play the
Game Boy maze. Decrypting the blob skips the game entirely — "no wrong answers".

## Lesson
Identify the *container* before reaching for a decompiler: `file` called this a Linux ELF,
but the strings said Windows PyInstaller, and the whole solve was four unwrapping steps with
only one genuinely analytical moment (reading `unscramble`). When a packer looks expensive —
VMProtect here — check whether the protected code's **side effects** are enough; a
`WINEDEBUG=+relay` trace found the dropped files in one run and made unpacking moot. And a
binary with no `.text` is a data file wearing an ELF header: dump the symbols, don't
disassemble.
