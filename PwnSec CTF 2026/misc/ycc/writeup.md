# ycc — Misc (Easy)

**Flag:** `pwnsec{9d6ede77379db34e}`

## Target
`ysh` (a shell written in the toy language *y*, compiled to a native binary by `ycc`) is
the login shell for user `app`. `/readflag` is setuid-root, mode `4111` (executable but
**not readable**), and prints the flag when called as `/readflag owo`. So the flag must
be *executed* out, not read.

Two walls stand in the way:

1. **`ysh` never reaches `spawn`.** The interactive REPL calls `dispatch(line)`, which
   only ever invokes entries of the `HANDLERS` map. `spawn(trimmed)` lives in
   `cmd_run_line`, reachable solely through `ysh -c`. So no arbitrary command from the prompt.
2. **The one expressive handler is sandboxed.** `eval` writes your y code to
   `/tmp/_ysh_eval.y` and compiles it with
   `ycc --no-exec --no-io --compile`, then runs the result.

## What the sandbox actually is
`ycc` is a **y → C transpiler**: it emits C, then shells out to
`/usr/bin/cc -w -O2 -std=gnu99 -no-pie ... -I$YCC_RUNTIME_DIR $YCC_RUNTIME_DIR/runtime.c`.

Diffing `--emit-c` with and without the flags shows the whole sandbox is **five deleted
lines** of the generated prelude:

```c
y_scope_set(scope, "exec",       y_mk_func(y_builtin_exec,       1, NULL));
y_scope_set(scope, "spawn",      y_mk_func(y_builtin_spawn,      1, NULL));
y_scope_set(scope, "read_file",  y_mk_func(y_builtin_read_file,  1, NULL));
y_scope_set(scope, "write_file", y_mk_func(y_builtin_write_file, 2, NULL));
y_scope_set(scope, "getenv",     y_mk_func(y_builtin_getenv,     1, NULL));
```

It only unbinds *names*. `runtime.c` is still compiled in, so `y_builtin_exec` — and
libc's `system()`, via `stdlib.h` from `runtime.h` — are still linked. Escaping the
sandbox therefore just means getting arbitrary text into the generated C.

## The bug: unescaped dot-field in codegen
`runtime.c` ships a correct escaper, `y_escape_c_string()`, with a proper
`\%03o` fallback — **and never calls it.** `ycc` (itself written in y) re-implements
escaping at the y level. That escaper is applied to string literals, which are solid:
every byte 0x01–0xFF round-trips safely (`"` → `\"`, `\` → `\\`, controls → octal).

But **field access is emitted by a different path that does no escaping at all**:

```c
YValue *_v = y_map_get(_m, "FIELD");
if (!_v) { fprintf(stderr, "runtime error: key 'FIELD' not found\n"); exit(1); }
```

`FIELD` is the raw *token value* after the `.`, and the parser accepts any token there —
including a **string token**. `1.2.3` emitting `y_map_get(_m, "3")` is the tell. Since a
y string literal may contain a real `"` via `\x22`/`\"`, the field escapes its own C
string literal:

```
m."a\x22);exit(0);//"   ->   y_map_get(_m, "a");exit(0);//")
```

## Building a payload that compiles
Two constraints shape the final payload:

* `FIELD` is interpolated **twice** (the lookup and the error message), so the injection
  must be syntactically valid in both places.
* The first site is a **declaration** (`YValue *_v = ...`), where a top-level `,` is a
  declarator separator, not the comma operator — `_v = A, system(...), exit(0)` fails to
  compile. Use the conditional operator instead, which needs no commas.

With `FIELD` = `zz") ? (YValue*)0 : (YValue*)(long)system("/readflag owo` both sites land
as valid expressions:

```c
YValue *_v = y_map_get(_m, "zz") ? (YValue*)0 : (YValue*)(long)system("/readflag owo");
if (!_v) { fprintf(stderr, "runtime error: key 'zz") ? (YValue*)0
         : (YValue*)(long)system("/readflag owo' not found\n"); exit(1); }
```

Key `zz` is absent from the map, so `y_map_get` returns `NULL`, the condition is false,
and the false branch — `system("/readflag owo")` — runs.

## Exploit
```
eval let m = {a:1}; print(m."zz\") ? (YValue*)0 : (YValue*)(long)system(\"/readflag owo");
```

```
y> flag for you pwnsec{9d6ede77379db34e}
runtime error: key 'zz
```

(The service speaks TLS on 443: `openssl s_client -quiet -connect <host>:443 -servername <host>`.)

## Paths not taken
* `calc`/`to_rpn` index a 16-slot array with an unbounded `sp`, but `y_arr_set`/`y_arr_index`
  wrap the index modulo `count`, so there is no OOB — a deliberate-looking dead end.
* `scope_new/def/find/get/set` and `global_get` stay registered under the sandbox, but they
  operate on the interpreter's separate `g_vm_scopes` table, empty in a compiled program.
* `import` is a compile-time textual include that bypasses `--no-io`'s *runtime* read ban,
  but the flag file is mode `4111` — unreadable — so reading was never the path.

## Lesson
A sandbox that removes *names* rather than *capabilities* is only as strong as the code
generator underneath it: `runtime.c` was still linked, so one unescaped interpolation in
codegen restored everything the flags took away. The decisive recon step was
`diff <(ycc -S) <(ycc --no-exec --no-io -S)` — five lines — which reframed the task from
"break the sandbox" to "inject C". And a correct-but-uncalled helper
(`y_escape_c_string`) is a strong hint that the real escaper is a buggy re-implementation:
check every interpolation site, not just the obvious one.
