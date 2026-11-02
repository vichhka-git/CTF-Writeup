# Project Mangoo

Pwn, 64 points, 210 solves. A Windows console program runs under Wine behind a TLS socket. It asks
for a challenge response, then serves a six-option gateway console. A signed 16-bit bounds check on
the channel index lets a negative index reach the context header, the header points at a telemetry
buffer the user fills, and an indirect call through that buffer becomes a stack pivot into
attacker-controlled bytes.

## What you are given

`project-mangoo.zip` expands to:

```
project_mangoo.exe  139,776 bytes, PE32+ x86-64, stripped
Dockerfile          ubuntu:22.04 with wine64 and socat
run_mangoo.sh       socat wrapper, runs the exe as user ctf
docker-compose.yml  MANGOO_ROOT_KEY in the environment
```

The flag is `getenv("MANGOO_ROOT_KEY")`. The portal supplies `<challenge-host>` and `<port>`; the
instance is TLS wrapped, and the team's client used `ssl` with verification disabled. The compose
file publishes a plain TCP port for local work, so a local reproduction needs the same TLS wrapper
or a local forward.

## Reproduction

1. Get past the greeting. `main` seeds `srand(time ^ pid)`, prints 32 random bytes as 64 hex
   characters on the `[*] Session Challenge:` line, then waits at `[*] Authorization Token:`. The
   expected token is

   ```
   token[i] = rol8(challenge[i], 3) ^ ((0x11 * i) & 0xff) ^ 0x6a
   ```

   sent as 64 hex characters. A correct answer gives `[+] Session authenticated.`

2. Map the console: `1) Ingest Telemetry Stream`, `2) Query Channel`, `3) Commit Configuration`,
   `4) System Status`, `5) Terminate`, `6) Sync Channel`.

3. Find where the flag lives. The root key is copied with `strncpy` into a 256-byte `VirtualAlloc`
   buffer and the pointer is stored at `ctx+0x50`, where `ctx` is a stack object in `main`. Nothing
   prints the buffer's contents, so the exit is a call that takes the pointer as its argument.

4. Read the channel index handling. `Sync Channel` (case 6, `0x140019ea0`) reads the index with
   `atoi` and then does:

   ```
   cmp ax, 0xf
   jg  out_of_bounds
   ```

   The compare is signed 16-bit, so every negative index passes. The descriptor is
   `ptr = [ctx + idx*32 + 0x58]`, and the handler performs `call [ptr+0x10]` whenever that slot
   holds something other than `0x140019cb0` (the check is inverted).

5. Pick `idx = -2`. Then `idx*32 + 0x58 = 0x18`, so `ptr = [ctx+0x18]`, which is the telemetry
   buffer that option 1 allocates and fills. Up to `0x2c00` bytes are accepted, so `[buf+0x10]` is
   an arbitrary call target.

6. Leak with the same bug. `Query Channel` prints `ID`, `Status`, `Label` and `Ref` for any index.
   Index -3 gives `Ref: 0000000140001550`, an image pointer, so base = leak - 0x1550 =
   `0x140000000` (the PE has no DYNAMIC_BASE, so this mainly confirms the layout). Index -1 gives
   the root-key buffer, which was `Ref: 00000000007f0000` in the recorded local run; on the live
   service read the value out of the response instead of reusing that one.

7. Build the buffer. The pivot gadget is `0x1400016d0`:

   ```
   mov rax, [rcx]
   mov rsp, rax
   add rsp, 0x18
   ret
   ```

   The Sync handler leaves `rcx = ctx+0x18`, so `rsp` becomes `buf+0x18`. The notes describe the
   bottom of the allocation as having no stack room, so the chain hops forward twice with
   `0x14000fde0` (`add rsp,0x1040; pop rdi; ret`) and then runs from `0x20b0`:

   | offset | value | purpose |
   |---|---|---|
   | 0x10 | `0x1400016d0` | indirect call target, the pivot |
   | 0x18 | `0x14000fde0` | first hop |
   | 0x1060 | 0 | popped into rdi |
   | 0x1068 | `0x14000fde0` | second hop |
   | 0x20b0 | 0 | popped into rdi |
   | 0x20b8 | `0x140019cd0` | stack alignment |
   | 0x20c0 | `0x14000bd60` | `pop rcx; ret` |
   | 0x20c8 | root-key pointer | argument for `puts` |
   | 0x20d0 | `0x140018348` | `puts` in msvcrt |
   | 0x20d8, 0x20e0 | `0x140019cd0` | keep the chain landing on a `ret` |

   The buffer is `0x20e8` bytes, uploaded as hex after `1` and the `Size:` and `Stream:` prompts.

8. Trigger it. Choose `6`, then channel `-2`. The handler calls `[buf+0x10]`, the pivot moves `rsp`
   into the buffer, the two hops walk to `0x20b0`, and `puts` prints the root key.

9. The process faults once the chain runs past the buffer. That is expected and harmless:
   `setvbuf(_IONBF)` makes stdout unbuffered, so the flag is already on the wire. The accepted run
   ended with `RESULT: hiCTF{...}`.

10. What the notes do not record: the root-key buffer address on the accepted live run, and the
    exact fault text, which differs between the two local runs in `run1.txt` and `run2.txt`.

## Why it works

The index guard tests only the upper bound. A signed 16-bit compare against 15 leaves every value
below zero open, so an array read becomes a read of the context header. The header already holds
pointers the program placed there, including the telemetry buffer, and the telemetry buffer is user
data. The indirect call `[ptr+0x10]` then treats that user data as a code address, and one
`mov rsp, ...` gadget turns the same buffer into the stack the chain runs on.

Wine does not add a layer here. The PE is not DYNAMIC_BASE, so the gadget addresses are stable, and
the only value the chain has to read at runtime is the root-key pointer, which the same
out-of-bounds read hands back.

## Flag

```
hiCTF{n0_g4dg3ts_n0_sh3llc0d3_jusT_p1v0t_d33p3r_5dd4aae270}
```
