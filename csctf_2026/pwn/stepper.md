# stepper

**Category:** Pwn · **Points:** 900 · **Flag:** `CSCTF{4lEtOtFfb70qFDzWJrrgOixJ}`

## What the handout gives you

- `stepper.c` — the harness. It maps a 4 KB RWX code page and a 4 KB stack, keeps 16 guest registers in a `ctx` array, and loops for at most 12 steps.
- `stepper` — the compiled target, a 16 KB PIE built with `-O0 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now`.

Each step asks for a length of at most 6 and then that many raw bytes. Every byte is checked against four banned values: 0x0f, 0x05, 0x34, 0xcd, which together rule out a direct `syscall` or `int` and the one-byte `xor al` encoding. The 8-byte slot is then filled with NOPs, the input is copied over the first bytes, and `run_step` jumps to the slot.

## Walkthrough

1. **Find the return path.** The slot is bigger than eight bytes. At `code+8` the harness writes `ff 25 00 00 00 00` (`jmp qword ptr [rip+0]`), and at `code+14` it stores the address of `guest_exit`. A step shorter than 8 bytes runs off its own bytes into NOPs and then into that jump, so every step ends by jumping through the pointer at `code+14`. `guest_exit` saves all 16 registers into `ctx` and returns to the harness. That pointer is the way out.

2. **Note what survives.** `ctx` persists across steps, including RSP, which starts at `stack+0x1000-0x100`. The code page also persists: each step overwrites bytes 0..7 with NOPs before the copy, but bytes 8..15 are never touched.

3. **Get an address inside the page.** Step 1, six bytes: `call $+5; pop rax` (encoded `e8 00 00 00 00 58`). The call pushes the address of the next instruction and the pop moves it to rax, so rax = `code+5`.

4. **Keep it in two places.** Step 2: `push rax; mov rsi, rax` (`50 48 89 c6`). The guest stack now holds `code+5`, and rsi points at the same address. Both are needed later.

5. **Read the jump pointer.** Step 3: `mov rax, [rax+9]` (`48 8b 40 09`). With rax = `code+5` the load reads the qword at `code+14`, which is `guest_exit`.

6. **Turn it into `read`.** In the shipped binary `guest_exit` is at 0x1317 and the `read` PLT stub at 0x1160; the difference is 0x1b7. Step 4: `sub rax, 0x1b7` (`48 2d b7 01 00 00`). rax is now the PLT address, and the PIE base cancels because both symbols sit in the same image.

7. **Set the length.** Step 5: `mov edx, 0x1000` (`ba 00 10 00 00`).

8. **Rewrite the pointer, then use it.** Step 6: `mov [rsi+9], rax; xor edi, edi` (`48 89 46 09 31 ff`). rsi still holds `code+5`, so the store lands on `code+14` and replaces `guest_exit` with the `read` PLT stub. edi = 0 selects stdin. The step then falls into the jump, which calls `read(0, code+5, 0x1000)`.

9. **Return into the payload.** The `read` call returns to the address on top of the stack, which step 2 pushed: `code+5`. Send a 22-byte `execve("/bin//sh", NULL, NULL)` stub immediately after step 6, with no length line in front of it. The syscall bytes pass the filter because they arrive as data, not as a step.

10. **Use the shell.** The shell is attached to the socket; `cat /flag` prints the flag.

The timing detail matters. Steps 1 to 5 are sent after each `length>` prompt. Step 6 and the shellcode must be written in one go, because once `read` is running the harness will not print another prompt.

## Answer

`cat /flag` returns `CSCTF{4lEtOtFfb70qFDzWJrrgOixJ}`.

On the instance `/flag` is a symlink, so the target has to be resolved rather than assumed.

## Notes

- Six bytes is a hard budget. `mov [rsi+9], rax` takes four and `xor edi, edi` takes two, so the last step is exactly full.
- Sending the shellcode before step 6 does not work: it would be consumed as the step's code, fail the length check, or lose most of its bytes to the 6-byte limit.
- If the offsets differ in your copy, recompute the distance between `guest_exit` and the `read` PLT stub. Only the difference is used, so the trick survives any PIE base.
- A step must reach the jump. One that loops, faults, or runs off the page never returns to the harness, so the connection stalls or dies.
