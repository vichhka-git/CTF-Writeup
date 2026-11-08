# golem

**Category:** Misc · **Points:** 540 · **Flag:** `CSCTF{67PhGilFd0XF2XOPyTMq9D24}`

## What the handout gives you

A specification (`SPEC.md`), a set of worked examples, and a network audit service. The
service sends a program in a small register machine language and an input tape, expects the
program's output, and repeats one hundred times. One wrong answer ends the session.

The machine is called GASM: sixteen unsigned 16-bit registers, a program counter, and a
handful of block constructs.

## Walkthrough

1. **Read the spec's arithmetic rules carefully.** All arithmetic is modulo 65536.
   Assignment of a negative value wraps. Division by zero yields 65535, and modulo by zero
   returns the dividend unchanged. Shift counts are masked with 15 before shifting, and
   right shifts are logical, not arithmetic.

2. **Read the block constructs.** `rep N` repeats a body N times. `ifz` and `ifn` test the
   register **once, at entry**, not on each iteration. `end` closes a block. Instructions
   read their operands before the destination is written, which matters when source and
   destination are the same register.

3. **Read the tape semantics.** `in` reads one byte from the input tape, and reading past
   the end returns 65535 rather than halting. `out` appends a byte to the output stream.

4. **Build an interpreter that follows all ten quirks.** That sounds like a lot, but it is
   a hundred lines: decode an instruction, apply the wrapped arithmetic, handle the block
   stack, and keep the tape pointer. The supplied examples are the test suite.

5. **Validate against every example.** The examples cover each quirk at least once —
   division by zero, the shift mask, the past-end read, the once-only block test. If all
   of them reproduce their expected output, the interpreter is correct.

6. **Talk to the service.** For each round, read the program and the input tape, run it,
   and reply with the output bytes as space-separated decimal numbers. The rounds are
   timed, so the interpreter has to be fast enough: a straightforward Python
   implementation handles the program sizes comfortably.

7. **Finish all one hundred rounds.** The service prints the flag after the last correct
   answer. A single mistake closes the connection and you start again.

## Answer

`CSCTF{67PhGilFd0XF2XOPyTMq9D24}`

## Notes

The traps are all in the spec, not in the programs. An interpreter that uses ordinary
integer arithmetic, or that re-tests a loop condition each pass, passes the first few
examples and then diverges on a program that depends on the wrap or the once-only test.

Run the examples before connecting. Debugging a round against a live socket that closes on
the first wrong answer wastes far more time than getting the interpreter right offline.
