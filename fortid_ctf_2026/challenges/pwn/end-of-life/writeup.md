# FortID CTF 2026 Writeup: End of Life

- **Category:** Pwn
- **Challenge author:** ante
- **Points / Solves:** 154 pts / 57 solves
- **Flag:** `FortID{3oF_15_JU57_4_5u993571On_ed12f9c3f7}`

---

## Challenge

> MS Windows 10 has reached its (endoflife.date), but MS DOS is still going strong.

---

## Summary

The DOS program validates `INPUT.TXT` as text, where Ctrl-Z ends input, but then scans the same file in binary mode with an unbounded `%[^ ]` into a 17-byte stack buffer. A DOS real-mode segment alias lets the overflow overwrite executable bytes and redirect the saved return address to a file-copy stub.

## Solution

### 1. Bypass validation and map the overflow

Sixteen lowercase bytes pass `check_input`; Ctrl-Z ends that text-mode check. The binary-mode scan continues past it. Borland startup initializes the stack with `SP=0`; `process_input` puts its buffer at `DS:FFE0`, with the saved near return address 20 bytes from the buffer start. The payload places `0x25F0` there. Since `DS=CS+0x23F`, `DS:0000` aliases `CS:23F0`; the 32-byte overflow to offset zero makes the following input bytes executable through that alias.

The first 0x200 bytes of the loaded data segment are copied into the overflow to keep normal file and formatting strings intact. Spaces are changed to `!` so the scanset does not stop early. The code is placed at `DS:0200` / `CS:25F0`.

### 2. Copy the flag into the service response

The 16-bit stub uses DOS `INT 21h` to open `FLAG.TXT`, create `OUTPUT.TXT`, read the flag, and write it to the output file. The service base64-encodes that file; the solver decodes and prints it.

Run from `pwn/end-of-life/` with `python3 solve.py [host] [-p port]`; `HOST` and `PORT` environment variables are also supported. `handout.zip` supplies `CHALL.EXE` automatically.

```bash
python3 solve.py
# FortID{3oF_15_JU57_4_5u993571On_ed12f9c3f7}
```

## Flag

```text
FortID{3oF_15_JU57_4_5u993571On_ed12f9c3f7}
```

## Lessons

DOS text-mode Ctrl-Z handling and real-mode segment arithmetic matter alongside the usual stack offset. Deriving the Borland startup stack from its MZ entry code made the return overwrite deterministic.
