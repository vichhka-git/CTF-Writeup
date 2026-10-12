# FortID CTF 2026 Writeup: GDB SaaS

- **Category:** Pwn
- **Challenge author:** ante
- **Points / Solves:** 129 pts / 101 solves
- **Flag:** `FortID{N0_5h3ll_n33d3D_jU57_m41N_beeeea54eb}`

---

## Challenge

> Get your `main`s disassembled for free ...

---

## Summary

The service accepts an ELF and runs `gdb -ex "disassemble <name>"` on it. A crafted DWARF line table names `flag.txt` as the source file. Sending `/s main` makes GDB print source lines from that file, which is copied beside the ELF.

## Recon

The server rejects shell metacharacters and line breaks in the function name, then copies `flag.txt` into the temporary directory containing the uploaded ELF. The `disassemble` command supports the `/s` modifier, which prints source lines using the ELF's DWARF line information.

## Root cause

The service trusts attacker-controlled DWARF metadata when selecting source files for GDB's source listing. The uploaded ELF sets its compilation directory to `.` and its line table source name to `flag.txt`. On the organizer's GDB, `/s` resolves that source beside the temporary ELF, exposing the copied flag.

## Exploitation

Compile a tiny ELF from a file literally named `flag.txt`, mapping the build directory to `.` in DWARF. Upload its base64 encoding and request `/s main`. The complete reproducible script is [solve.py](solve.py).

The service uses TLS; run:

```bash
python3 solve.py HOST --port 1337
```

The script prints the recovered flag after extracting it from GDB's output.

## Flag

```text
FortID{N0_5h3ll_n33d3D_jU57_m41N_beeeea54eb}
```

## Lessons

GDB's source listing follows DWARF paths supplied by the object file. Filtering shell syntax does not make debugger operations safe when debug metadata can direct file lookup.
