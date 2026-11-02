# Ghost in RAM

Forensics, 64 points, 204 solves. The handout is a memory image from a Linux host that
was wiped after collection. Nothing plaintext in it is the answer: the real flag sits
XOR-obfuscated in the BSS of a running process, and the image carries its own type
information so you can rebuild enough of the kernel structures to find that process.

## What you are given

`ghost-in-ram.zip` is 1.69 GB and expands to a single ELF64 file, `mem.elf`, of
2,164,394,051 bytes. It is a QEMU core dump covering the guest's 4 GB physical address
space. The kernel banner in the image identifies Linux `7.0.12+kali-cloud-amd64` (Kali
`7.0.12-2kali1`). There is no service and no login material.

Volatility3 2.28.2 is installed in the team workspace, but no symbol table exists for
that kernel, so the solve was done with a hand-written parser over the image's BTF.

## Reproduction

1. Read the ELF header and the program headers. Every `PT_LOAD` has `p_vaddr` equal to
   `p_paddr`, so the headers describe physical RAM rather than a process address space.
   Build a physical-to-file map from them:

   ```
   0x00000000 + 0x0a0000  -> file 0x00000838
   0x000c0000 + 0x7ff40000 -> file 0x000a0838
   0xfd000000 + 0x01000000 -> file 0x7ffe0838
   0xfffc0000 + 0x00040000 -> file 0x80fe0838
   ```

   `PT_NOTE` holds two `CORE` notes and two `QEMU` notes, and there is no `NT_FILE`
   record, so no process map comes for free.

2. Find the kernel. The banner appears at file offsets `0x21e0918`, `0x2346478` and
   `0x3a9ab78`. The image also contains a `.BTF` section header at file offset
   `0x28eb838` with 2,966,132 bytes of type records. Use those types for the structure
   offsets instead of guessing at a kernel build.

3. Locate `init_task`. Scan for the string `swapper/0`, subtract the `comm` offset
   `0xcd0` from the physical address of the hit, and keep the candidate whose `pid`
   field at `0xab0` is zero. The recorded result is physical `0x2e13180`.

   ```python
   init_p = 0x2e13180
   print(u32(init_p + 0xab0), comm_at(init_p))    # 0 swapper/0
   ```

4. Walk the task list. The BTF offsets used are `tasks = 0x9e8`, `pid = 0xab0`,
   `comm = 0xcd0` and `mm = 0xa38`. Follow `next_task` until you return to the list
   head. The recorded walk yields 66 tasks.

5. Look at the user processes. pid 131 reports `rsyslogd`, pid 132 reports
   `thumbnaild`, pid 133 reports `cfgparser`. Their argv gives them away:
   `/bin/decoy1_logwriter`, `/bin/decoy2_thumbd`, `/bin/decoy3_confparse`. pid 130
   reports `syncfsd` with argv `syncfsd: ` and is the only one whose binary is the same
   statically linked multi-call program as `/init`.

6. Read pid 130's address space. Take `mm` from the task, translate it through the
   direct map at `0xffff888000000000`, read `mm->pgd` at `mm + 0x78`, then walk the four
   paging levels for the target virtual address. Two reads are needed:

   | virtual address | physical | file offset | content |
   |---|---|---|---|
   | `0x4af0e0` | `0x2deb0e0` | `0x2dcb918` | `u32` length 30 |
   | `0x4af0f0` | `0x2deb0f0` | `0x2dcb928` | 30 obfuscated bytes |

7. Take the transform from the binary rather than trying candidates. The decode loop is
   at virtual `0x401ab2`:

   ```
   0x401ab2  lea   rcx, [rip + 0xad637]      ; rcx = 0x4af0f0
   0x401ac0  movzx edx, byte ptr [rcx+rax]
   0x401ac4  xor   edx, 0x5a
   0x401ac7  mov   byte ptr [r14+rax+0x980], dl
   ```

8. Apply XOR `0x5a` to the 30 bytes:

   ```
   32 33 19 0e 1c 21 3d 32 6a 29 2e 05 2a 28 6a 39
   69 29 29 05 28 34 3d 05 2a 2d 34 69 3e 27
   ```

   The plaintext is the flag. The same code path prints `SEED=0x6f2e1a53`,
   `A=0x41c64e6d`, `C=0x3039` at `0x401bba`, which explains the flag wording about a
   broken RNG.

9. Explain away the plaintext hits before accepting anything from a string sweep. A
   byte scan of the whole 2.1 GB file finds only four literal `hiCTF{` strings, at file
   offsets `0x21d4073`, `0x21dc26f`, `0x3e8287f` and `0x3f484d3`. The values are
   `hiCTF{stop_here}` and `hiCTF{d3bug_m3}` in `flag_cache=` lines, sometimes repeated
   inside a second binary. The two notes that record these offsets disagree on whether
   the fourth hit is at `0x3f484d3` or `0x3f4c038`; either way all four are decoys. A
   truncated `quality=flag_cache=hiCTF` fragment sits at `0x5844348`. The third decoy
   binary carries a base64 decoy (`ZmxhZ3tub3BlfQ==`) that decodes to `flag{nope}`, next
   to the text "the real flag is not stored here".

## Why it works

The image keeps the process structures that describe what was running, so a task walk
plus a page-table walk reproduces what the process could read at the moment of capture.
The flag is only present under one XOR with a constant, with an explicit length field
one page slot earlier, so no string search will return it. Everything a string search
does return is labelled as a decoy by the author, which is what separates the intended
carrier from the noise.

One detail in the local record is inconsistent. The team submission log calls pid 130 a
psscan-only process, while the workspace reproducer walks `init_task.tasks` and reports
pid 130 in the list. The notes do not resolve which route the original solve used; the
offsets, the length field and the 30 cipher bytes agree in both records.

## Flag

```
hiCTF{gh0st_pr0c3ss_rng_pwn3d}
```
