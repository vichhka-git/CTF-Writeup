# Memory Liar

Forensics, 54 points, 661 solves. The handout is a 16 MiB memory capture
from a Windows workstation whose automated triage reported a clean process list. The
list is the lie: one EPROCESS record has been unlinked from the active chain, and the
flag sits in a custom record next to that process.

## What you are given

`memory-liar.zip` expands to `memory.raw`, exactly 16,777,216 bytes. There is no live
service and no login material.

The image is sparse and synthetic rather than a full physical dump: 181,745 bytes are
non-zero and the whole-file entropy is 0.145 bits per byte. Volatility is not needed and
does not help, because the structures are hand-built for this challenge.

## Reproduction

1. Establish that the file is a memory image and not a container. `file` reports data,
   there is no archive magic, and a string sweep returns 50-odd lines. Note the planted
   text first, then set it aside: at `0x355000` there is a block headed
   `[CONFIDENTIAL - ENDPOINT INCIDENT LOG]` that states the host audit found no hidden
   tasks or hooks, followed at `0x3550f1` by a "Forensics Verification Token" of the
   form `hiCTF{th1s_1s_4_f4k3_d3c0y_fl4g_f0r_n00bs_883a1c}`. The value names itself as
   a decoy, and the claim above it contradicts the process records, which is the point
   of the challenge title.

2. Find the kernel image and the process pool. One mapped PE sits at `0x200000`: `MZ` at
   `0x200000`, `e_lfanew` 0x80 pointing at `PE\0\0` at `0x200080`, machine `0x14c`,
   ImageBase `0x82800000`. The PDB path `ntkrpamp.pdb` is at `0x201534` and a `KDBG`
   owner tag is at `0x210008`. These are cosmetic; nothing in the solve depends on them.

   Scan for the literal `Proc` marker and walk backwards 4 bytes to the record base. The
   recorded hits are at `0x30b000`, then every `0x8000` up to `0x353000`, plus one more
   at `0x35d000`, for 11 records in total.

3. Learn the observed record layout from the ten that agree with the audit. `Proc`
   appears at base `+4`; DirectoryTableBase is at `+0x20`, PID at `+0xbc`,
   ActiveProcessLinks at `+0xc0` (Flink) and `+0xc4` (Blink), ImageFileName at `+0x174`
   as 16 bytes, and the thread list at `+0x190`.

   ```python
   import struct
   d = open('memory.raw','rb').read()
   def rec(base):
       return (d[base+4:base+8], struct.unpack('<I', d[base+0xbc:base+0xc0])[0],
               d[base+0x174:base+0x184].split(b'\0')[0])
   print([rec(b) for b in range(0x30b000, 0x353001, 0x8000)])
   ```

   The ten listed names are the ordinary Windows set: System, smss.exe, csrss.exe,
   wininit.exe, services.exe, lsass.exe, two svchost.exe, explorer.exe and notepad.exe.

4. Look at the eleventh record at `0x35d000`. Its name field reads `winxnet.exe` and its
   PID is 1337. More importantly, its two list pointers both equal `0x8035d0c0`, which is
   its own list entry address. A record whose Flink and Blink point at itself is not on
   any list.

5. Confirm what the real list contains. Kernel mappings in this image use virtual
   address equal to physical address plus `0x80000000`, so the list head at virtual
   `0x82811000` is physical `0x211000`. Read two dwords there:

   ```
   Flink 0x8030b0c0 -> record 0x30b000 (System)
   Blink 0x803530c0 -> record 0x353000 (notepad.exe)
   ```

   The chain covers the ten audited processes and stops at notepad.exe. The unlinked
   `winxnet.exe` is the process the audit missed.

6. Decode the payload that belongs to the hidden process. At physical `0x35f000` there
   is a fixed-size header followed by ciphertext. The layout, verified against the raw
   bytes, is `<4sIII`: magic `ROOT`, PID, XOR key, length.

   ```
   0x35f000  52 4f 4f 54   "ROOT"
   0x35f004  39 05 00 00   pid    = 1337   (matches the unlinked process)
   0x35f008  5d 00 00 00   key    = 0x5d
   0x35f00c  33 00 00 00   length = 0x33 = 51
   0x35f010  ciphertext, 51 bytes
   ```

   One of the local notes reads the magic as a five-byte `ROOT9` and shifts the fields
   by one byte. That is a misreading: the `39` is the low byte of the PID field. The
   `<4sIII` parse above is the one that produces a sensible key and length.

7. XOR the 51 payload bytes with `0x5d`:

   ```python
   key, ln = 0x5d, 0x33
   print(bytes(b ^ key for b in d[0x35f010:0x35f010 + ln]).decode())
   ```

   The plaintext names the technique in the flag itself: DKOM unlink of an EPROCESS,
   caught by cross-checking the list rather than trusting it.

8. Read the surrounding bytes for corroboration if you want it. Directly after the
   record at `0x35f050` there is a control host string and port, and at `0x35f070` the
   marker `OP_SHADOW_LIAR_ACTIVE`. Neither is needed for the flag, and neither should be
   extracted as text without noting that the same region also holds the ciphertext.

## Why it works

Windows keeps the active process list as a doubly linked list inside each EPROCESS. An
attacker who unlinks a record (a direct kernel object manipulation) removes it from
every tool that walks the list, which is why the automated audit reports ten clean
processes. The record itself still exists in the pool, and by construction its own two
pointers are left pointing at itself, which is the signature to look for. The flag is
stored next to that hidden record, keyed with a single byte and an explicit length, so
the artifact that survives is the one the list denies.

## Flag

```
hiCTF{dk0m_unl1nk_3pr0c3ss_l1st_cr0ss_ch3ck_7c3a9f}
```
