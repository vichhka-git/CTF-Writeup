# flag_check_appliance_v2_FINAL

**Category:** rev · **Points:** 77 · **Solves:** 118 · **Author:** msanft

## Challenge

A 57 MiB raw disk image and a QEMU launch script. `run.sh` takes the flag as an
argument, turns each byte into a kernel command line word (`ctf.byte.0=66
ctf.byte.1=6c ...`) and injects it through SMBIOS type 11
(`io.systemd.boot.kernel-cmdline-extra`). Inside the VM, a chain of systemd
services decides whether that command line is the flag.

## TL;DR

The root partition is a squashfs with 7914 generated oneshot services. Each one
tests a single bit of a single flag byte through a `Requisite=` on a template
unit that matches `ctf.byte.<n>` values, then hands off to a success or failure
service. That is a 3958-level decision DAG over 704 flag bits (`88 × 8`), ending
in `echo CTF_RESULT=ACCEPT` or `echo CTF_RESULT=REJECT`. Nothing ever starts the
chain at boot — the target that wants it is not pulled in — so the intended solve
is static: parse the units, walk the DAG symbolically, and solve the resulting
linear system over GF(2).

## Files

| file | description |
|---|---|
| `flag_check_appliance_v2_FINAL.raw` | 60 100 608 B raw disk, GPT: 36 MiB ESP + 20.3 MiB squashfs root |
| `OVMF_CODE_4M.fd` | 3 653 632 B OVMF firmware code |
| `OVMF_VARS_4M.fd` | 540 672 B OVMF variable store |
| `run.sh` | 674 B wrapper: flag → `ctf.byte.N=HH` → QEMU |
| `solve.py` | static solver: unit graph → affine walk → GF(2) elimination |

Tools: `qemu-system-x86_64` (only for the intended boot path), plus `sgdisk`,
`squashfs-tools` / `unsquashfs`, `grep`, `python3` for the static solve.

## Analysis

### Partition layout

```
$ sgdisk -p flag_check_appliance_v2_FINAL.raw
Disk flag_check_appliance_v2_FINAL.raw: 117384 sectors, 57.3 MiB
Sector size (logical/physical): 512/512 bytes
Disk identifier (GUID): 8BF24459-95EB-47FA-9B4A-A63DB682653E
Partition table holds up to 128 entries
First usable sector is 2048, last usable sector is 117350
Number  Start (sector)  End (sector)  Size        Code  Name
   1            2048         75775   36.0 MiB     EF00  esp
   2           75776        117343   20.3 MiB     8304  root-x86-64
```

Partition 2 is the challenge:

```
$ dd if=flag_check_appliance_v2_FINAL.raw of=root.img bs=512 skip=75776 count=41568
$ file root.img
root.img: Squashfs filesystem, little endian, version 4.0, zstd compressed,
21280781 bytes, 9690 inodes, blocksize: 131072 bytes,
created: Thu Oct 22 20:12:27 2026
```

`unsquashfs` reports a valid 4:0 superblock, zstd compression, 131072-byte
blocks, filesystem size 21280781 bytes, exportable via NFS.

### What is in the root filesystem

```
$ ls /rootfs/usr/lib/systemd/system | grep -c '\.service$'
8038
$ ls /rootfs/usr/lib/systemd/system | grep -c '@\.service$'
31
```

8038 units, of which 31 are templates (instances carry a suffix). Ten of the
templates are the flag check; the other 21 are stock systemd templates (getty,
user@, systemd-*, …) with no conditions. The ten:

| template | conditions | meaning |
|---|---|---|
| `1125edcf-…@` | `ctf.byte.%i=01,03,05,…,ff` | bit 0 of byte `%i` set |
| `4bf8d9e6-…@` | `ctf.byte.%i=02,03,06,07,…` | bit 1 set |
| `3e1e0305-…@` | `ctf.byte.%i=04..07,…` | bit 2 set |
| `e1cac6db-…@` | `ctf.byte.%i=08..0b,…` | bit 3 set |
| `541682b8-…@` | `ctf.byte.%i=10..13,…` | bit 4 set |
| `db845c80-…@` | `ctf.byte.%i=20..23,…` | bit 5 set |
| `5312a969-…@` | `ctf.byte.%i=40..43,…` | bit 6 set |
| `f6718fc4-…@` | `ctf.byte.%i=80..83,…` | bit 7 set |
| `0c06b17c-…@` | `ctf.byte.%i` **and** `=|ctf.byte.%i=00`..`=ff` | byte `%i` exists |
| `2989c08e-…@` | `ctf.byte.%i` | byte `%i` exists |

Each bit template lists exactly the 128 byte values with that bit set, as
OR-ed `ConditionKernelCommandLine=` lines (a leading `|` means "or" in systemd).
A `Requisite=<template>@<n>.service` therefore fails unless byte `n` of the
command line carries the wanted bit.

A concrete node looks like this:

```
[Unit]
DefaultDependencies=no
Requisite=<bit-template>@<n>.service
After=<bit-template>@<n>.service
OnSuccess=<uuid>.service
OnFailure=<uuid>.service
[Service]
Type=oneshot
ExecStart=/usr/bin/true
StandardOutput=null
StandardError=null
```

`OnSuccess=`/`OnFailure=` are ordinary dependencies, so a node passes the run to
one of two children depending on one bit. Two special units terminate it:
`acad129c-…` runs `echo CTF_RESULT=ACCEPT` (to `/dev/console`, then
`poweroff.target`) and `a0e15bd1-…` runs `echo CTF_RESULT=REJECT`.

### The graph

The entry is the one UUID unit with a 793-entry `After=` list —
`c821258a-35fa-444e-8562-353fb1e10397.service`; the next largest `After=` in the
image has 5 entries. Those 793 words are the eight bit templates for bytes
0..87, then the exists-template for bytes 0..87, then the `2989c08e` exists test
for byte 88. So the list gives the flag length (88) and the first 703 tests; the
entry's `OnSuccess` leads to `2ddb3c0e-…`, the first of 3958 decision levels.

Levels hold one or two units (`|levels| = 1` for 795 levels, `2` for 3163), and
both units of a two-unit level test the same bit — one is reached on "the bit is
0", the other on "the bit is 1", and their edges reconverge. Walking the DAG
with the real flag takes 3957 steps, one unit per level.

### Why static analysis is enough

Something has to start the chain. `beb2d825-…target` contains `Wants=c821258a-…`,
and nothing in the filesystem references `beb2d825`; `default.target` is a
symlink to `graphical.target`. The ACCEPT chain is part of no boot target, so
booting the image never evaluates it (793 of the 7914 nodes are unreachable
junk anyway).

## Solution

### 1. Extract the units

`unsquashfs` straight into a directory on Linux. On a macOS host the squashfs
cannot be unpacked onto a bind mount (file ownership, `etc/gshadow`:
`Permission denied`), so unpack inside a container and tar it out:

```bash
docker run --rm --platform linux/amd64 -v "$PWD":/w -w /w debian:bookworm-slim sh -c '
    apt-get update && apt-get install -y --no-install-recommends squashfs-tools gdisk >/dev/null
    dd if=public/flag_check_appliance_v2_FINAL.raw of=/root.img bs=512 skip=75776 count=41568 status=none
    unsquashfs -q -d /rootfs /root.img
    tar -C /rootfs -cf /w/units.tar usr/lib/systemd/system'
mkdir -p units && tar -C units -xf units.tar --strip-components=4
```

```
$ ls units | wc -l
8154
```

On Linux, `unsquashfs` straight into a directory and skip the tar.

### 2. Read the entry unit

The entry is 12 lines: `[Unit]`, `DefaultDependencies=no`, one `Wants=` line,
one very long `After=` line (793 space-separated units), `OnSuccess=`, the
`OnFailure=` fallback, and a `[Service]` section with `ExecStart=/usr/bin/true`.
It has no `Requisite=` either — an easy second identifier.

```bash
f=units/c821258a-35fa-444e-8562-353fb1e10397.service
grep -c '^After=' $f                          # 1 line …
grep '^After=' $f | tr ' ' '\n' | grep -c .    # … holding 793 units
grep '^After=' $f | tr ' ' '\n' | sed -n '1p;9p;793p'
grep '^On' $f
```

```
1
793
After=1125edcf-2d3e-4bf5-b45a-fcdfd25e4796@0.service
1125edcf-2d3e-4bf5-b45a-fcdfd25e4796@1.service
2989c08e-831e-4874-a74d-10aa457fe5af@88.service
OnSuccess=2ddb3c0e-cab4-4b3c-8925-9f62d187b1c3.service
OnFailure=a0e15bd1-d456-4dd7-9f0f-10845dfcd1bd.service
```

The 793 tokens are eight bit tests for each byte `0..87`, then the
`0c06b17c` exists test for bytes `0..87`, then the `2989c08e` exists test for
byte 88. The bit-tested range is therefore 88 bytes (`88 × 8 = 704` bits), and
four other nodes additionally `Requisite=` the `ctf.byte.88` test, which pins the
length from both sides — the recovered flag is exactly 88 characters.
`OnFailure=` goes straight to the REJECT unit, skipping all 3958 levels.

### 3. Solve the DAG

`solve.py` classifies the ten templates by their condition sets, builds the graph
from `OnSuccess`/`OnFailure`, derives the depth of every node by longest path
from the entry, and then walks the levels carrying the *state* — which of the
two units of the level the run is in — as an affine expression over the 704 flag
bits. Plain levels give a transition `state' = state ⊕ test ⊕ c`; levels whose
false branch ends in REJECT are checks and yield one or two linear equations.
Gaussian elimination over GF(2) determines all 704 bits, and the solver then
walks the graph with the recovered flag to prove it ends in ACCEPT.

```bash
python3 solve.py units
```

```
units 7914, depths 3958, checks 793, equations 793, rank 704/704
undetermined bits: 0
flag: flag{https://github.com/systemd/systemd/commit/294446dcb98eaa1ced5839da674c2065b1367a3a}
walk: 3957 units -> ACCEPT
```

793 equations for 704 unknowns, full rank, unique solution, and the acceptance
walk hits ACCEPT after exactly 3957 hops — the same count as walking the graph
with the flag by hand.

### 4. Cross-check with the appliance

Booting confirms it end to end on a machine with KVM (or patience for TCG).
`./run.sh '<flag>'` prints `CTF_RESULT=ACCEPT` on the serial console and powers
off: the ACCEPT unit is `ExecStart=/usr/bin/echo CTF_RESULT=ACCEPT` with
`StandardOutput=tty`, `TTYPath=/dev/console`, `OnSuccess=poweroff.target`. That
boot was not run while writing this up — without KVM the TCG fallback is very
slow — so the static solve above is what pins the flag.

## Flag

```
flag{https://github.com/systemd/systemd/commit/294446dcb98eaa1ced5839da674c2065b1367a3a}
```

## Notes

* The polarity matters: `Requisite` satisfied → `OnSuccess`. Treating "test
  true" as failure dies at REJECT after 7 steps, so the walk itself validates the
  reading of the units.
* `0c06b17c-…` and `2989c08e-…` both mean "byte exists"; the length is fixed by
  the bit-tested range `0..87` plus the four nodes that `Requisite=` the
  `ctf.byte.88` test, i.e. 88 bytes.
* Junk units that no edge points at (`b5077f5f-…`, `6d38051d-…`, `d5fa2475-…`)
  are ignored, which is why there are 793 checks for 7914 nodes.
* Gaussian elimination on integer rows must mask with `(1 << NBIT) - 1` when
  picking a pivot. A row whose top bit is the constant column otherwise gets
  pivoted as if it were a variable and the system is reported inconsistent.
