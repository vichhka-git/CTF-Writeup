# RESURRECTION (Operation Eclipse Void)

Forensics, 59 points, 308 solves (author Hidden Investigations). One 1 GiB disk image
with a deliberately pulverised front end holds five flag fragments. Each fragment is
stored as a mangled ordinal tag, two hyphens and a payload, and each one lives in NTFS
metadata rather than in a file. No string search finds any of them.

## What you are given

`resurrection.zip` expands to `resurrection.raw`, exactly 1,073,741,824 bytes. `file`
reports data because the start of the image is zeroed.

The README fixes the flag format as `hiCTF{part1part2part3part4part5}` and states that
each recovered phase reveals an ordinal tag, so the fragments are ordered by tag and not
by the offset where you happen to find them.

Working on the original is fine for reading. If you want The Sleuth Kit, `fls`, `icat`
and `fsstat` are enough, but autodetection struggles until you make a private copy with
valid front structures. Never write to the original.

## Reproduction

1. Recover the geometry from the backup structures. The primary GPT and the primary VBR
   are gone, but the backup GPT header sits at `0x3ffffe00` and the backup NTFS boot
   sector at `0x3fdffe00`, ending in the usual `55 aa`.

   ```
   backup GPT: revision 0x10000, header size 92, current LBA 2097151
   usable LBAs 34..2097118, entry array at LBA 2097119 (file 0x3fffbe00)
   entry 0: Microsoft reserved, LBAs 34..32767
   entry 1: Microsoft basic data, LBAs 32768..2093055
   ```

   Partition 1 therefore starts at `0x1000000`. Do not trust the CRCs: the header CRC
   is stored as `0x4de45e51` and computes to `0x2b051b2b` after the usual fixup, and the
   entry array CRC is stored as `deadbeef`. Corroborate the geometry from NTFS instead.

2. Parse the backup boot sector at `0x3fdffe00`. It reports 512 bytes per sector,
   8 sectors per cluster (4096 bytes), MFT LCN 85845, MFTMirr LCN 2, and record size
   indicator -10, so records are 1024 bytes.

   ```
   32768 * 512 + 85845 * 4096 = 0x15f55000   start of $MFT
   ```

   Records 0 to 11 decode to the standard metadata set, so the offsets above are right.

3. Work through the five carriers. Every carrier stores
   `<mangled ordinal>--<payload>`. Verify each rule from the raw bytes rather than
   assuming the tag is spelled correctly, because the author mangled all of them.

   Part 1, inode 179, `Windows/System32/kbdusx.dll`. The ConsoleHost history for the
   SecOps analyst contains a warning line about an unsigned input filter driver hooking
   the keyboard layout table and naming `kbdusx.dll`. The file is 1,068 bytes; its PE
   has `PointerToRawData = 0x200` and `SizeOfRawData = 0x200`, so the mapped image ends
   at `0x400` and a 44-byte overlay sits after it. XOR the overlay with the 4-byte
   `TimeDateStamp` at `0x88` (`80 85 ec 65`), repeating the four bytes:

   ```python
   ts = d[0x88:0x8c]
   print(bytes(d[0x400 + i] ^ ts[i % 4] for i in range(42)).decode())
   # f!r5t--hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_
   ```

   The last two overlay bytes decode to noise, which is how you know the message is the
   first 42 bytes. The payload starts with the flag prefix, so this is part 1.

   Part 2, inode 111, `Users/Finance_Victim/Desktop/Confidential_Q3`. The unnamed
   non-resident `$DATA` stream is 34 runs of zero bytes. Read the runlist and take each
   run length as a byte:

   ```
   34 runs -> chr(len) -> 53c0nd--n7f5_runl157_cl5_g30m37ry_
   ```

   Part 3, `Windows/System32/config/TxR/tx_journal.log`. Read 34 blocks at `0x50`
   stride, take the FILETIME at `+0x20` in each, and decode the difference between
   consecutive timestamps:

   ```
   char = (t[i] - t[i-1] - 10000) + 16    -> th1jd--7r4ns4c710n_n4n0_f1l371m3_
   ```

   Note the first payload character is the digit `7`, not a letter, in keeping with the
   rest of the leetspeak. One local note gives the block count as 51 while the working
   reproducer reads 34; the derivation above is the one that reproduces the stored text.

   Part 4, `Windows/System32/winevt/Logs/Security_Audit.evtx`. At file offset `0x11cd`
   there are 33 little-endian `u32` values whose low byte is a character:

   ```python
   raw = d[0x11cd:0x11cd + 33 * 4]
   print(''.join(chr(struct.unpack('<I', raw[i:i+4])[0]) for i in range(0, len(raw), 4)))
   # f01_1rth--3v7x_b1n4ry_xml_70k3n5_
   ```

   Part 5, `$Bitmap` inode 6 at `0x15f56800`. Follow its `$DATA` run to the bitmap,
   walk the bits least-significant first, and map every run of zero bits to
   `chr(run_len + 1)`. Drop the unprintable runs at the head and tail:

   ```
   51f7h--b17m4p_orph4n_v01d_r35urr3c710n}
   ```

   The payload carries the closing brace, which confirms it is the last fragment.

4. Order the payloads by the ordinal the tag encodes, not by the literal spelling.
   Part 1 reads `f!r5t`, part 2 `53c0nd`, part 3 `th1jd`, part 4 `f01_1rth` and part 5
   `51f7h`. Strip the tag and the two hyphens from each, concatenate, and wrap in
   `hiCTF{` and `}`. The first payload already contains the opening brace and the last
   one already contains the closing brace, so remove those while joining.

## Why it works

NTFS records a great deal of structure that is not file content: runlists describe how
clusters are laid out, transaction journal records and event logs carry timestamps, and
`$Bitmap` records which clusters are free. Each of those fields is a numeric sequence
with one value per entry, and a numeric sequence can carry bytes. Because nothing is
stored in a file's bytes, no string search and no carving pass finds a fragment, which
is what the challenge description means by "the structural dissonance of the medium".
The ordinal tags are also mangled, so they serve to order the parts and to tell you the
stored value is a tag rather than payload.

## Flag

```
hiCTF{p3_0v3rl4y_71m3d473574mp_k3y_n7f5_runl157_cl5_g30m37ry_7r4ns4c710n_n4n0_f1l371m3_3v7x_b1n4ry_xml_70k3n5_b17m4p_orph4n_v01d_r35urr3c710n}
```
