# Carrier Shadow

**Category:** Rev · **Points:** 540 · **Flag:** `CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}`

## What the handout gives you

The handout provides a single stripped static x86-64 ELF executable recovered from an abandoned command post.

- `carrier-shadow` — 1,337,736 bytes, statically linked 64-bit ELF executable, stripped, SHA-256 `995fd7161d984898e521eb581f93380b11f31e3de342b368519a2221fb192a04`.

## Walkthrough

1. **Inspect ELF segments and sections.** Running standard analysis commands (`readelf -l carrier-shadow`) shows typical static binary segments alongside a `PT_GNU_EH_FRAME` program header located at file offset `0x9b600`. Standard static analysis shows no embedded archives in data sections or overlay data past the end of the file.

```bash
readelf -l carrier-shadow | grep -A 2 EH_FRAME
```

2. **Trace execution flow.** Disassembling the binary entry point `_start` leads to functions at `0x99160` and `0x99320`. The binary reads its own program headers from memory, locates the `PT_GNU_EH_FRAME` segment, and inspects the `.eh_frame_hdr` binary search table.

3. **Examine the FDE binary search table.** In standard DWARF unwind tables, `.eh_frame_hdr` holds pairs of 32-bit signed offsets: `(initial_loc, fde_offset)`. Function `0x995e0` traverses the array of `initial_loc` values. Instead of validating unwinding data, it evaluates differences between consecutive entries.

4. **Locate the payload signature.** The decoder initializes an xorshift32 PRNG using seed `0x6a2b3c4d` (`x ^= x << 13; x ^= x >> 17; x ^= x << 5`). It scans the FDE list for an 8-element sequence matching this keystream. The matching sequence begins at FDE index 123.

5. **Read the carrier metadata header.** Starting at index 123, symbols are encoded in the delta between consecutive `initial_loc` entries: `symbol = (initial_loc[k] - initial_loc[k-1]) - 2`.
   - Index 132 yields table index 0, selecting code lengths stored at virtual address `0x9b340`.
   - Indices 133 through 136 encode four little-endian length bytes, giving an exact payload length of 17,733 bytes (141,864 bits).

6. **Decode the canonical Huffman bitstream.** The 256-byte table at `0x9b340` defines symbol bit-lengths for a canonical Huffman code. Subsequent FDE deltas emit encoded symbols. Mapping symbols back to their canonical Huffman bit sequences reconstructs the compressed stream.

7. **Decrypt and decompress the payload.** Pack the 141,864 bits into 17,733 bytes. XOR each byte with the xorshift32 stream seeded with `0x6a2b3c4d`. Passing the decrypted stream into raw DEFLATE (`wbits=-15`) yields a 34,192-byte second-stage ELF binary (`payload.elf`).

8. **Extract the authorization string.** Inspecting strings in the decompressed ELF binary reveals the hidden authorization flag.

## Answer

Running `strings` against the extracted second-stage ELF binary exposes the authorization string:

`CSCTF{b3Oz2vgRuhe66X7SaM1B8qhUjfM2hV}`

## Notes

The carrier conceals the payload inside DWARF exception-handling metadata rather than executable code sections. Because `.eh_frame_hdr` binary search tables sort entries by function address, modifications to `initial_loc` can break standard debuggers and unwinding tools while appearing normal to casual section inspections.
