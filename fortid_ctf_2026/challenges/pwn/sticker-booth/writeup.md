# FortID CTF 2026 Writeup: Sticker Booth

- **Category:** Pwn
- **Challenge author:** ipaljak
- **Points / Solves:** 147 pts / 64 solves
- **Flag:** `FortID{I_h0p3_Y0u_W1ll_Pu7_Th15_5t1ck3r_0n_Y0ur_L4p70p_4da1dffded}`

---

## Challenge

> A place where you can safely customize your stickers and print them out!

---

## Summary

The `mono` filter processes one row past a photo's declared height. With a 16x1 photo, its 64-byte overrun reaches the next allocator block and clears a shared caption header. A stale caption pointer can then be reclaimed by an upload, used to leak the builtin ticket, and reused again as a forged builtin record to print `flag.txt`.

## Recon and root cause

The supplied binary is a static, non-PIE x86-64 executable. `photo` allocates 16 bytes of metadata plus `width * height * 4` pixel bytes, rounded up to an 8-byte boundary. The `mono` loop processes rows while `y <= height`, writing four bytes per pixel. A 16x1 photo requests 80 bytes, already 8-byte aligned, so its extra 64-byte row begins at the next allocation.

Two captions with identical text share a payload. Its 16-bit reference count and type occupy the first four bytes; its length is at offset 4 and its content starts at offset 16. The neighbouring builtin payload stores the random booth ticket at offset 8. Zeroing the caption header makes `remove` free the payload even though the other caption item still points to it.

## Exploitation

Run the complete solver with the organizer host and port:

```bash
python3 solve.py <host> <port>
```

The script creates a 16x1 photo, two identical captions, and a builtin sticker. After `mono` corrupts the shared caption header, it removes one caption and uploads a 120-byte fake caption into the freed block. The surviving caption prints 120 bytes from offset 16; bytes 112–119 reveal the adjacent builtin ticket.

The solver removes that upload and reuses the block with a forged builtin header containing the leaked ticket and the path `flag.txt`. Printing the stale caption now passes the ticket check and reads the flag file.

## Flag

```text
FortID{I_h0p3_Y0u_W1ll_Pu7_Th15_5t1ck3r_0n_Y0ur_L4p70p_4da1dffded}
```

## Lessons

Allocator alignment determines whether a small row overrun reaches the next object. A shared payload also becomes a use-after-free when adjacent corruption clears its reference count before one alias is removed. The random ticket protects the builtin reader only until adjacent data is exposed through the stale caption.
