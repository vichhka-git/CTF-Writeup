# FortID CTF 2026 Writeup: Baby Pwn

- **Category:** Intro
- **Challenge author:** ipaljak
- **Points / Solves:** 118 pts / 150 solves
- **Flag:** `FortID{W0ah_My_F4v0r173_r3viw_C0n7a1n5_4_Fl4G_c1bfe2c91b}`

---

## Challenge

> Everyone's opinion matters to us. Submit a review, save your thoughts for
> later, and make sure your favourite feedback is never forgotten.
>
> Can you leave one last review?

---

## Summary

Deleting a review leaves the `favourite` pointer dangling. The draft feature allocates the same 40-byte object size and accepts all 40 bytes, allowing the stale review's display callback to be replaced with `win()`.

## Recon and root cause

`review_t` contains a 32-byte text field and an 8-byte display function pointer. `delete_review()` frees the review and clears only `review`; it never clears `favourite`. `write_draft()` allocates a 40-byte `draft_t` and reads the requested number of bytes into it. The supplied ELF is x86-64, non-PIE, and exports `win()` at a fixed address.

## Exploitation

Run the complete solver with the organizer host and port:

```bash
python3 solve.py <host> <port>
```

The script submits a review, marks it favourite, deletes it, and allocates a 40-byte draft. The first 32 bytes fill the text; the final 8 bytes contain the ELF's `win()` address. Previewing the stale favourite invokes that callback and prints the flag. The exploit was confirmed locally and on the organizer TLS instance.

## Flag

```text
FortID{W0ah_My_F4v0r173_r3viw_C0n7a1n5_4_Fl4G_c1bfe2c91b}
```

## Lessons

When a freed object contains a callback and a later feature allocates the same size, check whether that allocation can overwrite the stale object directly. The non-PIE build made the callback target deterministic, so no heap leak or ROP chain was needed.
