# FortID CTF 2026 Writeup: Fortune Teller

- **Category:** Pwn
- **Challenge author:** ipaljak
- **Points / Solves:** 118 pts / 148 solves
- **Flag:** `FortID{Fortun3_Fav0r5_Th3_b0ld_bu7_al50_Th05e_Th4t_C4n_Expl0i7_F0rma7_Str1ng_VulnZZ_2a0cfd5e1f}`

---

## Challenge

> The oracle will answer any question 🔮, you might even get blessed with a flag...

---

## Summary

The oracle passes the user's question directly to `printf`, creating a format string vulnerability. A stack leak reveals a PIE return address; a positional halfword write changes the global `blessing` to `0x1337` and reaches `win()`.

## Recon and root cause

`chall.c` shows `printf(question)` in `ask_oracle()`. `receive_blessing()` calls `win()` only when the global variable equals `0x1337`. The ELF is PIE with full RELRO, a canary, and NX; GOT overwrites and direct stack execution are unnecessary.

On the supplied build, `%37$p` leaks a pointer at PIE offset `0x1441`, and `blessing` is at PIE offset `0x404c`. The question buffer begins at variadic argument 6, so a pointer placed at input offset 32 is argument 10.

## Exploitation

The complete reproducible solver is [solve.py](solve.py). Run it with the organizer instance host and port:

```bash
python3 solve.py <host> <port>
```

It connects over TLS, obtains the PIE base from the leak, and builds a payload equivalent to:

```text
%4919c%10$hn + padding to 32 bytes + p64(PIE_base + 0x404c)
```

`4919 == 0x1337`, so `%hn` stores the required value. Selecting menu option 2 calls `win()` and prints the flag. The same payload succeeded locally against the supplied binary and remotely against the organizer instance.

## Flag

```text
FortID{Fortun3_Fav0r5_Th3_b0ld_bu7_al50_Th05e_Th4t_C4n_Expl0i7_F0rma7_Str1ng_VulnZZ_2a0cfd5e1f}
```

## Lessons

A small global gate can make a format string write simpler than a ROP chain. The positional argument layout and PIE-relative symbol offsets should be measured against the actual supplied build; the remote TLS service confirmed those offsets here.
