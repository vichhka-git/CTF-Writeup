# FortID CTF 2026 Writeup: String Peek and Poke

- **Category:** Pwn
- **Challenge author:** ante
- **Points / Solves:** 202 pts / 30 solves
- **Flag:** `FortID{wh3n_7h3_0nly_t00l_15_4_h4mm3r_3v3ry_5tr1ng_15_4_n41l_e9f84e4946}`

---

## Challenge

> Strings, strings everywhere...

---

## Summary

Unchecked `std::string` indexing exposes adjacent runtime objects and lets a negative-index assignment overwrite libstdc++'s shared `ctype<char>` facet. A short library pointer leak supplies the runtime base; replacing the facet's widening dispatch with a `setcontext` pivot runs `system()` and reads the flag.

## Recon and root cause

`chall.cpp` declares `std::string notes[8]`, then uses `notes[idx]` for both `put` and `get` without checking `idx`. Each string occupies 0x20 bytes. A large `get -26` reveals pointers into the PIE, but its fake string length runs past mapped memory and the process closes before another command can run.

The deployed runtime has `PIE - libstdc++ = 0x27e000`. The aligned object at libstdc++ offset `0x26f440` therefore corresponds to index

```text
(0x26f440 - (0x27e000 + 0x203260)) / 0x20 = -67825
```

`get -67825` prints a safe 0x70-byte view containing four libstdc++ code pointers at offsets `0xd2db0`, `0xd2e30`, `0xd2da0`, and `0xd2df0`. Subtracting these offsets gives one consistent libstdc++ base, and the command loop remains usable.

At index `-1`, the fake string header points into the writable `ctype<char>` facet at `libstdc++ + 0x27ba20`. Assigning a 0x520-byte value writes the forged facet and context there. The payload points `_M_table` at a small replacement mask table, clears `_M_widen_ok`, installs a fake vtable, and places a `ucontext` for `setcontext` in the facet memory. `get 0` reaches `std::endl`, which calls the redirected `do_widen` slot; `setcontext` restores registers for `system("cat</flag.txt")` and returns to `_exit`.

The command has no spaces because the input parser reads the value with `operator>>`. The organizer container exposes `/flag.txt` as a symlink to `/tmp/flag.txt`.

## Exploitation

The complete TLS exploit is [solve.py](./solve.py). It reads the short disclosure, checks that all four base candidates agree, builds the payload for the deployed libc/libstdc++ offsets, and prints the flag:

```bash
python3 solve.py <INSTANCE_HOST> 1337
```

The instance endpoint is `tcp-ssl`; `solve.py` uses pwntools with TLS enabled. The flag was retrieved from the live instance and accepted by the organizer:

```text
FortID{wh3n_7h3_0nly_t00l_15_4_h4mm3r_3v3ry_5tr1ng_15_4_n41l_e9f84e4946}
```

## Lessons

- An unchecked index over a C++ object array can reinterpret unrelated mapped data as a valid-looking object header.
- The largest disclosure was useful for analysis but not for exploitation because the read fault ended the command session. A bounded view of a runtime object provided the leak needed on the live connection.
- Validate library-to-PIE offsets against the deployed loader. The local container and remote instance placed libstdc++ at different offsets.
