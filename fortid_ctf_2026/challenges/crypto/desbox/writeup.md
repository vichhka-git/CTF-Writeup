# FortID CTF 2026 Writeup: DESBox

- **Category:** Crypto
- **Challenge author:** ipaljak
- **Points / Solves:** 133 pts / 88 solves
- **Flag:** `FortID{C0Mp11M3n75_0n_3xpl01tiN6_C0MP13Ment5!!1}`

---

## Challenge

> I tried to install a famous MS-DOS emulator, but ended up installing this program.
>
> I don’t think this can run DOOM...

---

## Summary

DESBox implements a simulated MS-DOS environment with an encryption utility `KEYB.COM`. The service takes two 24-byte keys, applies a random byte permutation and XORs with a secret table before loading them as 3DES keys. By supplying constant-byte keys (e.g., all `0x00` and all `0x02`), the random permutation becomes the identity, allowing deterministic key loading across successive invocations to decrypt the flag using the service's debug decryption oracle.

## Solution

### Step 1: Invariant Key Loading and Multi-Invocation Oracle

The service accepts two 24-byte keys $K_A, K_B$ and computes:
$$K_{\text{loaded}} = \text{adjust\_key\_parity}(\text{permute}(K) \oplus \text{MASK})$$
It encrypts the secret flag under $K_A$ and provides a single-block decryption oracle under $K_B$.

The service enforces that within a single run, $K_A \neq K_B$, their effective byte multisets differ, and they are not bitwise complements. However:
1. When all bytes of a key are identical ($K = [c]^{24}$), $\text{permute}(K) = K$ is deterministic regardless of the random shuffle.
2. The state is stateless across invocations in the interactive shell loop.
3. In invocation 1, setting $K_A = [0x00]^{24}$ and $K_B = [0x02]^{24}$ yields $C_{\text{flag}} = \text{DES3}_{K_0}(\text{FLAG})$.
4. In invocation 2, setting $K_A = [0x02]^{24}$ and $K_B = [0x00]^{24}$ allows querying the debug decryption oracle on $C_{\text{flag}}$ under $K_B = K_0$, returning the plaintext flag directly.

```python
#!/usr/bin/env python3
import os
import re
import socket
import ssl
import sys

def solve():
    host = os.environ["HOST"]
    port = int(os.environ.get("PORT", 1337))

    s = socket.create_connection((host, port), timeout=10)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname=host)
    f = ss.makefile("rw", buffering=1, encoding="utf-8")

    def read_until(target):
        buf = ""
        while target not in buf:
            chunk = f.read(1)
            if not chunk:
                break
            buf += chunk
        return buf

    # 1. Wait for prompt and run KEYB with KA=0x00, KB=0x02
    read_until("C:\\> ")
    f.write("KEYB\n")
    read_until("KEY A> ")
    f.write(("00" * 24) + "\n")
    read_until("KEY B> ")
    f.write(("02" * 24) + "\n")
    read_until("C:\\FLAG.BIN encrypted under Key A:\n")
    ct_flag = f.readline().strip()

    read_until("Debug ciphertext> ")
    f.write(("00" * 8) + "\n")

    # 2. Re-run KEYB with KA=0x02, KB=0x00 to decrypt ct_flag
    read_until("C:\\> ")
    f.write("KEYB\n")
    read_until("KEY A> ")
    f.write(("02" * 24) + "\n")
    read_until("KEY B> ")
    f.write(("00" * 24) + "\n")
    read_until("C:\\FLAG.BIN encrypted under Key A:\n")
    _ = f.readline().strip()

    read_until("Debug ciphertext> ")
    f.write(ct_flag + "\n")

    read_until("Debug output:\n")
    decrypted_hex = f.readline().strip()
    raw = bytes.fromhex(decrypted_hex)
    match = re.search(rb"FortID\{.*?\}", raw)
    if match:
        print(match.group(0).decode())

if __name__ == "__main__":
    solve()
```

## Flag

```
FortID{C0Mp11M3n75_0n_3xpl01tiN6_C0MP13Ment5!!1}
```
