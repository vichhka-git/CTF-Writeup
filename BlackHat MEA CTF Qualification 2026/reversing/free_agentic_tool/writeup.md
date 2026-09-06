# free-agentic-tool Writeup (TFC CTF 2026 / Flagyard)

## Challenge Overview
- **Category:** Reversing
- **Files provided:** `free-agent.exe`, `traffic.pcapng`, `free-agent_session_debug.zip`

## Analysis & Walkthrough

### 1. Unpacking `free-agent.exe`
- Static analysis of `free-agent.exe` revealed that it extracts `.txt` logs into `free-agent_session_debug.zip` encrypted with AES-256-CBC using a key located at file offset `0x46f180`.
- Decrypting the debug logs revealed the host environment:
  - Username: `lightlight`
  - Computer name: `DESKTOP-DD6SS6U`
- At file offset `0x49f940` (VA `0x8a1d40`), an embedded compressed binary payload with magic `FALZ\x01\x00` was identified.
- Decompressing with custom LZSS and applying the byte transformation `((out[i] ^ key[(7*i + 3) % 32]) - key[i % 32]) & 0xff` yielded a clean 64-bit Go binary (`decrypted_agent.exe`).

### 2. Protocol & Cryptography in `decrypted_agent.exe`
- `decrypted_agent.exe` implements a gRPC client connecting over HTTP/2 on port 50051 to `/free.model`:
  - `/free.model/Init`
  - `/free.model/Prompt`
  - `/free.model/Model`
- The client generates an X25519 private key from `sha256(b"lightlight_DESKTOP-DD6SS6U")`.
- In `/free.model/Init` (Frame 753 / 758):
  - Client public key: `fcce28708604b98004450d32ea2ab2ffb9e4dc1961cc7257af2f80c8c8b1fa76`
  - Server public key: `d26e1248c5c117fc4c3afe949b4a3e79dd2890775e9823161edd03e9c319323a`
  - Session ID: `f3bbb50728251459`
  - Shared secret: `14488f97ebdc8e8bad1e48057af735b86dbecbea2c6e7105eb7c38145d1e3072`
- Function `main.GOOGOOGOOOOGGOO` at `0x8660c0` computes the AES-GCM session key:
  `key = 7c29d2dc03567d188b844a11d08d5c82707bb052ea012e0729658948fc832b93`

### 3. Decrypting gRPC Traffic
- Using AES-GCM with empty AD and 12-byte nonces:
  - Frame 763 (`t1` Prompt): `whoami`
  - Frame 802 (`t1` Response): `desktop-dd6ss6u\lightlight`
  - Frame 1385 (`t2` Prompt): `dir D:\.`
  - Frame 1510 (`t3` Prompt): `dir D:\BlackHat\`
  - Frame 1645 (`t4` Prompt): writes password `!!!_thr347_4ct0r_5ecr37_k3yy_!!!` to `D:\BlackHat\key.txt`
  - Frame 2096 (`t6` Prompt): executes `openssl enc -aes-256-cbc -salt -pbkdf2 -iter 200000 -in D:\BlackHat\flag.txt -out D:\BlackHat\flag.txt.enc -pass file:D:\BlackHat\key.txt`
  - Frame 2195 (`t7` Response): client uploads the encrypted `flag.txt.enc` file.

### 4. Decrypting Flag
- Decrypting `flag.txt.enc` with OpenSSL using password `!!!_thr347_4ct0r_5ecr37_k3yy_!!!`:
  ```bash
  openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter 200000 -in flag.txt.enc -pass file:key.txt
  ```
  yields the flag:
  `BHFlagY{wh4t_y0u_5Ee_15n't_wh4t_y0u_G3t_8cc56ad688964fd5f72f3c414971b1d6}`
