# CSAW CTF Quals 2026 - Autobahn (Rev, ID 35)

## Challenge Information
- **Name:** Autobahn
- **Category:** Rev
- **ID:** 35
- **Points:** 188
- **Author:** WubberDuckkie
- **Flag:** `csaw{c0d3_th4t_rewr1t3s_1ts3lf_c4nt_b3_tru5t3d}`

## Description
> Our engine only fires with the right password. We built it tough: pop it open in a disassembler and the important part is pure noise. It only makes sense once the engine is running.

## Analysis & Reverse Engineering

### 1. Initial Reconnaissance
- Provided binary: `files/nitro` (ELF 64-bit x86-64 executable, not stripped).
- Key symbols present:
  - `main` (`0x4011d6`)
  - `secret_check` (`0x40130d` to `0x40146b`, 350 bytes)
  - `smc_key.0` (`0x4020a8`, 8 bytes: `1337c0debaadf00d`)
  - `enc_flag` (`0x402020`, 47 bytes)

### 2. Self-Modifying Code (SMC) Decryption
In `main()`:
1. `sysconf(_SC_PAGESIZE)` is called to determine page boundaries.
2. `mprotect(0x401000, len, PROT_READ | PROT_WRITE | PROT_EXEC)` is called on the page containing `secret_check`.
3. An 8-byte XOR decryption loop runs over the 350 bytes of `secret_check`:
   $$\text{secret\_check}[i] \gets \text{secret\_check}[i] \oplus \text{smc\_key}[i \pmod 8]$$
4. Control transfers to `secret_check(argv[1])`.

### 3. Password Verification & Flag Generation
Decompiling the decrypted `secret_check` function reveals:
1. It builds a local string `"n2o_boost"` (length 9) byte-by-byte and verifies that `argv[1]` matches `"n2o_boost"` exactly.
2. If correct, it decodes `enc_flag` (47 bytes at `0x402020`) using the decrypted function's own code bytes as key material:
   $$\text{flag}[i] = \text{enc\_flag}[i] \oplus \left(0x6b + \text{dec\_code}[(7i + 3) \pmod{350}] + 5i\right) \pmod{256}$$
3. It prints `NITRO ENGAGED: <flag>`.

Evaluating the formula or executing `./nitro 'n2o_boost'` produces the flag:
`csaw{c0d3_th4t_rewr1t3s_1ts3lf_c4nt_b3_tru5t3d}`
