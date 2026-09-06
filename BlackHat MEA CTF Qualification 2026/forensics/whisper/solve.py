#!/usr/bin/env python3
"""
Solver script for Whisper (Forensics) - BlackHat MEA Qualification CTF 2026
Extracts the passphrase from Ollama history, recovers the exfiltration script from Trash,
derives the BLAKE2b archive key, decrypts session.zip, and decodes the flag.
"""

import base64
import hashlib
import os
import pathlib
import re
import sys

CHALLENGE_DIR = pathlib.Path(__file__).resolve().parent

try:
    import pyzipper
except ImportError:
    # Try importing from user's environment or triage venv
    venv_site = CHALLENGE_DIR / "whisper_evidence/home/dwright/.local/share/.venv/lib/python3.12/site-packages"
    if venv_site.exists():
        sys.path.insert(0, str(venv_site))
        import pyzipper
    else:
        raise ImportError("pyzipper module is required to decrypt AES zip files")

def _read_from_dir(evidence_dir):
    history_file = evidence_dir / "home/dwright/.ollama/history"
    history_text = history_file.read_text(encoding="utf-8", errors="ignore")
    zip_path = evidence_dir / "home/dwright/.cache/fontconfig/session.zip"
    zip_bytes = zip_path.read_bytes()
    return history_text, zip_bytes

def _read_from_tar(tar_path):
    import tarfile
    with tarfile.open(tar_path, "r:gz") as tar:
        hf = tar.extractfile("whisper_evidence/home/dwright/.ollama/history")
        history_text = hf.read().decode("utf-8", errors="ignore")
        zf = tar.extractfile("whisper_evidence/home/dwright/.cache/fontconfig/session.zip")
        zip_bytes = zf.read()
    return history_text, zip_bytes

def solve():
    evidence_dir = CHALLENGE_DIR / "whisper_evidence"
    tar_path = CHALLENGE_DIR / "whisper_evidence.tar.gz"
    zip_path = CHALLENGE_DIR / "whisper_evidence.zip"

    if evidence_dir.exists():
        history_text, zip_bytes = _read_from_dir(evidence_dir)
    elif tar_path.exists():
        history_text, zip_bytes = _read_from_tar(tar_path)
    elif zip_path.exists():
        import tempfile, subprocess
        with tempfile.TemporaryDirectory() as tmp_dir:
            print(f"[*] Extracting {zip_path.name} to temporary directory...")
            subprocess.run(["7z", "x", str(zip_path), f"-o{tmp_dir}", "-y"], check=True, stdout=subprocess.DEVNULL)
            temp_tar = pathlib.Path(tmp_dir) / "whisper_evidence.tar.gz"
            history_text, zip_bytes = _read_from_tar(temp_tar)
    else:
        raise FileNotFoundError("Neither whisper_evidence directory, whisper_evidence.tar.gz, nor whisper_evidence.zip found")

    # 1. Recover passphrase from Ollama chat history
    m = re.search(r"use the password\s+(\S+)", history_text)
    if not m:
        raise ValueError("Passphrase not found in Ollama history")
    raw_password = m.group(1).strip()
    print(f"[+] Recovered raw passphrase from Ollama history: {raw_password}")

    # 2. Derive encryption key as defined in cache_mgr.py
    archive_password = hashlib.blake2b(
        raw_password.encode("utf-8"),
        digest_size=32
    ).hexdigest()[:20].encode("utf-8")
    print(f"[+] Derived BLAKE2b archive password: {archive_password.decode('utf-8')}")

    # 3. Decrypt exfiltrated session.zip from fontconfig cache
    import io
    print("[*] Decrypting session.zip with pyzipper...")
    with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.setpassword(archive_password)
        csv_data = zf.read("internal_api_keys.csv").decode("utf-8")

    # 4. Extract base64 flag from internal_api_keys.csv
    flag = None
    for line in csv_data.splitlines():
        if "master_vault" in line:
            parts = line.split(",")
            b64_key = parts[1].strip()
            flag = base64.b64decode(b64_key).decode("utf-8")
            print(f"[+] Found master_vault token: {b64_key}")
            print(f"[+] Decoded flag: {flag}")
            break

    if not flag:
        raise ValueError("Flag not found in internal_api_keys.csv")
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"\n[+] FINAL FLAG: {flag}")
