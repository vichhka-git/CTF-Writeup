# COMPFEST CTF - Forensic Challenge: "Intern" Writeup

* **Category**: Forensics
* **Points**: 500
* **Flag**: `COMPFEST18{hopefully_there_isnt_too_much_questions_PlfSNpTtoNCp1evs}`
* **Format**: Interactive 30-Question Quiz Service

---

## Executive Summary
The **Intern** challenge presents a comprehensive multi-stage cyber incident investigation involving disk forensics (AD1 images), memory analysis (Linux ELF core dump of Windows memory), threat actor de-anonymization (browser/chat extraction, DPAPI decryption), and reverse engineering of an obfuscated 4-stage malware pipeline (packed Go binaries utilizing UAC bypass, COM persistence, process hollowing, and reverse TCP shellcode).

---

## Challenge Breakdown

### Part 1: Initiation (Questions 1 – 6)
* **Q1**: Compute Blake3 hashes of the 3 challenge artifacts:
  - `{12b27ea2-0101-4435-a4af-5a8743ce345f}.ad1` (Criminal Disk)
  - `{12b27ea2-0101-4435-a4af-5a8743ce345f}.elf` (Criminal Memory)
  - `{f1733278-c744-4bf0-9b9a-b1dfb278f4bf}.ad1` (Victim Profile Disk)
  - **Answer**: `6d97129e85a6552bb07a8a83037eae7cda2022ffd4370b7dbc8a2ed59c05f696,deff31d22f07b9f546b146d1417e758bf77e260d39b18ec8eb5d29d9dc58cb9b,233138454a22accfea9eaaf76bda028d8787acbf16aed83fd6291eff05d3b748`
* **Q2**: Investigating the victim's `.vscode/extensions/` directory revealed a malicious extension named `whiskerstein.vscode-helloworld-0.3.0`.
  - **Answer**: `vscode-helloworld`
* **Q3 – Q6**: Inspecting `extension.js` and `package.json` showed the extension was fetched from GitHub. Accessing the commit history / release metadata revealed 3 releases, with `0.3.0` published at `2026-06-27 11:02:24` and `0.2.0` being the prior benign version.
  - **Q3 Answer**: `https://github.com/whiskerstein-cf/helloworld-vscode/releases/tag/0.3.0`
  - **Q4 Answer**: `2026-06-27 11:02:24`
  - **Q5 Answer**: `3`
  - **Q6 Answer**: `0.2.0`

---

### Part 2: Malicious Activity (Questions 7 – 9)
* **Q7**: `extension.js` downloads a first-stage payload from `http://192.168.0.114:6767/AnyDesk.exe`.
  - **Answer**: `http://192.168.0.114:6767/AnyDesk.exe`
* **Q8**: From the Google Drive folder recovered by investigators (password `compfest18`), `AnyDesk.exe` was unpacked and its SHA-256 computed.
  - **Answer**: `28b8c8225d52edd5b654a9b89a875b556ebfb06c8b818ca132e2fef06a98a189`
* **Q9**: Investigating the criminal's sticky notes (`plum.sqlite` on the criminal disk) uncovered a note:
  - **Answer**: `Company website: http://10.0.2.15:7070`

---

### Part 3: The Hacker (Questions 10 – 16)
* **Q10 – Q13**: Inspecting criminal applications in `AppData/Roaming` and `AppData/Local` revealed Discord (`leveldb`) and Telegram desktop data.
  - Chat logs identified 2 Telegram accounts, usernames `whiskerstein` and `dooggdogg`, and partner handle `goose`.
  - **Q10 Answer**: `Discord,Telegram`
  - **Q11 Answer**: `2`
  - **Q12 Answer**: `whiskerstein,dooggdogg`
  - **Q13 Answer**: `goose`
* **Q14**: Threat actor conversation explicitly mentioned creating 4 binaries (`meoware/1`, `meoware/2`, `meoware/3`, `meoware/4`).
  - **Answer**: `4`
* **Q15**: Disassembling `AnyDesk.exe` (`main.sendZipToServer`) identified the ransomware exfiltration endpoint:
  - **Answer**: `http://192.168.0.114:5000/submit`
* **Q16**: Decrypting Edge credentials from the criminal memory dump (`{12b27ea2-0101-4435-a4af-5a8743ce345f}.elf`):
  - Extracted LSA DPAPI masterkeys using Volatility 3 and corrected an 8-byte CBC IV shift flaw in `pypykatz`.
  - Decrypted Edge App-Bound encryption key (`c459a815...`) and decrypted Edge's `Login Data` SQLite database using AES-256-GCM:
  - **Answer**: `hehewhiskerstein:.v4SQ4Ls&9dUi-wz`

---

### Part 4: More??!! (Questions 17 – 23)
* **Q17**: Disassembling `AnyDesk.exe`'s global slice `main.files` and `main.download` revealed 3 additional binaries fetched from `http://192.168.0.114:9000/`:
  - **Answer**: `http://192.168.0.114:9000/WindowsDefender.exe,http://192.168.0.114:9000/wsl.exe,http://192.168.0.114:9000/code.exe`
* **Q18**: Extracted `WindowsDefender.zip`, `wsl.zip`, and `code.zip` (password `compfest18`) and computed SHA-256 hashes:
  - **Answer**: `1e33cf8fbb72a4ec463e6b7a680d0d8ff5a2f1859cdb518b4abd052cb3f3338a,481ae0e266362df553befed223c1b85087da423416d5215fb8484fbc49a33dd9,c6a1b3235de1ea5ae084826098fad4d5f781b21ec3d6f959db186dde9b3cd87d`
* **Q19**: Disassembly of `AnyDesk.exe` (`main.main` lines 730–736) shows it immediately launches `code.exe`.
  - **Answer**: `code.exe`
* **Q20 – Q22**: Unpacking `code.exe` in Wine/GDB revealed registry keys `Software\Classes\ms-settings\CurVer` and execution of `fodhelper.exe`.
  - **Q20 Answer**: `UAC bypass`
  - **Q21 Answer**: `T1548.002`
  - **Q22 Answer**: `fodhelper.exe`
* **Q23**: Examining the registry payload string written by `code.exe` revealed the target executable executed with elevated privileges:
  - **Answer**: `C:\Users\Public\Music\wsl.exe`

---

### Part 5: Going Deeper (Questions 24 – 30)
* **Q24 – Q26**: Analyzing `unpacked_wsl.bin` (`meoware/3`):
  - `wsl.exe` creates a COM shell verb hijacking registry entry under `SOFTWARE\Classes\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell` (Recycle Bin) to execute `WindowsDefender.exe` upon user interaction.
  - **Q24 Answer**: `wsl.exe`
  - **Q25 Answer**: `Recycle Bin`
  - **Q26 Answer**: `WindowsDefender.exe`
* **Q27 – Q28**: Analyzing `unpacked_defender.bin` (`meoware/2`):
  - Uses `ZwQueryInformationProcess`, `ReadProcessMemory`, and `WriteProcessMemory` to hollow out `C:\Windows\explorer.exe` (spawning suspended process via `EXTENDED_STARTUPINFO_PRESENT`).
  - **Q27 Answer**: `Process Hollowing`
  - **Q28 Answer**: `C:\Windows\explorer.exe`
* **Q29 – Q30**: Capturing the injected shellcode:
  - Intercepted wineserver `write_process_memory` syscalls, extracting the exact 512-byte payload written to `0x140012050`.
  - Computed Blake3 hash: `c609f009cb0336f68b67b5c5c768d6da4542c342c20e1fa28f4a828b3308d83d`.
  - Disassembled shellcode, resolving `ws2_32.dll` function hashes and extracting the reverse TCP `sockaddr_in` (`192.168.100.66:10990`).
  - **Q29 Answer**: `c609f009cb0336f68b67b5c5c768d6da4542c342c20e1fa28f4a828b3308d83d`
  - **Q30 Answer**: `192.168.100.66:10990`

---

## Final Flag
```text
COMPFEST18{hopefully_there_isnt_too_much_questions_PlfSNpTtoNCp1evs}
```
