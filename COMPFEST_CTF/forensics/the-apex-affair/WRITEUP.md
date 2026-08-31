# The Apex Affair - Comprehensive Forensics Writeup

- **Category:** Forensics
- **Points:** 500
- **Challenge Type:** Multi-stage Interactive Forensic Investigation (Windows Disk & Memory Analysis)
- **Flag:** `COMPFEST18{th1s_chall3nges_was_cool_right?_oOWezGXDBhzqS9jb}`

---

## Executive Summary

**The Apex Affair** is an enterprise-grade DFIR (Digital Forensics and Incident Response) challenge simulating a sophisticated APT cyberattack against Northbridge Industrial Solutions targeting Finance Manager Edward Collins. The attack chain spans:
1. **Initial Access:** Phishing email delivering malicious installer disguised as a Google Chrome update.
2. **Execution & Evasion:** Execution of `chrome_update.dll`, dropping malicious binaries, disabling Windows Defender Real-Time Protection and Security Engine.
3. **Persistence:** Image File Execution Options (IFEO) debugger hijacking for `SecurityHealthSystray.exe`.
4. **Command & Control (C2):** Covert C2 operations using Google Calendar API (CalendarRAT) with AES-encrypted commands.
5. **Defense Evasion / Process Injection:** Process injection into `notepad.exe` using custom shellcode.
6. **Impact (Ransomware):** Custom ransomware encrypting financial merger & acquisition proposals (`Apex_Orion_Acquisition_Proposal.docx`).

---

## Incident Timeline & Detailed Forensic Analysis

### Part 1: Initial Access & Phishing Triage
- **Email Client:** Analysis of `%LOCALAPPDATA%\Microsoft\Olk` (New Outlook for Windows) SQLite database and message stores.
- **Phishing Email Timestamp:** `2026-08-15 08:45:38` (UTC).
- **Phishing Subject:** `Update Your Browser - Download the Latest Google Chrome` sent from a spoofed domain.
- **LNK / Attachment Execution:** User executed the attachment at `2026-08-15 16:42:36` (UTC), confirmed via Shellbags, LNK parsing, and Windows Prefetch (`CHROME_UPDATE.EXE`).

### Part 2: Defense Evasion & Persistence
- **Scheduled Task:** `GoogleChromeUpdater` configured to execute:
  `rundll32.exe "C:\Users\Public\chrome_update.dll",Drop`
- **Dropped Binaries:** 2 binaries placed in `C:\Program Files\Google\Chrome\`:
  - `C:\Program Files\Google\Chrome\GoogleUpdater.exe`
  - `C:\Program Files\Google\Chrome\software_reporter_tool.exe`
- **Defender Disablement Commands:**
  `"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "add-exclusion" "Paths" "C:\Program Files\Google\Chrome"|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "secengine" "disable"|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "tp" "off"|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "rtp" "off"`
  Executed at timestamp `2026-08-15 16:48:38` (UTC).
- **Persistence Mechanism (IFEO):**
  Registry key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecurityHealthSystray.exe\Debugger=systray.exe`
  MITRE ATT&CK Technique: `T1547.001` (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder).
  Executed at: `2026-08-15 16:49:32` (UTC).

### Part 3: Covert Command & Control (Google Calendar RAT)
- **C2 Channel:** Google Calendar API.
- **Attacker Calendar ID:** `18a7bdbf39f6baa148901225fa21b72cfe492720379a04f2068e1d364db65457@group.calendar.google.com`.
- **C2 Protocol:** Commands were encoded in event `summary_description` fields.
- **Discovery Commands:**
  - `systeminfo` executed at `2026-08-15 17:11:14` (UTC).
  - Process enumeration: `for /f "tokens=1" %i in ('tasklist /nh') do @echo %i`.
- **AES-256 C2 Key:** Extracted from memory heap inspection: `KEqrg7kVO1xP2BqJG9fZUpMyWblZFQWuClvZb0EYIzw=`.
- **Target User Profile:** `Edward Collins`.

### Part 4: Process Injection & Shellcode Extraction
- **Injected Process:** `notepad.exe` at base virtual address `0x00000151c1e20000`.
- **In-Memory Payload Hash:** `9e2413e4d0469a25c7840872f5fa98d93c4bb1c2f9a0d184f47eadaf808fefcf`.

### Part 5: Impact & File Decryption
- **Ransom Note Details:**
  - Attacker ETH Address: `0x08FE9fc8288Cf5D5EE5f4F69c0e4f774FFA275d4`
  - Attack ID: `0x8fe24bdb`
- **Ransomware Encryption Parameters:**
  - AES Key: `a545e0a8c675ce955431882c239e555e2de01b6bf63cd0c84514627cc306481f`
  - AES IV: `7a89a98c355a84e98a3f4ef3045871d4`
  - Header Size: `4096` bytes
- **Decrypted Document:**
  File: `Apex_Orion_Acquisition_Proposal.docx`
  SHA256: `d33cc7764e98bcdef507065dc96d4b2e5fd2af0ec95d60e9b4e115fa75b2ea5e`

---

## Interactive Quiz Answers Summary Table

| Part | Question Description | Exact Verified Answer |
|---|---|---|
| **1.1** | Email client used by victim | `Outlook` |
| **1.2** | Timestamp phishing email received | `2026-08-15 08:45:38` |
| **1.3** | Subject of phishing email | `Update Your Browser - Download the Latest Google Chrome` |
| **1.4** | Timestamp malicious attachment executed | `2026-08-15 16:42:36` |
| **2.1** | Name of persistence scheduled task | `GoogleChromeUpdater` |
| **2.2** | Task execution command line | `rundll32.exe "C:\Users\Public\chrome_update.dll",Drop` |
| **2.3** | Dropped payload count & absolute paths | `2\|C:\Program Files\Google\Chrome\GoogleUpdater.exe\|C:\Program Files\Google\Chrome\software_reporter_tool.exe` |
| **2.4** | Defender disablement commands | `"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "add-exclusion" "Paths" "C:\Program Files\Google\Chrome"\|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "secengine" "disable"\|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "tp" "off"\|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "rtp" "off"` |
| **2.5** | Evasion execution timestamp | `2026-08-15 16:48:38` |
| **2.6** | IFEO registry key & value | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecurityHealthSystray.exe\Debugger=systray.exe` |
| **2.7** | MITRE ATT&CK technique ID | `T1547.001` |
| **2.8** | Persistence execution timestamp | `2026-08-15 16:49:32` |
| **3.1** | Covert C2 infrastructure | `Google Calendar` |
| **3.2** | Attacker Calendar ID | `18a7bdbf39f6baa148901225fa21b72cfe492720379a04f2068e1d364db65457@group.calendar.google.com` |
| **3.3** | Calendar field used for command exchange | `summary_description` |
| **3.4** | First discovery command executed | `systeminfo` |
| **3.5** | First discovery timestamp | `2026-08-15 17:11:14` |
| **3.6** | Process discovery command | `for /f "tokens=1" %i in ('tasklist /nh') do @echo %i` |
| **3.7** | Base64 AES C2 key | `KEqrg7kVO1xP2BqJG9fZUpMyWblZFQWuClvZb0EYIzw=` |
| **3.8** | Victim full name | `Edward Collins` |
| **4.1** | Injected process and base address | `notepad.exe;0x00000151c1e20000` |
| **4.2** | SHA256 of extracted payload | `9e2413e4d0469a25c7840872f5fa98d93c4bb1c2f9a0d184f47eadaf808fefcf` |
| **5.1** | Attacker cryptocurrency address | `0x08FE9fc8288Cf5D5EE5f4F69c0e4f774FFA275d4` |
| **5.2** | Ransom transaction ID | `0x8fe24bdb` |
| **5.3** | Key, IV, Header size for decryption | `a545e0a8c675ce955431882c239e555e2de01b6bf63cd0c84514627cc306481f;7a89a98c355a84e98a3f4ef3045871d4;4096` |
| **5.4** | SHA256 of decrypted proposal docx | `d33cc7764e98bcdef507065dc96d4b2e5fd2af0ec95d60e9b4e115fa75b2ea5e` |

---

## Flag
```
COMPFEST18{th1s_chall3nges_was_cool_right?_oOWezGXDBhzqS9jb}
```
