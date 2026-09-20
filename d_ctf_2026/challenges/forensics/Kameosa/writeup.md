---
title: "Kameosa"
ctf: "D-CTF 2026 Quals"
date: 2026-09-18
category: forensics
difficulty: hard
points: 386
flag_format: "CTF{...}"
author: "Antigravity & Team"
---

# Kameosa

## Summary

Kameosa is an in-depth Windows disk image and memory/log analysis challenge featuring an infected VirtualBox Windows 10 virtual machine with a base VDI (`Defcamp Machine.vdi`) and a differential snapshot VDI (`{ca7f590b-...}.vdi`). The system was compromised by the **Bart** ransomware family (first observed June 2016), which encrypted user files into `.bart.zip` archives using ZipCrypto and modified user desktop wallpaper settings. By analyzing the NTFS Master File Table ($MFT), Windows Event Logs (Security, System, PowerShell, DeviceSetupManager, Storage Spaces), Windows Defender support logs (`MPLog.log`), and Prefetch files across the layered disk images, all 15 question flags were recovered.

---

## Solved Flags Overview (15 / 15)

| Flag ID | Question Summary | Solved Value |
|---|---|---|
| **5671 (Q1)** | Full SID of interactive account + total number of local accounts | `S-1-5-21-2459065227-3906730899-1249136888-1000+5` |
| **5672 (Q2)** | File accessed from CD-ROM during setup + SHA1 of lowfi sig in Engine VFZ line | `VBOXPOST.CMD+e8f505c96b3c364e8c7951417beb9bc046e15cde` |
| **5673 (Q3)** | Two distinct paths under which file from Q2 appears in logs | `\Device\CdRom0\VBOXPOST.CMD+\\?\D:\VBOXPOST.CMD` |
| **5674 (Q4)** | Binary performing encryption | `malw.exe` |
| **5675 (Q5)** | Ransomware family name + first spotted month-year | `Bart+June-2016` |
| **5676 (Q6)** | First and last record of Security.evtx in file order (UTC) + minutes log fails to cover encryption event | `2026-07-28 19:33:24.590+2026-07-29 07:04:42.154+178` |
| **5677 (Q7)** | NTP server name + contacted IP:PORT | `time.windows.com+104.40.149.189:123` |
| **5678 (Q8)** | Model, serial number, and capacity in bytes of disk 0 | `VBOX HARDDISK+VBb8368025-e4856f82+98956017664` |
| **5679 (Q9)** | ParentId of disk 0 + RegistryId GUID | `PCI\VEN_8086&DEV_2829&SUBSYS_00000000&REV_02\3&267a616a&0&68+{939d205b-8ac3-11f1-929a-806e6f6e6963}` |
| **5680 (Q10)** | Number of DPAPI events indicating credential key located | `9` |
| **5681 (Q11)** | Cleared event log channel + exact UTC timestamp | `Microsoft-Windows-PowerShell/Operational+2026-07-28 11:15:43.634195` |
| **5682 (Q12)** | Extension appended by ransomware to encrypted files | `.bart.zip` |
| **5683 (Q13)** | Registry key value name modified for wallpaper | `WallPaper` |
| **5684 (Q14)** | Original helper file name helping get needed keys for flag | `song.txt.txt` |
| **5685 (Q15)** | Final Challenge Flag | `CTF{S3a_Shant1_rul3ed_th3m_A11_7331!!!}` |

---

## Detailed Methodology & Solution Steps

### 1. Environment and Disk Image Layering

The challenge provided an 18 GB 7-zip archive (`toc.7z`, password `infected`) containing:
- Base virtual disk: `Defcamp Machine.vdi` (19.1 GB uncompressed, 98.9 GB virtual disk capacity)
- Differential snapshot disk: `Snapshots/{ca7f590b-0b11-4bbf-a118-6710bd478948}.vdi`
- Snapshot state: `2026-07-29T10-03-38-612485000Z.sav`
- VirtualBox machine definition: `Defcamp Machine.vbox`
- Execution logs: `Logs/VBox.log`

Using `dissect.hypervisor` and `dissect.target.filesystems.ntfs`:
```python
import dissect.hypervisor
from dissect.util.stream import RangeStream
from dissect.target.filesystems.ntfs import NtfsFilesystem

base_v = dissect.hypervisor.vdi.VDI(open('Defcamp Machine.vdi', 'rb'))
diff_v = dissect.hypervisor.vdi.VDI(open('{ca7f590b-0b11-4bbf-a118-6710bd478948}.vdi', 'rb'))
diff_v.parent = base_v.open()

# Mount the layered NTFS partition starting at offset 1048576 (1 MB partition offset)
stream = RangeStream(diff_v.open(), 1048576, diff_v.size - 1048576)
fs = NtfsFilesystem(stream)
```

### 2. Identity and System Setup Analysis (Q1, Q2, Q3)

- **Q1 (Interactive Account & Local Accounts):**
  Inspecting the `SAM` registry hive (`C:\Windows\System32\config\SAM`) revealed 5 local accounts (`Administrator`, `Guest`, `DefaultAccount`, `WDAGUtilityAccount`, `vboxuser`). The interactive user account `vboxuser` has RID `1000`, giving SID `S-1-5-21-2459065227-3906730899-1249136888-1000`. Combined format: `S-1-5-21-2459065227-3906730899-1249136888-1000+5`.

- **Q2 (Setup File from CD-ROM & VFZ Signature):**
  Windows Defender support logs (`C:\ProgramData\Microsoft\Windows Defender\Support\MPLog.log`) recorded the execution of VirtualBox guest post-installation script:
  Line 192: `[MpRtp] Engine VFZ lofi/sample/expensive: \Device\CdRom0\VBOXPOST.CMD ... sigseq=0x42965b2654dc`
  Line 182: `sigsha=e8f505c96b3c364e8c7951417beb9bc046e15cde, cached=false, resource="\Device\CdRom0\VBOXPOST.CMD"`
  Value: `VBOXPOST.CMD+e8f505c96b3c364e8c7951417beb9bc046e15cde`.

- **Q3 (Distinct Paths in Logs):**
  In `MPLog.log`, the file appears under two representations:
  - Line 181/182/192: `\Device\CdRom0\VBOXPOST.CMD`
  - Line 194/195: `\\?\D:\VBOXPOST.CMD`
  Value: `\Device\CdRom0\VBOXPOST.CMD+\\?\D:\VBOXPOST.CMD`.

### 3. Malware Threat Intelligence & Encryption Analysis (Q4, Q5, Q12, Q13)

- **Q4 (Malware Binary):**
  Prefetch file `C:\Windows\Prefetch\MALW.EXE-1F9BC0ED.pf` and Desktop artifacts identified `malw.exe`.
- **Q5 (Ransomware Family):**
  The malware creates `.bart.zip` files and a ransom note referencing Bart ransomware. Bart ransomware was first documented in June 2016 by Proofpoint. Value: `Bart+June-2016`.
- **Q12 (Ransomware File Extension):**
  Appended extension is `.bart.zip`.
- **Q13 (Wallpaper Registry Value):**
  In the NTUSER hive (`Software\Microsoft\Windows\CurrentVersion\Policies\System`), the value modified to enforce the ransom wallpaper is `WallPaper`.

### 4. Hardware and Network Forensics (Q7, Q8, Q9)

- **Q7 (NTP Server & Contacted Socket):**
  In `System.evtx`, Time-Service Event 37 recorded synchronization with `time.windows.com`, contacting `104.40.149.189:123`.
- **Q8 (Disk 0 Physical Specs):**
  From `setupapi.dev.log` and the `SYSTEM` hive `Enum\IDE`:
  Model: `VBOX HARDDISK`
  Serial: `VBb8368025-e4856f82`
  Capacity: `98956017664` bytes (92.16 GiB).
  Value: `VBOX HARDDISK+VBb8368025-e4856f82+98956017664`.
- **Q9 (Disk 0 ParentId & RegistryId GUID):**
  From `Enum\IDE\DiskVBOX_HARDDISK...`:
  ParentId: `PCI\VEN_8086&DEV_2829&SUBSYS_00000000&REV_02\3&267a616a&0&68`
  RegistryId GUID from Device Classes: `{939d205b-8ac3-11f1-929a-806e6f6e6963}`.

### 5. Event Logs & Timelines (Q6, Q10, Q11)

- **Q10 (DPAPI Credential Events):**
  In `Microsoft-Windows-Crypto-DPAPI/Operational.evtx`, Event ID 2 ("DPAPI successfully located a credential key") occurred exactly 9 times.
- **Q11 (Cleared Channel & Exact Timestamp):**
  In `System.evtx`, Event ID 104 recorded clearing of channel `Microsoft-Windows-PowerShell/Operational` at UTC timestamp `2026-07-28 11:15:43.634195`.
- **Q6 (Security.evtx Range & Encryption Gap):**
  In `Defcamp Machine.vdi` (base VDI), `Security.evtx` contains 11 active chunks.
  - First record: Record 1 at `2026-07-28 19:33:24.590` UTC.
  - Last stored record in active chunks: Record 905 at `2026-07-29 07:04:42.154` UTC.
  - The encryption event occurred at `2026-07-29 10:03:11` UTC.
  - Time gap: `10:03:11 - 07:04:42 = 2 hours 58 minutes 29 seconds = 178 whole minutes`.
  Value: `2026-07-28 19:33:24.590+2026-07-29 07:04:42.154+178`.

### 6. Key Recovery & Final Flag (Q14, Q15)

- **Q14 (Original Helper File Name):**
  Inspection of the user's Recent shortcuts in the Master File Table ($MFT Record #115827 and #107801) identified `song.txt.lnk` pointing to `Desktop\song.txt.txt` (a text file containing the lyrics of the traditional sea shanty *Spanish Ladies*). The original helper file name was `song.txt.txt`.
- **Q15 (Final Flag):**
  Resident MFT record #107802 stored the plaintext contents of `secret.txt` before encryption:
  ```
  Hmm you had all the luck needed in this situation and you got the flag here it is!
  CTF{S3a_Shant1_rul3ed_th3m_A11_7331!!!}
  ```

---

## Flag

```
CTF{S3a_Shant1_rul3ed_th3m_A11_7331!!!}
```
