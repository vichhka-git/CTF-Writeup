# 2 - Bottle Out — Final Solutions & Forensic Evidence

**Event**: Holmes CTF 2026: The Reichenbach Directive  
**Challenge ID**: 75959  
**Difficulty**: Easy  
**Points**: 1000  

---

## Complete Answers Summary

| # | Question | Answer | Format / Mask |
|---|---|---|---|
| **1** | What are the remote address and port of the VPN server that the user connected to? | `18.156.81.166:7577` | `IPv4:port` |
| **2** | What Certificate Authority (CA) issued the VPN client certificate? | `NPLN-CA` | `string` |
| **3** | What is the IP address assigned to the user by the VPN server? | `10.129.175.2` | `IPv4` |
| **4** | It seems that the PC is remotely managed. What is the name and version of the installed remote management agent? | `Tactical RMM v.2.11.0` | `Agent Name v.X.Y.Z` |
| **5** | What is the domain the remote management agent connects to? | `api.antimattercommunication.xyz` | `fully qualified domain name` |
| **6** | What is the remote management agent Authentication Token? | `98ec588da683c01820232943a6151e8e7772419b` | `SHA-1 Hash` |
| **7** | What is the first of the three commands executed in Operation Vanish? | `Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force` | `(*********** ************ *:\*****\****\***** ******** ******)` |
| **8** | What is the account used to connect to the instant messaging server through the software previously identified? | `spurio9@murknet.htb` | `email address` |
| **9** | What is the password for that account? | `spur999!*` | `string` |
| **10** | What is the full name of the jailer? | `Abel Stokes` | `FirstName LastName` |

---

## Detailed Forensic Evidence

### Questions 1, 2, 3: OpenVPN Configuration & Connection Logs
- **Source**: Unallocated cluster runs carved from the raw disk `\\.\D:` (`$MFT` record for `spur.log`, cluster runs `0x152C6C` and `0x14FE0F`).
- **Log Snippet**:
  ```text
  UDPv4 link remote: [AF_INET]18.156.81.166:7577
  VERIFY OK: depth=1, CN=NPLN-CA
  VERIFY OK: depth=0, CN=spur
  MANAGEMENT: >STATE:1788265270,ASSIGN_IP,,10.129.175.2,,,,
  ```
- **Findings**:
  - **Q1**: `18.156.81.166:7577`
  - **Q2**: `NPLN-CA`
  - **Q3**: `10.129.175.2`

---

### Questions 4, 5, 6: Remote Management Agent (Tactical RMM)
- **Source**: 
  - Executable: `D:\Program Files\TacticalAgent\tacticalrmm.exe`
  - Registry: `D:\Windows\System32\config\SOFTWARE` -> `SOFTWARE\TacticalRMM`
- **Registry Values**:
  - `BaseURL` = `https://api.antimattercommunication.xyz`
  - `ApiURL` = `https://api.antimattercommunication.xyz`
  - `Token` = `98ec588da683c01820232943a6151e8e7772419b`
  - Product Version from PE metadata = `2.11.0`, Product Name = `Tactical RMM`
- **Findings**:
  - **Q4**: `Tactical RMM v.2.11.0`
  - **Q5**: `api.antimattercommunication.xyz`
  - **Q6**: `98ec588da683c01820232943a6151e8e7772419b`

---

### Question 7: Operation Vanish
- **Source**: `D:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`
- **Context**: Decoded Base64 command invoked via Tactical RMM during cleanup script named "Operation Vanish":
  ```powershell
  Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force
  Remove-Item -LiteralPath C:\Users\spur\OpenVPN -Recurse -Force
  Remove-Item -LiteralPath "C:\Users\spur\AppData\Roaming\Gajim" -Recurse -Force
  ```
- **Mask Matching**:
  - `***********` -> `Remove-Item`
  - `************` -> `-LiteralPath`
  - `*:\*****\****\*****` -> `C:\Users\spur\Gajim`
  - `********` -> `-Recurse`
  - `******` -> `-Force`
- **Finding**:
  - **Q7**: `Remove-Item -LiteralPath C:\Users\spur\Gajim -Recurse -Force`

---

### Questions 8, 9: Gajim Instant Messaging Credentials
- **Source**: Carved SQLite database `Settings.sqlite` (Entry 156449, clusters `0x3120F3`, `0x295E95`, `0x242ADD`).
- **Table**: `account_settings`
  - `account`: `spurio9@murknet.htb`
  - `name`: `password`, `value`: `spur999!*`
- **Findings**:
  - **Q8**: `spurio9@murknet.htb`
  - **Q9**: `spur999!*`

---

### Question 10: Jailer Full Name
- **Source**: Chrome session storage file `D:\Users\spur\AppData\Local\Google\Chrome\User Data\Default\Sessions\Session_13432739740965801`.
- **Evidence**:
  - Browser tab title: `Mail - Abel Stokes - Outlook` (URL: `https://outlook.live.com/mail/?deeplink=mail%2F`)
  - Concurrently open tabs on the jailer's laptop:
    - `https://www.google.com/search?q=how+to+use+chloroform`
    - `https://www.google.com/search?q=my+hostage+doesn%27t+listen+to+me`
    - `https://chatgpt.com/`
    - `https://betway.com/`
- **Finding**:
  - **Q10**: `Abel Stokes`
