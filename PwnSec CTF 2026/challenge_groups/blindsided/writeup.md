# Blindsided (Challenge Group)

* **Category:** BlueTeam / DFIR / Incident Response
* **Difficulty:** Medium
* **Total Points:** 210 (17 * 1 pt + 193 pts)
* **Flag:** `pwnsec{64045c11925ba1ef21444f0bc35ae29532552cf440faddfd6291d84d6465191c}`

---

## Scenario Overview

> An HR employee reported receiving an email from a job applicant named **Aurelio Nadeau** containing what looked like a CV and cover letter. The employee says they simply opened the PDF attachment to review the application.
>
> Minutes later the SOC flagged an unusual outbound connection from the workstation. The employee insists:
>
> *"I just opened a PDF. I didn't run anything."*
>
> Forensic artifacts have been collected from the workstation. Trace the full attack chain &mdash; from initial access to exfiltration &mdash; and answer the questions.
>
> **- @Abdullah**

---

## Attack Chain Breakdown & Task Solutions

### Task 1: Blindsided - 1 - The Subdomain
* **Slug:** `blindsided---1---the-subdomain`
* **Points:** 1
* **Question:**
  What is the subdomain of the company that Patrick has access to?
* **Analysis:**
  Examining the browser history (`History` SQLite database from Chrome/Edge) and email client data reveals access to ACME IT's internal recruitment portal: `careers.acmeit.com`.
* **Answer:** `careers.acmeit.com`

---

### Task 2: Blindsided - 2 - The True Extension
* **Slug:** `blindsided---2---the-true-extension`
* **Points:** 1
* **Question:**
  What was the full filename of the malicious file executed by the victim, including its true extension?
* **Analysis:**
  Inspecting the downloaded email attachment `Aurelio Nadeau.zip` shows an archive containing a Windows shortcut crafted to look like a document: `Aurelio_Nadeau_CV.pdf.lnk`.
* **Answer:** `Aurelio_Nadeau_CV.pdf.lnk`

---

### Task 3: Blindsided - 3 - Masquerading
* **Slug:** `blindsided---3---masquerading`
* **Points:** 1
* **Question:**
  What MITRE ATT&CK technique was used to disguise the malicious LNK file as a PDF document?
* **Analysis:**
  The attacker appended `.pdf` prior to `.lnk` to deceive the user when file extensions are hidden or overlooked by Windows Explorer. According to MITRE ATT&CK, this technique is **T1036.007** (*Masquerading: Double File Extension*).
* **Answer:** `T1036.007`

---

### Task 4: Blindsided - 4 - The Decoy Path
* **Slug:** `blindsided---4---the-decoy-path`
* **Points:** 1
* **Question:**
  What is the target fake path configured in the malicious LNK file?
* **Analysis:**
  Parsing the LNK file structures (`LECmd` or binary inspection of `Aurelio_Nadeau_CV.pdf.lnk`) shows the target working directory and decoy path: `C:\Users\Default\Downloads\CVs`.
* **Answer:** `C:\Users\Default\Downloads\CVs`

---

### Task 5: Blindsided - 5 - The Distraction
* **Slug:** `blindsided---5---the-distraction`
* **Points:** 1
* **Question:**
  What decoy file was opened to distract the victim?
* **Analysis:**
  When the LNK script executed, it immediately opened `Cover_letter.pdf` in the default PDF viewer to keep the victim unsuspecting while launching background payloads.
* **Answer:** `Cover_letter.pdf`

---

### Task 6: Blindsided - 6 - Second Stage
* **Slug:** `blindsided---6---second-stage`
* **Points:** 1
* **Question:**
  What is the URL of the second-stage PowerShell script downloaded by the attacker?
* **Analysis:**
  The command line embedded in the LNK invoked PowerShell to fetch a stage 2 script:
  `http://edcvbgtrf.medianewsonline.com:8000/812hoqq.ps1`.
* **Answer:** `http://edcvbgtrf.medianewsonline.com:8000/812hoqq.ps1`

---

### Task 7: Blindsided - 7 - The Payload Archive
* **Slug:** `blindsided---7---the-payload-archive`
* **Points:** 1
* **Question:**
  What is the URL of the ZIP archive downloaded by the attacker as part of the attack?
* **Analysis:**
  In `812hoqq.ps1`, PowerShell downloads a signed application bundle hosted on Dropbox:
  `https://www.dl.dropboxusercontent.com/scl/fi/kkpbmsijwvytuyn4vevxq/Stardock.zip?rlkey=otwecndex77qyzf6n0j73udkq&st=dftviim1&dl=1`.
* **Answer:** `https://www.dl.dropboxusercontent.com/scl/fi/kkpbmsijwvytuyn4vevxq/Stardock.zip?rlkey=otwecndex77qyzf6n0j73udkq&st=dftviim1&dl=1`

---

### Task 8: Blindsided - 8 - Living off the Land
* **Slug:** `blindsided---8---living-off-the-land`
* **Points:** 1
* **Question:**
  What legitimate software was extracted and executed from the ZIP file?
* **Analysis:**
  The Stardock bundle extracted a legitimate signed binary from WindowBlinds: `WB11Config.exe`.
* **Answer:** `WB11Config.exe`

---

### Task 9: Blindsided - 9 - The Side-Loaded DLL
* **Slug:** `blindsided---9---the-side-loaded-dll`
* **Points:** 1
* **Question:**
  What is the name of the malicious DLL that was side-loaded by WB11Config.exe?
* **Analysis:**
  `WB11Config.exe` loads DLLs from its current working directory. The attacker dropped a malicious proxy DLL named `wblindp2.dll` to execute code under the trusted process context.
* **Answer:** `wblindp2.dll`

---

### Task 10: Blindsided - 10 - Emptying the Browser
* **Slug:** `blindsided---10---emptying-the-browser`
* **Points:** 1
* **Question:**
  What is the URL of the open-source tool downloaded by the malware to steal saved browser passwords, cookies, and history?
* **Analysis:**
  The malware downloads the compiled Go open-source tool `hack-browser-data` from:
  `http://edcvbgtrf.medianewsonline.com:8000/hack-browser-data.exe`.
* **Answer:** `http://edcvbgtrf.medianewsonline.com:8000/hack-browser-data.exe`

---

### Task 11: Blindsided - 11 - Where the Loot Landed
* **Slug:** `blindsided---11---where-the-loot-landed`
* **Points:** 1
* **Question:**
  Where did the malware store the harvested browser credential output on disk?
* **Analysis:**
  Process command-line arguments and file system modifications show `hack-browser-data.exe` dumping its output directory to:
  `C:\Users\Patrick\AppData\Local\Temp\hbdata`.
* **Answer:** `C:\Users\Patrick\AppData\Local\Temp\hbdata`

---

### Task 12: Blindsided - 12 - Combing the Disk
* **Slug:** `blindsided---12---combing-the-disk`
* **Points:** 1
* **Question:**
  Which two folders on the victim's machine were specifically targeted for document collection? Format: `Folder1:Folder2`
* **Analysis:**
  The script enumerated user documents across both the Desktop and Documents folders.
* **Answer:** `C:\Users\Patrick\Desktop:C:\Users\Patrick\Documents`

---

### Task 13: Blindsided - 13 - What They Wanted
* **Slug:** `blindsided---13---what-they-wanted`
* **Points:** 1
* **Question:**
  What file extensions were targeted during the document collection phase?
* **Analysis:**
  The document collection script filtered files with matching extensions (alphabetically sorted):
  `.doc .docx .jpg .pdf .png .ppt .pptx .txt .xls .xlsx`.
* **Answer:** `.doc .docx .jpg .pdf .png .ppt .pptx .txt .xls .xlsx`

---

### Task 14: Blindsided - 14 - Staged for Exfiltration
* **Slug:** `blindsided---14---staged-for-exfiltration`
* **Points:** 1
* **Question:**
  What was the full path of the encrypted file staged for exfiltration?
* **Analysis:**
  The collected loot was compressed, encrypted, and written to:
  `C:\Users\Patrick\AppData\Local\Temp\Patrick_192.168.10.129.txt`.
* **Answer:** `C:\Users\Patrick\AppData\Local\Temp\Patrick_192.168.10.129.txt`

---

### Task 15: Blindsided - 15 - Where It Went
* **Slug:** `blindsided---15---where-it-went`
* **Points:** 1
* **Question:**
  What was the full URL used for data exfiltration?
* **Analysis:**
  Network packet analysis (`capture.pcapng`) reveals an HTTP POST request uploading the staged file to:
  `http://51.20.98.70:4444/upload`.
* **Answer:** `http://51.20.98.70:4444/upload`

---

### Task 16: Blindsided - 16 - Hiding in Plain Sight
* **Slug:** `blindsided---16---hiding-in-plain-sight`
* **Points:** 1
* **Question:**
  What process did the malware attempt to inject into for camouflage, and what was the fallback? Format: `Primary:Fallback`
* **Analysis:**
  Decompiling `wblindp2.dll` indicates process injection logic attempting to target Microsoft Edge (`msedge.exe`) first, falling back to Windows Explorer (`explorer.exe`) if Edge is not running.
* **Answer:** `msedge.exe:explorer.exe`

---

### Task 17: Blindsided - 17 - Impact
* **Slug:** `blindsided---17---impact`
* **Points:** 1
* **Question:**
  What is the password for the victim's careers.acmeit.com account?
* **Analysis:**
  Decrypting the exfiltrated browser credentials using the derived encryption key (`Patrick:192.168.10.129`) recovers Patrick's saved portal password: `Patrick@12@!`.
* **Answer:** `Patrick@12@!`

---

### Task 18: Blindsided - 18 - Claim your points
* **Slug:** `blindsided---18---claim-your-points`
* **Points:** 193
* **Question:**
  Concatenate every answer submitted in this group, in order (question 1 through 17), directly with no separators, spaces, or newlines. The seal is the SHA-256 of that string.
  `pwnsec{ sha256(answer1 + answer2 + ... + answer17) }`
* **Calculation:**
  See [`solve.py`](./solve.py).
* **Final Flag:**
  ```
  pwnsec{64045c11925ba1ef21444f0bc35ae29532552cf440faddfd6291d84d6465191c}
  ```
