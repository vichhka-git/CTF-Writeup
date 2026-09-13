#!/usr/bin/env python3
"""
PwnSec CTF 2026 - Blindsided (Challenge Group / BlueTeam / DFIR)
Solution and Seal Verification Script
"""

import hashlib

# All 17 accepted answers in exact sequence:
answers = [
    "careers.acmeit.com",                                                                                                # Task 1: The Subdomain
    "Aurelio_Nadeau_CV.pdf.lnk",                                                                                         # Task 2: The True Extension
    "T1036.007",                                                                                                         # Task 3: Masquerading
    "C:\\Users\\Default\\Downloads\\CVs",                                                                                # Task 4: The Decoy Path
    "Cover_letter.pdf",                                                                                                  # Task 5: The Distraction
    "http://edcvbgtrf.medianewsonline.com:8000/812hoqq.ps1",                                                             # Task 6: Second Stage
    "https://www.dl.dropboxusercontent.com/scl/fi/kkpbmsijwvytuyn4vevxq/Stardock.zip?rlkey=otwecndex77qyzf6n0j73udkq&st=dftviim1&dl=1", # Task 7: The Payload Archive
    "WB11Config.exe",                                                                                                    # Task 8: Living off the Land
    "wblindp2.dll",                                                                                                      # Task 9: The Side-Loaded DLL
    "http://edcvbgtrf.medianewsonline.com:8000/hack-browser-data.exe",                                                    # Task 10: Emptying the Browser
    "C:\\Users\\Patrick\\AppData\\Local\\Temp\\hbdata",                                                                  # Task 11: Where the Loot Landed
    "C:\\Users\\Patrick\\Desktop:C:\\Users\\Patrick\\Documents",                                                         # Task 12: Combing the Disk
    ".doc .docx .jpg .pdf .png .ppt .pptx .txt .xls .xlsx",                                                              # Task 13: What They Wanted
    "C:\\Users\\Patrick\\AppData\\Local\\Temp\\Patrick_192.168.10.129.txt",                                              # Task 14: Staged for Exfiltration
    "http://51.20.98.70:4444/upload",                                                                                    # Task 15: Where It Went
    "msedge.exe:explorer.exe",                                                                                           # Task 16: Hiding in Plain Sight
    "Patrick@12@!"                                                                                                       # Task 17: Impact
]

def main():
    concat_str = "".join(answers)
    seal = hashlib.sha256(concat_str.encode("utf-8")).hexdigest()
    flag = f"pwnsec{{{seal}}}"

    print(f"[*] Total answers verified:    {len(answers)}")
    print(f"[*] Concatenated length:       {len(concat_str)}")
    print(f"[*] SHA-256 Digest:            {seal}")
    print(f"[*] Final Track Flag:          {flag}")

    expected_flag = "pwnsec{64045c11925ba1ef21444f0bc35ae29532552cf440faddfd6291d84d6465191c}"
    assert flag == expected_flag, f"Flag mismatch! Expected: {expected_flag}, Got: {flag}"
    print("[+] All 18 tasks verified and match the 100% accepted flag!")

if __name__ == "__main__":
    main()
