#!/usr/bin/env python3
"""
PwnSec CTF 2026 - Ghost Flight (Challenge Group / BlueTeam / OSINT)
Solution and Seal Verification Script
"""

import hashlib

# Track Answers:
# Task 1: Registration code of the aircraft (Shenzhen Bao'an -> Hangzhou Xiaoshan, Sept 2016)
# Task 2: Withdrawal date (DD/MM/YYYY)
# Task 3: Storage airport location
# Task 4: Origin and destination (IATA-IATA) of ferry flight
# Task 5: Twin aircraft registration involved in cockpit cigarette fire incident

answers = [
    "B-5360",
    "12/04/2019",
    "Castellón-Costa Azahar Airport",
    "HEL-SNN",
    "B-5363"
]

def main():
    concat_str = "".join(answers)
    seal = hashlib.sha256(concat_str.encode("utf-8")).hexdigest()
    flag = f"pwnsec{{{seal}}}"

    print(f"[*] Concatenated string: {concat_str}")
    print(f"[*] SHA-256 Digest:      {seal}")
    print(f"[*] Final Track Flag:    {flag}")

    expected_flag = "pwnsec{29c58d587d4e5e0a8380753406daf02c3b4346b7f02d8899ad22888ca74b8b9c}"
    assert flag == expected_flag, f"Flag mismatch! Got: {flag}"
    print("[+] All answers verified and match the 100% accepted flag!")

if __name__ == "__main__":
    main()
