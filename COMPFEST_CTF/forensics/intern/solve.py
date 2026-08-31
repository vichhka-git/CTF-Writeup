#!/usr/bin/env python3
"""
Automated Solver for COMPFEST CTF - Forensic: Intern (500 pts)
Author: Antigravity
Flag: COMPFEST18{hopefully_there_isnt_too_much_questions_PlfSNpTtoNCp1evs}
"""

import sys
import socket
import time
import os

ANSWERS = [
    # Part 1: Initiation
    "6d97129e85a6552bb07a8a83037eae7cda2022ffd4370b7dbc8a2ed59c05f696,deff31d22f07b9f546b146d1417e758bf77e260d39b18ec8eb5d29d9dc58cb9b,233138454a22accfea9eaaf76bda028d8787acbf16aed83fd6291eff05d3b748",
    "vscode-helloworld",
    "https://github.com/whiskerstein-cf/helloworld-vscode/releases/tag/0.3.0",
    "2026-06-27 11:02:24",
    "3",
    "0.2.0",
    
    # Part 2: Malicious Activity
    "http://192.168.0.114:6767/AnyDesk.exe",
    "28b8c8225d52edd5b654a9b89a875b556ebfb06c8b818ca132e2fef06a98a189",
    "Company website: http://10.0.2.15:7070",
    
    # Part 3: The Hacker
    "Discord,Telegram",
    "2",
    "whiskerstein,dooggdogg",
    "goose",
    "4",
    "http://192.168.0.114:5000/submit",
    "hehewhiskerstein:.v4SQ4Ls&9dUi-wz",
    
    # Part 4: More??!!
    "http://192.168.0.114:9000/WindowsDefender.exe,http://192.168.0.114:9000/wsl.exe,http://192.168.0.114:9000/code.exe",
    "1e33cf8fbb72a4ec463e6b7a680d0d8ff5a2f1859cdb518b4abd052cb3f3338a,481ae0e266362df553befed223c1b85087da423416d5215fb8484fbc49a33dd9,c6a1b3235de1ea5ae084826098fad4d5f781b21ec3d6f959db186dde9b3cd87d",
    "code.exe",
    "UAC bypass",
    "T1548.002",
    "fodhelper.exe",
    "C:\\Users\\Public\\Music\\wsl.exe",
    
    # Part 5: Going deeper
    "wsl.exe",
    "Recycle Bin",
    "WindowsDefender.exe",
    "Process Hollowing",
    "C:\\Windows\\explorer.exe",
    "c609f009cb0336f68b67b5c5c768d6da4542c342c20e1fa28f4a828b3308d83d",
    "192.168.100.66:10990"
]

def solve(host, port, token=None):
    s = socket.create_connection((host, int(port)))
    f = s.makefile('rw', buffering=1, encoding='utf-8', errors='ignore')
    
    def read_until(pattern):
        buf = ""
        while True:
            ch = f.read(1)
            if not ch:
                break
            buf += ch
            if pattern in buf:
                break
        return buf

    # Handle CTFd token prompt
    out = read_until("access token:")
    sys.stdout.write(out)
    if not token:
        token = os.environ.get("CTFD_TOKEN") or input("Enter CTFd access token: ")
            
    f.write(token + "\n")
    f.flush()

    for idx, ans in enumerate(ANSWERS, 1):
        prompt = read_until("> Answer:")
        sys.stdout.write(prompt)
        sys.stdout.flush()
        print(f"[[SENDING Q{idx}]]: {ans}")
        f.write(ans + "\n")
        f.flush()

    # Read remaining response to print flag
    rest = f.read()
    sys.stdout.write(rest)
    sys.stdout.flush()
    s.close()

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 solve.py <host> <port> [ctfd_token]")
        print("Example: python3 solve.py <HOST> <PORT>")
        sys.exit(1)
    
    h = sys.argv[1]
    p = sys.argv[2]
    tok = sys.argv[3] if len(sys.argv) > 3 else None
    solve(h, p, tok)
