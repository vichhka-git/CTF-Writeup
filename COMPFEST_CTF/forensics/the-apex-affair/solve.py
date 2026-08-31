#!/usr/bin/env python3
"""Submit the verified Apex Affair answer set to an authorized instance."""

import os
import socket
import sys
import time


HOST = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CHALLENGE_HOST")
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("CHALLENGE_PORT", "30022"))
TOKEN = os.environ.get("CHALLENGE_TOKEN")


def recv_until(sock, marker, timeout=30):
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before expected prompt")
        data.extend(chunk)
    return bytes(data)


answers = [
    # Part 1
    "Outlook",
    "2026-08-15 08:45:38",
    "Update Your Browser - Download the Latest Google Chrome",
    "2026-08-15 16:42:36",
    # Part 2
    "GoogleChromeUpdater",
    'rundll32.exe "C:\\Users\\Public\\chrome_update.dll",Drop',
    "2|C:\\Program Files\\Google\\Chrome\\GoogleUpdater.exe|C:\\Program Files\\Google\\Chrome\\software_reporter_tool.exe",
    '"C:\\Program Files\\Google\\Chrome\\GoogleUpdater.exe" "add-exclusion" "Paths" "C:\\Program Files\\Google\\Chrome"|"C:\\Program Files\\Google\\Chrome\\GoogleUpdater.exe" "secengine" "disable"|"C:\\Program Files\\Google\\Chrome\\GoogleUpdater.exe" "tp" "off"|"C:\\Program Files\\Google\\Chrome\\GoogleUpdater.exe" "rtp" "off"',
    "2026-08-15 16:48:38",
    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\SecurityHealthSystray.exe\\Debugger=systray.exe",
    "T1547.001",
    "2026-08-15 16:49:32",
    # Part 3
    "Google Calendar",
    "18a7bdbf39f6baa148901225fa21b72cfe492720379a04f2068e1d364db65457@group.calendar.google.com",
    "summary_description",
    "systeminfo",
    "2026-08-15 17:11:14",
    'for /f "tokens=1" %%i in (\'tasklist /nh\') do @echo %%i',
    "KEqrg7kVO1xP2BqJG9fZUpMyWblZFQWuClvZb0EYIzw=",
    "Edward Collins",
    # Part 4
    "notepad.exe;0x00000151c1e20000",
    "9e2413e4d0469a25c7840872f5fa98d93c4bb1c2f9a0d184f47eadaf808fefcf",
    # Part 5
    "0x08FE9fc8288Cf5D5EE5f4F69c0e4f774FFA275d4",
    "0x8fe24bdb",
    "a545e0a8c675ce955431882c239e555e2de01b6bf63cd0c84514627cc306481f;7a89a98c355a84e98a3f4ef3045871d4;4096",
    "d33cc7764e98bcdef507065dc96d4b2e5fd2af0ec95d60e9b4e115fa75b2ea5e"
]

if not HOST or not TOKEN:
    raise SystemExit(
        "usage: CHALLENGE_TOKEN=... python3 solve.py HOST [PORT]"
    )


with socket.create_connection((HOST, PORT), timeout=30) as r:
    r.settimeout(30)

    # Receive prompt for token.
    recv_until(r, b"token:")
    print("[+] Sending Token...")
    r.sendall(TOKEN.encode() + b"\n")

    for idx, ans in enumerate(answers):
        prompt = recv_until(r, b"> Answer:")
        print(f"\n--- Question {idx+1}/{len(answers)} ---")
        print(prompt.decode("utf-8", errors="ignore")[-300:])
        print(f"[+] Sending Answer [{idx+1}/{len(answers)}]: {ans}")
        r.sendall(ans.encode() + b"\n")
        time.sleep(0.1)

    print("\n--- FINAL OUTPUT ---")
    r.settimeout(10)
    output = bytearray()
    while True:
        try:
            chunk = r.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        output.extend(chunk)
    print(bytes(output).decode("utf-8", errors="ignore"))
