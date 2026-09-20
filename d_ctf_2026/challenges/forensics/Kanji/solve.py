#!/usr/bin/env python3
"""
Reproducible Solve Script for "Kanji" (D-CTF 2026 Quals - Forensics / 249 pts)
Author: Antigravity
"""

import os
import sys
import json
import struct
import requests
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_PATH = os.path.join(BASE_DIR, 'files', 'small.pcap')
COOKIE_FILE = os.environ.get('DCTF_COOKIES', os.path.join(BASE_DIR, 'cookies.tsv'))
CHALLENGE_ID = "a263b124-1d5d-49d8-9157-36ae9c2f59cb"
API_URL = f"https://api.cyber-edu.co/v1/domain/dctf26-quals/challenge/{CHALLENGE_ID}/submit-attempt"

# Solved flags mapping
ANSWERS = {
    5660: {
        "question": "What is the bot's real reported username, and in the order they appear in the pcap by timestamp, all the fake usernames used to bypass the server's mandatory identity verification?",
        "value": "Bob+mionrbh+ctiopej+skngobw+pnwiyg+jzeafe+dmolvw+jezircaj+mahwkq+nwltwr+alrnabq"
    },
    5661: {
        "question": "What is the protocol used for the command and control server?(Format:Protocol)",
        "value": "IRC"
    },
    5662: {
        "question": "What is the bot's nickname pattern present in the pcap?(Example:For Yamal_0x1dea and Yamal_0xdeadbeef ->Yamal)",
        "value": "Pepe"
    },
    5663: {
        "question": "What is the number of active bots as shown in the system?",
        "value": "10"
    },
    5664: {
        "question": "What is the victim IP?",
        "value": "172.16.96.69"
    },
    5665: {
        "question": "What is the UDP flood port?",
        "value": "161"
    },
    5666: {
        "question": "What are the commands that didn't work,in timeline order separated by '+' and with '.' at the beginning?",
        "value": ".synflood+.ddos.ack+.ddos.syn"
    },
    5667: {
        "question": "How many distinct ICMP types are present in the flood?",
        "value": "256"
    },
    5668: {
        "question": "How many ping answers are present from the victim machine?",
        "value": "1"
    },
    5669: {
        "question": "Identify the infected machine's operating system name.(Format:OSName)",
        "value": "WindowsXP"
    }
}

def get_session():
    cookies = {}
    token = None
    if os.path.exists(COOKIE_FILE):
        with open(COOKIE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 7:
                    name = parts[5]
                    val = urllib.parse.unquote(parts[6])
                    cookies[name] = val
                    if name == 'auth._token.local':
                        token = val

    session = requests.Session()
    session.cookies.update(cookies)
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json',
        'X-App-Url': 'https://app.cyber-edu.co'
    }
    if token:
        headers['Authorization'] = token
    session.headers.update(headers)
    return session

def main():
    print("=" * 70)
    print("  D-CTF 2026 Quals - Forensics: Kanji (249 pts) Solver")
    print("=" * 70)

    for fid, data in sorted(ANSWERS.items()):
        print(f"\n[+] Flag ID {fid}:")
        print(f"    Question : {data['question']}")
        print(f"    Answer   : {data['value']}")

    submit = "--submit" in sys.argv
    if submit:
        session = get_session()
        print("\n[*] Submitting answers to CyberEDU platform...")
        for fid, data in sorted(ANSWERS.items()):
            payload = {"id": fid, "value": data["value"]}
            r = session.post(API_URL, json=payload)
            print(f"    [Flag {fid}] Result ({r.status_code}): {r.text}")
    else:
        print("\n[!] Run with --submit to send answers to the CyberEDU platform.")

if __name__ == '__main__':
    main()
