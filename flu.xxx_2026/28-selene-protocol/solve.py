#!/usr/bin/env python3
"""Selene.Protocol.v1.1-LNR: unpack selene.exe from setup.exe and recover the flag."""
import struct, zlib, sys

# ---------- minimal PE helpers (no third-party modules) ----------
def pe_sections(raw):
    e = struct.unpack_from('<I', raw, 0x3c)[0]
    n = struct.unpack_from('<H', raw, e + 6)[0]
    optsz = struct.unpack_from('<H', raw, e + 20)[0]
    off = e + 24 + optsz
    ib = struct.unpack_from('<Q', raw, e + 24 + 24)[0]
    out = {}
    for _ in range(n):
        name = raw[off:off + 8].rstrip(b'\0').decode('latin1')
        vs, va, rs, rp = struct.unpack_from('<IIII', raw, off + 8)
        out[name] = dict(vsize=vs, va=va, rawsz=rs, rawptr=rp)
        off += 40
    return ib, out

def va2off(ib, secs, va):
    for s in secs.values():
        d = va - ib - s['va']
        if 0 <= d < max(s['vsize'], s['rawsz']):
            return s['rawptr'] + d
    raise KeyError(hex(va))

# ---------- ChaCha20 (RFC 8439 block function) ----------
def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def ror(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff

def qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = rotl(s[b] ^ s[c], 7)

def chacha_block(key, ctr=0, nonce=b'\0' * 8):
    init = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574) \
        + struct.unpack('<8I', key) + (ctr, 0) + struct.unpack('<2I', nonce)
    s = list(init)
    for _ in range(10):
        qr(s, 0, 4, 8, 12); qr(s, 1, 5, 9, 13); qr(s, 2, 6, 10, 14); qr(s, 3, 7, 11, 15)
        qr(s, 0, 5, 10, 15); qr(s, 1, 6, 11, 12); qr(s, 2, 7, 8, 13); qr(s, 3, 4, 9, 14)
    return struct.pack('<16I', *[(s[i] + init[i]) & 0xffffffff for i in range(16)])

def keyroll_xor(key, data):
    """setup.exe's stream: every 64-byte block uses ChaCha20(key, ctr=0, nonce=0) and
    then rolls key ^= keystream[0:32]."""
    out = bytearray(len(data))
    k = bytearray(key)
    for i in range(0, len(data), 64):
        ks = chacha_block(bytes(k))
        chunk = data[i:i + 64]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
        k = bytearray(a ^ b for a, b in zip(k, ks[:32]))
    return bytes(out)

# ---------- installer key ----------
def fnv_extension(material):
    h = 0x811c9dc5
    ext = bytearray()
    for i in range(16):
        h ^= material[i]
        h = (h * 0x1000193) & 0xffffffff
        ext.append(((h >> 13) ^ (h >> 5) ^ (i * 0x3b)) & 0xff)
    return bytes(ext)

# ---------- license mixer ----------
def mixer(r):
    r = list(r)
    for _ in range(3):
        r[0] = (r[0] + r[1]) & 0xffffffff; r[3] = rotl(r[3] ^ r[0], 11)
        r[2] = (r[2] + r[3]) & 0xffffffff; r[1] = rotl(r[1] ^ r[2], 7)
        r[4] = (r[4] + r[5]) & 0xffffffff; r[7] = rotl(r[7] ^ r[4], 13)
        r[6] = (r[6] + r[7]) & 0xffffffff; r[5] = ror(r[5] ^ r[6], 15)
        r[0], r[4] = r[4], r[0]
    return r

def inv_mixer(r):
    r = list(r)
    for _ in range(3):
        r[0], r[4] = r[4], r[0]          # undo swap
        r5 = rotl(r[5], 15) ^ r[6]       # undo r5 = ror(r5 ^ r6, 15)
        r6 = (r[6] - r[7]) & 0xffffffff  # undo r6 += r7
        r7 = ror(r[7], 13) ^ r[4]        # undo r7 = rol(r7 ^ r4, 13)
        r4 = (r[4] - r5) & 0xffffffff    # undo r4 += r5
        r1 = ror(r[1], 7) ^ r[2]         # undo r1 = rol(r1 ^ r2, 7)
        r2 = (r[2] - r[3]) & 0xffffffff  # undo r2 += r3
        r3 = ror(r[3], 11) ^ r[0]        # undo r3 = rol(r3 ^ r0, 11)
        r0 = (r[0] - r1) & 0xffffffff    # undo r0 += r1
        r[0], r[1], r[2], r[3] = r0, r1, r2, r3
        r[4], r[5], r[6], r[7] = r4, r5, r6, r7
    return r

def main(path):
    raw = open(path, 'rb').read()
    _, secs = pe_sections(raw)

    # 1. installer payload: PE section .lnr0 -> LNR1 archive -> selene.exe
    s = secs['.lnr0']
    material = b'LNRPKG1066proper'
    key = material + fnv_extension(material)
    arch = keyroll_xor(key, raw[s['rawptr']:s['rawptr'] + s['vsize']])
    assert arch[:4] == b'LNR1', arch[:8]
    size = struct.unpack_from('<I', arch, 0x16)[0]
    exe = arch[0x1a:0x1a + size]
    assert exe[:2] == b'MZ'
    open('selene.exe', 'wb').write(exe)
    print('archive: %d bytes, member %r, %d bytes -> selene.exe'
          % (len(arch), arch[12:22].rstrip(b'\0'), size))

    # 2. the debugger's expected mixer outputs
    ib, secs = pe_sections(exe)
    t = secs['.text']
    crc = zlib.crc32(exe[t['rawptr']:t['rawptr'] + t['rawsz']]) & 0xffffffff
    const = struct.unpack('<8I', exe[va2off(ib, secs, ib + 0xf358):][:32])
    expected = [(rotl(crc, 3 * i) ^ (const[i] ^ ((i + 1) * 0x9e3779b9))) & 0xffffffff
                for i in range(8)]
    blob = struct.pack('<8I', *inv_mixer(expected))
    assert mixer(struct.unpack('<8I', blob)) == expected
    print('crc32(.text) = %08x' % crc)
    print('license blob = %s' % blob.hex())

    # 3. flag = C ^ ChaCha20(key=blob, ctr=0, nonce=0)
    C = exe[va2off(ib, secs, ib + 0xf2a0):][:38]
    ks = chacha_block(blob) + chacha_block(blob, ctr=1)
    flag = bytes(a ^ b for a, b in zip(C, ks))
    print('flag = %s' % flag.decode())

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'setup.exe')
