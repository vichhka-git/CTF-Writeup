import struct
import os
import requests
from pwn import remote

API_KEY = os.environ.get('CTFD_TOKEN')
CHALLENGE_ID = 20

def get_instance():
    if not API_KEY:
        raise RuntimeError('set CTFD_TOKEN before requesting an instance')
    headers = {
        'Authorization': f'Token {API_KEY}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    r = requests.get(f'https://mirror-ctf.compfest.id/api/v1/containers/info/{CHALLENGE_ID}', headers=headers)
    data = r.json()
    if data.get('status') == 'created' or 'connection' in data:
        conn = data['connection']
        return conn['host'], conn['port']
    
    r = requests.post('https://mirror-ctf.compfest.id/api/v1/containers/request', json={'challenge_id': CHALLENGE_ID}, headers=headers)
    data = r.json()
    conn = data['connection']
    return conn['host'], conn['port']

def rol64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xffffffffffffffff

def forward(in_bytes):
    r8, r9 = struct.unpack('<QQ', in_bytes)
    # Stage 1 (64-bit):
    r8 ^= 0xa6f1c0d93b5e2748
    A = r8
    B = r9
    
    # Stage 2 (32-bit):
    A_low = A & 0xffffffff
    A = (A + A_low * (B & 0xffffffff)) & 0xffffffffffffffff
    B = rol64(B, 13)
    A = A ^ B
    
    # Stage 3 (64-bit):
    B = (B + A) & 0xffffffffffffffff
    B = rol64(B, 29)
    B = (B * 0xff51afd7ed558ccd) & 0xffffffffffffffff
    A = (A + B) & 0xffffffffffffffff
    A = rol64(A, 17)
    
    # Stage 4 (32-bit):
    out_low = A ^ B
    out_high = (A + B) & 0xffffffffffffffff
    return struct.pack('<QQ', out_low, out_high)

def solve():
    host, port = get_instance()
    print(f'Connecting to {host}:{port}...')
    io = remote(host, port)
    io.sendlineafter(b'CTFd access token: ', API_KEY.encode())
    line = io.recvline().decode().strip()
    print('Received line:', line)
    req_hex = line.split(': ')[1].strip()
    req_bytes = bytes.fromhex(req_hex)
    ans = forward(req_bytes)
    print('Sending answer:', ans.hex())
    io.sendlineafter(b'response:\n', ans.hex().encode())
    resp = io.recvall(timeout=5).decode()
    print('Response:\n' + resp)
    return resp

if __name__ == '__main__':
    solve()
