#!/usr/bin/env python3
"""WHSP protocol client for the WHISPER Beacon challenge."""
import socket
import struct
import sys

HOST = "ec2-18-236-161-153.us-west-2.compute.amazonaws.com"
PORT = 9002

# S-box extracted from the binary at 0x4020a0
SBOX = bytes([
    0xee, 0xad, 0xf6, 0x3e, 0x9c, 0xac, 0x9f, 0x0f, 0x99, 0x12, 0xe3, 0xb4, 0xf2, 0xcf, 0x19, 0x25,
    0x30, 0x14, 0xdd, 0xa2, 0xcb, 0x93, 0xb7, 0xe8, 0x53, 0x94, 0x75, 0x5d, 0xaa, 0x50, 0xc1, 0x70,
    0xf7, 0xd8, 0x48, 0xf9, 0xae, 0x56, 0xc7, 0x61, 0xe4, 0x22, 0x96, 0xe0, 0x6c, 0xa0, 0x74, 0x3f,
    0x81, 0x6f, 0x0d, 0x60, 0xb0, 0x38, 0x41, 0x58, 0x0b, 0x49, 0x85, 0x1b, 0x44, 0xc4, 0x97, 0x00,
    0x76, 0xdb, 0x0c, 0xbd, 0x78, 0x6a, 0x10, 0x05, 0xe2, 0x08, 0x1c, 0xdc, 0x67, 0x91, 0x7f, 0xab,
    0xbf, 0x3a, 0x2f, 0xcd, 0x7b, 0xfe, 0x37, 0x51, 0x32, 0x71, 0xa8, 0x31, 0x04, 0x24, 0x3c, 0x59,
    0x11, 0xd1, 0x98, 0x63, 0x82, 0xa6, 0xef, 0xd6, 0x86, 0x36, 0xd7, 0xf4, 0x43, 0xe9, 0x17, 0x5f,
    0x6e, 0x2a, 0xc6, 0x18, 0x8b, 0xfb, 0x52, 0xa4, 0x02, 0x3b, 0xde, 0x27, 0xcc, 0x1e, 0x4e, 0x8e,
    0xd2, 0x65, 0xf3, 0xb8, 0x69, 0x20, 0xd0, 0xe6, 0x2d, 0xb1, 0x7a, 0xd9, 0xf0, 0x0e, 0x4b, 0x88,
    0x45, 0x06, 0xfa, 0xb5, 0x40, 0xc9, 0x62, 0x42, 0x7c, 0x09, 0xb2, 0xf1, 0xfc, 0xce, 0x79, 0xf8,
    0x5e, 0x07, 0x46, 0x9d, 0x73, 0x4a, 0x01, 0x6b, 0xba, 0x47, 0x16, 0x8d, 0xa1, 0x8c, 0x0a, 0x13,
    0x23, 0x77, 0x6d, 0xbb, 0x5c, 0xb9, 0xbe, 0xc5, 0x39, 0xca, 0x87, 0x66, 0x7e, 0x89, 0x9e, 0x57,
    0xd4, 0x9b, 0x03, 0x4d, 0xe7, 0xa9, 0xeb, 0xa5, 0xb6, 0x68, 0x80, 0x15, 0xa7, 0x64, 0xff, 0xe1,
    0x29, 0xa3, 0xaf, 0xf5, 0x26, 0xc2, 0x1f, 0xd3, 0xc8, 0x8a, 0x1a, 0x2e, 0xfd, 0x5b, 0xb3, 0xe5,
    0x33, 0x4f, 0x5a, 0x8f, 0xda, 0x55, 0x72, 0xdf, 0x54, 0x92, 0x83, 0xbc, 0x1d, 0xec, 0x34, 0xc0,
    0x84, 0xd5, 0xc3, 0x7d, 0x28, 0x4c, 0x90, 0xea, 0x95, 0x3d, 0x21, 0x9a, 0x2b, 0x2c, 0xed, 0x35,
])

KEY = b'SENTINEL'  # 8 bytes at 0x4021a0


def rol8(val, bits):
    """Rotate left an 8-bit value."""
    return ((val << bits) | (val >> (8 - bits))) & 0xff


def shuffle(buf):
    """
    Shuffle function at 0x4013b0.
    For idx 1..8:
      al = buf[idx-1]
      al = ROL(al, 3)
      al ^= counter (starts 0, increments by 0x1f)
      al ^= buf[idx & 7]
      al = SBOX[al]
      result[idx-1] = al
    """
    buf = bytearray(buf)
    result = bytearray(8)
    counter = 0
    for idx in range(1, 9):
        al = buf[idx - 1]
        al = rol8(al, 3)
        al ^= (counter & 0xff)
        al ^= buf[idx & 7]   # idx & 7: wraps around at 8
        al = SBOX[al]
        result[idx - 1] = al
        counter += 0x1f
    return bytes(result)


def recvn(sock, n):
    """Receive exactly n bytes."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def recv_frame(sock):
    """Receive a WHSP frame. Returns (msg_type, payload)."""
    header = recvn(sock, 8)
    magic = header[0:4]
    version = header[4]
    msg_type = header[5]
    payload_len = struct.unpack('>H', header[6:8])[0]

    assert magic == b'WHSP', f"Bad magic: {magic}"
    assert version == 1, f"Bad version: {version}"

    if payload_len > 0:
        payload = recvn(sock, payload_len)
        checksum = recvn(sock, 1)[0]
        expected = sum(payload) & 0xff
        assert checksum == expected, f"Checksum mismatch: got {checksum}, expected {expected}"
    else:
        checksum = recvn(sock, 1)[0]
        payload = b''

    print(f"  <- type=0x{msg_type:02x} len={payload_len} payload={payload[:80]}")
    return msg_type, payload


def send_frame(sock, msg_type, payload=b''):
    """Send a WHSP frame."""
    header = b'WHSP' + bytes([1, msg_type]) + struct.pack('>H', len(payload))
    checksum = sum(payload) & 0xff
    print(f"  -> type=0x{msg_type:02x} len={len(payload)} payload={payload[:80]}")
    sock.sendall(header + payload + bytes([checksum]))


def main():
    print(f"Connecting to {HOST}:{PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    print("Connected!")

    # Step 1: Receive banner (type 0x80)
    msg_type, banner = recv_frame(sock)
    print(f"Banner: {banner.decode('utf-8', errors='replace')}")
    assert msg_type == 0x80

    # Step 2: Send HELLO (type 0x01, no payload)
    send_frame(sock, 0x01, b'')

    # Step 3: Receive nonce/challenge (type 0x81, 8 bytes)
    msg_type, nonce = recv_frame(sock)
    assert msg_type == 0x81
    assert len(nonce) == 8
    print(f"Nonce: {nonce.hex()}")

    # Step 4: Compute challenge response
    # XOR nonce with KEY (SENTINEL), then shuffle twice
    xored = bytes(a ^ b for a, b in zip(nonce, KEY))
    response = shuffle(shuffle(xored))

    # Send response (type 0x02, 8 bytes)
    send_frame(sock, 0x02, response)

    # Step 5: Receive OK or DENY
    msg_type, resp = recv_frame(sock)
    resp_text = resp.decode('utf-8', errors='replace')
    print(f"Auth response: {resp_text}")

    if msg_type != 0x82:
        print("Authentication failed!")
        sock.close()
        return None

    # Step 6: Send REQUEST (type 0x03, first byte = 0x07)
    send_frame(sock, 0x03, bytes([0x07]))

    # Step 7: Receive encrypted token (type 0x83)
    msg_type, encrypted = recv_frame(sock)
    print(f"Encrypted token ({len(encrypted)} bytes): {encrypted.hex()}")

    # Step 8: Decrypt token
    # From the disassembly at 0x4017ef-0x40184d:
    # 1. keystream[i] = nonce[i] ^ KEY[i] for i in 0..7
    # 2. shuffle(keystream) twice
    # 3. For each byte i of the token:
    #    - if (i & 7) == 0: shuffle(keystream) once (including i=0!)
    #    - encrypted[i] = token[i] ^ keystream[i & 7]
    #
    # The critical difference: at i=0, r9=0 so it falls through to shuffle
    # BEFORE encrypting the first byte. So total: 2 initial + 1 per-block shuffles.

    keystream = bytearray(xored)  # nonce ^ KEY
    keystream = bytearray(shuffle(keystream))  # shuffle 1
    keystream = bytearray(shuffle(keystream))  # shuffle 2

    decrypted = bytearray()
    for i in range(len(encrypted)):
        if (i & 7) == 0:
            keystream = bytearray(shuffle(keystream))
        decrypted.append(encrypted[i] ^ keystream[i & 7])

    token = bytes(decrypted).decode('utf-8', errors='replace')
    print(f"\n{'='*60}")
    print(f"DECRYPTED TOKEN: {token}")
    print(f"{'='*60}")

    sock.close()
    return token


if __name__ == '__main__':
    token = main()
    if token:
        print(f"\nFlag: {token}")
