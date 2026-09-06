#!/usr/bin/env python3
"""
free-agentic-tool solver
TFC CTF 2026 / Flagyard
"""

import pathlib
import subprocess
from Crypto.Cipher import AES

HERE = pathlib.Path(__file__).resolve().parent

def main():
    # 1. AES-GCM session key derived from ECDH shared secret + session_id hash
    # Client PrivKey derived from sha256(b"lightlight_DESKTOP-DD6SS6U")
    # Shared secret = X25519(client_priv, server_pub)
    # Key = sha256(sha256(transformed_session_id) + sha256(shared_secret))
    session_key = bytes.fromhex("7c29d2dc03567d188b844a11d08d5c82707bb052ea012e0729658948fc832b93")

    def decrypt_frame(fnum):
        pcap_path = str(HERE / "dist" / "traffic.pcapng")
        cmd = [
            "tshark", "-r", pcap_path,
            "-Y", f"frame.number == {fnum}",
            "-T", "fields",
            "-e", "http2.data.data"
        ]
        raw_hex = subprocess.check_output(cmd).decode().strip()
        data = bytes.fromhex(raw_hex.replace(":", ""))
        msg_len = int.from_bytes(data[1:5], "big")
        return data[5:5+msg_len]

    def parse_proto(msg):
        pos = 0
        fields = {}
        while pos < len(msg):
            tag = msg[pos]
            fn = tag >> 3
            wt = tag & 7
            pos += 1
            if wt == 0:
                val = 0
                shift = 0
                while pos < len(msg):
                    b = msg[pos]
                    pos += 1
                    val |= (b & 0x7f) << shift
                    shift += 7
                    if not (b & 0x80): break
                fields[fn] = val
            elif wt == 2:
                l = 0
                shift = 0
                while pos < len(msg):
                    b = msg[pos]
                    pos += 1
                    l |= (b & 0x7f) << shift
                    shift += 7
                    if not (b & 0x80): break
                val = msg[pos:pos+l]
                pos += l
                fields[fn] = val
            else:
                break
        return fields

    # Frame 1645: Server command writing key.txt
    msg1645 = decrypt_frame(1645)
    f1645 = parse_proto(msg1645)
    nonce1645 = f1645[1]
    ct1645 = f1645[2]
    c1645 = AES.new(session_key, AES.MODE_GCM, nonce=nonce1645)
    pt1645 = c1645.decrypt_and_verify(ct1645[:-16], ct1645[-16:])
    payload1645 = parse_proto(pt1645)
    key_text = payload1645[5].decode()
    print(f"[*] Recovered OpenSSL key: {key_text}")

    # Frame 2195: Client upload of flag.txt.enc
    msg2195 = decrypt_frame(2195)
    f2195 = parse_proto(msg2195)
    nonce2195 = f2195[3]
    ct2195 = f2195[4]
    c2195 = AES.new(session_key, AES.MODE_GCM, nonce=nonce2195)
    pt2195 = c2195.decrypt_and_verify(ct2195[:-16], ct2195[-16:])
    payload2195 = parse_proto(pt2195)
    enc_file_data = payload2195[4]

    key_file = HERE / "key.txt"
    enc_file = HERE / "flag.txt.enc"
    with open(key_file, "w") as f:
        f.write(key_text)
    with open(enc_file, "wb") as f:
        f.write(enc_file_data)

    cmd = [
        "openssl", "enc", "-d", "-aes-256-cbc",
        "-salt", "-pbkdf2", "-iter", "200000",
        "-in", str(enc_file),
        "-pass", f"file:{key_file}"
    ]
    flag = subprocess.check_output(cmd).decode().strip()
    print(f"[+] Flag: {flag}")
    return flag

if __name__ == "__main__":
    main()
