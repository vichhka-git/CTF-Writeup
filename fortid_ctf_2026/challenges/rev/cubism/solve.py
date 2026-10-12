#!/usr/bin/env python3
import base64
import os
import re
import socket
import ssl
import sys
import zlib

PAINTING_B64 = "eJzVWUuygzAM23MN7bn/8V6HV4aA5V/iUOiiMxWu4ziW4oR1PX2wfS9YyWeREBgKbvt5sJxsvoP924oRqYcPykJbDp+WB1h+k6geL66ojHghlnw06LMgidBjMGxnoqDoYRuts1PtlER2RfdIELCdioKix8Oo3wgL2wF1v2r9VqFeleRQixcMZSz01cjSEq2qKyK7RJDi0G+YVYqqVa1VFPYfaJ591zigv9bKD/ECzrrFFTw6C6X6ArMo3DdTOfNYqCtXv07C9Dsf7avJ7Z83x9tGWqvgeVRjCwSKdoU7KkrWpMJjvU/1UCRsM9ws8kvrDGMK07DQ7eJfg7YbTGlVvx+9p7PhmUR/nYGiqgeVQ+RUJzy0tXOOlfG4iSzbZZoon3EyD29Eoa2FtBwebdxDBfrEcwCyvWeEWQ76xDyc0a2DGdxbXoky3TkS8SuNAkWpLdmHpG1/53g76imXe5oJnufTtgda2U9qHTSJTDlJpHrw56G1HenzlXaNsRtrsM5g9Gf0tkN2flFmleyFd2eyruOvQyvfGmXRPN+q7q7uv5/Mo51qZPICV8fherD2wtIzWS+KmWuxrtPf9mFMH/x7+2x25O1iX2Qe6r+NUlDZlxhdcfAUOuumYXdv1i/3cOHsSGTZ/qzREkWNhJZ0r2b6nmDOboroLPr69SG0RB+anzEPzj7E8lB0DmjZMqZGTPuMNVayc44hwkKxm1r3Gl5FyR7cOEtH1L7yhOJ2KwjnYUPVWic6+Qdmrogh"

def solve():
    payload = zlib.decompress(base64.b64decode(PAINTING_B64))

    host = os.environ.get("HOST")
    port = os.environ.get("PORT")

    if not host or not port:
        if len(sys.argv) >= 3:
            host = sys.argv[1]
            port = int(sys.argv[2])
        elif len(sys.argv) == 2:
            parts = sys.argv[1].split(":")
            host = parts[0]
            port = int(parts[1])
        else:
            sys.exit("usage: solve.py HOST PORT (or set HOST and PORT)")
    else:
        port = int(port)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=15) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            out = b""
            while b"row." not in out:
                chunk = ssock.recv(1024)
                if not chunk:
                    break
                out += chunk

            ssock.sendall(payload)

            resp = b""
            while True:
                try:
                    chunk = ssock.recv(1024)
                    if not chunk:
                        break
                    resp += chunk
                    if b"FortID{" in resp or b"Not quite" in resp:
                        break
                except Exception:
                    break

            text = resp.decode("utf-8", errors="replace")
            print(text)
            m = re.search(r"FortID\{[^\}]+\}", text)
            if m:
                print("FLAG:", m.group(0))

if __name__ == "__main__":
    solve()
