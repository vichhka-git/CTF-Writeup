#!/usr/bin/env python3
"""Serve the handout server.py on a TCP port (stand-in for the challenge's wrapper).

    KEY=00112233445566778899aabbccddeeff FLAG='flag{LOCAL_ORACLE_OK}' \
        python3 serve.py server.py 9710

Only needed for local testing; the real instance is reached over TLS.
"""
import os
import socket
import subprocess
import sys
import threading

srv, port = sys.argv[1], int(sys.argv[2])
PY = os.environ.get("PYTHON", sys.executable)   # server.py needs Python >= 3.10 (match)

def handle(conn):
    p = subprocess.Popen([PY, "-u", srv], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def up():
        try:
            while True:
                d = conn.recv(65536)
                if not d:
                    break
                p.stdin.write(d)
                p.stdin.flush()
        except Exception:
            pass
        finally:
            try:
                p.stdin.close()
            except Exception:
                pass

    def down():
        try:
            while True:
                d = p.stdout.read(1)
                if not d:
                    break
                conn.sendall(d)
        except Exception:
            pass
        finally:
            conn.close()

    threading.Thread(target=up, daemon=True).start()
    down()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
s.listen(8)
while True:
    c, _ = s.accept()
    threading.Thread(target=handle, args=(c,), daemon=True).start()
