import socket
import time
import re
import os
import sys

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def solve():
    s = socket.socket()
    host = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CHALLENGE_HOST")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("CHALLENGE_PORT", "7000"))
    if not host:
        raise SystemExit("usage: solve.py HOST [PORT]")
    s.connect((host, port))

    def recv_prompt():
        buf = b""
        start = time.time()
        while time.time() - start < 4.0:
            s.settimeout(0.5)
            try:
                chunk = s.recv(4096)
                if not chunk: break
                buf += chunk
                if b"Answer: " in buf or b"COMPFEST" in buf or b"flag" in buf:
                    time.sleep(0.1)
                    try:
                        s.settimeout(0.2)
                        while True:
                            m = s.recv(4096)
                            if not m: break
                            buf += m
                    except socket.timeout: pass
                    break
            except socket.timeout: pass
        text = buf.decode('utf-8', errors='ignore')
        return ANSI_ESCAPE.sub('', text)

    answers = [
        ("Q1", "192.168.100.10"),
        ("Q2", "5.1.26100.8521"),
        ("Q3", "de-ad-be-ef"),
        ("Q4", "2196231738"),
        ("Q5", "d0nt_ruN_th3_m4lw4r3_y4hh_82117caa"),
        ("Q6", "c61e123e24a6025bc1aac86391385070"),
        ("Q7", "bd7bf788d62bdec9c219316da4487314_y0u_g0t_tr4pp3d!"),
        ("Q8", "16031115"),
        ("Q9", "be69c8c00b73aadbb26ca44707ec1d489f891d2e848dd7e834b8f881bcdeb33d"),
        ("Q10", "00009600_046ecd9d"),
        ("Q11", "Johannes_Passing")
    ]

    for q_name, ans in answers:
        recv_prompt()
        s.sendall(ans.encode() + b"\n")

    final_resp = recv_prompt()
    print(final_resp)
    flag_match = re.search(r'COMPFEST18\{[^}]+\}', final_resp)
    if flag_match:
        print("FLAG:", flag_match.group(0))
    s.close()

if __name__ == '__main__':
    solve()
