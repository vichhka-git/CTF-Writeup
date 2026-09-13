#!/usr/bin/env python3
"""Zigerions / Pickle_Riiiiick -- peel four layers to an AES-128 blob.

Layer 1  43MB Linux static ELF = a **Windows** PyInstaller onefile bundle (python310.dll,
         "Failed to pre-initialize embedded python interpreter") whose MEI cookie sits at
         offset 6290383 with ~37MB of data *after* it, so the usual
         "archive ends at EOF" assumption fails. Locate it from the cookie instead:
             overlayPos = cookiePos + 88 - lengthofPackage
Layer 2  The bundled script `stub.pyc` (Python 3.10) carries
             XOR_KEY = (165, 60, 255, 0, 85, 170)
             MARKER  = b'<<<PAYLOAD_START>>>'
         and main() reads its own file, splits on MARKER, takes a 4-byte little-endian
         length, and calls unscramble() -- which XORs with the repeating key **and then
         reverses the whole buffer** (the `-1` in BUILD_SLICE). That yields a 5.59MB PE32+.
Layer 3  The PE is MinGW + VMProtect 3.x (all original sections empty, 5.5MB .vmp1), GUI
         subsystem. No need to unpack it: run it under wine and it drops
         %TEMP%\\AURA.gb (a Game Boy ROM -- "a maze with no wrong answers") and
         %TEMP%\\svchost.
Layer 4  `svchost` is a 5.6KB *non-stripped* Linux ELF built from chal.c with **no .text at
         all** -- only .rodata/.data holding five objects:
             __3 (16B)  = b'M68K_AES_FLAGKEY'   <- AES-128 key
             __2 (11B)  = 00 01 02 04 08 ... 36 <- AES Rcon
             __1 (256B) = AES inverse S-box
             __0 (256B) = AES forward S-box
             __4 (48B)  = ciphertext (3 blocks)
         AES-128-ECB decrypt -> the flag, PKCS#7 padded with 9 bytes.

This script reproduces layers 1, 2 and 4 offline; layer 3 needs one `wine` run.
"""
import struct
import sys

from Crypto.Cipher import AES

MEI = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE = 88
MARKER = b"<<<PAYLOAD_START>>>"
XOR_KEY = bytes((165, 60, 255, 0, 85, 170))


def unscramble(data: bytes) -> bytes:
    """stub.py's unscramble(): repeating-key XOR, then reverse."""
    return bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(data))[::-1]


def carve_pe(path: str) -> bytes:
    blob = open(path, "rb").read()
    cp = blob.rfind(MEI)
    _, lenpkg, toc, toclen, pyver, _ = struct.unpack("!8sIIii64s", blob[cp:cp + COOKIE])
    print(f"[1] MEI cookie @{cp}  python{pyver}  archive @{cp + COOKIE - lenpkg}")

    rest = blob.split(MARKER, 1)[1]
    n = struct.unpack("<I", rest[:4])[0]
    pe = unscramble(rest[4:4 + n])
    print(f"[2] payload {n} bytes -> {pe[:2]!r} (PE32+)" if pe[:2] == b"MZ" else "[2] not a PE!")
    return pe


def read_objs(elf_path: str) -> dict:
    d = open(elf_path, "rb").read()

    def rd(addr, size):                      # .rodata @0x401000->0x1000, .data @0x402220->0x1220
        off = 0x1220 + (addr - 0x402220) if addr >= 0x402220 else 0x1000 + (addr - 0x401000)
        return d[off:off + size]

    return {
        "key": rd(0x401000, 16),
        "rcon": rd(0x401010, 11),
        "inv_sbox": rd(0x401020, 256),
        "sbox": rd(0x401120, 256),
        "ct": rd(0x402220, 48),
    }


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1].endswith(("Pickle_Riiiiick", ".bin")):
        pe = carve_pe(sys.argv[1])
        open("payload.exe", "wb").write(pe)
        print("[3] wrote payload.exe -- run it once under wine, then pass %TEMP%/svchost here")
        return 0

    o = read_objs(sys.argv[1])
    print(f"[4] key={o['key']!r}")
    assert o["sbox"][:4].hex() == "637c777b", "forward S-box mismatch"
    assert o["inv_sbox"][:4].hex() == "52096ad5", "inverse S-box mismatch"
    pt = AES.new(o["key"], AES.MODE_ECB).decrypt(o["ct"])
    pad = pt[-1]
    flag = pt[:-pad] if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad else pt
    print("FLAG:", flag.decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
