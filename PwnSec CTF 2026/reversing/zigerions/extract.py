#!/usr/bin/env python3
"""Extract a PyInstaller CArchive (and its inner PYZ) without pyinstxtractor.

The bundle here is unusual: the MEI cookie sits at offset 6290383 of a 43MB file, with ~37MB
of data *after* it, so the usual "archive ends at EOF" assumption does not hold. The archive
is located from the cookie instead: overlayPos = cookiePos + COOKIE_SIZE - lengthofPackage.

Usage: extract.py <binary> <outdir>
"""
import marshal
import os
import struct
import sys
import zlib

MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
COOKIE = 88  # 8s + I + I + i + i + 64s


def main() -> int:
    path, out = sys.argv[1], sys.argv[2]
    data = open(path, "rb").read()

    cp = data.rfind(MAGIC)
    if cp < 0:
        print("no MEI cookie", file=sys.stderr)
        return 1
    magic, lenpkg, toc, toclen, pyver, pylib = struct.unpack("!8sIIii64s", data[cp:cp + COOKIE])
    overlay = cp + COOKIE - lenpkg
    print(f"cookie@{cp} pyver={pyver} overlay={overlay} lenPkg={lenpkg} toc={toc}/{toclen}")

    os.makedirs(out, exist_ok=True)
    pos = overlay + toc
    end = pos + toclen
    entries = []
    while pos < end:
        (elen,) = struct.unpack("!i", data[pos:pos + 4])
        fields = data[pos:pos + elen]
        epos, csize, usize, cflag, ctype = struct.unpack("!IIIBc", fields[4:18])
        name = fields[18:].split(b"\x00")[0].decode("utf-8", "replace")
        entries.append((epos, csize, usize, cflag, ctype.decode(), name))
        pos += elen

    print(f"{len(entries)} TOC entries")
    for epos, csize, usize, cflag, ctype, name in entries:
        blob = data[overlay + epos: overlay + epos + csize]
        if cflag:
            try:
                blob = zlib.decompress(blob)
            except Exception as e:
                print(f"  ! {name}: inflate failed {e}")
        safe = name.replace("\\", "/").lstrip("/") or "unnamed"
        dest = os.path.join(out, safe)
        os.makedirs(os.path.dirname(dest) or out, exist_ok=True)
        # PyInstaller strips the .pyc header from 's'/'m'/'M' entries
        if ctype in ("s", "m", "M"):
            dest += ".pyc"
            hdr = struct.pack("<I", 0x0A0D0DE7 if pyver >= 37 else 0x0A0D0D33)
            blob = hdr + b"\x00" * 12 + blob
        open(dest, "wb").write(blob)
        print(f"  [{ctype}] {name:48} {len(blob):>9} -> {dest}")

        if ctype == "z":
            unpack_pyz(blob, os.path.join(out, safe + "_extracted"), pyver)
    return 0


def unpack_pyz(blob: bytes, out: str, pyver: int) -> None:
    """Unpack an inner PYZ archive (magic 'PYZ\\0' + pyc magic + TOC offset)."""
    if blob[:4] != b"PYZ\x00":
        print("    (not a PYZ)")
        return
    pyc_magic = blob[4:8]
    (tocpos,) = struct.unpack("!i", blob[8:12])
    try:
        toc = marshal.loads(blob[tocpos:])
    except Exception as e:
        print(f"    PYZ toc unmarshal failed: {e}")
        return
    if isinstance(toc, list):
        toc = dict(toc)
    os.makedirs(out, exist_ok=True)
    print(f"    PYZ: {len(toc)} entries -> {out}")
    for name, (typ, off, length) in toc.items():
        raw = blob[off:off + length]
        try:
            raw = zlib.decompress(raw)
        except Exception:
            pass
        dest = os.path.join(out, name.replace(".", "/") + ".pyc")
        os.makedirs(os.path.dirname(dest) or out, exist_ok=True)
        open(dest, "wb").write(pyc_magic + b"\x00" * 12 + raw)


if __name__ == "__main__":
    sys.exit(main())
