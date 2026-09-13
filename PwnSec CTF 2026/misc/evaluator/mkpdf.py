#!/usr/bin/env python3
"""Minimal hand-rolled PDF writer (no reportlab/fpdf on this box).

Emits a single-page PDF whose text is extractable by the usual server-side extractors
(pdftotext / pypdf / pdfplumber) because it uses plain Tj/TJ text showing operators with a
standard Helvetica base font and no compression.

Usage:
  mkpdf.py out.pdf "line one" "line two" ...
  mkpdf.py out.pdf --file lines.txt
"""
import sys


def esc(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def build(lines, font_size=10, leading=12, width=612, height=792, margin=54, hidden=()):
    """`lines` render normally; `hidden` lines go in with text render mode 3 (invisible),
    so they land in the PDF text layer but not in the rasterised page an OCR pass sees."""
    ops = ["BT", f"/F1 {font_size} Tf", f"{leading} TL", f"1 0 0 1 {margin} {height - margin} Tm"]
    for ln in lines:
        ops.append(f"({esc(ln)}) Tj")
        ops.append("T*")
    if hidden:
        ops.append("3 Tr")                      # invisible rendering mode
        ops.append(f"1 0 0 1 {margin} {height - margin} Tm")
        for ln in hidden:
            ops.append(f"({esc(ln)}) Tj")
            ops.append("T*")
        ops.append("0 Tr")
    ops.append("ET")
    content = "\n".join(ops).encode("latin-1", "replace")

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] "
         f"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>").encode(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream",
    ]

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n"
            "%%EOF\n").encode()
    return bytes(out)


if __name__ == "__main__":
    out = sys.argv[1]
    if len(sys.argv) > 3 and sys.argv[2] == "--file":
        lines = open(sys.argv[3]).read().splitlines()
    else:
        lines = sys.argv[2:]
    open(out, "wb").write(build(lines))
    print(f"wrote {out} ({len(lines)} lines)")
