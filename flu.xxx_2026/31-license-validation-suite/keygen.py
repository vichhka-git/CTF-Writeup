#!/usr/bin/env python3
"""Pure-static reimplementation of the LIcense Validation Suite keygen (challenge 31).

Faithful 32-bit emulation of the loop at vaddr 0x12dd..0x1303:
    edi  = r8d + esi           ; esi = 17*rdx
    ecx  = eax*31              ; shl ecx,5 ; sub ecx,eax
    eax  = edi + ecx
    al   = rol(al,3)           ; only the low byte
    al  ^= seed[rdx]           ; only the low byte
    eax ^= 0xffffffc7          ; full 32-bit xor
    buf[rdx] = al
r8d = 0x37 when ptrace(PTRACE_TRACEME) returned 0 (normal, untraced Linux)
      0x91 when it returned -1 (running under a tracer)
"""
SEED = bytes.fromhex("30becde91b0b32d2751fcc4119af4ce98c40abd26d3a9e016ad4")  # .rodata @0x2120

def gen(r8d, seed=SEED):
    eax = 0xFFFFFFA5
    out = bytearray()
    for rdx in range(26):
        esi = (0x11 * rdx) & 0xFFFFFFFF
        ecx = (eax * 31) & 0xFFFFFFFF
        eax = ((r8d + esi) + ecx) & 0xFFFFFFFF
        al = eax & 0xFF
        al = ((al << 3) & 0xFF) | (al >> 5)          # rol al, 3
        al ^= seed[rdx]
        eax = (eax & 0xFFFFFF00) | al                # low byte really changed
        eax ^= 0xFFFFFFC7
        out.append(eax & 0xFF)
    return bytes(out)

if __name__ == "__main__":
    print("untraced (r8d=0x37):", gen(0x37).decode("latin1"))
    print("traced   (r8d=0x91):", gen(0x91).hex())
