#!/usr/bin/env python3
import struct

MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9

# Five 64-bit ciphertext blocks compared by the binary after the payload
# passes the e0f{...} shape checks.
CIPHERTEXT = [
    (0x1B091B13, 0xDE7CB151),
    (0x12EF2C85, 0xC51BEF8F),
    (0xCDA3E579, 0xBA8825C9),
    (0xAFB73975, 0xCD920DFA),
    (0xF9C7B73E, 0x90292538),
]

# Dynamic trace at the XTEA key reads showed a different four-word key for
# each 8-byte payload block.
KEYS = [
    [0xDD49804D, 0x34977E4D, 0x8FE8249E, 0xE854AAE6],
    [0xF0BAC219, 0x5708189B, 0x4FEC05BF, 0xFED2AFE5],
    [0x04937FE7, 0x8695EFE2, 0x32B6F39B, 0x2377D59A],
    [0xBD51750E, 0x45F94F25, 0xF4E1EAA1, 0x8239EE94],
    [0x96994594, 0xC69BC73E, 0x552C1D11, 0xC8814CB4],
]

# For each block, the plaintext words are XORed with this chaining state before
# XTEA. These states were recovered by probing the binary with known prefixes.
CHAIN = [
    (0xF2D99444, 0x5A7A920F),
    (0x6785BF62, 0x4AF29EC0),
    (0x30DD6693, 0x8C592BC9),
    (0x0A740AC2, 0x477F5D33),
    (0xC2CAAC15, 0x7F3E0055),
]


def xtea_decrypt(v0, v1, key):
    total = (DELTA * 32) & MASK
    for _ in range(32):
        v1 = (
            v1
            - (
                (((v0 << 4) & MASK) ^ (v0 >> 5)) + v0
                ^ ((total + key[(total >> 11) & 3]) & MASK)
            )
        ) & MASK
        total = (total - DELTA) & MASK
        v0 = (
            v0
            - (
                (((v1 << 4) & MASK) ^ (v1 >> 5)) + v1
                ^ ((total + key[total & 3]) & MASK)
            )
        ) & MASK
    return v0, v1


payload = b""
for ct, key, chain in zip(CIPHERTEXT, KEYS, CHAIN):
    pre0, pre1 = xtea_decrypt(*ct, key)
    p0 = pre0 ^ chain[0]
    p1 = pre1 ^ chain[1]
    payload += struct.pack("<II", p0, p1)

print("e0f{" + payload.decode() + "}")
