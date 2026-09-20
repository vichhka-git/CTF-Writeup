#!/usr/bin/env python3
"""P_CRYPTO / Disk 1331 -- recover the real clearance token.

Disk 1541 holds:
  XMIT.A (C1), XMIT.B (C2)  -- two 252-byte screen dumps, SAME keystream (two-time pad)
  SEALED                    -- 40-byte token, "XOR under tonights session key, same key"
  KEY.OLD                   -- 40-byte SUPERSEDED key (decoy)
  FRAME                     -- unencrypted screen template (decoy)

Decoys deliberately planted:
  FRAME            -> "FLAG: PAINTTHESCREEN"
  SEALED ^ KEY.OLD -> "STALEKEYDERIVED"
  JS comment       -> flag{k3y_r3us3_c0nf1rm3d}

Real path: crib-drag C1^C2 to recover the true keystream, then SEALED ^ K.
"""
import re, sys, os

H = open(os.path.join(os.path.dirname(__file__), '..', 'crypto_page.html')).read()
def arr(n): return [int(x) for x in re.search(r'var '+n+r'=\[([0-9,\s]+)\]', H).group(1).split(',')]
C1, C2, SEALED, KEYOLD = arr('C1'), arr('C2'), arr('SEALED'), arr('KEYOLD')

def enc(s):                      # ASCII -> C64 screen code (A-Z -> 1..26, rest -> ord)
    return [ord(c)-64 if 'A' <= c <= 'Z' else ord(c) for c in s]
def dec(v):                      # screen code -> ASCII
    return ''.join(chr(64+c) if 1 <= c <= 26 else chr(c) for c in v)

X = [a ^ b for a, b in zip(C1, C2)]

# --- step 1: crib drag C1^C2 ------------------------------------------------
# "DIRECTORATE" dragged over X hits offset 0 and yields "NIGHT DESK " opposite it;
# "INTERCEPT 0009" hits offset 11 opposite " OPS BULLETIN ".
P1 = "NIGHT DESK INTERCEPT 0009   OUTBOUND FRO"          # XMIT.A
P2 = dec([X[i] ^ enc(P1)[i] for i in range(len(P1))])     # XMIT.B, for free
assert P2.startswith("DIRECTORATE OPS BULLETIN TO ALL CHANNEL ")

# --- step 2: true keystream -------------------------------------------------
K = [C1[i] ^ enc(P1)[i] for i in range(len(P1))]
assert K[16:40] == KEYOLD[16:40], "KEY.OLD matches the real stream only past the widened offset"

# --- step 3: unseal ---------------------------------------------------------
token = dec([SEALED[i] ^ K[i] for i in range(40)]).rstrip()
print("XMIT.A :", P1)
print("XMIT.B :", P2)
print("decoy (SEALED ^ KEY.OLD):", dec([a ^ b for a, b in zip(SEALED, KEYOLD)]).rstrip())
print("SEALED plaintext        :", token)
print("FLAG:", "flag{%s}" % token.lower())
