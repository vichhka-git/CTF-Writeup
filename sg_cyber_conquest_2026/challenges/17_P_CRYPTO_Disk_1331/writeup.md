# P_CRYPTO — Disk 1331 (250 pts)

## Artifacts on the 1541 disk (all inline in `/crypto/` page JS)
| File | Bytes | Role |
|---|---|---|
| `XMIT.A` (C1) | 252 | intercept 1 |
| `XMIT.B` (C2) | 252 | intercept 2, **same keystream** |
| `SEALED` | 40 | the clearance token, XOR'd under tonight's session key |
| `KEY.OLD` | 40 | **superseded** session key SK-0009-4ADF (decoy) |
| `FRAME` | 280 | plain screen template (decoy) |

## Three planted decoys
1. JS comment: `flag{k3y_r3us3_c0nf1rm3d}` — "left here so nobody repeats the work… has not been re-checked".
2. `FRAME` decodes to a screen reading `FLAG: PAINTTHESCREEN`.
3. `SEALED ^ KEY.OLD` = `STALEKEYDERIVED` — the stale key gives a stale answer.

The description says *"Recover the **real** clearance"*: all three are traps.

## Real path — two-time pad
`C1 ^ C2` cancels the keystream. Crib-dragging over `C1^C2`:
- `DIRECTORATE` at offset 0 ⇄ `NIGHT DESK ` — both sides English, mutually confirming.
- `INTERCEPT 0009` at offset 11 ⇄ ` OPS BULLETIN `.

```
XMIT.A : NIGHT DESK INTERCEPT 0009   OUTBOUND FRO...
XMIT.B : DIRECTORATE OPS BULLETIN TO ALL CHANNEL ...
```

True keystream `K = C1 ^ P1`. Cross-check: `K[16:40] == KEY.OLD[16:40]` exactly, but
`K[0:16] != KEY.OLD[0:16]` — this is the "offsets shifted when the dump got widened"
comment. The old key is only right past the shifted boundary, which is why the stale
answer looks plausible for 15 characters and is wrong.

Alignment proof: `SEALED[16:40] ^ K[16:40]` is 24 × screen-code `32` (space padding),
so `SEALED` really is enciphered at stream offset 0.

## Unseal
```
SEALED ^ K = "P41NT_7FD277420C" + 24 spaces
```
C64 screen codes (A–Z → 1..26, everything else raw ASCII). Lowercased it matches this
event's flag shape `word_<10 hex>`.

## Flag
`flag{p41nt_7fd277420c}`

Reproduce: `python3 solve.py`
