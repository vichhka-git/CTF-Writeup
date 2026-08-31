# IT'S ME, BURHAN! — Writeup (Reverse Engineering, 484 pts)

## TL;DR
Burhan's admin password is a deterministic function of the wanderer's own public
guild state. Reverse the obfuscated Java `burhanquest.jar`, replay the frieren
account's quest chain to gather the 9 "guild blocks", invert the transform
pipeline with Z3 to recover the 16-char base32 admin password, log in as burhan,
open the sealed archive, and Z3-invert the same pipeline byte-wise to decrypt the
flag.

## The jar
`burhanquest.jar` is a control-flow-obfuscated Java terminal app. The main class
is string-encrypted (`Main.a(String)` XORs each char with 0xBB24; other strings
via `Main.b`). Decompiled + de-obfuscated source is in
The de-obfuscated Java notes are not included; the PRNG/transform engine (`p`)
and permutation helper (`L`) are re-implemented in `solve.py`.

## Password derivation ("lives in the guild itself")
1. Login `frieren`/`frieren`; menu option 1 "Data Diri" exposes
   `Level Pengembara` (h) and `Koin Didapatkan` (g).
2. Quest chain: `o = LehmerSelect(sha256(i32(h)||i32(g)) mod 4896, n=18, k=3)`
   picks the 3 quests to run (Q(o0+1) -> Q(o1+1) -> Q(o2+1)).
3. Run each quest (option 5). Each battle prints a `sigil-pertempuran`; option 7
   (Papan Pengumuman) prints a `sigil-arsip`, option 6 (Ekspor) a `sigil-ekspor`.
   These plus h, g, and the summed monster coins (s = g + coins) form 9 blocks.
4. `t = sha256(concat(blocks)) mod 17643225600`; `u = LehmerSelect(t,18,9)` (the
   9 transform ops); `v = sha256(i32(g)||i32(h)) mod 362880`, `w = LehmerSelect(v,9,9)`
   (block permutation); `x = t mod 32` (base32 rotation).
5. Chain hash: `acc = sha256(op[u0](blocks[w0]))`, then
   `acc = sha256(acc || op[ui](blocks[wi]))`. Take 16 5-bit symbols from `acc` = y.
6. Solve for the 16 pre-image symbols with Z3 over the same 18-op pipeline on
   5-bit lanes; map via base32 alphabet rotated by x -> the admin password.

## Flag
Login `burhan`/`<password>`; admin option 13 "Lihat Arsip Tersegel" prints the
sealed ciphertext = the flag pushed forward through pipeline `u` (byte-wise).
Z3-invert byte-wise to recover the plaintext flag.

## flag_mode = random
Each container instance is seeded with a fresh random flag (constant prefix
`COMPFEST18{bUR_BuR_BUr_buRh4n_h4Un7s_m3_t!L_t0D4y_`, random 16-char suffix), so
the solver must be run against your own live instance.

## Live run

The solver was verified against a live instance. The admin password and
transcript are intentionally not published because each instance has fresh
state and a random flag.

## Run
```
CTFD_TOKEN=... python3 solve.py <HOST> <PORT>
```
