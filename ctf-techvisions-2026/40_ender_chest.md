## 40 — ender chest (Crypto)

1. Read `chall.py` and `output.txt`. The custom curve parameters are small enough that the group order is smooth.
2. Factor the curve order. It is `11 · 367 · 13399 · 58453 · 484079 · 40128631 · 76927309`.
3. Solve the discrete logarithm `d` with Pohlig-Hellman on each prime-power subgroup, then combine with CRT. The result is `d = 2327569722739447708246377569803395`.
4. Verify `d · G == Q`.
5. The `ender_chest` ciphertext key is `sha256(str(d))`. Decrypt it with AES-CBC and the supplied IV.
6. `shulker_box` is keyed by `sha256(str(Q[0]))`; that is the trap and does not decrypt to the flag.

`TVX{D1dn5_F4lL_4_7h3_7r4p_7h15_t1me}`
