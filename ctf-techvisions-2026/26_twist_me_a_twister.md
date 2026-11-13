## 26 — Twist me a twister (Reverse Engineering)

1. Open `TwistMeATwister.exe` in a .NET decompiler. The flag is built by `Program.Reveal()` from the FieldRVA data at `0x2130`.
2. For output index `i`, compute `loc2 = (i * 7 + 3) % 40`. Take `data[loc2]`, rotate it right by `(loc2 % 5) + 1`, then XOR with `(55 + loc2 * 11) & 0xff`.
3. The resulting 40 bytes are ASCII. `Main` compares the input against them.

`TVX{Fl4ggy_fl4g_fl4g_tw15ty_tw15t_tw15t}`
