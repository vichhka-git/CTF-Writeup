## 25 — Summer is over (Reverse Engineering)

1. Open `SummerIsOver.exe` in a .NET decompiler. `Program.Main` compares input with `Program.Reveal()`.
2. `Program.Reveal()` uses the 26-byte `Program.blob` and the 8-byte `Program.schedule`. The routine decrypts the blob in blocks, reverses selected blocks, and applies the schedule.
3. Reconstruct the decryption order from the IL, then read the resulting 26 bytes as ASCII.

`TVX{4nd_S0_7h3_5un_Sh1n35}`
