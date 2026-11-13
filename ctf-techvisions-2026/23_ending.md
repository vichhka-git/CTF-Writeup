## 23 — Ending (Reverse Engineering)

1. Open `Ending.exe` in a .NET decompiler. `Program.Unpack` Base64-decodes and gunzips a UTF-16LE string beginning `H4sI...`.
2. The unpacked payload is XOR/ROR-obfuscated. For each byte index `i`, the inverse is `Ror8(data[i], (i % 5) + 1) ^ ((199 + i * 91) & 0xff)`.
3. The result is a small bytecode program interpreted by a custom VM. The instruction set includes memory/register loads, XOR/ADD/SUB, rotations, conditional jumps, and a one-byte output instruction.
4. Emulate the bytecode by hand or with a table of registers and memory. The output bytes spell the flag.

`TVX{S0me_1nt2r2st1ng_t2xt_h2r2}`
