## 24 — Steel and feathers (Reverse Engineering)

1. Open `SteelAndFeathers.exe` in a .NET decompiler. `Program.Run()` contains a Base64 string that is gzipped.
2. Decode and decompress it. The payload is then deobfuscated per byte with `Ror8(byte[i], (i % 7) + 1) ^ ((23 + i * 41) & 0xff)`.
3. The recovered payload is a custom VM program. Trace its register/memory operations and output instruction.
4. `Program.Main` compares the user input with the VM output, so the output is the flag.

`TVX{Congratulations_You_Know_Some_ball}`
