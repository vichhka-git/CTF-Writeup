## 28 — Ghost in the Envars (DFIR)

1. Extract `memory.raw` from the supplied archive and load it with Volatility 3.
2. Enumerate processes and note the dead `svchost.exe` with PID 2468, PPID 6708, created and exited on 2026-11-11 at 19:58:26.
3. Search the process’s PEB environment block in physical memory. The `SESSION_AUTH_TOKEN` value is the flag, stored as a Base64 string.
4. The same Base64 value appears at physical offsets `0x17b7d012`, `0x1ee7b38a`, and `0x1ee7c39e`.
5. Do not use the PowerShell `-EncodedCommand` value. That command contains the decoy `TVX{dont_use_ai_for_solving}` and explicitly labels the environment-block value as the real flag.

`TVX{m3m0ry_4rt_n0t_pr0mpt_2026}`
