## 5 — tracevx (DFIR)

1. Open `traceVX.ad1` in FTK Imager and export the NTFS volume. Review user profiles, browser history, PowerShell operational logs, and the Recycle Bin.
2. Identify the affected account `Ahmed` and host `WIN-TRACE-01`. The phishing page was reached through a shortcut or downloaded document; the browser record shows the landing time as `2026-09-17T14:31:51Z`.
3. Open `url_reputation.bin`. It is XOR-obfuscated with `0x98`. Repeating that XOR recovers the phishing host `login-microsoftonline.secure-verify.cc`.
4. In the PowerShell operational log, locate the encoded command and the staged `stage.cmdline`. The chain drops and runs `Navigator.exe`.
5. Carve `Navigator.exe` from the gzip member inside `disk.img` at offset `0x4d000`. Its SHA-256 is `411ff3850c2ed96028e4f39184fed07c3fdacf56936e03581ce479c6ed7ab8cd`.
6. Establish the remaining answers from the timeline: C2 `185.192.48.239:443`, exfiltration size `8388608` bytes (8 MiB), and the ten incident questions.
7. Connect to the challenge service and answer its ten questions. The final flag is:

`TVX{Ahmed@WIN-TRACE-01_TraceTelemetry-185.192.48.239_8MiB_411ff385}`
