# TESSERA

Forensics, 62 points, 239 solves. A 3 GB Windows evidence tree holds three flag
fragments: an ETW trace, a machine-scope DPAPI vault, and an NTFS reparse point. Each
fragment is prefixed with a decoy ordinal marker that is not part of the flag.

## What you are given

`tessera.zip` expands to a directory tree rooted at `extracted/evidence`, about 3.0 GB.
It contains `$MFT`, the registry hives `SYSTEM`, `SECURITY`, `SAM` and `SOFTWARE`, three
user `NTUSER.DAT` files, and the event logs under `Windows/System32/winevt/Logs`. There
is no service and no login material. The flag format is `hiCTF{part1part2part3}`.

The description is deliberately floral. Read it as an ALPC conversation (the local
interstice, the unmapped portico), a service running in session 0 (the isolated,
sightless sanctum), and a reparse point that redirects something (the lingering phantom).

## Reproduction

1. Start with the ETW trace, `Windows/System32/LogFiles/WMI/AuditDiagTrace.etl`, which
   is 16,384 bytes. One event comes from the provider
   `Microsoft-Windows-Diagnostics-LpcEndpoint` (`{e13b77a8-14b6-4efc-81e0-4494488a0186}`)
   and carries a UTF-16 string of the form `PORT=<port name>;HEX=<hex payload>`.

   ```python
   d = open('AuditDiagTrace.etl','rb').read()
   i = d.find(b'P\x00O\x00R\x00T\x00=\x00')
   out = bytearray()
   while d[i+1] == 0 and 32 <= d[i] < 127:
       out.append(d[i]); i += 2
   port, hx = out.decode().split(';HEX=')
   print(port, bytes(b ^ 0x5a for b in bytes.fromhex(hx)))
   ```

   The port is `\RPC Control\AepLocalEndpoint_Q8`. The hex decodes under XOR `0x5a` to
   `1ist-----hiCTF{alpc_p0rt_c0lloquy_||TargetService:DiagTrackSvcAux`. Fragment 1 is
   `alpc_p0rt_c0lloquy_`; the `1ist-----` prefix is the stage marker, and the string
   after `||` names the service that leads to stage 2.

2. Look at that service's registry parameters. Path:
   `HKLM\SYSTEM\CurrentControlSet\Services\DiagTrackSvcAux\Parameters`.

   ```
   ServiceVault = C:\Windows\System32\config\systemprofile\AppData\Local\
                  Microsoft\Windows\Caches\cpinforev.dat
   EntropyToken = base64, decodes to a 16-character ASCII entropy string
   ```

   The vault file is 662 bytes and begins with the DPAPI blob version `01 00 00 00`.

3. Parse the blob header to learn what you are dealing with. It is a machine-scope
   DPAPI blob: provider `df9d8cd0-1501-11d1-8c7a-00c04fc297eb`, master key GUID
   `efa8d061-7897-448f-a17a-89173346d7d8`, flags `0x4` (system scope), no description,
   and a crypto algorithm field of `0x6610` (AES-256) with SHA-512 for the HMAC.

   ```
   0x00 01 00 00 00                version
   0x04 provider GUID (16 bytes)
   0x14 01 00 00 00                master key version
   0x18 master key GUID (16 bytes)
   0x28 04 00 00 00                flags
   ```

4. Derive the master key, then unprotect the blob. The material is split across the
   two hives you were given: the boot key comes from `SYSTEM`, and the `DPAPI_SYSTEM`
   LSA secret in `SECURITY` yields the machine key. With impacket's `dpapi.py`, the
   master-key step takes the master key file
   `Windows/System32/Microsoft/Protect/S-1-5-18/efa8d061-7897-448f-a17a-89173346d7d8`
   plus both hives, and the unprotect step takes the blob, the recovered master key and
   the entropy string from step 2.

   ```
   dpapi.py masterkey -file <protect-file> -system SYSTEM -security SECURITY
   dpapi.py unprotect  -file cpinforev.dat -key <masterkey> -entropy <entropy>
   ```

   The plaintext is a JSON document with these fields:

   ```json
   {"FlagPart2": "--s32nd--s35s10n_z3r0_syst3npr0f1l3_",
    "NextKey": "<32-character ASCII AES key>",
    "TargetLocator": {"NodeHex": "45544C4C6F63616C53746F7265",
                      "Subsystem": "%ALLUSERSPROFILE%\\Microsoft\\Diagnosis",
                      "Schema": "NTFS_REPARSE_STREAM_LOCATOR"},
    "IV_HEX": "101112131415161718191a1b1c1d1e1f"}
   ```

   Fragment 2 is `s35s10n_z3r0_syst3npr0f1l3_`. The `--s32nd--` prefix is a marker, not
   content. The vault also hands you the key and IV for stage 3, so the flag fragments
   never have to be assembled out of order by guesswork.

5. Resolve the locator. `NodeHex` decodes to the ASCII name `ETLLocalStore`, and the
   subsystem path says to look under `ProgramData/Microsoft/Diagnosis`. Search `$MFT`
   for a 1024-byte `FILE` record whose name attribute matches `ETLLocalStore` in UTF-16;
   the recorded hit is record 101281.

6. Read the reparse attribute from that record. Walk the attribute chain and take type
   `0xC0`. In record 101281 the attribute is 56 bytes with tag `0xA0000028` (a custom,
   non-Microsoft tag) and a 48-byte payload after an 8-byte header.

7. Decrypt with AES-256-CBC using `NextKey` and `IV_HEX`. The stored ciphertext has two
   corrupted bytes in the first block: positions 14 and 15 are `02 00` where the original
   values were `51 5e`. Only block 0 and its neighbour are affected, so the rest of the
   plaintext decrypts normally. The practical repair is a 16-bit search over those two
   bytes, accepting the candidate whose padding is valid and whose plaintext is all
   printable ASCII.

   ```
   f4efda2cbfa8208e5b387ec8d2870200 ... (stored)
   f4efda2cbfa8208e5b387ec8d2515e00 ... (repaired)
   plaintext: iiiiiiiiiii-3hird---r3p4r53_buff3r_vort3x}   pad 0x06
   ```

   Fragment 3 is `r3p4r53_buff3r_vort3x`; it carries the closing brace, which confirms
   that this is the last stage.

8. Strip the three markers (`1ist-----`, `--s32nd--`, `iiiiiiiiiii-3hird---`) and join
   the fragments in stage order. Each fragment ends in an underscore except the last, so
   the concatenation needs no separators.

## Why it works

Each stage hides a fragment in a place that has legitimate reasons to hold binary data:
an ETW event field, a DPAPI-protected configuration blob, and a reparse buffer on a
directory. None of them is a file whose bytes you can grep. The vault also carries the
key and IV for the next stage, so the chain closes once you unwrap DPAPI with the two
hives you were given, and the ordinal markers give the order without being the answer.

## Flag

```
hiCTF{alpc_p0rt_c0lloquy_s35s10n_z3r0_syst3npr0f1l3_r3p4r53_buff3r_vort3x}
```
