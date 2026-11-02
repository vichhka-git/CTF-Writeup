# The Miner That Mined The Victim

Forensics, 97 points, 72 solves (author Hidden Investigations). The handout is a
triage-style collection of a Windows C: drive plus a live service that asks fourteen
questions about the incident, one at a time, and prints the flag only if you answer all
of them in one session. The answers come from the artifacts. The flag does not.

## What you are given

`the-miner-that-mined-the-victim.zip` expands to a directory tree of roughly the size of
a real triage export: `$MFT`, `$LogFile`, the registry hives, the event logs, the Edge
profile, the prefetch directory, the recycle bin and the `C:\Sysmon` archive directory.

The live instance is a TLS question server. The portal supplies its host and port; treat
them as `<challenge-host>` and `<port>` and connect with TLS. Three wrong answers in a
row wipe your progress and close the connection, so prepare every answer offline before
you open a session. Treat the collection as live malware and do not run `miner.exe`.

## Reproduction

1. Inventory the collection before touching anything. The five sources that answer all
   fourteen questions are the Sysmon event log, the `$MFT`, the `SYSTEM` and `SOFTWARE`
   hives, the Edge `History` SQLite database, and the prefetch file for the payload.

2. Convert the Sysmon log carefully. Stock `python-evtx` is not enough: it returned only
   58 Sysmon records because the file header's chunk count is stale. Walk every 64 KB
   `ElfChnk` block instead and you get 7,460 records.

3. Build the timeline in UTC. The recorded sequence is: Sysmon installed and started at
   14:15:32, a `winget` install of the .NET 9 desktop runtime at 14:15:46, Edge searches
   from 14:20:26 to 14:21:08 (including the misspelled query `crcaked crypto mining tools
   2026`), a lure page titled "CoinBoost Pro v3.2, Free Mining Optimizer" visited at
   14:25:21, the download at 14:25:27, extraction between 14:25:43 and 14:25:50, the run
   at 14:26:55, encryption from 14:26:59 to 14:27:01, and deletion of the folder at 14:27:47.

4. Question 1, the OS version recorded during execution. Read the ransomware debug log
   at `Users\<victim>\AppData\Local\Temp\ransomware_debug.log`, not the registry. The log
   line is `OS Version: Microsoft Windows NT 10.0.26200.0`. The registry
   `CurrentVersion` block reports build 26200 with UBR 8037, which is a different string
   and is not what the question wants.

5. Question 2, the effective UTC offset and the value that proves it. Read
   `SYSTEM\ControlSet001\Control\TimeZoneInformation`: `TimeZoneKeyName` is `Pacific
   Standard Time`, `Bias` is 480 and `ActiveTimeBias` is 420. Daylight saving was in
   effect, so the effective offset is UTC-7 and the answer is `UTC-7, 420`. This also
   tells you that the 07:26 timestamps in the debug log are local time.

6. Questions 3 and 4, the delivery URLs. The Edge `History` database has the download
   chain, and Sysmon event 15 captured the `Zone.Identifier` alternate data stream written
   by the browser. That stream is the most convenient copy, because it holds both the
   referrer and the host URL as plain text:

   ```
   ReferrerUrl=https://<file-host>/d/<share-id>
   HostUrl=https://<file-host>/decrypt/download?downloadId=<GUID>
   ```

   Question 3 wants the share URL including the `#fragment`, and question 4 wants the GUID
   from the redirect. The exact strings are in the collection and are deliberately not
   reproduced here; the format above is enough to locate them.

7. Question 5, when the download finished. The Edge downloads table gives the end time,
   and Sysmon event 15 for `miner.zip` lands at 14:25:35.959, so the accepted answer is
   `2026-05-13 14:25:36 UTC`.

8. Question 6, whether the program ran, when, and how many times. The payload was deleted,
   but `Windows\Prefetch\MINER.EXE-9A2B223D.pf` survives. In a prefetch file the last-run
   FILETIME array starts at `0x80` and the run count is a `u32` at `0xC8`. That gives
   `2026-05-13 14:26:55 UTC, 1`, and the count is corroborated by a single process-exit
   event and a single debug-log run.

9. Question 7, the .NET crypto assembly loaded before the first encrypted file. Use
   Sysmon event 7 (image load) for the payload PID. The accepted answer is
   `C:\Program Files\dotnet\shared\Microsoft.NETCore.App\9.0.16\System.Security.Cryptography.dll,
   2026-05-13 14:26:58 UTC`. Note the ordering: the first `.vibed` file is created at
   14:26:59.1, so the crypto load has to precede it.

10. Question 8, the registry value the payload changed. Sysmon event 13 records a
    `SetValue` on `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware`
    with data `DWORD (0x00000001)`. The debug log confirms it from the attacker side:
    `ERROR in DisableRealtimeProtection` followed by `SUCCESS: Set DisableAntiSpyware=1`.

11. Question 9, the current ATT&CK technique for that change. The accepted answer is
    `T1685`. The instance rejected both `T1562.001` and `T1112`, so use the current
    numbering for Impair Defenses rather than the older sub-technique.

12. Question 10, "recover the important text from triage artifacts". This is the step
    that needs the MFT. Two things line up. First, the document names in `Documents` are
    ROT13, so `vzcbegnag.txt` is `important.txt` and `vg'f fbzrjurer.txt` is
    `it's somewhere.txt`. Second, the Sysmon rule set has archiving enabled, so every
    deleted original was copied to `C:\Sysmon\<MD5><SHA256><padding>.txt`. For the
    `important.txt` file that archive copy is small enough to be stored resident inside
    the MFT: record 147927 holds a 37-byte `$DATA` value.

    ```
    grep -abo 'hiCTF{' 'C$MFT'        # 151477904:hiCTF{
    151477904 / 1024 = 147927
    ```

    The value is `hiCTF{finally_u_proved_ur_worthiness}`. It is an intermediate token,
    not the event flag. Submitting it to the platform returns "incorrect".

13. Question 11, the deleted folder. Parse the recycle bin `$I` record. The recorded
    values are original path `C:\Users\<victim>\Downloads\miner`, original size 179623 and
    deletion time 2026-05-13 14:27:47 UTC (the `$I` record's SI mtime is 14:27:47.959).
    The payload survives as `$R` entries for `miner.dll` and `miner.exe` but not as file
    bytes, which is why the encryption algorithm cannot be recovered here. Question 12
    asks the same folder's exact byte size, `179623`.

14. Question 13, the plaintext of the deleted `bar.txt`. Find the archived copy the same
    way as step 12. Record 147908 holds a 35-byte resident `$DATA` value reading
    `I will always be there for you bro!`.

15. Question 14, the shred pattern. Sysmon event 23 for `noting.txt` has
    `Archived: false - shredded file with pattern 0x706c6568`. The pattern as stored on
    disk is `68 65 6c 70`, which spells `help`.

16. Open one TLS session and send the fourteen answers in order. The local transcript
    records every accepted answer and the server's final line, which prints the flag. An
    earlier attempt failed because the token from step 12 was submitted as the flag.

## Why it works

The flag exists only on the instance, so the artifacts are a lookup table rather than a
container. Every question targets a different artifact that a responder would collect:
prefetch for execution, the registry for configuration, Sysmon for the process timeline,
Edge for delivery, and the MFT for what was deleted. The two hard steps are both about
deleted content. Sysmon's archive feature copied each original file under a hash-derived
name before deletion, and those copies are small enough to sit resident inside `$MFT`, so
they survive even though the files are gone. The ROT13 names are the hint that the answer
is in those documents, and the token inside one of them is a decoy for anyone who stops at
the first `hiCTF{` string.

## Flag

```
hiCTF{c4r3ful_4b0ut_cr4ck3d_t001s_e315a23532}
```
