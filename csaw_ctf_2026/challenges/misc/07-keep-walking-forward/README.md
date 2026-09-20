# Keep Walking Forward

- Category: Misc
- ID: 7
- Type: dynamic
- Value: 377
- Solves: 145
- Author: 3p1cac
- Files:
  - `capture.pcapng`
  - `vcheck.7z`
  - `vcheck.log`

## Description

Security pushed a GPO that disabled our access to PowerShell after some recent cases of "misuse". We still need a way to check file versions and right clicking through Properties is a chore. Luckily, our new hire wrote a utility for checking Windows binary versions and was kind enough to compress and upload it to our internal CDN for everyone to use. However, we are now receiving reports of some endpoints generating traffic to suspicious domains. The domains are, sadly, now unreachable, but we managed to get our hands on a key log file from earlier triage. Here are the artifacts we have. Can you figure out what happened and find the flag?
