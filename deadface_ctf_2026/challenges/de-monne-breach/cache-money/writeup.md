# Cache Money

- **Category:** De Monne Breach
- **Points:** 150
- **Flag:** `deadface{C:\ProgramData\WindowsCache\telemetry.ps1}`

## Challenge

We know a suspicious task launches a PowerShell script from an unusual directory. What is the script's full Windows path? Submit the flag as `deadface{absolute\file\path}`. Use the memory dump evidence from **Who Goes There?**

## Solution

TaskCache Actions blob (UTF-16LE) = "powershell.exe" -NoProfile -File C:\ProgramData\WindowsCache\telemetry.ps1; registered by the attacker SSH session as WindowsTelemetryCheck; 11x ASCII / 92x UTF-16 in memory.
