# Borrowed Script

- **Category:** De Monne Breach
- **Points:** 100
- **Flag:** `deadface{d34th@10.77.10.66}`

## Challenge

The workstation obtained `telemetry.ps1` from another machine before scheduling it. What internal IPv4 address supplied the script? Submit the source username and the IP address. Submit the flag as `deadface{username@IP}`. Use the memory dump evidence from **Who Goes There?**

## Solution

Recovering PowerShell command history from the memory image shows the sequence that staged the implant: a Test-Path check for the script under the unusual directory, a directory listing, then an scp pulling the script from a remote account, followed by the New-ScheduledTaskAction call that registers it. The scp source string — the remote username together with the host address — is the answer, and that host address matches the attacker machine identified as the name poisoner in the packet capture.
