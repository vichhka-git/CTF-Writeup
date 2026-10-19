# False Telemetry

- **Category:** De Monne Breach
- **Points:** 250
- **Flag:** `deadface{167.172.132.224_4815_30}`

## Challenge

`WindowsTelemetryCheck` runs a PowerShell script that repeatedly tests a connection. Identify the destination IPv4 address, TCP port, and delay between attempts. Submit the flag as `deadface{IP_PORT_SECONDS}`. Use the memory dump evidence from **Who Goes There?**

## Solution

The scheduled task identified in an earlier challenge runs a PowerShell script from an unusual directory. The script body itself is resident in the memory image's file-cache region (two identical copies), and can be recovered with a UTF-16 and ASCII string search for the script name and for PowerShell beacon constructs. The body is a loop that repeatedly calls Test-NetConnection against a fixed destination with a fixed sleep between attempts, giving the destination address, the TCP port and the interval. The same destination and port appear independently as the exfiltration endpoint in the network capture from the sibling challenge, which cross-confirms the values from a second artefact.
