# The Workstation in the Middle

- **Category:** De Monne Breach
- **Points:** 40

## Challenge

The compromised De Monne employee was working at a Windows device. What is that device's hostname? Preserve the capitalization shown in memory. Submit the flag as `deadface{COMPUTER-NAME}`. Use the memory dump evidence from **Who Goes There?**

## Solution

CONFIRMED | the team's own carve of memory.raw: `COMPUTERNAME=DMF-WS11-042` occurs 260 times; the handful of shorter hits (DMF-WS11-04, DMF-WS1, DMF) are page-boundary truncations of the same string, not alternatives. Casing as required: DMF-WS11-042. Consistent with the SSH evidence from Who Goes There? (10.77.10.66 -> this host). the team additionally corroborated via ActiveComputerName/Tcpip registry keys and flagged an mnmsrvc default value as a decoy. | the team
