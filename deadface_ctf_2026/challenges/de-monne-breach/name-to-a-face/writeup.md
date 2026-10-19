# Name to a Face

- **Category:** De Monne Breach
- **Points:** 10
- **Flag:** `deadface{nkessler}`

## Challenge

A poisoned name answer prompted an SMB authentication attempt. Which username did the workstation send? Submit the flag as `deadface{username}`. Use the PCAP from **Uninvited Guest*.

## Solution

Filter the capture for NTLMSSP type-3 authentication messages (`tshark -Y 'ntlmssp.messagetype==3' -T fields -e ntlmssp.auth.username -e ntlmssp.auth.hostname`). The workstation repeatedly sends the same account name while attempting SMB authentication against the poisoned name, giving the username directly.
