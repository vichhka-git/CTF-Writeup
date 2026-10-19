# Crown Jewels

- **Category:** De Monne Breach
- **Points:** 75
- **Flag:** `deadface{annual_report.pdf}`

## Challenge

The attacker copied several documents from the executive share. What was the first PDF read from that share? Submit its full filename, including the extension. Submit the flag as `deadface{file.txt}`. Use the PCAP from **Uninvited Guest*.

## Solution

Filter the capture for SMB2 Create and Read operations against the executive share (`tshark -Y 'smb2.cmd==5 || smb2.cmd==8' -T fields -e smb2.filename -e smb2.tree`) and order by frame number. The first PDF opened and read from that share is the answer; an .xlsx accessed between PDFs is a distractor, so the filter must select on extension and on an actual Read, not merely a Create.
