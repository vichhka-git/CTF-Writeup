# Public Offering

- **Category:** De Monne Breach
- **Points:** 75
- **Flag:** `deadface{167.172.132.224_4815}`

## Challenge

Kali sent a ZIP archive outside the corporate network. What public IPv4 address and TCP destination port received the archive? Submit the flag as `deadface{IP_PORT}`. Use the PCAP from **Uninvited Guest*.

## Solution

Filter the capture for TCP traffic leaving the corporate RFC1918 ranges, which isolates a single external destination and port. Confirm it is the archive exfiltration rather than ordinary browsing by searching the stream payloads for the ZIP local-file-header signature (`tshark -Y 'tcp contains 50:4b:03:04'`), which matches on the same stream. The attacker host is also by far the loudest talker on the segment, which corroborates the attribution.
