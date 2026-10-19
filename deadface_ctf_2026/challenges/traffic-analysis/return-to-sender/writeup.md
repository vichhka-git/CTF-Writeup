# Return to Sender

- **Category:** Traffic Analysis
- **Points:** 80
- **Flag:** `deadface{http_exfil_sneaky_business}`

## Challenge

Something on this network is stealing data and sneaking it out disguised as ordinary web traffic. You've been handed a packet capture from the affected machine. Buried, a compromised host is quietly shipping stolen data out to a server it shouldn't be talking to. Find the traffic that doesn't belong, figure out what's being smuggled, and piece it back together. Submit the flag as `deadface{flag_text}`.

## Solution

Script ```python
#!/usr/bin/env python3
import base64
from scapy.all import rdpcap, TCP, Raw packets = rdpcap('./artifacts/PCAP03.pcap')
chunks = sess_id = None for pkt in packets: if pkt.haslayer(TCP) and pkt.haslayer(Raw): load = pkt[Raw].load if b'POST /api/upload?seq=' in load and b'telemetry.deadface-cc.net' in load: headers, body = load.split(b'\r\n\r\n', 1) for line in headers.split(b'\r\n'): if line.lower.startswith(b'x-session-id:'): sess_id = line.split(b':', 1)[1].strip chunks.append(body.strip) full_b64 = b''.join(chunks) + (sess_id if sess_id else b'')
flag = base64.b64decode(full_b64).decode('utf-8')
print(f"Flag: {flag}")
```
