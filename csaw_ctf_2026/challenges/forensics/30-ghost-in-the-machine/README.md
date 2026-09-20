# Ghost in the Machine

- Category: Forensics
- ID: 30
- Type: dynamic
- Value: 197
- Solves: 227
- Author: WubberDuckkie
- Files:
  - `capture.pcap`

## Description

We intercepted a host quietly beaconing out of a locked-down network. The firewall logs every byte that leaves — and every byte here is boring. Same source, same destination, the same little `PING` payload, over and over.

And yet something is getting out. It's buried in the noise, it's scrambled, and the operator left just enough on the wire to unscramble it — if you know which columns to trust.

Find the message.
