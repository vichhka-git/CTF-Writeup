# Twilight Zone Transfer

- **Category:** Traffic Analysis
- **Points:** 50
- **Flag:** `deadface{dns_zone_transfer}`

## Challenge

A misconfigured DNS server allowed an unauthorized zone transfer (AXFR). The attacker enumerated hostnames, then pulled the ENTIRE zone in one request. The capture already contains that transfer, find it and read the records. Submit the flag with the dog's name as: `deadface{flag-text}`

## Solution

PCAP04.pcap frame 37 AXFR reply txid 0x1234 (TCP/53, ns1 192.168.56.10 -> attacker 10.10.14.9): TXT _flag.deadface-cc.net = deadface{dns_zone_transfer}; "dog's name" clause is a copy-paste from hail-caesar, no dog string exists in the capture
