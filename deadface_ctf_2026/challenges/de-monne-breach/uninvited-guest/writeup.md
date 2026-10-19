# Uninvited Guest

- **Category:** De Monne Breach
- **Points:** 25
- **Flag:** `deadface{10.77.10.66}`

## Challenge

Nathan's workstation asked the local network to resolve a file-server name. Which corporate IPv4 address supplied the suspicious answer? Submit the flag as `deadface{IP}`. [Download PCAP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/for/dctf26-for/demonne.pcap)(7.5MB) SHA256: `a717623237abefb2fc061d6df8f6e9d1391f066f5ac448042b5eb72d41a8ddb3`

## Solution

The workstation broadcasts an LLMNR query for a misspelled file-server name, and exactly one host on the segment answers, claiming the name maps to itself. Four pieces of evidence make that host the answer rather than a legitimate server: it is the only responder in the whole capture; it additionally registers the name over NBNS with a <1c> Domain Controllers record, which is a name-poisoning signature a real file server would never claim; it had itself queried public DNS for the correctly spelled server name and received NXDOMAIN, i.e. attacker reconnaissance establishing the real name was unresolvable; and after the victim connects to it, it relays an NTLMSSP exchange onward to a third host on port 445.
