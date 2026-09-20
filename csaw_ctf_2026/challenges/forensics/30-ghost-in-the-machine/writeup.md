# Ghost in the Machine - Writeup

- **Category:** Forensics
- **ID:** 30
- **Author:** WubberDuckkie
- **Flag:** `csaw{t1m1ng_1s_3v3ryth1ng_1n_th3_s1l3nt_ch4nn3l}`

## Challenge Summary

The challenge provides a packet capture `files/capture.pcap` with the description:
> "We intercepted a host quietly beaconing out of a locked-down network. The firewall logs every byte that leaves — and every byte here is boring. Same source, same destination, the same little PING payload, over and over.
> And yet something is getting out. It's buried in the noise, it's scrambled, and the operator left just enough on the wire to unscramble it — if you know which columns to trust."

## Analysis & Solution Walkthrough

1. **PCAP Header Repair:**
   Inspecting `files/capture.pcap` revealed a corrupted magic number (`0xc4 0xc3 0xb2 0xa1` instead of `0xd4 0xc3 0xb2 0xa1`). Flipping byte 0 back to `0xd4` rendered the file readable by Scapy/Wireshark.

2. **Traffic Triage:**
   The capture contains 504 UDP packets, all from `10.13.37.5` to `10.13.37.9:9000` with payload `PING` and IP ID 4919 (`0x1337`).
   Analyzing varying fields across the capture showed:
   - **IP TTL:** Exactly two values: `64` (385 packets) and `113` (119 packets).
   - **Source Ports:**
     - For TTL 113: 119 packets with ports in the `50xxx` range.
     - For TTL 64: 385 packets grouped into runs of 8 packets per port, with ports:
       `40115` ('s'), `40104` ('h'), `40052` ('4'), `40100` ('d'), `40111` ('o'), `40119` ('w').
       These grouped runs repeated 8 times (48 groups total), spelling the repeating string `"sh4dow"`.

3. **Covert Timing Channel:**
   Examining the inter-packet arrival time deltas between consecutive TTL 64 packets revealed a bimodal distribution:
   - ~50 ms (0.05 s) representing binary `0`.
   - ~150 ms (0.15 s) representing binary `1`.
   There are exactly 384 deltas (48 bytes * 8 bits).

4. **Decryption & Flag Extraction:**
   Decoding the 384 bits into 48 bytes (MSB first) and applying repeating-key XOR with the key `"sh4dow"` unscrambles the message:
   `csaw{t1m1ng_1s_3v3ryth1ng_1n_th3_s1l3nt_ch4nn3l}`.

## Reproduction

Run the standalone solver:
```bash
python3 agent_workspace/solve.py
```
Output:
```
Key: sh4dow
Flag: csaw{t1m1ng_1s_3v3ryth1ng_1n_th3_s1l3nt_ch4nn3l}
```
