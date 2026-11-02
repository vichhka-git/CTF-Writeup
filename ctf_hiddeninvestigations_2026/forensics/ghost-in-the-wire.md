# Ghost in the Wire

Forensics, 53 points, 786 solves. One packet capture holds an
ICMP exfiltration channel hidden behind a second, busier ICMP conversation. Extracting
the flag is a matter of filtering on payload length rather than on protocol, because a
naive sweep that concatenates every ICMP body produces garbage.

## What you are given

`ghost-in-the-wire.zip` expands to `ghost_traffic.pcap`, 1,857 bytes. There is no live
service.

The capture is a classic little-endian libpcap file: magic `d4c3b2a1`, version 2.4,
snaplen 65,535, link type 1 (Ethernet). Thirty complete records occupy file offsets
`0x18` to `0x740`, with nothing after them. `tshark` and Scapy are not required; the
whole file parses with the `struct` module.

## Reproduction

1. Confirm the framing and the protocol mix. Walk the records by reading the 16-byte
   header (`<IIII` for seconds, microseconds, captured length, original length), then
   the captured frame:

   ```python
   import struct
   d = open('ghost_traffic.pcap','rb').read()
   print(d[:4].hex(), struct.unpack('<HHIIII', d[4:24]))
   # d4c3b2a1 (2, 4, 0, 0, 65535, 1)
   ```

   Every frame is Ethernet type `0x0800`, IPv4 with IHL 20, protocol 1 (ICMP). There is
   no TCP, no DNS and no HTTP, so ICMP is the only possible carrier.

2. Print one line per packet with the ICMP type, id, sequence number and payload. Parse
   the ICMP header at `Ethernet(14) + IHL` and remember the ICMP body starts 8 bytes
   after that.

   ```python
   ihl = (f[14] & 0xf) * 4
   icmp = f[14 + ihl:]
   typ, code = icmp[0], icmp[1]
   ident, seq = struct.unpack('>HH', icmp[4:8])
   print(typ, hex(ident), seq, len(icmp) - 8, icmp[8:])
   ```

3. Two ICMP conversations show up. Packets 0, 1, 28 and 29 carry 16 and 17 byte ASCII
   bodies and read like keepalives: `AAAAAAAAAAAAAAAA`, `ping from server1`,
   `health check ok`, `monitor alive 001`. Packets 2 to 27 are 43-byte frames between a
   second pair of addresses that appear nowhere else, each with a one-byte body, id
   `0x1337`, sequence 1 to 26.

4. Filter on body length, not on address, and concatenate by sequence number:

   ```python
   rows, off = [], 24
   while off + 16 <= len(d):
       s, us, incl, orig = struct.unpack('<IIII', d[off:off+16]); off += 16
       f = d[off:off+incl]; off += incl
       if f[23] != 1: continue
       icmp = f[14 + (f[14] & 0xf) * 4:]
       if len(icmp) - 8 != 1: continue
       rows.append((struct.unpack('>H', icmp[6:8])[0], icmp[8:9]))
   print(b''.join(b for _, b in sorted(rows)).decode())
   ```

   This returns 26 single-byte frames and prints the flag. The decoded bytes already
   start with `hiCTF{` and end with the closing brace, so no further transform is
   applied. Filtering on the address instead of the length works too, but only if you
   already know which of the two conversations is the signal.

5. Check the alternatives before settling. The local recon records both as negative:
   the ICMP id is constant (`0x1337`) rather than varying, the sequences are monotonic
   rather than arbitrary, and the timestamps advance exactly one second per frame with
   every microsecond field zero, so neither header fields nor inter-packet timing carry
   data. Capture order happens to match sequence order, but sequence is the ordering key
   the author used.

   For reference, the covert payloads sit at file offsets `0xe7 + 0x3b * k` for k from 0
   to 25, ending at `0x6aa`, and the frames are 59 bytes apart in the file.

## Why it works

Both streams share the same ICMP id, which defeats the usual "filter on the id" move,
and the decoy bodies are longer than the signal bodies, which defeats the usual
"concatenate all ICMP payloads" move. The one property the decoys do not have is a
one-byte body, so a length filter isolates the channel without needing to know the
addresses in advance.

## Flag

```
hiCTF{1cmp_3xf1l_d3t3ct3d}
```
