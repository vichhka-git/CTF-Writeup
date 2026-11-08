# Radar Silence

**Category:** network · **Points:** 120 · **Flag:** `CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}`

## What the handout gives you

The README identifies RDR37 as `192.0.2.37`, OPS40 as `192.0.2.40`, and asks whether a bearer token left the radar station. The attached capture is an isolated DNS replay.

- `radar-silence.pcapng` — 4,052 bytes, with 28 Ethernet frames carrying IPv4, UDP, and DNS.
- `README.md` — gives the station mapping and the required flag format: a lowercase station ID followed by `_rotation_` and a 32-character lowercase hexadecimal token.

## Walkthrough

1. Inspect the packet capture's DNS queries and keep the source address in view. RDR37 sends queries from `192.0.2.37` to the resolver at `192.0.2.1`; OPS40's queries come from `192.0.2.40` and are not evidence of a leak from RDR37. The capture contains only 28 packets, so checking the DNS names and their source addresses is enough to separate the two hosts.

2. Filter for queries from `192.0.2.37` whose names end in `update.svc-telemetry.example`. Four names have an indexed label immediately before that domain. Their leftmost labels are data chunks, and the two-digit labels give their order:

   - `00`: `miytaojxmy3gk`
   - `01`: `ojxg4ydcnldmf`
   - `02`: `rtamrzg5sgiyz`
   - `03`: `tgmztknjqhfta`

   The queries are interleaved with normal-looking names such as `wpad.airnet.example`, `time.airnet.example`, and `rdr37-diag.airnet.example`. Those names lack the indexed update-domain pattern and are not part of the token. In packet order, the chunks appear as index 02 in frame 5, 00 in frame 9, 03 in frame 15, and 01 in frame 21. The DNS replies repeat the question names, so use each station-originated query once.

3. Concatenate the four data labels in numeric index order, without dots or the index labels. The 52-character result is unpadded Base32 text for 32 bytes. Uppercase it for a standard Base32 decoder; decoding yields the 32 ASCII characters `b1097f6e977015cac0297ddc3335509f`. Every character is a lowercase hexadecimal digit, matching the token length required by the README. Preserve the decoded bytes as ASCII; interpreting the hex characters as a binary number would change the submitted token.

4. Use the station ID associated with the packet source, not the resolver or OPS40. The handout maps `192.0.2.37` to RDR37, so the lowercase source name is `rdr37`. The recovered value is therefore a bearer token exfiltrated by RDR37 and should be reissued, as the README directs.

## Answer

Combining the station ID, required `_rotation_` separator, and decoded token gives `CSCTF{rdr37_rotation_b1097f6e977015cac0297ddc3335509f}`.

## Notes

The DNS query order is deliberately different from chunk order. Use the `00`–`03` labels to assemble the payload; sorting by packet time would produce the wrong Base32 input.
