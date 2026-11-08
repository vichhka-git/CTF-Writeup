# Ghost Signal

**Category:** Network · **Points:** 900 · **Flag:** `CSCTF{28358943}`

## What the handout gives you

Three captures of the same incident: an SS7/M3UA capture, a Diameter capture and a
billing export (`billing_events.json`). The brief asks to reconstruct the intrusion
chain and says the flag is eight lowercase hex characters — again a truncated hash.

## Walkthrough

1. **Open the captures as SCTP, not TCP.** Both pcaps carry IPv4 protocol 132. Wireshark
   decodes them once you set the SCTP payload protocol identifier: 46 is Diameter
   (port 3868), 3 is M3UA carrying SS7 (port 2905). Without that, everything looks like
   undecoded DATA chunks.

2. **Read the Diameter side.** Twenty-eight messages, command codes 301 and 302
   (credit-control request and answer). Most are ordinary. Four are not: the session id
   is `hss.eastern-tele.ro;1723740150;49211`, the origin host flips from
   `cscf.rogue.evil-domain.net` to `cscf.pivot.eastern-tele.ro`, and one answer carries
   a redirect-host AVP pointing at `diameter://intercept-49211.evil-domain.net`. The
   subscription-id AVP nests an IMSI of `226012014000001`.

3. **Read the SS7 side.** Sixty M3UA data chunks. The first forty-five are routine
   routing-info queries with transaction ids of the form `1000xxxx`. Then five
   transaction ids `4921 00xx` and five `4921 00xx` again appear, followed by five MAP
   `updateLocation` requests. In those, the IMSI is BCD-packed as
   `22 06 21 10 04 00 00 f1`, which decodes by swapping each nibble pair to
   `226012014000001` — the same subscriber the Diameter messages name.

4. **Read the billing export.** Forty events. Ten belong to the intrusion: five
   `atk_*` credit-control requests with a zero charge and the anomaly
   `zero_charge_on_roaming`, and five `pivot_*` answers with
   `unusual_routing_path` and the serving CSCF `cscf.pivot.eastern-tele.ro`. The first
   of those ten carries the timestamp `1723740150`, which is also the second field of
   the Diameter session id.

5. **Pick one identifier per artifact.** The brief's hint is precise about this: hosts
   and global titles are noise, and what matters is the unique identifier each file
   contributes.

   - SS7 capture: the subscriber's IMSI, `226012014000001`
   - Diameter capture: the full session id, `hss.eastern-tele.ro;1723740150;49211`
   - billing export: the first anomalous event's Unix timestamp, `1723740150`

6. **Hash the join.** Concatenate the three with single colons and take the SHA-256.
   The leading eight hex characters are the flag body.

## Answer

The preimage is

`226012014000001:hss.eastern-tele.ro;1723740150;49211:1723740150`

whose SHA-256 begins `2835894…`, so the flag is `CSCTF{28358943}`.

## Notes

Decoding the BCD IMSI correctly is the usual place to go wrong: the digits come out
swapped in pairs, and a naive hex dump gives `2206211004000f1`, which hashes to
nothing useful. The byte `f1` is the fill nibble that makes the odd-length string come
out right.

The Diameter session id contains its own semicolons. Keep it whole — it is one field,
not three — and only the join between the three fields uses colons.
