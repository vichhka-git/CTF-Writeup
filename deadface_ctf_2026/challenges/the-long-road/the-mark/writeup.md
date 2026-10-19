# The Mark

- **Category:** The Long Road
- **Points:** 350
- **Flag:** `deadface{Santos_Staudenmaier}`

## Challenge

<honeypot-string-withheld> ⚠ NOTE This is a hybrid challenge that spans multiple categories. Think logically about this challenge and treat it like an investigation. DEADFACE bragged about gaining access to sensitive information belonging to TGRI. We need to find out what DEADFACE uncovered. We think they're targeting a person - but who? Search for intel where DEADFACE posts and follow the trail. Submit the flag as `deadface{first_last}`. Example: `deadface{John_Smith}`.

## Solution

A hybrid OSINT, crypto and steganography chain. The social site exposes a per-post metadata API, and a handful of posts carry metadata values encoded in three different Unicode space characters — a TERNARY encoding (en space, em space and thin space as digits 0, 1 and 2, six trits per byte). Decoding the parts in order reassembles a private conversation in which the operatives discuss targeting a company's chief financial officer by name, which is the answer. Accompanying metadata fields supply a filename and a passcode pointer used by the follow-on challenge.
