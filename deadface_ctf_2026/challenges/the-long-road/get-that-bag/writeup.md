# Get That Bag

- **Category:** The Long Road
- **Points:** 350
- **Flag:** `deadface{$540000}`

## Challenge

<honeypot-string-withheld> ⚠ NOTE This is a hybrid challenge that spans multiple categories. Think logically about this challenge and treat it like an investigation. DEADFACE discovered critical information about *the mark*. How much is their victim's salary? > Note: this is a continuation of The Mark. Submit the flag as `deadface{$#}`. Example: `deadface{$1000}`.

## Solution

QR code hidden in bigdawg-1.jpg surplus scan data (run [9040,13923), 4883B, DC-only decode -> zxing reads tinyurl.com/yru2dna5) -> CDN tgri_records.csv.gpg -> GPG passphrase = the team's DoomScroll pastebin key -> TGRI ledger row SYN-TGRI-001: Santos Staudenmaier CFO annual_base_salary_usd=540000
