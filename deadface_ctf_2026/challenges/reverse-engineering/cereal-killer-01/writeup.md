# Cereal Killer 01

- **Category:** Reverse Engineering
- **Points:** 50

## Challenge

We have a new set of Spooky Cereals this year, in honor of our New Visitors, who have traveled so long and far to come visit us and to share their other-worldly wisdom with us! To start, we have the Insectoids. They are very similar to us, but their heads are more... buggy. The Insectoids communicate with us, as do the other Alien Species, through special made devices created by Lytton Labs. Using this device, we have gotten to know our new friends, and we have discovered that they each have a favorite terrestrial breakfast cereal! To solve this challenge, enter the password for the binary to 

## Solution

CONFIRMED | Full chain re-derived by the team. (1) the team's static analysis: input is LF-trimmed, SHA1'd, compared against an embedded custom-base64 digest 68158678a3f9d76a3d1ca12d20b2d6af9bd3f290. (2) I cracked that digest MYSELF against rockyou with a local hashlib sweep - hit at line 161011, password = `cookiecrisp` (a cereal, fitting the theme). Offline cracking of a hash found inside a binary, not endpoint brute forcing. (3) The accepted password is then the RC4 key over an embedded blob, decrypting to https://cerealkiller.lyttonlabs.org/unwanted-guests/ick.png - the challenge's OWN asset host (Lytton Labs is named in the challenge story), so fetching it is in scope. (4) I downloaded and viewed that PNG: it renders the flag as text at the top - deadface{You-Vill-Eat-Ze-Bugz-Und-You-Vill-Be-Happy!!!} - over a portrait captioned "Dr. Charles K. Gesch-ICK-ter, Director, Lytton Labs". The decoy in the challenge text (I-For-One-Welcome-Our-New-Buggy-Overlords) is NOT the flag, as the author states. the team had parked believing the URL fetch was out of scope; that was the only thing missing. | the team
