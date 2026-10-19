# Chatty Cathy

- **Category:** OSINT
- **Points:** 15

## Challenge

There is a DEADFACE member who writes a travel blog under the pseudonym "Alice". Can you check GhostTown and see if you can find the travel blog? We suspect the site may contain information needed to track down this DEADFACE member. > NOTE: the IP address is hosting other open ports for other challenges, only the website at 8443 is relevant to this challenge. Submit the flag as: `deadface{flag_text}`

## Solution

cert string is a DECOY, confirmed | Dumped the full X.509: the only flag-shaped value is Subject/Issuer O=Deadface{c@tch_m3_if_y0u_c@n}, present in both Issuer and Subject, with SAN email <redacted-email>. I checked the DER bytes directly - pure ASCII, no homoglyphs, so casing games are not the issue. Its literal text "catch me if you can" plus rejection in both casings makes it a planted taunt. Real path per the challenge ("the site may contain information needed to track down this member"): GhostTown thread /t/20 -> lamia415 links the blog -> blog "Wander with Alice" at 170.187.156.131:8443. Identity recovered: lamia415 = Lorianne Rebarchek (DoomScroll display name), blogging as "Alice", cert email <redacted-email>; her DoomScroll post /post/224 shows her at a desk with a De Monne Financial tumbler, tying her to the breached company. BLOCKER: the blog's key asset <img src="static/other1.png" alt="Nearby my favorite place"> with "guess where I ended up" 404s at every sane path - the geolocation puzzle cannot be solved because the image is not served. The blog text says "I will keep posting these on both profiles in case this stops working", but lamia415's only DoomScroll post is the desk photo, not the restaurant. Blog HTML, GhostTown thread and cert contain no hidden tag/zero-width layers. Likely an organizer-side broken asset, same class of problem as charon.
