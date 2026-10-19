# Exposing Myself Through Bad OPSEC

- **Category:** OSINT
- **Points:** 25
- **Flag:** `deadface{c@tch_m3_if_y0u_c@n}`

## Challenge

Now that you've found the DEADFACE member's travel blog, what else can we determine about this site and this member? Perhaps the site's certificate can tell us more. > NOTE: the IP address is hosting other open ports for other challenges, only the website at 8443 is relevant to this challenge. Submit the flag as: `deadface{flag-text}`

## Solution

The challenge continues the investigation of the DEADFACE member's travel blog hosted at `https://170.187.156.131:8443/`. The challenge description hints:
> "Now that you've found the DEADFACE member's travel blog, what else can we determine about this site and this member? Perhaps the site's certificate can tell us more." Inspecting the TLS certificate served on port 8443 reveals:
- **Subject:** `C=US, ST=Louisiana, L=New Orleans, O=Deadface{c@tch_m3_if_y0u_c@n}, OU=Operations, CN=170.187.156.131, emailAddress=<redacted-email>`
- The flag is embedded in the `Organization` (`O`) attribute: `deadface{c@tch_m3_if_y0u_c@n}`.
