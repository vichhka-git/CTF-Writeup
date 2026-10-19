# I Want to be a Real Boy  (4 of 4 series)

- **Category:** Web
- **Points:** 250
- **Flag:** `deadface{oh_you_shouldnt_be_here}`

## Challenge

When it comes to a web application, the admin is king. We have already discovered so much data, do you think we can become an admin as well? > NOTE: This IP address is hosting other ports for other challenges, only the website is relevant to this challenge. > NOTE: Do not perform port scanning on this host, only the address and port discovered in OSINT matter. Submit the flag as: `deadface{flag-text}` http://45.79.200.170:3000/

## Solution

Final stage of the Health Spark series, reached by chaining the three earlier bugs. SQL injection on the login endpoint discloses a working account; mass assignment on the profile endpoint re-issues a validly signed session token with an elevated role (the department identifier is pinned server-side, but the role field is reflected); that role unlocks an administrator photo-import endpoint which is a server-side request forgery sink accepting only http/https. Pointing it at the loopback interface reaches an internal-only administration console that is not exposed externally, and its operator note carries this stage's token.
