# No Holding Back

- **Category:** De Monne Slayer
- **Points:** 210
- **Flag:** `deadface{IDOR_u_2_f1nD_m0r3_Fl4gz}`

## Challenge

DEADFACE was able to extract bank data from several of De Monne's customers. Something in the app's logic allows DEADFACE to gather details from pretty much any user they want. DEADFACE claims they left a flag behind as proof that they have access to De Monne's customer data. The problem is, we don't know who the user is (or their password). Submit the flag as `deadface{flag_text}` > Use the ZIP from **Hard Kept Secrets**

## Solution

OSINT (GhostTown t/58, DoomScroll post 267) leaked John Doe credentials john.doe@example.com:Welcome1!; authenticated via /api/auth/login with X-Internal-Token, then exploited IDOR on GET /api/accounts/1007/statements to exfiltrate restricted internal audit statement
