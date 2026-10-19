# Inside Man

- **Category:** De Monne Slayer
- **Points:** 20
- **Flag:** `deadface{l3FT_b3Hind!}`

## Challenge

Leaks indicate that DEADFACE obtained data that normal customers don't have access to on the app. Logging was turned off on the backend, so De Monne isn't sure which account was used. DEADFACE either compromised a developer account, or something is hardcoded in the app that gave them easy access. Submit the flag as `deadface{flag_text}` > Use the ZIP from **Hard Kept Secrets**

## Solution

CONFIRMED - deadface{l3FT_b3Hind!} | the team verified against the LIVE API, not just the source. jadx shows com/demonne/financial/LoginActivity.java lines 20-21 hold a hardcoded backdoor: INTERNAL_ACCOUNT = "audit@demonne-financial.local", INTERNAL_PASS = "demonnefinancial", and line 57 short-circuits the normal flow when they match, calling performInternalLogin. Using those credentials for real - POST http://dmf.dctf.io:8081/api/auth/login with header X-Internal-Token: <the INTERNAL_API_TOKEN from Hard Kept Secrets> - returns 200 with a JWT for user_id 5 and user.message = deadface{l3FT_b3Hind!}. So the flag is served by the backend to the backdoor account, which is exactly the challenge's premise ("DEADFACE either compromised a developer account, or something is hardcoded"). ApiService also exposes api/accounts, api/auth/me, api/accounts/{id}/statements and api/accounts/{id}/transactions - likely relevant to the rest of the De Monne Slayer series. | the team
