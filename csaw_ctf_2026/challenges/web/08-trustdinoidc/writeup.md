# TrustDinOIDC — Writeup

## Challenge
- **Name:** TrustDinOIDC
- **Category:** Web
- **Points:** 348
- **Solves:** 161

## Summary

The challenge is an OIDC-based web app ("TrustDinOIDC") that sells dinosaur posters. The "Flagosaurus" print is admin-only. Two identity providers (PaleoID, StrataID) issue RS256 JWTs with x5c certificate chains. The vulnerability is that StrataID does not pin its signing key — it accepts any self-signed certificate with the correct Common Name. Combined with scope escalation to `flagosaurus:redeem`, this grants admin access.

## Vulnerability

**x5c JWT Injection + Scope Escalation**

1. The server validates JWT signatures using the public key extracted from the `x5c` certificate in the JWT header
2. PaleoID pins its signing key (rejects forged certs), but **StrataID does not** — any cert with `CN=strataid.example.com` is accepted
3. The legitimate tokens have `scope: "openid profile freeosaurus:redeem"` granting "Member" tier
4. Adding `flagosaurus:redeem` to the scope elevates to "Curator" tier, which grants access to the Flagosaurus section

## Exploit Steps

1. Generate an RSA keypair and self-signed certificate with `CN=strataid.example.com`
2. Forge a JWT with:
   - Header: `alg=RS256`, `x5c=[our_cert]`
   - Payload: `iss=strataid.example.com`, `sub=admin`, `scope=openid profile flagosaurus:redeem`
3. Sign with our private key
4. Set the forged JWT as the `session` cookie
5. Fetch the main page — the Flagosaurus section now shows the flag

## Flag

`csaw{str4ta_sk1pped_th3_p1n}`

## Key Observations

- The challenge name "TrustDinOIDC" is a pun on "Trust + Dino + OIDC" and the trust model vulnerability
- The flag `str4ta_sk1pped_th3_p1n` confirms the mechanism: StrataID skipped the key pinning
- PaleoID properly pins its key (rejects forged certs), serving as a contrast
- The `scope` claim is what determines the tier/access level, not `sub` or `role`
