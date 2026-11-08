# Cloudflare Deanon: Find the Back Office

**Category:** OSINT · **Points:** 419 · **Flag:** `CSCTF{t2YGg14buPVPPnd9uvazWcdvT9UMCh3J}`

## What the handout gives you

The handout is one text file, `README.md` (642 bytes). It is the third task in the NestEgg Capital lab and points back to the first task for the full briefing. The goal is the operator's backend panel and the hot wallet admin key it displays. The answer boundary is explicit: use the unique origin established in Task 2, take the key exactly as the simulated panel shows it, and do not enumerate paths, run wordlists, or generate candidate keys. There are no attachments and no target address in this handout.

## Walkthrough

1. **Start from the Task 2 origin.** Task 2 settled the clear-web origin at `185.146.86.118`. Port 80 on that address served the same 4,443-byte NestEgg Capital page as the Cloudflare-fronted site, down to the `Last-Modified: Wed, 21 Oct 2026 20:50:41 GMT` header. That match ruled out an edge or parking address and fixed the host to use for Task 3.

2. **Notice the second service.** The Task 2 result also exposed an HTTP service on port 8080 of the same host, with the title `NestEgg CRM | Backend`. Port 80 is the public marketing page. Port 8080 is the operator side, and it is not behind Cloudflare. The task boundary points at this host, so no other address was tested.

3. **Request the backend root.** One request was enough:

   `curl http://185.146.86.118:8080/`

   The root returned the backend panel directly, identifying itself as the NestEgg CRM backend. Since the boundary forbids path enumeration, the service root is the only URL needed. There is no login wall or hidden route in front of the key.

4. **Read the hot wallet admin key.** The panel displayed a field labelled Hot wallet admin key with the value `t2YGg14buPVPPnd9uvazWcdvT9UMCh3J`. The value is 32 alphanumeric characters. It is shown verbatim, so copying it is the whole step; there is no decoding, hashing, or reconstruction.

5. **Wrap it in the flag format.** The handout gives `CSCTF{<answer>}` and names the admin key as the answer. Substituting the displayed key produces `CSCTF{t2YGg14buPVPPnd9uvazWcdvT9UMCh3J}`.

## Answer

The verified origin's port 8080 panel displays the hot wallet admin key:

`t2YGg14buPVPPnd9uvazWcdvT9UMCh3J`

Wrapped in the challenge format, the flag is:

`CSCTF{t2YGg14buPVPPnd9uvazWcdvT9UMCh3J}`

## Notes

- The public platform is proxied by Cloudflare; port 8080 on the origin is not. That is why the Task 2 address is required. A request to the public hostname does not reach the CRM service.
- Port 80 and port 8080 share an IP but not a document root. The marketing page has no link to the backend, and the backend's title is the only clue that the two services belong together.
- The Task 2 boundary excluded Cloudflare edge addresses, DNS resolvers, and historical or parking addresses. Those exclusions still apply here; the origin is the only valid host.
- No directory discovery is needed or permitted. The panel answers at `/`, and the key is in the response body rather than a hidden path or a generated value.
