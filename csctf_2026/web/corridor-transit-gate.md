# Corridor Transit Gate

**Category:** Web · **Points:** 450 · **Flag:** `CSCTF{HOFjdEHnIDdWxpPppcANZd7m}`

## What the handout gives you

A running instance of the corridor transit gate: a web front end, a Go reverse proxy in
front of it, and an internal dispatch API behind it. The brief says a consignment was
held at the gate and the supervisor's emergency clearance is what releases it.

## Walkthrough

1. **Read the front-end bundle.** The page ships a single-page app whose JavaScript is
   split into chunks. One of them, the dispatch administration chunk, names the internal
   endpoint `/api/v1/internal/dispatch/emergency-clearance` and shows the JSON body it
   expects: a `consignment_id` and a `reason`.

2. **Try it directly and get refused.** Requesting the path from outside returns a gateway
   error reading `GW_ACL_INTERNAL_ROUTE_PROHIBITED`. The Go proxy in front matches on the
   request path and only forwards prefixes it knows, so anything under
   `/api/v1/internal/` is dropped before it reaches the application.

3. **Check what the proxy does allow.** The public API lives under `/api/v1/corridor/`.
   That prefix is forwarded verbatim, and the backend behind the proxy is a Python
   framework that normalises dot segments before routing.

4. **Split the two views.** Send the internal path with encoded dot segments so the proxy
   sees the allowed prefix while the backend sees the internal route:

   `/api/v1/corridor/%2e%2e/internal/dispatch/emergency-clearance`

   The proxy matches the literal `/api/v1/corridor/` prefix and forwards. The backend
   decodes `%2e%2e` to `..`, collapses it, and dispatches to the internal handler.

5. **Send the clearance request.** The handler wants the held consignment and a reason.
   `{"consignment_id": "CTLD-FR-8821", "reason": "Authorised emergency corridor escort"}`
   is accepted; any other consignment is not held and answers with an error.

6. **Read the response.** The handler returns the emergency clearance token, which is the
   flag.

## Answer

`CSCTF{HOFjdEHnIDdWxpPppcANZd7m}`

## Notes

Two normalisations disagree: the proxy normalises nothing and matches prefixes on the raw
path, the framework normalises dot segments and then routes. Encoding the dots keeps the
proxy happy and lets the backend resolve them.

The endpoint name comes from the JavaScript, so read the bundle before fuzzing. No
wordlist finds that path quickly, and the gateway blocks most of it anyway.
