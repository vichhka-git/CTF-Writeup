# Operation Dawn: The Command Seal

**Category:** Web · **Points:** 272 · **Flag:** `CSCTF{ElQcK0Lqvm0Uy6PnGBuo18Jq}`

## What the handout gives you

The challenge exposes an HTTP service representing a military communications relay for battlefield orders and status reporting.

- `/report` — an endpoint receiving status reports formatted as XML documents.
- `/order` — an endpoint accepting cryptographically signed mission orders for execution.
- Challenge brief — instructions indicating that standing orders require command verification.

## Walkthrough

1. **Map the XML API endpoints.** Interacting with the service reveals two active endpoints: `POST /report` parses submitted reports and reflects summary text, while `POST /order` expects a signed order structure and checks authorization before processing instructions.

2. **Test for XML External Entity (XXE) injection.** Submitting a custom DOCTYPE with a parameter entity to `POST /report` reveals that the XML parser resolves external entities. Requesting system files such as `file:///etc/passwd` triggers a 400 error because the entity resolver restricts file access to paths beneath `/opt/relay/`.

3. **Exfiltrate the outbox state.** The application maintains operational logs in `/opt/relay/outbox/last-order.txt`. Submitting an XXE payload referencing `file:///opt/relay/outbox/last-order.txt` reflects the content of the last dispatched order:
   - `id`: `cmd-6002`
   - `kind`: `routine`
   - `text`: `hold the canal checkpoint and report at dusk`
   - `digest`: `3285LDdHeDDsT0GAAYpPfB9xgKcH/obiPxlWg4JzueM=`
   - `sig`: the command authority's RSA signature over the order digest

4. **Analyze signature verification versus execution.** The `POST /order` endpoint expects a `<relay>` root containing an `<order>` block and an `<auth>` block. The authorization validator uses an XPath query or element lookup to locate the specific `<order>` tag whose `id` attribute matches `<auth><ref>cmd-6002</ref>`. Once found, it computes the canonical digest of that tag and verifies the RSA signature. However, the order execution handler retrieves the first `<order>` child node under `<relay>` without checking whether it was the signed node.

5. **Craft an XML Signature Wrapping (XSW) payload.** Construct a payload containing two `<order>` tags inside `<relay>`. Place an unauthorized target order first:
   ```xml
   <order id="cmd-6003">
     <kind>standing</kind>
     <text>give standing order</text>
   </order>
   ```
   Place the authentic signed `cmd-6002` order second, followed by the original `<auth>` block referencing `cmd-6002`.

6. **Execute the wrapped order.** Send the payload to `POST /order` with `Content-Type: application/xml`. The verification routine validates the signature against the second order element (`cmd-6002`), while the command engine executes the first element (`cmd-6003`). The server honours the requested standing order and prints the flag.

## Answer

The server response confirms execution of the standing order and prints:

`command standing order honoured: CSCTF{ElQcK0Lqvm0Uy6PnGBuo18Jq}`

## Notes

The entity resolver rejects paths outside `/opt/relay/`. Enumerating standard local spool directories (`inbox`, `outbox`, `config`) within `/opt/relay/` identifies the stored order file containing the valid cryptographic signature.
