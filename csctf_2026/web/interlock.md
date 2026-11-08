# Interlock

**Category:** web · **Points:** 707 · **Flag:** `CSCTF{fqd4cwEoeObDAEaNYJBScLNn}`

## What the handout gives you

The README describes a quarantined substation that must be isolated with an order approved by two different roster engineers. The reliability console is at the dispatcher root and links its API schema at `/api/v1/schema`. It warns that some clients rewrite escaped request paths and recommends preserving the path exactly.

- `README.md` — incident brief, schema location, path-preservation warning, and flag format.

## Walkthrough

1. Fetch `/api/v1/schema` from the reliability console. It lists the delegate, order, approval, and dispatch endpoints, along with each JSON field. Use the assigned dispatcher root for `TARGET`.

   `curl --path-as-is "$TARGET/api/v1/schema"`

   The schema shows that delegate registration accepts `name`; order creation accepts `bus` and `requester_token`; approval accepts `order_id` and `approver_token`; dispatch accepts `order_id`, `target`, and `unlock`. The edge policy checks the received path before the application handles it.

2. The edge policy evaluates the path as received. Send operations requests with `/./ops/...` and use `curl --path-as-is` so the dot segment survives. This reaches the operations routes without the edge proxy rejecting their ordinary `/ops/...` paths.

3. Register `ʳ.mendal` and `ª.torvo` through `POST /./ops/delegates`, once per JSON body with a `name` field. Registration uniqueness uses casefold only, so these compatibility characters remain distinct from the ASCII roster names. Roster matching applies NFKC and casefold: the names resolve to the non-compromised engineers `r.mendal` and `a.torvo`. The returned tokens are `tok-12` and `tok-2`.

4. Create the order with `POST /./ops/orders` and body `{"bus":["KR-B1","KR-B2"],"requester_token":"tok-12"}`. The service returns order `ord-13`. Approve it with `POST /./ops/orders/approve`, passing `order_id` `ord-13` and approver token `tok-2`. These tokens resolve to different roster principals, satisfying dual control.

5. The schema defines the release digest as SHA-256 of `interlock|<order_id>|<bus identifiers joined by comma>`. For this order, hash `interlock|ord-13|KR-B1,KR-B2`; the resulting unlock value is `6ff751be09dd3fafb30f706d88027a46e886adb52b0fbd6e3e1e768737a7a051`.

6. Dispatch through `POST /./ops/dispatch` with the order ID and unlock value. Set `target` to `http:/\sg-kr.grid.test/dispatch`. The dispatch validator parses the authority with a backslash, so its host check sees no hostname and skips the quarantine comparison. The later URL parser normalizes the same value to `http://sg-kr.grid.test/dispatch`, allowing the gateway to receive the order and return its isolation receipt.

## Answer

The receipt carries the clearance code. Submit the complete token exactly as returned: `CSCTF{fqd4cwEoeObDAEaNYJBScLNn}`.

## Notes

The path and URL checks use different parsers. Keep the `/./` route prefix and the backslash in the dispatch target; normalizing either value removes the relevant parser disagreement.
