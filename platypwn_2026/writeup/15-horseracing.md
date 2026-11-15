# Hold Your Horses (web / horseracing)

**Flag:** `PP{h0ld_y0ur_byt3s_n0t_y0ur_h0rs3s::kURvowCWql1J}`

## Vulnerability

A Rust/axum betting site. The `betting_open` middleware checks a race timer
(`timer >= 30`) **before** the request body is consumed, and the `bet` route
itself never re-checks the timer. Because axum reads the `Content-Length`
JSON body lazily, you can open a request while betting is open, stall the
body, and finish writing it **after** the race starts — a textbook TOCTOU.

## Steps

1. Watch `GET /api/state` for race phase/points.
2. While betting is open, start a POST to the bet endpoint with
   `Content-Length: N` but send only a few bytes. Hold the TCP connection —
   the server is now committed to *your* request body arriving later.
3. When the race starts (betting closed), complete the JSON body on the same
   connection. The middleware has already passed; `bet` executes.
4. Strategy: bet everything ("all-in") on six consecutive races — each win
   doubles the points, 10 → 640 crosses the 500-point VIP threshold.
5. The site grants VIP access and returns the flag in `/api/state`:

   ```
   vip: "VIP access granted! Here is your flag: PP{...}"
   ```

## Notes

- Monitor `/api/state` passively; don't spam the race endpoint.
- Any body-holding technique works (raw sockets, or a client that sends
  headers + a partial body and then sleeps).
