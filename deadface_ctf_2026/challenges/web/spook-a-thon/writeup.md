# Spook-A-Thon

- **Category:** Web
- **Points:** 80
- **Flag:** `deadface{serve_me_up_a_flag}`

## Challenge

The DEADFACE crew set up a discussion board to pick movies for their Halloween marathon. Their sysadmin, Jerry, was in a hurry, and left more exposed than a movie board should. Find what Jerry leaked and ask the server nicely for its secret. Target: `170.187.156.131`. > NOTE: Avoid port 8443 on this host that is for a different challenge. Submit the flag as: `deadface{flag-text}`

## Solution

The board is served by Python's built-in `http.server`, which the Server header discloses. That handler resolves a directory request to index.html, but a request carrying a query string (for example `/?x=1`) bypasses that match and returns a full DIRECTORY LISTING instead. The listing exposes the server source alongside the page. Reading the source reveals a WebSocket service on a separate port that answers a get_flag command only when a specific admin session cookie is present, and the source also contains that cookie value. Connecting to the WebSocket with the cookie set returns admin status true and then the flag, which confirms the finding end to end rather than merely lifting a string out of source.
