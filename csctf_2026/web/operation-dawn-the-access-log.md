# Operation Dawn: The Access Log

**Category:** Web · **Points:** 120 · **Flag:** `CSCTF{07_beacon_tow_vigil_bollard_8c0371}`

## What the handout gives you

A single `access.log` from an Ash Army checkpoint portal. The brief says one visitor
walked out with the checkpoint's link secret without ever triggering an error page, and
that the recovered value already carries its own braces.

## Walkthrough

1. **Read the log for shape, not content.** Most requests are ordinary status polling of
   `/api/status?unit=43`. The interesting ones are the same endpoint with a parameter that
   contains SQL.

2. **Notice the sleep.** The injected conditions are of the form
   `IF(SUBSTR(token,<pos>,1)='<char>',SLEEP(2),0)`, which is time-based blind injection. No
   response differs, no error page is produced — only the request duration changes.

3. **Use the response time column.** Each log line carries a request time. Lines that took
   about two seconds or more are the ones where the condition was true. Everything below a
   second and a half is a false guess.

4. **Sort by position.** The injection walks the token one character at a time. Group the
   slow requests by `SUBSTR` position and keep the character that was being tested in each
   true case.

5. **Reconstruct the secret.** Concatenating the characters in position order gives the
   link secret exactly as stored.

## Answer

`CSCTF{07_beacon_tow_vigil_bollard_8c0371}`

## Notes

The attacker's quoted character is the value to collect, not the parameter name. Watch for
the position offset: `SUBSTR` is one-based in SQLite, so the first recovered character
belongs to position one.

The log is the whole challenge. There is no live target and no need to replay the
injection — sorting the slow lines is enough.
