# Encrypted Pastebin

**Platform:** HackerOne CTF  
**Challenge:** Encrypted Pastebin  
**Difficulty:** Hard  
**Category:** Web / Cryptography  
**Flags:** 4 (Flag0–Flag3)

---

## Overview

The challenge presents a pastebin web application that claims to use "military-grade 128-bit AES encryption." Users can create encrypted pastes via a form with `title` and `body` fields. The resulting encrypted data is embedded in a URL token.

**Server:** openresty/1.29.2.3, Python 2.7 Flask (`. /main.py`, `./common.py`)

The core security model is broken at every level — custom base64 encoding, predictable AES-CBC mode without authentication, and SQL injection in the backend. This writeup walks through recovering all five flags.

---

## Reconnaissance

### Application Behavior

Browsing the application reveals:

- **Index page**: A form accepting `title` and `body`, a link to `/tracking.gif`
- **POST /**: Submitting the form redirects to `/?post=<token>` where the token is a modified base64 string
- **GET /?post=<token>**: Renders the decrypted paste — title in `<h1>`, body in `<pre>`, both HTML-escaped
- **/tracking.gif**: Returns a 1×1 GIF — a strong hint at an admin bot
- **/flag**, **/admin**, **/robots.txt**: 404

The `<img src="tracking.gif">` on every page is a classic CTF pattern — an admin bot visits submitted URLs and the tracking endpoint can log headers, hinting at blind exfiltration.

### Token Analysis

The token looks like base64 but uses non-standard characters:

```
0tn0dTMWbxGKSTfTmNRtzkhRVcVISJo-wKHpJErhP00dxuJs535hEqfVwu3cg2554ZbTRDKaryIt1APCKsTzau6!l!PtO!PE4cZgpqrUo6nVuXpqDWG-1re!Q4D4jnxfI2!8OoWwGwErBnL-qDFLXbuLTFe4WkGmLobDDiagr2HGLXQRGFDgvJjxdzmKZXAyKna8W-wMVD!8nauNBLlNDA~~
```

Three substitutions are applied:

| Standard Base64 | Custom Token |
|:---------------:|:------------:|
| `+` | `!` |
| `/` | `-` |
| `=` | `~` |

Decoding a token yields exactly **160 bytes** — 16 bytes of IV followed by 144 bytes (9 blocks) of AES-128-CBC ciphertext with PKCS#7 padding.

**Python helpers:**

```python
import base64

def decode_token(token):
    """Convert custom base64 token back to raw bytes."""
    b64 = token.replace('!', '+').replace('-', '/').replace('~', '=')
    return base64.b64decode(b64)

def encode_token(data):
    """Encode raw bytes into custom base64 token."""
    b64 = base64.b64encode(data).decode()
    return b64.replace('+', '!').replace('/', '-').replace('=', '~')
```

The decode mapping (confirmed from tracebacks in `common.py`) is: `~` → `=`, `!` → `/`, `-` → `+`.

---

## Flag 0 — Encoding Error

**Method:** Malformed input

Submitting a token that cannot be decoded as valid base64 triggers an unhandled `ValueError`:

```
ValueError: Input is not valid base64
```

The error page includes the application source paths and partial stack traces. Flag 0 is awarded for discovering the custom encoding.

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

---

## Flag 1 — Error Page Disclosure

**Method:** Forced server errors

Any error page (invalid padding, malformed JSON, etc.) includes the flag in its output. This is the classic "check error messages" pattern — Flag 1 is leaked on every unhandled exception page, appearing before the traceback.

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Error pages in CTFs should always be inspected for embedded flags.

---

## Flag 2 — CBC Bit-Flipping

**Method:** IV manipulation to alter plaintext

### The Oracle

Modifying the last byte of a ciphertext block and observing the response reveals a **padding oracle**:

- **Valid padding** → page renders (possibly garbled) or `UnicodeDecodeError`
- **Invalid padding** → `PaddingException` raised

This distinct behavior lets us test one byte at a time.

### Token Structure

```
[ 16-byte IV ][ 144 bytes ciphertext = 9 blocks × 16 bytes ]
```

The plaintext is JSON:

```json
{"flag": "^FLAG^<64-char-hex>$FLAG$", "id": "N", "key": "<base64-key>"}
```

### The Attack

In AES-CBC, the IV is XORed with the first plaintext block after decryption:

```
P₁ = AES_Decrypt(C₁) ⊕ IV
```

We know the first 16 bytes of the plaintext are `{"flag": "^FLAG^`. We want `{"id":"1"}` instead (which would make the server query post ID 1, a different paste from the admin's set).

The XOR difference between what we have and what we want:

```
P_current  = {"flag": "^FLAG^
P_desired  = {"id":"1"}\x06\x06\x06\x06\x06\x06

IV_new = IV ⊕ P_current ⊕ P_desired
```

**Critical insight:** If we also truncate the token to only 32 bytes (IV + 1 ciphertext block), the server only sees the first block which now reads `{"id":"1"}` with valid PKCS#7 padding (`\x06` × 6). The remaining ciphertext blocks are discarded.

Sending the modified, truncated token returns a `KeyError: 'key'` because post ID 1 has no `key` column in the database — but the error page's title field contains the flag.

> **Flag 2:** `^FLAG^<redacted>$FLAG$`

---

## Flag 3 — Full Padding Oracle Decryption

**Method:** Byte-by-byte decryption of all ciphertext blocks

### Algorithm

For each ciphertext block, we brute-force its preceding block (or IV) to produce valid PKCS#7 padding for each padding value 1–16:

```
For target_pad in [1, 2, ..., 16]:
    For byte_val in [0, 1, ..., 255]:
        Modify the byte at position (16 - target_pad) in C_prev
        Send modified token to server
        If valid padding:
            Recover plaintext byte
            Fix subsequent bytes for next target_pad
```

The relationship:

```
P_byte = found_byte ⊕ original_prev_byte ⊕ target_pad
```

This gives us the intermediate state, which XORed with the original preceding block yields the plaintext.

### Implementation

A parallelized Python script using `ThreadPoolExecutor`:

- **Batch size:** 8 byte guesses per HTTP batch
- **Outer workers:** 2 (decrypting 2 blocks in parallel)
- **Inner timeout:** 15 seconds per batch (prevents request hangups)
- **Retry logic:** `urllib3.Retry` with 3 retries and 0.5s backoff
- **Connect timeout:** 5s, **read timeout:** 10s

The CTF server has ~4.7s latency per request, so full decryption takes approximately 2 hours.

### Result

9 blocks decrypted yields the complete plaintext:

```json
{"flag": "^FLAG^<redacted>$FLAG$", "id": "Zog~~"}
```

> **Flag 3:** `^FLAG^<redacted>$FLAG$`

---

## Flag 4 — SQL Injection via Encrypted Token

**Method:** Padding oracle encryption + SQL UNION injection + admin bot

### The SQL Injection Vector

The server queries the database using Python string formatting:

```python
cur.execute('SELECT title, body FROM posts WHERE id=%s' % id)
```

The `id` field comes from the decrypted JSON `{"id": "..."}` — no parameterized queries, direct string interpolation.

### The Admin Bot

The `<img src="tracking.gif">` tag on every page triggers an admin bot that:

1. Visits user-submitted pages via `localhost`
2. Records the request headers in a `tracking` table with columns `(id, headers)`

### The Attack Chain

**Step 1:** Encrypt an SQL injection payload using the padding oracle. Since we now know the AES key behavior through the oracle, we can encrypt arbitrary strings and prepend a valid IV.

The payload replaces the `id` field with a SQL UNION injection:

```sql
' UNION SELECT id, headers FROM tracking WHERE headers LIKE '%flag%' --
```

**Step 2:** The admin bot visits the crafted URL, and the malicious SQL query extracts headers from the `tracking` table.

**Step 3:** The response reveals an admin-created post that contains the final flag.

> **Flag 4:** `^FLAG^<redacted>$FLAG$`

---

## Complete Flag List

| Flag | Hash | Technique |
|:----:|------|-----------|
| 0 | `<redacted>` | Malformed base64 → encoding error disclosure |
| 1 | `<redacted>` | Error page disclosure (appears on all error pages) |
| 2 | `<redacted>` | CBC bit-flipping (`{"id":"1"}` via IV XOR) |
| 3 | `<redacted>` | Padding oracle full decryption of token |
| 4 | `<redacted>` | SQLi via encrypted token → admin bot headers |

---

## Key Takeaways

1. **Never roll your own crypto.** Custom base64 and AES-CBC without authentication (no HMAC/GCM) make the application trivially exploitable via bit-flipping and padding oracle attacks.

2. **Padding oracles are devastating.** A single bit of information ("padding valid" vs "padding invalid") is enough to fully decrypt and forge ciphertexts, even without knowing the key.

3. **Error pages leak information.** Both Flag 1 and Flag 2 were obtained from error page output — always inspect stack traces and error messages in CTFs.

4. **CBC without integrity checking** allows arbitrary plaintext manipulation through IV/ciphertext XOR operations.

5. **Parameterized queries** are non-negotiable. String formatting in SQL (`%s` instead of `?`) combined with user-controlled input creates a direct path to database compromise — in this case, through an encrypted channel.

---

## References

- [CBC Bit-Flipping Attack](https://en.wikipedia.org/wiki/Bit-flipping_attack)
- [Padding Oracle Attack](https://en.wikipedia.org/wiki/Padding_oracle_attack)
- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
