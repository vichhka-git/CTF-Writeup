# Hackyholidays CTF (Grinch Networks)

**Platform:** HackerOne CTF (Hacker101)
**Challenge:** Hackyholidays CTF (Grinch Networks)
**Difficulty:** Moderate
**Category:** Web
**Flags:** 12

---

## Overview

A multi-flag CTF challenge featuring the Grinch Networks application — a full-stack web app with a suite of interconnected services including a people rater, swag shop, forum, quiz, signup manager, and attack box. Each service contains a distinct vulnerability class, progressively increasing in complexity from simple information disclosure to blind SQL injection, buffer overflow emulation, and DDoS orchestration.

**Server:** openresty/1.29, PHP 7.x, Python 2.7 Flask

---

## Reconnaissance

### Application Behavior

The challenge presents a navigation page linking to multiple sub-applications. Each sub-application is a self-contained web service with its own attack surface.

| Page/Endpoint | Method | Purpose |
|---------------|--------|---------|
| / | GET | Main menu / nav page |
| /robots.txt | GET | Disallowed paths |
| /s3cr3t-ar3a/ | GET | Hidden jQuery-based page |
| /people-rater/ | GET | Rate people by ID |
| /swag-shop/ | GET | Shopping application |
| /secure-login/ | GET/POST | Login form |
| /my-diary/ | GET | Template-based diary viewer |
| /hate-mail-generator/ | GET/POST | Email template generator |
| /forum/ | GET/POST | Discussion forum |
| /evil-quiz/ | GET/POST | Quiz application |
| /signup-manager/ | GET/POST | User signup form |
| /attack-box/ | GET/POST | DDoS attack panel |

### Key Findings

1. **robots.txt exposure**: The `/robots.txt` file contains a hidden path hint and the first flag.
2. **jQuery obfuscation**: The `/s3cr3t-ar3a/` page loads a heavily obfuscated `jquery.min.js` containing hex flag fragments.
3. **Insecure API endpoints**: The People Rater and Swag Shop expose unauthenticated JSON APIs with IDOR and session leak vulnerabilities.
4. **Weak authentication**: The Secure Login and Forum use weak credentials that can be brute-forced or cracked.
5. **Template injection**: My Diary and Hate Mail Generator both suffer from server-side template injection.
6. **Blind SQL injection**: Evil Quiz's name field is vulnerable to boolean-based blind SQLi.
7. **PHP type juggling**: Signup Manager uses `is_numeric()` with `intval()`, enabling overflow via scientific notation.
8. **Hash cracking**: The Attack Box DDoS panel uses a predictable MD5 hash salt.

---

## Flag 0 — Robots.txt Disclosure

**Method:** Direct file access

### Vulnerability

The `/robots.txt` file is publicly accessible and contains a flag comment.

### Exploit

```bash
curl https://<instance>.ctf.hacker101.com/robots.txt
```

The response contains the flag directly in the file.

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Always check `/robots.txt` — it often leaks hidden paths and sometimes flags.

---

## Flag 1 — jQuery Obfuscation

**Method:** Static analysis of obfuscated JavaScript

### Vulnerability

The `/s3cr3t-ar3a/` page loads `/assets/js/jquery.min.js`, which is not the real jQuery but a heavily obfuscated script that constructs the flag from hex fragments stored in JavaScript variables.

### Exploit

The flag is built from 21 variable references in a specific order:
```
h1_1 + h1_2 + h1_3 + h1_1 + h3_0..h3_12 + h1_4 + h1_2 + h1_3 + h1_4
```

Each variable holds a hex fragment. The solve script extracts all `hX_Y` variables via regex and concatenates them in order.

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Obfuscated client-side code can still be statically analyzed. Look for patterns in variable naming and string construction.

---

## Flag 2 — IDOR on People Rater

**Method:** Insecure Direct Object Reference via base64-encoded JSON IDs

### Vulnerability

The People Rater application fetches records using base64-encoded JSON IDs. The IDs visible in the UI start at 2, but there is no access control check for id=1.

### Exploit

```python
b64_id = base64.b64encode(json.dumps({"id": 1}).encode()).decode()
r = requests.get(f"{base_url}/people-rater/entry/?id={b64_id}")
```

The response reveals the hidden admin record containing the flag.

> **Flag 2:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Always test for IDOR by enumerating adjacent IDs. Base64 encoding is not security — it is encoding.

---

## Flag 3 — Swag Shop Session Leak

**Method:** Unauthenticated API access to session data

### Vulnerability

The Swag Shop exposes `/swag-shop/api/sessions/` which returns all active sessions with their user UUIDs, without authentication. The `/swag-shop/api/user?uuid=` endpoint then reveals user data including the flag.

### Exploit

1. Fetch session list from `/swag-shop/api/sessions/`
2. Decode each session (base64) to find a logged-in user UUID
3. Query `/swag-shop/api/user?uuid=<uuid>` to retrieve user info containing the flag

> **Flag 3:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** API endpoints that leak session data are critical vulnerabilities. Never expose internal UUIDs or session tokens via unauthenticated APIs.

---

## Flag 4 — Secure Login ZIP Crack

**Method:** Brute-forced credentials + cookie tampering + password-protected ZIP

### Vulnerability

The Secure Login form accepts weak credentials (username: `access`, password: `computer`). After login, a cookie controls admin access. The admin panel reveals a password-protected ZIP file (`my_secure_files_not_for_you.zip`) with password `hahahaha`.

### Exploit

1. Brute-force login with `access:computer`
2. Tamper the session cookie to set `admin: true`
3. Download the protected ZIP file with the admin cookie
4. Extract using password `hahahaha`

```bash
unzip -P hahahaha my_secure_files_not_for_you.zip
```

> **Flag 4:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Never rely on client-side access controls. Cookie values can be tampered with. Use server-side authorization for sensitive operations.

---

## Flag 5 — My Diary Template LFI

**Method:** Server-side template inclusion bypass via str_replace abuse

### Vulnerability

The My Diary application loads templates by name, but blocks `admin.php` and `secretadmin.php` via `str_replace`. However, `str_replace` only removes the first occurrence and doesn't recurse.

### Exploit

Craft a payload that, after all `str_replace` removals, resolves to `secretadmin.php`:

```python
payload = "secretsecretadminadmin.php.phpadminadmin.php.php"
# After removing "secretadmin.php":  secret_____admin.php.admin.php
# After removing "admin.php":        secretadmin.php
```

> **Flag 5:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** `str_replace` is not a security control. Use proper allowlists or regex-based path validation for file inclusion.

---

## Flag 6 — Hate Mail Template Injection

**Method:** Server-side template injection via preview_data field

### Vulnerability

The Hate Mail Generator renders user-provided template markup with user-provided data. The template engine supports `{{template:filename}}` syntax, which includes arbitrary template files server-side.

### Exploit

Inject `{{template:38dhs_admins_only_header.html}}` into the `preview_data` name field:

```python
payload = "{{template:38dhs_admins_only_header.html}}"
data = {"preview_markup": "Hello {{name}}", "preview_data": {"name": payload}}
```

The admin-only template is rendered in the preview, revealing the flag.

> **Flag 6:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Template engines must sandbox user input. Never allow template directives in user-controlled data fields.

---

## Flag 7 — Forum Admin Post

**Method:** Credential reuse after phpMyAdmin leak and MD5 cracking

### Vulnerability

The phpMyAdmin panel is exposed and leaks user credentials. The forum admin password hash (MD5) can be cracked. Admin credentials `grinch:BahHumbug` grant access to a hidden forum post containing the flag.

### Exploit

1. Discover credentials via phpMyAdmin database dump leak
2. Crack the MD5 hash of the admin password (`BahHumbug`)
3. Login to the forum as `grinch:BahHumbug`
4. Access the admin-only post at `/forum/3/2/`

> **Flag 7:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Database leaks combined with weak password hashing (MD5) are a powerful attack chain. Always use strong, unique passwords.

---

## Flag 8 — Blind SQLi on Evil Quiz

**Method:** Boolean-based blind SQL injection

### Vulnerability

The Evil Quiz name parameter is vulnerable to boolean-based blind SQL injection. The application's response differs based on whether the injected condition is true or false, allowing character-by-character extraction of the admin password.

### Exploit

```sql
' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='S' --
```

Through iterative boolean-based extraction, the admin credentials are revealed:
- Username: `admin`
- Password: `S3creT_p4ssw0rd-$`

Login to `/evil-quiz/admin/` to retrieve the flag.

> **Flag 8:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Blind SQL injection requires patience but is fully automatable. Any difference in response (content, length, status code) can be used as an oracle.

---

## Flag 9 — Signup Manager Overflow

**Method:** PHP type juggling and integer overflow

### Vulnerability

The Signup Manager uses `is_numeric()` which accepts scientific notation (`1e9`), then `intval()` which converts it to `1000000000`. This large value overflows into adjacent memory in the serialized user record, specifically the admin flag byte at position 112. Setting `lastname` to a 9-character string with `Y` at index 8 sets the admin bit to 1.

### Exploit

```python
data = {
    "action": "signup",
    "username": "exploituser",
    "password": "exploitpass",
    "age": "1e9",           # intval → 1000000000 → overflow
    "firstname": "exploit",
    "lastname": "12345678Y" # Y at index 8 (9th char) modifies admin flag bit
}
```

The `1e9` age writes past the intended buffer bounds, allowing the 9th character of `lastname` (`Y` = 0x59) to toggle the admin bit, granting admin access and revealing the flag.

> **Flag 9:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** PHP's loose typing system (`is_numeric` accepting `1e9`, `intval` silently converting it) can lead to logic flaws. Always validate input types strictly.

---

## Flag 10 — Attack Box Login

**Method:** Lateral movement with r3c0n-server extracted credentials

### Vulnerability

The r3c0n-server (a separate reconnaissance service) leaks credentials through a nested SQL injection SSRF attack. The extracted credentials (`grinchadmin:s4nt4sucks`) are valid for the Attack Box login panel.

### Exploit

1. Use the r3c0n-server API with a nested SQLi SSRF to blind-enumerate credentials
2. Extract username `grinchadmin` and password `s4nt4sucks` via LIKE-based boolean queries
3. Login to `/attack-box/login/` with these credentials to get the flag

```python
data = {"username": "grinchadmin", "password": "s4nt4sucks"}
```

> **Flag 10:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Credential reuse across services amplifies the impact of any single breach. Segment authentication domains.

---

## Flag 11 — Attack Box DDoS (0.0.0.0)

**Method:** Hash salt cracking + localhost bypass + payload chaining

### Vulnerability

The Attack Box DDoS panel requires a signed payload using an MD5 hash with a secret salt. The salt (`mrgrinch463`) can be cracked from known plaintext attacks. The target validation checks for `127.0.0.1` or `localhost` but fails to block `0.0.0.0`, which also routes to localhost. The completed attack log contains a `goto` redirect that leads to a challenge-completion page with the flag.

### Exploit

1. Crack the MD5 hash salt: `mrgrinch463` (found via known plaintext attack on observable hashes)
2. Craft a payload targeting `0.0.0.0` with a valid hash:
   ```python
   h = hashlib.md5(("mrgrinch463" + "0.0.0.0").encode()).hexdigest()
   payload = base64.b64encode(json.dumps({"target": "0.0.0.0", "hash": h}))
   ```
3. Launch the attack via `/attack-box/launch/?payload=<payload>`
4. Poll the attack JSON log until a `goto` entry appears
5. Follow the `goto` redirect to the completion page for the flag

> **Flag 11:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Input validation bypasses are common with IP address parsing. `0.0.0.0` is a valid way to reach localhost that many filters miss. Always use allowlists for localhost detection, not blocklists.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | robots.txt disclosure |
| 1 | `<redacted>` | jQuery obfuscation analysis |
| 2 | `<redacted>` | IDOR via base64-encoded JSON |
| 3 | `<redacted>` | Swag Shop session leak |
| 4 | `<redacted>` | Weak credentials + cookie tamper + ZIP crack |
| 5 | `<redacted>` | str_replace LFI bypass |
| 6 | `<redacted>` | Server-side template injection |
| 7 | `<redacted>` | phpMyAdmin leak + MD5 crack |
| 8 | `<redacted>` | Blind SQLi password extraction |
| 9 | `<redacted>` | PHP type juggling overflow |
| 10 | `<redacted>` | r3c0n-server credential pivot |
| 11 | `<redacted>` | Hash salt crack + 0.0.0.0 bypass |

---

## Key Takeaways

1. **Information disclosure**: Always check `/robots.txt`, source maps, and API documentation endpoints for leaks.
2. **Encoding ≠ encryption**: Base64, URL encoding, and hex encoding are reversible — never use them as security controls.
3. **IDOR is everywhere**: Increment IDs, especially in API parameters, even when they look random or encoded.
4. **Cookie tampering**: Client-side session data (base64-encoded JSON in cookies) can always be modified.
5. **PHP type juggling**: `is_numeric()` + `intval()` is a dangerous combination — scientific notation can bypass length checks.
6. **Blind SQLi automation**: Boolean-based blind SQL injection is tedious by hand but trivial to automate with a script.
7. **Template injection**: Any template engine fed user input is a potential RCE or data leak vector.
8. **Credential reuse**: Users and services that share passwords across boundaries create easy lateral movement paths.
9. **Hash cracking**: MD5 salts can be recovered via known-plaintext attacks on observable hash outputs.
10. **Input validation bypass**: `0.0.0.0` bypasses naive localhost checks — always use allowlists for network validation.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — automates all 12 flag captures |

## Usage

```bash
pip install requests
python3 solve.py https://<instance-id>.ctf.hacker101.com/
```

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [PHP is_numeric documentation](https://www.php.net/manual/en/function.is-numeric.php)
- [PHP intval documentation](https://www.php.net/manual/en/function.intval.php)
- [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP Blind SQL Injection](https://owasp.org/www-community/attacks/Blind_SQL_Injection)
