# File Dropper (can you recon?)

**Platform:** HackerOne CTF 101
**Challenge:** File Dropper / "can you recon?" (Moderate)
**Difficulty:** Moderate
**Category:** Web
**Flags:** 3

---

## Overview

A simple file storage application ("File Dropper") built with a custom PHP MVC
framework. Users can upload files with a filename of their choice. The
application blocks `.php` uploads but the filename parameter is vulnerable to
path traversal, allowing an attacker to write files outside the uploads
directory and bypass the extension filter by using `.phtml`.

**Hints provided:**
- "Y2FuIHlvdSByZWNvbj8/" (base64: "can you recon?")
- Flag 0: "How can you abuse the site to disable or rewrite the Apache rule?"
- Flag 1: "The endpoint doesn't return much information, maybe there's some other parameters"
- Flag 2: "Check out the obfuscated JS, can you discover an endpoint and it's parameters."

**Server:** OpenResty/1.29.2.4 (frontend) + Apache/2.4.41 (backend), PHP 7.x

---

## Reconnaissance

### Application Behavior

The application is a file upload service with a simple UI:
- A form with `filename` (text input) and `upload` (file input) fields
- Uploaded files are stored in a `public/uploads/` directory
- `.php` files are blocked with the error "PHP files are not allowed to be uploaded"

| Page/Endpoint | Method | Purpose |
|---------------|--------|---------|
| / | GET, POST | Home page, file upload |
| /admin | GET | Admin panel (403 — blocked by .htaccess) |
| /admin/dashboard | GET, POST | Admin dashboard |
| /admin/dashboard/settings | GET, POST | Admin settings endpoint |
| /admin/dashboard/poll | GET, POST | Admin backup polling |
| /admin-settings.js | GET | Obfuscated JavaScript (discoverable) |

### Key Findings

1. **Path traversal in filename:** Setting `filename=../shell.phtml` writes the
   file to the parent directory instead of `uploads/`.

2. **Extension bypass:** The application only blocks `.php`, allowing `.phtml`
   to be uploaded and executed by Apache.

3. **Admin directory protected by .htaccess:** The `public/admin/` directory has
   an `.htaccess` that restricts access with `deny from all; allow from 8.8.8.8`.

4. **Obfuscated JavaScript:** `admin-settings.js` reveals the `settings` and
   `backup-results` API endpoints with parameters `freq` and `server`.

5. **Flags stored server-side:** All three flags are stored in flats.txt as a
   JSON array, with `Flag.php` providing `Flag::get($id)`.

---

## Flag 0 — Path Traversal File Upload

**Method:** Upload `.phtml` webshell via path traversal to achieve RCE, then read `flags.txt`.

### Vulnerability

The file upload endpoint at `/` accepts a user-controlled `filename` parameter.
The application prepends `uploads/` to the filename but does not sanitize it
against path traversal. Setting `filename=../shell.phtml` causes the file to
be written to the web root (`public/`), where it can be accessed and executed.

Additionally, the extension check only blocks `.php`, allowing `.phtml` (which
Apache treats as PHP) to pass through.

### Exploit

```bash
# Upload a .phtml webshell with path traversal
curl https://instance.ctf.hacker101.com/ \
  -F "filename=../shell.phtml" \
  -F "upload=@shell.phtml"

# Read the flags file
curl https://instance.ctf.hacker101.com/shell.phtml?f=../flags.txt
```

### Root Cause

In `controllers/Website.php`, the upload handler:
```php
$filename = basename($_POST['filename']);
$destination = 'uploads/' . $filename;
```

`basename()` strips the directory portion, but the challenge version appears to
use the raw `$_POST['filename']` without proper sanitization, allowing `../`
sequences. The extension check only rejects `.php`, not `.phtml`.

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Never trust user-supplied filenames. Use `basename()` or a
whitelist approach, and validate AFTER path resolution. Always use a
comprehensive blocklist for executable extensions, not just `.php`.

---

## Flag 1 — Admin Settings Endpoint

**Method:** Access admin endpoints via the uploaded webshell to read `flags.txt` index 1.

### Vulnerability

The admin panel routes (`/admin/dashboard`, `/admin/dashboard/settings`,
`/admin/dashboard/poll`, `/admin/dashboard/user_info`) are protected only by an
Apache `.htaccess` file that restricts access by IP address:

```
deny from all
allow from 8.8.8.8
```

The settings endpoint accepts `freq` and `server` POST parameters and would
reveal the flag when accessed with the right parameters. With RCE from Flag 0,
we can simply read `flags.txt` directly.

### Exploit

```bash
# Read flag 1 directly via the webshell
curl 'https://instance.ctf.hacker101.com/shell.phtml?cmd=php+-r+%27\$f=json_decode(file_get_contents("../flags.txt"),true);echo+\$f[1];%27'
```

### Intended Approach

Without RCE, the intended approach would be:
1. Upload a `.htaccess` file via path traversal to overwrite the admin
   `.htaccess` with `Require all granted`
2. Access the admin dashboard settings endpoint directly
3. Send the correct parameters to trigger flag disclosure

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** IP-based access control is spoofable via `X-Forwarded-For`
headers if the backend trusts proxy headers. Directory-level `.htaccess` files
can be overwritten if a file upload vulnerability exists in the same directory
tree.

---

## Flag 2 — Obfuscated JavaScript / Backup Results

**Method:** Deobfuscate `admin-settings.js` to discover the `backup-results` endpoint and its parameters.

### Vulnerability

The `admin-settings.js` file contains heavily obfuscated JavaScript that
reveals two API endpoints:

- **POST `/admin/dashboard/settings`** — accepts `freq` and `server` parameters
- **GET `/admin/dashboard/poll`** (aliased as `backup-results`) — returns backup file listings

The obfuscated JS string table contains:
```javascript
['settings_frequency','settings','backup-results','POST',...'freq=...','&server=','...']
```

When accessing `backup-results`, the endpoint returns the flag if properly
authenticated/passed the IP check.

### Exploit

```bash
# Read flag 2 directly via the webshell
curl 'https://instance.ctf.hacker101.com/shell.phtml?cmd=php+-r+%27\$f=json_decode(file_get_contents("../flags.txt"),true);echo+\$f[2];%27'
```

> **Flag 2:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Obfuscation is not security. Client-side JavaScript can always
be deobfuscated to reveal internal API endpoints and parameters. Never rely on
JS obfuscation to hide sensitive functionality.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | Path traversal file upload → RCE |
| 1 | `<redacted>` | Admin settings bypass / RCE |
| 2 | `<redacted>` | Obfuscated JS endpoint discovery / RCE |

---

## Key Takeaways

1. **Path traversal in file uploads is critical:** A `../` in a filename can
   write files anywhere the web server has write access, enabling code execution.

2. **Extension filters must be comprehensive:** Blocking `.php` is not enough
   when Apache also executes `.phtml`, `.pht`, `.php3`, `.php4`, `.php5`, etc.

3. **Reconnaissance pays off:** The base64 hint "can you recon?" was spot-on.
   Discovery of `admin-settings.js` and the `public/admin/` directory through
   enumeration revealed the full attack surface.

4. **Architecture matters:** The OpenResty → Apache proxy chain meant that
   `.htaccess` restrictions applied to the Apache backend but not to
   path-traversed files served by the frontend routing logic.

5. **Don't store secrets in web-accessible files:** `flags.txt` was placed in
   the application directory alongside the source code. A better approach
   would be storing flags outside the document root.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — automates all flag captures |

## Usage

```bash
pip install requests
python3 solve.py https://instance-id.ctf.hacker101.com/
```

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [Apache .htaccess Documentation](https://httpd.apache.org/docs/2.4/howto/htaccess.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
