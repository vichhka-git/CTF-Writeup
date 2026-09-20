---
title: "Juggler"
ctf: "CSAW CTF Qualifications 2026"
date: 2026-09-20
category: web
difficulty: medium
points: 465
flag_format: "csaw{...}"
author: "cursor-grok-4.6"
---

# Juggler

## Challenge Information

- **Name:** Juggler
- **Category:** Web
- **ID:** 11
- **Points:** 465
- **Author:** 3p1cac
- **Stack:** PHP 8.2 / Apache / SQLite
- **Flag:** `csaw{tw0_f0r_0n3_2gc9w2hz}`

## Summary

The title and description name both bugs: **mass** assignment of session keys
from a JSON profile update, and PHP **type juggling** in a non-strict
`in_array` admin check. Set `$_SESSION["role"] = true` and `/admin.php` treats
it as an admin role.

## Solution

### Step 1: Mass assignment

`dashboard.php` includes `profile_update.php` on `POST` with
`Content-Type: application/json`. That handler copies every JSON key that
already exists in `$_SESSION`:

```php
foreach ($jsonData as $jsonKey => $jsonValue) {
    if (array_key_exists($jsonKey, $_SESSION))
        $_SESSION[$jsonKey] = $jsonValue;
```

After login, session keys include `user_id`, `username`, `role`, and
`csrf_token`. A JSON body can therefore overwrite `role` with a boolean.

### Step 2: Loose `in_array`

`admin.php` loads role names from `config.ini` and checks:

```php
if (!isset($_SESSION["role"]) || !in_array($_SESSION["role"], $adminRoles))
    header("Location: index.php");
```

No third argument, so comparison is loose. In PHP, `true == "any-nonempty-string"`
is `true`, so `in_array(true, ["placeholder_admin_role1", ...])` succeeds.
The panel then prints `file_get_contents("../flag.txt")`.

### Step 3: Reproduce

```text
python3 agent_workspace/solve.py http://HOST:80
```

Register, login, `POST /dashboard.php` with
`{"username":"...","password":"","role":true,"csrf_token":"..."}`, then
`GET /admin.php`.

## Flag

`csaw{tw0_f0r_0n3_2gc9w2hz}`
