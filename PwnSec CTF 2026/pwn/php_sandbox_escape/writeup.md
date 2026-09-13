---
title: "PHP Sandbox Escape"
ctf: "PwnSec CTF 2026"
date: 2026-09-12
category: pwn
difficulty: hard
points: 220
flag_format: "pwnsec{...}"
---

# PHP Sandbox Escape

## Summary

Arbitrary `eval($_POST[cmd])` behind a huge `disable_functions` list and `open_basedir`. Class methods are not disabled. `SplFileObject` writes a shared object under `/tmp`; PHP 8.6's `Pdo\Sqlite::loadExtension` dlopens that path (it does not consult `sqlite3.extension_dir`). A constructor runs `/readflag`.

## Solution

### Step 1: leftover APIs

`fwrite`/`dl`/`ini_set` are disabled. Live internals include `fopen`, `hex2bin`, `SplFileObject`, `SQLite3`, and `Pdo\Sqlite`. `SQLite3::loadExtension` exists but errors with "SQLite Extensions are disabled" because `sqlite3.extension_dir` is empty (INI_SYSTEM). `Pdo\Sqlite::loadExtension` has no such check: it `realpath`s the argument and `sqlite3_load_extension`s it.

### Step 2: native helper

Compile a tiny `.so` (Ubuntu 24.04, matching the handout image) whose constructor does `system("/readflag > /tmp/flagout")`. Upload it as hex via `SplFileObject::fwrite(hex2bin(...))`, then:

```php
$pdo = new Pdo\Sqlite("sqlite::memory:");
$pdo->loadExtension("/tmp/pwn.so");
echo (new SplFileObject("/tmp/flagout"))->fgets();
```

`disable_functions` does not apply to object methods. Flag: `pwnsec{636ff69c21faa1db}`.

## Rejected

`SQLite3::enableLoadExtension` is gone in this 8.6.0-dev; the sqlite3 INI gate is a decoy. `.user.ini` cannot widen `open_basedir` or set `sqlite3.extension_dir`. `/proc` basedir tricks are canonicalized. FFI is not compiled. Do not rebuild php-src from current git — the remote is an unpinned snapshot.
