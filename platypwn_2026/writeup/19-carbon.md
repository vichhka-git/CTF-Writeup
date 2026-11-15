# Carbon (fullpwn) — 2 flags

**Flags:**
`PP{c4rb0n_c4ch3d_s3ss10n_r3pl4y::yNF50podsr4G}` (user)
`PP{0p3r4t0r_3nv_1s_r00t::M93Zj-UWVVDj}` (root)

A Node.js (Next.js 15.5.6) application on a Linux box with a Redis and an
internal admin API on loopback.

## User flag — Next.js RSC RCE (CVE-2025-55182)

1. Fingerprint: response headers show Next.js 15.5.6. The RSC action path is
   reachable at `POST /` with `Next-Action: <id>`.
2. Send a multipart POST carrying a `Next-Action` header and a crafted
   chunk/value gadget that the RSC decoder resolves into arbitrary function
   invocation — the known payload pattern uses a `then` getter chain
   (`$1:__proto__:then`) to escape the decoder's sandbox and reach
   `Function`/`eval`-like execution.
3. The RCE runs as the `nextjs` user. Land a callback (reverse shell or
   response-echo) and read the filesystem.
4. `/opt/carbon/ops-notes.md` hints at the internal services.

## Root flag — Redis session replay + operator chain

1. The app talks to Redis on `127.0.0.1:6379`. Read the operator's cached
   session: `redis-cli GET session:operator` — it holds an operator session
   token.
2. The internal admin API on `127.0.0.1:9000` accepts
   `/admin/operator-credential` with `Authorization: Bearer <token>` and
   returns the **operator OS password** (cached session replay).
3. `su - operator` with that password.
4. `sudo -l` shows `(root) NOPASSWD: /usr/bin/env`.
5. `sudo -n /usr/bin/env /bin/sh -c 'cat /root/root.txt'` → root flag.

Flag texts map to the chain: "carbon cached session replay" (the Redis
session) and "operator env is root" (the sudo env one-liner).
