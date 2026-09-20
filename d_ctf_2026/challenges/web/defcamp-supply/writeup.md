# DefCamp CTF 2026: DefCamp Supply (Web) - Writeup

## Challenge Overview
- **Category:** Web
- **Points:** 445
- **Type:** deployment / kubernetes
- **Provided Artifacts:** `public.zip` containing partial backend component (`profile_check.py`, `verify_profile.py`, templates, static assets)

## Vulnerability Analysis

### 1. Race Condition on `/redeem`
Every session starts with 0 credits and can normally claim 2 starter credits once via `POST /redeem`. However, the backend lacks database transaction locking/concurrency control. Sending 16 concurrent requests via a thread pool results in multiple claims executing simultaneously, inflating account balance to 32 credits (well above the 20 credits required to unlock the premium `zero_day_debugger`).

### 2. Business Logic Flaw in ETA Calculation
Orders queued via `/checkout` calculate delivery ETA using `quantity`. Setting `quantity` to a negative number such as `-30` produces a negative ETA (`eta <= 0`), causing the application to treat the order as instantly delivered/processed (`status: "done"`) and triggering the profile verification routine (`verify_custom_profile`).

### 3. Command Injection in Custom Profile Verification
`profile_check.py` implements custom profile verification via:
```python
def verify_custom_profile(profile: str) -> str:
    command = f'python3 verify_profile.py "{profile}"'
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return (completed.stdout + completed.stderr).strip()
```
Because `profile` is directly interpolated into a shell string with `shell=True`, passing a crafted profile such as:
```text
stealth"; cat /home/ctf/flag.txt #
```
escapes the python invocation, executes arbitrary shell commands on the container as the `ctf` user, and embeds stdout in the order result.

## Exploit Chain & Reproduction
1. Establish a new session with `http://<host>:<port>/`.
2. Concurrently fire 16 `POST /redeem` requests to accumulate >= 20 credits.
3. Submit `POST /checkout` with:
   - `item_id`: `zero_day_debugger`
   - `quantity`: `-30`
   - `profile`: `stealth"; cat /home/ctf/flag.txt #`
4. The response immediately returns `status: "done"` and `result` containing the flag.

## Flag
`CTF{00fd1af2af55ba826af4759fc024770d7ae720622e457b570d16224a8f43b5e2}`
