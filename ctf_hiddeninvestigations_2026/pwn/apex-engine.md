# Apex Engine

Pwn, 55 points, 525 solves. A TLS service runs a multi-threaded settlement engine behind a six-item
menu: view an account, start escrow transfers, withdraw, upgrade the account tier, open a secure
enclave and exit. The chain is a race between eight settlement workers, an unsigned
comparison on the wrapped balance, and a path check that runs before the file it guards is
opened.

## What you are given

`pwn-apex-engine.zip` expands to one file, `challenge`, 14,472 bytes: ELF64 x86-64 PIE, stripped,
dynamically linked, pthreads. No source ships and there is no local service.

The portal supplies `<challenge-host>` and `<port>` for a TLS instance. The client wraps the socket
with `ssl`, disables certificate verification and passes the same name as `server_hostname`. No
login material is issued.

The menu strings are enough to navigate:

```
1. View Account & Holdings        4. Upgrade Account Tier (VIP: 10,000 credits)
2. Initiate Escrow Transfer       5. Access Secure Vault Enclave
3. Withdraw from Escrow Vault     6. Exit
```

## Reproduction

1. Look at the account. Option 1 prints `=== [APEX SETTLEMENT ENGINE - ACCOUNT STATUS] ===` with
   `Cash Balance`, `Escrow Vault` and `Account Tier`. A fresh session starts at 100 credits and
   `STANDARD TIER (Basic)`.

2. Read the transfer path. Option 2 asks `Transfer Amount:`, compares the amount against the
   balance, prints `[+] Order #n submitted for async settlement.` and detaches a settlement
   worker (0x1ef0). That worker sleeps `usleep(0x61a8)`, 25 ms, before it debits `cash` (at
   0x43e0) and credits `escrow` (at 0x43e8). The check happens in the request thread and the
   accounting happens 25 ms later, with no reservation of funds in between.

3. Race the check. Write eight `2\n100\n` pairs into the socket in a single `sendall`. All eight
   workers pass `cash >= 100` while the balance is still 100. When they settle, cash is
   `100 - 800` modulo 2^64 and escrow is 800. The service caps orders in flight (there is a
   `Maximum concurrent orders reached` path), and eight is what the accepted run used.

4. Upgrade. Option 4 compares the balance with 10,000 (`cmp cash, 0x270f` then `jbe deny`) and the
   comparison is unsigned, so the wrapped balance passes. The service answers
   `[+] Congratulations! Your account has been upgraded to VIP Tier.` and then
   `[+] Secure Vault Enclave storage is now accessible.`

5. Enter the enclave. Option 5 prints `--- [SECURE VAULT ENCLAVE] ---` with a second menu:
   `1. Create Document Slot`, `2. Stream Document via Enclave`, `3. Edit Document Target Path`,
   `4. Return to Main Menu`. Create slot 0 with `1` then `0`. The slot is initialised with a
   default preview target that does not contain the substring `flag`.

6. Read the check. Option 2 dispatches a streaming thread (0x1d80) which runs
   `strstr(slot->path, "flag")`, sleeps 25 ms, then calls `fopen(slot->path, "r")`. A match prints
   `[-] SECURITY ALERT: Access to '%s' denied!`. Option 3 (0x1998) rewrites `slot->path` from an
   unvalidated `fgets` and imposes no check of its own.

7. Land the edit inside the sleep. Send the stream request, one rejected menu choice to burn an
   extra iteration, and then the edit, all in one write:

   ```
   2
   0
   9
   3
   0
   /flag
   ```

   The `9` produces `[-] Unknown choice.` and costs one enclave menu turn, which puts the edit
   after the `strstr` and still inside the 25 ms window. The streaming thread then opens `/flag`
   and prints its contents inside the `[SECURE ENCLAVE DATA STREAM]` block.

8. Retry as needed. The timing is per connection. The accepted run tried four paddings (none, one,
   two and four throwaway choices) in that order and stopped at the first connection that returned
   the flag. The captured flag was saved locally, and the submission log
   records it accepted (`goodFlag`, 30 October 2026).

9. What the notes do not record: which padding produced the accepted run, and the exact balance
   digits the service printed after the wrap. The exploit needs the wrap to happen, not any
   particular displayed value.

## Why it works

Three independent mistakes stack. The settlement worker checks the balance when the order is
accepted and updates it 25 ms later, so concurrent orders all spend credits that exist once. The
tier gate then compares the resulting balance as an unsigned 64-bit value, so the underflow reads
as an enormous positive balance. Finally, the enclave tests the target path for the substring
`flag` long before it opens the file, and leaves a writable field in the gap, so a legal edit
during the sleep changes which file is opened. Fixing any one of the three would break the chain.

## Flag

```
hiCTF{t0ct0u_mult1thr34d_r4c3_c0nd1t10n_w1n_8d3f_73d9174dc9}
```
