# Freal World Manipulation

* **Category:** PWN
* **Difficulty:** Medium (97 solves)
* **Points:** 122
* **Flag:** `pwnsec{e33587a46b3eaecd}`

## Summary

`freal` is an Ubuntu 22.04 x86_64 service implementing custom big-decimal / IEEE-754 arithmetic in BSS (`decimal`). With all mitigations enabled (Full RELRO, PIE, Canary, NX), the service manages arbitrary decimal structures using an internal array of pointers, capacities, and an allocated byte budget.

## Vulnerability & Primitive Chain

1. **PIE Leak**: `view(-11)` reads backward from `decimal` into RELRO data, hitting `__dso_handle` (`pie + 0x5008`). Its value points to itself, leaking the PIE base address.
2. **Capacity Overflow**: Calling `add` 90 times with 8MiB limbs (`0x800000`) satisfies `calibrated()` (`budget > 0x1fffffff`). Performing a multiplication (`multiply(0, 1, upward)`) on two large finite values (e.g. `1e200 * 1e200`) overflows to `+Inf` and recalculates `capacity`:
   ```c
   capacity = ((usable_a >> 4) * (usable_b >> 4)) << 7;
   ```
   This sets `capacity` to an immense value, opening up arbitrary read/write via large positive index `I = (target - decimal) / 8`.
3. **Mmap Spray & Leak**: Because the heap is ASLR-separated from PIE (~171MB away), we spray mmap allocations filling them with `pie + 0x5020`. Stride-walking looking for pointer values (`0x7f...`) allows dumping the `stdout` `FILE*` and heap base.
4. **House of Apple 2**: Overwriting the `stdout` `FILE` structure with a crafted fake structure pointing `_wide_data` and wide vtable to `system("/bin/sh")` executes a shell when `puts` is called on menu exit.

## Exploit Script

See [`spray_fill.py`](./spray_fill.py) for the complete exploit chain against the challenge instance.

## Flag

```
pwnsec{e33587a46b3eaecd}
```
