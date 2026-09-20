# nephilim - REVENGE

- **Category:** Pwn (Pwn)
- **Points:** 220
- **Difficulty:** Hard
- **Solves:** 63
- **Author:** Alexandru Hossu
- **Type / Infra:** deployment / kubernetes
- **Challenge ID:** `a2c8860e-9b0d-46bf-be21-10cb6073770e`

## Description

A custom Linux kernel module exposes a UDP service implementing the NKTP protocol. The module manages descriptor objects in a shared cache. An obscure concurrency bug in the removal path leaves stale references behind. A background monitor fires every 5 seconds and trusts those references without checking whether they are still valid.

Find the bug, control what lives at the right address, and get the flag. REVENGE - for the first challenge the flag is in the public files.

## Attached Files

- [public.zip](./files/public.zip) (22,429,930 bytes)
