# nephilim - REVENGE

Revenge is the same NKTP kernel-module challenge as original nephilim, with the planted `/flag` removed from the public initrd.

`nkrcu.ko` / `nknet.ko` / `nkmon.ko` `.text` hashes match the first challenge, as do `bzImage` and `vmlinux`. The public initrd still contains `./flag`, but the body is `CTF{fake_local_flag_not_the_real_one_exploit_on_remote_to_get_it}`.

## Bug

`nkrcu_snap_create` drops the RCU read-side critical section before storing a raw descriptor pointer in `nk_snaps`. `nkrcu_remove` + `synchronize_rcu` frees that object while the snapshot still holds it. `nkmon` wakes every 5 seconds on `system_wq` and calls `desc->ops[0](desc)` on each snapshot.

`nkrcu_info` leaks `_printk` and `nkrcu_pivot` (`mov rsp, [rdi]; ret`). `nkrcu_spray_alloc` reallocates the same kmalloc-128 cache.

## Exploit

1. Create descriptors that will hold flag bytes.
2. Leak KASLR from `nkrcu_info` using the original vmlinux `_printk` offset.
3. Spray a `/flag` path + `loff_t` positions, then ROP chunks (`filp_open` / `kernel_read`) separated by padding so the hijacked stack can grow downward.
4. Snapshot + remove a victim descriptor, reclaim it with a fake `ops` pointer to `nkrcu_pivot`.
5. Wait for `nkmon`, then read the flag back through `nkrcu_info`.

Remote recovered:

```
CTF{27b4e49556e5770960207de9e65725b3e400de76aa1e48d1b2bea697da3eacac}
```
