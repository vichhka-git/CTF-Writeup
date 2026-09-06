# Bug Where

## Summary

Unprivileged guest uid 1337 in nsjail-wrapped QEMU TCG. The flag is `DYN_FLAG` on a 1MiB IDE disk (`/dev/sda`), not in the initramfs. Two author-planted pieces both pay:

1. QEMU `0F 18` prefetch helper is a present/absent kernel-page timing oracle (KASLR).
2. Linux 7.2.0-rc3-round100 `io_ring_buffers_peek` still `kfree`s the cached iovec array on the `KBUF_MODE_FREE` success path.

No SMEP/SMAP/PTI on `qemu64`, so ret2usr from a fake `pipe_buf_operations->confirm` is enough. Then read `/dev/sda` as root.

## Solution

Bundle `IORING_OP_SEND` with `IOSQE_BUFFER_SELECT` grows a 64-entry iovec (kmalloc-1k). Leave leftover provided buffers so the MORE retry takes `KBUF_MODE_FREE` and frees that array while the request still uses it.

Reclaim with `pipe()` / `F_SETPIPE_SZ` (two independent `KMALLOC_PARTITION_RANDOM` sites, so a given boot hits about 1/8). The next send writes `iov[1].iov_base = &fake_ops` over `pipe_buffer.ops`. `read()` calls `confirm` in userland → `commit_creds(init_cred)`.

Remote has `kaslr`. Prefetch mapped vs unmapped pages, then scan 2MiB slots from `0xffffffff81000000` and take the start of the longest present run (`_text`). Offsets from the shipped vmlinux: `commit_creds = _text+0x2dcfd0`, `init_cred = _text+0x200d700`.

Reconnect if the partition miss prints `[-] MISS`.

## Flag

```
BHFlagY{eb7195fbe0f4a56ac0a7f6f05a43aa03}
```
