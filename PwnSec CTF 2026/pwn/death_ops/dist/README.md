# alphabet-seccomp — Player Distribution

## Running the Challenge

Requirements: Docker, Docker Compose, KVM support

```bash
docker compose up -d
```

Connect to the challenge:

```bash
nc localhost 31337
```

## Files

- `Dockerfile` — Container image definition
- `docker-compose.yml` — Service definition
- `run-qemu.sh` — QEMU launch script
- `bzImage` — Linux 4.9.333 kernel image
- `rootfs.cpio.gz` — Initial ramdisk
