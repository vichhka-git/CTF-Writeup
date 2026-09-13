#!/bin/sh
set -eu

# cd /home/ctf

exec qemu-system-x86_64 \
  -m 256M \
  -kernel ./bzImage \
  -initrd ./rootfs.cpio.gz \
  -append "console=ttyS0 oops=panic panic=1 kaslr pti=on quiet" \
  -nographic \
  -no-reboot \
  -monitor none \
  -serial stdio \
  -net none \
  -enable-kvm \
  -s
