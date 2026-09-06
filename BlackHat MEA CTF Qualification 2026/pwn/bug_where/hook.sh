#!/bin/sh
set -eu

if [ -z "${DYN_FLAG:-}" ]; then
    echo "DYN_FLAG is not set" >&2
    exit 1
fi

escaped_flag=$(printf '%s' "${DYN_FLAG}" | sed 's/[\\&|]/\\&/g')
sed -i "s|REDACTED|${escaped_flag}|" /tmp/nsjail.cfg
unset DYN_FLAG escaped_flag

md5sum /srv/app/run /srv/app/bzImage \
    /srv/app/initramfs.cpio.gz /srv/usr/bin/qemu-system-x86_64 \
    > /etc/healthcheck.txt
