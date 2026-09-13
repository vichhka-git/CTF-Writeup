FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      qemu-system-x86 \
      socat \
      ca-certificates \
      busybox-static \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 993 kvm && useradd -m -u 1000 -G kvm ctf
WORKDIR /home/ctf

COPY --chown=ctf:ctf bzImage /home/ctf/bzImage
COPY --chown=ctf:ctf rootfs.cpio.gz /home/ctf/rootfs.cpio.gz
COPY --chown=ctf:ctf run-qemu.sh /home/ctf/run-qemu.sh

RUN chmod 0555 /home/ctf/run-qemu.sh \
 && chmod 0444 /home/ctf/bzImage /home/ctf/rootfs.cpio.gz

USER ctf
EXPOSE 31337

CMD ["socat", "-T", "120", "TCP-LISTEN:31337,reuseaddr,fork", "EXEC:/home/ctf/run-qemu.sh,stderr"]
