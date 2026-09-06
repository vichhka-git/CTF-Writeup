FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90 AS qemu-builder

ARG DEBIAN_FRONTEND=noninteractive
ARG QEMU_VERSION=11.0.2
ARG QEMU_SHA256=3745f6ea88e2e87fe0dc838b2b1d4e0a770bf48e01a1d5a186842a1fff76ccf5

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        busybox-static \
        ca-certificates \
        curl \
        libglib2.0-dev \
        libpixman-1-dev \
        libseccomp-dev \
        ninja-build \
        pax-utils \
        patch \
        pkg-config \
        python3 \
        python3-venv \
        xz-utils \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/qemu
COPY --chmod=0444 qemu-hardening.patch /tmp/qemu-hardening.patch

RUN curl -fsSLo /tmp/qemu.tar.xz \
        "https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz" \
    && echo "${QEMU_SHA256}  /tmp/qemu.tar.xz" | sha256sum -c - \
    && tar -xJf /tmp/qemu.tar.xz --strip-components=1 \
    && patch -p1 < /tmp/qemu-hardening.patch \
    && ./configure \
        --prefix=/usr \
        --target-list=x86_64-softmmu \
        --enable-tcg \
        --disable-mshv \
        --disable-kvm \
        --without-default-devices \
        --enable-seccomp \
        --disable-tools \
        --disable-docs \
        --disable-guest-agent \
        --disable-plugins \
        --disable-slirp \
        --disable-vnc \
        --disable-gtk \
        --disable-sdl \
        --disable-spice \
        --disable-opengl \
        --disable-curses \
        --disable-fdt \
        --disable-nitro \
        --disable-usb-redir \
        --disable-virtfs \
        --disable-vhost-net \
        --disable-vhost-user \
        --disable-vhost-vdpa \
        --disable-linux-aio \
        --disable-linux-io-uring \
        --disable-curl \
        --disable-libnfs \
        --disable-libssh \
        --disable-rbd \
        --disable-glusterfs \
        --disable-werror \
        --block-drv-rw-whitelist=raw,file \
        --block-drv-ro-whitelist=raw,file \
    && ninja -C build qemu-system-x86_64 \
    && install -Dm0555 build/qemu-system-x86_64 \
        /opt/root/usr/bin/qemu-system-x86_64 \
    && lddtree -l /opt/root/usr/bin/qemu-system-x86_64 \
    | sort -u | while read -r library; do \
        case "${library}" in \
            /opt/root/*) ;; \
            *) cp --parents "${library}" /opt/root ;; \
        esac; \
    done \
    && install -Dm0555 /bin/busybox /opt/root/bin/busybox \
    && ln -s busybox /opt/root/bin/sh \
    && ln -s busybox /opt/root/bin/dd \
    && ln -s busybox /opt/root/bin/rm \
    && ln -s busybox /opt/root/bin/chmod \
    && install -Dm0444 pc-bios/bios-256k.bin \
        /opt/root/usr/share/qemu/bios-256k.bin \
    && install -Dm0444 pc-bios/linuxboot_dma.bin \
        /opt/root/usr/share/qemu/linuxboot_dma.bin

FROM pwn.red/jail@sha256:ee52ad5fd6cfed7fd8ea30b09792a6656045dd015f9bef4edbbfa2c6e672c28c

COPY --from=qemu-builder /opt/root/ /srv/
COPY --chmod=0555 app-run /srv/app/run
COPY --chmod=0444 bzImage initramfs.cpio.gz /srv/app/
RUN mkdir -m 0755 /srv/dev \
    && mkdir -m 0555 /srv/proc \
    && mkdir -m 1777 /srv/tmp
COPY --chmod=0555 hook.sh /jail/hook.sh

ENV JAIL_ENV_DYN_FLAG=REDACTED \
    JAIL_MEM=0 \
    JAIL_PIDS=0 \
    JAIL_CPU=0 \
    JAIL_TIME=0 \
    JAIL_TMP_SIZE=16M \
    JAIL_DEV=null,zero,urandom,random,tty,ptmx

ENTRYPOINT ["/jail/run"]
