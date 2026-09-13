FROM ubuntu:22.04@sha256:3b06811b2afd352be909dd088a004166d665dc76d38b13eada33522a9d915c6f

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctf
WORKDIR /home/ctf

COPY src/freal /home/ctf/freal
COPY flag.txt /home/ctf/flag.txt
RUN chown -R root:root /home/ctf \
    && chmod 755 /home/ctf /home/ctf/freal \
    && chmod 444 /home/ctf/flag.txt

EXPOSE 9999
CMD ["/bin/sh", "-c", "set -eu; if [ -f /home/ctf/flag.txt ]; then h=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \\n'); mv /home/ctf/flag.txt /home/ctf/flag-$h.txt; chmod 444 /home/ctf/flag-$h.txt; fi; exec socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/home/ctf/freal,stderr,su=ctf"]