FROM ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54 AS runtime
WORKDIR /app
COPY --chmod=555 launcher /app/run
COPY --chmod=555 baiby-pwn /app/baiby-pwn
RUN echo "BHFlagY{DEFAULT}" > /flag.txt \
    && mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

FROM pwn.red/jail
COPY --from=runtime / /srv
ENV JAIL_MEM=0 JAIL_PIDS=0 JAIL_CPU=0 JAIL_TIME=0 JAIL_SYSCALLS=landlock_create_ruleset,landlock_add_rule,landlock_restrict_self
