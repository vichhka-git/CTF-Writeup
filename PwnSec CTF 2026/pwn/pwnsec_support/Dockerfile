FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tini \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 1337 -s /usr/sbin/nologin app

WORKDIR /app
COPY l3afvm /app/l3afvm
COPY ctf_sql.l3af /app/ctf_sql.l3af
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh /app/l3afvm \
 && chown -R app:app /app \
 && test -s /app/l3afvm && test -s /app/ctf_sql.l3af

ENV PORT=8080
EXPOSE 8080

USER app
ENTRYPOINT ["/usr/bin/tini", "--", "/app/docker-entrypoint.sh"]
CMD ["/app/l3afvm", "/app/ctf_sql.l3af"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/ | grep -q "PwnSec" || exit 1
