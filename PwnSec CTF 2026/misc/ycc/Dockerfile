FROM alpine

RUN apk add --no-cache build-base
WORKDIR /app

COPY ycc.c runtime.h runtime.c ysh.y /app/
RUN cc -O2 -std=gnu99 -Wl,--build-id=none -I/app -o /app/ycc /app/ycc.c /app/runtime.c -lm && \
    /app/ycc --compile /app/ysh.y -o /app/ysh && \
    rm -f /app/ycc.c /app/ysh.y
RUN addgroup -S app && adduser -S app -G app
RUN chown -R root:root /app && \
    chmod -R go-w /app && \
    chmod +x /app/ysh /app/ycc

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]