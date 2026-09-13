FROM python:3.12-slim

RUN pip install --no-cache-dir flask gunicorn \
    && groupadd --system ctf \
    && useradd --system --gid ctf --no-create-home --shell /usr/sbin/nologin ctf

WORKDIR /app
COPY --chown=root:root webapp.py sessionstore.py /app/
COPY --chown=root:root templates/ /app/templates/
COPY --chown=root:root static/ /app/static/
COPY --chown=root:root flag.txt /app/flag.txt

# chmod while still root, BEFORE dropping privileges
RUN chmod 555 /app \
    && chmod -R 555 /app/templates /app/static \
    && chmod 444 /app/webapp.py /app/sessionstore.py /app/flag.txt \
    && chmod 444 /app/templates/*.html /app/static/*.css /app/static/*.js

USER ctf
EXPOSE 9999
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:9999", "webapp:app"]
