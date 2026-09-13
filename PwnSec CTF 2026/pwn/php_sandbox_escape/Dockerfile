FROM ubuntu@sha256:d80997daaa3811b175119350d84305e1ec9129e1799bba0bd1e3120da3ff52c3

RUN apt-get update \
   && apt-get install -y --no-install-recommends build-essential autoconf automake bison flex make git pkgconf \
   re2c curl file binutils libtool valgrind nginx ca-certificates pax-utils \
   libxml2-dev libsqlite3-dev libbz2-dev libz-dev libcurl4-openssl-dev libonig-dev libssl-dev libreadline-dev \
   libedit-dev libsqlite3-dev libfcgi-dev libmysqlclient-dev libjpeg-dev libpng-dev libfreetype6-dev libwebp-dev \
   && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/php/php-src.git \
   && cd php-src \
   && ./buildconf --force \
   && ./configure --prefix=/app/php-bin --with-config-file-path=/app/php-bin/etc --enable-fpm --with-fpm-user=ctf --with-fpm-group=ctf --with-readline \
   && make -j4 \
   && make install \
   && rm -rf /app/php-src

RUN cd /app/php-bin/etc \
   && mv php-fpm.d/www.conf.default php-fpm.d/www.conf \
   && mv php-fpm.conf.default php-fpm.conf

COPY src/nginx.conf /etc/nginx/sites-available/default
COPY src/php.ini /app/php-bin/etc
COPY src/init.sh /init.sh
COPY src/flag /flag
COPY src/readflag.c /src/readflag.c

RUN gcc /src/readflag.c -o /readflag && chmod +s /readflag
# adduser makes /home/ctf 0750; nginx workers run as www-data and cannot
# traverse it, so every request under the web root answers 403.
RUN adduser --disabled-password --gecos "" ctf && mkdir -p /home/ctf/scripts \
   && chown ctf:ctf /home/ctf/scripts && chmod 755 /home/ctf

CMD ["/init.sh"]
