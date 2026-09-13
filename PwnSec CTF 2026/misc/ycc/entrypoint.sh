#!/bin/sh
set -e

FLAG="${FLAG:-test_flag}"
cat > /app/readflag.y << EOF
let args = argv();
if (len(args) > 1 && args[1] == "owo") {
    print("flag for you $FLAG");
} else {
    print("no flag for you! do /readflag owo to get the flag");
}
EOF
/app/ycc --compile /app/readflag.y -o /readflag
rm -f /app/readflag.y

chown root:root /readflag
chmod 4111 /readflag

ln -sf /app/ysh /bin/sh

unset FLAG
export -n FLAG 2>/dev/null || true
exec su -s /bin/sh app