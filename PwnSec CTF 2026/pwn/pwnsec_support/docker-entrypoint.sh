#!/bin/sh
# docker-entrypoint.sh — thin wrapper; the guest listens on 8080.
set -eu

echo "PwnSec Support starting on :8080" >&2
exec "$@"
