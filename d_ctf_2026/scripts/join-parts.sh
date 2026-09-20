#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    printf 'usage: %s PART_PREFIX OUTPUT\n' "$0" >&2
    printf 'example: %s challenges/forensics/Kameosa/files/toc.7z.zip. toc.7z.zip\n' "$0" >&2
    exit 2
fi

prefix=$1
output=$2
shopt -s nullglob
parts=("${prefix}"[0-9][0-9][0-9])
if (( ${#parts[@]} == 0 )); then
    printf 'no numbered parts found for %s\n' "$prefix" >&2
    exit 1
fi

cat "${parts[@]}" > "$output"
printf 'reassembled %d parts into %s\n' "${#parts[@]}" "$output"
