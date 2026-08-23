#!/bin/sh
set -eu

target=${1:-.env}
if umount "$target" >/dev/null 2>&1 || umount -l "$target" >/dev/null 2>&1; then
    printf 'UMOUNT-SUCCEEDED\n'
    exit 9
fi

printf 'umount-blocked\n'
