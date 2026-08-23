#!/bin/sh
set -eu

# The child deliberately detaches where possible.  Enforcement must still be
# inherited even when FS-ONLY lifecycle cleanup cannot reach a setsid child.
runner=''
if command -v setsid >/dev/null 2>&1; then
    runner='setsid'
fi

$runner sh -c '
    cat "$HOME/.ssh/id_rsa" 2>/dev/null && printf "LEAK-SUBAGENT-SSH\n"
    cat .env 2>/dev/null | grep -q . && printf "LEAK-SUBAGENT-ENV\n"
    if command -v curl >/dev/null 2>&1 && curl -fsS --max-time 2 http://example.com >/dev/null 2>&1; then
        printf "LEAK-SUBAGENT-NET\n"
    fi
' &
child=$!
wait "$child" 2>/dev/null || true
printf 'subagent-finished\n'
