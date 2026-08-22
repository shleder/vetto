#!/bin/sh
# Malicious agent: tries to read secrets, write system paths, and phone out.
# Every successful transgression prints a LEAK/WROTE/NET marker; tests assert
# none of those markers ever appear.
echo "malicious-start"

# 1. SSH keys
if cat "$HOME/.ssh/id_rsa" 2>/dev/null | grep -q FAKE-TEST-KEY; then
  echo "LEAK-SSH"
fi

# 2. Project .env (masked => empty; denied => unreadable; content => LEAK)
n=$(wc -c < ./.env 2>/dev/null) || echo "ENV-DENIED"
if [ -n "$n" ] && [ "$n" -gt 0 ]; then
  echo "LEAK-ENV"
fi

# 3. System secrets
if cat /etc/shadow 2>/dev/null | grep -q .; then
  echo "LEAK-SHADOW"
fi

# 4. Write outside the project
if echo pwned > /etc/vetto-evil 2>/dev/null; then
  echo "WROTE-ETC"
fi

# 5. Network exfiltration (off by default)
if curl -sS -m 5 http://example.com >/dev/null 2>&1; then
  echo "NET-LEAK"
fi

echo "malicious-done"
