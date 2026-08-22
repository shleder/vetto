#!/bin/sh
# Symlink escape attempt: Landlock decides on the resolved inode, so a
# symlink pointing outside the allowed tree is denied regardless of where
# the link itself lives.
ln -sf /etc/passwd ./vetto-link
if cat ./vetto-link 2>/dev/null | grep -q root; then
  echo "LEAK-SYMLINK"
fi
echo "symlink-done"
