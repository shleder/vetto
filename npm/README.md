# vetto — npm alpha preview

This package contains the real `vetto` native sandbox binary for **Linux
x86_64 with glibc 2.29 or newer**. It is an early npm distribution preview
published under the `beta` tag; it is not the stable cross-platform release
channel yet.

```bash
npm install --global @shleddy/vetto@beta
vetto doctor --probe
```

The bundled executable provides Landlock filesystem isolation, seccomp socket
and syscall filtering, namespace isolation where supported, environment
allowlisting, audit output, and post-session reports. It requires Linux with
Landlock support; run `vetto doctor` to see the tier available on your machine.

Package version: `0.0.1-alpha.0`. The bundled core currently reports its Rust
application version as `vetto 0.1.0`.

This alpha package:

- supports Linux x64 only;
- contains no install scripts or network downloader;
- ships a stripped native binary plus the Apache-2.0 license;
- does not support Windows or macOS through npm yet.

Project: <https://github.com/shleder/vetto>
