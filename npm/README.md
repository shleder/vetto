# vetto — cross-platform npm distribution

Install globally with npm:

```bash
npm install --global @shleddy/vetto
vetto doctor
```

The package also includes copy-only Codex session inspection:

```bash
vetto rescue --json scan
vetto rescue diagnose SESSION
vetto rescue snapshot SESSION --output ./recovery/session.jsonl
```

`vetto` ships the native `vetto` executable in the package. It does
not run an install script, download code at install time, or require a Rust
toolchain. The small launcher runs on the Node.js installation that provides
npm.

Prebuilt targets in `0.2.0`:

| Platform | Architecture | Native path |
| --- | --- | --- |
| Linux | x86_64 | `linux-x64` |
| Linux | arm64 | `linux-arm64` |
| macOS | x86_64 | `darwin-x64` |
| macOS | arm64 | `darwin-arm64` |
| Windows | x86_64 | `win32-x64` |

Linux requires a glibc-based distribution with Landlock support for the full
sandbox tier. The Windows backend is experimental and reports its available
capabilities through `vetto doctor`.

The npm package is the only supported user installation channel for the native
CLI. For policy reference and security limitations, see the project
documentation: <https://github.com/shleder/vetto>.
