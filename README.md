# leash

A sandbox/security layer for AI coding agents.

## Quick start

```bash
cargo build --release
./target/release/leash init          # scaffold a leash.toml policy
./target/release/leash -- npm run dev
```

Wrap any agent command and enforce filesystem/network policy before it can
touch your machine:

```bash
leash --profile default -- npx claude
leash --dry-run -- cargo build      # preview restrictions
leash --ci -- make test             # non-interactive JSON event log
leash doctor                        # environment health check
```

Licensed under the Apache License, Version 2.0.
