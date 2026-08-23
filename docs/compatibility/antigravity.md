# Antigravity compatibility gate

Status: `unsupported` in the current Vetto adapter registry.

Vetto does not claim Antigravity recovery until the provider's local state
layout, session identity, and transcript format can be reproduced with
sanitized fixtures. The adapter contract requires an explicit root and
copy-only operations; guessing a path or rewriting provider state would be an
unsafe compatibility claim.

Useful external validation threads:

- [Remote Dev #106](https://github.com/eXPerience83/remote-dev-containers/issues/106)
  is a concrete request to validate Antigravity `/resume` continuity across
  container recreation without reading or rewriting vendor storage.
- [His #16](https://github.com/heyjstn/his/issues/16) requests an Antigravity
  history adapter and lists the required detection, parsing, and fixture work.

Before registering an adapter, we need:

1. a documented versioned state root and session identity;
2. redacted fixtures covering a normal, interrupted, and resumed session;
3. a negative fixture proving credentials and settings are not read;
4. cross-platform path behavior, including symlink/junction handling; and
5. confirmation that `/resume` semantics are not being confused with a
   provider-owned database repair.

Until those conditions are met, `vetto rescue --adapter antigravity` must fail
closed as `unsupported`. The public npm package must not advertise support
that has not passed this gate.
