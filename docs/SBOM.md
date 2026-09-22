# Software Bill of Materials (SBOM)

Vetto publishes a machine-readable Software Bill of Materials (SBOM) conforming to the [CycloneDX 1.5](https://cyclonedx.org/) specification for all release artifacts.

## Generating SBOM

To generate an SBOM locally:

```bash
./scripts/gen-sbom.sh [output-path.json]
```

This script will use `cargo-cyclonedx` if installed, or fall back to an integrated parser for `Cargo.lock` that extracts package names, versions, and SHA256 checksums.

## Release Integration

In CI / release trains, SBOM generation can be attached as a release step:

```yaml
- name: Generate CycloneDX SBOM
  run: ./scripts/gen-sbom.sh vetto-sbom.json

- name: Upload SBOM to release
  uses: softprops/action-gh-release@v1
  with:
    files: vetto-sbom.json
```

For release `v0.4.0`, pre-generated CycloneDX 1.5 SBOM artifacts are published directly on [GitHub Releases](https://github.com/shleder/vetto/releases/tag/v0.4.0).
