# Packaging sources

These files build vetto from source or act as checksum-gated templates. They
are repository code only: no workflow in this directory publishes a release,
uploads an artifact, or changes an external package registry.

- `homebrew/vetto.rb`: install the current Git repository with `--HEAD`.
- `aur/vetto-git/`: source-based `vetto-git` package (tracks main).
- `aur/vetto/`: stable `vetto` package (release tarball + pinned SHA-256).
  Bump `pkgver`/`sha256sums` in `PKGBUILD` and mirror them into `.SRCINFO`
  on every release.
- `rpm/vetto.spec`: local RPM build recipe.
- `scoop/vetto.json.template`: rendered by release-train (`Render Scoop manifest`
  step) into `vetto.json` from the real Windows archive + its `.sha256`
  sidecar and attached to the GitHub Release. Never hand-edit checksums.
- `chocolatey/`: local Chocolatey package template with mandatory checksum.
- the root `flake.nix`: reproducible Nix build from the checked-out source.

Templates deliberately contain no fake URL or checksum.
