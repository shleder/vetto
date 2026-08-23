# Packaging sources

These files build vetto from source or act as checksum-gated templates. They
are repository code only: no workflow in this directory publishes a release,
uploads an artifact, or changes an external package registry.

- `homebrew/vetto.rb`: install the current Git repository with `--HEAD`.
- `aur/PKGBUILD`: source-based `vetto-git` package.
- `rpm/vetto.spec`: local RPM build recipe.
- `scoop/vetto.json.template`: rendered only after a real archive and SHA-256
  are supplied.
- `chocolatey/`: local Chocolatey package template with mandatory checksum.
- the root `flake.nix`: reproducible Nix build from the checked-out source.

Templates deliberately contain no fake URL or checksum.
