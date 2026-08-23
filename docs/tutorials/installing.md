# Installing vetto in two minutes

Target length: 2 minutes.

1. Show the supported-platform table and explain FULL versus FS-ONLY in one
   sentence.
2. Install the alpha cross-platform package with
   `npm install --global @shleddy/vetto@next`. To pin this release, use
   `npm install --global @shleddy/vetto@0.2.0-alpha.1`. The package contains native
   executables for Linux x64/ARM64, macOS x64/Apple Silicon, and Windows x64;
   it does not download a binary during installation. For source builds, use
   `cargo install --git https://github.com/shleder/vetto --locked`.
3. Run `vetto doctor` and read the selected tier aloud.
4. In a temporary project, run `vetto -- sh -c 'printf "sandbox works\n"'`.
5. Close with the fail-closed rule: an unavailable backend stops the command;
   vetto never silently runs it unsandboxed.
