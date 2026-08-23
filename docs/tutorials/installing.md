# Installing vetto in two minutes

Target length: 2 minutes.

1. Show the supported-platform table and explain FULL versus FS-ONLY in one
   sentence.
2. Install from source with `cargo install --git https://github.com/shleder/vetto --locked`.
   On Linux x64, also show `npm install -g @shleddy/vetto@beta` as the current
   alpha distribution path.
3. Run `vetto doctor` and read the selected tier aloud.
4. In a temporary project, run `vetto -- sh -c 'printf "sandbox works\n"'`.
5. Close with the fail-closed rule: an unavailable backend stops the command;
   vetto never silently runs it unsandboxed.
