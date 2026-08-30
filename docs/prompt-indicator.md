# Prompt (PS1) Indicator Integration

When running under a `vetto` sandboxed session, the supervisor exports the following environment variables to the sandboxed agent and child shells:

- `VETTO_SANDBOX=1`
- `VETTO_SESSION_ID=<uuid>`
- `VETTO_TIER=<full|fs-only|macos-seatbelt|windows-sandbox>`
- `VETTO_PROFILE=<profile-name>`

## `vetto shell-env`

Run `vetto shell-env` to emit shell export definitions for testing or scripting:

```bash
eval "$(vetto shell-env)"
```

## Shell Integration Examples

### Bash (`~/.bashrc`)

```bash
if [ -n "$VETTO_SANDBOX" ]; then
    PS1="[vetto:${VETTO_PROFILE:-active}] $PS1"
fi
```

### Zsh (`~/.zshrc`)

```zsh
if [[ -n "$VETTO_SANDBOX" ]]; then
    PROMPT="[vetto] $PROMPT"
fi
```

### Fish (`~/.config/fish/config.fish`)

```fish
if set -q VETTO_SANDBOX
    function fish_prompt
        echo -n "[vetto] "
        # ... standard prompt ...
    end
end
```

### PowerShell (`$PROFILE`)

```powershell
if ($env:VETTO_SANDBOX -eq "1") {
    function prompt {
        "[vetto] " + $(Get-Location) + "> "
    }
}
```
