# Running Codex safely with vetto

Target length: 4 minutes.

1. Create a disposable Git repository and a dummy `.env` value.
2. Run `vetto doctor --probe` and show that the secret path is unreachable.
3. Start `vetto --agent codex -- codex exec "summarize this repository"`.
4. Explain the statusline counters and open the event overlay with `Ctrl+]`.
5. Repeat with a provider-specific strict network policy only when the task
   needs network access.
6. Show that credentials remain absent unless explicitly placed in
   `[environment].pass_through`.
