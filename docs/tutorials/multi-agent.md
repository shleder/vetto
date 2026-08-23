# Multi-agent mode

Target length: 6 minutes.

1. Define two named agents in a multi-agent manifest rather than relying on
   ambiguous repeated `--` separators.
2. Run `vetto multi --manifest vetto-agents.toml`.
3. Show that each agent receives its own sandbox handle, event stream, limits,
   and report directory.
4. Cycle panes and terminate only one selected agent.
5. Open the combined report and compare blocked/file/network counts.
6. Emphasize that failure to establish any requested sandbox fails the whole
   launch before agents begin.
