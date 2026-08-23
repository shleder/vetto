# Understanding vetto's TUI

Target length: 5 minutes.

1. Demonstrate `--tui=statusline` with an interactive command.
2. Resize the terminal and show that the child PTY receives the new size.
3. Open `Ctrl+]`, filter file/network/blocked events, then return to the agent.
4. Demonstrate `--tui=full` with a headless agent command.
5. Open the file, network, graph, and summary panels.
6. Export one view and point out that visibility is best-effort while kernel
   enforcement remains active independently.
