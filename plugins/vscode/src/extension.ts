import * as fs from "node:fs";
import * as path from "node:path";
import * as vscode from "vscode";

type JsonEvent = Record<string, unknown>;

class EventItem extends vscode.TreeItem {
  constructor(event: JsonEvent) {
    const kind = stringField(event, "kind") ?? stringField(event, "type") ?? "event";
    const decision = stringField(event, "decision");
    const target =
      stringField(event, "path") ??
      stringField(event, "target") ??
      stringField(event, "message") ??
      "";
    super(`${decision ? `${decision} ` : ""}${kind}`, vscode.TreeItemCollapsibleState.None);
    this.description = target;
    this.tooltip = new vscode.MarkdownString(`\`\`\`json\n${JSON.stringify(event, null, 2)}\n\`\`\``);
    const lowered = decision?.toLowerCase();
    this.iconPath = new vscode.ThemeIcon(
      lowered === "blocked" || lowered === "denied" ? "shield" : "eye",
    );
  }
}

class EventProvider implements vscode.TreeDataProvider<EventItem> {
  private readonly changed = new vscode.EventEmitter<EventItem | undefined>();
  readonly onDidChangeTreeData = this.changed.event;

  constructor(private readonly eventFile: string) {}

  refresh(): void {
    this.changed.fire(undefined);
  }

  getTreeItem(item: EventItem): vscode.TreeItem {
    return item;
  }

  async getChildren(): Promise<EventItem[]> {
    let text: string;
    try {
      text = await fs.promises.readFile(this.eventFile, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return [];
      }
      throw error;
    }

    return text
      .split(/\r?\n/u)
      .filter(Boolean)
      .slice(-500)
      .reverse()
      .flatMap((line) => {
        try {
          return [new EventItem(JSON.parse(line) as JsonEvent)];
        } catch {
          return [];
        }
      });
  }
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  await vscode.workspace.fs.createDirectory(context.globalStorageUri);
  const eventFile = vscode.Uri.joinPath(context.globalStorageUri, "session.jsonl").fsPath;
  const reportDir = vscode.Uri.joinPath(context.globalStorageUri, "reports").fsPath;
  await vscode.workspace.fs.createDirectory(vscode.Uri.file(reportDir));

  const provider = new EventProvider(eventFile);
  context.subscriptions.push(vscode.window.registerTreeDataProvider("vetto.events", provider));

  context.subscriptions.push(
    vscode.commands.registerCommand("vetto.run", async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        void vscode.window.showErrorMessage("Open a workspace folder before running vetto.");
        return;
      }
      const command = await vscode.window.showInputBox({
        title: "Run an agent through vetto",
        prompt: "Agent command and arguments",
        placeHolder: 'codex exec "review this project"',
      });
      if (!command) {
        return;
      }

      const cfg = vscode.workspace.getConfiguration("vetto");
      const executable = cfg.get<string>("executable", "vetto");
      const profile = cfg.get<string>("profile", "default");
      const network = cfg.get<string>("network", "off");
      const tui = cfg.get<string>("tui", "statusline");
      const formats = cfg.get<string>("reportFormats", "html,json");
      const args = [
        quote(executable),
        "--profile",
        quote(profile),
        "--net",
        quote(network),
        "--tui",
        quote(tui),
        "--jsonl",
        quote(eventFile),
        "--report",
        quote(formats),
        "--report-dir",
        quote(reportDir),
        "--",
        command,
      ];
      const terminal = vscode.window.createTerminal({
        name: "vetto",
        cwd: folder.uri,
        iconPath: new vscode.ThemeIcon("shield"),
      });
      terminal.show(true);
      terminal.sendText(args.join(" "), true);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("vetto.doctor", () => {
      const executable = vscode.workspace.getConfiguration("vetto").get<string>("executable", "vetto");
      const terminal = vscode.window.createTerminal({ name: "vetto doctor" });
      terminal.show(true);
      terminal.sendText(`${quote(executable)} doctor`, true);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("vetto.hookInstall", () => {
      const executable = vscode.workspace.getConfiguration("vetto").get<string>("executable", "vetto");
      const terminal = vscode.window.createTerminal({ name: "vetto hook" });
      terminal.show(true);
      terminal.sendText(`${quote(executable)} hook install`, true);
    }),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("vetto.rescue", async () => {
      const adapter = await vscode.window.showQuickPick(
        [
          { label: "claude", description: "Scan and recover Claude Code project transcripts" },
          { label: "codex", description: "Diagnose and checkpoint Codex SQLite state trees" },
          { label: "cursor", description: "Inspect and repair Cursor session databases" },
        ],
        { title: "Select AI Agent Rescue Adapter" },
      );
      if (!adapter) return;

      const executable = vscode.workspace.getConfiguration("vetto").get<string>("executable", "vetto");
      const terminal = vscode.window.createTerminal({ name: `vetto rescue (${adapter.label})` });
      terminal.show(true);
      terminal.sendText(`${quote(executable)} rescue --adapter ${adapter.label} --json scan`, true);
    }),
  );

  const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
  statusBarItem.text = "$(shield) Vetto";
  statusBarItem.tooltip = "Vetto: Operator OS Sandbox & Agent Protection (Click to Run)";
  statusBarItem.command = "vetto.run";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  context.subscriptions.push(
    vscode.commands.registerCommand("vetto.refreshEvents", () => provider.refresh()),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("vetto.openLastReport", async () => {
      const entries = await fs.promises.readdir(reportDir, { withFileTypes: true });
      const reports = await Promise.all(
        entries
          .filter((entry) => entry.isFile() && entry.name.endsWith(".html"))
          .map(async (entry) => {
            const fullPath = path.join(reportDir, entry.name);
            return { fullPath, modified: (await fs.promises.stat(fullPath)).mtimeMs };
          }),
      );
      reports.sort((a, b) => b.modified - a.modified);
      if (!reports[0]) {
        void vscode.window.showInformationMessage("No vetto HTML report has been generated yet.");
        return;
      }
      await vscode.env.openExternal(vscode.Uri.file(reports[0].fullPath));
    }),
  );
}

export function deactivate(): void {}

function stringField(event: JsonEvent, key: string): string | undefined {
  const value = event[key];
  return typeof value === "string" ? value : undefined;
}

function quote(value: string): string {
  if (process.platform === "win32") {
    return `'${value.replaceAll("'", "''")}'`;
  }
  return `'${value.replaceAll("'", `'\\''`)}'`;
}
