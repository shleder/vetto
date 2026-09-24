import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

type JsonEvent = Record<string, unknown>;

class EventItem extends vscode.TreeItem {
    constructor(event: JsonEvent) {
        const kind = stringField(event, 'kind') ?? stringField(event, 'type') ?? 'event';
        const decision = stringField(event, 'decision');
        const target =
            stringField(event, 'path') ??
            stringField(event, 'target') ??
            stringField(event, 'message') ??
            '';
        super(`${decision ? `${decision} ` : ''}${kind}`, vscode.TreeItemCollapsibleState.None);
        this.description = target;
        this.tooltip = new vscode.MarkdownString(`\`\`\`json\n${JSON.stringify(event, null, 2)}\n\`\`\``);
        const lowered = decision?.toLowerCase();
        this.iconPath = new vscode.ThemeIcon(
            lowered === 'blocked' || lowered === 'denied' ? 'shield' : 'eye'
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
            text = await fs.promises.readFile(this.eventFile, 'utf8');
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
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

let statusBarItem: vscode.StatusBarItem;

export async function activate(context: vscode.ExtensionContext): Promise<void> {
    await vscode.workspace.fs.createDirectory(context.globalStorageUri);
    const eventFile = vscode.Uri.joinPath(context.globalStorageUri, 'session.jsonl').fsPath;
    const reportDir = vscode.Uri.joinPath(context.globalStorageUri, 'reports').fsPath;
    await vscode.workspace.fs.createDirectory(vscode.Uri.file(reportDir));

    const provider = new EventProvider(eventFile);
    context.subscriptions.push(vscode.window.registerTreeDataProvider('vetto.events', provider));

    // 1. Status Bar Item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'vetto.openAudit';
    statusBarItem.text = '$(shield) Vetto: Active';
    statusBarItem.tooltip = 'Vetto Sandbox Active (Click to open Audit Report)';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // 2. Command: Run Sandboxed Task
    let runCmd = vscode.commands.registerCommand('vetto.runSandboxed', async () => {
        const config = vscode.workspace.getConfiguration('vetto');
        const vettoPath = getVettoPath(config);
        const profile = getDefaultProfile(config);
        const net = getDefaultNet(config);
        const tui = config.get<string>('tui') || 'statusline';
        const formats = config.get<string>('reportFormats') || 'html,json';

        const cmd = await vscode.window.showInputBox({
            prompt: 'Enter command to run inside Vetto Sandbox',
            placeHolder: 'e.g. npm run build'
        });

        if (cmd) {
            const terminal = vscode.window.createTerminal({
                name: 'Vetto Sandbox',
                iconPath: new vscode.ThemeIcon('shield'),
            });
            terminal.show();
            terminal.sendText(
                `${quote(vettoPath)} --profile ${quote(profile)} --net ${quote(net)} --tui ${quote(tui)} --jsonl ${quote(eventFile)} --report ${quote(formats)} --report-dir ${quote(reportDir)} -- ${cmd}`
            );
        }
    });
    context.subscriptions.push(runCmd);

    // 3. Command: Show Sandbox Status
    let statusCmd = vscode.commands.registerCommand('vetto.showStatus', () => {
        vscode.window.showInformationMessage('Vetto Sandbox is active and protecting your workspace.');
        statusBarItem.text = '$(shield) Vetto: 0 blocks';
    });
    context.subscriptions.push(statusCmd);

    // 4. Command: Diff Sessions
    let diffCmd = vscode.commands.registerCommand('vetto.diffSessions', async () => {
        const config = vscode.workspace.getConfiguration('vetto');
        const vettoPath = getVettoPath(config);

        const sessionA = await vscode.window.showInputBox({
            prompt: 'Enter first Session ID (or leave blank to list sessions via audit)',
            placeHolder: 'Session ID A'
        });

        if (!sessionA) {
            const terminal = vscode.window.createTerminal({ name: 'Vetto Audit' });
            terminal.show();
            terminal.sendText(`${quote(vettoPath)} audit`);
            return;
        }

        const sessionB = await vscode.window.showInputBox({
            prompt: 'Enter second Session ID to compare',
            placeHolder: 'Session ID B'
        });

        if (!sessionB) {
            return;
        }

        const terminal = vscode.window.createTerminal({ name: 'Vetto Diff' });
        terminal.show();
        terminal.sendText(`${quote(vettoPath)} diff-sessions ${quote(sessionA)} ${quote(sessionB)}`);
    });
    context.subscriptions.push(diffCmd);

    // 5. Command: Open Audit Report
    let auditCmd = vscode.commands.registerCommand('vetto.openAudit', async () => {
        const config = vscode.workspace.getConfiguration('vetto');
        const vettoPath = getVettoPath(config);

        let opened = false;
        try {
            if (fs.existsSync(reportDir)) {
                const entries = await fs.promises.readdir(reportDir, { withFileTypes: true });
                const reports = await Promise.all(
                    entries
                        .filter((entry) => entry.isFile() && entry.name.endsWith('.html'))
                        .map(async (entry) => {
                            const fullPath = path.join(reportDir, entry.name);
                            return { fullPath, modified: (await fs.promises.stat(fullPath)).mtimeMs };
                        })
                );
                reports.sort((a, b) => b.modified - a.modified);
                if (reports[0]) {
                    await vscode.env.openExternal(vscode.Uri.file(reports[0].fullPath));
                    opened = true;
                }
            }
        } catch {
            // ignore
        }

        if (!opened) {
            const terminal = vscode.window.createTerminal({ name: 'Vetto Audit' });
            terminal.show();
            terminal.sendText(`${quote(vettoPath)} audit --latest`);
        }
    });
    context.subscriptions.push(auditCmd);

    // 6. Command: Run Task Sandboxed
    let runTaskCmd = vscode.commands.registerCommand('vetto.runTaskSandboxed', async () => {
        try {
            const tasks = await vscode.tasks.fetchTasks();
            if (!tasks || tasks.length === 0) {
                vscode.window.showWarningMessage('Vetto: No tasks found in workspace (tasks.json).');
                return;
            }

            const items = tasks.map((t) => ({
                label: t.name,
                description: t.source || t.definition.type,
                detail: t.detail,
                task: t,
            }));

            const selection = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select a task to run inside the Vetto sandbox',
            });

            if (!selection) {
                return;
            }

            const config = vscode.workspace.getConfiguration('vetto');
            const vettoPath = getVettoPath(config);
            const profile = getDefaultProfile(config);
            const net = getDefaultNet(config);

            const task = selection.task;
            let commandToRun = '';

            const execution = task.execution as
                | { commandLine?: string; command?: string; args?: (string | { value?: string })[] }
                | undefined;

            if (execution && execution.commandLine) {
                commandToRun = execution.commandLine;
            } else if (execution && execution.command) {
                const args = (execution.args || [])
                    .map((a) => (typeof a === 'string' ? a : a.value || ''))
                    .join(' ');
                commandToRun = `${execution.command} ${args}`.trim();
            } else {
                commandToRun = task.name;
            }

            const terminalName = `Vetto Sandbox [${task.name}]`;
            let terminal = vscode.window.terminals.find((t) => t.name === terminalName);
            if (!terminal) {
                terminal = vscode.window.createTerminal({
                    name: terminalName,
                    iconPath: new vscode.ThemeIcon('shield'),
                });
            }

            terminal.show();
            const sandboxedCommand = `${quote(vettoPath)} --profile ${quote(profile)} --net ${quote(net)} -- ${commandToRun}`;
            terminal.sendText(sandboxedCommand);

            vscode.window.showInformationMessage(`Vetto: Executing task "${task.name}" sandboxed.`);
        } catch (err: unknown) {
            const msg = err instanceof Error ? err.message : String(err);
            vscode.window.showErrorMessage(`Vetto error: ${msg}`);
        }
    });
    context.subscriptions.push(runTaskCmd);

    // 7. Command: Doctor
    let doctorCmd = vscode.commands.registerCommand('vetto.doctor', () => {
        const config = vscode.workspace.getConfiguration('vetto');
        const vettoPath = getVettoPath(config);
        const terminal = vscode.window.createTerminal({ name: 'Vetto Doctor' });
        terminal.show(true);
        terminal.sendText(`${quote(vettoPath)} doctor`, true);
    });
    context.subscriptions.push(doctorCmd);

    // 8. Command: Hook Install
    let hookCmd = vscode.commands.registerCommand('vetto.hookInstall', () => {
        const config = vscode.workspace.getConfiguration('vetto');
        const vettoPath = getVettoPath(config);
        const terminal = vscode.window.createTerminal({ name: 'Vetto Hook' });
        terminal.show(true);
        terminal.sendText(`${quote(vettoPath)} hook install`, true);
    });
    context.subscriptions.push(hookCmd);

    // 9. Command: Rescue
    let rescueCmd = vscode.commands.registerCommand('vetto.rescue', async () => {
        const adapter = await vscode.window.showQuickPick(
            [
                { label: 'claude', description: 'Scan Claude Code project transcripts' },
                { label: 'codex', description: 'Scan Codex session state trees' },
                { label: 'cursor', description: 'Scan Cursor session databases' },
            ],
            { title: 'Select AI Agent Rescue Adapter' }
        );
        if (!adapter) return;

        const config = vscode.workspace.getConfiguration('vetto');
        const vettoPath = getVettoPath(config);
        const terminal = vscode.window.createTerminal({ name: `Vetto Rescue (${adapter.label})` });
        terminal.show(true);
        terminal.sendText(`${quote(vettoPath)} rescue --adapter ${adapter.label} --json scan`, true);
    });
    context.subscriptions.push(rescueCmd);

    // 10. Command: Refresh Events
    context.subscriptions.push(
        vscode.commands.registerCommand('vetto.refreshEvents', () => provider.refresh())
    );

    // 11. Command: Open Last Report
    context.subscriptions.push(
        vscode.commands.registerCommand('vetto.openLastReport', async () => {
            const entries = await fs.promises.readdir(reportDir, { withFileTypes: true });
            const reports = await Promise.all(
                entries
                    .filter((entry) => entry.isFile() && entry.name.endsWith('.html'))
                    .map(async (entry) => {
                        const fullPath = path.join(reportDir, entry.name);
                        return { fullPath, modified: (await fs.promises.stat(fullPath)).mtimeMs };
                    })
            );
            reports.sort((a, b) => b.modified - a.modified);
            if (!reports[0]) {
                void vscode.window.showInformationMessage('No Vetto HTML report has been generated yet.');
                return;
            }
            await vscode.env.openExternal(vscode.Uri.file(reports[0].fullPath));
        })
    );
}

export function deactivate(): void {}

function getVettoPath(config: vscode.WorkspaceConfiguration): string {
    return config.get<string>('path') || config.get<string>('executable') || config.get<string>('executablePath') || 'vetto';
}

function getDefaultProfile(config: vscode.WorkspaceConfiguration): string {
    return config.get<string>('defaultProfile') || config.get<string>('profile') || 'default';
}

function getDefaultNet(config: vscode.WorkspaceConfiguration): string {
    return config.get<string>('defaultNet') || config.get<string>('network') || 'off';
}

function stringField(event: JsonEvent, key: string): string | undefined {
    const value = event[key];
    return typeof value === 'string' ? value : undefined;
}

function quote(value: string): string {
    if (process.platform === 'win32') {
        return `'${value.replaceAll("'", "''")}'`;
    }
    return `'${value.replaceAll("'", `'\\''`)}'`;
}
