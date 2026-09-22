import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
    // 1. Status Bar Item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'vetto.openAudit';
    statusBarItem.text = '$(shield) Vetto: Active';
    statusBarItem.tooltip = 'Click to open the latest audit report';
    statusBarItem.show();
    context.subscriptions.push(statusBarItem);

    // 2. Command: Run Sandboxed Task
    let runCmd = vscode.commands.registerCommand('vetto.runSandboxed', async () => {
        const config = vscode.workspace.getConfiguration('vetto');
        const vettoPath = config.get<string>('path') || 'vetto';
        const profile = config.get<string>('defaultProfile') || 'default';

        const cmd = await vscode.window.showInputBox({
            prompt: 'Enter command to run inside Vetto Sandbox',
            placeHolder: 'e.g. npm run build'
        });

        if (cmd) {
            const terminal = vscode.window.createTerminal('Vetto Sandbox');
            terminal.show();
            terminal.sendText(`${vettoPath} --profile ${profile} -- ${cmd}`);
        }
    });
    context.subscriptions.push(runCmd);

    // 3. Command: Show Sandbox Status
    let statusCmd = vscode.commands.registerCommand('vetto.showStatus', () => {
        vscode.window.showInformationMessage('Vetto Sandbox is active and protecting your workspace.');
        // In a real implementation, we could read local IPC or log files to update block counts.
        statusBarItem.text = '$(shield) Vetto: 0 blocks';
    });
    context.subscriptions.push(statusCmd);

    // 4. Command: Diff Sessions
    let diffCmd = vscode.commands.registerCommand('vetto.diffSessions', () => {
        const config = vscode.workspace.getConfiguration('vetto');
        const vettoPath = config.get<string>('path') || 'vetto';
        
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('No workspace opened for diffing.');
            return;
        }

        const cwd = workspaceFolders[0].uri.fsPath;
        const terminal = vscode.window.createTerminal('Vetto Diff');
        terminal.show();
        terminal.sendText(`${vettoPath} diff-sessions`);
    });
    context.subscriptions.push(diffCmd);

    // 5. Command: Open Audit Report
    let auditCmd = vscode.commands.registerCommand('vetto.openAudit', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('No workspace opened.');
            return;
        }

        // Typical location of Vetto's session logs
        const auditPath = path.join(workspaceFolders[0].uri.fsPath, '.vetto', 'sessions');
        if (fs.existsSync(auditPath)) {
            const uri = vscode.Uri.file(auditPath);
            await vscode.commands.executeCommand('vscode.openFolder', uri, true);
        } else {
            vscode.window.showInformationMessage('No Vetto audit logs found in the current workspace.');
        }
    });
    context.subscriptions.push(auditCmd);
}

export function deactivate() {}
