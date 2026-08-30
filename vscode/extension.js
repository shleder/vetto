const vscode = require('vscode');

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    let disposable = vscode.commands.registerCommand('vetto.runTaskSandboxed', async () => {
        try {
            const tasks = await vscode.tasks.fetchTasks();
            if (!tasks || tasks.length === 0) {
                vscode.window.showWarningMessage('Vetto: No tasks found in workspace (tasks.json).');
                return;
            }

            const items = tasks.map(t => ({
                label: t.name,
                description: t.source || t.definition.type,
                detail: t.detail,
                task: t
            }));

            const selection = await vscode.window.showQuickPick(items, {
                placeHolder: 'Select a task to run inside the Vetto sandbox'
            });

            if (!selection) {
                return;
            }

            const config = vscode.workspace.getConfiguration('vetto');
            const vettoBin = config.get('executablePath', 'vetto');
            const profile = config.get('defaultProfile', 'default');
            const net = config.get('defaultNet', 'off');

            const task = selection.task;
            let commandToRun = '';

            if (task.execution && task.execution.commandLine) {
                commandToRun = task.execution.commandLine;
            } else if (task.execution && task.execution.command) {
                const args = (task.execution.args || []).map(a => typeof a === 'string' ? a : a.value || '').join(' ');
                commandToRun = `${task.execution.command} ${args}`.trim();
            } else {
                commandToRun = task.name;
            }

            const terminalName = `Vetto Sandbox [${task.name}]`;
            let terminal = vscode.window.terminals.find(t => t.name === terminalName);
            if (!terminal) {
                terminal = vscode.window.createTerminal(terminalName);
            }

            terminal.show();
            const sandboxedCommand = `${vettoBin} --profile ${profile} --net ${net} -- ${commandToRun}`;
            terminal.sendText(sandboxedCommand);

            vscode.window.showInformationMessage(`Vetto: Executing task "${task.name}" sandboxed.`);
        } catch (err) {
            vscode.window.showErrorMessage(`Vetto error: ${err.message || err}`);
        }
    });

    context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};
