import * as path from 'path';
import * as vscode from 'vscode';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind
} from 'vscode-languageclient/node';

let client: LanguageClient;

export function activate(context: vscode.ExtensionContext) {
    // Get configuration
    const config = vscode.workspace.getConfiguration('racf');
    const pythonPath = config.get<string>('pythonPath', 'python');
    const customServerPath = config.get<string>('serverPath', '');

    // Determine server path - bundled or custom
    const serverScript = customServerPath ||
        path.join(context.extensionPath, 'server', 'racf_server.py');

    // Server options - spawn the Python process
    const serverOptions: ServerOptions = {
        command: pythonPath,
        args: [serverScript],
        transport: TransportKind.stdio
    };

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector: [{ scheme: 'file', language: 'racf' }],
        synchronize: {
            fileEvents: vscode.workspace.createFileSystemWatcher('**/*.{racf,racfcmd}')
        },
        outputChannelName: 'RACF Language Server'
    };

    // Create and start the client
    client = new LanguageClient(
        'racfLanguageServer',
        'RACF Language Server',
        serverOptions,
        clientOptions
    );

    // Start the client
    client.start();

    // Register info command
    const showInfoCommand = vscode.commands.registerCommand('racf.showInfo', () => {
        vscode.window.showInformationMessage(
            'RACF: Guarding mainframe access since 1976. ' +
            'Your bank account thanks you.'
        );
    });

    context.subscriptions.push(showInfoCommand);
}

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
