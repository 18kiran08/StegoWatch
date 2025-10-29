/**
 * Malware Steganography Detector - VSCode Extension
 * 
 * Main extension file that integrates with VSCode API
 */

const vscode = require('vscode');
const { MalwareDetector } = require('./detector');
const fs = require('fs');
const path = require('path');

let diagnosticCollection;
let statusBarItem;
let detectionEnabled = true;
let currentStats = { total: 0, critical: 0, high: 0, medium: 0 };
let extensionScanResults = [];
let previousExtensionIds = new Set();
let latestFindings = []; // Store findings for quick access

/**
 * Extension activation
 */
function activate(context) {
    console.log('Security Scanner is now active');

    // Create diagnostic collection for showing warnings/errors
    diagnosticCollection = vscode.languages.createDiagnosticCollection('security-scanner');
    context.subscriptions.push(diagnosticCollection);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = 'malwareDetector.showReport';
    context.subscriptions.push(statusBarItem);
    updateStatusBar();

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.scanCurrentFile', scanCurrentFile)
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.scanWorkspace', scanWorkspace)
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.showReport', showReport)
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.toggleRealTime', toggleRealTime)
    );
    
    // Register command for ignoring findings
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.ignoreFinding', ignoreFinding)
    );
    
    // Register command for scanning extensions
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.scanInstalledExtensions', scanInstalledExtensions)
    );
    
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.showExtensionReport', showExtensionReport)
    );
    
    // Register command to open file at line
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.openFileAtLine', openFileAtLine)
    );
    
    // Register command to clear all diagnostics
    context.subscriptions.push(
        vscode.commands.registerCommand('malwareDetector.clearDiagnostics', clearAllDiagnostics)
    );
    
    // Register Code Action Provider for Quick Fixes
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file' },
            new SecurityCodeActionProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );

    // Real-time scanning on text change
    context.subscriptions.push(
        vscode.workspace.onDidChangeTextDocument(event => {
            if (detectionEnabled && getConfig().enabled) {
                scanDocument(event.document);
            }
        })
    );

    // Scan on file open
    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(document => {
            if (detectionEnabled && getConfig().enabled) {
                scanDocument(document);
            }
        })
    );

    // Scan on file save
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            if (getConfig().enabled) {
                scanDocument(document);
            }
        })
    );
    
    // Scan when switching between files (active editor changes)
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && detectionEnabled && getConfig().enabled) {
                scanDocument(editor.document);
            }
        })
    );
    
    // Clear diagnostics when a file is closed
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument(document => {
            diagnosticCollection.delete(document.uri);
        })
    );

    // Initialize extension tracking and watch for new installations
    initializeExtensionTracking();
    context.subscriptions.push(
        vscode.extensions.onDidChange(() => {
            checkForNewExtensions();
        })
    );

    // Scan currently open editor on activation
    if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
    }
}

/**
 * Get extension configuration
 */
function getConfig() {
    const config = vscode.workspace.getConfiguration('malwareDetector');
    return {
        enabled: config.get('enabled', true),
        detectUnicodeStego: config.get('detectUnicodeStego', true),
        detectInvisibleChars: config.get('detectInvisibleChars', true),
        detectExcessiveIndentation: config.get('detectExcessiveIndentation', true),
        detectBidiOverride: config.get('detectBidiOverride', true),
        detectHomoglyphs: config.get('detectHomoglyphs', true),
        detectSuspiciousEval: config.get('detectSuspiciousEval', true),
        maxIndentation: config.get('maxIndentation', 200),
        minStegoSequence: config.get('minStegoSequence', 10),
        excludeLanguages: config.get('excludeLanguages', []),
        allowCJKinComments: config.get('allowCJKinComments', true),
        severity: config.get('severity', 'Warning'),
        autoScanNewExtensions: config.get('autoScanNewExtensions', true)
    };
}

/**
 * Scan a single document
 */
function scanDocument(document) {
    console.log('[Security Scanner] Scanning document:', document.fileName, 'Language:', document.languageId);
    
    // Always clear existing diagnostics for this file first
    diagnosticCollection.delete(document.uri);
    
    // Skip certain file types
    const config = getConfig();
    if (config.excludeLanguages.includes(document.languageId)) {
        console.log('[Security Scanner] Skipping excluded language:', document.languageId);
        updateStats([]);
        return;
    }

    // Skip very large files (> 1MB) for performance
    if (document.getText().length > 1024 * 1024) {
        console.log('[Security Scanner] Skipping large file');
        updateStats([]);
        return;
    }

    const text = document.getText();
    const detector = new MalwareDetector(config);
    const detections = detector.detectAnomalies(text, document.languageId);
    
    console.log('[Security Scanner] Found', detections.length, 'detections');

    // Convert detections to VSCode diagnostics
    const diagnostics = detections.map(detection => {
        const range = new vscode.Range(
            detection.line - 1,
            detection.column,
            detection.line - 1,
            detection.column + detection.length
        );

        const severity = mapSeverity(detection.severity, config.severity);
        const diagnostic = new vscode.Diagnostic(range, detection.message, severity);
        
        diagnostic.source = 'Security Scanner';
        diagnostic.code = detection.type;
        
        // Add detailed information
        if (detection.details) {
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, range),
                    detection.details
                )
            ];
        }

        return diagnostic;
    });

    diagnosticCollection.set(document.uri, diagnostics);

    // Update statistics
    updateStats(detections);
}

/**
 * Map detection severity to VSCode diagnostic severity
 */
function mapSeverity(detectionSeverity, configSeverity) {
    if (detectionSeverity === 'critical') {
        return vscode.DiagnosticSeverity.Error;
    }
    
    // Use config setting for non-critical issues
    switch (configSeverity) {
        case 'Error':
            return vscode.DiagnosticSeverity.Error;
        case 'Warning':
            return vscode.DiagnosticSeverity.Warning;
        case 'Information':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Warning;
    }
}

/**
 * Update detection statistics
 */
function updateStats(detections) {
    currentStats = {
        total: detections.length,
        critical: detections.filter(d => d.severity === 'critical').length,
        high: detections.filter(d => d.severity === 'high').length,
        medium: detections.filter(d => d.severity === 'medium').length
    };
    updateStatusBar();
}

/**
 * Update status bar display
 */
function updateStatusBar() {
    if (currentStats.total === 0) {
        statusBarItem.text = '$(shield) Security Scan: Clear';
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = 'No suspicious patterns detected';
    } else if (currentStats.critical > 0) {
        statusBarItem.text = `$(alert) Security: ${currentStats.critical} Critical`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
        statusBarItem.tooltip = `${currentStats.critical} critical, ${currentStats.high} high, ${currentStats.medium} medium severity findings`;
    } else if (currentStats.high > 0) {
        statusBarItem.text = `$(warning) Security: ${currentStats.high} High`;
        statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        statusBarItem.tooltip = `${currentStats.high} high, ${currentStats.medium} medium severity findings`;
    } else {
        statusBarItem.text = `$(info) Security: ${currentStats.medium} Medium`;
        statusBarItem.backgroundColor = undefined;
        statusBarItem.tooltip = `${currentStats.medium} medium severity findings`;
    }
    
    statusBarItem.show();
}

/**
 * Command: Scan current file
 */
function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showInformationMessage('No active editor');
        return;
    }

    scanDocument(editor.document);
    
    if (currentStats.total === 0) {
        vscode.window.showInformationMessage('No suspicious patterns detected in current file');
    } else {
        vscode.window.showWarningMessage(
            `Found ${currentStats.total} potentially suspicious pattern(s) (${currentStats.critical} critical)`,
            'Show Details'
        ).then(selection => {
            if (selection === 'Show Details') {
                showReport();
            }
        });
    }
}

/**
 * Command: Scan entire workspace
 */
async function scanWorkspace() {
    const config = getConfig();
    
    // Clear existing diagnostics
    diagnosticCollection.clear();
    
    // Show progress
    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Scanning workspace for suspicious patterns...",
        cancellable: true
    }, async (progress, token) => {
        // Find all files (excluding node_modules, etc.)
        const files = await vscode.workspace.findFiles(
            '**/*.{js,ts,jsx,tsx,py,java,go,rs,php,rb}',
            '**/node_modules/**'
        );
        
        let scannedFiles = 0;
        let totalDetections = 0;
        
        for (const fileUri of files) {
            if (token.isCancellationRequested) {
                break;
            }
            
            const document = await vscode.workspace.openTextDocument(fileUri);
            scanDocument(document);
            
            scannedFiles++;
            totalDetections += currentStats.total;
            
            progress.report({
                increment: (100 / files.length),
                message: `${scannedFiles}/${files.length} files (${totalDetections} issues found)`
            });
        }
        
        return { scannedFiles, totalDetections };
    }).then(result => {
        if (result.totalDetections === 0) {
            vscode.window.showInformationMessage(
                `Scanned ${result.scannedFiles} files - No suspicious patterns detected`
            );
        } else {
            vscode.window.showWarningMessage(
                `Scanned ${result.scannedFiles} files - Found ${result.totalDetections} potentially suspicious pattern(s)`,
                'Show Problems'
            ).then(selection => {
                if (selection === 'Show Problems') {
                    vscode.commands.executeCommand('workbench.actions.view.problems');
                }
            });
        }
    });
}

/**
 * Command: Show detailed report
 */
function showReport() {
    const panel = vscode.window.createWebviewPanel(
        'securityReport',
        'Anomaly Findings',
        vscode.ViewColumn.Two,
        {}
    );

    panel.webview.html = generateReportHTML();
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

/**
 * Generate HTML report
 */
function generateReportHTML() {
    const config = getConfig();
    
    // Collect all diagnostics from the collection
    const allFindings = [];
    diagnosticCollection.forEach((uri, diagnostics) => {
        diagnostics.forEach(diagnostic => {
            const fileName = path.basename(uri.fsPath);
            const line = diagnostic.range.start.line + 1;
            const message = diagnostic.message;
            
            // Determine severity
            let severity = 'Medium';
            if (diagnostic.severity === vscode.DiagnosticSeverity.Error) {
                severity = 'Critical';
            } else if (diagnostic.severity === vscode.DiagnosticSeverity.Warning) {
                severity = 'High';
            }
            
            allFindings.push({
                file: fileName,
                filePath: uri.fsPath,
                line: line,
                message: message,
                severity: severity,
                findingName: extractFindingName(message)
            });
        });
    });
    
    return `<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Anomaly Findings</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                color: var(--vscode-foreground);
                background-color: var(--vscode-editor-background);
                padding: 40px 60px;
                line-height: 1.7;
                max-width: 1200px;
                margin: 0 auto;
            }
            
            h1 {
                font-size: 32px;
                font-weight: 600;
                color: var(--vscode-foreground);
                margin-bottom: 8px;
                letter-spacing: -0.5px;
            }
            
            .subtitle {
                color: var(--vscode-descriptionForeground);
                font-size: 14px;
                margin-bottom: 40px;
            }
            
            h2 {
                font-size: 20px;
                font-weight: 600;
                color: var(--vscode-foreground);
                margin-top: 48px;
                margin-bottom: 20px;
                padding-bottom: 8px;
                border-bottom: 1px solid var(--vscode-panel-border);
            }
            
            h3 {
                font-size: 16px;
                font-weight: 600;
                color: var(--vscode-foreground);
                margin-top: 24px;
                margin-bottom: 12px;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 16px;
                margin: 32px 0;
            }
            
            .stat-card {
                background: var(--vscode-textBlockQuote-background);
                border: 1px solid var(--vscode-panel-border);
                border-radius: 8px;
                padding: 20px;
                transition: transform 0.2s;
            }
            
            .stat-card:hover {
                transform: translateY(-2px);
            }
            
            .stat-label {
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                color: var(--vscode-descriptionForeground);
                margin-bottom: 8px;
            }
            
            .stat-value {
                font-size: 36px;
                font-weight: 700;
                line-height: 1;
            }
            
            .stat-value.critical { color: #f48771; }
            .stat-value.high { color: #f0ad4e; }
            .stat-value.medium { color: #5bc0de; }
            .stat-value.total { color: var(--vscode-textLink-foreground); }
            
            .category-card {
                background: var(--vscode-textBlockQuote-background);
                border: 1px solid var(--vscode-panel-border);
                border-radius: 8px;
                padding: 24px;
                margin-bottom: 16px;
            }
            
            .category-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 16px;
            }
            
            .severity-badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 12px;
                font-size: 11px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            
            .severity-badge.critical {
                background: rgba(244, 135, 113, 0.15);
                color: #f48771;
            }
            
            .severity-badge.high {
                background: rgba(240, 173, 78, 0.15);
                color: #f0ad4e;
            }
            
            .category-card ul {
                margin: 12px 0;
                padding-left: 20px;
            }
            
            .category-card li {
                margin: 8px 0;
                color: var(--vscode-descriptionForeground);
            }
            
            .category-card p {
                color: var(--vscode-descriptionForeground);
                margin: 12px 0;
            }
            
            .category-card strong {
                color: var(--vscode-foreground);
            }
            
            code {
                background: var(--vscode-textCodeBlock-background);
                padding: 3px 6px;
                border-radius: 4px;
                font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
                font-size: 13px;
                color: var(--vscode-textPreformat-foreground);
            }
            
            .info-section {
                background: var(--vscode-textBlockQuote-background);
                border-left: 3px solid var(--vscode-textLink-foreground);
                padding: 20px;
                margin: 24px 0;
                border-radius: 0 8px 8px 0;
            }
            
            .config-table {
                width: 100%;
                margin: 16px 0;
                border-collapse: collapse;
            }
            
            .config-table td {
                padding: 10px;
                border-bottom: 1px solid var(--vscode-panel-border);
            }
            
            .config-table td:first-child {
                font-weight: 600;
                color: var(--vscode-foreground);
                width: 200px;
            }
            
            .config-table td:last-child {
                color: var(--vscode-descriptionForeground);
            }
            
            .status-enabled {
                color: #73c991;
                font-weight: 600;
            }
            
            .status-disabled {
                color: #f48771;
                font-weight: 600;
            }
            
            .finding-card {
                background: var(--vscode-editor-inactiveSelectionBackground);
                border: 1px solid var(--vscode-panel-border);
                border-radius: 8px;
                padding: 16px 20px;
                margin-bottom: 12px;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            
            .finding-card:hover {
                transform: translateY(-1px);
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            }
            
            .finding-header {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 10px;
                gap: 12px;
            }
            
            .finding-info {
                display: flex;
                align-items: center;
                gap: 10px;
                flex: 1;
            }
            
            .finding-title {
                font-weight: 600;
                font-size: 15px;
                color: var(--vscode-foreground);
            }
            
            .finding-location {
                font-family: 'Monaco', 'Menlo', 'Consolas', monospace;
                font-size: 13px;
                color: var(--vscode-textLink-foreground);
            }
            
            .finding-location code {
                background: var(--vscode-textCodeBlock-background);
                padding: 4px 8px;
                border-radius: 4px;
            }
            
            .finding-message {
                color: var(--vscode-descriptionForeground);
                font-size: 13px;
                line-height: 1.6;
                padding-left: 0;
            }
            
            .finding-card .severity-badge.critical {
                background: #f14c4c;
                color: white;
            }
            
            .finding-card .severity-badge.high {
                background: #ff9800;
                color: white;
            }
            
            .finding-card .severity-badge.medium {
                background: #ffc107;
                color: #333;
            }
        </style>
    </head>
    <body>
        <h1>Anomaly Findings</h1>
        <div class="subtitle">Detected ${currentStats.total} potential code anomalies: ${currentStats.critical} critical, ${currentStats.high} high, ${currentStats.medium} medium severity</div>
        
        ${allFindings.length > 0 ? `
            <h2>Findings</h2>
            ${allFindings.map((finding, index) => `
                <div class="finding-card">
                    <div class="finding-header">
                        <div class="finding-info">
                            <span class="finding-title">${escapeHtml(finding.findingName)}</span>
                            <span class="severity-badge ${finding.severity.toLowerCase()}">${finding.severity}</span>
                        </div>
                        <div class="finding-location">
                            <code>${escapeHtml(finding.file)}:${finding.line}</code>
                        </div>
                    </div>
                    <div class="finding-message">
                        ${escapeHtml(finding.message)}
                    </div>
                </div>
            `).join('')}
        ` : ''}
        
        <h2>Detection Categories</h2>
        
        <div class="category-card">
            <div class="category-header">
                <h3>Unicode Steganography</h3>
                <span class="severity-badge critical">Critical</span>
            </div>
            <p>Detects sequences of invisible Unicode characters that could encode hidden data.</p>
            <ul>
                <li>Unicode Variation Selectors (U+FE00 to U+FE0F, U+E0100 to U+E01EF)</li>
                <li>Private Use Area characters (U+E000 to U+F8FF)</li>
            </ul>
            <p><strong>Context:</strong> Similar patterns have been observed in documented security incidents but may also occur in legitimate internationalization contexts. Review the source and intended purpose.</p>
        </div>

        <div class="category-card">
            <div class="category-header">
                <h3>Bidirectional Text Controls</h3>
                <span class="severity-badge critical">Critical</span>
            </div>
            <p>Detects bidirectional text control characters that can alter text rendering direction.</p>
            <ul>
                <li>Left-to-Right/Right-to-Left Override characters</li>
                <li>Referenced in CVE-2021-42574 (Trojan Source vulnerability)</li>
            </ul>
            <p><strong>Context:</strong> May be legitimate in right-to-left language contexts but warrant review in typical source code files.</p>
        </div>

        <div class="category-card">
            <div class="category-header">
                <h3>Zero-Width Characters</h3>
                <span class="severity-badge high">High</span>
            </div>
            <p>Detects invisible spacing and control characters in source code.</p>
            <ul>
                <li>Zero-Width Space (U+200B)</li>
                <li>Zero-Width Joiner/Non-Joiner (U+200C, U+200D)</li>
                <li>Zero-Width No-Break Space (U+FEFF)</li>
            </ul>
            <p><strong>Context:</strong> May be used for legitimate text processing or could indicate unintentional artifacts from copy-paste operations.</p>
        </div>

        <div class="category-card">
            <div class="category-header">
                <h3>Unusual Indentation</h3>
                <span class="severity-badge high">High</span>
            </div>
            <p>Detects lines with more than ${config.maxIndentation} spaces of leading whitespace.</p>
            <p><strong>Context:</strong> May indicate unusual code structure, generated code, or could be intentional formatting. Verify this aligns with your codebase standards.</p>
        </div>

        <div class="category-card">
            <div class="category-header">
                <h3>Non-ASCII Identifiers</h3>
                <span class="severity-badge high">High</span>
            </div>
            <p>Detects lookalike characters in code identifiers (homoglyphs).</p>
            <ul>
                <li>Cyrillic characters that resemble Latin (e.g., 'а' vs 'a')</li>
                <li>Greek characters that resemble Latin (e.g., 'ο' vs 'o')</li>
            </ul>
            <p><strong>Context:</strong> May be intentional for internationalization or could indicate unintentional character confusion.</p>
        </div>

        <div class="category-card">
            <div class="category-header">
                <h3>Dynamic Code Execution</h3>
                <span class="severity-badge critical">Critical</span>
            </div>
            <p>Detects patterns involving dynamic code execution and evaluation.</p>
            <ul>
                <li><code>eval(atob(...))</code> - Base64 decode and execute</li>
                <li><code>Function(atob(...))</code> - Dynamic function creation</li>
                <li><code>child_process.exec()</code> - Command execution</li>
            </ul>
            <p><strong>Context:</strong> May be legitimate but warrants review to ensure proper input validation and that sources are trusted.</p>
        </div>

        <h2>Current Configuration</h2>
        <div class="info-section">
            <p><strong>Settings</strong></p>
            <p>These settings control the detection behavior. To change them, go to <strong>VSCode Settings</strong> (Cmd+, or Ctrl+,) and search for "suspicious code" or "malwareDetector".</p>
        </div>
        <table class="config-table">
            <tr>
                <td>Scanner Status</td>
                <td><span class="${config.enabled ? 'status-enabled' : 'status-disabled'}">${config.enabled ? 'Enabled' : 'Disabled'}</span></td>
            </tr>
            <tr>
                <td>Real-time Scanning</td>
                <td><span class="${detectionEnabled ? 'status-enabled' : 'status-disabled'}">${detectionEnabled ? 'Active' : 'Paused'}</span></td>
            </tr>
            <tr>
                <td>CJK Support</td>
                <td>${config.allowCJKinComments ? 'Allowed in comments (reduces false positives)' : 'Strict detection mode'}</td>
            </tr>
            <tr>
                <td>Max Indentation</td>
                <td>${config.maxIndentation} spaces</td>
            </tr>
            <tr>
                <td>Min Stego Sequence</td>
                <td>${config.minStegoSequence} characters</td>
            </tr>
        </table>

        <h2>Important Information</h2>
        <div class="info-section">
            <p><strong>About Detections</strong></p>
            <p>This tool identifies potentially suspicious code patterns based on research of documented security vulnerabilities and attack techniques. Detections are indicators that warrant review, not confirmations of malicious intent.</p>
        </div>
        
        <div class="info-section">
            <p><strong>False Positives</strong></p>
            <p>Some patterns may occur in legitimate code, particularly in internationalized applications, generated code, or specialized use cases. You can suppress false positives by adding <code>// security-ignore</code> comments. Configure thresholds and exclusions in settings as needed for your environment.</p>
        </div>
        
        <div class="info-section">
            <p><strong>Detection Research</strong></p>
            <p>Detection patterns are based on analysis of documented security vulnerabilities (including CVE-2021-42574) and publicly disclosed security incidents. Patterns are continuously updated based on security research.</p>
        </div>
    </body>
    </html>`;
}

/**
 * Command: Toggle real-time detection
 */
function toggleRealTime() {
    detectionEnabled = !detectionEnabled;
    
    if (detectionEnabled) {
        vscode.window.showInformationMessage('Real-time security scanning enabled');
        // Scan current document
        if (vscode.window.activeTextEditor) {
            scanDocument(vscode.window.activeTextEditor.document);
        }
    } else {
        vscode.window.showInformationMessage('Real-time security scanning paused');
    }
}

/**
 * Command: Ignore a finding (add security-ignore comment)
 */
async function ignoreFinding(document, line) {
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document !== document) {
        return;
    }

    const reason = await vscode.window.showInputBox({
        prompt: 'Enter reason for ignoring this finding (optional)',
        placeHolder: 'e.g., This is intentional for...'
    });

    const commentText = reason 
        ? `// security-ignore: ${reason}`
        : '// security-ignore';

    const edit = new vscode.WorkspaceEdit();
    const lineObj = document.lineAt(line);
    const indent = lineObj.text.match(/^\s*/)[0];
    edit.insert(document.uri, new vscode.Position(line, 0), `${indent}${commentText}\n`);

    await vscode.workspace.applyEdit(edit);
    vscode.window.showInformationMessage('Finding ignored. The line will be excluded from future scans.');
}

/**
 * Code Action Provider for Quick Fixes
 */
class SecurityCodeActionProvider {
    provideCodeActions(document, range, context) {
        const codeActions = [];

        // Offer "Ignore this finding" quick fix for each diagnostic
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === 'Security Scanner') {
                const action = new vscode.CodeAction(
                    'Ignore this finding (add security-ignore comment)',
                    vscode.CodeActionKind.QuickFix
                );
                action.command = {
                    command: 'malwareDetector.ignoreFinding',
                    title: 'Ignore Finding',
                    arguments: [document, range.start.line]
                };
                action.diagnostics = [diagnostic];
                action.isPreferred = false;
                codeActions.push(action);
            }
        }

        return codeActions;
    }
}

/**
 * Extract short finding name from detection message
 */
function extractFindingName(message) {
    // Remove warning emoji
    message = message.replace(/⚠️\s*/g, '');
    
    // Common patterns to extract
    const patterns = [
        /^(Unicode steganography|Potential Unicode steganography)/i,
        /^(Dynamic code execution|Suspicious code execution)/i,
        /^(Invisible character)/i,
        /^(Bidirectional text)/i,
        /^(Command execution)/i,
        /^(Unusual indentation|Excessive indentation)/i,
        /^(Homoglyph|Non-ASCII character)/i
    ];
    
    for (const pattern of patterns) {
        const match = message.match(pattern);
        if (match) return match[1];
    }
    
    // Extract first part before "detected" or colon
    if (message.includes(' detected')) {
        return message.split(' detected')[0].trim();
    }
    if (message.includes(':')) {
        const part = message.split(':')[0].trim();
        if (part.length < 50) return part;
    }
    
    // Fallback: first 40 chars
    return message.substring(0, 40).trim() + (message.length > 40 ? '...' : '');
}

/**
 * Get severity badge with emoji
 */
function getSeverityBadge(severity) {
    const badges = {
        'Critical': '[🔴 Critical]',
        'High': '[🟠 High]',
        'Medium': '[🟡 Medium]',
        'Low': '[🔵 Low]'
    };
    return badges[severity] || `[${severity}]`;
}

/**
 * Command to open a file at a specific line
 */
async function openFileAtLine(filePath, line) {
    try {
        const document = await vscode.workspace.openTextDocument(filePath);
        const editor = await vscode.window.showTextDocument(document);
        const position = new vscode.Position(line - 1, 0);
        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(new vscode.Range(position, position), vscode.TextEditorRevealType.InCenter);
    } catch (error) {
        vscode.window.showErrorMessage(`Could not open ${filePath}: ${error.message}`);
    }
}

/**
 * Clear all diagnostics and rescan current file
 */
async function clearAllDiagnostics() {
    console.log('[Security Scanner] Clearing all diagnostics and rescanning');
    
    // Clear all diagnostics
    diagnosticCollection.clear();
    
    // Reset stats
    currentStats = { total: 0, critical: 0, high: 0, medium: 0 };
    updateStatusBar();
    
    // Rescan current file if one is open
    if (vscode.window.activeTextEditor) {
        scanDocument(vscode.window.activeTextEditor.document);
        vscode.window.showInformationMessage('Diagnostics cleared and file rescanned');
    } else {
        vscode.window.showInformationMessage('Diagnostics cleared');
    }
}

/**
 * Initialize tracking of currently installed extensions
 */
function initializeExtensionTracking() {
    previousExtensionIds.clear();
    vscode.extensions.all
        .filter(ext => !ext.id.startsWith('vscode.') && ext.extensionPath)
        .forEach(ext => previousExtensionIds.add(ext.id));
    
    console.log(`[Security Scanner] Tracking ${previousExtensionIds.size} extensions for changes`);
}

/**
 * Check for newly installed extensions and scan them automatically
 */
async function checkForNewExtensions() {
    const currentExtensions = vscode.extensions.all.filter(ext => 
        !ext.id.startsWith('vscode.') && ext.extensionPath
    );
    
    const newExtensions = currentExtensions.filter(ext => 
        !previousExtensionIds.has(ext.id)
    );
    
    if (newExtensions.length > 0) {
        console.log(`[Security Scanner] Detected ${newExtensions.length} new extension(s):`, 
            newExtensions.map(e => e.id).join(', '));
        
        // Update tracking
        newExtensions.forEach(ext => previousExtensionIds.add(ext.id));
        
        // Auto-scan new extensions
        await scanNewExtensions(newExtensions);
    }
    
    // Also check for removed extensions
    const currentIds = new Set(currentExtensions.map(ext => ext.id));
    const removedIds = [...previousExtensionIds].filter(id => !currentIds.has(id));
    
    if (removedIds.length > 0) {
        console.log(`[Security Scanner] Detected ${removedIds.length} removed extension(s):`, 
            removedIds.join(', '));
        removedIds.forEach(id => previousExtensionIds.delete(id));
    }
}

/**
 * Scan newly installed extensions automatically
 */
async function scanNewExtensions(newExtensions) {
    const config = getConfig();
    if (!config.autoScanNewExtensions) {
        // If auto-scan is disabled, just notify
        const choice = await vscode.window.showInformationMessage(
            `New extension(s) installed: ${newExtensions.map(e => e.id.split('.')[1]).join(', ')}. Scan for security issues?`,
            'Scan Now',
            'Skip'
        );
        
        if (choice !== 'Scan Now') {
            return;
        }
    }
    
    const detector = new MalwareDetector(config);
    const newResults = [];
    
    for (const extension of newExtensions) {
        console.log(`[Security Scanner] Auto-scanning new extension: ${extension.id}`);
        const result = await scanExtension(extension);
        
        if (result.issues.length > 0) {
            newResults.push(result);
            extensionScanResults.push(result);
        }
    }
    
    // Show results
    if (newResults.length > 0) {
        // Build detailed findings list with clickable links
        const ext = newResults[0]; // Focus on first extension for now
        const findings = [];
        latestFindings = []; // Clear previous findings
        
        ext.issues.forEach(issue => {
            issue.detections.forEach(detection => {
                const fileName = issue.file.split('/').pop(); // Just filename
                const fullPath = path.join(ext.path, issue.file);
                const findingName = extractFindingName(detection.message);
                const severityBadge = getSeverityBadge(detection.severity);
                
                // Store for command reference
                latestFindings.push({ path: fullPath, line: detection.line });
                const findingIndex = latestFindings.length - 1;
                
                findings.push(`• ${findingName} ${severityBadge} - ${fileName}:${detection.line}`);
            });
        });
        
        // Limit to first 10 findings for notification
        const displayFindings = findings.slice(0, 10);
        const moreCount = findings.length - displayFindings.length;
        
        const extensionName = ext.id.split('.')[1];
        const criticalCount = ext.issues.reduce((sum, issue) => 
            sum + issue.detections.filter(d => d.severity === 'Critical').length, 0
        );
        
        // Build notification message
        const findingsList = displayFindings.join('\n');
        const moreText = moreCount > 0 ? `\n...and ${moreCount} more` : '';
        
        const message = `⚠️ Security Alert: "${extensionName}"${criticalCount > 0 ? ` (${criticalCount} critical)` : ''}\n\n${findingsList}${moreText}\n\nClick "View Full Report" to see all details and jump to code.`;
        
        const choice = await vscode.window.showWarningMessage(
            message,
            { modal: false },
            'View Full Report',
            'Uninstall',
            'Dismiss'
        );
        
        if (choice === 'View Full Report') {
            showExtensionReport();
        } else if (choice === 'Uninstall') {
            const uninstallChoice = await vscode.window.showWarningMessage(
                `Uninstall "${ext.name}" (${ext.id})?`,
                'Yes, Uninstall',
                'Cancel'
            );
            
            if (uninstallChoice === 'Yes, Uninstall') {
                await vscode.commands.executeCommand('workbench.extensions.uninstallExtension', ext.id);
                vscode.window.showInformationMessage(`Extension "${ext.name}" has been uninstalled.`);
            }
        }
    } else {
        // Only show success notification if auto-scan is enabled
        if (config.autoScanNewExtensions) {
            const extensionNames = newExtensions.map(e => e.id.split('.')[1]).join(', ');
            vscode.window.showInformationMessage(
                `Security Scan: New extension "${extensionNames}" appears clean.`
            );
        }
    }
}

/**
 * Scan all installed VSCode extensions
 */
async function scanInstalledExtensions() {
    const startTime = Date.now();
    extensionScanResults = [];
    
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Scanning installed extensions...",
        cancellable: false
    }, async (progress) => {
        const extensions = vscode.extensions.all.filter(ext => 
            !ext.id.startsWith('vscode.') && // Skip built-in extensions
            ext.extensionPath
        );
        
        console.log(`[Security Scanner] Scanning ${extensions.length} extensions`);
        
        let scanned = 0;
        for (const extension of extensions) {
            scanned++;
            progress.report({ 
                message: `${scanned}/${extensions.length}: ${extension.id}`,
                increment: (1 / extensions.length) * 100
            });
            
            const result = await scanExtension(extension);
            if (result.issues.length > 0) {
                extensionScanResults.push(result);
            }
        }
        
        const duration = ((Date.now() - startTime) / 1000).toFixed(1);
        const suspiciousCount = extensionScanResults.length;
        
        if (suspiciousCount > 0) {
            // Build summary of all findings with structured format
            const allFindings = [];
            latestFindings = []; // Clear previous findings
            
            extensionScanResults.forEach(ext => {
                const extName = ext.id.split('.')[1];
                ext.issues.forEach(issue => {
                    issue.detections.forEach(detection => {
                        const fileName = issue.file.split('/').pop();
                        const fullPath = path.join(ext.path, issue.file);
                        const findingName = extractFindingName(detection.message);
                        const severityBadge = getSeverityBadge(detection.severity);
                        
                        // Store for command reference
                        latestFindings.push({ path: fullPath, line: detection.line });
                        
                        allFindings.push(`• ${findingName} ${severityBadge} - ${extName}/${fileName}:${detection.line}`);
                    });
                });
            });
            
            // Show first 10 findings
            const displayFindings = allFindings.slice(0, 10);
            const moreCount = allFindings.length - displayFindings.length;
            const findingsList = displayFindings.join('\n');
            const moreText = moreCount > 0 ? `\n...and ${moreCount} more` : '';
            
            const message = `⚠️ Found issues in ${suspiciousCount} extension(s) (${duration}s)\n\n${findingsList}${moreText}\n\nClick "View Full Report" to see all details and jump to code.`;
            
            const choice = await vscode.window.showWarningMessage(
                message,
                { modal: false },
                'View Full Report',
                'Dismiss'
            );
            
            if (choice === 'View Full Report') {
                showExtensionReport();
            }
        } else {
            vscode.window.showInformationMessage(
                `Security Scan Complete: All ${extensions.length} extensions appear clean (${duration}s)`
            );
        }
    });
}

/**
 * Scan a single extension for suspicious patterns
 */
async function scanExtension(extension) {
    const result = {
        id: extension.id,
        name: extension.packageJSON?.displayName || extension.id,
        publisher: extension.packageJSON?.publisher || 'unknown',
        version: extension.packageJSON?.version || 'unknown',
        path: extension.extensionPath,
        issues: []
    };
    
    try {
        // Scan JavaScript files in the extension
        const jsFiles = findFilesInExtension(extension.extensionPath, ['.js', '.node']);
        const config = getConfig();
        const detector = new MalwareDetector(config);
        
        for (const filePath of jsFiles) {
            try {
                const content = fs.readFileSync(filePath, 'utf8');
                const detections = detector.detectAnomalies(content, 'javascript');
                
                if (detections.length > 0) {
                    result.issues.push({
                        file: path.relative(extension.extensionPath, filePath),
                        detections: detections.map(d => ({
                            line: d.line,
                            message: d.message,
                            severity: d.severity
                        }))
                    });
                }
            } catch (err) {
                // Skip files that can't be read (binary, etc.)
                if (err.code !== 'EISDIR') {
                    console.log(`[Security Scanner] Could not read ${filePath}: ${err.message}`);
                }
            }
        }
    } catch (err) {
        console.error(`[Security Scanner] Error scanning extension ${extension.id}:`, err);
    }
    
    return result;
}

/**
 * Recursively find files with specific extensions
 */
function findFilesInExtension(dir, extensions, maxFiles = 100) {
    const files = [];
    
    function scan(currentDir, depth = 0) {
        if (depth > 10 || files.length >= maxFiles) return; // Prevent deep recursion and limit files
        
        try {
            const entries = fs.readdirSync(currentDir, { withFileTypes: true });
            
            for (const entry of entries) {
                if (files.length >= maxFiles) break;
                
                const fullPath = path.join(currentDir, entry.name);
                
                // Skip common large directories
                if (entry.isDirectory()) {
                    if (!['node_modules', 'test', 'tests', '.git'].includes(entry.name)) {
                        scan(fullPath, depth + 1);
                    }
                } else if (entry.isFile()) {
                    const ext = path.extname(entry.name);
                    if (extensions.includes(ext)) {
                        files.push(fullPath);
                    }
                }
            }
        } catch (err) {
            // Skip directories we can't read
        }
    }
    
    scan(dir);
    return files;
}

/**
 * Show extension scan report
 */
function showExtensionReport() {
    const panel = vscode.window.createWebviewPanel(
        'extensionSecurityReport',
        'Extension Security Scan',
        vscode.ViewColumn.One,
        { enableScripts: true }
    );
    
    // Handle messages from webview
    panel.webview.onDidReceiveMessage(
        async message => {
            if (message.command === 'openFile') {
                await openFileAtLine(message.file, message.line);
            }
        }
    );
    
    panel.webview.html = generateExtensionReportHTML();
}

/**
 * Generate HTML report for extension scan
 */
function generateExtensionReportHTML() {
    const totalExtensions = extensionScanResults.length;
    let totalIssues = 0;
    
    extensionScanResults.forEach(ext => {
        ext.issues.forEach(issue => {
            totalIssues += issue.detections.length;
        });
    });
    
    const extensionRows = extensionScanResults.map(ext => {
        const issueCount = ext.issues.reduce((sum, issue) => sum + issue.detections.length, 0);
        const criticalCount = ext.issues.reduce((sum, issue) => 
            sum + issue.detections.filter(d => d.severity === 'Critical').length, 0);
        
        const filesList = ext.issues.map(issue => {
            const fullPath = path.join(ext.path, issue.file);
            return `
            <div class="file-section">
                <div class="file-name">${escapeHtml(issue.file)}</div>
                <div class="detections">
                    ${issue.detections.map(d => {
                        const findingName = extractFindingName(d.message);
                        const encodedPath = encodeURIComponent(fullPath);
                        return `
                        <div class="detection-item severity-${d.severity.toLowerCase()}">
                            <span class="finding-name">${escapeHtml(findingName)}</span>
                            <span class="severity-badge">${d.severity}</span>
                            <a href="#" class="line-link" data-file="${encodedPath}" data-line="${d.line}" 
                               title="Click to open ${issue.file}:${d.line}">
                                📍 Line ${d.line}
                            </a>
                        </div>
                    `;
                    }).join('')}
                </div>
            </div>
        `;
        }).join('');
        
        return `
            <div class="extension-card ${criticalCount > 0 ? 'critical' : ''}">
                <div class="extension-header">
                    <div class="extension-title">
                        <h3>${escapeHtml(ext.name)}</h3>
                        <span class="extension-id">${escapeHtml(ext.id)}</span>
                    </div>
                    <div class="extension-meta">
                        <span class="publisher">by ${escapeHtml(ext.publisher)}</span>
                        <span class="version">v${escapeHtml(ext.version)}</span>
                    </div>
                </div>
                <div class="issue-summary">
                    <span class="issue-count">${issueCount} potential issue(s) found</span>
                    ${criticalCount > 0 ? `<span class="critical-badge">${criticalCount} critical</span>` : ''}
                </div>
                <div class="files-list">
                    ${filesList}
                </div>
            </div>
        `;
    }).join('');
    
    return `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    padding: 30px;
                    background: var(--vscode-editor-background);
                    color: var(--vscode-editor-foreground);
                    line-height: 1.6;
                }
                h1 {
                    font-size: 28px;
                    margin-bottom: 10px;
                    font-weight: 600;
                }
                .subtitle {
                    font-size: 16px;
                    color: var(--vscode-descriptionForeground);
                    margin-bottom: 30px;
                }
                .extension-card {
                    background: var(--vscode-editor-inactiveSelectionBackground);
                    border: 1px solid var(--vscode-panel-border);
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                }
                .extension-card.critical {
                    border-left: 4px solid #f14c4c;
                }
                .extension-header {
                    margin-bottom: 15px;
                }
                .extension-title {
                    display: flex;
                    align-items: baseline;
                    gap: 12px;
                    margin-bottom: 5px;
                }
                .extension-title h3 {
                    font-size: 20px;
                    font-weight: 600;
                }
                .extension-id {
                    font-size: 13px;
                    color: var(--vscode-descriptionForeground);
                    font-family: 'Courier New', monospace;
                }
                .extension-meta {
                    display: flex;
                    gap: 15px;
                    font-size: 13px;
                    color: var(--vscode-descriptionForeground);
                }
                .issue-summary {
                    display: flex;
                    gap: 10px;
                    align-items: center;
                    margin-bottom: 15px;
                    padding: 10px;
                    background: var(--vscode-textBlockQuote-background);
                    border-radius: 4px;
                }
                .issue-count {
                    font-weight: 500;
                }
                .critical-badge {
                    background: #f14c4c;
                    color: white;
                    padding: 2px 8px;
                    border-radius: 10px;
                    font-size: 12px;
                    font-weight: 500;
                }
                .file-section {
                    margin-bottom: 15px;
                }
                .file-name {
                    font-family: 'Courier New', monospace;
                    font-size: 13px;
                    color: var(--vscode-textLink-foreground);
                    margin-bottom: 8px;
                    font-weight: 500;
                }
                .detections {
                    margin-left: 20px;
                }
                .detection-item {
                    padding: 10px 12px;
                    margin-bottom: 8px;
                    border-radius: 4px;
                    display: flex;
                    gap: 12px;
                    align-items: center;
                    font-size: 13px;
                }
                .detection-item.severity-critical {
                    background: rgba(241, 76, 76, 0.1);
                    border-left: 3px solid #f14c4c;
                }
                .detection-item.severity-high {
                    background: rgba(255, 152, 0, 0.1);
                    border-left: 3px solid #ff9800;
                }
                .detection-item.severity-medium {
                    background: rgba(255, 193, 7, 0.1);
                    border-left: 3px solid #ffc107;
                }
                .finding-name {
                    flex: 1;
                    font-weight: 500;
                }
                .severity-badge {
                    padding: 3px 8px;
                    border-radius: 10px;
                    font-size: 11px;
                    font-weight: 600;
                    text-transform: uppercase;
                    min-width: 80px;
                    text-align: center;
                }
                .severity-critical .severity-badge {
                    background: #f14c4c;
                    color: white;
                }
                .severity-high .severity-badge {
                    background: #ff9800;
                    color: white;
                }
                .severity-medium .severity-badge {
                    background: #ffc107;
                    color: #333;
                }
                .line-link {
                    font-family: 'Courier New', monospace;
                    color: var(--vscode-textLink-foreground);
                    text-decoration: none;
                    font-weight: 500;
                    padding: 4px 8px;
                    border-radius: 4px;
                    background: var(--vscode-textBlockQuote-background);
                    cursor: pointer;
                    white-space: nowrap;
                    transition: background 0.2s;
                }
                .line-link:hover {
                    background: var(--vscode-list-hoverBackground);
                    text-decoration: none;
                }
                .empty-state {
                    text-align: center;
                    padding: 60px 20px;
                    color: var(--vscode-descriptionForeground);
                }
                .info-box {
                    background: var(--vscode-textBlockQuote-background);
                    border-left: 4px solid var(--vscode-textLink-foreground);
                    padding: 15px;
                    margin-bottom: 30px;
                    border-radius: 4px;
                }
            </style>
        </head>
        <body>
            <h1>Extension Security Scan Results</h1>
            <div class="subtitle">
                Found potential issues in ${totalExtensions} extension(s) - ${totalIssues} total findings
            </div>
            
            ${totalExtensions === 0 ? `
                <div class="empty-state">
                    <h2>No Issues Found</h2>
                    <p>All scanned extensions appear to be clean.</p>
                </div>
            ` : `
                <div class="info-box">
                    <strong>Note:</strong> These findings indicate potentially suspicious code patterns. 
                    Review each carefully as some may be legitimate functionality. Consider the extension's 
                    reputation, publisher, and use case before uninstalling.
                </div>
                ${extensionRows}
            `}
            <script>
                const vscode = acquireVsCodeApi();
                
                // Handle line link clicks
                document.addEventListener('click', (e) => {
                    if (e.target.classList.contains('line-link') || e.target.closest('.line-link')) {
                        e.preventDefault();
                        const link = e.target.classList.contains('line-link') ? e.target : e.target.closest('.line-link');
                        const filePath = decodeURIComponent(link.dataset.file);
                        const line = parseInt(link.dataset.line);
                        
                        vscode.postMessage({
                            command: 'openFile',
                            file: filePath,
                            line: line
                        });
                    }
                });
            </script>
        </body>
        </html>
    `;
}

/**
 * Extension deactivation
 */
function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}

module.exports = {
    activate,
    deactivate
};

