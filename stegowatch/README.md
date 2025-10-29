# StegoWatch

Real-time security scanner for VSCode that detects Unicode steganography, invisible characters, and code obfuscation patterns in extensions and source code.

## Features

### 🔍 Automatic Extension Scanning
- Scans new extensions on install
- Detects patterns from real malware (e.g., ellacrity.recoil)
- Instant security alerts with detailed findings

### 🛡️ Code Analysis
- Unicode steganography (U+FE00-U+FE0F, U+E0100-U+E01EF)
- Invisible characters (zero-width spaces, BOM, etc.)
- Bidirectional text attacks (CVE-2021-42574)
- Dynamic code execution (`eval(atob(...))`, `new Function(...)`)
- Command execution (`child_process.exec()`)
- Excessive indentation & homoglyph attacks

### ⚡ Real-Time Detection
- Scans as you type, save, or switch files
- Diagnostics in Problems panel
- Clickable line numbers in reports
- Quick Fix to suppress false positives

## Quick Start

### Installation

```bash
code --install-extension stegowatch-1.0.0.vsix
```

### Commands

| Command | Description |
|---------|-------------|
| `Security: Scan Current File` | Scan active file |
| `Security: Scan All Installed Extensions` | Scan VSCode extensions |
| `Security: Show Anomaly Findings` | View detailed report |
| `Security: Clear Diagnostics and Rescan` | Force refresh |

### Example Detection

```
⚠️ Security Alert: "suspicious-ext" (2 critical)

• Dynamic code execution [🔴 Critical] - index.js:42
• Unicode steganography [🔴 Critical] - utils.js:89
• Invisible character [🟡 Medium] - main.js:156

[View Full Report] [Uninstall] [Dismiss]
```

## Configuration

Settings: `Cmd+,` → search "stegowatch" or "malwareDetector"

```jsonc
{
  "malwareDetector.enabled": true,
  "malwareDetector.autoScanNewExtensions": true,
  "malwareDetector.detectUnicodeStego": true,
  "malwareDetector.minStegoSequence": 10,
  "malwareDetector.maxIndentation": 200,
  "malwareDetector.allowCJKinComments": true
}
```

## False Positives

Suppress findings with comments:

```javascript
// security-ignore: This is intentional for...
eval(someCode); // This line will be ignored
```

Or use Quick Fix (💡) in the editor.

## Documentation

- **QUICK_START.md** - Getting started guide
- **FINDING_FORMAT_GUIDE.md** - Understanding findings format
- **AUTO_SCAN_GUIDE.md** - Automatic extension scanning
- **TROUBLESHOOTING.md** - Common issues and solutions

## Demo

Test with the included demo extension:

```bash
cd demo-suspicious-extension
code --install-extension demo-suspicious-extension-0.1.0.vsix
```

See `demo-suspicious-extension/DEMO_GUIDE.md` for full demo instructions.

## Detection Capabilities

Based on analysis of real malware:
- **ellacrity.recoil** - Unicode steganography (1000+ downloads)
- **GlassWorm** - Token stealing campaign
- **Trojan Source** - CVE-2021-42574

## Development

### Build

```bash
npm install -g vsce
vsce package
```

### Test Files

- `test-examples.js` - All detection types
- `test-chinese-false-positives.js` - Legitimate Chinese code
- `test-multilingual.js` - 10 languages for false positive testing

## License

MIT License

## Credits

Created to address the ellacrity.recoil malware incident and protect developers from supply chain attacks targeting VSCode extensions.
