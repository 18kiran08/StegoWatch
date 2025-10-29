/**
 * Malware Steganography Detector - Core Detection Logic
 * 
 * This module implements detection algorithms for various code obfuscation
 * and steganography techniques used by malware like GlassWorm and ellacrity.recoil.
 */

/**
 * Unicode Character Categories for Detection
 */
const UnicodeCategories = {
    // Unicode Variation Selectors (used in ellacrity.recoil malware)
    VARIATION_SELECTORS_1_16: {
        ranges: [[0xFE00, 0xFE0F]],
        name: "Variation Selectors 1-16",
        severity: "critical",
        description: "Used for Unicode steganography to hide malicious payloads"
    },
    VARIATION_SELECTORS_17_256: {
        ranges: [[0xE0100, 0xE01EF]],
        name: "Variation Selectors 17-256",
        severity: "critical",
        description: "Private Use Area - used in ellacrity.recoil malware for payload encoding"
    },
    
    // Zero-width characters (common in obfuscation)
    ZERO_WIDTH: {
        ranges: [
            [0x200B, 0x200D], // Zero-width space, joiner, non-joiner
            [0x2060, 0x2060], // Word joiner
            [0xFEFF, 0xFEFF]  // Zero-width no-break space (BOM)
        ],
        name: "Zero-Width Characters",
        severity: "high",
        description: "Invisible characters often used to hide code or bypass filters"
    },
    
    // Bidirectional text override (used in attacks)
    BIDI_OVERRIDE: {
        ranges: [
            [0x202A, 0x202E], // LRE, RLE, PDF, LRO, RLO
            [0x2066, 0x2069]  // LRI, RLI, FSI, PDI
        ],
        name: "Bidirectional Text Override",
        severity: "critical",
        description: "Can reverse code appearance, hiding malicious logic"
    },
    
    // Format control characters
    FORMAT_CONTROL: {
        ranges: [
            [0x00AD, 0x00AD], // Soft hyphen
            [0x180E, 0x180E], // Mongolian vowel separator
            [0x061C, 0x061C]  // Arabic letter mark
        ],
        name: "Format Control Characters",
        severity: "medium",
        description: "Invisible formatting characters that may hide code"
    },
    
    // Private Use Area (often malicious)
    PRIVATE_USE_AREA: {
        ranges: [
            [0xE000, 0xF8FF],   // BMP Private Use
            [0xF0000, 0xFFFFF], // Supplementary Private Use A
            [0x100000, 0x10FFFF] // Supplementary Private Use B
        ],
        name: "Private Use Area Characters",
        severity: "high",
        description: "Custom characters that can encode hidden data"
    }
};

/**
 * CJK (Chinese, Japanese, Korean) and legitimate Unicode ranges
 * These should NOT trigger warnings
 */
const LegitimateUnicodeRanges = {
    CJK_UNIFIED: [[0x4E00, 0x9FFF]],
    CJK_EXTENSION_A: [[0x3400, 0x4DBF]],
    CJK_EXTENSION_B: [[0x20000, 0x2A6DF]],
    CJK_COMPATIBILITY: [[0xF900, 0xFAFF]],
    HANGUL: [[0xAC00, 0xD7AF]],
    HIRAGANA: [[0x3040, 0x309F]],
    KATAKANA: [[0x30A0, 0x30FF]],
    ARABIC: [[0x0600, 0x06FF]],
    HEBREW: [[0x0590, 0x05FF]],
    CYRILLIC: [[0x0400, 0x04FF]],
    EMOJI: [
        [0x1F300, 0x1F9FF], // Emoticons, symbols
        [0x2600, 0x26FF],   // Misc symbols
        [0x2700, 0x27BF]    // Dingbats
    ]
};

/**
 * Homoglyph pairs (lookalike characters used in attacks)
 */
const HomoglyphPairs = {
    // Latin vs Cyrillic
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    // Greek
    'α': 'a', 'β': 'b', 'γ': 'y', 'ε': 'e', 'ι': 'i', 'ο': 'o', 'υ': 'u',
    // Other lookalikes
    'ⅰ': 'i', 'ⅼ': 'l', '０': '0', 'Ο': 'O', '１': '1', 'І': 'I'
};

class MalwareDetector {
    constructor(config) {
        this.config = config;
        this.detectionResults = [];
    }

    /**
     * Check if a line should be ignored (false positive suppression)
     */
    isLineIgnored(lines, lineNum) {
        // Check if previous line has security-ignore comment
        if (lineNum > 0) {
            const prevLine = lines[lineNum - 1];
            if (/\/\/\s*security-ignore/i.test(prevLine)) {
                return true;
            }
        }
        
        // Check if current line has inline security-ignore comment
        const currentLine = lines[lineNum];
        if (/\/\/\s*security-ignore/i.test(currentLine)) {
            return true;
        }
        
        return false;
    }

    /**
     * Main detection function - scans text for all anomalies
     */
    detectAnomalies(text, languageId = null) {
        this.detectionResults = [];
        
        const lines = text.split('\n');
        
        for (let lineNum = 0; lineNum < lines.length; lineNum++) {
            const line = lines[lineNum];
            const lineNumber = lineNum + 1;
            
            // Skip empty lines
            if (line.trim().length === 0) continue;
            
            // Skip lines marked with security-ignore
            if (this.isLineIgnored(lines, lineNum)) continue;
            
            // Detect various anomaly types
            if (this.config.detectUnicodeStego) {
                this.detectUnicodeSteganography(line, lineNumber);
            }
            
            if (this.config.detectInvisibleChars) {
                this.detectInvisibleCharacters(line, lineNumber);
            }
            
            if (this.config.detectExcessiveIndentation) {
                this.detectExcessiveIndentation(line, lineNumber);
            }
            
            if (this.config.detectBidiOverride) {
                this.detectBidiOverride(line, lineNumber);
            }
            
            if (this.config.detectHomoglyphs) {
                this.detectHomoglyphs(line, lineNumber, languageId);
            }
            
            if (this.config.detectSuspiciousEval) {
                this.detectSuspiciousEval(line, lineNumber);
            }
        }
        
        return this.detectionResults;
    }

    /**
     * Detect Unicode Variation Selectors and PUA characters (steganography)
     * This is the technique used in ellacrity.recoil malware
     */
    detectUnicodeSteganography(line, lineNumber) {
        let stegoSequence = [];
        let startCol = -1;
        
        for (let i = 0; i < line.length; i++) {
            const codePoint = line.codePointAt(i);
            
            // Check if character is a Variation Selector or PUA
            const category = this.getUnicodeCategory(codePoint);
            
            if (category && (
                category === UnicodeCategories.VARIATION_SELECTORS_1_16 ||
                category === UnicodeCategories.VARIATION_SELECTORS_17_256 ||
                category === UnicodeCategories.PRIVATE_USE_AREA
            )) {
                if (startCol === -1) startCol = i;
                stegoSequence.push({ char: line[i], codePoint, category });
                
                // Skip surrogate pairs
                if (codePoint > 0xFFFF) i++;
            } else {
                // End of sequence
                if (stegoSequence.length >= this.config.minStegoSequence) {
                    this.addDetection({
                        type: 'unicode-steganography',
                        severity: 'critical',
                        line: lineNumber,
                        column: startCol,
                        length: stegoSequence.length,
                        message: `⚠️ Potential Unicode steganography detected: ${stegoSequence.length} invisible characters in sequence`,
                        details: `Found ${stegoSequence.length} Unicode Variation Selectors or Private Use Area characters. This pattern has been observed in malware (e.g., ellacrity.recoil) to encode hidden payloads. These characters could encode up to ${stegoSequence.length} bytes of data. However, this may also occur in legitimate internationalization or specialized applications.`,
                        codePoints: stegoSequence.map(s => `U+${s.codePoint.toString(16).toUpperCase()}`).join(', '),
                        recommendation: 'Review the source and purpose of these characters. Verify this is intentional and from a trusted source.'
                    });
                }
                stegoSequence = [];
                startCol = -1;
            }
        }
        
        // Check final sequence
        if (stegoSequence.length >= this.config.minStegoSequence) {
            this.addDetection({
                type: 'unicode-steganography',
                severity: 'critical',
                line: lineNumber,
                column: startCol,
                length: stegoSequence.length,
                message: `⚠️ Potential Unicode steganography detected: ${stegoSequence.length} invisible characters at line end`,
                details: `Found ${stegoSequence.length} Unicode Variation Selectors or Private Use Area characters. Similar patterns have been used in malware to hide data. Verify this is expected.`,
                codePoints: stegoSequence.map(s => `U+${s.codePoint.toString(16).toUpperCase()}`).join(', ')
            });
        }
    }

    /**
     * Detect individual invisible characters
     */
    detectInvisibleCharacters(line, lineNumber) {
        for (let i = 0; i < line.length; i++) {
            const codePoint = line.codePointAt(i);
            const category = this.getUnicodeCategory(codePoint);
            
            if (category === UnicodeCategories.ZERO_WIDTH) {
                this.addDetection({
                    type: 'invisible-character',
                    severity: 'high',
                    line: lineNumber,
                    column: i,
                    length: 1,
                    message: `⚠️ Invisible character detected: ${category.name}`,
                    details: `Character U+${codePoint.toString(16).toUpperCase()} - ${category.description}. May be used for legitimate purposes (e.g., text processing) or could indicate obfuscation.`,
                    recommendation: 'Verify this character is intentional and serves a valid purpose in your code.'
                });
            }
            
            // Skip surrogate pairs
            if (codePoint > 0xFFFF) i++;
        }
    }

    /**
     * Detect excessive indentation (hiding code off-screen)
     */
    detectExcessiveIndentation(line, lineNumber) {
        const leadingSpaces = line.match(/^[\s\t]*/)[0];
        const spaceCount = leadingSpaces.replace(/\t/g, '    ').length; // Convert tabs to 4 spaces
        
        if (spaceCount > this.config.maxIndentation) {
            this.addDetection({
                type: 'excessive-indentation',
                severity: 'high',
                line: lineNumber,
                column: 0,
                length: leadingSpaces.length,
                message: `⚠️ Unusual indentation detected: ${spaceCount} spaces`,
                details: `This line has ${spaceCount} spaces of indentation, which exceeds the configured threshold of ${this.config.maxIndentation}. While this may be intentional formatting, it could also indicate hidden code beyond the visible editor area.`,
                recommendation: 'Review the indentation. Verify this is expected in your codebase or consider adjusting the detection threshold.'
            });
        }
    }

    /**
     * Detect bidirectional text override attacks
     */
    detectBidiOverride(line, lineNumber) {
        for (let i = 0; i < line.length; i++) {
            const codePoint = line.codePointAt(i);
            const category = this.getUnicodeCategory(codePoint);
            
            if (category === UnicodeCategories.BIDI_OVERRIDE) {
                this.addDetection({
                    type: 'bidi-override',
                    severity: 'critical',
                    line: lineNumber,
                    column: i,
                    length: 1,
                    message: `⚠️ Bidirectional text control character detected`,
                    details: `Character U+${codePoint.toString(16).toUpperCase()} (${category.name}). These characters can alter text rendering direction and have been used in code injection attacks (CVE-2021-42574). However, they may be legitimate in right-to-left language contexts.`,
                    recommendation: 'Verify this character is necessary for your use case. If not working with RTL languages, consider removing it.'
                });
            }
        }
    }

    /**
     * Detect homoglyph attacks (lookalike characters)
     */
    detectHomoglyphs(line, lineNumber, languageId) {
        // Skip detection in comments if CJK is allowed
        if (this.config.allowCJKinComments && this.isInComment(line, languageId)) {
            return;
        }
        
        // Look for identifier-like tokens
        const tokens = line.match(/\b[a-zA-Z_]\w*\b/g) || [];
        
        for (const token of tokens) {
            for (let i = 0; i < token.length; i++) {
                const char = token[i];
                
                if (HomoglyphPairs[char]) {
                    const column = line.indexOf(token) + i;
                    const codePoint = char.codePointAt(0);
                    
                    this.addDetection({
                        type: 'homoglyph',
                        severity: 'high',
                        line: lineNumber,
                        column: column,
                        length: 1,
                        message: `⚠️ Non-ASCII character in identifier: '${char}' resembles '${HomoglyphPairs[char]}'`,
                        details: `Character U+${codePoint.toString(16).toUpperCase()} in identifier '${token}'. This character visually resembles ASCII but is from a different Unicode block. May be intentional for internationalization or could indicate identifier spoofing.`,
                        recommendation: 'If ASCII was intended, replace with standard ASCII character. If internationalization is intended, this may be acceptable.'
                    });
                }
            }
        }
    }

    /**
     * Detect suspicious eval patterns (like eval(atob(...)))
     */
    detectSuspiciousEval(line, lineNumber) {
        const suspiciousPatterns = [
            { pattern: /eval\s*\(\s*atob\s*\(/gi, desc: "eval with base64 decoding (eval(atob(...)))" },
            { pattern: /eval\s*\(\s*Buffer\.from\s*\(/gi, desc: "eval with Buffer decoding (eval(Buffer.from(...)))" },
            { pattern: /Function\s*\(\s*atob\s*\(/gi, desc: "Dynamic function with base64 (Function(atob(...)))" },
            { pattern: /eval\s*\(\s*.*?\.toString\s*\(\s*\)/gi, desc: "eval with toString conversion" },
            { pattern: /child_process\.exec\s*\(/gi, desc: "child_process.exec() - command execution" },
            { pattern: /\.then\s*\(\s*eval\s*\)/gi, desc: "Promise chain with eval (.then(eval))" }
        ];
        
        for (const { pattern, desc } of suspiciousPatterns) {
            const matches = [...line.matchAll(pattern)];
            
            for (const match of matches) {
                this.addDetection({
                    type: 'suspicious-eval',
                    severity: 'critical',
                    line: lineNumber,
                    column: match.index,
                    length: match[0].length,
                    message: `⚠️ Dynamic code execution pattern detected: ${desc}`,
                    details: `Pattern "${match[0]}" detected. While this may be legitimate code, similar patterns have been observed in malicious scripts for obfuscation and dynamic payload execution. This warrants review to ensure it's from a trusted source.`,
                    recommendation: 'Review the context and source of this code. If possible, refactor to avoid dynamic code execution. Ensure any external data is properly validated.'
                });
            }
        }
    }

    /**
     * Helper: Get Unicode category for a code point
     */
    getUnicodeCategory(codePoint) {
        for (const category of Object.values(UnicodeCategories)) {
            for (const [start, end] of category.ranges) {
                if (codePoint >= start && codePoint <= end) {
                    return category;
                }
            }
        }
        return null;
    }

    /**
     * Helper: Check if position is in a comment
     */
    isInComment(line, languageId) {
        // Simple heuristic - check for common comment patterns
        const trimmed = line.trim();
        
        // Single-line comments
        if (trimmed.startsWith('//') || 
            trimmed.startsWith('#') || 
            trimmed.startsWith('--') ||
            trimmed.startsWith('/*')) {
            return true;
        }
        
        return false;
    }

    /**
     * Helper: Add a detection result
     */
    addDetection(detection) {
        this.detectionResults.push(detection);
    }

    /**
     * Generate a summary report
     */
    generateReport() {
        const bySeverity = {
            critical: this.detectionResults.filter(d => d.severity === 'critical'),
            high: this.detectionResults.filter(d => d.severity === 'high'),
            medium: this.detectionResults.filter(d => d.severity === 'medium')
        };
        
        return {
            total: this.detectionResults.length,
            critical: bySeverity.critical.length,
            high: bySeverity.high.length,
            medium: bySeverity.medium.length,
            detections: this.detectionResults,
            summary: this.generateSummary(bySeverity)
        };
    }

    /**
     * Generate human-readable summary
     */
    generateSummary(bySeverity) {
        const lines = [];
        
        if (bySeverity.critical.length > 0) {
            lines.push(`🔴 CRITICAL: Found ${bySeverity.critical.length} critical security issues`);
        }
        if (bySeverity.high.length > 0) {
            lines.push(`🟠 HIGH: Found ${bySeverity.high.length} high-severity issues`);
        }
        if (bySeverity.medium.length > 0) {
            lines.push(`🟡 MEDIUM: Found ${bySeverity.medium.length} medium-severity issues`);
        }
        
        if (lines.length === 0) {
            lines.push('✅ No security issues detected');
        }
        
        return lines.join('\n');
    }
}

module.exports = {
    MalwareDetector,
    UnicodeCategories,
    HomoglyphPairs
};

