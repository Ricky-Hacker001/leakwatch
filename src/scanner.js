// leakwatch/src/scanner.js
// Core scanning engine — reads files, applies patterns, returns findings

const fs = require("fs");
const path = require("path");
const { PATTERNS, SKIP_FILES, ALLOWLIST_PATTERNS } = require("./patterns");

/**
 * Check if a file path should be skipped
 */
function shouldSkipFile(filePath) {
  const normalized = filePath.replace(/\\/g, '/');
  return SKIP_FILES.some((pattern) => pattern.test(normalized));
}

/**
 * Check if a match is likely a false positive
 */
function isAllowlisted(matchString) {
  return ALLOWLIST_PATTERNS.some((p) => p.test(matchString));
}

/**
 * Scan a single file's content for all patterns
 * Returns array of findings
 */
function scanContent(content, filePath) {
  const findings = [];
  const lines = content.split("\n");

  for (const rule of PATTERNS) {
    // Reset regex state
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    const counts = {};
    let match;

    while ((match = regex.exec(content)) !== null) {
      const matchStr = match[0];

      // Skip allowlisted matches
      if (isAllowlisted(matchStr)) continue;

      // Find line number
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split("\n").length;
      const lineContent = lines[lineNum - 1] || "";

      // Skip comment lines
      const trimmed = lineContent.trim();
      if (
        trimmed.startsWith("//") ||
        trimmed.startsWith("#") ||
        trimmed.startsWith("*") ||
        trimmed.startsWith("<!--")
      ) {
        continue;
      }

      // For bulk patterns (like email), only warn if count threshold met
      if (rule.minCount) {
        counts[rule.id] = (counts[rule.id] || 0) + 1;
        if (counts[rule.id] < rule.minCount) continue;
      }

      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        description: rule.description,
        tip: rule.tip || null,
        category: rule.category || "SECRET",
        file: filePath,
        line: lineNum,
        match: maskMatch(matchStr),
        rawLine: lineContent.trim().substring(0, 120),
      });

      // Avoid duplicate findings for same rule+line
      if (findings.filter(f => f.ruleId === rule.id && f.file === filePath && f.line === lineNum).length > 1) {
        findings.pop();
      }
    }
  }

  return findings;
}

/**
 * Mask sensitive match for display (show first 4 + last 2 chars)
 */
function maskMatch(str) {
  if (str.length <= 8) return "****";
  return str.substring(0, 4) + "****" + str.substring(str.length - 2);
}

/**
 * Scan a list of files (paths relative to cwd)
 */
function scanFiles(filePaths, options = {}) {
  const allFindings = [];
  const scannedCount = { files: 0, skipped: 0 };

  for (const filePath of filePaths) {
    if (shouldSkipFile(filePath)) {
      scannedCount.skipped++;
      continue;
    }

    let content;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      // Binary or unreadable file — skip
      scannedCount.skipped++;
      continue;
    }

    // Skip huge files (> 1MB) — likely generated/binary
    if (content.length > 1_000_000) {
      scannedCount.skipped++;
      continue;
    }

    const findings = scanContent(content, filePath);
    allFindings.push(...findings);
    scannedCount.files++;

    if (options.verbose && findings.length > 0) {
      process.stderr.write(`  [!] ${filePath} — ${findings.length} finding(s)\n`);
    }
  }

  return { findings: allFindings, scanned: scannedCount };
}

/**
 * Get all staged files from git (for pre-push hook)
 */
function getStagedFiles() {
  const { execSync } = require("child_process");
  try {
    const output = execSync("git diff --name-only HEAD~1 HEAD 2>/dev/null || git diff --cached --name-only 2>/dev/null", {
      encoding: "utf8",
    });
    return output
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((f) => path.resolve(f));
  } catch {
    return [];
  }
}

/**
 * Get all files in a directory recursively
 */
function getAllFiles(dir = ".") {
  const files = [];
  const MAX_FILES = 500; // safety limit

  function walk(current) {
    if (files.length > MAX_FILES) return;
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      const full = path.join(current, entry.name);
      const normalized = full.replace(/\\/g, '/');

      // Skip immediately by name
      if (
        entry.name === 'node_modules' ||
        entry.name === '.git' ||
        entry.name === 'dist' ||
        entry.name === 'build' ||
        entry.name === 'coverage' ||
        entry.name === '.gitignore' ||
        entry.name.endsWith('.min.js') ||
        entry.name === 'package-lock.json' ||
        entry.name === 'yarn.lock'
      ) continue;

      if (entry.isDirectory()) {
        walk(full);
      } else {
        files.push(full);
      }
    }
  }
  walk(dir);
  return files;
}

module.exports = { scanFiles, scanContent, getStagedFiles, getAllFiles, maskMatch };