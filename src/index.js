// leakwatch/src/index.js
// Main CLI logic — handles commands: scan, install, uninstall

const path = require("path");
const fs = require("fs");
const { scanFiles, getStagedFiles, getAllFiles } = require("./scanner");
const {
  printBanner,
  printSummaryLine,
  printFindings,
  printBlockMessage,
  printCleanMessage,
  printJsonReport,
} = require("./reporter");

const args = process.argv.slice(2);
const command = args[0] || "scan";

// ── HELP ──────────────────────────────────────────────────────────
if (command === "--help" || command === "-h" || command === "help") {
  console.log(`
  leakwatch — CLI pre-push secret & PII scanner

  Usage:
    leakwatch scan              Scan entire project
    leakwatch scan [file]       Scan a specific file or directory
    leakwatch install           Install pre-push git hook
    leakwatch uninstall         Remove the git hook
    leakwatch check             Scan staged/committed files (used by hook)

  Flags:
    --json                      Output findings as JSON
    --verbose                   Show all files being scanned
    --no-banner                 Skip the ASCII banner

  Examples:
    leakwatch scan
    leakwatch scan src/
    leakwatch install
    leakwatch check --json
  `);
  process.exit(0);
}

// ── INSTALL GIT HOOK ──────────────────────────────────────────────
if (command === "install") {
  const gitDir = findGitDir();
  if (!gitDir) {
    console.error("  ❌  Not a git repository. Run inside a git project.");
    process.exit(1);
  }

  const hooksDir = path.join(gitDir, "hooks");
  if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true });

  const hookPath = path.join(hooksDir, "pre-push");
  const hookContent = `#!/bin/sh
# LeakWatch pre-push hook
# Installed by: npx leakwatch install

npx leakwatch check
if [ $? -ne 0 ]; then
  exit 1
fi
exit 0
`;

  fs.writeFileSync(hookPath, hookContent);
  fs.chmodSync(hookPath, "755");

  console.log(`
  ✅  LeakWatch git hook installed!

  Every git push will now be scanned for secrets and PII.
  To remove: npx leakwatch uninstall
  To skip once: git push --no-verify
  `);
  process.exit(0);
}

// ── UNINSTALL GIT HOOK ────────────────────────────────────────────
if (command === "uninstall") {
  const gitDir = findGitDir();
  if (!gitDir) {
    console.error("  ❌  Not a git repository.");
    process.exit(1);
  }

  const hookPath = path.join(gitDir, "hooks", "pre-push");
  if (fs.existsSync(hookPath)) {
    const content = fs.readFileSync(hookPath, "utf8");
    if (content.includes("LeakWatch")) {
      fs.unlinkSync(hookPath);
      console.log("  ✅  LeakWatch hook removed.");
    } else {
      console.log("  ⚠️   Hook exists but was not installed by LeakWatch. Not removing.");
    }
  } else {
    console.log("  ℹ️   No hook found.");
  }
  process.exit(0);
}

// ── SCAN / CHECK ──────────────────────────────────────────────────
const isCheck  = command === "check";   // used by hook (staged files only)
const isScan   = command === "scan" || (!isCheck && command !== "install");
const jsonMode = args.includes("--json");
const verbose  = args.includes("--verbose");
const noBanner = args.includes("--no-banner") || isCheck;

// Determine which files to scan
let filesToScan = [];

if (isCheck) {
  // Hook mode: scan files changed in last commit / staged
  filesToScan = getStagedFiles();
  if (filesToScan.length === 0) {
    // fallback: scan all
    filesToScan = getAllFiles(".");
  }
} else {
  // Scan mode: scan directory or specific file
    const COMMANDS = ["scan", "check", "install", "uninstall", "help"];
    const target = args.find(a => !a.startsWith("--") && !COMMANDS.includes(a)) || ".";
    const resolved = path.resolve(target);

  if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
    filesToScan = [resolved];
  } else {
    filesToScan = getAllFiles(resolved);
  }
}

if (!jsonMode && !noBanner) printBanner();

if (!jsonMode) {
  const label = isCheck ? "Checking pushed files" : "Scanning";
  const count = filesToScan.length;
  process.stdout.write(`  ${label} ${count} file(s)...\n\n`);
}

const { findings, scanned } = scanFiles(filesToScan, { verbose });

if (jsonMode) {
  printJsonReport(findings, scanned);
  process.exit(findings.some(f => ["CRITICAL","HIGH"].includes(f.severity)) ? 1 : 0);
}

printSummaryLine(findings, scanned);
printFindings(findings);

if (findings.length > 0) {
  const hasCriticalOrHigh = findings.some(f => ["CRITICAL","HIGH"].includes(f.severity));
  if (hasCriticalOrHigh) {
    printBlockMessage();
    process.exit(1);
  } else {
    console.log("  ⚠️  Medium/Low issues found. Review before pushing.\n");
    process.exit(0);
  }
} else {
  if (!isCheck) printCleanMessage();
}

// ── HELPERS ───────────────────────────────────────────────────────
function findGitDir() {
  let dir = process.cwd();
  while (dir !== path.dirname(dir)) {
    const gitPath = path.join(dir, ".git");
    if (fs.existsSync(gitPath)) return gitPath;
    dir = path.dirname(dir);
  }
  return null;
}