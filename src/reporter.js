// leakwatch/src/reporter.js
// Formats scan results into beautiful terminal output

const chalk = require("chalk");

const SEVERITY_CONFIG = {
  CRITICAL: { color: chalk.bgRed.white.bold, icon: "🔴", order: 0 },
  HIGH:     { color: chalk.red.bold,          icon: "🟠", order: 1 },
  MEDIUM:   { color: chalk.yellow.bold,       icon: "🟡", order: 2 },
  LOW:      { color: chalk.blue,              icon: "🔵", order: 3 },
};

function printBanner() {
  console.log("");
  console.log(chalk.bold("  ██╗     ███████╗ █████╗ ██╗  ██╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗"));
  console.log(chalk.bold("  ██║     ██╔════╝██╔══██╗██║ ██╔╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║"));
  console.log(chalk.bold("  ██║     █████╗  ███████║█████╔╝ ██║ █╗ ██║███████║   ██║   ██║     ███████║"));
  console.log(chalk.bold("  ██║     ██╔══╝  ██╔══██║██╔═██╗ ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║"));
  console.log(chalk.bold("  ███████╗███████╗██║  ██║██║  ██╗╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║"));
  console.log(chalk.bold("  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝"));
  console.log("");
  console.log(chalk.gray("  Pre-push secret & PII scanner — github.com/yourusername/leakwatch"));
  console.log("");
}

function printSummaryLine(findings, scanned) {
  const critical = findings.filter(f => f.severity === "CRITICAL").length;
  const high     = findings.filter(f => f.severity === "HIGH").length;
  const medium   = findings.filter(f => f.severity === "MEDIUM").length;
  const low      = findings.filter(f => f.severity === "LOW").length;

  console.log(chalk.gray(`  Scanned ${scanned.files} files  ·  skipped ${scanned.skipped}`));
  console.log("");

  if (findings.length === 0) {
    console.log(chalk.green.bold("  ✅  No secrets or PII found. Safe to push.\n"));
    return;
  }

  const parts = [];
  if (critical) parts.push(chalk.bgRed.white.bold(` ${critical} CRITICAL `));
  if (high)     parts.push(chalk.red.bold(`${high} HIGH`));
  if (medium)   parts.push(chalk.yellow.bold(`${medium} MEDIUM`));
  if (low)      parts.push(chalk.blue(`${low} LOW`));

  console.log("  " + parts.join(chalk.gray("  ·  ")));
  console.log("");
}

function printFindings(findings) {
  if (findings.length === 0) return;

  // Sort by severity then file
  const sorted = [...findings].sort((a, b) => {
    const aOrder = SEVERITY_CONFIG[a.severity]?.order ?? 99;
    const bOrder = SEVERITY_CONFIG[b.severity]?.order ?? 99;
    if (aOrder !== bOrder) return aOrder - bOrder;
    return a.file.localeCompare(b.file);
  });

  // Group by file
  const byFile = {};
  for (const f of sorted) {
    if (!byFile[f.file]) byFile[f.file] = [];
    byFile[f.file].push(f);
  }

  for (const [file, filefindings] of Object.entries(byFile)) {
    const relFile = file.replace(process.cwd() + "/", "");
    console.log(chalk.bold.white(`  📄 ${relFile}`));

    for (const finding of filefindings) {
      const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.LOW;
      const sevLabel = cfg.color(` ${finding.severity} `);
      const catLabel = finding.category === "PII"
        ? chalk.magenta("[PII]")
        : chalk.cyan("[SECRET]");

      console.log(`     ${cfg.icon}  ${sevLabel} ${catLabel} ${chalk.white.bold(finding.ruleName)}`);
      console.log(`        ${chalk.gray("Line " + finding.line + ":")} ${chalk.gray(finding.rawLine.substring(0, 80))}`);
      console.log(`        ${chalk.yellow("Found:")} ${chalk.red(finding.match)}`);
      console.log(`        ${chalk.gray(finding.description)}`);
      if (finding.tip) {
        console.log(`        ${chalk.green("💡 " + finding.tip)}`);
      }
      console.log("");
    }
  }
}

function printBlockMessage() {
  console.log(chalk.bgRed.white.bold("\n  🚫  PUSH BLOCKED — secrets or PII detected in your commit\n"));
  console.log(chalk.yellow("  Fix the issues above, then push again."));
  console.log(chalk.gray("  To skip this check (not recommended): git push --no-verify\n"));
}

function printCleanMessage() {
  console.log(chalk.green.bold("  ✅  All clear — no secrets or PII detected.\n"));
}

function printJsonReport(findings, scanned) {
  const report = {
    timestamp: new Date().toISOString(),
    summary: {
      total: findings.length,
      critical: findings.filter(f => f.severity === "CRITICAL").length,
      high: findings.filter(f => f.severity === "HIGH").length,
      medium: findings.filter(f => f.severity === "MEDIUM").length,
      low: findings.filter(f => f.severity === "LOW").length,
      filesScanned: scanned.files,
    },
    findings: findings.map(f => ({
      ...f,
      file: f.file.replace(process.cwd() + "/", ""),
    })),
  };
  console.log(JSON.stringify(report, null, 2));
}

module.exports = {
  printBanner,
  printSummaryLine,
  printFindings,
  printBlockMessage,
  printCleanMessage,
  printJsonReport,
};