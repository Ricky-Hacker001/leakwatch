# 🔍 LeakWatch

**CLI pre-push secret & PII scanner for developers.**  
Catches API keys, passwords, Aadhaar, UPI IDs, PAN numbers, and 30+ more patterns before they leave your machine.

[![npm version](https://badge.fury.io/js/leakwatch.svg)](https://badge.fury.io/js/leakwatch)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

---

## Why LeakWatch?

Every week, developers accidentally push API keys, database passwords, and user PII to GitHub.

- GitGuardian and Trufflehog are cloud-dependent and enterprise-priced
- No existing tool detects **India-specific PII** — Aadhaar, UPI IDs, PAN, GST numbers
- Most tools are post-push. **LeakWatch blocks before it leaves your machine**

LeakWatch is:
- ✅ **100% local** — nothing leaves your machine
- ✅ **Zero config** — works in 10 seconds
- ✅ **India-first** — only scanner with Aadhaar, UPI, PAN, GST patterns
- ✅ **Open source** — MIT license, no account needed

---

## Quickstart

```bash
# Scan your project right now (no install needed)
npx leakwatch scan

# Install as a permanent pre-push git hook
npx leakwatch install
```

That's it. Every future `git push` will be scanned automatically.

---

## What it detects

### 🔑 Secrets & API Keys
| Pattern | Examples |
|---|---|
| AWS Keys | `AKIA...`, `aws_secret_access_key` |
| GitHub Tokens | `ghp_...`, `gho_...` |
| OpenAI Keys | `sk-proj-...` |
| Stripe | `sk_live_...`, `pk_live_...` |
| Razorpay | `rzp_live_...` |
| Twilio | AC/SK tokens |
| Slack | `xoxb-...`, webhook URLs |
| Telegram Bot | `1234567890:ABC...` |
| Firebase | `AIza...` |
| SendGrid | `SG....` |
| JWT Tokens | `eyJ...` hardcoded |
| MongoDB URIs | Connection strings with credentials |
| MySQL/Postgres | Connection strings with credentials |
| Private Keys | RSA, EC, DSA, OpenSSH |
| Generic secrets | `password=`, `secret=`, `token=` patterns |

### 🇮🇳 India-Specific PII (unique to LeakWatch)
| Pattern | Risk |
|---|---|
| **Aadhaar Number** | DPDP Act violation, UIDAI regulation |
| **PAN Card Number** | Income tax identity |
| **UPI ID** | Payment identifier |
| **Indian Phone Number** | DPDP Act — PII |
| **GST Number** | Business identity |
| **IFSC Code** | Bank routing data |
| **Indian Passport Number** | Government ID |
| **Voter ID** | Government ID |

### 🌐 Global PII
- Credit card numbers (Luhn-validated patterns)
- Bulk email addresses

---

## Commands

```bash
leakwatch scan              # Scan entire project
leakwatch scan src/         # Scan specific folder
leakwatch scan app.js       # Scan specific file
leakwatch install           # Install pre-push git hook
leakwatch uninstall         # Remove git hook
leakwatch check             # Scan staged files (used by hook internally)
leakwatch scan --json       # Output as JSON (for CI pipelines)
leakwatch scan --verbose    # Show each file being scanned
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: LeakWatch Secret Scan
  run: npx leakwatch scan --no-banner --json
```

### GitLab CI

```yaml
leakwatch:
  stage: test
  script:
    - npx leakwatch scan --no-banner
```

---

## Severity Levels

| Level | Meaning | Push blocked? |
|---|---|---|
| 🔴 CRITICAL | Active credentials, keys with financial risk | Yes |
| 🟠 HIGH | Sensitive IDs, government IDs, tokens | Yes |
| 🟡 MEDIUM | Phone numbers, UPI IDs, low-risk identifiers | No (warning) |
| 🔵 LOW | Email addresses, internal IPs | No (info) |

---

## Allowlist (skip false positives)

Add a `.leakwatchignore` file to skip patterns or files:

```
# Ignore specific file
tests/fixtures/fake-keys.js

# Ignore a pattern ID
aadhaar
pan_number
```

Or inline in code:
```js
const EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"; // leakwatch-ignore
```

---

## Contributing

Pull requests welcome! Especially:
- New regex patterns for secrets
- More India-specific PII patterns
- False positive fixes
- Language-specific parsers

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Roadmap

- [ ] `.leakwatchignore` file support
- [ ] VSCode extension
- [ ] Web dashboard for team reports (paid)
- [ ] Slack/webhook alerts on detection
- [ ] Auto-remediation suggestions
- [ ] Support for `.env.example` false-positive suppression

---

## License

MIT — free forever for individuals.  
Team dashboard (coming soon) will be paid.

---

**Made with ❤️ by Ricky** — built because I found a real PII leak on a university portal and realised no one was protecting developers from themselves.