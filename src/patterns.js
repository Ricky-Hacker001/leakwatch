// leakwatch/src/patterns.js
// All regex patterns for secrets, API keys, and India-specific PII

const PATTERNS = [

  // ─── GENERIC SECRETS ────────────────────────────────────────────

  {
    id: "generic_password",
    name: "Hardcoded Password",
    severity: "CRITICAL",
    pattern: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"]([^'"]{4,})['"]|(?:password|passwd|pwd|secret)\s*=\s*([^\s;,\n]{4,})/gi,
    description: "Hardcoded password found in source",
    tip: "Use environment variables: process.env.PASSWORD"
  },
  {
    id: "generic_secret",
    name: "Generic Secret / Token",
    severity: "CRITICAL",
    pattern: /(?:secret|token|key|auth)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{16,})['"]|(?:secret|token|key|auth)\s*=\s*([a-zA-Z0-9_\-\.]{16,})/gi,
    description: "Generic secret or token found",
    tip: "Move to .env file and add .env to .gitignore"
  },
  {
    id: "private_key",
    name: "Private Key Block",
    severity: "CRITICAL",
    pattern: /-----BEGIN\s(?:RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----/gi,
    description: "Private key found in file",
    tip: "Never commit private keys. Use SSH agent or secrets manager."
  },
  {
    id: "env_file",
    name: ".env File Committed",
    severity: "HIGH",
    pattern: /^\.env$/m,
    fileMatch: /^\.env(\..+)?$/,
    description: ".env file detected",
    tip: "Add .env to .gitignore immediately"
  },

  // ─── API KEYS ────────────────────────────────────────────────────

  {
    id: "aws_access_key",
    name: "AWS Access Key ID",
    severity: "CRITICAL",
    pattern: /AKIA[0-9A-Z]{16}/g,
    description: "AWS Access Key ID found",
    tip: "Revoke this key immediately at https://console.aws.amazon.com/iam"
  },
  {
    id: "aws_secret_key",
    name: "AWS Secret Access Key",
    severity: "CRITICAL",
    pattern: /(?:aws_secret|aws_secret_access_key|AWS_SECRET)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    description: "AWS Secret Access Key found",
    tip: "Rotate key immediately in AWS IAM console"
  },
  {
    id: "google_api_key",
    name: "Google API Key",
    severity: "HIGH",
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    description: "Google API key found",
    tip: "Restrict key in Google Cloud Console or revoke and regenerate"
  },
  {
    id: "github_token",
    name: "GitHub Personal Access Token",
    severity: "CRITICAL",
    pattern: /gh[pousr]_[A-Za-z0-9_]{20,255}/g,
    description: "GitHub token found",
    tip: "Revoke at https://github.com/settings/tokens"
  },
  {
    id: "github_oauth",
    name: "GitHub OAuth Token",
    severity: "CRITICAL",
    pattern: /gho_[0-9a-zA-Z]{36}/g,
    description: "GitHub OAuth token found",
    tip: "Revoke immediately in GitHub Developer Settings"
  },
  {
    id: "stripe_secret",
    name: "Stripe Secret Key",
    severity: "CRITICAL",
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    description: "Stripe live secret key found",
    tip: "Revoke at https://dashboard.stripe.com/apikeys"
  },
  {
    id: "stripe_publishable",
    name: "Stripe Publishable Key",
    severity: "MEDIUM",
    pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
    description: "Stripe live publishable key found",
    tip: "Publishable keys are less dangerous but should not be hardcoded"
  },
  {
    id: "twilio_sid",
    name: "Twilio Account SID",
    severity: "HIGH",
    pattern: /AC[a-z0-9]{32}/g,
    description: "Twilio Account SID found",
    tip: "Revoke at https://www.twilio.com/console"
  },
  {
    id: "twilio_token",
    name: "Twilio Auth Token",
    severity: "CRITICAL",
    pattern: /SK[a-z0-9]{32}/g,
    description: "Twilio Auth Token found"
  },
  {
    id: "slack_token",
    name: "Slack Bot/API Token",
    severity: "HIGH",
    pattern: /xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}/g,
    description: "Slack token found",
    tip: "Revoke at https://api.slack.com/apps"
  },
  {
    id: "slack_webhook",
    name: "Slack Webhook URL",
    severity: "HIGH",
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-zA-Z0-9]+/g,
    description: "Slack webhook URL found"
  },
  {
    id: "firebase_key",
    name: "Firebase API Key",
    severity: "HIGH",
    pattern: /(?:firebase|FIREBASE)[^'"]*['"]AIza[0-9A-Za-z\-_]{35}['"]/g,
    description: "Firebase API key found"
  },
  {
    id: "sendgrid_key",
    name: "SendGrid API Key",
    severity: "HIGH",
    pattern: /SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}/g,
    description: "SendGrid API key found"
  },
  {
    id: "jwt_token",
    name: "JWT Token (hardcoded)",
    severity: "HIGH",
    pattern: /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}/g,
    description: "Hardcoded JWT token found",
    tip: "Never hardcode JWT tokens — generate them at runtime"
  },
  {
    id: "razorpay_key",
    name: "Razorpay API Key",
    severity: "CRITICAL",
    pattern: /rzp_live_[a-zA-Z0-9]{14,}/g,
    description: "Razorpay live API key found",
    tip: "Revoke at https://dashboard.razorpay.com/app/keys"
  },
  {
    id: "razorpay_test",
    name: "Razorpay Test Key",
    severity: "LOW",
    pattern: /rzp_test_[a-zA-Z0-9]{14,}/g,
    description: "Razorpay test key (low risk but avoid hardcoding)"
  },
  {
    id: "openai_key",
    name: "OpenAI API Key",
    severity: "CRITICAL",
    pattern: /sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_\-]{50,}/g,
    description: "OpenAI API key found — can incur massive bills",
    tip: "Revoke at https://platform.openai.com/api-keys"
  },
  {
    id: "anthropic_key",
    name: "Anthropic API Key",
    severity: "CRITICAL",
    pattern: /sk-ant-api[0-9a-zA-Z_\-]{40,}/g,
    description: "Anthropic API key found"
  },
  {
    id: "telegram_bot_token",
    name: "Telegram Bot Token",
    severity: "HIGH",
    pattern: /[0-9]{8,10}:[a-zA-Z0-9_\-]{35}/g,
    description: "Telegram bot token found"
  },
  {
    id: "mongodb_uri",
    name: "MongoDB Connection String",
    severity: "CRITICAL",
    pattern: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s'"]+/gi,
    description: "MongoDB connection string with credentials found",
    tip: "Use environment variables for all database URIs"
  },
  {
    id: "mysql_uri",
    name: "MySQL/PostgreSQL Connection String",
    severity: "CRITICAL",
    pattern: /(?:mysql|postgres|postgresql):\/\/[^:]+:[^@]{4,}@[^\s'"]+/gi,
    description: "Database connection string with credentials found"
  },

  // ─── INDIA-SPECIFIC PII ──────────────────────────────────────────

  {
    id: "aadhaar",
    name: "Aadhaar Number",
    severity: "CRITICAL",
    pattern: /\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b/g,
    description: "Aadhaar number found — DPDP Act violation risk",
    tip: "Aadhaar data is regulated under UIDAI. Never store or commit raw Aadhaar numbers.",
    category: "PII"
  },
  {
    id: "pan_number",
    name: "PAN Card Number",
    severity: "HIGH",
    pattern: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
    description: "PAN card number found",
    tip: "PAN is sensitive tax identity data. Remove from codebase.",
    category: "PII"
  },
  {
    id: "upi_id",
    name: "UPI ID",
    severity: "MEDIUM",
    pattern: /\b[a-zA-Z0-9._\-]{2,256}@(?:oksbi|okaxis|okicici|okhdfcbank|paytm|upi|ybl|ibl|axl|jupiteraxis|waicici|ptyes|pthdfc|okbizaxis|apl|barodampay|centralbank|citi|cnrb|cosbank|dbs|dcb|ezeepay|fbl|federal|freecharge|hdfcbank|hsbc|idbi|idfc|ikwik|imobile|indus|iob|juspay|kotak|lvb|mahb|myicici|niyoicici|oksbi|pnb|postbank|rajgovhdfcbank|rbl|sbi|sc|slicepay|sib|syndicate|timecosmos|uco|unionbank|united|vijb|yesbank)\b/gi,
    description: "UPI ID found in source code",
    tip: "UPI IDs are payment identifiers — load from config, not source",
    category: "PII"
  },
  {
    id: "indian_phone",
    name: "Indian Phone Number",
    severity: "MEDIUM",
    pattern: /(?:\+91|0091|91)?[-\s]?[6-9][0-9]{9}\b/g,
    description: "Indian mobile number found",
    tip: "Phone numbers are PII under DPDP Act. Remove from code.",
    category: "PII"
  },
  {
    id: "gst_number",
    name: "GST Identification Number",
    severity: "HIGH",
    pattern: /\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b/g,
    description: "GST number found — business identity data",
    category: "PII"
  },
  {
    id: "ifsc_code",
    name: "IFSC Code with Account Number",
    severity: "HIGH",
    pattern: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
    description: "IFSC code found — may indicate bank account exposure",
    category: "PII"
  },
  {
    id: "passport_india",
    name: "Indian Passport Number",
    severity: "CRITICAL",
    pattern: /\b[A-PR-WYa-pr-wy][1-9]\d{5}[1-9]\b/g,
    description: "Indian passport number found",
    category: "PII"
  },
  {
    id: "voter_id",
    name: "Voter ID Number",
    severity: "HIGH",
    pattern: /\b[A-Z]{3}[0-9]{7}\b/g,
    description: "Possible Indian Voter ID found",
    category: "PII"
  },

  // ─── GLOBAL PII ──────────────────────────────────────────────────

  {
    id: "email_bulk",
    name: "Email Address (bulk)",
    severity: "LOW",
    pattern: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
    description: "Email address found — may be PII",
    minCount: 3, // only warn if 3+ emails found
    category: "PII"
  },
  {
    id: "credit_card",
    name: "Credit Card Number",
    severity: "CRITICAL",
    pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
    description: "Credit card number found — PCI-DSS violation risk",
    category: "PII"
  },
  {
    id: "ip_address_internal",
    name: "Internal IP Address",
    severity: "LOW",
    pattern: /\b(?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}\b/g,
    description: "Internal IP address found — may expose network topology"
  }

];

// Files to always skip
const SKIP_FILES = [
  /node_modules/,
  /\.git\//,
  /dist\//,
  /build\//,
  /coverage\//,
  /\.min\.js$/,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /\.png$/, /\.jpg$/, /\.jpeg$/, /\.gif$/, /\.svg$/, /\.ico$/,
  /\.woff$/, /\.woff2$/, /\.ttf$/, /\.eot$/,
  /\.mp4$/, /\.mp3$/, /\.wav$/,
  /\.zip$/, /\.tar$/, /\.gz$/,
];

// Patterns that are clearly false positives
const ALLOWLIST_PATTERNS = [
  /example\.com/i,
  /test@test/i,
  /placeholder/i,
  /your_api_key_here/i,
  /YOUR_KEY/,
  /INSERT_HERE/i,
  /xxxxxxxx/i,
  /\$\{.*\}/,  // template literals like ${API_KEY}
  /process\.env\./,
];

module.exports = { PATTERNS, SKIP_FILES, ALLOWLIST_PATTERNS };