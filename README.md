# SentinelEliteScan

[![SentinelEliteScan](https://github.com/joearzua/sentinel-elite-scan/actions/workflows/sentinelscan.yml/badge.svg)](https://github.com/joearzua/sentinel-elite-scan/actions/workflows/sentinelscan.yml)

Secrets, payment card (PAN), and PII scanner for codebases. Runs as a CLI or GitHub Action. Fails CI builds when Critical findings are present.

---

## What it detects

| Check | Severity | Threat prevented |
|---|---|---|
| AWS Access Key ID (`AKIA…`) | **Critical** | Full AWS account takeover |
| AWS Secret Access Key | **Critical** | Full AWS account takeover |
| Private Key (PEM header) | **Critical** | Identity and TLS compromise |
| Payment Card Number (PAN) | **Critical** | PCI DSS violation, card fraud |
| Stripe Live Secret/Restricted Key | **Critical** | Payment account compromise |
| OpenAI / Anthropic API Key | **Critical** | LLM billing abuse, data access |
| Google Service Account JSON | **Critical** | GCP cloud account compromise |
| GitHub PAT / OAuth / Actions Token | **High** | Source code and repo exfiltration |
| Slack Bot / User Token / Webhook | **High** | Workspace data and messaging access |
| Database connection string | **High** | Direct database exfiltration |
| JWT token | **High** | Auth session hijack |
| SendGrid / Mailgun / Twilio keys | **High** | Email/SMS account abuse |
| High-entropy unrecognized string | **High** | Unknown secret type detected via entropy |
| US Social Security Number (SSN) | **Medium** | PII exposure, identity theft |
| Stripe test / publishable keys | **Medium** | Integration enumeration, live env confirmed |
| Hardcoded passwords | **Medium** | Credential exposure |
| Generic API key assignments | **Medium** | Unclassified secret exposure |

---

## Installation

```bash
pip install .
# or from PyPI once published:
# pip install sentinel-elite-scan
```

---

## CLI usage

```bash
# Scan working tree
sentinelscan scan /path/to/repo

# Scan working tree AND full git history
sentinelscan scan /path/to/repo --git-history

# Output as JSON (useful for CI artifact storage or integration with other tools)
sentinelscan scan /path/to/repo --json

# Combine flags
sentinelscan scan . --git-history --json | tee report.json

# Suppress CI failure on Critical (not recommended for production gates)
sentinelscan scan . --no-fail
```

**Exit codes:**
- `0` — no findings, or only Medium/High findings
- `1` — one or more Critical findings (causes CI to fail)

---

## Example output

```
╭─────────────────────────────────────────────────────────────────╮
│              SentinelEliteScan — Results                        │
│  Scanned: .  |  Total: 3  CRITICAL: 1  HIGH: 1  MEDIUM: 1       │
╰─────────────────────────────────────────────────────────────────╯

╭──────────┬─────────────────────────┬──────┬──────────────────────────┬───────────────────────┬──────────╮
│ Severity │ File                    │ Line │ Check                    │ Value (redacted)      │ Commit   │
├──────────┼─────────────────────────┼──────┼──────────────────────────┼───────────────────────┼──────────┤
│ CRITICAL │ src/config/db.ts        │   12 │ Database Connection Str… │ postgres://admin:p8…  │          │
│ HIGH     │ .env.bak                │    3 │ GitHub Personal Access … │ ghp_zK3x2…            │ a1b2c3d4 │
│ MEDIUM   │ tests/fixtures/data.py  │   45 │ Hardcoded Password       │ hunter2*…             │          │
╰──────────┴─────────────────────────┴──────┴──────────────────────────┴───────────────────────┴──────────╯

Check descriptions:
  ▸ Database Connection String: Database connection string with embedded credentials
  ▸ GitHub Personal Access Token: GitHub PAT — full repository and account access
  ▸ Hardcoded Password: Hardcoded password — credential exposure risk
```

JSON output (`--json`):

```json
{
  "scanner": "SentinelEliteScan",
  "version": "1.0.0",
  "scanned_path": ".",
  "summary": {
    "total": 3,
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 1
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "file": "src/config/db.ts",
      "line": 12,
      "check": "Database Connection String",
      "description": "Database connection string with embedded credentials",
      "value_redacted": "postgres:****"
    }
  ]
}
```

---

## GitHub Action

Add this file to your repository at `.github/workflows/sentinelscan.yml`:

```yaml
name: SentinelEliteScan

on:
  push:
    branches: ["**"]
  pull_request:
    branches: ["**"]

jobs:
  sentinel-scan:
    name: Secrets & PAN Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # needed for --git-history

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
          cache: pip

      - name: Install SentinelEliteScan
        run: pip install .

      - name: Run scan
        shell: bash
        run: |
          set -o pipefail
          sentinelscan scan . --git-history --json | tee sentinel-report.json

      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sentinel-scan-report
          path: sentinel-report.json
```

The `set -o pipefail` line is critical — without it, the shell pipe would swallow sentinelscan's exit code 1, and the step would always pass regardless of findings.

The scan report JSON is uploaded as a build artifact even when the step fails, so you can download and review it.

---

## Threat model

### Why regex alone is not sufficient for PAN detection

A naive regex for 16-digit numbers matches an enormous number of false positives:

- Timestamps (`20240118123456`)
- Unix epoch values and IDs
- Phone numbers with country codes
- Internal order/reference numbers
- Random numeric strings in test fixtures

The **Luhn algorithm** validates the check digit embedded in every valid payment card number per ISO/IEC 7812. A random 16-digit number has approximately a 10% chance of passing Luhn by chance, reducing false positives by ~90% compared to pure regex. Combined with the pattern requiring a card-network-specific prefix (Visa `4…`, Mastercard `5[1-5]…`, Amex `3[47]…`, etc.), the false positive rate drops to well under 1%.

This is the same validation that payment terminals and e-commerce checkout forms run before even attempting a charge.

### Why Shannon entropy analysis supplements regex patterns

Not every secret follows a known format. Internal API keys, self-hosted auth tokens, and rotating session tokens often have no identifiable prefix. Shannon entropy measures the information density of a string — genuine secrets generated from cryptographically random sources have entropy typically above 4.5 bits per character (base64 keyspace), while human-readable strings, variable names, and sentences remain well below that threshold.

SentinelEliteScan applies entropy analysis only to strings that appear in assignment contexts (e.g., `api_key = "…"`, `token: "…"`) and enforces minimum length and character-class diversity requirements to further suppress false positives from hex hashes, UUIDs embedded in non-secret contexts, and minified code.

### What this scanner does NOT catch

- Secrets passed through environment variables at runtime (correct approach — use env vars)
- Secrets stored in a secrets manager (Vault, AWS Secrets Manager, etc.)
- Encrypted secrets at rest that decrypt correctly at runtime
- Obfuscated or encoded secrets (e.g., base64-encoded connection strings without an assignment context)

SentinelEliteScan is a defense-in-depth layer, not a substitute for secrets management architecture.

---

## False positive handling

If a finding is a known false positive (e.g., a test fixture with a synthetic card number), you can suppress it in two ways:

1. Add a comment on the line: `# sentinelscan:ignore`  
   *(support coming in v1.1)*
2. Use `--no-fail` in contexts where findings are expected (e.g., a dedicated test fixtures directory scan)

The recommended practice is to maintain a separate test directory that is excluded from the production scan path.
