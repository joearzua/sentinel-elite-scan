import re
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    severity: Severity
    description: str
    requires_luhn: bool = False
    capture_group: int = 1


PATTERNS: list[Pattern] = [
    # ── CRITICAL ──────────────────────────────────────────────────────────────
    Pattern(
        name="AWS Access Key ID",
        regex=re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        severity=Severity.CRITICAL,
        description="AWS IAM access key — full account takeover possible",
    ),
    Pattern(
        name="AWS Secret Access Key",
        regex=re.compile(
            r'(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key'
            r'|AWS_SECRET[_\-]ACCESS[_\-]KEY)'
            r'\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?'
        ),
        severity=Severity.CRITICAL,
        description="AWS secret access key — full account takeover possible",
    ),
    Pattern(
        name="Private Key (PEM)",
        regex=re.compile(
            r'-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----',
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description="Private key in PEM format — identity and auth compromise",
        capture_group=0,
    ),
    Pattern(
        name="Payment Card Number (PAN)",
        regex=re.compile(
            r'\b(?:'
            r'4[0-9]{12}(?:[0-9]{3})?'           # Visa
            r'|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}'  # Mastercard
            r'|3[47][0-9]{13}'                    # Amex
            r'|3(?:0[0-5]|[68][0-9])[0-9]{11}'   # Diners
            r'|6(?:011|5[0-9]{2})[0-9]{12}'       # Discover
            r'|(?:2131|1800|35\d{3})\d{11}'       # JCB
            r')\b'
        ),
        severity=Severity.CRITICAL,
        description="Payment card number (PCI DSS violation) — validated with Luhn algorithm",
        requires_luhn=True,
        capture_group=0,
    ),
    Pattern(
        name="Stripe Live Secret Key",
        regex=re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b'),
        severity=Severity.CRITICAL,
        description="Stripe live secret key — full payment account compromise",
    ),
    Pattern(
        name="Stripe Live Restricted Key",
        regex=re.compile(r'\b(rk_live_[0-9a-zA-Z]{24,})\b'),
        severity=Severity.CRITICAL,
        description="Stripe live restricted key — payment operations access",
    ),
    Pattern(
        name="Google Service Account Key",
        regex=re.compile(r'"type"\s*:\s*"service_account"'),
        severity=Severity.CRITICAL,
        description="GCP service account JSON credential — cloud account compromise",
        capture_group=0,
    ),
    Pattern(
        name="Anthropic API Key",
        regex=re.compile(r'\b(sk-ant-[a-zA-Z0-9\-_]{20,})\b'),
        severity=Severity.CRITICAL,
        description="Anthropic API key — LLM billing and data access",
    ),
    Pattern(
        name="OpenAI API Key",
        regex=re.compile(r'\b(sk-(?:proj-)?[A-Za-z0-9]{20,})\b'),
        severity=Severity.CRITICAL,
        description="OpenAI API key — LLM billing and data access",
    ),

    # ── HIGH ──────────────────────────────────────────────────────────────────
    Pattern(
        name="GitHub Personal Access Token",
        regex=re.compile(
            r'\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b'
        ),
        severity=Severity.HIGH,
        description="GitHub PAT — full repository and account access",
    ),
    Pattern(
        name="GitHub OAuth Token",
        regex=re.compile(r'\b(gho_[0-9a-zA-Z]{36})\b'),
        severity=Severity.HIGH,
        description="GitHub OAuth token — user-delegated repository access",
    ),
    Pattern(
        name="GitHub Actions Token",
        regex=re.compile(r'\b(ghs_[0-9a-zA-Z]{36})\b'),
        severity=Severity.HIGH,
        description="GitHub Actions ephemeral token",
    ),
    Pattern(
        name="Slack Bot Token",
        regex=re.compile(r'\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b'),
        severity=Severity.HIGH,
        description="Slack bot token — workspace messaging and data access",
    ),
    Pattern(
        name="Slack User Token",
        regex=re.compile(r'\b(xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+)\b'),
        severity=Severity.HIGH,
        description="Slack user token — full user-level workspace access",
    ),
    Pattern(
        name="Slack Webhook URL",
        regex=re.compile(
            r'(https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[a-zA-Z0-9]+)'
        ),
        severity=Severity.HIGH,
        description="Slack incoming webhook — can post arbitrary messages to channels",
    ),
    Pattern(
        name="SendGrid API Key",
        regex=re.compile(r'\b(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})\b'),
        severity=Severity.HIGH,
        description="SendGrid API key — transactional email send access",
    ),
    Pattern(
        name="Twilio Auth Token",
        regex=re.compile(
            r'(?i)twilio.{0,30}[\'"]([a-f0-9]{32})[\'"]'
        ),
        severity=Severity.HIGH,
        description="Twilio auth token — SMS/call account access",
    ),
    Pattern(
        name="Database Connection String",
        regex=re.compile(
            r'(?i)((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql|sqlserver|mariadb)'
            r'://[^@\s\'"]{3,}@[^\s\'"]{4,})',
        ),
        severity=Severity.HIGH,
        description="Database connection string with embedded credentials",
    ),
    Pattern(
        name="JWT Token",
        regex=re.compile(
            r'\b(eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_+/=]+)\b'
        ),
        severity=Severity.HIGH,
        description="JSON Web Token — may contain auth session credentials",
    ),
    Pattern(
        name="Mailgun API Key",
        regex=re.compile(r'\b(key-[0-9a-f]{32})\b'),
        severity=Severity.HIGH,
        description="Mailgun API key — email send and domain access",
    ),
    Pattern(
        name="Supabase Service Role Key",
        regex=re.compile(r'\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b'),
        severity=Severity.HIGH,
        description="Likely Supabase/JWT service key — bypasses Row Level Security",
    ),

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    Pattern(
        name="Social Security Number (SSN)",
        regex=re.compile(
            r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
        ),
        severity=Severity.MEDIUM,
        description="US Social Security Number — PII exposure and identity theft risk",
        capture_group=0,
    ),
    Pattern(
        name="Stripe Test Secret Key",
        regex=re.compile(r'\b(sk_test_[0-9a-zA-Z]{24,})\b'),
        severity=Severity.MEDIUM,
        description="Stripe test secret key — confirms Stripe integration, test env access",
    ),
    Pattern(
        name="Stripe Live Publishable Key",
        regex=re.compile(r'\b(pk_live_[0-9a-zA-Z]{24,})\b'),
        severity=Severity.MEDIUM,
        description="Stripe live publishable key — confirms live environment, lower direct risk",
    ),
    Pattern(
        name="Generic API Key Assignment",
        regex=re.compile(
            r'(?i)(?:api[_\-]?key|api[_\-]?secret|app[_\-]?secret|client[_\-]?secret|access[_\-]?token)'
            r'\s*[:=]\s*[\'"]([A-Za-z0-9\-_/+=.]{16,})[\'"]'
        ),
        severity=Severity.MEDIUM,
        description="Generic API key or secret hardcoded in source",
    ),
    Pattern(
        name="Hardcoded Password",
        regex=re.compile(
            r'(?i)(?:password|passwd|pwd)\s*[:=]\s*[\'"]([^\'"]{8,})[\'"]'
        ),
        severity=Severity.MEDIUM,
        description="Hardcoded password — credential exposure risk",
    ),
]
