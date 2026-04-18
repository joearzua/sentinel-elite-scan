import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .entropy import is_high_entropy, shannon_entropy
from .luhn import luhn_check, extract_candidate_pans
from .patterns import PATTERNS, Severity

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
BINARY_CHECK_BYTES = 8192

SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".pyc", ".pyo", ".pyd",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".ogg",
    ".db", ".sqlite", ".sqlite3",
    ".lock",  # lockfiles have no secrets but lots of hashes
})

SKIP_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "__pycache__", ".tox", ".venv", "venv",
    "env", "dist", "build", ".cache", ".pytest_cache", ".mypy_cache",
    "coverage", "htmlcov", ".next", ".nuxt", "vendor",
})

_ASSIGNMENT_ENTROPY_RE = re.compile(
    r'(?:'
    r'[:=]\s*[\'"`]([^\'"` \t]{20,200})[\'"`]'        # quoted assignment value
    r'|(?:key|token|secret|password|credential|auth|api)'
    r'[^\s=\'"]*\s*=\s*(\S{20,200})'                   # unquoted assignment
    r')',
    re.IGNORECASE,
)

_TEST_INDICATORS = frozenset({
    "example", "placeholder", "changeme", "replace_me",
    "your_key", "your_token", "your_secret", "insert_key",
    "xxxxxxxx", "aaaaaaaa", "12345678901234567890",
    "todo", "fixme", "foobar",
})

_TEST_WORDS = re.compile(
    r'\b(?:test|dummy|fake|mock|sample)\b', re.IGNORECASE
)


@dataclass
class Finding:
    file_path: str
    line_number: int
    pattern_name: str
    severity: Severity
    description: str
    matched_value: str
    entropy: float | None = None
    commit_hash: str | None = None


def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(BINARY_CHECK_BYTES)
    except OSError:
        return True


def _redact(value: str, keep: int = 8) -> str:
    value = value.strip()
    if len(value) <= keep:
        return "*" * len(value)
    stars = min(len(value) - keep, 24)
    return value[:keep] + "*" * stars


def _is_test_value(value: str) -> bool:
    v = value.lower()
    if any(ind in v for ind in _TEST_INDICATORS):
        return True
    return bool(_TEST_WORDS.search(value))


def _scan_text(
    text: str,
    file_path: str,
    commit_hash: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    for line_num, line in enumerate(lines, start=1):
        # ── Named pattern checks ─────────────────────────────────────────────
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                if pattern.capture_group == 0 or match.lastindex is None:
                    raw_value = match.group(0)
                else:
                    raw_value = match.group(pattern.capture_group) or match.group(0)

                if pattern.requires_luhn and not luhn_check(raw_value):
                    continue

                if _is_test_value(raw_value):
                    continue

                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_num,
                    pattern_name=pattern.name,
                    severity=pattern.severity,
                    description=pattern.description,
                    matched_value=_redact(raw_value),
                    commit_hash=commit_hash,
                ))

        # ── Formatted PAN (with spaces/dashes) ───────────────────────────────
        for candidate in extract_candidate_pans(line):
            digits_only = "".join(c for c in candidate if c.isdigit())
            if not luhn_check(digits_only):
                continue
            if _is_test_value(candidate):
                continue
            # Skip if already caught by compact PAN pattern
            already = any(
                f.line_number == line_num and f.pattern_name == "Payment Card Number (PAN)"
                for f in findings
            )
            if not already:
                findings.append(Finding(
                    file_path=file_path,
                    line_number=line_num,
                    pattern_name="Payment Card Number (PAN)",
                    severity=Severity.CRITICAL,
                    description="Payment card number (PCI DSS violation) — validated with Luhn algorithm",
                    matched_value=_redact(candidate),
                    commit_hash=commit_hash,
                ))

        # ── Entropy-based detection ───────────────────────────────────────────
        for match in _ASSIGNMENT_ENTROPY_RE.finditer(line):
            value = (match.group(1) or match.group(2) or "").strip('"\'`; ,\t')
            if not value or not is_high_entropy(value):
                continue

            # Skip if a named pattern already caught this location
            already = any(
                f.line_number == line_num
                and abs(line.find(f.matched_value[:6]) - line.find(value[:6])) < 3
                for f in findings
                if f.line_number == line_num
            )
            if already:
                continue

            findings.append(Finding(
                file_path=file_path,
                line_number=line_num,
                pattern_name="High-Entropy String",
                severity=Severity.HIGH,
                description=(
                    f"Unrecognized high-entropy string "
                    f"(entropy={shannon_entropy(value):.2f} bits/char) — likely secret"
                ),
                matched_value=_redact(value),
                entropy=shannon_entropy(value),
                commit_hash=commit_hash,
            ))

    return findings


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file; returns empty list for binary/oversized/unreadable files."""
    try:
        if path.stat().st_size > MAX_FILE_SIZE:
            return []
    except OSError:
        return []

    if path.suffix.lower() in SKIP_EXTENSIONS:
        return []

    name = path.name.lower()
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return []

    if _is_binary(path):
        return []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    return _scan_text(text, str(path))


def scan_directory(root: Path) -> Iterator[Finding]:
    """Walk a directory tree and yield findings from each eligible file."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames
            if d not in SKIP_DIRS and not d.startswith(".")
        ]
        for filename in filenames:
            file_path = Path(dirpath) / filename
            yield from scan_file(file_path)


def scan_git_history(root: Path) -> Iterator[Finding]:
    """
    Scan all unique blobs across the full git history.
    Streams one commit at a time to bound memory usage.
    """
    try:
        log_result = subprocess.run(
            ["git", "-C", str(root), "log", "--all", "--format=%H"],
            capture_output=True, text=True, check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"git log failed: {exc.stderr.strip()}") from exc
    except FileNotFoundError as exc:
        raise RuntimeError("git executable not found in PATH") from exc

    commit_hashes = [h for h in log_result.stdout.strip().splitlines() if h]
    seen_blobs: set[str] = set()

    for commit_hash in commit_hashes:
        try:
            tree_result = subprocess.run(
                ["git", "-C", str(root), "ls-tree", "-r", "--long", commit_hash],
                capture_output=True, text=True, check=True,
            )
        except subprocess.CalledProcessError:
            continue

        for tree_line in tree_result.stdout.splitlines():
            parts = tree_line.split(None, 4)
            if len(parts) < 5:
                continue

            blob_hash = parts[2]
            size_str = parts[3]
            file_path = parts[4]

            if blob_hash in seen_blobs:
                continue
            seen_blobs.add(blob_hash)

            if Path(file_path).suffix.lower() in SKIP_EXTENSIONS:
                continue

            name_lower = Path(file_path).name.lower()
            if name_lower.endswith(".min.js") or name_lower.endswith(".min.css"):
                continue

            try:
                if size_str != "-" and int(size_str) > MAX_FILE_SIZE:
                    continue
            except ValueError:
                pass

            try:
                blob_result = subprocess.run(
                    ["git", "-C", str(root), "cat-file", "blob", blob_hash],
                    capture_output=True, check=True,
                )
            except subprocess.CalledProcessError:
                continue

            if b"\x00" in blob_result.stdout[:BINARY_CHECK_BYTES]:
                continue

            try:
                text = blob_result.stdout.decode("utf-8", errors="replace")
            except Exception:
                continue

            yield from _scan_text(text, file_path, commit_hash=commit_hash)
