import math
import re

ENTROPY_THRESHOLD = 4.5
MIN_LENGTH = 20
MAX_LENGTH = 200

_LOW_ENTROPY_INDICATORS = {
    "example", "test", "dummy", "placeholder", "changeme",
    "password", "username", "localhost", "undefined", "null",
    "aaaaaaa", "1234567", "abcdefg", "replace", "insert",
}

_URL_PATTERN = re.compile(r'^https?://')
_MOSTLY_SAME_CHAR = re.compile(r'^(.)\1{9,}$')


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy(value: str, threshold: float = ENTROPY_THRESHOLD) -> bool:
    """Return True if value looks like an unrecognized secret based on entropy."""
    if len(value) < MIN_LENGTH or len(value) > MAX_LENGTH:
        return False

    # Skip URLs
    if _URL_PATTERN.match(value):
        return False

    # Skip strings with spaces (natural language / sentences)
    if value.count(" ") > 2:
        return False

    # Skip repeated-character strings
    if _MOSTLY_SAME_CHAR.match(value):
        return False

    # Skip obvious low-entropy indicators
    value_lower = value.lower()
    for indicator in _LOW_ENTROPY_INDICATORS:
        if indicator in value_lower:
            return False

    # Require a mix of character classes for it to look like a secret
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    has_digit = any(c.isdigit() for c in value)
    char_class_count = sum([has_upper, has_lower, has_digit])
    if char_class_count < 2:
        return False

    return shannon_entropy(value) >= threshold
