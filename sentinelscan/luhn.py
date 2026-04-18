import re

_FORMATTED_PAN = re.compile(r'\b(?:\d[ -]?){12,18}\d\b')


def luhn_check(number: str) -> bool:
    """Validate a card number string using the Luhn algorithm."""
    digits = "".join(c for c in number if c.isdigit())
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def extract_candidate_pans(text: str) -> list[str]:
    """
    Extract digit strings (possibly space/dash separated) that could be PANs.
    Returns raw matched strings; callers should run luhn_check on each.
    """
    candidates: list[str] = []
    for match in _FORMATTED_PAN.finditer(text):
        raw = match.group(0)
        digits = "".join(c for c in raw if c.isdigit())
        if 13 <= len(digits) <= 19:
            candidates.append(raw)
    return candidates
