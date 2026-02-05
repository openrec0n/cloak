"""Output sanitization for preventing sensitive data leakage.

This module provides functions to detect and remove sensitive AWS data from
summaries before they are sent to Claude's context.
"""

import re

# Patterns that should NEVER appear in summaries sent to Claude
SENSITIVE_PATTERNS = {
    "arn": re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9/_-]+"),
    "account_id": re.compile(r"(?<!-)\b\d{12}\b"),
    "access_key": re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}"),
    "s3_bucket_url": re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3\."),
    "s3_bucket_arn": re.compile(r"arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"),
    "ec2_resource": re.compile(
        r"\b(i|sg|vpc|subnet|vol|snap|ami|eni|igw|rtb|acl|natgw|eip)-[a-f0-9]{8,17}\b"
    ),
    "iam_resource": re.compile(r"(user|role|group|policy)/[a-zA-Z0-9+=,.@_-]+"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


def validate_summary(summary: str) -> tuple[bool, list[str]]:
    """Validate that summary contains no sensitive data.

    This function checks summaries for sensitive AWS resource identifiers
    before they are sent to Claude's context.

    Args:
        summary: The summary text to validate

    Returns:
        Tuple of (is_safe, violations)
        - is_safe: True if no sensitive patterns found
        - violations: List of violation descriptions with examples

    Example:
        >>> is_safe, violations = validate_summary("Found 10 buckets in us-east-1")
        >>> assert is_safe
        >>> is_safe, violations = validate_summary("Found arn:aws:s3:::my-bucket")
        >>> assert not is_safe
        >>> assert 'arn' in violations[0]
    """
    violations = []

    for pattern_name, pattern_regex in SENSITIVE_PATTERNS.items():
        matches = pattern_regex.findall(summary)
        if matches:
            # Show first 3 matches as examples
            examples = matches[:3]
            violation = f"{pattern_name}: {', '.join(str(m) for m in examples)}"
            violations.append(violation)

    return len(violations) == 0, violations


def sanitize_text(text: str, replacement: str = "[REDACTED]") -> str:
    """Remove sensitive patterns from text.

    This function replaces all sensitive patterns with a redaction placeholder.
    Useful for cleaning text before logging or display.

    Args:
        text: Text to sanitize
        replacement: Replacement string for sensitive data

    Returns:
        Sanitized text with all sensitive patterns replaced

    Example:
        >>> sanitize_text("Bucket: arn:aws:s3:::my-bucket")
        'Bucket: [REDACTED]'
    """
    sanitized = text
    for pattern_regex in SENSITIVE_PATTERNS.values():
        sanitized = pattern_regex.sub(replacement, sanitized)
    return sanitized
