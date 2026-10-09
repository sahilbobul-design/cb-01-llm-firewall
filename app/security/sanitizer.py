import re
from typing import Tuple


class ContentSanitizer:
    """
    Sanitizes and redacts sensitive data (API keys, secrets, PII, system tokens).
    GUARANTEE: Pure string transformations; never executes any content.
    """

    def __init__(self):
        self.secret_patterns = [
            (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_KEY]"),
            (re.compile(r"(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})"), "[REDACTED_GITHUB_TOKEN]"),
            (re.compile(r"sk-[a-zA-Z0-9]{32,64}"), "[REDACTED_API_KEY]"),
            (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "[REDACTED_SLACK_TOKEN]"),
            (re.compile(r"-----BEGIN\s+[A-Z\s]+\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+\s+KEY-----"), "[REDACTED_PRIVATE_KEY]"),
            (re.compile(r"password\s*[:=]\s*['\"][^\s'\"]+['\"]", re.I), "password='[REDACTED_PASSWORD]'"),
        ]

        self.pii_patterns = [
            (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
            (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "[REDACTED_CREDIT_CARD]"),
        ]

    def sanitize(self, text: str) -> Tuple[str, int]:
        """
        Returns (sanitized_text, redactions_count).
        """
        if not text:
            return "", 0

        sanitized = text
        redactions = 0

        # Redact secrets
        for pat, replacement in self.secret_patterns:
            matches = pat.findall(sanitized)
            if matches:
                redactions += len(matches)
                sanitized = pat.sub(replacement, sanitized)

        # Redact high-risk PII
        for pat, replacement in self.pii_patterns:
            matches = pat.findall(sanitized)
            if matches:
                redactions += len(matches)
                sanitized = pat.sub(replacement, sanitized)

        return sanitized, redactions


sanitizer = ContentSanitizer()
