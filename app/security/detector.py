import re
import ipaddress
from typing import Any, Dict, List, Tuple
from pydantic import BaseModel


class DetectionMatch(BaseModel):
    category: str
    match_type: str
    snippet: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL


class ContentDetectionResult(BaseModel):
    has_prompt_injection: bool = False
    has_system_attack: bool = False
    has_secrets: bool = False
    has_pii: bool = False
    has_suspicious_ip: bool = False
    has_suspicious_url: bool = False
    matches: List[DetectionMatch] = []
    extracted_indicators: List[str] = []


class ContentSecurityDetector:
    """
    Multi-vector regex & heuristic detector for:
    - Prompt Injections & System Prompt Attacks
    - Secrets & Credentials (API Keys, Tokens, Passwords)
    - PII (SSN, Credit Cards, Emails, Phone Numbers)
    - Suspicious IPs & Phishing URLs
    """

    def __init__(self):
        # 1. Prompt Injection & Override Directives
        self.injection_patterns = [
            (re.compile(r"ignore\s+(all\s+)?(previous|prior|system)\s+(instructions|directives|rules|prompts)", re.I), "PROMPT_INJECTION", "Instruction Override", "HIGH"),
            (re.compile(r"disregard\s+(all\s+)?(previous|prior|system)\s+(guidelines|instructions|rules)", re.I), "PROMPT_INJECTION", "Directive Disregard", "HIGH"),
            (re.compile(r"forget\s+(all\s+)?(prior|previous)\s+(rules|constraints|instructions)", re.I), "PROMPT_INJECTION", "Memory Wipe Attack", "HIGH"),
            (re.compile(r"(do\s+anything\s+now|DAN\s+mode|developer\s+mode\s+enabled)", re.I), "PROMPT_INJECTION", "DAN Jailbreak Persona", "CRITICAL"),
            (re.compile(r"(\[?SYSTEM\s+DIRECTIVE\]?|IMPORTANT\s+SYSTEM\s+NOTICE:?|SYSTEM\s+OVERRIDE:?)", re.I), "SYSTEM_PROMPT_ATTACK", "System Role Impersonation", "HIGH"),
            (re.compile(r"repeat\s+(your\s+)?(initial|system|original)\s+(prompt|instructions)", re.I), "SYSTEM_PROMPT_ATTACK", "System Prompt Leak Attempt", "HIGH"),
            (re.compile(r"what\s+(are|were)\s+your\s+(exact\s+)?system\s+instructions", re.I), "SYSTEM_PROMPT_ATTACK", "Prompt Extraction Attempt", "HIGH"),
            (re.compile(r"(print|reveal|show|display)\s+(your\s+)?(system\s+prompt|core\s+instructions|initial\s+prompt)", re.I), "SYSTEM_PROMPT_ATTACK", "System Prompt Extraction Directive", "HIGH"),
        ]

        # 2. Secret & Credential Patterns
        self.secret_patterns = [
            (re.compile(r"(AKIA[0-9A-Z]{16})"), "SECRET_DETECTED", "AWS Access Key", "CRITICAL"),
            (re.compile(r"(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})"), "SECRET_DETECTED", "GitHub Personal Token", "CRITICAL"),
            (re.compile(r"(xox[baprs]-[0-9a-zA-Z]{10,48})"), "SECRET_DETECTED", "Slack Token", "HIGH"),
            (re.compile(r"(sk-[a-zA-Z0-9]{32,64})"), "SECRET_DETECTED", "OpenAI / AI Secret Key", "CRITICAL"),
            (re.compile(r"(bearer\s+[a-zA-Z0-9_\-\.]{30,})", re.I), "SECRET_DETECTED", "Bearer Token", "HIGH"),
            (re.compile(r"(password\s*[:=]\s*['\"][^\s'\"]{6,}['\"])", re.I), "SECRET_DETECTED", "Hardcoded Password", "HIGH"),
            (re.compile(r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----"), "SECRET_DETECTED", "Private Key Header", "CRITICAL"),
        ]

        # 3. PII Patterns
        self.pii_patterns = [
            (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "PII_DETECTED", "Social Security Number (SSN)", "HIGH"),
            (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "PII_DETECTED", "Credit Card Number", "HIGH"),
            (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "PII_DETECTED", "Email Address", "LOW"),
            (re.compile(r"\b(?:\+?1[-.]?)?\(?[2-9]\d{2}\)?[-.]?\d{3}[-.]?\d{4}\b"), "PII_DETECTED", "Phone Number", "LOW"),
        ]

        # 4. IP Patterns
        self.ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        # 5. Suspicious URLs
        self.url_pattern = re.compile(r"https?://[^\s<>\"']+", re.I)

    def scan(self, text: str) -> ContentDetectionResult:
        if not text:
            return ContentDetectionResult()

        res = ContentDetectionResult()

        # Check prompt injection
        for pat, cat, match_name, sev in self.injection_patterns:
            for match in pat.finditer(text):
                res.matches.append(DetectionMatch(
                    category=cat,
                    match_type=match_name,
                    snippet=match.group(0)[:60],
                    severity=sev
                ))
                res.extracted_indicators.append(match_name)
                if cat == "PROMPT_INJECTION":
                    res.has_prompt_injection = True
                elif cat == "SYSTEM_PROMPT_ATTACK":
                    res.has_system_attack = True

        # Check secrets
        for pat, cat, match_name, sev in self.secret_patterns:
            for match in pat.finditer(text):
                # Redact actual secret snippet in match object for security!
                raw = match.group(0)
                redacted = raw[:4] + "****" + raw[-2:] if len(raw) > 6 else "****"
                res.matches.append(DetectionMatch(
                    category=cat,
                    match_type=match_name,
                    snippet=redacted,
                    severity=sev
                ))
                res.extracted_indicators.append(match_name)
                res.has_secrets = True

        # Check PII
        for pat, cat, match_name, sev in self.pii_patterns:
            for match in pat.finditer(text):
                res.matches.append(DetectionMatch(
                    category=cat,
                    match_type=match_name,
                    snippet="[REDACTED_PII]",
                    severity=sev
                ))
                res.extracted_indicators.append(match_name)
                res.has_pii = True

        # Check IPs
        for ip_match in self.ip_pattern.finditer(text):
            ip_str = ip_match.group(0)
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                # Flag non-loopback public or suspicious routable IPs found in prompt
                if not ip_obj.is_loopback:
                    res.matches.append(DetectionMatch(
                        category="SUSPICIOUS_IP",
                        match_type=f"IP Address: {ip_str}",
                        snippet=ip_str,
                        severity="MEDIUM" if ip_obj.is_private else "HIGH"
                    ))
                    res.extracted_indicators.append(f"IP:{ip_str}")
                    res.has_suspicious_ip = True
            except ValueError:
                pass

        # Check URLs
        for url_match in self.url_pattern.finditer(text):
            url_str = url_match.group(0)
            if any(term in url_str.lower() for term in [".test", "malicious", "evil", "attacker", "exfil", "@"]):
                res.matches.append(DetectionMatch(
                    category="SUSPICIOUS_URL",
                    match_type="Suspicious Domain / Phishing Indicator",
                    snippet=url_str,
                    severity="HIGH"
                ))
                res.extracted_indicators.append("Suspicious URL")
                res.has_suspicious_url = True

        return res


content_detector = ContentSecurityDetector()
