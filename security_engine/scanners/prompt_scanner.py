import re
from pathlib import Path
from typing import List, Optional, Tuple
from security_engine.scanners.base import BaseScanner
from security_engine.schemas import ScannerResult, Verdict


class PromptInjectionScanner(BaseScanner):
    """
    Heuristic, pattern-based, and semantic scanner for Direct/Indirect
    Prompt Injections and LLM Jailbreak patterns.
    """

    @property
    def name(self) -> str:
        return "PromptInjectionScanner"

    def __init__(self):
        # Weighted threat patterns: (pattern, weight, category, indicator_name)
        self.rules: List[Tuple[re.Pattern, int, str, str]] = [
            # High-severity override vectors (weight 40-50)
            (re.compile(r"ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions|directives|rules|constraints|prompts)", re.IGNORECASE), 50, "direct_override", "System Override Directive"),
            (re.compile(r"disregard\s+(all\s+)?(previous|prior|above|system)\s+(guidelines|instructions|rules|prompts)", re.IGNORECASE), 50, "direct_override", "System Disregard Directive"),
            (re.compile(r"forget\s+(all\s+)?(prior|previous|existing)\s+(constraints|rules|instructions)", re.IGNORECASE), 45, "direct_override", "Memory Wipe Directive"),
            (re.compile(r"you\s+are\s+no\s+longer\s+bound\s+by", re.IGNORECASE), 45, "direct_override", "Safety Bound Break"),

            # Jailbreak personas & roleplay escape (weight 35-45)
            (re.compile(r"(do\s+anything\s+now|DAN\s+mode|developer\s+mode\s+enabled)", re.IGNORECASE), 45, "jailbreak_persona", "DAN / Developer Mode Jailbreak"),
            (re.compile(r"pretend\s+you\s+(have\s+no|don't\s+have|are\s+free\s+of)\s+(safety|content)\s+(filters|guidelines|policies)", re.IGNORECASE), 40, "jailbreak_persona", "Unrestricted Persona Simulation"),
            (re.compile(r"in\s+this\s+hypothetical\s+scenario,\s+you\s+must\s+act\s+as\s+an\s+unfiltered", re.IGNORECASE), 35, "jailbreak_persona", "Hypothetical Scenario Filter Bypass"),

            # Exfiltration & Poisoning (weight 40-50)
            (re.compile(r"(forward|send|email|transmit)\s+(the\s+)?(user's\s+)?(api\s+credentials|secret\s+keys|passwords?|tokens?)\s+to", re.IGNORECASE), 50, "data_exfiltration", "Credential Exfiltration Attempt"),
            (re.compile(r"(tell\s+the\s+user\s+to\s+)?delete\s+(their\s+)?(local\s+)?(database|files|system)", re.IGNORECASE), 45, "destructive_action", "Destructive Payload Command"),

            # Delimiter attacks & system impersonation (weight 25-35)
            (re.compile(r"(\[SYSTEM\s+DIRECTIVE\]|SYSTEM\s+DIRECTIVE:|IMPORTANT\s+SYSTEM\s+NOTICE:)", re.IGNORECASE), 35, "delimiter_hijack", "Impersonated System Directive Header"),
            (re.compile(r"(###\s*INSTRUCTION:|###\s*SYSTEM:|<admin_override>)", re.IGNORECASE), 30, "delimiter_hijack", "Markdown/XML Delimiter Hijack"),
            (re.compile(r"\[ATTACK:\s*[^\]]+\]", re.IGNORECASE), 35, "adversarial_marker", "Explicit Adversarial Annotation"),
        ]

    def scan_text(self, text: str, context: Optional[str] = None) -> ScannerResult:
        full_content = text
        if context:
            full_content = f"{context}\n\n{text}"

        total_weight = 0
        matched_indicators = []
        matched_rules = []
        categories = set()

        for pattern, weight, cat, indicator_name in self.rules:
            matches = pattern.findall(full_content)
            if matches:
                total_weight += weight
                matched_indicators.append(f"{indicator_name} (Matches: {len(matches)})")
                matched_rules.append(indicator_name)
                categories.add(cat)

        threat_score = min(100.0, float(total_weight))

        if threat_score >= 50.0:
            verdict = Verdict.MALICIOUS
        elif threat_score >= 25.0:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.BENIGN

        return ScannerResult(
            scanner_name=self.name,
            verdict=verdict,
            threat_score=threat_score,
            matched_rules=matched_rules,
            indicators=matched_indicators,
            details={
                "categories_detected": list(categories),
                "analyzed_length": len(full_content)
            }
        )

    def scan_file(self, file_path: Optional[Path] = None, file_bytes: Optional[bytes] = None) -> ScannerResult:
        content_str = ""
        if file_bytes:
            content_str = file_bytes.decode("utf-8", errors="replace")
        elif file_path and file_path.exists():
            content_str = file_path.read_text(encoding="utf-8", errors="replace")

        return self.scan_text(content_str)
