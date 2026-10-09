import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from security_engine.config import engine_settings
from security_engine.scanners.base import BaseScanner
from security_engine.schemas import ScannerResult, Verdict

logger = logging.getLogger(__name__)


class YaraScanner(BaseScanner):
    """
    YARA signature engine. Uses native yara-python or Linux yara CLI if available,
    with an embedded pure-Python YARA rule matcher fallback.
    """

    @property
    def name(self) -> str:
        return "YaraScanner"

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or engine_settings.RULES_DIR
        self.compiled_rules = None
        self.has_native_yara = False
        self._parsed_rules: List[Dict] = []

        self._init_yara()

    def _init_yara(self):
        try:
            import yara
            rule_files = {}
            for yar_file in self.rules_dir.glob("*.yar"):
                rule_files[yar_file.stem] = str(yar_file)
            if rule_files:
                self.compiled_rules = yara.compile(filepaths=rule_files)
                self.has_native_yara = True
                logger.info("Compiled native YARA rules successfully.")
        except Exception as e:
            logger.info(f"Native YARA compiler unavailable ({e}). Using pure-Python YARA fallback engine.")
            self._load_fallback_rules()

    def _load_fallback_rules(self):
        """Loads and parses .yar rule files into regex patterns for pure-Python fallback."""
        for yar_file in self.rules_dir.glob("*.yar"):
            try:
                content = yar_file.read_text(encoding="utf-8", errors="replace")
                # Simple rule parser: rule <name> { ... strings: $s = ... condition: ... }
                rule_blocks = re.findall(r"rule\s+([A-Za-z0-9_]+)\s*\{([^}]+)\}", content)
                for rule_name, body in rule_blocks:
                    strings_block = re.search(r"strings:\s*(.*?)(?:condition:|$)", body, re.DOTALL)
                    patterns = []
                    if strings_block:
                        for line in strings_block.group(1).splitlines():
                            line = line.strip()
                            # Match $s = /pattern/ nocase or $s = "string" nocase
                            regex_match = re.search(r"\$[a-zA-Z0-9_]+\s*=\s*/(.*?)/\s*(nocase)?", line)
                            str_match = re.search(r"\$[a-zA-Z0-9_]+\s*=\s*\"(.*?)\"\s*(nocase)?", line)
                            if regex_match:
                                pat = regex_match.group(1)
                                flags = re.IGNORECASE if regex_match.group(2) else 0
                                patterns.append(re.compile(pat, flags))
                            elif str_match:
                                pat = re.escape(str_match.group(1))
                                flags = re.IGNORECASE if str_match.group(2) else 0
                                patterns.append(re.compile(pat, flags))

                    self._parsed_rules.append({
                        "name": rule_name,
                        "source_file": yar_file.name,
                        "patterns": patterns
                    })
            except Exception as read_err:
                logger.warning(f"Failed parsing YARA rule {yar_file.name}: {read_err}")

    def scan_data(self, data_bytes: bytes) -> ScannerResult:
        matched_rules = []
        indicators = []
        threat_score = 0.0

        if self.has_native_yara and self.compiled_rules:
            try:
                matches = self.compiled_rules.match(data=data_bytes)
                for m in matches:
                    matched_rules.append(m.rule)
                    indicators.append(f"YARA Rule Hit: {m.rule}")
                    threat_score += 35.0
            except Exception as e:
                logger.error(f"Native YARA match error: {e}")

        if not self.has_native_yara:
            # Fallback pure-Python matching
            text_decoded = data_bytes.decode("utf-8", errors="replace")
            for r in self._parsed_rules:
                for p in r["patterns"]:
                    if p.search(text_decoded):
                        matched_rules.append(r["name"])
                        indicators.append(f"YARA Hit: {r['name']} ({r['source_file']})")
                        threat_score += 35.0
                        break

        threat_score = min(100.0, threat_score)

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
            matched_rules=list(set(matched_rules)),
            indicators=indicators,
            details={
                "engine_mode": "native_yara" if self.has_native_yara else "python_fallback",
                "rules_evaluated": len(self._parsed_rules) if not self.has_native_yara else "native_compiled"
            }
        )

    def scan_text(self, text: str, context: Optional[str] = None) -> ScannerResult:
        full_text = text if not context else f"{context}\n\n{text}"
        return self.scan_data(full_text.encode("utf-8"))

    def scan_file(self, file_path: Optional[Path] = None, file_bytes: Optional[bytes] = None) -> ScannerResult:
        if file_bytes:
            return self.scan_data(file_bytes)
        elif file_path and file_path.exists():
            return self.scan_data(file_path.read_bytes())
        return self.scan_data(b"")
