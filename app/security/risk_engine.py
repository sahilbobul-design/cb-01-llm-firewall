from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from app.security.detector import ContentDetectionResult


class RiskEvaluation(BaseModel):
    risk_score: int
    status: str  # SAFE, SUSPICIOUS, BLOCKED
    reasons: List[str]
    breakdown: Dict[str, int]


class RiskEngine:
    """
    Combines rule detections, YARA matches, and ClamAV findings into
    a unified cybersecurity risk score (0-100) and action classification.
    """

    def evaluate(
        self,
        content_res: ContentDetectionResult,
        yara_res: Optional[Dict[str, Any]] = None,
        clamav_res: Optional[Dict[str, Any]] = None,
        network_events: Optional[List[Dict[str, Any]]] = None
    ) -> RiskEvaluation:
        score = 0
        reasons: List[str] = []
        breakdown: Dict[str, int] = {}

        # 1. Content Security Detections
        if content_res.has_prompt_injection:
            score += 50
            reasons.append("PROMPT_INJECTION")
            breakdown["prompt_injection"] = 50

        if content_res.has_system_attack:
            score += 50
            reasons.append("SYSTEM_PROMPT_ATTACK")
            breakdown["system_prompt_attack"] = 50

        if content_res.has_secrets:
            score += 35
            reasons.append("SECRET_DETECTED")
            breakdown["secret_detected"] = 35

        if content_res.has_pii:
            score += 10
            reasons.append("PII_DETECTED")
            breakdown["pii_detected"] = 10

        if content_res.has_suspicious_ip:
            score += 10
            reasons.append("SUSPICIOUS_IP")
            breakdown["suspicious_ip"] = 10

        if content_res.has_suspicious_url:
            score += 20
            reasons.append("SUSPICIOUS_URL")
            breakdown["suspicious_url"] = 20

        # 2. Linux ClamAV Malware Scanner
        if clamav_res and clamav_res.get("infected", False):
            score += 60
            reasons.append("MALWARE_DETECTED")
            breakdown["malware_detected"] = 60

        # 3. Linux YARA Pattern Scanner
        if yara_res and yara_res.get("detected", False):
            score += 40
            reasons.append("YARA_PATTERN_DETECTED")
            breakdown["yara_detection"] = 40

        # 4. Network Monitoring Findings
        if network_events:
            high_sev = [e for e in network_events if e.get("severity") in ("HIGH", "CRITICAL")]
            if high_sev:
                score += 25
                reasons.append("SUSPICIOUS_NETWORK_TRAFFIC")
                breakdown["network_threat"] = 25

        # Cap score at 100
        final_score = min(100, score)

        # Classification thresholds
        if final_score >= 70:
            classification = "BLOCKED"
        elif final_score >= 30:
            classification = "SUSPICIOUS"
        else:
            classification = "SAFE"

        # Deduplicate reasons while preserving order
        unique_reasons = list(dict.fromkeys(reasons))

        return RiskEvaluation(
            risk_score=final_score,
            status=classification,
            reasons=unique_reasons,
            breakdown=breakdown
        )


risk_engine = RiskEngine()
