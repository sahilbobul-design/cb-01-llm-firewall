from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Verdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class Recommendation(str, Enum):
    ALLOW = "ALLOW"
    FLAG_FOR_REVIEW = "FLAG_FOR_REVIEW"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"


class ScannerResult(BaseModel):
    scanner_name: str
    verdict: Verdict
    threat_score: float = Field(..., ge=0.0, le=100.0)
    matched_rules: List[str] = Field(default_factory=list)
    indicators: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class ComprehensiveThreatReport(BaseModel):
    scan_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    record_id: Optional[str] = None
    dataset: Optional[str] = None
    source_type: str = "text"
    ground_truth_label: Optional[str] = None
    overall_verdict: Verdict
    overall_threat_score: float = Field(..., ge=0.0, le=100.0)
    detected_attack_types: List[str] = Field(default_factory=list)
    recommendation: Recommendation
    scanner_results: Dict[str, ScannerResult]
    summary_message: str

    model_config = ConfigDict(from_attributes=True)


class PromptScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Raw text prompt to analyze for jailbreaks / injections")
    context: Optional[str] = Field(None, description="Optional surrounding document/email context")


class BatchEvaluationSummary(BaseModel):
    total_scanned: int
    malicious_detected: int
    suspicious_detected: int
    benign_detected: int
    accuracy_against_ground_truth: Optional[float] = None
    false_positives: int
    false_negatives: int
    scans: List[ComprehensiveThreatReport] = Field(default_factory=list)
