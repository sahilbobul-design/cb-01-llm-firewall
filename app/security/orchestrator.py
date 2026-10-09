import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from sqlalchemy.orm import Session

from app.config import settings
from app.database.models import SecurityEvent, ToolResult
from app.network.monitor import network_monitor
from app.security.detector import content_detector
from app.security.risk_engine import RiskEvaluation, risk_engine
from app.security.sanitizer import sanitizer
from app.security_tools.registry import tool_registry
from app.storage.hashing import compute_file_hash_info
from app.storage.quarantine import quarantine
from backend.processors.email import extract_email_data
from backend.processors.pdf import extract_pdf_data
from backend.processors.webpage import extract_webpage_data

logger = logging.getLogger(__name__)


class SecurityOrchestrator:
    """
    Central Security Orchestrator for the AI Security Gateway.
    
    Guarantees:
    - Never executes untrusted document content.
    - Isolates files in non-executable quarantine storage before scanning.
    - Selects appropriate security tools based on payload type.
    - Gracefully continues even if individual Linux tools are unavailable.
    - Emits structured ToolResult and SecurityEvent records to the database.
    - Evaluates final risk score (0-100) and classification (SAFE, SUSPICIOUS, BLOCKED).
    - Applies secret & PII sanitization.
    """

    def __init__(self):
        self.detector = content_detector
        self.risk_engine = risk_engine
        self.sanitizer = sanitizer
        self.registry = tool_registry

    async def scan_payload(
        self,
        text_content: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        source_type: str = "text",
        db: Optional[Session] = None
    ) -> Dict[str, Any]:
        scan_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc)
        tool_results_data: Dict[str, Any] = {}
        file_info = None

        extracted_text = text_content or ""

        # -------------------------------------------------------------
        # 1. File Handling & Quarantine (if file is provided)
        # -------------------------------------------------------------
        yara_result = None
        clamav_result = None

        if file_bytes:
            file_info = compute_file_hash_info(file_bytes, original_filename=filename)

            # Isolate in strict quarantine directory before running scanners
            with quarantine.isolate(file_bytes, original_filename=filename or "upload") as qfile:
                # Run YARA if enabled
                try:
                    yara_result = await self.registry.yara.scan(qfile)
                    tool_results_data["yara"] = yara_result
                except Exception as y_err:
                    logger.error(f"YARA scanner error in orchestrator: {y_err}")
                    yara_result = {"tool": "yara", "status": "ERROR", "error": str(y_err)}
                    tool_results_data["yara"] = yara_result

                # Run ClamAV if enabled
                try:
                    clamav_result = await self.registry.clamav.scan(qfile)
                    tool_results_data["clamav"] = clamav_result
                except Exception as c_err:
                    logger.error(f"ClamAV scanner error in orchestrator: {c_err}")
                    clamav_result = {"tool": "clamav", "status": "ERROR", "error": str(c_err)}
                    tool_results_data["clamav"] = clamav_result

            # Extract readable text content safely based on type
            if file_info.mime_type == "application/pdf" or (filename and filename.lower().endswith(".pdf")):
                pdf_data = extract_pdf_data(file_bytes=file_bytes, file_name=filename)
                extracted_text = pdf_data.get("content", "")
                source_type = "pdf"
            elif file_info.mime_type == "message/rfc822" or (filename and filename.lower().endswith(".eml")):
                email_data = extract_email_data(raw_content=file_bytes, file_name=filename)
                extracted_text = email_data.get("content", "")
                source_type = "email"
            elif file_info.mime_type == "text/html" or (filename and filename.lower().endswith((".htm", ".html"))):
                web_data = extract_webpage_data(html_content=file_bytes, file_name=filename)
                extracted_text = web_data.get("content", "")
                source_type = "webpage"

        # -------------------------------------------------------------
        # 2. Content Security & Rule Detection
        # -------------------------------------------------------------
        detection_result = self.detector.scan(extracted_text)

        # -------------------------------------------------------------
        # 3. Network Traffic Analysis (if enabled)
        # -------------------------------------------------------------
        network_data = None
        if settings.NETWORK_MONITOR_ENABLED:
            try:
                network_data = await network_monitor.capture_and_analyze()
                tool_results_data["tshark"] = network_data
            except Exception as net_err:
                logger.warning(f"Network monitor error: {net_err}")
                tool_results_data["tshark"] = {"tool": "tshark", "status": "ERROR", "error": str(net_err)}
        else:
            tool_results_data["tshark"] = {"tool": "tshark", "status": "DISABLED"}

        # -------------------------------------------------------------
        # 4. Jev Interface (Placeholder)
        # -------------------------------------------------------------
        tool_results_data["jev"] = {"tool": "jev", "status": "UNAVAILABLE"}

        # -------------------------------------------------------------
        # 5. Risk Engine Evaluation
        # -------------------------------------------------------------
        network_events = network_data.get("events", []) if network_data else []
        evaluation: RiskEvaluation = self.risk_engine.evaluate(
            content_res=detection_result,
            yara_res=yara_result,
            clamav_res=clamav_result,
            network_events=network_events
        )

        # -------------------------------------------------------------
        # 6. Sanitization
        # -------------------------------------------------------------
        sanitized_content, redactions_count = self.sanitizer.sanitize(extracted_text)

        # -------------------------------------------------------------
        # 7. Database Persistence (Tool Results & Security Events)
        # -------------------------------------------------------------
        if db:
            try:
                # Save tool results
                for tool_name, t_res in tool_results_data.items():
                    status_str = t_res.get("status", "COMPLETED")
                    is_detected = bool(t_res.get("detected") or t_res.get("infected"))
                    sev = "HIGH" if is_detected else "INFO"
                    db_tool = ToolResult(
                        scan_id=scan_id,
                        tool_name=tool_name,
                        tool_version=None,
                        status=status_str,
                        severity=sev,
                        detected=is_detected,
                        output_summary=t_res,
                        execution_time_ms=float(t_res.get("execution_time_ms", 0.0)),
                        created_at=timestamp
                    )
                    db.add(db_tool)

                # Save security events
                for match in detection_result.matches:
                    db_event = SecurityEvent(
                        scan_id=scan_id,
                        layer="CONTENT_RULES",
                        event_type=match.category,
                        severity=match.severity,
                        description=f"{match.match_type}: {match.snippet}",
                        event_metadata={"category": match.category, "match": match.match_type},
                        created_at=timestamp
                    )
                    db.add(db_event)

                if yara_result and yara_result.get("detected"):
                    for m in yara_result.get("matches", []):
                        db.add(SecurityEvent(
                            scan_id=scan_id,
                            layer="LINUX_SECURITY",
                            event_type="YARA_PATTERN_DETECTED",
                            severity="HIGH",
                            description=f"YARA rule hit: {m}",
                            event_metadata={"rule": m},
                            created_at=timestamp
                        ))

                if clamav_result and clamav_result.get("infected"):
                    db.add(SecurityEvent(
                        scan_id=scan_id,
                        layer="LINUX_SECURITY",
                        event_type="MALWARE_DETECTED",
                        severity="CRITICAL",
                        description=f"ClamAV detected: {clamav_result.get('signature', 'Malware')}",
                        event_metadata={"signature": clamav_result.get("signature")},
                        created_at=timestamp
                    ))

                db.commit()
            except Exception as db_err:
                logger.error(f"Failed to persist security events to DB: {db_err}")
                db.rollback()

        # -------------------------------------------------------------
        # 8. Construct Unified Response
        # -------------------------------------------------------------
        return {
            "scan_id": scan_id,
            "timestamp": timestamp.isoformat(),
            "source_type": source_type,
            "risk_score": evaluation.risk_score,
            "status": evaluation.status,
            "reasons": evaluation.reasons,
            "threat_breakdown": evaluation.breakdown,
            "threats": {
                "prompt_injection": detection_result.has_prompt_injection,
                "system_attack": detection_result.has_system_attack,
                "secret_detected": detection_result.has_secrets,
                "pii_detected": detection_result.has_pii,
                "suspicious_ip": detection_result.has_suspicious_ip,
                "suspicious_url": detection_result.has_suspicious_url,
                "yara_detected": bool(yara_result and yara_result.get("detected")),
                "clamav_infected": bool(clamav_result and clamav_result.get("infected"))
            },
            "file_security": {
                "file_hash": file_info.file_hash if file_info else None,
                "file_size": file_info.file_size if file_info else None,
                "mime_type": file_info.mime_type if file_info else None,
                "yara": yara_result.get("status", "UNAVAILABLE") if yara_result else "SKIPPED",
                "clamav": clamav_result.get("status", "UNAVAILABLE") if clamav_result else "SKIPPED"
            },
            "tool_results": tool_results_data,
            "sanitized_content": sanitized_content if evaluation.status != "BLOCKED" else "[BLOCKED_BY_SECURITY_GATEWAY]",
            "redactions_count": redactions_count
        }

    async def scan_llm_output(self, output_text: str, db: Optional[Session] = None) -> Dict[str, Any]:
        """
        Output Firewall scanning after LLM produces a response.
        Inspects for leakage of system prompts, API keys, credentials, or PII.
        """
        detection = self.detector.scan(output_text)
        sanitized_text, redactions = self.sanitizer.sanitize(output_text)

        is_sensitive = (
            detection.has_secrets or
            detection.has_system_attack or
            (detection.has_pii and redactions > 0)
        )

        return {
            "is_sensitive": is_sensitive,
            "action": "REDACT_AND_ALLOW" if (is_sensitive and not detection.has_system_attack) else ("BLOCK" if detection.has_system_attack else "ALLOW"),
            "secrets_detected": detection.has_secrets,
            "pii_detected": detection.has_pii,
            "system_prompt_leakage": detection.has_system_attack,
            "redactions_count": redactions,
            "safe_output": sanitized_text if not detection.has_system_attack else "[REDACTED_SYSTEM_PROMPT_LEAKAGE]"
        }


security_orchestrator = SecurityOrchestrator()
