import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from backend.models import Base, Dataset, Record


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ToolResult(Base):
    __tablename__ = "tool_results"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    scan_id = Column(String(36), nullable=False, index=True)
    tool_name = Column(String(50), nullable=False, index=True)
    tool_version = Column(String(50), nullable=True)
    status = Column(String(30), nullable=False, index=True)  # COMPLETED, DETECTED, CLEAN, INFECTED, UNAVAILABLE, DISABLED, ERROR
    severity = Column(String(20), nullable=False, default="INFO", index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    detected = Column(Boolean, nullable=False, default=False)
    output_summary = Column(JSON, nullable=False, default=dict)
    execution_time_ms = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_tool_results_scan_tool", "scan_id", "tool_name"),
    )

    def __repr__(self) -> str:
        return f"<ToolResult(tool={self.tool_name}, status={self.status}, detected={self.detected})>"


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    scan_id = Column(String(36), nullable=False, index=True)
    layer = Column(String(50), nullable=False, index=True)  # RULES, LINUX_SECURITY, RISK_ENGINE, NETWORK, OUTPUT_FIREWALL
    event_type = Column(String(60), nullable=False, index=True)  # PROMPT_INJECTION, MALWARE_DETECTED, SECRET_DETECTED, PII, NETWORK_ACTIVITY
    severity = Column(String(20), nullable=False, default="LOW", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    event_metadata = Column("metadata", JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_security_events_scan_layer", "scan_id", "layer"),
    )

    def __repr__(self) -> str:
        return f"<SecurityEvent(event={self.event_type}, severity={self.severity})>"
