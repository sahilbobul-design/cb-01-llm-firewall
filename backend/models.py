import uuid
from datetime import datetime, timezone
from typing import Any, Dict
from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    UniqueConstraint
)
from sqlalchemy.orm import relationship
from backend.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Dataset(Base):
    __tablename__ = "datasets"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    source = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    records = relationship("Record", back_populates="dataset", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Dataset(name={self.name}, source={self.source})>"


class Record(Base):
    __tablename__ = "records"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    dataset_id = Column(String(36), ForeignKey("datasets.id", ondelete="CASCADE"), nullable=False, index=True)
    source_type = Column(String(32), nullable=False, index=True)  # email, webpage, pdf
    content = Column(Text, nullable=False)
    label = Column(String(32), nullable=False, index=True)        # benign, prompt_injection, malicious_file
    attack_type = Column(String(64), nullable=True, index=True)   # direct_prompt_injection, indirect_prompt_injection, pdf_prompt_injection, malware, None
    file_name = Column(String(255), nullable=True)
    file_hash = Column(String(64), nullable=True, index=True)     # SHA-256
    content_hash = Column(String(64), nullable=False, index=True)  # SHA-256 of extracted content for deduplication
    
    # In PostgreSQL and SQLAlchemy, map DB column "metadata" to attribute record_metadata
    record_metadata = Column("metadata", JSON, nullable=False, default=dict)
    
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Relationships
    dataset = relationship("Dataset", back_populates="records")

    __table_args__ = (
        # Composite indexes for rapid filtering and deduplication
        Index("ix_records_dataset_filehash", "dataset_id", "file_hash"),
        Index("ix_records_dataset_contenthash", "dataset_id", "content_hash"),
        Index("ix_records_source_label", "source_type", "label"),
    )

    def __repr__(self) -> str:
        return f"<Record(id={self.id}, dataset_id={self.dataset_id}, label={self.label}, source_type={self.source_type})>"
