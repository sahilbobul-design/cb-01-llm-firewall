from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class SourceType(str, Enum):
    EMAIL = "email"
    WEBPAGE = "webpage"
    PDF = "pdf"


class RecordLabel(str, Enum):
    BENIGN = "benign"
    PROMPT_INJECTION = "prompt_injection"
    MALICIOUS_FILE = "malicious_file"


class AttackType(str, Enum):
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_PROMPT_INJECTION = "indirect_prompt_injection"
    PDF_PROMPT_INJECTION = "pdf_prompt_injection"
    MALWARE = "malware"
    NONE = "null"


# ---------------------------------------------------------
# Dataset Schemas
# ---------------------------------------------------------

class DatasetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Unique dataset identifier name")
    source: str = Field(..., min_length=1, max_length=255, description="Origin or citation source")
    description: Optional[str] = Field(None, description="Detailed dataset description")


class DatasetCreate(DatasetBase):
    pass


class DatasetResponse(DatasetBase):
    id: str
    created_at: datetime
    record_count: Optional[int] = 0

    model_config = ConfigDict(from_attributes=True)


class DatasetDetailResponse(DatasetResponse):
    records_by_source_type: Dict[str, int] = Field(default_factory=dict)
    records_by_label: Dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------
# Record Schemas
# ---------------------------------------------------------

class CommonRecordSchema(BaseModel):
    """Canonical schema for normalized security research records."""
    id: Optional[str] = None
    dataset: str = Field(..., description="Name or identifier of the dataset")
    source_type: SourceType = Field(..., description="Allowed: email, webpage, pdf")
    content: str = Field(..., description="Extracted clean text content")
    label: RecordLabel = Field(..., description="Allowed: benign, prompt_injection, malicious_file")
    attack_type: Optional[str] = Field(
        None,
        description="Allowed: direct_prompt_injection, indirect_prompt_injection, pdf_prompt_injection, malware, or null"
    )
    file_name: Optional[str] = Field(None, description="Original filename if applicable")
    file_hash: Optional[str] = Field(None, description="SHA-256 hash of the original raw file")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Structured metadata dictionary")
    created_at: Optional[datetime] = None

    @field_validator("attack_type")
    @classmethod
    def validate_attack_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "null" or v == "":
            return None
        valid_attacks = {
            "direct_prompt_injection",
            "indirect_prompt_injection",
            "pdf_prompt_injection",
            "malware"
        }
        if v not in valid_attacks:
            raise ValueError(f"Invalid attack_type '{v}'. Allowed: {valid_attacks} or null")
        return v

    @model_validator(mode="after")
    def validate_label_and_attack_alignment(self) -> "CommonRecordSchema":
        # Keep malicious_file strictly separate from prompt_injection
        if self.label == RecordLabel.MALICIOUS_FILE and self.attack_type is not None:
            if self.attack_type in {"direct_prompt_injection", "indirect_prompt_injection", "pdf_prompt_injection"}:
                raise ValueError("malicious_file label cannot have a prompt injection attack_type")
        if self.label == RecordLabel.PROMPT_INJECTION and self.attack_type == "malware":
            raise ValueError("prompt_injection label cannot have malware attack_type")
        if self.label == RecordLabel.BENIGN and self.attack_type is not None:
            raise ValueError("benign label must have null attack_type")
        return self


class RecordResponse(BaseModel):
    id: str
    dataset: str
    source_type: str
    content: str
    label: str
    attack_type: Optional[str] = None
    file_name: Optional[str] = None
    file_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_orm_model(cls, record: Any) -> "RecordResponse":
        dataset_name = record.dataset.name if record.dataset else record.dataset_id
        return cls(
            id=record.id,
            dataset=dataset_name,
            source_type=record.source_type,
            content=record.content,
            label=record.label,
            attack_type=record.attack_type,
            file_name=record.file_name,
            file_hash=record.file_hash,
            metadata=record.record_metadata if record.record_metadata is not None else {},
            created_at=record.created_at
        )


class RecordListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    records: List[RecordResponse]


# ---------------------------------------------------------
# Import Schemas
# ---------------------------------------------------------

class ImportSummary(BaseModel):
    dataset: str
    total_found: int
    imported: int
    duplicates: int
    invalid: int


class DatasetImportRequest(BaseModel):
    dataset_name: str = Field(..., description="One of: 'BIPIA', 'PDF_INJECTION', 'CIC_EVASIVE_PDFMAL2022' or custom registered name")
    custom_raw_path: Optional[str] = Field(None, description="Optional custom directory path to raw data")


class BatchRecordImportRequest(BaseModel):
    dataset_name: str
    records: List[CommonRecordSchema]
