import logging
from pathlib import Path
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.importers.bipia import BIPIAImporter
from backend.importers.pdf_injection import PDFInjectionImporter
from backend.importers.pdf_malware import PDFMalwareImporter
from backend.models import Dataset, Record
from backend.schemas import (
    DatasetCreate,
    DatasetDetailResponse,
    DatasetImportRequest,
    DatasetResponse,
    ImportSummary,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/datasets", tags=["Datasets"])

IMPORTER_REGISTRY = {
    "bipia": BIPIAImporter,
    "pdf_injection": PDFInjectionImporter,
    "pdf_malware": PDFMalwareImporter,
    "cic_evasive_pdfmal2022": PDFMalwareImporter,
}


def resolve_importer(name: str):
    key = name.strip().lower()
    importer_cls = IMPORTER_REGISTRY.get(key)
    if not importer_cls:
        # Check partial match
        if "bipia" in key:
            importer_cls = BIPIAImporter
        elif "injection" in key:
            importer_cls = PDFInjectionImporter
        elif "malware" in key or "cic" in key:
            importer_cls = PDFMalwareImporter
    if not importer_cls:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown dataset '{name}'. Available importers: {list(IMPORTER_REGISTRY.keys())}"
        )
    return importer_cls()


@router.get("", response_model=List[DatasetResponse])
def list_datasets(db: Session = Depends(get_db)):
    """List all registered datasets with current record counts."""
    datasets = db.query(Dataset).all()
    results = []
    for d in datasets:
        count = db.query(func.count(Record.id)).filter(Record.dataset_id == d.id).scalar() or 0
        results.append(
            DatasetResponse(
                id=d.id,
                name=d.name,
                source=d.source,
                description=d.description,
                created_at=d.created_at,
                record_count=count
            )
        )
    return results


@router.get("/{dataset_id}", response_model=DatasetDetailResponse)
def get_dataset(dataset_id: str, db: Session = Depends(get_db)):
    """Get dataset details, including records breakdown by source_type and label."""
    # Lookup by id or by exact name
    dataset = db.query(Dataset).filter(
        (Dataset.id == dataset_id) | (Dataset.name == dataset_id)
    ).first()

    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset with id or name '{dataset_id}' not found."
        )

    total_count = db.query(func.count(Record.id)).filter(Record.dataset_id == dataset.id).scalar() or 0

    # Counts by source type
    source_counts = (
        db.query(Record.source_type, func.count(Record.id))
        .filter(Record.dataset_id == dataset.id)
        .group_by(Record.source_type)
        .all()
    )
    records_by_source_type = {src: count for src, count in source_counts}

    # Counts by label
    label_counts = (
        db.query(Record.label, func.count(Record.id))
        .filter(Record.dataset_id == dataset.id)
        .group_by(Record.label)
        .all()
    )
    records_by_label = {lbl: count for lbl, count in label_counts}

    return DatasetDetailResponse(
        id=dataset.id,
        name=dataset.name,
        source=dataset.source,
        description=dataset.description,
        created_at=dataset.created_at,
        record_count=total_count,
        records_by_source_type=records_by_source_type,
        records_by_label=records_by_label
    )


@router.post("", response_model=DatasetResponse, status_code=status.HTTP_201_CREATED)
def create_dataset(payload: DatasetCreate, db: Session = Depends(get_db)):
    """Manually register a new dataset."""
    existing = db.query(Dataset).filter(Dataset.name == payload.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Dataset with name '{payload.name}' already exists."
        )
    new_dataset = Dataset(
        name=payload.name,
        source=payload.source,
        description=payload.description
    )
    db.add(new_dataset)
    db.commit()
    db.refresh(new_dataset)
    return DatasetResponse(
        id=new_dataset.id,
        name=new_dataset.name,
        source=new_dataset.source,
        description=new_dataset.description,
        created_at=new_dataset.created_at,
        record_count=0
    )


@router.post("/import", response_model=ImportSummary)
def trigger_dataset_import(
    payload: DatasetImportRequest,
    db: Session = Depends(get_db)
):
    """
    Trigger safe data ingestion for a known dataset source.
    Reads raw untrusted files, extracts features safely, deduplicates,
    persists normalized records, and outputs an import summary.
    """
    importer = resolve_importer(payload.dataset_name)

    raw_path: Optional[Path] = None
    if payload.custom_raw_path:
        raw_path = Path(payload.custom_raw_path)
        if not raw_path.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Specified custom_raw_path does not exist: {raw_path}"
            )

    try:
        summary = importer.import_dataset(db=db, raw_path=raw_path)
        return summary
    except Exception as e:
        logger.error(f"Import failed for {payload.dataset_name}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Import operation encountered an error: {str(e)}"
        )
