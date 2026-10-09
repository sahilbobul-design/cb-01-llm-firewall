import hashlib
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import asc, desc, func
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import get_db
from backend.models import Dataset, Record
from backend.schemas import (
    BatchRecordImportRequest,
    ImportSummary,
    RecordLabel,
    RecordListResponse,
    RecordResponse,
    SourceType,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/records", tags=["Records"])


@router.get("", response_model=RecordListResponse)
def list_records(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1, description="Page number starting from 1"),
    page_size: int = Query(
        settings.PAGE_SIZE_DEFAULT,
        ge=1,
        le=settings.PAGE_SIZE_MAX,
        description="Number of records per page"
    ),
    source_type: Optional[SourceType] = Query(None, description="Filter by source_type: email, webpage, pdf"),
    label: Optional[RecordLabel] = Query(None, description="Filter by label: benign, prompt_injection, malicious_file"),
    attack_type: Optional[str] = Query(None, description="Filter by attack_type"),
    dataset: Optional[str] = Query(None, description="Filter by dataset name or dataset ID"),
    dataset_id: Optional[str] = Query(None, description="Alias for dataset parameter"),
    limit: Optional[int] = Query(None, description="Alias for page_size parameter"),
    file_hash: Optional[str] = Query(None, description="Filter by SHA-256 file hash"),
    search: Optional[str] = Query(None, description="Case-insensitive text search in record content"),
    sort_by: str = Query("created_at", description="Field to sort by: created_at, id, file_name, label, source_type"),
    order: str = Query("desc", description="Sort direction: asc or desc")
):
    """
    Retrieve paginated security records with comprehensive filtering, sorting,
    and deduplication guarantees.
    """
    if limit is not None:
        page_size = limit
    if dataset_id and not dataset:
        dataset = dataset_id

    query = db.query(Record)

    # 1. Dataset filter (support by UUID or Name)
    if dataset:
        dataset_obj = db.query(Dataset).filter(
            (Dataset.id == dataset) | (Dataset.name == dataset)
        ).first()
        if dataset_obj:
            query = query.filter(Record.dataset_id == dataset_obj.id)
        else:
            # If dataset filter was given but no dataset exists, return empty result
            return RecordListResponse(total=0, page=page, page_size=page_size, records=[])

    # 2. Source Type filter
    if source_type:
        query = query.filter(Record.source_type == source_type.value)

    # 3. Label filter
    if label:
        query = query.filter(Record.label == label.value)

    # 4. Attack Type filter
    if attack_type is not None:
        if attack_type.lower() in ["null", "none"]:
            query = query.filter(Record.attack_type.is_(None))
        else:
            query = query.filter(Record.attack_type == attack_type)

    # 5. File Hash filter
    if file_hash:
        query = query.filter(Record.file_hash == file_hash.strip().lower())

    # 6. Text search filter
    if search:
        query = query.filter(Record.content.ilike(f"%{search.strip()}%"))

    # Compute total matching records
    total = query.count()

    # 7. Sorting
    sort_col = getattr(Record, sort_by, Record.created_at)
    if order.lower() == "asc":
        query = query.order_by(asc(sort_col))
    else:
        query = query.order_by(desc(sort_col))

    # 8. Pagination
    offset = (page - 1) * page_size
    records = query.offset(offset).limit(page_size).all()

    record_responses = [RecordResponse.from_orm_model(r) for r in records]

    return RecordListResponse(
        total=total,
        page=page,
        page_size=page_size,
        records=record_responses
    )


@router.get("/export/csv")
def export_records_csv(
    db: Session = Depends(get_db),
    source_type: Optional[SourceType] = Query(None, description="Filter by source_type: email, webpage, pdf"),
    label: Optional[RecordLabel] = Query(None, description="Filter by label: benign, prompt_injection, malicious_file"),
    attack_type: Optional[str] = Query(None, description="Filter by attack_type"),
    dataset: Optional[str] = Query(None, description="Filter by dataset name or dataset ID"),
    file_hash: Optional[str] = Query(None, description="Filter by SHA-256 file hash"),
    search: Optional[str] = Query(None, description="Case-insensitive text search in record content"),
):
    """Export normalized security records as a downloadable CSV file."""
    import csv
    import io
    import json
    from fastapi.responses import Response

    query = db.query(Record)
    if dataset:
        dataset_obj = db.query(Dataset).filter(
            (Dataset.id == dataset) | (Dataset.name == dataset)
        ).first()
        if dataset_obj:
            query = query.filter(Record.dataset_id == dataset_obj.id)
        else:
            return Response(content="id,dataset,source_type,label,attack_type,file_name,file_hash,content_hash,content,metadata_json,created_at\n", media_type="text/csv")

    if source_type:
        query = query.filter(Record.source_type == source_type.value)
    if label:
        query = query.filter(Record.label == label.value)
    if attack_type is not None:
        if attack_type.lower() in ["null", "none"]:
            query = query.filter(Record.attack_type.is_(None))
        else:
            query = query.filter(Record.attack_type == attack_type)
    if file_hash:
        query = query.filter(Record.file_hash == file_hash.strip().lower())
    if search:
        query = query.filter(Record.content.ilike(f"%{search.strip()}%"))

    records = query.order_by(Record.created_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "dataset", "source_type", "label", "attack_type",
        "file_name", "file_hash", "content_hash", "content", "metadata_json", "created_at"
    ])
    for r in records:
        dataset_name = r.dataset.name if r.dataset else r.dataset_id
        meta_str = json.dumps(r.record_metadata or {}, ensure_ascii=False)
        writer.writerow([
            r.id, dataset_name, r.source_type, r.label, r.attack_type or "",
            r.file_name or "", r.file_hash or "", r.content_hash or "",
            r.content, meta_str, r.created_at.isoformat() if r.created_at else ""
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=records.csv"}
    )


@router.get("/{record_id}", response_model=RecordResponse)
def get_record(record_id: str, db: Session = Depends(get_db)):
    """Retrieve a single normalized security record by its unique ID."""
    record = db.query(Record).filter(Record.id == record_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Record with id '{record_id}' not found."
        )
    return RecordResponse.from_orm_model(record)


@router.post("/import", response_model=ImportSummary, status_code=status.HTTP_201_CREATED)
def import_records_batch(payload: BatchRecordImportRequest, db: Session = Depends(get_db)):
    """
    Import a batch of already-normalized CommonRecordSchema records directly into the database.
    Applies strict deduplication via file_hash and content_hash.
    """
    dataset_name = payload.dataset_name.strip()
    dataset = db.query(Dataset).filter(Dataset.name == dataset_name).first()
    if not dataset:
        dataset = Dataset(
            id=str(uuid.uuid4()),
            name=dataset_name,
            source="Batch API Ingestion",
            description=f"Auto-created dataset from batch import endpoint for {dataset_name}"
        )
        db.add(dataset)
        db.commit()
        db.refresh(dataset)

    # Preload existing hashes for fast deduplication
    existing_file_hashes = {
        h[0] for h in db.query(Record.file_hash)
        .filter(Record.dataset_id == dataset.id, Record.file_hash.isnot(None))
        .all()
    }
    existing_content_hashes = {
        h[0] for h in db.query(Record.content_hash)
        .filter(Record.dataset_id == dataset.id)
        .all()
    }

    seen_batch_file_hashes = set()
    seen_batch_content_hashes = set()

    total_found = len(payload.records)
    imported = 0
    duplicates = 0
    invalid = 0

    to_insert = []
    now = datetime.now(timezone.utc)

    for item in payload.records:
        try:
            content_clean = item.content.strip()
            if not content_clean:
                invalid += 1
                continue

            content_hash = hashlib.sha256(content_clean.encode("utf-8")).hexdigest()
            file_hash = item.file_hash

            is_duplicate = False
            if file_hash:
                if file_hash in existing_file_hashes or file_hash in seen_batch_file_hashes:
                    is_duplicate = True
            elif content_hash:
                if content_hash in existing_content_hashes or content_hash in seen_batch_content_hashes:
                    is_duplicate = True

            if is_duplicate:
                duplicates += 1
                continue

            if file_hash:
                seen_batch_file_hashes.add(file_hash)
            seen_batch_content_hashes.add(content_hash)

            rec_id = item.id or str(uuid.uuid4())
            rec_created_at = item.created_at or now

            db_record = Record(
                id=rec_id,
                dataset_id=dataset.id,
                source_type=item.source_type.value,
                content=item.content,
                label=item.label.value,
                attack_type=item.attack_type,
                file_name=item.file_name,
                file_hash=file_hash,
                content_hash=content_hash,
                record_metadata=item.metadata,
                created_at=rec_created_at
            )
            to_insert.append(db_record)

        except Exception as e:
            logger.warning(f"Invalid record during batch import: {e}")
            invalid += 1

    if to_insert:
        db.bulk_save_objects(to_insert)
        db.commit()
        imported = len(to_insert)

    return ImportSummary(
        dataset=dataset_name,
        total_found=total_found,
        imported=imported,
        duplicates=duplicates,
        invalid=invalid
    )
