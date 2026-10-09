import abc
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import Dataset, Record
from backend.schemas import CommonRecordSchema, ImportSummary

logger = logging.getLogger(__name__)


class DatasetImporter(abc.ABC):
    """
    Abstract Base Class for dataset-specific importers.
    
    Guarantees:
    - Never modifies raw dataset files.
    - Validates each raw record against the CommonRecordSchema.
    - Normalizes into common format.
    - Performs hash-based deduplication against existing database records.
    - Persists valid normalized records to PostgreSQL.
    - Exports normalized JSON lines to dataset/processed/<subdir>/.
    - Produces a timestamped audit manifest.
    """

    def __init__(
        self,
        dataset_name: str,
        source: str,
        description: str,
        processed_subdir: str
    ):
        self.dataset_name = dataset_name
        self.source = source
        self.description = description
        self.processed_dir = settings.PROCESSED_DIR / processed_subdir
        self.manifests_dir = settings.MANIFESTS_DIR
        
        # Ensure destination directories exist
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.manifests_dir.mkdir(parents=True, exist_ok=True)

    def get_or_create_dataset_entry(self, db: Session) -> Dataset:
        """Finds or registers the dataset entry in the database."""
        dataset = db.query(Dataset).filter(Dataset.name == self.dataset_name).first()
        if not dataset:
            dataset = Dataset(
                id=str(uuid.uuid4()),
                name=self.dataset_name,
                source=self.source,
                description=self.description,
                created_at=datetime.now(timezone.utc)
            )
            db.add(dataset)
            db.commit()
            db.refresh(dataset)
        return dataset

    @abc.abstractmethod
    def read_and_normalize(
        self, raw_path: Path
    ) -> List[Tuple[Optional[CommonRecordSchema], Optional[str]]]:
        """
        Reads raw data and yields tuples of (normalized_schema, error_message).
        If validation succeeds: (CommonRecordSchema, None)
        If invalid: (None, "reason")
        """
        pass

    def compute_content_hash(self, text: str) -> str:
        """Deterministic SHA-256 of extracted textual content."""
        clean = (text or "").strip().encode("utf-8")
        return hashlib.sha256(clean).hexdigest()

    def import_dataset(
        self,
        db: Session,
        raw_path: Optional[Path] = None,
        save_processed_copy: bool = True
    ) -> ImportSummary:
        """
        Main orchestration method:
        1. Reads raw data (read-only)
        2. Validates records
        3. Normalizes records
        4. Calculates hashes
        5. Removes duplicates
        6. Stores in database
        7. Produces summary and audit manifest
        """
        if raw_path is None:
            raw_path = self.get_default_raw_path()

        logger.info(f"Starting import for dataset '{self.dataset_name}' from {raw_path}")

        dataset_entry = self.get_or_create_dataset_entry(db)

        # Preload existing hashes for fast deduplication
        existing_file_hashes = {
            h[0] for h in db.query(Record.file_hash)
            .filter(Record.dataset_id == dataset_entry.id, Record.file_hash.isnot(None))
            .all()
        }
        existing_content_hashes = {
            h[0] for h in db.query(Record.content_hash)
            .filter(Record.dataset_id == dataset_entry.id)
            .all()
        }

        records_to_insert: List[Record] = []
        processed_records_json: List[Dict[str, Any]] = []

        seen_in_batch_file_hashes = set()
        seen_in_batch_content_hashes = set()

        total_found = 0
        imported_count = 0
        duplicates_count = 0
        invalid_count = 0

        raw_items = self.read_and_normalize(raw_path)

        for record_schema, err in raw_items:
            total_found += 1
            if err or record_schema is None:
                invalid_count += 1
                logger.debug(f"Invalid record in {self.dataset_name}: {err}")
                continue

            content_hash = self.compute_content_hash(record_schema.content)
            file_hash = record_schema.file_hash

            # Deduplication Check
            is_duplicate = False
            if file_hash:
                if file_hash in existing_file_hashes or file_hash in seen_in_batch_file_hashes:
                    is_duplicate = True
            elif content_hash:
                if content_hash in existing_content_hashes or content_hash in seen_in_batch_content_hashes:
                    is_duplicate = True

            if is_duplicate:
                duplicates_count += 1
                continue

            # Record is unique and valid
            if file_hash:
                seen_in_batch_file_hashes.add(file_hash)
            seen_in_batch_content_hashes.add(content_hash)

            record_id = record_schema.id or str(uuid.uuid4())
            now = record_schema.created_at or datetime.now(timezone.utc)

            db_record = Record(
                id=record_id,
                dataset_id=dataset_entry.id,
                source_type=record_schema.source_type.value,
                content=record_schema.content,
                label=record_schema.label.value,
                attack_type=record_schema.attack_type,
                file_name=record_schema.file_name,
                file_hash=file_hash,
                content_hash=content_hash,
                record_metadata=record_schema.metadata,
                created_at=now
            )
            records_to_insert.append(db_record)

            if save_processed_copy:
                processed_dict = {
                    "id": record_id,
                    "dataset": self.dataset_name,
                    "source_type": record_schema.source_type.value,
                    "content": record_schema.content,
                    "label": record_schema.label.value,
                    "attack_type": record_schema.attack_type,
                    "file_name": record_schema.file_name,
                    "file_hash": file_hash,
                    "metadata": record_schema.metadata,
                    "created_at": now.isoformat()
                }
                processed_records_json.append(processed_dict)

        # Batch insert to DB
        if records_to_insert:
            db.bulk_save_objects(records_to_insert)
            db.commit()
            imported_count = len(records_to_insert)

        # Write to processed directory as JSONL / JSON
        if save_processed_copy and processed_records_json:
            timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            processed_file = self.processed_dir / f"{self.dataset_name.lower()}_{timestamp_str}.jsonl"
            with open(processed_file, "w", encoding="utf-8") as f:
                for rec in processed_records_json:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            logger.info(f"Saved {len(processed_records_json)} normalized records to {processed_file}")

        summary = ImportSummary(
            dataset=self.dataset_name,
            total_found=total_found,
            imported=imported_count,
            duplicates=duplicates_count,
            invalid=invalid_count
        )

        # Save manifest
        self.save_manifest(summary, raw_path)

        return summary

    def save_manifest(self, summary: ImportSummary, raw_path: Path) -> Path:
        """Writes an audit manifest of the import operation."""
        timestamp = datetime.now(timezone.utc)
        manifest_filename = f"{self.dataset_name.lower()}_{timestamp.strftime('%Y%m%d_%H%M%S')}_manifest.json"
        manifest_path = self.manifests_dir / manifest_filename
        manifest_data = {
            "dataset": summary.dataset,
            "timestamp": timestamp.isoformat(),
            "raw_source_path": str(raw_path),
            "summary": summary.model_dump(),
            "status": "COMPLETED"
        }
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)
        return manifest_path

    @abc.abstractmethod
    def get_default_raw_path(self) -> Path:
        """Returns the canonical raw data directory for this dataset."""
        pass
