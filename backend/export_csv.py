import csv
import json
import logging
from pathlib import Path
from sqlalchemy.orm import Session

from backend.config import settings
from backend.database import SessionLocal, init_db
from backend.models import Dataset, Record

logger = logging.getLogger("export_csv")


def export_all_records_to_csv(output_dir: Path = settings.PROCESSED_DIR):
    """
    Exports normalized dataset records from the database to clean CSV files:
    1. Comprehensive master file: normalized_records_all.csv
    2. Sub-category CSV files:
       - email/records_email.csv
       - webpage/records_webpage.csv
       - pdf_injection/records_pdf_injection.csv
       - pdf_malware/records_pdf_malware.csv
    """
    init_db()
    db: Session = SessionLocal()
    try:
        records = db.query(Record).order_by(Record.created_at.desc()).all()
        if not records:
            print("No records found in database to export.")
            return

        headers = [
            "id",
            "dataset",
            "source_type",
            "label",
            "attack_type",
            "file_name",
            "file_hash",
            "content_hash",
            "content",
            "metadata_json",
            "created_at"
        ]

        # 1. Master CSV containing all records
        master_csv_path = output_dir / "normalized_records_all.csv"
        master_csv_path.parent.mkdir(parents=True, exist_ok=True)

        rows_by_source = {"email": [], "webpage": [], "pdf_injection": [], "pdf_malware": []}
        all_rows = []

        for r in records:
            dataset_name = r.dataset.name if r.dataset else r.dataset_id
            meta_str = json.dumps(r.record_metadata or {}, ensure_ascii=False)
            row = [
                r.id,
                dataset_name,
                r.source_type,
                r.label,
                r.attack_type or "",
                r.file_name or "",
                r.file_hash or "",
                r.content_hash or "",
                r.content,
                meta_str,
                r.created_at.isoformat() if r.created_at else ""
            ]
            all_rows.append(row)

            # Categorize
            if r.source_type == "email":
                rows_by_source["email"].append(row)
            elif r.source_type == "webpage":
                rows_by_source["webpage"].append(row)
            elif r.source_type == "pdf":
                if r.label == "malicious_file" or "malware" in (r.attack_type or "") or "CIC" in dataset_name:
                    rows_by_source["pdf_malware"].append(row)
                else:
                    rows_by_source["pdf_injection"].append(row)

        with open(master_csv_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(all_rows)

        print(f"[+] Master CSV written: {master_csv_path} ({len(all_rows)} records)")

        # 2. Write per-category CSV files
        for category, cat_rows in rows_by_source.items():
            cat_dir = output_dir / category
            cat_dir.mkdir(parents=True, exist_ok=True)
            cat_csv_path = cat_dir / f"records_{category}.csv"
            with open(cat_csv_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                writer.writerows(cat_rows)
            print(f"[+] Category CSV written: {cat_csv_path} ({len(cat_rows)} records)")

    finally:
        db.close()


if __name__ == "__main__":
    export_all_records_to_csv()
