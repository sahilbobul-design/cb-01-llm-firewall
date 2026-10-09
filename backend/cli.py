import argparse
import json
import logging
import sys
from typing import List

from backend.database import SessionLocal, init_db
from backend.importers.bipia import BIPIAImporter
from backend.importers.pdf_injection import PDFInjectionImporter
from backend.importers.pdf_malware import PDFMalwareImporter
from backend.models import Dataset, Record

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("importer-cli")


def get_importers():
    return {
        "bipia": BIPIAImporter(),
        "pdf_injection": PDFInjectionImporter(),
        "pdf_malware": PDFMalwareImporter(),
    }


def run_import(dataset_name: str):
    init_db()
    importers = get_importers()
    db = SessionLocal()
    try:
        if dataset_name == "all":
            summaries = []
            for name, importer in importers.items():
                print(f"\n==========================================")
                print(f"[*] Running importer for: {name.upper()}")
                print(f"==========================================")
                summary = importer.import_dataset(db=db)
                summaries.append(summary)
                print(json.dumps(summary.model_dump(), indent=2))
            return summaries
        else:
            key = dataset_name.lower().strip()
            if key not in importers:
                print(f"Error: Unknown dataset '{dataset_name}'. Available: {list(importers.keys())} or 'all'")
                sys.exit(1)
            importer = importers[key]
            print(f"\n[*] Running importer for: {key.upper()}")
            summary = importer.import_dataset(db=db)
            print(json.dumps(summary.model_dump(), indent=2))
            return [summary]
    finally:
        db.close()


def print_stats():
    init_db()
    db = SessionLocal()
    try:
        datasets = db.query(Dataset).all()
        print("\n=== DATASET INVENTORY ===")
        if not datasets:
            print("No datasets found in database.")
            return

        for d in datasets:
            count = db.query(Record).filter(Record.dataset_id == d.id).count()
            print(f"\nDataset: {d.name} (ID: {d.id})")
            print(f"  Source: {d.source}")
            print(f"  Total Records: {count}")

            # Breakdown by label
            labels = db.query(Record.label).filter(Record.dataset_id == d.id).all()
            label_counts = {}
            for (l,) in labels:
                label_counts[l] = label_counts.get(l, 0) + 1
            print(f"  By Label: {label_counts}")

            # Breakdown by source_type
            srcs = db.query(Record.source_type).filter(Record.dataset_id == d.id).all()
            src_counts = {}
            for (s,) in srcs:
                src_counts[s] = src_counts.get(s, 0) + 1
            print(f"  By Source: {src_counts}")
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="LLM Security Research Dataset CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Import command
    import_parser = subparsers.add_parser("import", help="Run dataset ingestion")
    import_parser.add_argument(
        "--dataset",
        "-d",
        required=True,
        help="Dataset name: bipia, pdf_injection, pdf_malware, or all"
    )

    # Stats command
    subparsers.add_parser("stats", help="Show current dataset and record counts")

    # Init DB command
    subparsers.add_parser("init-db", help="Initialize database schema tables")

    # Export CSV command
    subparsers.add_parser("export-csv", help="Export all normalized records to CSV files")

    args = parser.parse_args()

    if args.command == "import":
        run_import(args.dataset)
    elif args.command == "stats":
        print_stats()
    elif args.command == "init-db":
        init_db()
        print("Database initialized successfully.")
    elif args.command == "export-csv":
        from backend.export_csv import export_all_records_to_csv
        export_all_records_to_csv()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
