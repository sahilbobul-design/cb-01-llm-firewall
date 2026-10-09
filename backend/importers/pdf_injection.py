import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.config import settings
from backend.importers.base import DatasetImporter
from backend.processors.pdf import extract_pdf_data
from backend.schemas import AttackType, CommonRecordSchema, RecordLabel, SourceType

logger = logging.getLogger(__name__)


class PDFInjectionImporter(DatasetImporter):
    """
    Importer for PDF Prompt Injection Synthetic Datasets.
    Processes:
    - Benign PDF samples -> label: benign, attack_type: null
    - Prompt-injected PDF samples -> label: prompt_injection, attack_type: pdf_prompt_injection
    """

    def __init__(self):
        super().__init__(
            dataset_name="PDF_INJECTION",
            source="Synthetic PDF Injection Benchmark",
            description=(
                "Synthetic and collected PDF documents containing benign documents "
                "alongside documents with embedded indirect and direct prompt injections."
            ),
            processed_subdir="pdf_injection"
        )

    def get_default_raw_path(self) -> Path:
        return settings.RAW_DIR / "pdf_injection"

    def _determine_label_and_attack(self, file_path: Path, meta_dict: Optional[Dict[str, Any]] = None) -> Tuple[RecordLabel, Optional[str]]:
        if meta_dict:
            lbl = meta_dict.get("label")
            if lbl in ["prompt_injection", "injected", "attack", 1, "1", True]:
                return RecordLabel.PROMPT_INJECTION, AttackType.PDF_PROMPT_INJECTION.value
            elif lbl in ["benign", "clean", 0, "0", False]:
                return RecordLabel.BENIGN, None

        # Infer from path and filename
        path_lower = str(file_path).lower()
        if any(term in path_lower for term in ["inject", "attack", "poison", "malicious_prompt", "payload"]):
            return RecordLabel.PROMPT_INJECTION, AttackType.PDF_PROMPT_INJECTION.value

        return RecordLabel.BENIGN, None

    def read_and_normalize(
        self, raw_path: Path
    ) -> List[Tuple[Optional[CommonRecordSchema], Optional[str]]]:
        results: List[Tuple[Optional[CommonRecordSchema], Optional[str]]] = []

        if not raw_path.exists():
            return [(None, f"Path does not exist: {raw_path}")]

        # Look for companion metadata manifest if exists (e.g., manifest.json or metadata.json)
        metadata_map: Dict[str, Dict[str, Any]] = {}
        manifest_files = list(raw_path.glob("*.json")) + list(raw_path.glob("manifest*.json"))
        for mf in manifest_files:
            try:
                data = json.loads(mf.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for entry in data:
                        fname = entry.get("file_name") or entry.get("filename")
                        if fname:
                            metadata_map[fname] = entry
                elif isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, dict):
                            metadata_map[k] = v
            except Exception as e:
                logger.warning(f"Failed parsing companion manifest {mf.name}: {e}")

        # Collect all PDF files
        pdf_files: List[Path] = []
        if raw_path.is_file() and raw_path.suffix.lower() == ".pdf":
            pdf_files = [raw_path]
        else:
            pdf_files = [p for p in raw_path.rglob("*.pdf") if p.is_file()]

        for pdf_file in pdf_files:
            try:
                extracted = extract_pdf_data(file_path=pdf_file)
                companion_meta = metadata_map.get(pdf_file.name, {})

                label, attack_type = self._determine_label_and_attack(pdf_file, companion_meta)

                # Merge extraction metadata with any dataset metadata
                combined_metadata = {
                    **extracted["metadata"],
                    **companion_meta,
                    "source_path": str(pdf_file.relative_to(settings.DATASET_DIR) if settings.DATASET_DIR in pdf_file.parents else pdf_file.name)
                }

                # Ensure extracted content is non-empty or meaningful placeholder if blank document
                content = extracted["content"]
                if not content:
                    content = f"[PDF Document with no extractable plain text. Filename: {pdf_file.name}]"

                schema = CommonRecordSchema(
                    dataset=self.dataset_name,
                    source_type=SourceType.PDF,
                    content=content,
                    label=label,
                    attack_type=attack_type,
                    file_name=pdf_file.name,
                    file_hash=extracted["file_hash"],
                    metadata=combined_metadata
                )
                results.append((schema, None))
            except Exception as e:
                results.append((None, f"Error processing PDF {pdf_file.name}: {e}"))

        return results
