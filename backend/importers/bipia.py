import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.config import settings
from backend.importers.base import DatasetImporter
from backend.processors.email import extract_email_data
from backend.processors.pdf import sanitize_text
from backend.processors.webpage import extract_webpage_data
from backend.schemas import AttackType, CommonRecordSchema, RecordLabel, SourceType

logger = logging.getLogger(__name__)


class BIPIAImporter(DatasetImporter):
    """
    Importer for Microsoft BIPIA (Benchmark for Indirect Prompt Injection Attacks).
    Processes:
    - Email QA / Email prompt injection data (source_type: email)
    - Web QA / Webpage prompt injection data (source_type: webpage)
    """

    def __init__(self):
        super().__init__(
            dataset_name="BIPIA",
            source="Microsoft BIPIA (Benchmark for Indirect Prompt Injection Attacks)",
            description=(
                "Evaluation suite for Indirect Prompt Injection attacks spanning "
                "Email QA and Webpage QA tasks, with benign and poisoned contexts."
            ),
            processed_subdir="email"
        )

    def get_default_raw_path(self) -> Path:
        return settings.RAW_DIR

    def _determine_source_type(self, item: Dict[str, Any], file_path: Path) -> SourceType:
        """Infers source_type from item dictionary, directory structure, or file suffix."""
        st = item.get("source_type") or item.get("data_type") or item.get("type")
        if st:
            st_str = str(st).lower()
            if "web" in st_str or "html" in st_str:
                return SourceType.WEBPAGE
            if "email" in st_str or "mail" in st_str:
                return SourceType.EMAIL

        # Check directory names
        parts = [p.lower() for p in file_path.parts]
        if "webpage" in parts or "web" in parts:
            return SourceType.WEBPAGE
        if "email" in parts or "mail" in parts:
            return SourceType.EMAIL

        # Check file extension
        if file_path.suffix.lower() in {".htm", ".html"}:
            return SourceType.WEBPAGE
        if file_path.suffix.lower() in {".eml", ".msg"}:
            return SourceType.EMAIL

        # Default fallback for BIPIA is email if context looks like email, else webpage
        return SourceType.EMAIL

    def _determine_label_and_attack(self, item: Dict[str, Any]) -> Tuple[RecordLabel, Optional[str]]:
        raw_label = item.get("label")
        raw_attack = item.get("attack_type")

        # Normalize label
        is_attack = False
        if raw_label in [1, "1", True, "prompt_injection", "attack", "injected", "malicious", "poisoned"]:
            is_attack = True
        elif raw_label in [0, "0", False, "benign", "clean"]:
            is_attack = False
        elif item.get("is_injected") or item.get("injected_prompt") or item.get("attack_instruction"):
            is_attack = True

        if is_attack:
            label = RecordLabel.PROMPT_INJECTION
            # Indirect prompt injection is default for BIPIA
            attack_type = raw_attack or AttackType.INDIRECT_PROMPT_INJECTION.value
            if attack_type not in {"direct_prompt_injection", "indirect_prompt_injection"}:
                attack_type = AttackType.INDIRECT_PROMPT_INJECTION.value
        else:
            label = RecordLabel.BENIGN
            attack_type = None

        return label, attack_type

    def read_and_normalize(
        self, raw_path: Path
    ) -> List[Tuple[Optional[CommonRecordSchema], Optional[str]]]:
        results: List[Tuple[Optional[CommonRecordSchema], Optional[str]]] = []

        # Find target paths to scan
        paths_to_scan = []
        if raw_path.is_file():
            paths_to_scan = [raw_path]
        else:
            email_dir = raw_path / "email"
            web_dir = raw_path / "webpage"
            bipia_dir = raw_path / "bipia"

            for candidate in [email_dir, web_dir, bipia_dir, raw_path]:
                if candidate.exists() and candidate.is_dir():
                    for p in candidate.rglob("*"):
                        if p.is_file() and p.suffix.lower() in {".json", ".jsonl", ".eml", ".html", ".htm", ".txt"}:
                            paths_to_scan.append(p)

        paths_to_scan = list(set(paths_to_scan))

        for file_path in paths_to_scan:
            suffix = file_path.suffix.lower()

            # 1. Raw .eml file
            if suffix == ".eml":
                try:
                    extracted = extract_email_data(file_path=file_path)
                    content = extracted["content"]
                    label = RecordLabel.BENIGN
                    attack = None
                    if "inject" in file_path.name.lower() or "attack" in file_path.name.lower():
                        label = RecordLabel.PROMPT_INJECTION
                        attack = AttackType.INDIRECT_PROMPT_INJECTION.value

                    schema = CommonRecordSchema(
                        dataset=self.dataset_name,
                        source_type=SourceType.EMAIL,
                        content=content,
                        label=label,
                        attack_type=attack,
                        file_name=file_path.name,
                        file_hash=extracted["file_hash"],
                        metadata=extracted["metadata"]
                    )
                    results.append((schema, None))
                except Exception as e:
                    results.append((None, f"Failed parsing email {file_path.name}: {e}"))
                continue

            # 2. Raw .html file
            if suffix in {".html", ".htm"}:
                try:
                    extracted = extract_webpage_data(file_path=file_path)
                    content = extracted["content"]
                    label = RecordLabel.BENIGN
                    attack = None
                    if "inject" in file_path.name.lower() or "attack" in file_path.name.lower():
                        label = RecordLabel.PROMPT_INJECTION
                        attack = AttackType.INDIRECT_PROMPT_INJECTION.value

                    schema = CommonRecordSchema(
                        dataset=self.dataset_name,
                        source_type=SourceType.WEBPAGE,
                        content=content,
                        label=label,
                        attack_type=attack,
                        file_name=file_path.name,
                        file_hash=extracted["file_hash"],
                        metadata=extracted["metadata"]
                    )
                    results.append((schema, None))
                except Exception as e:
                    results.append((None, f"Failed parsing HTML {file_path.name}: {e}"))
                continue

            # 3. JSON or JSONL file
            if suffix in {".json", ".jsonl"}:
                try:
                    raw_text = file_path.read_text(encoding="utf-8", errors="replace")
                    raw_items = []
                    if suffix == ".jsonl":
                        for line in raw_text.splitlines():
                            line = line.strip()
                            if line:
                                raw_items.append(json.loads(line))
                    else:
                        parsed = json.loads(raw_text)
                        if isinstance(parsed, list):
                            raw_items = parsed
                        elif isinstance(parsed, dict):
                            if "data" in parsed and isinstance(parsed["data"], list):
                                raw_items = parsed["data"]
                            elif "records" in parsed and isinstance(parsed["records"], list):
                                raw_items = parsed["records"]
                            else:
                                raw_items = [parsed]

                    for item_idx, item in enumerate(raw_items):
                        try:
                            # Extract textual content
                            content = (
                                item.get("content") or
                                item.get("text") or
                                item.get("context") or
                                item.get("email_body") or
                                item.get("web_text") or
                                item.get("prompt") or
                                ""
                            )
                            content = sanitize_text(str(content))
                            if not content:
                                results.append((None, f"Empty content in {file_path.name} item {item_idx}"))
                                continue

                            src_type = self._determine_source_type(item, file_path)
                            label, attack_type = self._determine_label_and_attack(item)

                            # Retain any extra fields in metadata safely
                            metadata = {
                                "original_id": str(item.get("id") or f"{file_path.stem}_{item_idx}"),
                                "task": item.get("task", "qa"),
                                "question": item.get("question") or item.get("user_prompt"),
                                "injected_instruction": item.get("injected_prompt") or item.get("attack_instruction"),
                                "source_file": file_path.name
                            }

                            schema = CommonRecordSchema(
                                id=str(item.get("uuid")) if item.get("uuid") else None,
                                dataset=self.dataset_name,
                                source_type=src_type,
                                content=content,
                                label=label,
                                attack_type=attack_type,
                                file_name=file_path.name,
                                file_hash=item.get("file_hash"),
                                metadata=metadata
                            )
                            results.append((schema, None))
                        except Exception as item_err:
                            results.append((None, f"Validation error in {file_path.name} item {item_idx}: {item_err}"))

                except Exception as file_err:
                    results.append((None, f"Error reading {file_path.name}: {file_err}"))

        return results
