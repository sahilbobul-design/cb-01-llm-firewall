import hashlib
import io
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Union
import pypdf

logger = logging.getLogger(__name__)


def sanitize_text(text: Optional[str]) -> str:
    """Strips null characters and normalizes whitespace for safe database storage."""
    if not text:
        return ""
    # PostgreSQL cannot store NUL (0x00) characters in text columns
    sanitized = text.replace("\x00", "")
    return sanitized.strip()


def extract_pdf_data(
    file_path: Optional[Union[str, Path]] = None,
    file_bytes: Optional[bytes] = None,
    file_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Safely extract readable text, SHA-256 hash, and structural metadata from a PDF file.

    SECURITY GUARANTEES:
    - Pure python static parsing via pypdf.
    - Embedded files are NOT extracted or executed.
    - PDF JavaScript (/JS, /JavaScript) is detected for metadata only and NEVER executed.
    - External links (/URI, /Launch) are NOT resolved or followed.
    """
    if file_bytes is None:
        if file_path is None:
            raise ValueError("Either file_path or file_bytes must be provided.")
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"PDF file not found: {path}")
        file_bytes = path.read_bytes()
        if file_name is None:
            file_name = path.name

    # 1. Compute deterministic SHA-256 hash of the raw bytes
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)

    extracted_pages = []
    pdf_info = {}
    page_count = 0
    has_javascript = False
    has_embedded_files = False
    is_encrypted = False

    # Heuristic checks on raw bytes for active content (without executing)
    lower_bytes = file_bytes.lower()
    if b"/javascript" in lower_bytes or b"/js" in lower_bytes:
        has_javascript = True
    if b"/embeddedfiles" in lower_bytes or b"/embeddedfile" in lower_bytes or b"/ef" in lower_bytes:
        has_embedded_files = True

    try:
        reader = pypdf.PdfReader(io.BytesIO(file_bytes), strict=False)
        is_encrypted = reader.is_encrypted
        if is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                pass

        page_count = len(reader.pages)

        # Extract text page by page
        for page_idx, page in enumerate(reader.pages):
            try:
                page_text = page.extract_text()
                if page_text:
                    clean = sanitize_text(page_text)
                    if clean:
                        extracted_pages.append(clean)
            except Exception as page_err:
                logger.warning(f"Error extracting text from page {page_idx} of {file_name}: {page_err}")

        # Extract document metadata
        if reader.metadata:
            for k, v in reader.metadata.items():
                if v:
                    clean_k = str(k).replace("/", "").replace("\x00", "")
                    clean_v = str(v).replace("\x00", "")
                    pdf_info[clean_k] = clean_v

    except Exception as e:
        logger.warning(f"Failed to fully parse PDF structure for {file_name}: {e}")

    full_content = "\n\n".join(extracted_pages).strip()

    metadata = {
        "page_count": page_count,
        "file_size_bytes": file_size,
        "is_encrypted": is_encrypted,
        "has_javascript_markers": has_javascript,
        "has_embedded_file_markers": has_embedded_files,
        "pdf_info": pdf_info,
        "extraction_method": "pypdf_safe_parser"
    }

    return {
        "content": full_content,
        "file_hash": file_hash,
        "file_name": file_name,
        "metadata": metadata
    }
