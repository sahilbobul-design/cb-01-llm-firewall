import hashlib
import mimetypes
from pathlib import Path
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel


class FileHashInfo(BaseModel):
    file_hash: str
    file_size: int
    mime_type: str
    filename: Optional[str] = None


def compute_file_hash_info(
    file_bytes: bytes,
    original_filename: Optional[str] = None
) -> FileHashInfo:
    """
    Computes SHA-256, byte size, and detected MIME type.
    SECURITY GUARANTEE:
    The original_filename is treated purely as metadata and NEVER becomes
    the filesystem path.
    """
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)

    # Detect MIME type from header magic bytes or filename extension safely
    mime_type = "application/octet-stream"
    if file_bytes.startswith(b"%PDF-"):
        mime_type = "application/pdf"
    elif file_bytes.startswith(b"<!DOCTYPE html") or file_bytes.startswith(b"<html"):
        mime_type = "text/html"
    elif b"From:" in file_bytes[:100] and b"Subject:" in file_bytes[:500]:
        mime_type = "message/rfc822"
    elif original_filename:
        guessed, _ = mimetypes.guess_type(original_filename)
        if guessed:
            mime_type = guessed

    return FileHashInfo(
        file_hash=sha256_hash,
        file_size=file_size,
        mime_type=mime_type,
        filename=original_filename
    )
