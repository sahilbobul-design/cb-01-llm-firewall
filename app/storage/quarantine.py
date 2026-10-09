import os
import uuid
import stat
import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator
from app.config import settings

logger = logging.getLogger(__name__)


class QuarantineError(Exception):
    pass


class QuarantineManager:
    """
    Manages isolated, temporary file storage for untrusted uploads before scanning.

    SECURITY GUARANTEES:
    - Randomly generated UUID filenames (no user-controlled paths or names).
    - Path traversal is physically impossible because destination is fixed.
    - Strict file size limit validation.
    - Files are stored with non-executable, owner-only permissions (0600 on Linux/POSIX).
    - Automatic cleanup via context manager guarantee.
    - Never executes quarantined files.
    """

    def __init__(self, quarantine_dir: Path = settings.QUARANTINE_DIR):
        self.quarantine_dir = quarantine_dir
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        # On POSIX systems, ensure quarantine directory is 0700
        if os.name != "nt":
            try:
                os.chmod(self.quarantine_dir, 0o700)
            except Exception:
                pass

    @contextmanager
    def isolate(
        self,
        file_bytes: bytes,
        original_filename: str = "untrusted_upload"
    ) -> Generator[Path, None, None]:
        max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
        if len(file_bytes) > max_bytes:
            raise QuarantineError(
                f"File size {len(file_bytes)} bytes exceeds maximum allowed limit of {settings.MAX_FILE_SIZE_MB}MB."
            )

        # Generate completely random isolated name, completely ignoring user filename
        random_name = f"quarantine_{uuid.uuid4().hex}.bin"
        isolated_path = self.quarantine_dir / random_name

        try:
            # Write bytes safely
            isolated_path.write_bytes(file_bytes)

            # Restrict permissions: read/write only by current owner, strictly NO execute (0600)
            if os.name != "nt":
                try:
                    os.chmod(isolated_path, stat.S_IRUSR | stat.S_IWUSR)
                except Exception as perm_err:
                    logger.warning(f"Could not restrict POSIX permissions on {isolated_path}: {perm_err}")

            yield isolated_path

        finally:
            # Automatic Cleanup Guarantee
            if isolated_path.exists():
                try:
                    isolated_path.unlink()
                except Exception as cleanup_err:
                    logger.error(f"Failed to cleanup quarantined file {isolated_path}: {cleanup_err}")


quarantine = QuarantineManager()
