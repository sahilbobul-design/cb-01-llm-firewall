import abc
from pathlib import Path
from typing import Optional
from security_engine.schemas import ScannerResult


class BaseScanner(abc.ABC):
    """Abstract interface for modular threat scanners."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Scanner identification name."""
        pass

    @abc.abstractmethod
    def scan_text(self, text: str, context: Optional[str] = None) -> ScannerResult:
        """Scan textual input for threats."""
        pass

    @abc.abstractmethod
    def scan_file(self, file_path: Optional[Path] = None, file_bytes: Optional[bytes] = None) -> ScannerResult:
        """Scan raw binary or file payload for threats."""
        pass
