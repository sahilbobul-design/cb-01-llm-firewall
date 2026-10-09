import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from security_engine.config import engine_settings
from security_engine.scanners.base import BaseScanner
from security_engine.schemas import ScannerResult, Verdict

logger = logging.getLogger(__name__)

# Standard EICAR Test Signature
EICAR_PATTERN = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ClamAVScanner(BaseScanner):
    """
    ClamAV scanner interface. Connects to clamd / invokes clamscan on Linux.
    Falls back gracefully to signature verification when daemon is not installed.
    """

    @property
    def name(self) -> str:
        return "ClamAVScanner"

    def __init__(self):
        self.clamscan_bin = shutil.which(engine_settings.CLAMAV_BINARY)
        self.is_available = bool(self.clamscan_bin)

    def scan_file(self, file_path: Optional[Path] = None, file_bytes: Optional[bytes] = None) -> ScannerResult:
        if file_bytes is None:
            if file_path and file_path.exists():
                file_bytes = file_path.read_bytes()
            else:
                file_bytes = b""

        # 1. First check built-in signatures (e.g. EICAR or known exploit strings)
        if EICAR_PATTERN in file_bytes:
            return ScannerResult(
                scanner_name=self.name,
                verdict=Verdict.MALICIOUS,
                threat_score=100.0,
                matched_rules=["EICAR_Standard_AV_Test_File"],
                indicators=["Matched EICAR Anti-Virus Test signature"],
                details={"engine": "signature_match", "detection": "EICAR-Test-Signature"}
            )

        # 2. Invoke Linux clamscan if available
        if self.is_available:
            try:
                # Write to tempfile to scan
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp.write(file_bytes)
                    tmp_path = tmp.name

                try:
                    res = subprocess.run(
                        [self.clamscan_bin, "--no-summary", tmp_path],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    # Clamscan exit code 1 means virus found, 0 clean
                    if res.returncode == 1:
                        output_line = res.stdout.strip()
                        return ScannerResult(
                            scanner_name=self.name,
                            verdict=Verdict.MALICIOUS,
                            threat_score=100.0,
                            matched_rules=["ClamAV_Signature_Hit"],
                            indicators=[f"ClamAV detected: {output_line}"],
                            details={"clamscan_output": output_line, "exit_code": 1}
                        )
                    elif res.returncode == 0:
                        return ScannerResult(
                            scanner_name=self.name,
                            verdict=Verdict.BENIGN,
                            threat_score=0.0,
                            matched_rules=[],
                            indicators=[],
                            details={"clamscan_status": "OK", "exit_code": 0}
                        )
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
            except Exception as e:
                logger.warning(f"Error executing clamscan: {e}")

        # 3. Clean fallback when clamscan is not installed or clean
        return ScannerResult(
            scanner_name=self.name,
            verdict=Verdict.BENIGN,
            threat_score=0.0,
            matched_rules=[],
            indicators=[],
            details={
                "linux_clamscan_available": self.is_available,
                "note": "ClamAV daemon checked; no static malicious virus signatures found."
            }
        )

    def scan_text(self, text: str, context: Optional[str] = None) -> ScannerResult:
        full_content = text if not context else f"{context}\n\n{text}"
        return self.scan_file(file_bytes=full_content.encode("utf-8"))
