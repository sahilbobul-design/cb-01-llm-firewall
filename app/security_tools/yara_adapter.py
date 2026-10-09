import asyncio
import logging
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from app.config import settings
from app.security_tools.base import SecurityTool

logger = logging.getLogger(__name__)


class YaraAdapter(SecurityTool):
    name = "yara"

    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or settings.RULES_DIR
        self.yara_bin = shutil.which("yara")
        # Also check python yara module if present
        self.has_python_yara = False
        try:
            import yara
            self.has_python_yara = True
            self.yara_module = yara
        except ImportError:
            self.yara_module = None

    def is_available(self) -> bool:
        if not settings.YARA_ENABLED or not settings.LINUX_SECURITY_ENABLED:
            return False
        return bool(self.yara_bin or self.has_python_yara)

    async def health(self) -> Dict[str, Any]:
        if not settings.YARA_ENABLED:
            return {"tool": self.name, "status": "DISABLED", "installed": bool(self.yara_bin or self.has_python_yara), "enabled": False}
        if not (self.yara_bin or self.has_python_yara):
            return {"tool": self.name, "status": "UNAVAILABLE", "installed": False, "enabled": True}
        return {
            "tool": self.name,
            "status": "ACTIVE",
            "installed": True,
            "enabled": True,
            "engine": "binary" if self.yara_bin else "python_yara"
        }

    async def scan(self, target: Union[str, Path]) -> Dict[str, Any]:
        """
        Safely scans a validated target file with YARA detection rules.
        SECURITY GUARANTEES:
        - Target path must exist and be validated.
        - Strict shell=False execution.
        - Strict timeout enforcement.
        - Gracefully returns UNAVAILABLE if not installed.
        """
        if not self.is_available():
            return {
                "tool": self.name,
                "status": "UNAVAILABLE"
            }

        target_path = Path(target).resolve()
        if not target_path.exists() or not target_path.is_file():
            return {
                "tool": self.name,
                "status": "ERROR",
                "error": f"Target path {target} does not exist or is not a regular file."
            }

        # Gather valid YARA rule files
        rule_files = list(self.rules_dir.glob("*.yar"))
        if not rule_files:
            return {
                "tool": self.name,
                "status": "COMPLETED",
                "detected": False,
                "matches": [],
                "execution_time_ms": 0,
                "note": "No .yar rule files found in rules directory."
            }

        start_time = time.perf_counter()
        matches: List[str] = []

        try:
            if self.yara_bin:
                # Prefer native Linux YARA binary
                # We compile/pass rule files one by one or concatenated
                for rule_file in rule_files:
                    cmd = [
                        self.yara_bin,
                        "-w",  # disable warnings
                        str(rule_file.resolve()),
                        str(target_path)
                    ]
                    # Run via asyncio subprocess without shell
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(
                            proc.communicate(),
                            timeout=settings.SCANNER_TIMEOUT_SECONDS
                        )
                        output = stdout.decode("utf-8", errors="replace").strip()
                        if output:
                            for line in output.splitlines():
                                parts = line.strip().split()
                                if parts:
                                    matches.append(parts[0])
                    except asyncio.TimeoutError:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        logger.warning(f"YARA scan timed out on {rule_file.name}")
            elif self.has_python_yara and self.yara_module:
                # Fallback to python-yara library
                filepaths = {rf.stem: str(rf.resolve()) for rf in rule_files}
                compiled = self.yara_module.compile(filepaths=filepaths)
                res = compiled.match(filepath=str(target_path))
                for m in res:
                    matches.append(m.rule)

            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            unique_matches = list(sorted(set(matches)))
            # Exclude benign control verification markers from threat detection
            threat_matches = [m for m in unique_matches if not m.lower().startswith("test_benign")]
            detected = len(threat_matches) > 0

            return {
                "tool": self.name,
                "status": "DETECTED" if detected else "COMPLETED",
                "detected": detected,
                "matches": threat_matches if detected else unique_matches,
                "execution_time_ms": elapsed_ms
            }

        except Exception as e:
            logger.error(f"Error during YARA scan: {e}")
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "tool": self.name,
                "status": "ERROR",
                "error": str(e),
                "execution_time_ms": elapsed_ms
            }
