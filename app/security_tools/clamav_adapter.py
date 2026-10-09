import asyncio
import logging
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Optional, Union
from app.config import settings
from app.security_tools.base import SecurityTool

logger = logging.getLogger(__name__)


class ClamAVAdapter(SecurityTool):
    name = "clamav"

    def __init__(self):
        # Look for clamscan as standard binary per prompt specification
        self.clamscan_bin = shutil.which("clamscan")
        self.clamdscan_bin = shutil.which("clamdscan")

    def _resolve_binary(self) -> Optional[str]:
        clamd_socket = Path("/run/clamav/clamd.ctl")
        clamd_socket_var = Path("/var/run/clamav/clamd.ctl")
        if self.clamdscan_bin and (clamd_socket.exists() or clamd_socket_var.exists()):
            return self.clamdscan_bin
        return self.clamscan_bin or self.clamdscan_bin

    def is_available(self) -> bool:
        if not settings.CLAMAV_ENABLED or not settings.LINUX_SECURITY_ENABLED:
            return False
        return bool(self._resolve_binary())

    async def health(self) -> Dict[str, Any]:
        if not settings.CLAMAV_ENABLED:
            return {"tool": self.name, "status": "DISABLED", "installed": bool(self.clamscan_bin or self.clamdscan_bin), "enabled": False}
        binary = self._resolve_binary()
        if not binary:
            return {"tool": self.name, "status": "UNAVAILABLE", "installed": False, "enabled": True}
        return {
            "tool": self.name,
            "status": "ACTIVE",
            "installed": True,
            "enabled": True,
            "binary": Path(binary).name
        }

    async def scan(self, target: Union[str, Path]) -> Dict[str, Any]:
        """
        Safely scans a quarantined target file for malware/viruses using clamscan / clamdscan.
        SECURITY GUARANTEES:
        - Target path must exist and be validated.
        - Strictly non-interactive shell=False execution.
        - Strict timeout.
        - Returns UNAVAILABLE if not installed.
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

        start_time = time.perf_counter()
        binary = self._resolve_binary()
        cmd = [binary, "--no-summary"]
        if binary and "clamdscan" in binary:
            cmd.append("--fdpass")
        cmd.append(str(target_path))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=settings.SCANNER_TIMEOUT_SECONDS
            )

            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            returncode = proc.returncode
            stdout_str = stdout.decode("utf-8", errors="replace").strip()

            # clamscan return codes:
            # 0 = No virus found (CLEAN)
            # 1 = Virus(es) found (INFECTED)
            # 2 = Some error(s) occurred
            if returncode == 0:
                return {
                    "tool": self.name,
                    "status": "CLEAN",
                    "infected": False,
                    "execution_time_ms": elapsed_ms
                }
            elif returncode == 1:
                # Extract detected signature name if available
                detected_virus = "Malware Detected"
                if "FOUND" in stdout_str:
                    for line in stdout_str.splitlines():
                        if "FOUND" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                detected_virus = parts[1].replace("FOUND", "").strip()
                return {
                    "tool": self.name,
                    "status": "INFECTED",
                    "infected": True,
                    "signature": detected_virus,
                    "execution_time_ms": elapsed_ms
                }
            else:
                stderr_str = stderr.decode("utf-8", errors="replace").strip()
                if self.binary != self.clamscan_bin and self.clamscan_bin:
                    logger.info("clamdscan socket unavailable, falling back to clamscan...")
                    self.binary = self.clamscan_bin
                    return await self.scan(target)
                return {
                    "tool": self.name,
                    "status": "ERROR",
                    "error": stderr_str or f"ClamAV returned exit code {returncode}",
                    "execution_time_ms": elapsed_ms
                }

        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {
                "tool": self.name,
                "status": "ERROR",
                "error": "Scan operation timed out",
                "execution_time_ms": int((time.perf_counter() - start_time) * 1000)
            }
        except Exception as e:
            logger.error(f"Error executing ClamAV: {e}")
            return {
                "tool": self.name,
                "status": "ERROR",
                "error": str(e),
                "execution_time_ms": int((time.perf_counter() - start_time) * 1000)
            }
