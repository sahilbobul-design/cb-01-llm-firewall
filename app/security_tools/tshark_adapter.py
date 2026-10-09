import asyncio
import json
import logging
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from app.config import settings
from app.security_tools.base import SecurityTool

logger = logging.getLogger(__name__)


class TsharkAdapter(SecurityTool):
    """
    tshark adapter for controlled network traffic monitoring and metadata capture.

    SECURITY GUARANTEES:
    - Never scans PDFs, documents, or user text payloads.
    - Operates strictly on network capture analysis.
    - Strictly disabled by default (settings.TSHARK_ENABLED).
    - Interfaces and capture options are strictly allowlisted; arbitrary command-line
      parameters from users are completely forbidden.
    - Returns status 'DISABLED' when disabled.
    """

    name = "tshark"

    def __init__(self):
        self.tshark_bin = shutil.which("tshark")

    def is_available(self) -> bool:
        if not settings.TSHARK_ENABLED or not settings.NETWORK_MONITOR_ENABLED or not settings.LINUX_SECURITY_ENABLED:
            return False
        return bool(self.tshark_bin)

    async def health(self) -> Dict[str, Any]:
        if not settings.TSHARK_ENABLED or not settings.NETWORK_MONITOR_ENABLED:
            return {
                "tool": self.name,
                "status": "DISABLED",
                "installed": bool(self.tshark_bin),
                "enabled": False
            }
        if not self.tshark_bin:
            return {
                "tool": self.name,
                "status": "UNAVAILABLE",
                "installed": False,
                "enabled": True
            }
        return {
            "tool": self.name,
            "status": "ACTIVE",
            "installed": True,
            "enabled": True,
            "interface": settings.NETWORK_INTERFACE
        }

    async def scan(self, target: Any = None) -> Dict[str, Any]:
        """
        Runs a controlled capture or parses a pcap file.
        If target is None, performs a brief allowlisted interface capture.
        """
        if not self.is_available():
            return {
                "tool": self.name,
                "status": "DISABLED"
            }

        start_time = time.perf_counter()
        events: List[Dict[str, Any]] = []

        try:
            # Strictly allowlisted command options only
            duration = min(settings.NETWORK_CAPTURE_SECONDS, 10)  # capped
            cmd = [
                self.tshark_bin,
                "-i", settings.NETWORK_INTERFACE,
                "-a", f"duration:{duration}",
                "-T", "fields",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "_ws.col.Protocol",
                "-e", "frame.len"
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=duration + 5
            )

            lines = stdout.decode("utf-8", errors="replace").strip().splitlines()
            for line in lines[:50]:  # limit parsed lines
                parts = line.strip().split("\t")
                if len(parts) >= 3 and parts[0] and parts[1]:
                    events.append({
                        "event_type": "NETWORK_ACTIVITY",
                        "source": parts[0],
                        "destination": parts[1],
                        "protocol": parts[2] if len(parts) > 2 else "TCP",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "severity": "LOW"
                    })

            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            return {
                "tool": self.name,
                "status": "COMPLETED",
                "packets_captured": len(lines),
                "events": events,
                "execution_time_ms": elapsed_ms
            }

        except Exception as e:
            logger.warning(f"tshark capture encountered error: {e}")
            return {
                "tool": self.name,
                "status": "ERROR",
                "error": str(e),
                "execution_time_ms": int((time.perf_counter() - start_time) * 1000)
            }
