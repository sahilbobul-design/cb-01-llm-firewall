import logging
from typing import Any, Dict
from app.security_tools.clamav_adapter import ClamAVAdapter
from app.security_tools.jev_adapter import JevAdapter
from app.security_tools.tshark_adapter import TsharkAdapter
from app.security_tools.yara_adapter import YaraAdapter

logger = logging.getLogger(__name__)


class SecurityToolRegistry:
    """Registry managing modular security tool instances and health checks."""

    def __init__(self):
        self.yara = YaraAdapter()
        self.clamav = ClamAVAdapter()
        self.tshark = TsharkAdapter()
        self.jev = JevAdapter()

    async def get_all_tools_health(self) -> Dict[str, Any]:
        """Returns availability and health status for each tool."""
        yara_h = await self.yara.health()
        clamav_h = await self.clamav.health()
        tshark_h = await self.tshark.health()
        jev_h = await self.jev.health()

        return {
            "yara": yara_h,
            "clamav": clamav_h,
            "tshark": tshark_h,
            "jev": jev_h
        }

    async def get_tools_summary(self) -> Dict[str, Any]:
        """Provides the format required by GET /api/v1/security/tools."""
        yara_h = await self.yara.health()
        clamav_h = await self.clamav.health()
        tshark_h = await self.tshark.health()

        return {
            "yara": {
                "installed": yara_h.get("installed", False),
                "enabled": yara_h.get("enabled", False)
            },
            "clamav": {
                "installed": clamav_h.get("installed", False),
                "enabled": clamav_h.get("enabled", False)
            },
            "tshark": {
                "installed": tshark_h.get("installed", False),
                "enabled": tshark_h.get("enabled", False)
            }
        }


tool_registry = SecurityToolRegistry()
