import logging
from typing import Any, Dict, List
from app.config import settings
from app.security_tools.registry import tool_registry

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """
    Controlled network traffic analysis service.
    
    Guarantees:
    - Never blocks network traffic automatically in this analysis layer.
    - Operates via allowlisted tshark adapter only when explicitly enabled.
    - Emits structured security events.
    """

    def __init__(self):
        self.tshark = tool_registry.tshark

    async def capture_and_analyze(self) -> Dict[str, Any]:
        if not settings.NETWORK_MONITOR_ENABLED:
            return {
                "status": "DISABLED",
                "message": "Network monitoring is disabled (NETWORK_MONITOR_ENABLED=false)",
                "events": []
            }

        scan_result = await self.tshark.scan()
        events = scan_result.get("events", [])
        return {
            "status": scan_result.get("status", "COMPLETED"),
            "packets_captured": scan_result.get("packets_captured", 0),
            "events": events
        }


network_monitor = NetworkMonitor()
