from abc import ABC, abstractmethod
from typing import Any, Dict


class SecurityTool(ABC):
    """
    Standard interface for all cybersecurity scanning adapters.
    Every tool must implement scan() and health().
    """

    name: str = "unknown"

    @abstractmethod
    async def scan(self, target: Any) -> Dict[str, Any]:
        """
        Execute safety scan on validated target.
        Must return structured JSON dictionary.
        """
        pass

    @abstractmethod
    async def health(self) -> Dict[str, Any]:
        """
        Check health and availability of the underlying security scanner.
        """
        pass
