from typing import Any, Dict


class JevAdapter:
    """
    Placeholder interface for Jev classifier.
    
    IMPORTANT:
    Per project specifications, no unofficial endpoints, keys, model names,
    or SDK methods are invented. Raises NotImplementedError until official
    Jev interface specifications are confirmed.
    """

    name = "jev"

    async def classify(self, content: Any):
        raise NotImplementedError("Official Jev interface is not yet configured.")

    async def health(self) -> Dict[str, Any]:
        return {
            "tool": self.name,
            "status": "UNAVAILABLE",
            "installed": False,
            "enabled": False,
            "note": "Awaiting official Jev integration specification"
        }
