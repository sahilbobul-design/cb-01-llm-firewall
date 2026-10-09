from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.config import settings
from app.database.database import get_db
from app.security_tools.registry import tool_registry

router = APIRouter(tags=["Health & Status"])


@router.get("/health")
def api_health(db: Session = Depends(get_db)):
    """Health check verifying database connectivity and gateway uptime."""
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"disconnected: {e}"

    return {
        "status": "healthy" if "disconnected" not in db_status else "degraded",
        "database": db_status,
        "environment": settings.ENVIRONMENT,
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/api/v1/security/health")
async def security_tools_health():
    """Returns the operational health and availability of all security scanning tools."""
    tools_health = await tool_registry.get_all_tools_health()
    return {
        "gateway_status": "ONLINE",
        "linux_security_enabled": settings.LINUX_SECURITY_ENABLED,
        "tools": tools_health,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
