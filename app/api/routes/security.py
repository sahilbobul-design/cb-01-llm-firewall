from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import SecurityEvent, ToolResult
from app.security_tools.registry import tool_registry

router = APIRouter(prefix="/api/v1/security", tags=["Security Gateway"])


@router.get("/tools")
async def get_security_tools_status():
    """
    Returns installation and enabled status of all Linux cybersecurity tools.
    Strictly follows the required schema:
    {
      "yara": { "installed": bool, "enabled": bool },
      "clamav": { "installed": bool, "enabled": bool },
      "tshark": { "installed": bool, "enabled": bool }
    }
    """
    return await tool_registry.get_tools_summary()


@router.get("/dashboard")
async def get_security_dashboard_data(db: Session = Depends(get_db)):
    """
    Provides aggregated metrics and latest scan status for the frontend
    security dashboard (Section 27).
    """
    tools_summary = await tool_registry.get_tools_summary()

    # Query latest scan event from database
    latest_event = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).first()
    latest_tool = db.query(ToolResult).order_by(ToolResult.created_at.desc()).first()

    latest_scan_id = latest_event.scan_id if latest_event else (latest_tool.scan_id if latest_tool else None)

    latest_scan_data = {
        "scan_id": latest_scan_id,
        "available": bool(latest_scan_id),
        "recent_events_count": db.query(SecurityEvent).count(),
        "recent_tools_scanned_count": db.query(ToolResult).count()
    }

    # Format tools display states
    display_tools = {
        "YARA": "ACTIVE" if (tools_summary["yara"]["installed"] and tools_summary["yara"]["enabled"]) else ("DISABLED" if not tools_summary["yara"]["enabled"] else "UNAVAILABLE"),
        "ClamAV": "ACTIVE" if (tools_summary["clamav"]["installed"] and tools_summary["clamav"]["enabled"]) else ("DISABLED" if not tools_summary["clamav"]["enabled"] else "UNAVAILABLE"),
        "tshark": "ACTIVE" if (tools_summary["tshark"]["installed"] and tools_summary["tshark"]["enabled"]) else "DISABLED",
        "Jev": "PENDING"
    }

    return {
        "security_tools": display_tools,
        "tools_detailed": tools_summary,
        "latest_scan": latest_scan_data
    }
