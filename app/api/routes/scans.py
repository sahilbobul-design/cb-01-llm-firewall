from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import SecurityEvent, ToolResult
from app.security.orchestrator import security_orchestrator
from backend.models import Record

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


class TextScanRequest(BaseModel):
    prompt: Optional[str] = Field(None, description="Raw text prompt or email content to scan")
    source_type: str = Field("text", description="Source type: text, email, webpage, pdf")
    record_id: Optional[str] = Field(None, description="Optional ID of existing dataset record to scan")


class OutputScanRequest(BaseModel):
    output_text: str = Field(..., description="LLM generated output text to scan for sensitive leakage")


@router.post("")
async def scan_request(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Main Security Scan Endpoint (POST /api/v1/scans).
    
    Accepts:
    1. Text prompt payload via JSON
    2. File upload via multipart/form-data (PDF, HTML, EML, etc.)
    3. Reference to an existing dataset record ID
    
    Orchestration:
    - Quarantines and hashes uploaded files
    - Executes YARA + ClamAV on files
    - Executes Rule Detection (Prompt Injections, Secrets, PII, IPs)
    - Runs Risk Engine (0-100) -> SAFE / SUSPICIOUS / BLOCKED
    - Applies Sanitization and logs to database
    """
    content_type = request.headers.get("content-type", "")
    file_bytes = None
    filename = None
    text_content = None
    source_type = "text"

    if "multipart/form-data" in content_type:
        form = await request.form()
        uploaded_file = form.get("file")
        if uploaded_file and hasattr(uploaded_file, "read"):
            file_bytes = await uploaded_file.read()
            filename = getattr(uploaded_file, "filename", "uploaded_file.bin")
            source_type = "pdf" if filename.lower().endswith(".pdf") else ("email" if filename.lower().endswith(".eml") else "file")
        if form.get("prompt"):
            text_content = str(form.get("prompt"))
        if form.get("source_type"):
            source_type = str(form.get("source_type"))
        record_id = form.get("record_id")
        if record_id:
            record = db.query(Record).filter(Record.id == record_id).first()
            if not record:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Record '{record_id}' not found in database."
                )
            text_content = record.content
            source_type = record.source_type
            filename = record.file_name
    else:
        # JSON body or raw text payload
        try:
            body = await request.json()
        except Exception:
            body = {}
        
        record_id = body.get("record_id")
        if record_id:
            record = db.query(Record).filter(Record.id == record_id).first()
            if not record:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Record '{record_id}' not found in database."
                )
            text_content = record.content
            source_type = record.source_type
            filename = record.file_name
        else:
            text_content = body.get("prompt")
            source_type = body.get("source_type", "text")

    if not file_bytes and not text_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either a prompt payload or a file upload must be provided."
        )

    result = await security_orchestrator.scan_payload(
        text_content=text_content,
        file_bytes=file_bytes,
        filename=filename,
        source_type=source_type,
        db=db
    )

    return result


@router.post("/output")
async def scan_output_firewall(
    payload: OutputScanRequest,
    db: Session = Depends(get_db)
):
    """
    Output Firewall Endpoint (Section 19).
    Scans LLM-generated output for sensitive leakage (secrets, API keys, system prompt leaks).
    """
    return await security_orchestrator.scan_llm_output(payload.output_text, db=db)


@router.get("/events")
def list_security_events(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """List recent security events and detected threat markers."""
    events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    return [
        {
            "id": e.id,
            "scan_id": e.scan_id,
            "layer": e.layer,
            "event_type": e.event_type,
            "severity": e.severity,
            "description": e.description,
            "created_at": e.created_at.isoformat()
        }
        for e in events
    ]


@router.get("/tools-results")
def list_tool_results(
    limit: int = 50,
    db: Session = Depends(get_db)
):
    """List recent Linux tool scan results and execution times."""
    results = db.query(ToolResult).order_by(ToolResult.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "scan_id": r.scan_id,
            "tool_name": r.tool_name,
            "status": r.status,
            "severity": r.severity,
            "detected": r.detected,
            "execution_time_ms": r.execution_time_ms,
            "created_at": r.created_at.isoformat()
        }
        for r in results
    ]
