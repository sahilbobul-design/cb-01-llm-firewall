import email
import hashlib
import logging
from email import policy
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from backend.processors.pdf import sanitize_text
from backend.processors.webpage import extract_webpage_data

logger = logging.getLogger(__name__)


def extract_email_data(
    raw_content: Optional[Union[str, bytes]] = None,
    file_path: Optional[Union[str, Path]] = None,
    file_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Safely extract email subject, sender/recipient metadata, body text,
    and attachment descriptors from an RFC822/MIME email.

    SECURITY GUARANTEES:
    - Attachments are NOT saved or executed. Only their metadata and SHA-256 hashes are recorded.
    - HTML bodies are sanitized with scripts completely stripped.
    """
    if raw_content is None:
        if file_path is None:
            raise ValueError("Either raw_content or file_path must be provided.")
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Email file not found: {path}")
        raw_bytes = path.read_bytes()
        if file_name is None:
            file_name = path.name
    elif isinstance(raw_content, str):
        raw_bytes = raw_content.encode("utf-8")
    else:
        raw_bytes = raw_content

    file_hash = hashlib.sha256(raw_bytes).hexdigest()

    try:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as e:
        logger.warning(f"Error parsing email bytes: {e}")
        text = raw_bytes.decode("utf-8", errors="replace")
        return {
            "content": sanitize_text(text),
            "file_hash": file_hash,
            "file_name": file_name,
            "metadata": {
                "error": str(e),
                "extraction_method": "raw_email_fallback"
            }
        }

    # Extract headers
    subject = sanitize_text(str(msg.get("subject", "")))
    sender = sanitize_text(str(msg.get("from", "")))
    recipients = sanitize_text(str(msg.get("to", "")))
    cc = sanitize_text(str(msg.get("cc", "")))
    date = sanitize_text(str(msg.get("date", "")))
    message_id = sanitize_text(str(msg.get("message-id", "")))

    body_plain_parts: List[str] = []
    body_html_parts: List[str] = []
    attachments_metadata: List[Dict[str, Any]] = []

    # Walk message parts
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get_content_disposition() or "")
            filename = part.get_filename()

            # Identify attachments
            if "attachment" in content_disposition or (filename and content_type != "text/plain"):
                payload = part.get_payload(decode=True)
                att_size = len(payload) if payload else 0
                att_hash = hashlib.sha256(payload).hexdigest() if payload else None
                attachments_metadata.append({
                    "file_name": sanitize_text(filename or "unnamed_attachment"),
                    "content_type": content_type,
                    "size_bytes": att_size,
                    "sha256": att_hash
                })
            elif content_type == "text/plain":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        body_plain_parts.append(payload.decode(charset, errors="replace"))
                except Exception as part_err:
                    logger.warning(f"Error decoding plain part: {part_err}")
            elif content_type == "text/html":
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html_text = payload.decode(charset, errors="replace")
                        cleaned = extract_webpage_data(html_content=html_text)
                        body_html_parts.append(cleaned["content"])
                except Exception as html_err:
                    logger.warning(f"Error decoding html part: {html_err}")
    else:
        # Single-part email
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")
            if content_type == "text/html":
                cleaned = extract_webpage_data(html_content=decoded)
                body_html_parts.append(cleaned["content"])
            else:
                body_plain_parts.append(decoded)

    # Prefer plain text if available, otherwise use cleaned HTML
    if body_plain_parts:
        body_text = "\n\n".join(body_plain_parts)
    elif body_html_parts:
        body_text = "\n\n".join(body_html_parts)
    else:
        body_text = ""

    body_text = sanitize_text(body_text)

    # Combined content with Subject prefix for LLM research context
    if subject and body_text:
        combined_content = f"Subject: {subject}\n\n{body_text}"
    elif subject:
        combined_content = f"Subject: {subject}"
    else:
        combined_content = body_text

    metadata = {
        "subject": subject,
        "from": sender,
        "to": recipients,
        "cc": cc,
        "date": date,
        "message_id": message_id,
        "attachments_count": len(attachments_metadata),
        "attachments": attachments_metadata,
        "extraction_method": "python_email_safe_parser"
    }

    return {
        "content": combined_content,
        "file_hash": file_hash,
        "file_name": file_name,
        "metadata": metadata
    }
