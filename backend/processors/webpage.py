import hashlib
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Union
from bs4 import BeautifulSoup
from backend.processors.pdf import sanitize_text

logger = logging.getLogger(__name__)


def extract_webpage_data(
    html_content: Optional[Union[str, bytes]] = None,
    file_path: Optional[Union[str, Path]] = None,
    source_url: Optional[str] = None,
    file_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Safely extract readable text and structure metadata from HTML content.

    SECURITY GUARANTEES:
    - No JavaScript runtime (V8, NodeJS, or browser) is invoked.
    - No external network connections are made (URLs are never visited).
    - Scripts, styles, frames, and active elements are completely stripped.
    """
    if html_content is None:
        if file_path is None:
            raise ValueError("Either html_content or file_path must be provided.")
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"HTML file not found: {path}")
        html_bytes = path.read_bytes()
        if file_name is None:
            file_name = path.name
    elif isinstance(html_content, str):
        html_bytes = html_content.encode("utf-8")
    else:
        html_bytes = html_content

    # Calculate deterministic SHA-256 hash
    file_hash = hashlib.sha256(html_bytes).hexdigest()

    try:
        soup = BeautifulSoup(html_bytes, "html.parser")
    except Exception as e:
        logger.warning(f"Error parsing HTML with BeautifulSoup: {e}")
        # Fallback to plain decoding
        raw_text = html_bytes.decode("utf-8", errors="replace")
        return {
            "content": sanitize_text(raw_text),
            "file_hash": file_hash,
            "file_name": file_name,
            "metadata": {
                "source_url": source_url,
                "extraction_error": str(e),
                "extraction_method": "raw_fallback"
            }
        }

    # Extract title before stripping
    title = ""
    if soup.title and soup.title.string:
        title = sanitize_text(soup.title.string)

    # Collect structural stats before decomposition
    script_count = len(soup.find_all("script"))
    iframe_count = len(soup.find_all("iframe"))
    link_count = len(soup.find_all("a"))

    # Decompose untrusted, active or non-visible elements
    for element in soup(["script", "style", "noscript", "iframe", "object", "embed", "svg"]):
        element.decompose()

    # Extract readable text with clean separation
    text = soup.get_text(separator="\n", strip=True)
    clean_text = sanitize_text(text)

    metadata = {
        "source_url": source_url,
        "title": title,
        "script_tags_found": script_count,
        "iframe_tags_found": iframe_count,
        "links_found": link_count,
        "content_length_chars": len(clean_text),
        "extraction_method": "beautifulsoup_safe_parser"
    }

    return {
        "content": clean_text,
        "file_hash": file_hash,
        "file_name": file_name,
        "metadata": metadata
    }
