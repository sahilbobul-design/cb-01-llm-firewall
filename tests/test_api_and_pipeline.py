import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.database import Base, get_db
from backend.processors.pdf import extract_pdf_data
from backend.processors.webpage import extract_webpage_data
from backend.processors.email import extract_email_data

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded"]
    assert "version" in data


def test_list_datasets():
    response = client.get("/datasets")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 3
    dataset_names = [d["name"] for d in data]
    assert "BIPIA" in dataset_names
    assert "PDF_INJECTION" in dataset_names
    assert "CIC_EVASIVE_PDFMAL2022" in dataset_names


def test_get_dataset_detail():
    response = client.get("/datasets/BIPIA")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "BIPIA"
    assert "records_by_source_type" in data
    assert "records_by_label" in data


def test_list_records_pagination():
    response = client.get("/records?page=1&page_size=3")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "page" in data
    assert "page_size" in data
    assert data["page"] == 1
    assert data["page_size"] == 3
    assert len(data["records"]) <= 3


def test_filter_by_source_type():
    for st in ["email", "webpage", "pdf"]:
        response = client.get(f"/records?source_type={st}")
        assert response.status_code == 200
        data = response.json()
        for rec in data["records"]:
            assert rec["source_type"] == st


def test_filter_by_label():
    for lbl in ["benign", "prompt_injection", "malicious_file"]:
        response = client.get(f"/records?label={lbl}")
        assert response.status_code == 200
        data = response.json()
        for rec in data["records"]:
            assert rec["label"] == lbl


def test_malicious_file_separate_from_prompt_injection():
    response = client.get("/records?label=malicious_file")
    assert response.status_code == 200
    data = response.json()
    for rec in data["records"]:
        assert rec["label"] == "malicious_file"
        assert rec["attack_type"] == "malware"
        assert rec["attack_type"] != "prompt_injection"


def test_get_single_record():
    records_res = client.get("/records?page_size=1")
    rec_id = records_res.json()["records"][0]["id"]
    response = client.get(f"/records/{rec_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == rec_id
    assert "content" in data
    assert "metadata" in data


def test_batch_record_import_and_deduplication():
    import uuid
    unique_text = f"Unique synthetic testing body for API test verification - {uuid.uuid4()}"
    payload = {
        "dataset_name": "API_TEST_DATASET",
        "records": [
            {
                "dataset": "API_TEST_DATASET",
                "source_type": "email",
                "content": unique_text,
                "label": "benign",
                "attack_type": None,
                "metadata": {"test": True}
            }
        ]
    }
    # First import
    res1 = client.post("/records/import", json=payload)
    assert res1.status_code == 201
    summary1 = res1.json()
    assert summary1["imported"] == 1
    assert summary1["duplicates"] == 0

    # Second import with identical content -> should deduplicate
    res2 = client.post("/records/import", json=payload)
    assert res2.status_code == 201
    summary2 = res2.json()
    assert summary2["imported"] == 0
    assert summary2["duplicates"] == 1


def test_safe_webpage_processor():
    html_code = """
    <html>
        <head><title>Untrusted Site</title></head>
        <body>
            <script>alert("malicious script execution attempt");</script>
            <h1>Safe Article Heading</h1>
            <p>This is benign readable text content.</p>
        </body>
    </html>
    """
    res = extract_webpage_data(html_content=html_code)
    assert "Safe Article Heading" in res["content"]
    assert "This is benign readable text content." in res["content"]
    assert "alert(" not in res["content"]
    assert res["metadata"]["title"] == "Untrusted Site"
    assert res["metadata"]["script_tags_found"] == 1


def test_safe_email_processor():
    email_raw = (
        "From: test@sender.com\n"
        "To: target@victim.com\n"
        "Subject: Meeting Reminder\n"
        "Content-Type: text/plain\n\n"
        "Here is the text body."
    )
    res = extract_email_data(raw_content=email_raw)
    assert "Subject: Meeting Reminder" in res["content"]
    assert "Here is the text body." in res["content"]
    assert res["metadata"]["from"] == "test@sender.com"
