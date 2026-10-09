# 🛡️ SENTINEL AI — LLM Security Firewall & Enterprise Gateway
### Hackatopia 2026 — Cyber Security + Blockchain Track
**Problem Statement ID:** `CB-01` *(Original Code: CS-02)*  
**Category:** LLM Security, Classifiers & Gateway Proxies  
**Objective:** Build a gateway sitting between users, data sources, and an LLM app that detects direct and indirect prompt injection, jailbreaks, and sensitive data leaks, and blocks or cleans them while letting normal traffic through.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel%20Production-00f2fe?style=for-the-badge&logo=vercel)](https://sentinel-frontend-five-theta.vercel.app)
[![API Gateway](https://img.shields.io/badge/FastAPI%20Gateway-Localhost:8000-00d26a?style=for-the-badge&logo=fastapi)](http://localhost:8000/docs)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python)](https://python.org)
[![React 19](https://img.shields.io/badge/Frontend-React%2019%20%2B%20Vite-61DAFB?style=for-the-badge&logo=react)](https://react.dev)
[![Linux Defense](https://img.shields.io/badge/Linux%20Engine-YARA%20%2B%20ClamAV%20%2B%20tshark-E95420?style=for-the-badge&logo=linux)](https://github.com/sahilbobul-design/cb-01-llm-firewall)

---

## 📌 Executive Summary

**SENTINEL AI** is a defense-in-depth AI Security Gateway and reverse proxy designed to safeguard upstream Large Language Models (LLMs) and autonomous AI agents. As enterprises connect GenAI models to emails, enterprise documents, PDFs, and internal databases, adversarial actors hide instructions inside data sources to hijack LLMs into leaking private credentials or taking unauthorized actions.

SENTINEL AI intercepts every prompt, document attachment, and completion through a **14-Stage Multi-Vector Security Pipeline**, fusing **native Linux binary security (YARA + ClamAV daemon in <60ms)** with **content heuristic detection, zero-trust quarantine storage, and automated token redaction**.

> **Core Philosophy:**  
> **«ONE TEST CASE → COMPLETE 14-STAGE PIPELINE → REAL LINUX FORENSIC EVIDENCE → DYNAMIC CLEAN OR BLOCK VERDICT»**

---

## 🌐 Live Deployment Matrix

| Environment | Endpoint / URL | Purpose |
| :--- | :--- | :--- |
| **Production Cloud (Vercel)** | [https://sentinel-frontend-five-theta.vercel.app](https://sentinel-frontend-five-theta.vercel.app) | Live React 19 SOC Security Dashboard |
| **Live Kali Linux VM Tunnel** | [https://tazqe-103-89-235-244.free.pinggy.net](https://tazqe-103-89-235-244.free.pinggy.net) | Public HTTPS tunnel to live Linux Gateway |
| **Local Gateway API (FastAPI)** | `http://localhost:8000` | Inbound & Outbound Security Proxy |
| **Interactive API Docs (Swagger)**| `http://localhost:8000/docs` | Live OpenAPI test console for `/api/v1/scans` |
| **Local React Dev Server (Vite)** | `http://localhost:5173` | Hot-reloading development environment |

---

## 🖼️ User Interface & Security Operations Center (SOC)

### 1. Command Center & SOC Telemetry
Real-time connection telemetry across the FastAPI Gateway, PostgreSQL database, and Linux security daemons, alongside clean vs. attack discriminative accuracy metrics.

![Command Center](docs/screenshots/01_command_center.png)

---

### 2. Full Security Test (Hero Screen) & 14-Stage Pipeline
Interactive payload testing suite supporting text prompts and uploaded multi-format files (PDF, EML, HTML). Visualizes execution across all 14 defense nodes in real time with SVG radial risk gauges and Before/After sanitization diffs.

![Full Security Test Screen](docs/screenshots/02_hero_security_test.png)

---

### 3. The Chronicles of an Attack (3D Interactive Story)
An interactive storyline demonstrating an end-to-end prompt injection attack: from adversarial polyglot infiltration to Linux forensic deep inspection, weighted risk spike, and upstream LLM zero-trust shielding.

![3D Attack Storyline](docs/screenshots/03_3d_attack_storyline.png)

---

### 4. Security Test Lab (18 Automated Benchmark Test Cases)
Automated batch validation suite covering 18 critical scenarios with dynamic pass-rate calculation:
- `TC-01` to `TC-05`: Direct Injection, Persona Roleplay, Delimiter Hijack, System Directives, System Extraction.
- `TC-06` to `TC-09`: AWS Key Leakage, OpenAI Token, SSN Exposure, Multi-PII Exfiltration.
- `TC-10` to `TC-12`: C2 IP Egress, Malicious Redirect URLs, Phishing Payloads.
- `TC-13` to `TC-15`: Clean Invoice PDF, YARA Trigger File, ClamAV EICAR Antivirus File.
- `TC-16` to `TC-17`: Benign Technical Query, Clean Python Code Review.
- `TC-18`: Output Firewall model completion inspection.

![Security Test Lab](docs/screenshots/04_security_lab_18_tests.png)

---

## 🏛️ 14-Stage Security Pipeline Architecture

```
                    [Untrusted User Request / Data Source]
                     (Prompt, PDF Attachment, Email, Web)
                                      │
                                      ▼
    ┌──────────────────────────────────────────────────────────────────┐
    │ 1. Content & Size Validation    (Payload bounds, MIME validation)│
    │ 2. Cryptographic SHA-256 Digest (Forensic chain of custody)      │
    │ 3. Non-Executable Quarantine    (Isolated sandbox file staging)  │
    │ 4. Safe Text & AST Extraction   (Zero macro / script execution)  │
    │ 5. Prompt Injection Detector    (Direct override, DAN, Delimiter)│
    │ 6. PII Scanner                  (SSN, Credit Cards, Phones, Mail)│
    │ 7. Secret & Key Scanner         (AWS, GitHub, Slack, OpenAI keys)│
    │ 8. AI Classifier Interface      (Jev Modular Classifier Layer)   │
    │ 9. YARA Pattern Engine          (Static heuristic rules <120ms)  │
    │ 10. ClamAV Antivirus Daemon     (RAM-resident clamdscan <60ms)   │
    │ 11. tshark Network Telemetry    (Network egress & host isolation)│
    │ 12. Multi-Vector Risk Engine    (0-100 Normalized Weighted Score)│
    │ 13. Dynamic Sanitizer Engine    (Redacts secrets & masks PII)    │
    │ 14. Final Policy Decision       (SAFE | SUSPICIOUS | BLOCKED)    │
    └─────────────────────────────────┬────────────────────────────────┘
                                      │
                   ┌──────────────────┴──────────────────┐
                   ▼                                     ▼
      [BLOCKED / QUARANTINED]               [CLEANED / FORWARDED]
    Zero Model Context Exposure             Passed to Upstream LLM
   Replaced with [BLOCKED_NOTICE]                        │
                                                         ▼
                                            ┌─────────────────────────┐
                                            │ Output Firewall (/output)│
                                            └─────────────────────────┘
```

### Risk Scoring Matrix & Policy Actions
- **`0 – 29` | SAFE (Green)**: Benign traffic allowed to proceed to LLM with 0 latency penalty.
- **`30 – 69` | SUSPICIOUS (Amber)**: Sensitive credentials or PII sanitized/redacted; cleaned prompt forwarded.
- **`70 – 100` | BLOCKED (Crimson)**: Malicious injection or trojan binary immediately quarantined and dropped.

---

## 🐧 Linux Cybersecurity Layer

The gateway natively integrates with hardened Linux cybersecurity utilities:

- **YARA 4.5.8**:
  - Rules: `security_engine/rules/prompt_injection.yar`, `rules/suspicious_content.yar`, `security_engine/rules/pdf_malware.yar`
  - Scans for delimiter hijacking, prompt extraction, and embedded malware signatures in ~100ms.
- **ClamAV 1.4.6**:
  - Daemon socket execution: `/usr/bin/clamdscan --fdpass --no-summary`
  - High-speed scan: Detects EICAR & infected binaries in **~40–60ms** (accelerated from 35s standalone clamscan).
- **Safe Document Parsers**:
  - `pypdf` without JavaScript execution for PDFs.
  - Python standard `email` MIME reader for `.eml` files.
  - `BeautifulSoup4` with script decomposition for HTML pages.

---

## 📊 Threat Benchmark Datasets

The gateway is validated against recognized industry benchmark corpora:
1. **Microsoft BIPIA**: Benign & prompt-injected email and webpage contexts.
2. **Synthetic PDF Injections**: High-stealth resume and invoice indirect injections.
3. **CIC-Evasive-PDFMal2022**: Evasive malware PDFs tested against safe parsers.

---

## 🚀 Quickstart & Setup Guide

### 1. Prerequisites
- **Python**: 3.10+
- **Node.js**: 18+ (npm 10+)
- **Optional**: Docker / Oracle VirtualBox for native Linux layer

### 2. Localhost Setup (Windows / macOS / Linux)

```bash
# Clone the repository
git clone https://github.com/sahilbobul-design/cb-01-llm-firewall.git
cd cb-01-llm-firewall

# 1. Start Backend API Gateway
python -m pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

# 2. In a new terminal, start the React 19 Frontend
cd sentinel-frontend
npm install
npm run dev
```
- Open Frontend: **`http://localhost:5173`**
- Open Swagger Docs: **`http://localhost:8000/docs`**

---

### 3. Docker Deployment

```bash
# Start backend and PostgreSQL database
docker compose up -d --build

# Verify health
curl http://localhost:8001/health
```

---

### 4. Running the Kali Linux VM Layer (VirtualBox)

```cmd
:: Check Linux tool versions (YARA, ClamAV, tshark)
.\kali-cli.bat tools

:: Run full end-to-end security test suite
.\kali-cli.bat test

:: Open Web UI Dashboard in browser
.\kali-cli.bat ui
```

---

## 🧪 Automated Pytest Suite

```bash
# Run backend test suite
pytest tests/test_api_and_pipeline.py -v
```
**Results:** `31 passed (100% Pass Rate)`

---

## 📜 Key REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/scans` | Primary scan endpoint (accepts JSON text or multipart file upload) |
| `POST` | `/api/v1/scans/output` | Output Firewall: Sanitizes outbound LLM model completions |
| `GET` | `/api/v1/security/health` | Status of security pipeline and Linux tool daemons |
| `GET` | `/api/v1/security/tools` | Installed state for YARA, ClamAV, and tshark |
| `GET` | `/api/v1/security/dashboard` | Aggregated threat counts, blocked requests, and metrics |
| `GET` | `/datasets` | Registered threat benchmark datasets |
| `GET` | `/records` | Paginated records with filters (`dataset`, `label`, `source_type`) |
| `GET` | `/health` | Core system health and database connectivity probe |

---

## 👥 Hackatopia 2026 Team & Attribution

- **Project:** SENTINEL AI — LLM Security Firewall
- **Problem Statement:** `CB-01` — LLM firewall against prompt injection
- **GitHub Repository:** [https://github.com/sahilbobul-design/cb-01-llm-firewall](https://github.com/sahilbobul-design/cb-01-llm-firewall)
- **Production URL:** [https://sentinel-frontend-five-theta.vercel.app](https://sentinel-frontend-five-theta.vercel.app)
