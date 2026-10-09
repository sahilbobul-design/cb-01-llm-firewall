# SENTINEL AI — LLM Security Firewall & Gateway
## Technical Documentation, Architecture Notes & Operator Manual

---

### 1. Executive Summary

**SENTINEL AI** is an enterprise-grade AI Security Gateway and LLM Firewall designed to sit between untrusted user inputs (prompts, uploaded documents, emails, web pages) and upstream Large Language Models (LLMs).

Its primary objective is:
> **«ONE TEST CASE → COMPLETE SECURITY PIPELINE → REAL BACKEND EVIDENCE → FINAL VERDICT»**

Every request undergoes deep inspection, forensic cryptographic hashing, heuristic rule matching, Linux-native malware and YARA pattern scanning, weighted risk calculation, and automated token redaction to guarantee that **no malicious instruction, confidential credential, PII, or infected binary reaches the LLM**.

---

### 2. Live Deployment URLs & Access Matrix

| Environment | Endpoint / URL | Purpose |
| :--- | :--- | :--- |
| **Production Cloud (Vercel)** | [https://sentinel-frontend-five-theta.vercel.app](https://sentinel-frontend-five-theta.vercel.app) | Live React 19 SOC Frontend |
| **Vercel Project Dashboard** | [https://vercel.com/sahilbobul-designs-projects/sentinel-frontend](https://vercel.com/sahilbobul-designs-projects/sentinel-frontend) | Deployment telemetry & build logs |
| **Live Kali Linux VM Tunnel** | [https://tazqe-103-89-235-244.free.pinggy.net](https://tazqe-103-89-235-244.free.pinggy.net) | Public HTTPS tunnel to local Gateway |
| **Local Gateway (FastAPI)** | `http://127.0.0.1:8000` (or `http://localhost:8000`) | FastAPI Gateway + Database + Linux Tools |
| **Local Frontend Dev (Vite)** | `http://localhost:5173` | Hot-reloading development server |
| **Interactive API Docs (Swagger)**| `http://127.0.0.1:8000/docs` | OpenAPI documentation & test console |

---

### 3. Architecture & 14-Stage Security Pipeline

```
Untrusted Request (Prompt / File)
   ↓
1. Content & Size Validation (Payload boundary checks, MIME safety)
   ↓
2. Cryptographic SHA-256 Hashing (Forensic chain of custody)
   ↓
3. Safe Text Extraction (PDF, EML, Webpage without executing macros)
   ↓
4. Prompt Injection & Jailbreak Engine (Direct overrides, DAN, Delimiters)
   ↓
5. PII Scanner (Social Security Numbers, Emails, Phone Numbers)
   ↓
6. Secret Scanner (AWS Keys, OpenAI API Keys, Slack/Stripe Secrets)
   ↓
7. AI Classifier Interface (Jev Architecture Interface)
   ↓
8. YARA Binary Scanner (Static heuristic rule matching in <150ms)
   ↓
9. ClamAV Antivirus Daemon (Resident clamdscan over socket in <60ms)
   ↓
10. tshark Network Telemetry (Host-isolation validation & packet counts)
   ↓
11. Multi-Vector Risk Engine (Normalized 0–100 Weighted Score)
   ↓
12. Sanitization & Redaction Engine (Masks PII/Secrets or Blocks Payload)
   ↓
13. Final Policy Decision (SAFE | SUSPICIOUS | BLOCKED)
   ↓
14. LLM Exposure Prevention (Zero-trust quarantine)
```

#### Risk Scoring Thresholds
- `0 – 29`: **SAFE** (Green) — Safe to forward to LLM
- `30 – 69`: **SUSPICIOUS** (Amber) — Sanitized or flagged for review
- `70 – 100`: **BLOCKED** (Crimson) — Immediate block; prompt replaced with `[BLOCKED_BY_SECURITY_GATEWAY]`

---

### 4. Linux Cybersecurity Engine (Oracle VirtualBox Kali VM)

The cybersecurity layer executes natively inside Kali Linux (`kali-linux-2026.2-virtualbox-amd64`) with port 8000 forwarded to host Windows `127.0.0.1:8000`:

- **YARA 4.5.8**:
  - Binary path: `/usr/bin/yara`
  - Rule files: `security_engine/rules/prompt_injection.yar`, `rules/suspicious_content.yar`
  - Performance: ~100–140ms per scan
- **ClamAV 1.4.6**:
  - Daemon: `clamav-daemon.service` running resident in RAM
  - Client binary: `/usr/bin/clamdscan --fdpass --no-summary`
  - Performance: **~40–60ms** per scan (accelerated from 35s standalone clamscan)
  - Verification: Detects `Eicar-Test-Signature` in 57ms
- **tshark 4.6.6**:
  - Binary path: `/usr/bin/tshark`
  - Captures on loopback/virtual interface for network egress analysis
- **PostgreSQL 16 & SQLite**:
  - Normalized schemas: `datasets`, `records`, `security_events`, `tool_results`

---

### 5. Frontend Architecture & Features (React 19 + TypeScript)

#### 1. Command Center (`DASHBOARD`)
- Real-time connection indicators (FastAPI Gateway, PostgreSQL DB, Linux Layer).
- Clean vs. Attack Discriminative Accuracy metrics (100% pass for benign, 100% block for attacks).
- Status telemetry grid for YARA, ClamAV, tshark, and Jev.

#### 2. Full Security Test (`HERO SCREEN`)
- Quick Loaders: Benign technical prompts, DAN Jailbreaks, Credential Leakage, EICAR Virus, YARA triggers.
- File Dropzone for PDF, TXT, DOCX, and binary files.
- Interactive 14-Stage Visual Pipeline Graph.
- Radial SVG Risk Gauge (0–100) with dynamic breakdown cards.
- Side-by-side Before/After Sanitization Diff viewer.
- Cryptographic SHA-256 hash card with copy-to-clipboard.
- Modal displaying untouched backend JSON.

#### 3. Security Lab (`18 TEST CASES`)
- 18 comprehensive test scenarios:
  - `TC-01` to `TC-05`: Direct Injection, Persona Roleplay, Delimiter Hijack, System Directive, System Leakage.
  - `TC-06` to `TC-09`: AWS Key Leakage, OpenAI Token, SSN Exposure, Multi-PII Exfiltration.
  - `TC-10` to `TC-12`: C2 IP Egress, Malicious Redirect URLs, Phishing Payload.
  - `TC-13` to `TC-15`: Clean Invoice PDF, YARA Rule Trigger File, ClamAV EICAR Virus File.
  - `TC-16` to `TC-17`: Benign Physics Query, Clean Python Code Review.
  - `TC-18`: Output Firewall completion inspection.
- Batch Runner: Click **`▶ RUN ALL 18 TESTS`** to run all test cases with dynamic progress and pass rate calculations.

#### 4. Evidence & Audit (`EVIDENCE`)
- Queries PostgreSQL table `security_events` with filters for Severity and Decision.
- Interactive Output Firewall Simulator testing outbound model text against `/api/v1/scans/output`.

#### 5. Benchmark Datasets (`DATASETS`)
- Explores Microsoft BIPIA, Synthetic PDF Injection, and CIC-Evasive-PDFMal2022.
- Click **"Test Record"** on any dataset entry to instantly run it through the Full Security Test pipeline.
- Offline-resilient with bundled fallback datasets for remote judge evaluation.

---

### 6. Command Reference & Operator Runbook

#### VirtualBox Kali VM Management
```cmd
:: 1. Open Web UI Dashboard in browser
.\kali-cli.bat ui

:: 2. Run all live security tests (YARA, ClamAV, Injection)
.\kali-cli.bat test

:: 3. Check versions of Linux security tools
.\kali-cli.bat tools

:: 4. Restart Sentinel Gateway inside Kali VM
.\kali-cli.bat restart

:: 5. View live server log
.\kali-cli.bat logs

:: 6. Check API health
.\kali-cli.bat status

:: 7. Log in directly to Kali terminal via SSH
.\kali-cli.bat ssh
```

#### Frontend & Deployment Commands
```powershell
# 1. Run local frontend with Hot-Reloading
cd sentinel-frontend
npm run dev
# Opens on: http://localhost:5173

# 2. Build production frontend bundle
cd sentinel-frontend
npm run build

# 3. Deploy frontend to Vercel
.\deploy-vercel.bat
# Or manually:
cd sentinel-frontend
npx vercel --prod
```

#### Automated Pytest Suite (Inside Kali VM)
```bash
cd /home/kali/llm_platform
PYTHONPATH=. pytest
# Results: 31 passed in 25.90s (100% Pass Rate)
```

---

### 7. Key REST API Endpoints

| Method | Route | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | System health, database connectivity, and version |
| `GET` | `/api/v1/security/health` | Linux security layer and tool daemon status |
| `GET` | `/api/v1/security/tools` | Status and installed state for YARA, ClamAV, tshark |
| `GET` | `/api/v1/security/dashboard`| Aggregate telemetry and scan counts |
| `POST` | `/api/v1/scans` | Primary scan endpoint (supports JSON prompt or multipart file upload) |
| `POST` | `/api/v1/scans/output` | Output Firewall: sanitizes outbound LLM completions |
| `GET` | `/api/v1/scans/events` | Audit log of security events from database |
| `GET` | `/datasets` | Registered threat benchmark datasets |
| `GET` | `/records` | Paginated records with filters (`dataset`, `label`, `source_type`) |

---

### 8. Hackathon Judge Demonstration Script

1. **Step 1: Introduction (30 seconds)**
   - Open **[https://sentinel-frontend-five-theta.vercel.app](https://sentinel-frontend-five-theta.vercel.app)**.
   - Explain: *"SENTINEL AI is an enterprise AI Security Gateway that intercepts attacks before they touch an LLM. It combines prompt security with native Linux cybersecurity tools (YARA, ClamAV, tshark)."*

2. **Step 2: Benign Baseline Test (30 seconds)**
   - Go to **Full Security Test**.
   - Click **Clean Technical Prompt** preset.
   - Click **Run Full Security Test**.
   - Show: Risk score is **0 (SAFE)**, YARA is CLEAN, all pipeline badges green, prompt passed unchanged.

3. **Step 3: Multi-Vector Threat & Jailbreak (45 seconds)**
   - Click **Exfiltrate API Keys & PII** preset.
   - Click **Run Full Security Test**.
   - Show: Risk score shoots to **100 (BLOCKED)**.
   - Highlight the **Before/After Sanitization Diff**: sensitive keys and SSN are sanitized to `[BLOCKED_BY_SECURITY_GATEWAY]`.
   - Point out the reasons list: `PROMPT_INJECTION`, `SYSTEM_PROMPT_ATTACK`, `SECRET_DETECTED`, `PII_DETECTED`.

4. **Step 4: Linux File Forensics with ClamAV & YARA (45 seconds)**
   - Drop a PDF or select **EICAR Antivirus Test**.
   - Click **Run Full Security Test**.
   - Highlight real forensic SHA-256 hash.
   - Show ClamAV execution time: **57ms**, status: **INFECTED** (`Eicar-Test-Signature`).

5. **Step 5: Benchmark Intelligence & Security Lab (30 seconds)**
   - Switch to **Security Lab (18 TCs)** and click **Run All 18 Tests** to display automated batch validation.
   - Switch to **Benchmark Datasets** to show Microsoft BIPIA and PDF Injection records. Click **Test Record** to demonstrate end-to-end integration.
