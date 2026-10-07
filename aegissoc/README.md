# Ghost Trackers — AegisSOC Defensive Operations Suite

[![Security Standards](https://img.shields.io/badge/Security-Defensive%20Only-emerald.svg)](#safety-standard)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg?logo=react)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.0+-646CFF.svg?logo=vite)](https://vitejs.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4+-38B2AC.svg?logo=tailwind-css)](https://tailwindcss.com)

**Ghost Trackers (AegisSOC)** is a production-grade, modular defensive cybersecurity operations center and threat intelligence platform designed for SOC analysts, DevSecOps engineers, and security architects.

---

## Architecture & System Overview

Ghost Trackers consolidates 6 core defensive security operational capabilities into a unified dark-mode dashboard backed by high-throughput FastAPI microservices and persistent SQLite/SQLAlchemy storage.

```text
aegissoc/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── v1/
│   │   │   │   ├── vuln.py            # Static SAST, CVSS 3.1 & Dependency scanner
│   │   │   │   ├── architecture.py    # Cloud & Infrastructure configuration linter
│   │   │   │   ├── forensics.py       # Multi-format log parser & timeline generator
│   │   │   │   ├── threat_model.py    # STRIDE matrix & 5x5 qualitative risk heatmap
│   │   │   │   ├── security_tests.py  # DAST test harness, JUnit XML & SARIF export
│   │   │   │   └── malware.py         # Static PE/ELF analyzer, Shannon entropy, YARA
│   │   │   └── api.py                 # Unified v1 API router
│   │   ├── core/
│   │   │   ├── config.py              # Application settings
│   │   │   ├── database.py            # SQLAlchemy engine & session management
│   │   │   └── security.py            # Defensive safety guards & input sanitizer
│   │   ├── models/
│   │   │   └── schemas.py             # SQLAlchemy ORM models & Pydantic v2 schemas
│   │   ├── services/
│   │   │   ├── vuln_scanner.py        # Bandit/Semgrep regex heuristics & CVSS math
│   │   │   ├── architecture_linter.py # IAM, K8s, Dockerfile linters & CIS playbooks
│   │   │   ├── forensics_engine.py    # Apache, Linux auth & EVTX timeline parser
│   │   │   ├── threat_modeler.py      # STRIDE framework & qualitative risk engine
│   │   │   ├── security_tester.py     # DAST header/CORS tests, JUnit XML, SARIF
│   │   │   └── malware_triage.py      # Shannon entropy, PE/ELF parser, YARA engine
│   │   └── main.py                    # FastAPI application entrypoint
│   ├── tests/
│   │   └── test_all_modules.py        # Pytest integration test suite
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/                # Navbar, Sidebar, SeverityBadge
│   │   │   ├── dashboard/             # OverviewDashboard with Recharts metrics
│   │   │   └── modules/               # 6 Dedicated view interfaces
│   │   ├── services/
│   │   │   └── api.js                 # API client layer
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── package.json
│   ├── tailwind.config.js
│   ├── vite.config.js
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## 6 Functional Core Modules

### 1. Vulnerability Assessment & Static Detection (`/api/v1/vuln`)
- **Heuristic Source Scanner:** Regex rules for hardcoded AWS keys, generic secrets, SQL injection (`f-string` / dynamic concatenation), dangerous deserialization (`pickle.loads`, unsafe `yaml.load`), command injection (`shell=True`, `eval`).
- **CVSS 3.1 Base Scoring Engine:** Complete mathematical implementation of FIRST.org CVSS 3.1 specification (AV, AC, PR, UI, Scope, C, I, A) yielding base scores, qualitative ratings, and official vector strings.
- **Dependency Vulnerability Scanner:** Audits `requirements.txt` and `package.json` against known CVE vulnerability baselines.

### 2. Security Architecture Reviewer (`/api/v1/architecture`)
- **Infrastructure Linters:**
  - **AWS IAM Policy JSON:** Flags wildcard actions (`*`), wildcard resources, unauthenticated public AssumeRole trusts, and missing MFA conditions.
  - **Kubernetes Manifests:** Flags `privileged: true`, `runAsRoot: true`, missing CPU/memory limits, host namespace sharing, and writable root filesystems.
  - **Dockerfiles:** Flags root user execution, `:latest` base image tags, secrets in `ENV`/`ARG`, `ADD` vs `COPY`, and insecure administrative ports (22, 23, 3389).
- **Compliance Mapping:** Direct references to **CIS Benchmarks**, **NIST SP 800-53 Rev 5**, and **OWASP Top 10** with actionable remediation playbooks and code diffs.

### 3. Incident Response & Forensics (`/api/v1/forensics`)
- **Multi-Format Log Parser:** Ingests Apache/Nginx combined access logs, Linux `/var/log/auth.log`, and Windows Security Event Logs (EVTX JSON).
- **Artifact Timeline Generator:** Constructs chronological sequence of events, identifies attack spikes, flags scanner user-agents (e.g. sqlmap, nikto), isolates brute-force SSH attacks, and tags **MITRE ATT&CK** tactics (T1110, T1078, T1190, T1595).

### 4. Threat Modeling & Risk Assessment (`/api/v1/threat-model`)
- **STRIDE Framework Matrix:** Covers Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.
- **5x5 Qualitative Risk Heatmap:** Interactive matrix calculating Risk = Likelihood (1-5) × Impact (1-5), supporting lifecycle mitigation tracking and residual risk recalculation.

### 5. Automated Security Testing Harness (`/api/v1/security-tests`)
- **DAST Security Audit:** Scans HTTP endpoints for missing security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`), permissive CORS policies, and SSL/TLS enforcement.
- **CI/CD Integration:** One-click download endpoints for **JUnit XML** and **OASIS SARIF v2.1.0** reports for Jenkins, GitHub Actions, and GitLab CI.
- **Mock Target Sandbox:** Built-in configurable mock target for safe automated testing without network risk.

### 6. Defensive Malware Analysis & Artifact Triage (`/api/v1/malware`)
- **Static Artifact Analyzer:** Computes SHA-256, MD5, and pure Python SSDEEP / fuzzy hash signatures.
- **Shannon Entropy Visualizer:** Mathematical byte randomness calculation $H(X) = -\sum P(x) \log_2 P(x)$ across file chunks to pinpoint obfuscated or packed sections (entropy > 7.1).
- **PE/ELF Binary Inspection:** Parses DOS headers, PE architectures, section tables, and suspicious imported Windows APIs (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `IsDebuggerPresent`).
- **Mock YARA Engine:** Rule-based pattern matching for ransomware extortion notes, obfuscated PowerShell droppers, and UPX packer signatures.

---

## Safety Standard

Ghost Trackers operates exclusively under **defensive cybersecurity principles**:
- **Zero Live Payload Execution:** All binary and artifact analysis is purely static parsing and Shannon entropy inspection.
- **SSRF Defensive Guardrails:** DAST testing strictly restricts requests to permitted local sandboxes and explicit target endpoints; cloud metadata IPs (`169.254.169.254`) are blocked.
- **Safe Heuristic Rules:** Scanning utilizes deterministic regex and static AST heuristics without dynamic side effects.

---

## Quickstart Guide

### Option 1: Running with Docker Compose
```bash
# From the project root:
docker-compose up --build
```
- Access Frontend Dashboard: `http://localhost:5173`
- Access Backend API Docs: `http://localhost:8000/docs`

---

### Option 2: Running Locally

#### 1. Backend Setup
```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

#### 3. Run Backend Test Suite
```bash
cd backend
python -m pytest tests -v
```

---

## License & Attribution
Ghost Trackers — AegisSOC is engineered for enterprise defensive operations and cybersecurity resilience.
