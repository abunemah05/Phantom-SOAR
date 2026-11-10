# Phantom SOAR: Enterprise Security Orchestration, Automation, and Response Platform

Phantom SOAR is an enterprise-grade Security Orchestration, Automation, and Response (SOAR) platform built to bridge Security Operations Centers (SOC) with automated threat containment. Designed around the **SANS PICERL** incident response framework, **SOAPA** (Security Operations and Analytics Platform Architecture), **MITRE ATT&CK**, and **Wazuh SIEM** telemetry.

---

## 🛡️ Architecture & Core Standards

### 1. SANS PICERL Lifecycle Integration
- **Preparation:** Pre-configured catalog of 12 standard MITRE/SANS IR playbooks (Ransomware, Brute Force, Phishing, PrivEsc, WebShell, Exfiltration, etc.).
- **Identification:** Ingestion of Wazuh SIEM JSON telemetry, artifact extraction, and TIP enrichment.
- **Containment:** Severity-based dual-routing engine:
  - **HOTL (Human-On-The-Loop / Autonomous Containment):** Critical/High severity (or VirusTotal Threat Score > 50). Instantly executes host isolation, malicious process termination, and edge firewall IP blocking with sub-2-second MTTR.
  - **HITL (Human-In-The-Loop):** Low/Medium severity. Pauses in `Triaged` state awaiting manual analyst sign-off via one-click approval or denial.
- **Eradication:** Threat elimination via EDR file quarantine, process termination, and IAM credential resets.
- **Recovery:** Session revocation, token invalidation, and network restoration.
- **Lessons Learned:** Automated executive incident report generation using ReportLab Platypus.

### 2. Enterprise Integration Hub
- **EDR Connector (`backend/integrations/edr.py`):** Network isolation and process termination.
- **TIP Connector (`backend/integrations/tip.py`):** VirusTotal v3 and AbuseIPDB threat intelligence enrichment.
- **Firewall Connector (`backend/integrations/firewall.py`):** Dynamic IP blocking and rate limiting.
- **IAM Connector (`backend/integrations/iam.py`):** Account disabling and active OAuth/SSO token revocation.
- **ITSM Connector (`backend/integrations/itsm.py`):** Automated Jira ticketing and webhook alerting.

---

## 📁 Repository Structure

```
SOAR/
├── docker-compose.yml              # Complete 5-tier multi-container orchestration
├── .env.example                    # Configuration template
├── backend/
│   ├── config.py                   # Pydantic Settings & environment config
│   ├── database.py                 # SQLAlchemy engine & SQLite/Postgres fallback
│   ├── models.py                   # Alert, IocArtifact, Playbook, PlaybookExecution, ContainmentAction, IncidentReport
│   ├── schemas.py                  # Pydantic v2 schemas
│   ├── crud.py                     # Complete CRUD operations & get_ioc_artifacts_by_alert
│   ├── celery_app.py               # Celery async background worker configuration
│   ├── main.py                     # FastAPI application & router lifecycle
│   ├── integrations/               # Modular connector framework
│   │   ├── edr.py                  # Endpoint isolation & process termination
│   │   ├── tip.py                  # VirusTotal & AbuseIPDB threat queries
│   │   ├── firewall.py             # Perimeter IP blocking & rate limiting
│   │   ├── iam.py                  # Active Directory / Okta user containment
│   │   └── itsm.py                 # Jira tickets & webhook alerting
│   ├── engine/
│   │   ├── runner.py               # Automated HOTL / HITL severity routing engine
│   │   ├── reporter.py             # ReportLab Platypus executive PDF report generator
│   │   └── playbooks_catalog.py    # 12 pre-configured SANS / MITRE IR playbooks
│   ├── routers/
│   │   ├── webhooks.py             # POST /api/webhooks/wazuh
│   │   ├── alerts.py               # GET, approve, dismiss, and PDF streaming
│   │   ├── playbooks.py            # CRUD & toggle endpoints
│   │   └── demo.py                 # POST /api/demo/seed
│   ├── tests/                      # Pytest test suite (13 passing unit & integration tests)
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx            # Real-time SOC metrics & "Generate Demo Data"
│   │   │   ├── alerts/page.tsx     # Investigation Workspace & HITL action bar
│   │   │   └── playbooks/page.tsx  # Playbook Library, 12 templates & JSON editor
│   │   ├── components/
│   │   │   ├── Sidebar.tsx         # Client component with active route highlighting
│   │   │   ├── Navbar.tsx          # Real-time UTC clock & SOC status
│   │   │   ├── InvestigateModal.tsx# Executive modal with IoCs, MITRE & PDF streaming
│   │   │   └── PlaybookModal.tsx   # Live JSON workflow editor modal
│   │   └── lib/
│   │       ├── api.ts              # API client methods
│   │       └── types.ts            # TypeScript models
│   ├── package.json
│   └── Dockerfile
└── README.md
```

---

## 🚀 Quickstart Guide

### Option 1: Docker Compose (Production Environment)
```bash
docker-compose up --build
```
Services exposed:
- **Frontend Dashboard:** [http://localhost:3000](http://localhost:3000)
- **FastAPI Backend & Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **PostgreSQL:** Port 5432
- **Redis:** Port 6379

---

### Option 2: Local Development Environment

#### Backend:
```bash
# 1. Install Python dependencies
pip install -r backend/requirements.txt

# 2. Run backend test suite
python -m pytest backend/tests -v

# 3. Start FastAPI server
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend:
```bash
# In frontend/ directory:
npm install
npm run dev
```

---

## 🎓 University Graduation Defense Demonstration Steps

1. **Dashboard Launch:** Open [http://localhost:3000](http://localhost:3000).
2. **Instant Demo Seeder:** Click the prominent **"Generate Demo Data"** button on the header banner.
   - Instantly populates the database with:
     - 12 SANS / MITRE IR Playbooks.
     - **Critical LockBit 3.0 Ransomware Alert:** Executed under **HOTL (Human-On-The-Loop)** policy with automated endpoint isolation, process kill, IP block, and MTTR under 1.50 seconds.
     - **Medium Spearphishing Alert:** Routed under **HITL (Human-In-The-Loop)** policy, set to `Triaged` awaiting analyst review.
     - **High WebShell Attack:** Autonomously contained.
3. **HITL Review & Analyst Sign-off:**
   - Navigate to **"Alerts & Cases"** in the sidebar.
   - Click on the **Medium Phishing alert (#2)**.
   - The modal displays the **Executive IR Summary**, **IoC Artifacts & VirusTotal threat score**, **Containment timeline**, and **MITRE ATT&CK tags**.
   - Click **"Approve Containment"** (Green button).
   - The orchestrator instantly executes the containment actions, marks the alert `Contained`, calculates MTTR, and produces the executive incident report!
4. **Download Executive Incident PDF Report:**
   - Click **"Download PDF"** on any contained incident.
   - The ReportLab engine streams the executive PDF incident report complete with SANS PICERL classification, Threat Intelligence scorecard, and containment signatures.
5. **Playbook Library & Logic Editor:**
   - Navigate to **"Playbooks"** in the sidebar.
   - Inspect the 12 pre-configured SANS / MITRE cards.
   - Click the **Power Toggle** to dynamically activate/deactivate a playbook (`PATCH`).
   - Click the **Settings Icon** to launch the interactive live JSON workflow editor (`PUT`).
   - Click **"New Playbook"** and select any template from the 12 pre-configured templates dropdown.
