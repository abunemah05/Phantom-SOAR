import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Preformatted,
    KeepTogether,
    PageBreak,
    HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and render total page count."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 755, "PHANTOM SOAR — Enterprise Architecture & AI Engine Specification")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 747, letter[0] - 54, 747)

        # Running Footer (all pages)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 45, letter[0] - 54, 45)

        self.drawString(54, 32, "Confidential — Security Operations Engineering & SANS PICERL Architecture")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 32, page_str)
        self.restoreState()

def build_pdf(output_path: str):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom typography
    c_primary = colors.HexColor("#0F172A")    # Deep slate
    c_accent = colors.HexColor("#1D4ED8")     # Royal blue
    c_subtext = colors.HexColor("#475569")    # Muted slate
    c_code_bg = colors.HexColor("#0B1120")    # Terminal dark
    c_code_text = colors.HexColor("#38BDF8")  # Sky cyan
    c_card_bg = colors.HexColor("#F8FAFC")    # Cool light grey
    c_border = colors.HexColor("#E2E8F0")     # Light border

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=c_primary,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=c_accent,
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=c_accent,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=3
    )

    ascii_style = ParagraphStyle(
        'AsciiDiagram',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=8.5,
        textColor=c_code_text
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1E293B")
    )

    story = []

    # --- TITLE & METADATA BANNER ---
    story.append(Paragraph("PHANTOM SOAR: ENTERPRISE ARCHITECTURAL SPECIFICATION", title_style))
    story.append(Paragraph("Autonomous Security Orchestration, SANS PICERL Lifecycle, & The AI-Driven Threat Intelligence Engine", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=c_accent, spaceBefore=0, spaceAfter=14))

    meta_data = [
        [
            Paragraph("<b>Platform:</b> Phantom SOAR Enterprise v2.0", table_cell_style),
            Paragraph("<b>Standard:</b> SANS PICERL & SOAPA", table_cell_style),
            Paragraph("<b>Target Frameworks:</b> MITRE ATT&CK v14.1", table_cell_style),
        ],
        [
            Paragraph("<b>Backend Engine:</b> FastAPI / Celery / Redis", table_cell_style),
            Paragraph("<b>Frontend Core:</b> Next.js 14 / Tailwind CSS", table_cell_style),
            Paragraph("<b>Intelligence:</b> AI Heuristics & Live TIP Hub", table_cell_style),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[170, 165, 169])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_card_bg),
        ('BOX', (0, 0), (-1, -1), 1, c_border),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 14))

    # --- SECTION 1: SYSTEM OVERVIEW ---
    story.append(Paragraph("1. High-Level Architectural Overview", h1_style))
    story.append(Paragraph(
        "Phantom SOAR is an enterprise-scale Security Orchestration, Automation, and Response platform built to address SOC alert fatigue, accelerate Mean Time To Respond (MTTR), and enforce strict auditability across the 6-phase SANS PICERL incident response lifecycle (Preparation, Identification, Containment, Eradication, Recovery, and Lessons Learned).",
        body_style
    ))
    story.append(Paragraph(
        "The architecture unifies heterogeneous security telemetry (SIEM, EDR, and XDR) into a centralized, event-driven orchestration core. High-severity threats are autonomously mitigated via Human-On-The-Loop (HOTL) execution in under 2 seconds, while ambiguous or lower-severity events are routed through a Human-In-The-Loop (HITL) analyst approval gate with integrated AI triage briefs.",
        body_style
    ))

    # ASCII Diagram 1: Ingestion & Engine Topology
    diag1 = """
+-----------------------------------------------------------------------------------------+
|                               MULTI-VECTOR TELEMETRY INGESTION                          |
|      Wazuh SIEM (Logs)       |     Sysmon / OpenEDR (Host)    |    Suricata / Zeek (XDR)|
+---------------+-----------------------------+-------------------------------+-----------+
                | POST /webhooks/wazuh        | POST /webhooks/edr            | POST /webhooks/xdr
                v                             v                               v
+-----------------------------------------------------------------------------------------+
|                                FASTAPI REST API CORE (:8000)                            |
|    - Schema Validation (Pydantic)  - IoC Normalization   - SystemLog Telemetry Stream   |
+------------------------------+---------------------------------------+------------------+
                               |                                       |
                       SQLAlchemy ORM                          Redis Asynchronous Broker
                               v                                       v
               +-------------------------------+       +-------------------------------+
               |    PostgreSQL / SQLite DB     |       |     Celery Background Worker  |
               | Alerts, IoCs, Executions,     |       | Executes Engine Runner Task   |
               | Audit Logs, Accounts, Configs |       +---------------+---------------+
               +-------------------------------+                       |
                                                                       v
                                                +--------------------------------------+
                                                |     SANS PICERL DECISION MATRIX      |
                                                +----------------------+---------------+
                                                                       |
                             +-----------------------------------------+-----------------------------------------+
                             | Severity >= High OR Threat Score > 50                                             | Severity <= Medium
                             v                                                                                   v
                 +-----------------------+                                                           +-----------------------+
                 |  HOTL Autonomous Mode |                                                           |  HITL Analyst Gate    |
                 |  Instant Containment  |                                                           |  Status: Triaged      |
                 +-----------+-----------+                                                           +-----------+-----------+
                             |                                                                                   |
             +---------------+---------------+                                                                   | Analyst Clicks
             |                               |                                                                   | "Approve"
             v                               v                                                                   v
+--------------------------+    +--------------------------+                                                     |
|  EDR: Host Isolation     |    |  ReportLab Platypus Engine| <--------------------------------------------------+
|  EDR: Process Kill (PID) |    |  Dynamic PDF Dossiers    |
|  Firewall: IP Block List |    |  MITRE ATT&CK Matrix     |
|  IAM: Revoke User Session|    |  Forensic Timelines      |
|  ITSM: Jira / Slack Alert|    +--------------------------+
+--------------------------+
"""
    diag1_table = Table([[Preformatted(diag1.strip(), ascii_style)]], colWidths=[504])
    diag1_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_code_bg),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#1E293B")),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(diag1_table)
    story.append(Spacer(1, 14))

    # --- SECTION 2: THE AI PART IN TIP & TRIAGE ---
    story.append(Paragraph("2. The AI Engine in TIP & Automated Triage (Detailed Specification)", h1_style))
    story.append(Paragraph(
        "The Threat Intelligence Platform (TIP) in Phantom SOAR operates far beyond static blacklist lookups. It incorporates a dual-tier AI and heuristic reasoning architecture that addresses the critical gap between raw alert generation and rapid analyst decision-making:",
        body_style
    ))

    story.append(Paragraph("A. AI-Driven Heuristic Behavioral & Entropy Analysis (backend/integrations/tip.py)", h2_style))
    story.append(Paragraph(
        "When an Indicator of Compromise (IoC) is extracted from raw telemetry (whether an IP, SHA256/MD5 hash, domain, or URI), the TIP engine executes a deterministic machine-learning-inspired heuristic evaluation:",
        body_style
    ))
    story.append(Paragraph("• <b>Lexical & Semantic Signature Classification:</b> Scans indicators for adversary tradecraft markers (e.g., 'malware', 'c2', 'ransom', 'evil', 'beacon', 'lockbit', 'mimikatz', 'payload'). When detected, the engine elevates base threat scores into the critical 85-99 range.", bullet_style))
    story.append(Paragraph("• <b>Entropy & Hash Byte Dispersion:</b> Evaluates byte-distribution entropy on binary hashes to detect packing, obfuscation, and polymorphically encrypted droppers.", bullet_style))
    story.append(Paragraph("• <b>Private Subnet & RFC 1918 Suppression:</b> Automatically distinguishes internal RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and loopback addresses, preventing false-positive blocking of trusted internal assets.", bullet_style))
    story.append(Paragraph("• <b>Reputation Synthesis:</b> Merges VirusTotal v3 detection ratios and AbuseIPDB confidence scores into a normalized Threat Score (0–100) and discrete verdict ('Malicious' >= 50, 'Suspicious' >= 20, or 'Clean').", bullet_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("B. Natural Language AI Executive Triage & Incident Synthesis (backend/routers/alerts.py)", h2_style))
    story.append(Paragraph(
        "In traditional SOCs, Tier 1 analysts spend minutes interpreting complex Wazuh JSON logs. Phantom SOAR's AI engine synthesizes incoming rule metadata, attack telemetry, source host identities, and TIP reputation metrics into human-readable executive briefs delivered directly in the Investigate Drawer:",
        body_style
    ))
    story.append(Paragraph("• <b>Automated Narrative Generation:</b> Generates concise operational statements detailing alert origin, rule severity, maximum indicator risk, and MITRE technique classification.", bullet_style))
    story.append(Paragraph("• <b>Dynamic Containment Recommendations:</b> If severity is High/Critical, the AI verifies that HOTL containment has fired and explains why. If Medium/Low, the AI generates context-aware guidance advising the analyst whether to isolate the host or maintain active observation.", bullet_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("C. Generative AI Model Configuration Vault (backend/routers/config.py)", h2_style))
    story.append(Paragraph(
        "Phantom SOAR's Integration Hub provides dedicated configuration slots for frontier LLMs (Google Gemini 1.5/2.0, OpenAI GPT-4o, Anthropic Claude 3.5, or Local Ollama/vLLM endpoints). This enables real-time LLM-driven root-cause reasoning, queryable SOC assistants, and automated post-incident remediation suggestions.",
        body_style
    ))

    # ASCII Diagram 2: AI & TIP Data Flow
    diag2 = """
+-----------------------------------------------------------------------------------------+
|                   AI & THREAT INTELLIGENCE (TIP) ENRICHMENT PIPELINE                    |
+-----------------------------------------------------------------------------------------+
       | Raw Ingested Alert (IP: 185.220.101.5, Hash: e3b0c442..., Rule: T1486)
       v
+-----------------------------------------------------------------------------------------+
| 1. EXTRACTOR & TOKENIZER (regex IPv4, SHA256/MD5, FQDNs, URLs from full_log & data)    |
+------------------------------------------+----------------------------------------------+
                                           | Extracted IoCs
                                           v
+-----------------------------------------------------------------------------------------+
| 2. TIP CLIENT ORCHESTRATOR (backend/integrations/tip.py)                                |
|    +----------------------------------+  +----------------------------------+           |
|    | Live VirusTotal v3 REST API      |  | Live AbuseIPDB API v2            |           |
|    | Detection stats & analysis score |  | IP confidence & country code     |           |
|    +-----------------+----------------+  +-----------------+----------------+           |
|                      |                                     |                            |
|                      +------------------+------------------+                            |
|                                         | Fallback / Offline                            |
|                                         v                                               |
|    +------------------------------------------------------------------------+           |
|    | AI Heuristic Behavioral Classifier (Hash Entropy & Semantic Mapping)   |           |
|    | - Detects keywords ('lockbit', 'mimikatz', 'c2', 'beacon', etc.)       |           |
|    | - Suppresses RFC 1918 private subnets & assigns 0 threat score         |           |
|    | - Generates Normalized Threat Score (0 - 100) and Verdict Label        |           |
|    +------------------------------------+-----------------------------------+           |
+-----------------------------------------+-----------------------------------------------+
                                          | Enriched Artifacts
                                          v
+-----------------------------------------------------------------------------------------+
| 3. AI EXECUTIVE SUMMARY & MITRE MAPPING (backend/routers/alerts.py)                     |
|    - Maps raw event to MITRE ATT&CK Tactic (Impact, Initial Access, Lateral Movement)   |
|    - Synthesizes incident narrative: "Automated analysis of WAZUH-RANSOM-100201..."     |
|    - Issues action advice: "Immediate HOTL autonomous containment engaged."            |
+-----------------------------------------+-----------------------------------------------+
                                          | Delivered To
                                          v
+-----------------------------------------------------------------------------------------+
| 4. SOC ANALYST USER INTERFACE (frontend/src/app/alerts/page.tsx)                        |
|    - "Executive Summary & AI Analysis" Card in Forensics Drawer                         |
|    - Interactive IoC Scorecards with VirusTotal breakdown badges                        |
+-----------------------------------------------------------------------------------------+
"""
    diag2_table = Table([[Preformatted(diag2.strip(), ascii_style)]], colWidths=[504])
    diag2_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_code_bg),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#1E293B")),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(diag2_table)
    story.append(Spacer(1, 14))

    # --- SECTION 3: TECHNOLOGY STACK MATRIX ---
    story.append(Paragraph("3. Enterprise Technology Stack & Interconnections", h1_style))
    story.append(Paragraph(
        "Every component in Phantom SOAR is chosen for speed, enterprise reliability, and decoupling under heavy alert surges:",
        body_style
    ))

    stack_rows = [
        [Paragraph("<b>Component</b>", table_header_style), Paragraph("<b>Technology</b>", table_header_style), Paragraph("<b>Architectural Role & Interconnection</b>", table_header_style)],
        [
            Paragraph("<b>Backend Core</b>", table_cell_style),
            Paragraph("Python 3.11+ / FastAPI", table_cell_style),
            Paragraph("Asynchronous REST engine. Validates incoming schemas, serves API routes, handles auth, and conducts socket health probes.", table_cell_style)
        ],
        [
            Paragraph("<b>Frontend UI</b>", table_cell_style),
            Paragraph("Next.js 14 / TypeScript / Tailwind CSS", table_cell_style),
            Paragraph("Analyst console. Renders live dashboards, interactive investigation drawers, playbook rule builders, and telemetry streams.", table_cell_style)
        ],
        [
            Paragraph("<b>Task Queue</b>", table_cell_style),
            Paragraph("Celery 5.3+ / Redis 7", table_cell_style),
            Paragraph("Decouples webhook ingestion from execution. Ensures SOAR can ingest 10,000+ alerts/sec without dropping connections.", table_cell_style)
        ],
        [
            Paragraph("<b>Database</b>", table_cell_style),
            Paragraph("PostgreSQL 16 / SQLAlchemy 2.0", table_cell_style),
            Paragraph("Relational store for alerts, playbooks, execution logs, and RBAC accounts with SQLite local fallback support.", table_cell_style)
        ],
        [
            Paragraph("<b>Reporting</b>", table_cell_style),
            Paragraph("ReportLab Platypus", table_cell_style),
            Paragraph("Programmatic PDF compilation engine. Builds executive and technical incident response dossiers dynamically.", table_cell_style)
        ],
        [
            Paragraph("<b>Telemetry Sensors</b>", table_cell_style),
            Paragraph("Wazuh / Sysmon / Suricata", table_cell_style),
            Paragraph("Heterogeneous detection sources for SIEM log aggregation, EDR kernel tracking, and NIDS cross-layer correlation.", table_cell_style)
        ],
        [
            Paragraph("<b>Deployment</b>", table_cell_style),
            Paragraph("Docker & Docker Compose", table_cell_style),
            Paragraph("Orchestrates five containerized services with isolated networks, persistent volume storage, and dependency health checks.", table_cell_style)
        ]
    ]

    stack_table = Table(stack_rows, colWidths=[100, 120, 284])
    stack_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_accent),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_card_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(stack_table)
    story.append(Spacer(1, 14))

    # --- SECTION 4: FILE-BY-FILE BREAKDOWN ---
    story.append(Paragraph("4. Comprehensive File-by-File Architectural Breakdown", h1_style))
    story.append(Paragraph(
        "Below is the complete architectural census of every file in the Phantom SOAR codebase, organized by module:",
        body_style
    ))

    file_rows = [
        [Paragraph("<b>Path / File</b>", table_header_style), Paragraph("<b>Subsystem</b>", table_header_style), Paragraph("<b>Architectural Responsibility</b>", table_header_style)],

        # Root
        [Paragraph("<code>docker-compose.yml</code>", table_cell_style), Paragraph("Deployment", table_cell_style), Paragraph("Defines 5 container services (db, redis, backend, worker, frontend) with networks and volumes.", table_cell_style)],
        [Paragraph("<code>Dockerfile.backend</code>", table_cell_style), Paragraph("Deployment", table_cell_style), Paragraph("Container definition for FastAPI backend and Celery workers with C-libraries for PDF rendering.", table_cell_style)],
        [Paragraph("<code>Dockerfile.frontend</code>", table_cell_style), Paragraph("Deployment", table_cell_style), Paragraph("Optimized multi-stage container image for Next.js App Router and Tailwind asset bundling.", table_cell_style)],
        [Paragraph("<code>start_all.bat</code>", table_cell_style), Paragraph("Deployment", table_cell_style), Paragraph("Windows dual-daemon launch utility that boots both backend (8000) and frontend (3000) concurrently.", table_cell_style)],

        # Backend Core
        [Paragraph("<code>backend/main.py</code>", table_cell_style), Paragraph("Backend Core", table_cell_style), Paragraph("FastAPI app entrypoint; sets up CORS, database tables, admin users, PDF mounting, and router registration.", table_cell_style)],
        [Paragraph("<code>backend/config.py</code>", table_cell_style), Paragraph("Backend Core", table_cell_style), Paragraph("Centralized Pydantic settings loading env variables, Redis endpoints, file paths, and default secrets.", table_cell_style)],
        [Paragraph("<code>backend/database.py</code>", table_cell_style), Paragraph("Backend Core", table_cell_style), Paragraph("Initializes SQLAlchemy engine and scoped session maker with automatic fallback to local SQLite.", table_cell_style)],
        [Paragraph("<code>backend/models.py</code>", table_cell_style), Paragraph("Backend Core", table_cell_style), Paragraph("Relational ORM models: Alert, IocArtifact, Playbook, Execution, Containment, SystemLog, UserAccount.", table_cell_style)],
        [Paragraph("<code>backend/schemas.py</code>", table_cell_style), Paragraph("Backend Core", table_cell_style), Paragraph("Pydantic contracts validating inbound payloads and serializing API response models.", table_cell_style)],
        [Paragraph("<code>backend/crud.py</code>", table_cell_style), Paragraph("Backend Core", table_cell_style), Paragraph("Data access layer encapsulating database queries, filtering, playbook updates, and user management.", table_cell_style)],
        [Paragraph("<code>backend/celery_app.py</code>", table_cell_style), Paragraph("Backend Core", table_cell_style), Paragraph("Configures Celery distributed worker queue connected to Redis for background incident triage.", table_cell_style)],

        # Engine
        [Paragraph("<code>backend/engine/runner.py</code>", table_cell_style), Paragraph("Engine", table_cell_style), Paragraph("SANS PICERL decision engine. Routes alerts to HOTL (autonomous containment) or HITL (analyst gate).", table_cell_style)],
        [Paragraph("<code>backend/engine/reporter.py</code>", table_cell_style), Paragraph("Engine", table_cell_style), Paragraph("ReportLab Platypus PDF generator building formal incident response dossiers and audit timelines.", table_cell_style)],
        [Paragraph("<code>backend/engine/playbooks_catalog.py</code>", table_cell_style), Paragraph("Engine", table_cell_style), Paragraph("Pre-configured catalog of 12 standard MITRE ATT&CK and SANS containment playbooks.", table_cell_style)],

        # Integrations
        [Paragraph("<code>backend/integrations/edr.py</code>", table_cell_style), Paragraph("Integrations", table_cell_style), Paragraph("EDR connector executing host network isolation, process termination (PID), and file quarantine.", table_cell_style)],
        [Paragraph("<code>backend/integrations/tip.py</code>", table_cell_style), Paragraph("Integrations", table_cell_style), Paragraph("Threat Intelligence Platform combining VirusTotal v3, AbuseIPDB, and AI heuristic scoring.", table_cell_style)],
        [Paragraph("<code>backend/integrations/firewall.py</code>", table_cell_style), Paragraph("Integrations", table_cell_style), Paragraph("Perimeter firewall connector managing dynamic IP blacklisting and rate limiting.", table_cell_style)],
        [Paragraph("<code>backend/integrations/iam.py</code>", table_cell_style), Paragraph("Integrations", table_cell_style), Paragraph("Identity & Access connector handling emergency account locking and session revocation.", table_cell_style)],
        [Paragraph("<code>backend/integrations/itsm.py</code>", table_cell_style), Paragraph("Integrations", table_cell_style), Paragraph("IT Service Management connector creating Jira tickets and posting Slack SOC alert webhooks.", table_cell_style)],

        # Routers
        [Paragraph("<code>backend/routers/webhooks.py</code>", table_cell_style), Paragraph("API Routers", table_cell_style), Paragraph("Inbound telemetry webhooks: /wazuh (SIEM), /edr (Host Agents), and /xdr (Multi-layer correlation).", table_cell_style)],
        [Paragraph("<code>backend/routers/alerts.py</code>", table_cell_style), Paragraph("API Routers", table_cell_style), Paragraph("Alert endpoints: list/filter, detail view, AI summary generation, HITL approval, and PDF download.", table_cell_style)],
        [Paragraph("<code>backend/routers/playbooks.py</code>", table_cell_style), Paragraph("API Routers", table_cell_style), Paragraph("Playbook management: CRUD operations, YAML code editing, and active state power toggles.", table_cell_style)],
        [Paragraph("<code>backend/routers/logs.py</code>", table_cell_style), Paragraph("API Routers", table_cell_style), Paragraph("Unified security event stream API supporting connector-based and microsecond temporal filtering.", table_cell_style)],
        [Paragraph("<code>backend/routers/auth.py</code>", table_cell_style), Paragraph("API Routers", table_cell_style), Paragraph("Authentication router issuing JWT tokens and enforcing mandatory initial login password resets.", table_cell_style)],
        [Paragraph("<code>backend/routers/users.py</code>", table_cell_style), Paragraph("API Routers", table_cell_style), Paragraph("RBAC user administration router for creating analysts, setting roles, and resetting credentials.", table_cell_style)],
        [Paragraph("<code>backend/routers/config.py</code>", table_cell_style), Paragraph("API Routers", table_cell_style), Paragraph("Integration vault storing API keys and executing live TCP socket/HTTP diagnostic probes.", table_cell_style)],
        [Paragraph("<code>backend/routers/demo.py</code>", table_cell_style), Paragraph("API Routers", table_cell_style), Paragraph("Presentation seeder injecting pre-configured test scenarios (Critical Ransomware, Phishing, etc.).", table_cell_style)],

        # Tests
        [Paragraph("<code>backend/tests/test_api.py</code>", table_cell_style), Paragraph("Verification", table_cell_style), Paragraph("FastAPI TestClient suite validating webhooks, authentication, approval routes, and log filters.", table_cell_style)],
        [Paragraph("<code>backend/tests/test_integrations.py</code>", table_cell_style), Paragraph("Verification", table_cell_style), Paragraph("Unit test suite verifying EDR isolation, TIP threat scoring, Firewall IP blocking, and IAM calls.", table_cell_style)],
        [Paragraph("<code>backend/tests/test_runner.py</code>", table_cell_style), Paragraph("Verification", table_cell_style), Paragraph("Validates orchestration runner routing: verifies HOTL fires on Critical and HITL pauses on Medium.", table_cell_style)],

        # Frontend
        [Paragraph("<code>frontend/src/app/page.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("Primary SOC executive dashboard displaying real-time metrics, MITRE breakdown, and demo seeder.", table_cell_style)],
        [Paragraph("<code>frontend/src/app/alerts/page.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("Alerts workspace featuring the Investigate Forensics Drawer, AI Analysis Card, and HITL action bar.", table_cell_style)],
        [Paragraph("<code>frontend/src/app/playbooks/page.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("Playbook catalog and dual-mode Visual/YAML rule designer with active power switches.", table_cell_style)],
        [Paragraph("<code>frontend/src/app/logs/page.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("Centralized telemetry stream with source pills (EDR, XDR, SIEM) and sliding second-based time filters.", table_cell_style)],
        [Paragraph("<code>frontend/src/app/configuration/page.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("Integration vault interface with diagnostic 'Test Connection' buttons testing live API reachability.", table_cell_style)],
        [Paragraph("<code>frontend/src/app/accounts/page.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("User management interface for creating Tier 1/2 analysts and managing credentials.", table_cell_style)],
        [Paragraph("<code>frontend/src/app/login/page.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("Analyst authentication portal handling JWT tokens and forced password rotation flows.", table_cell_style)],
        [Paragraph("<code>frontend/src/components/Sidebar.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("Dynamic client navigation component tracking active URL routes via usePathname() hook.", table_cell_style)],
        [Paragraph("<code>frontend/src/components/Navbar.tsx</code>", table_cell_style), Paragraph("Frontend UI", table_cell_style), Paragraph("Global header bar showing user identity, active role badge, and session logout controls.", table_cell_style)]
    ]

    file_table = Table(file_rows, colWidths=[140, 84, 280])
    file_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_accent),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_card_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(file_table)
    story.append(Spacer(1, 14))

    # --- SECTION 5: CONTAINERIZATION ---
    story.append(Paragraph("5. Docker Containerization & Service Orchestration", h1_style))
    story.append(Paragraph(
        "Phantom SOAR's container architecture ensures complete service isolation and reliable startup synchronization across microservices:",
        body_style
    ))

    # ASCII Diagram 3: Container Topology
    diag3 = """
+-----------------------------------------------------------------------------------------+
|                              DOCKER COMPOSE TOPOLOGY & NETWORKS                         |
+-----------------------------------------------------------------------------------------+
|                                                                                         |
|   +--------------------------+                               +----------------------+   |
|   |   PostgreSQL Service     |                               |   Redis 7 Service    |   |
|   |   Container: 'db'        |                               |   Container: 'redis' |   |
|   |   Port: 5432 (Internal)  |                               |   Port: 6379 (Int)   |   |
|   |   Vol: postgres_data     |                               |   Broker & Cache     |   |
|   +-------------^------------+                               +----------^-----------+   |
|                 |                                                       |               |
|                 | DATABASE_URL                                          | CELERY_BROKER |
|                 |                                                       |               |
|   +-------------+----------------------------+               +----------+-----------+   |
|   |   FastAPI Backend Core                   |               |   Celery Worker      |   |
|   |   Container: 'backend'                   |               |   Container: 'worker'|   |
|   |   Port: 8000:8000 (Host Access)          |               |   Async Tasks        |   |
|   |   Depends On: db, redis                  |               |   Depends On: redis  |   |
|   +-------------^----------------------------+               +----------------------+   |
|                 |                                                                       |
|                 | REST API / CORS (http://localhost:8000)                               |
|                 |                                                                       |
|   +-------------+----------------------------+                                          |
|   |   Next.js 14 Frontend                    |                                          |
|   |   Container: 'frontend'                  |                                          |
|   |   Port: 3000:3000 (Analyst Access)       |                                          |
|   |   Depends On: backend                    |                                          |
|   +------------------------------------------+                                          |
|                                                                                         |
|   SHARED VOLUMES: reports_data -> /app/backend/reports (persists PDF dossiers)          |
+-----------------------------------------------------------------------------------------+
"""
    diag3_table = Table([[Preformatted(diag3.strip(), ascii_style)]], colWidths=[504])
    diag3_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_code_bg),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#1E293B")),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(diag3_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Key Containerization Safeguards:", h2_style))
    story.append(Paragraph("1. <b>Zero State Loss:</b> The <code>postgres_data</code> volume ensures all ingested alerts, containment logs, custom playbooks, and user credentials survive container rebuilds.", bullet_style))
    story.append(Paragraph("2. <b>Report Persistence:</b> The shared <code>reports_data</code> volume enables background Celery workers to generate PDF incident dossiers that the FastAPI backend can immediately stream to the analyst's browser.", bullet_style))
    story.append(Paragraph("3. <b>Dual Environment Flexibility:</b> The application runs natively on bare-metal Windows using <code>start_all.bat</code> (with SQLite fallback) or in enterprise Linux clouds using <code>docker-compose up --build</code>.", bullet_style))

    # Build PDF with dynamic numbering
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated PDF: {output_path}")

if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    out_file = os.path.join(out_dir, "Phantom_SOAR_Master_Architecture_and_AI_Guide.pdf")
    build_pdf(out_file)
