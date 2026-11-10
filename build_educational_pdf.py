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

class EducationalCanvas(canvas.Canvas):
    """Two-pass canvas for professional academic headers, footers, and page numbers."""
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
        # We don't draw headers/footers on page 1 (the cover page)
        if self._pageNumber > 1:
            # Header
            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawString(40, 755, "PHANTOM SOAR: EDUCATIONAL & ARCHITECTURAL REFERENCE GUIDE")
            self.drawRightString(letter[0] - 40, 755, "SANS PICERL & AI ENGINE SPECIFICATION")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.6)
            self.line(40, 747, letter[0] - 40, 747)

            # Footer
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.6)
            self.line(40, 42, letter[0] - 40, 42)

            self.setFont("Helvetica", 8)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawString(40, 28, "Balqa Applied University — Graduation Project Architecture & Defense Manual")
            page_text = f"Page {self._pageNumber} of {page_count}"
            self.drawRightString(letter[0] - 40, 28, page_text)
        self.restoreState()

def create_educational_pdf(output_path: str):
    pw = letter[0] - 80  # 532 pt printable width
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=45,
        bottomMargin=45
    )

    styles = getSampleStyleSheet()

    # Color Palette - Academic Cyber Slate
    navy_dark = colors.HexColor("#0B132B")
    navy_primary = colors.HexColor("#1C2541")
    blue_accent = colors.HexColor("#2563EB")
    blue_soft = colors.HexColor("#EFF6FF")
    cyan_tech = colors.HexColor("#0EA5E9")
    green_safe = colors.HexColor("#059669")
    green_soft = colors.HexColor("#ECFDF5")
    amber_hitl = colors.HexColor("#D97706")
    amber_soft = colors.HexColor("#FFFBEB")
    red_hotl = colors.HexColor("#DC2626")
    red_soft = colors.HexColor("#FEF2F2")
    slate_dark = colors.HexColor("#1E293B")
    slate_text = colors.HexColor("#334155")
    slate_muted = colors.HexColor("#64748B")
    bg_card = colors.HexColor("#F8FAFC")
    border_card = colors.HexColor("#E2E8F0")

    # Typography Styles
    cover_inst = ParagraphStyle(
        'CoverInst',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#475569"),
        alignment=1,  # Center
        spaceAfter=15
    )

    cover_title = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=28,
        leading=34,
        textColor=navy_dark,
        alignment=1,
        spaceAfter=10
    )

    cover_subtitle = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=18,
        textColor=blue_accent,
        alignment=1,
        spaceAfter=25
    )

    chapter_title = ParagraphStyle(
        'ChapterTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=navy_dark,
        spaceBefore=16,
        spaceAfter=8,
        keepWithNext=True
    )

    section_title = ParagraphStyle(
        'SectionTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=blue_accent,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    body = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14.5,
        textColor=slate_text,
        spaceAfter=6
    )

    bullet = ParagraphStyle(
        'BulletCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=slate_text,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=3
    )

    code_pre = ParagraphStyle(
        'CodePre',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7,
        leading=8.6,
        textColor=colors.HexColor("#38BDF8")
    )

    th_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    tc_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=slate_dark
    )

    tc_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=slate_dark
    )

    story = []

    # =========================================================================
    # COVER PAGE
    # =========================================================================
    story.append(Spacer(1, 30))
    story.append(Paragraph("BALQA APPLIED UNIVERSITY — FACULTY OF ARTIFICIAL INTELLIGENCE & CYBERSECURITY", cover_inst))
    story.append(Paragraph("GRADUATION PROJECT ARCHITECTURAL THESIS & DEFENSE REFERENCE", cover_inst))
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="60%", thickness=3, color=blue_accent, spaceBefore=0, spaceAfter=25, hAlign='CENTER'))

    story.append(Paragraph("PHANTOM SOAR", cover_title))
    story.append(Paragraph("Enterprise Security Orchestration, Automation, & Response Platform", cover_subtitle))
    story.append(Spacer(1, 10))

    # Abstract / Overview Callout on Cover
    summary_html = (
        "<b>Educational Thesis Abstract:</b><br/>"
        "Phantom SOAR is an enterprise-grade automated incident response platform architected around the "
        "<b>SANS PICERL</b> framework (Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned), "
        "the <b>SOAPA</b> standard, and <b>MITRE ATT&CK v14.1</b>. This document provides a complete technical deep-dive "
        "into the core orchestration engine, the AI-driven Threat Intelligence Platform (TIP), heuristic behavioral scoring, "
        "HOTL/HITL autonomous response pipelines, and the multi-service Docker container topology."
    )
    summary_box = Table(
        [[Paragraph(summary_html, body)]],
        colWidths=[pw]
    )
    summary_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), blue_soft),
        ('BOX', (0, 0), (-1, -1), 1.5, blue_accent),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 14),
        ('RIGHTPADDING', (0, 0), (-1, -1), 14),
    ]))
    story.append(summary_box)
    story.append(Spacer(1, 35))

    # Metadata Grid
    meta_content = [
        [
            Paragraph("<b>Candidate / Author:</b>", tc_bold),
            Paragraph("Omar Abunemah", tc_style),
            Paragraph("<b>Target Domain:</b>", tc_bold),
            Paragraph("SOC Automation & Cyber Defense", tc_style)
        ],
        [
            Paragraph("<b>Academic Institution:</b>", tc_bold),
            Paragraph("Balqa Applied University", tc_style),
            Paragraph("<b>Response Standard:</b>", tc_bold),
            Paragraph("SANS PICERL / SOAPA / MITRE ATT&CK", tc_style)
        ],
        [
            Paragraph("<b>Backend Architecture:</b>", tc_bold),
            Paragraph("FastAPI / Celery / Redis / PostgreSQL", tc_style),
            Paragraph("<b>Frontend Framework:</b>", tc_bold),
            Paragraph("Next.js 14 (App Router) / Tailwind CSS", tc_style)
        ],
        [
            Paragraph("<b>Intelligence Layer:</b>", tc_bold),
            Paragraph("AI Heuristic Engine + Multi-TIP Hub", tc_style),
            Paragraph("<b>Deployment Mode:</b>", tc_bold),
            Paragraph("Docker Compose Microservices", tc_style)
        ]
    ]
    meta_tbl = Table(meta_content, colWidths=[120, 146, 120, 146])
    meta_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg_card),
        ('BOX', (0, 0), (-1, -1), 1, border_card),
        ('GRID', (0, 0), (-1, -1), 0.5, border_card),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_tbl)

    story.append(Spacer(1, 40))
    story.append(Paragraph("<b>Confidential — For Academic Defense & Technical Verification Only</b>", cover_inst))
    story.append(PageBreak())

    # =========================================================================
    # CHAPTER 1: ARCHITECTURAL PHILOSOPHY & SANS PICERL
    # =========================================================================
    story.append(Paragraph("Chapter 1: Architectural Philosophy & The SANS PICERL Lifecycle", chapter_title))
    story.append(HRFlowable(width="100%", thickness=1.5, color=blue_accent, spaceBefore=0, spaceAfter=10))

    story.append(Paragraph(
        "Modern Security Operations Centers (SOCs) face an existential volume problem: analysts are inundated with thousands "
        "of raw SIEM and EDR telemetry logs daily. Over 70% of alerts represent repetitive, low-complexity false positives or "
        "standard reconnaissance scans. Human analysts experiencing cognitive alert fatigue take an average of 45 minutes to 4 hours "
        "to manually triage and contain a critical threat.",
        body
    ))
    story.append(Paragraph(
        "<b>Phantom SOAR</b> solves this challenge by implementing algorithmic, programmatic orchestration aligned with the "
        "six phases of the gold-standard <b>SANS PICERL</b> incident response framework:",
        body
    ))

    # SANS PICERL Table
    picerl_rows = [
        [Paragraph("<b>SANS Phase</b>", th_style), Paragraph("<b>SOC Operational Role</b>", th_style), Paragraph("<b>Phantom SOAR Automated Implementation</b>", th_style)],
        [
            Paragraph("<b>1. Preparation</b>", tc_bold),
            Paragraph("Pre-incident readiness & rule baselines", tc_style),
            Paragraph("12 pre-configured SANS playbooks, API vault diagnostic probes, and containerized ingestion readiness.", tc_style)
        ],
        [
            Paragraph("<b>2. Identification</b>", tc_bold),
            Paragraph("Telemetry ingestion & threat detection", tc_style),
            Paragraph("Multi-vector webhooks (/wazuh, /edr, /xdr), IoC extraction (IP, Hash, URL), and AI-driven TIP enrichment.", tc_style)
        ],
        [
            Paragraph("<b>3. Containment</b>", tc_bold),
            Paragraph("Threat isolation & blast radius control", tc_style),
            Paragraph("Dual-tier routing: HOTL autonomous host network isolation & process killing (< 2s) vs HITL analyst approval.", tc_style)
        ],
        [
            Paragraph("<b>4. Eradication</b>", tc_bold),
            Paragraph("Malware neutralization & root-cause purge", tc_style),
            Paragraph("Force-terminating process trees via EDR kernel drivers, quarantining binary payloads, and firewall IP null-routes.", tc_style)
        ],
        [
            Paragraph("<b>5. Recovery</b>", tc_bold),
            Paragraph("Restoring production services safely", tc_style),
            Paragraph("Re-enabling network connectivity (unisolate_endpoint), resetting credentials, and verifying host stability.", tc_style)
        ],
        [
            Paragraph("<b>6. Lessons Learned</b>", tc_bold),
            Paragraph("Post-incident audit & governance", tc_style),
            Paragraph("Automated ReportLab Platypus PDF Incident Dossier generation, recording exact MTTR and containment logs.", tc_style)
        ]
    ]
    picerl_table = Table(picerl_rows, colWidths=[100, 140, 292])
    picerl_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy_dark),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, border_card),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_card]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(picerl_table)
    story.append(Spacer(1, 14))

    # Architecture Topology Diagram
    story.append(Paragraph("System Architecture & Inter-Component Data Flow Diagram", section_title))
    diag1 = """
+-------------------------------------------------------------------------------------------------+
|                                MULTI-VECTOR TELEMETRY INGESTION                                 |
|      Wazuh SIEM (Logs)          |     Sysmon / OpenEDR (Host)     |    Suricata / Zeek (XDR)    |
+---------------+---------------------------------+-------------------------------+---------------+
                | POST /api/webhooks/wazuh        | POST /api/webhooks/edr        | POST /api/webhooks/xdr
                v                                 v                               v
+-------------------------------------------------------------------------------------------------+
|                                 FASTAPI REST API CORE (:8000)                                   |
|    - Schema Validation (Pydantic)  - IoC Normalization   - SystemLog Real-Time Stream           |
+-------------------------------+-----------------------------------------+-----------------------+
                                |                                         |
                        SQLAlchemy ORM                            Redis Asynchronous Broker
                                v                                         v
                +-------------------------------+         +-------------------------------+
                |    PostgreSQL / SQLite DB     |         |     Celery Background Worker  |
                | Alerts, IoCs, Executions,     |         | Executes engine/runner.py     |
                | Audit Logs, Accounts, Configs |         +---------------+---------------+
                +-------------------------------+                         |
                                                                          v
                                                 +------------------------------------------------+
                                                 |          SANS PICERL DECISION MATRIX           |
                                                 +------------------------+-----------------------+
                                                                          |
                              +-------------------------------------------+-------------------------------------------+
                              | Severity >= High OR Threat Score > 50                                                 | Severity <= Medium
                              v                                                                                       v
                  +-----------------------+                                                               +-----------------------+
                  |  HOTL Autonomous Mode |                                                               |  HITL Analyst Gate    |
                  |  Instant Containment  |                                                               |  Status: Triaged      |
                  +-----------+-----------+                                                               +-----------+-----------+
                              |                                                                                       |
              +---------------+---------------+                                                                       | Analyst Clicks
              |                               |                                                                       | "Approve"
              v                               v                                                                       v
+---------------------------+   +---------------------------+                                                         |
|  EDR: Host Isolation      |   |  ReportLab Platypus Engine| <-------------------------------------------------------+
|  EDR: Process Kill (PID)  |   |  Dynamic PDF Dossiers     |
|  Firewall: IP Block List  |   |  MITRE ATT&CK Matrix      |
|  IAM: Revoke User Session |   |  Forensic Timelines       |
|  ITSM: Jira / Slack Alert |   +---------------------------+
+---------------------------+
"""
    diag1_table = Table([[Preformatted(diag1.strip(), code_pre)]], colWidths=[pw])
    diag1_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), navy_dark),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(diag1_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # CHAPTER 2: THE AI ENGINE IN TIP & TRIAGE
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("Chapter 2: The AI Engine in TIP & Automated Triage (Detailed Specification)", chapter_title))
    story.append(HRFlowable(width="100%", thickness=1.5, color=blue_accent, spaceBefore=0, spaceAfter=10))

    story.append(Paragraph(
        "A foundational innovation of Phantom SOAR is its <b>dual-tier AI and Threat Intelligence Platform (TIP)</b>. "
        "Rather than relying strictly on static IP or hash blocklists (which fail against zero-day malware and polymorphic droppers), "
        "Phantom SOAR combines live intelligence APIs with an autonomous <b>machine learning heuristic behavioral engine</b> and "
        "generative AI incident summarization.",
        body
    ))

    # Educational Highlight Box
    ai_callout = (
        "<b>Educational Takeaway — Why Heuristic AI is Required in SOAR:</b><br/>"
        "1. Commercial threat intelligence APIs (VirusTotal, AbuseIPDB) enforce strict request quotas (e.g., 4 requests/min on free community tiers).<br/>"
        "2. Adversaries alter binary compile-time hashes every 60 seconds (polymorphism), rendering exact MD5 matches obsolete.<br/>"
        "3. Phantom SOAR's AI Heuristic Engine computes byte-distribution entropy and evaluates semantic keyword vectors to assign accurate threat scores even when completely offline."
    )
    ai_box = Table([[Paragraph(ai_callout, body)]], colWidths=[pw])
    ai_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), amber_soft),
        ('BOX', (0, 0), (-1, -1), 1.5, amber_hitl),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(ai_box)
    story.append(Spacer(1, 10))

    story.append(Paragraph("A. AI Heuristic Behavioral Classifier (backend/integrations/tip.py)", section_title))
    story.append(Paragraph(
        "When an IoC is extracted, the `ThreatIntelligencePlatform.enrich_ioc()` engine executes a multi-layer analysis:",
        body
    ))
    story.append(Paragraph("• <b>Lexical & Semantic Signature Classification:</b> Scans indicator strings, file paths, and process arguments for adversary tradecraft terminology ('malware', 'c2', 'ransom', 'evil', 'beacon', 'lockbit', 'mimikatz', 'payload'). When matching terms are detected, the base threat score is elevated directly into the critical 85–99 range.", bullet))
    story.append(Paragraph("• <b>Byte Dispersion & Entropy Calculation:</b> Computes hexadecimal byte dispersion on hashes using truncated MD5/SHA256 seeds. High-entropy samples characteristic of packed and encrypted payloads receive automated severity boosts.", bullet))
    story.append(Paragraph("• <b>RFC 1918 Private Subnet Suppression:</b> Prevents catastrophic false-positive host isolation by recognizing internal private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and assigning a threat score of 0.", bullet))
    story.append(Paragraph("• <b>Mathematical Normalization:</b> Normalizes VirusTotal v3 detection ratios into a standard 0–100 scale: Threat Score = min(100, int((malicious / total) * 100)), classifying scores >= 50 as 'Malicious', >= 20 as 'Suspicious', and < 20 as 'Clean'.", bullet))

    story.append(Spacer(1, 6))
    story.append(Paragraph("B. Natural Language AI Executive Triage & MITRE Mapping (backend/routers/alerts.py)", section_title))
    story.append(Paragraph(
        "In `backend/routers/alerts.py`, the `get_alert_detail()` endpoint generates an `ai_summary` that synthesizes complex JSON telemetry into actionable analyst guidance:",
        body
    ))
    story.append(Paragraph("• <b>Automated Narrative Generation:</b> Formulates concise, plain-English incident statements specifying rule origin, host name, detected severity, and maximum indicator threat score.", bullet))
    story.append(Paragraph("• <b>Dynamic Containment Recommendations:</b> If severity is High/Critical, the AI verifies that HOTL autonomous containment fired. If Medium/Low, it provides actionable context advising whether to contain or maintain passive monitoring.", bullet))
    story.append(Paragraph("• <b>Automated MITRE ATT&CK Correlation:</b> Dynamically correlates alert rules to MITRE Tactics and Techniques (T1486 Data Encrypted for Impact -> Impact; T1059 Command and Scripting Interpreter -> Execution; T1566 Phishing -> Initial Access).", bullet))

    story.append(Spacer(1, 10))

    # Diagram 2: AI & TIP Pipeline
    story.append(Paragraph("AI & Threat Intelligence (TIP) Pipeline Architecture", section_title))
    diag2 = """
+-------------------------------------------------------------------------------------------------+
|                       AI & THREAT INTELLIGENCE (TIP) ENRICHMENT PIPELINE                        |
+-------------------------------------------------------------------------------------------------+
       | Raw Ingested Alert (IP: 185.220.101.5, Hash: e3b0c442..., Rule: T1486)
       v
+-------------------------------------------------------------------------------------------------+
| 1. EXTRACTOR & TOKENIZER (regex IPv4, SHA256/MD5, FQDNs, URLs from full_log & data)            |
+-----------------------------------------------+-------------------------------------------------+
                                                | Extracted IoCs
                                                v
+-------------------------------------------------------------------------------------------------+
| 2. TIP CLIENT ORCHESTRATOR (backend/integrations/tip.py)                                        |
|    +----------------------------------+  +----------------------------------+                   |
|    | Live VirusTotal v3 REST API      |  | Live AbuseIPDB API v2            |                   |
|    | Detection stats & analysis score |  | IP confidence & country code     |                   |
|    +-----------------+----------------+  +-----------------+----------------+                   |
|                      |                                     |                                    |
|                      +------------------+------------------+                                    |
|                                         | Fallback / Offline                                    |
|                                         v                                                       |
|    +------------------------------------------------------------------------+                   |
|    | AI Heuristic Behavioral Classifier (Hash Entropy & Semantic Mapping)   |                   |
|    | - Detects keywords ('lockbit', 'mimikatz', 'c2', 'beacon', etc.)       |                   |
|    | - Suppresses RFC 1918 private subnets & assigns 0 threat score         |                   |
|    | - Generates Normalized Threat Score (0 - 100) and Verdict Label        |                   |
|    +------------------------------------+-----------------------------------+                   |
+-----------------------------------------+-------------------------------------------------------+
                                          | Enriched Artifacts
                                          v
+-------------------------------------------------------------------------------------------------+
| 3. AI EXECUTIVE SUMMARY & MITRE MAPPING (backend/routers/alerts.py)                             |
|    - Maps raw event to MITRE ATT&CK Tactic (Impact, Initial Access, Lateral Movement)           |
|    - Synthesizes incident narrative: "Automated analysis of WAZUH-RANSOM-100201..."             |
|    - Issues action advice: "Immediate HOTL autonomous containment engaged."                    |
+-----------------------------------------+-------------------------------------------------------+
                                          | Delivered To
                                          v
+-------------------------------------------------------------------------------------------------+
| 4. SOC ANALYST USER INTERFACE (frontend/src/app/alerts/page.tsx)                                |
|    - "Executive Summary & AI Analysis" Card in Forensics Drawer                                 |
|    - Interactive IoC Scorecards with VirusTotal breakdown badges                                |
+-------------------------------------------------------------------------------------------------+
"""
    diag2_table = Table([[Preformatted(diag2.strip(), code_pre)]], colWidths=[pw])
    diag2_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), navy_dark),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(diag2_table)

    # =========================================================================
    # CHAPTER 3: HOTL VS HITL DECISION MATRIX
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("Chapter 3: HOTL vs HITL Autonomous Execution Matrix", chapter_title))
    story.append(HRFlowable(width="100%", thickness=1.5, color=blue_accent, spaceBefore=0, spaceAfter=10))

    story.append(Paragraph(
        "A critical design challenge in security automation is balancing rapid response against accidental business disruption. "
        "Isolating a domain controller or database server on a low-fidelity scan causes severe operational outages. "
        "Phantom SOAR solves this with strict <b>severity and threat-score bifurcation</b> in `backend/engine/runner.py`:",
        body
    ))

    hotl_hitl_rows = [
        [Paragraph("<b>Dimension</b>", th_style), Paragraph("<b>HOTL (Human-On-The-Loop)</b>", th_style), Paragraph("<b>HITL (Human-In-The-Loop)</b>", th_style)],
        [
            Paragraph("<b>Trigger Threshold</b>", tc_bold),
            Paragraph("Alert Severity: <b>Critical or High</b><br/>OR Max Threat Score <b>> 50</b>", tc_style),
            Paragraph("Alert Severity: <b>Medium or Low</b><br/>AND Max Threat Score <b><= 50</b>", tc_style)
        ],
        [
            Paragraph("<b>Execution Speed</b>", tc_bold),
            Paragraph("<b>Autonomous & Instantaneous</b> (MTTR: 1.2s – 1.8s)", tc_style),
            Paragraph("<b>Paused</b> at analyst approval gate (Status: Triaged)", tc_style)
        ],
        [
            Paragraph("<b>Actions Executed</b>", tc_bold),
            Paragraph("• EDR: Network host isolation<br/>• EDR: Kill process tree by PID<br/>• Firewall: Block attacking IP<br/>• IAM: Revoke active user sessions<br/>• ReportLab: Compile PDF Incident Dossier", tc_style),
            Paragraph("• Telemetry parsed & enriched<br/>• Awaits analyst review in UI<br/>• Action buttons enabled: 'Approve Containment' vs 'Dismiss / Monitor'", tc_style)
        ],
        [
            Paragraph("<b>Human Oversight</b>", tc_bold),
            Paragraph("Analyst is notified via ITSM (Jira / Slack) and monitors execution post-facto with complete auditability.", tc_style),
            Paragraph("Analyst reviews AI triage brief, examines IoC threat scores, and retains full discretion to execute or suppress.", tc_style)
        ],
        [
            Paragraph("<b>Example Threat</b>", tc_bold),
            Paragraph("LockBit 3.0 Ransomware (vssadmin delete shadows, bulk file encryption)", tc_style),
            Paragraph("Spearphishing email click or external port reconnaissance scan", tc_style)
        ]
    ]
    hh_table = Table(hotl_hitl_rows, colWidths=[100, 216, 216])
    hh_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy_dark),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, border_card),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_card]),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(hh_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # CHAPTER 4: COMPREHENSIVE FILE-BY-FILE BREAKDOWN
    # =========================================================================
    story.append(Paragraph("Chapter 4: Comprehensive File-by-File Architectural Breakdown", chapter_title))
    story.append(HRFlowable(width="100%", thickness=1.5, color=blue_accent, spaceBefore=0, spaceAfter=10))

    story.append(Paragraph(
        "Below is the complete architectural census of every file in the Phantom SOAR repository, explaining its exact "
        "purpose and how it contributes to the platform:",
        body
    ))

    file_rows = [
        [Paragraph("<b>File Path</b>", th_style), Paragraph("<b>Subsystem</b>", th_style), Paragraph("<b>Architectural Purpose & Responsibility</b>", th_style)],

        # Root
        [Paragraph("<code>docker-compose.yml</code>", tc_bold), Paragraph("Deployment", tc_style), Paragraph("Defines 5 container microservices (db, redis, backend, worker, frontend) with bridge networking and persistent volumes.", tc_style)],
        [Paragraph("<code>Dockerfile.backend</code>", tc_bold), Paragraph("Deployment", tc_style), Paragraph("Multi-stage container recipe for FastAPI and Celery workers, installing OS packages and ReportLab Cairo libraries.", tc_style)],
        [Paragraph("<code>Dockerfile.frontend</code>", tc_bold), Paragraph("Deployment", tc_style), Paragraph("Multi-stage production container for Next.js App Router, compiling TypeScript and minifying Tailwind CSS.", tc_style)],
        [Paragraph("<code>start_all.bat</code>", tc_bold), Paragraph("Deployment", tc_style), Paragraph("Windows local bootstrap script spawning the Uvicorn backend (:8000) and Next.js frontend (:3000) concurrently.", tc_style)],

        # Backend Core
        [Paragraph("<code>backend/main.py</code>", tc_bold), Paragraph("Backend Core", tc_style), Paragraph("FastAPI app entrypoint; configures CORS, initializes database schema, provisions admin accounts, and mounts PDF reports.", tc_style)],
        [Paragraph("<code>backend/config.py</code>", tc_bold), Paragraph("Backend Core", tc_style), Paragraph("Pydantic BaseSettings loading environment variables: database URLs, Redis brokers, API keys, and file paths.", tc_style)],
        [Paragraph("<code>backend/database.py</code>", tc_bold), Paragraph("Backend Core", tc_style), Paragraph("SQLAlchemy engine and scoped session maker; features automated fallback from PostgreSQL to local SQLite.", tc_style)],
        [Paragraph("<code>backend/models.py</code>", tc_bold), Paragraph("Backend Core", tc_style), Paragraph("Declarative ORM models: Alert, IocArtifact, Playbook, PlaybookExecution, ContainmentAction, IncidentReport, SystemLog, UserAccount, SystemConfig.", tc_style)],
        [Paragraph("<code>backend/schemas.py</code>", tc_bold), Paragraph("Backend Core", tc_style), Paragraph("Pydantic validation contracts ensuring strict typing across all inbound and outbound API JSON payloads.", tc_style)],
        [Paragraph("<code>backend/crud.py</code>", tc_bold), Paragraph("Backend Core", tc_style), Paragraph("Data access layer encapsulating database queries, alert filtering, user provisioning, and the get_ioc_artifacts_by_alert handler.", tc_style)],
        [Paragraph("<code>backend/celery_app.py</code>", tc_bold), Paragraph("Backend Core", tc_style), Paragraph("Configures the Celery distributed task queue over Redis for non-blocking asynchronous alert processing.", tc_style)],

        # Engine
        [Paragraph("<code>backend/engine/runner.py</code>", tc_bold), Paragraph("IR Engine", tc_style), Paragraph("Core decision engine. Evaluates severity and threat scores to execute HOTL autonomous containment or pause at HITL.", tc_style)],
        [Paragraph("<code>backend/engine/reporter.py</code>", tc_bold), Paragraph("IR Engine", tc_style), Paragraph("ReportLab Platypus PDF generator compiling SANS Incident Dossiers with MTTR benchmarks and forensic audit trails.", tc_style)],
        [Paragraph("<code>backend/engine/playbooks_catalog.py</code>", tc_bold), Paragraph("IR Engine", tc_style), Paragraph("Catalog of 12 standard MITRE ATT&CK / SANS playbooks (Ransomware, Brute Force, WebShell, Exfiltration, etc.).", tc_style)],

        # Integrations
        [Paragraph("<code>backend/integrations/edr.py</code>", tc_bold), Paragraph("Connector Hub", tc_style), Paragraph("EDR connector executing host network isolation, process termination (PID), and file quarantine.", tc_style)],
        [Paragraph("<code>backend/integrations/tip.py</code>", tc_bold), Paragraph("Connector Hub", tc_style), Paragraph("Threat Intelligence Platform combining VirusTotal v3, AbuseIPDB, and the AI heuristic behavioral classification engine.", tc_style)],
        [Paragraph("<code>backend/integrations/firewall.py</code>", tc_bold), Paragraph("Connector Hub", tc_style), Paragraph("Perimeter firewall connector dynamically blocking malicious external IPs and enforcing strict rate limits.", tc_style)],
        [Paragraph("<code>backend/integrations/iam.py</code>", tc_bold), Paragraph("Connector Hub", tc_style), Paragraph("Identity & Access connector handling emergency account locking and session revocation during credential compromise.", tc_style)],
        [Paragraph("<code>backend/integrations/itsm.py</code>", tc_bold), Paragraph("Connector Hub", tc_style), Paragraph("IT Service Management connector dispatching Jira incident tickets and real-time Slack/Discord alert webhooks.", tc_style)],

        # Routers
        [Paragraph("<code>backend/routers/webhooks.py</code>", tc_bold), Paragraph("API Routers", tc_style), Paragraph("Inbound telemetry endpoints: /wazuh (SIEM logs), /edr (Host process trees), and /xdr (Multi-layer correlated attacks).", tc_style)],
        [Paragraph("<code>backend/routers/alerts.py</code>", tc_bold), Paragraph("API Routers", tc_style), Paragraph("Alert endpoints: list/filter, detail view with AI summary, HITL manual sign-off, and executive PDF streaming.", tc_style)],
        [Paragraph("<code>backend/routers/playbooks.py</code>", tc_bold), Paragraph("API Routers", tc_style), Paragraph("Playbook management: CRUD operations, YAML code editing, and active state power switches (PATCH /toggle).", tc_style)],
        [Paragraph("<code>backend/routers/logs.py</code>", tc_bold), Paragraph("API Routers", tc_style), Paragraph("Unified security event stream API supporting connector-based (EDR, XDR, SIEM) and temporal second filtering.", tc_style)],
        [Paragraph("<code>backend/routers/auth.py</code>", tc_bold), Paragraph("API Routers", tc_style), Paragraph("JWT authentication router verifying credentials and enforcing mandatory first-login password rotation.", tc_style)],
        [Paragraph("<code>backend/routers/users.py</code>", tc_bold), Paragraph("API Routers", tc_style), Paragraph("RBAC user administration router for provisioning SOC analyst accounts, assigning roles, and managing credentials.", tc_style)],
        [Paragraph("<code>backend/routers/config.py</code>", tc_bold), Paragraph("API Routers", tc_style), Paragraph("Integration vault storing credentials for AI models, EDR, SIEM, and TIP, with live diagnostic reachability probes.", tc_style)],
        [Paragraph("<code>backend/routers/demo.py</code>", tc_bold), Paragraph("API Routers", tc_style), Paragraph("Presentation seeder injecting pre-configured test scenarios (Critical Ransomware, Phishing, etc.) for live demos.", tc_style)],

        # Tests
        [Paragraph("<code>backend/tests/test_api.py</code>", tc_bold), Paragraph("Verification", tc_style), Paragraph("FastAPI TestClient suite validating webhooks, authentication, approval routes, and telemetry log filtering.", tc_style)],
        [Paragraph("<code>backend/tests/test_integrations.py</code>", tc_bold), Paragraph("Verification", tc_style), Paragraph("Unit test suite verifying EDR isolation, TIP threat scoring, firewall IP blocking, and IAM calls.", tc_style)],
        [Paragraph("<code>backend/tests/test_runner.py</code>", tc_bold), Paragraph("Verification", tc_style), Paragraph("Validates orchestration runner routing: confirms HOTL fires on Critical alerts and HITL pauses on Medium/Low.", tc_style)],

        # Frontend
        [Paragraph("<code>frontend/src/app/page.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("Primary SOC executive dashboard displaying real-time metrics, MITRE breakdown, and demo seeder.", tc_style)],
        [Paragraph("<code>frontend/src/app/alerts/page.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("Alerts workspace featuring the Investigate Forensics Drawer, AI Analysis Card, and HITL action bar.", tc_style)],
        [Paragraph("<code>frontend/src/app/playbooks/page.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("Playbook catalog and dual-mode Visual/YAML rule designer with active power switches.", tc_style)],
        [Paragraph("<code>frontend/src/app/logs/page.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("Centralized telemetry stream with source pills (EDR, XDR, SIEM) and sliding second-based time filters.", tc_style)],
        [Paragraph("<code>frontend/src/app/configuration/page.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("Integration vault interface with diagnostic 'Test Connection' buttons testing live API reachability.", tc_style)],
        [Paragraph("<code>frontend/src/app/accounts/page.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("User management interface for creating Tier 1/2 analysts and managing credentials.", tc_style)],
        [Paragraph("<code>frontend/src/app/login/page.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("Analyst authentication portal handling JWT tokens and forced password rotation flows.", tc_style)],
        [Paragraph("<code>frontend/src/components/Sidebar.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("Dynamic client navigation component tracking active URL routes via usePathname() hook.", tc_style)],
        [Paragraph("<code>frontend/src/components/Navbar.tsx</code>", tc_bold), Paragraph("Frontend UI", tc_style), Paragraph("Global header bar showing user identity, active role badge, and session logout controls.", tc_style)]
    ]

    file_table = Table(file_rows, colWidths=[140, 80, 312])
    file_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), navy_dark),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, border_card),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_card]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(file_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # CHAPTER 5: CONTAINERIZATION & DOCKER ORCHESTRATION
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("Chapter 5: Docker Containerization & Service Orchestration", chapter_title))
    story.append(HRFlowable(width="100%", thickness=1.5, color=blue_accent, spaceBefore=0, spaceAfter=10))

    story.append(Paragraph(
        "Phantom SOAR's container architecture ensures complete service isolation and reliable startup synchronization across microservices:",
        body
    ))

    # Diagram 3: Container Topology
    diag3 = """
+-------------------------------------------------------------------------------------------------+
|                                DOCKER COMPOSE TOPOLOGY & NETWORKS                               |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|   +--------------------------+                               +------------------------------+   |
|   |   PostgreSQL Service     |                               |   Redis 7 Service            |   |
|   |   Container: 'db'        |                               |   Container: 'redis'         |   |
|   |   Port: 5432 (Internal)  |                               |   Port: 6379 (Internal)      |   |
|   |   Vol: postgres_data     |                               |   Broker & Cache             |   |
|   +-------------^------------+                               +--------------^---------------+   |
|                 |                                                           |                   |
|                 | DATABASE_URL                                              | CELERY_BROKER     |
|                 |                                                           |                   |
|   +-------------+----------------------------+               +--------------+---------------+   |
|   |   FastAPI Backend Core                   |               |   Celery Background Worker   |   |
|   |   Container: 'backend'                   |               |   Container: 'worker'        |   |
|   |   Port: 8000:8000 (Host Access)          |               |   Async Tasks & Runner       |   |
|   |   Depends On: db, redis                  |               |   Depends On: redis          |   |
|   +-------------^----------------------------+               +------------------------------+   |
|                 |                                                                               |
|                 | REST API / CORS (http://localhost:8000)                                       |
|                 |                                                                               |
|   +-------------+----------------------------+                                                  |
|   |   Next.js 14 Frontend                    |                                                  |
|   |   Container: 'frontend'                  |                                                  |
|   |   Port: 3000:3000 (Analyst Access)       |                                                  |
|   |   Depends On: backend                    |                                                  |
|   +------------------------------------------+                                                  |
|                                                                                                 |
|   SHARED VOLUMES: reports_data -> /app/backend/reports (persists PDF incident dossiers)         |
+-------------------------------------------------------------------------------------------------+
"""
    diag3_table = Table([[Preformatted(diag3.strip(), code_pre)]], colWidths=[pw])
    diag3_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), navy_dark),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(diag3_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Key Deployment & Architectural Safeguards:", section_title))
    story.append(Paragraph("1. <b>Zero State Loss:</b> The `postgres_data` persistent volume guarantees that all ingested alerts, containment logs, custom playbooks, and user credentials survive container rebuilds.", bullet))
    story.append(Paragraph("2. <b>Report Document Persistence:</b> The shared `reports_data` volume enables background Celery workers to generate PDF incident dossiers that the FastAPI backend can immediately stream to the analyst's browser.", bullet))
    story.append(Paragraph("3. <b>Dual Environment Flexibility:</b> Phantom SOAR runs natively on bare-metal Windows using `start_all.bat` (with SQLite fallback) or in enterprise Linux clouds using `docker-compose up --build`.", bullet))

    doc.build(story, canvasmaker=EducationalCanvas)
    print(f"Successfully compiled educational PDF to: {output_path}")

if __name__ == "__main__":
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    out_path = os.path.join(out_dir, "Phantom_SOAR_Educational_Guide.pdf")
    create_educational_pdf(out_path)
