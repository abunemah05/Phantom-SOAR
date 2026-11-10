"""Incident PDF report (ReportLab Platypus).

The report only shows what the platform recorded for the alert: telemetry,
IOC verdicts and their evidence sources, the MITRE mapping from telemetry or
the matched playbook, every response action with its target, connector and
execution mode, and the real MTTR. When any action was simulated the report
carries a prominent SIMULATED notice.
"""
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from backend.config import settings

PRIMARY = colors.HexColor("#0f172a")
ACCENT_BLUE = colors.HexColor("#2563eb")
ACCENT_RED = colors.HexColor("#dc2626")
ACCENT_AMBER = colors.HexColor("#d97706")
ACCENT_GREEN = colors.HexColor("#16a34a")
MUTED = colors.HexColor("#64748b")
HEADER_BG = colors.HexColor("#1e293b")
ROW_ALT_BG = colors.HexColor("#f8fafc")

STATUS_COLORS = {
    "Success": ACCENT_GREEN,
    "Simulated": ACCENT_AMBER,
    "Awaiting Approval": ACCENT_AMBER,
    "Skipped": MUTED,
    "Blocked": ACCENT_RED,
    "Failed": ACCENT_RED,
}
VERDICT_COLORS = {"Malicious": ACCENT_RED, "Suspicious": ACCENT_AMBER, "Clean": ACCENT_GREEN, "Unknown": MUTED}


def _text(value: Any, default: str = "N/A") -> str:
    if value is None or (isinstance(value, str) and not value.strip()):
        return default
    return escape(str(value))


def _grid_style(header: bool = True, background: Optional[colors.Color] = None) -> TableStyle:
    commands = [
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if background is not None:
        commands.append(("BACKGROUND", (0, 0), (-1, -1), background))
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), HEADER_BG))
    return TableStyle(commands)


def _mttr_text(mttr: Any) -> str:
    try:
        value = float(mttr)
    except (TypeError, ValueError):
        return "Not contained"
    if value <= 0:
        return "Not contained"
    if value < 120:
        return f"{value:.2f} s (alert creation to containment)"
    if value < 7200:
        return f"{value / 60:.1f} min (alert creation to containment)"
    return f"{value / 3600:.1f} h (alert creation to containment)"


def generate_pdf_report(alert_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """Render the incident report for one alert and return the PDF path."""
    alert_id = int(alert_data.get("alert_id") or 0)
    if not output_path:
        os.makedirs(settings.REPORTS_DIR, exist_ok=True)
        output_path = os.path.join(settings.REPORTS_DIR, f"incident_report_alert_{alert_id}.pdf")

    doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("DocTitle", parent=styles["Heading1"], fontName="Helvetica-Bold",
                                 fontSize=20, leading=24, textColor=PRIMARY, spaceAfter=4)
    subtitle_style = ParagraphStyle("DocSubTitle", parent=styles["Normal"], fontName="Helvetica",
                                    fontSize=10, leading=14, textColor=MUTED)
    section = ParagraphStyle("SectionHeading", parent=styles["Heading2"], fontName="Helvetica-Bold",
                             fontSize=13, leading=17, textColor=ACCENT_BLUE, spaceBefore=12, spaceAfter=6)
    cell = ParagraphStyle("CellNormal", parent=styles["Normal"], fontName="Helvetica",
                          fontSize=8.5, leading=11, textColor=colors.HexColor("#1e293b"))
    cell_small = ParagraphStyle("CellSmall", parent=cell, fontSize=7.5, leading=9.5, textColor=MUTED)
    cell_bold = ParagraphStyle("CellBold", parent=cell, fontName="Helvetica-Bold")
    cell_header = ParagraphStyle("CellHeader", parent=cell, fontName="Helvetica-Bold", textColor=colors.white)
    notice_style = ParagraphStyle("Notice", parent=cell, fontName="Helvetica-Bold", fontSize=10,
                                  leading=13, textColor=ACCENT_RED)

    iocs: List[Dict[str, Any]] = alert_data.get("ioc_artifacts") or []
    actions: List[Dict[str, Any]] = alert_data.get("containment_actions") or []
    simulated_actions = [a for a in actions if a.get("execution_mode") == "simulated" or a.get("status") == "Simulated"]

    story: List[Any] = []
    story.append(Paragraph(
        "<para align='center'><b>CONFIDENTIAL // SOC INTERNAL USE ONLY // PHANTOM SOAR IR REPORT</b></para>",
        ParagraphStyle("Banner", parent=styles["Normal"], fontSize=8, textColor=ACCENT_RED),
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph("PHANTOM SOAR | Incident Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | "
        f"Platform Version: {escape(settings.PROJECT_VERSION)}",
        subtitle_style,
    ))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT_BLUE, spaceBefore=4, spaceAfter=10))

    if simulated_actions:
        notice = Table([[Paragraph(
            f"SIMULATED: {len(simulated_actions)} of {len(actions)} response action(s) in this report were "
            "simulated because the connector is not configured. No command was sent to any real system "
            "for those actions.",
            notice_style,
        )]], colWidths=[530])
        notice.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 1.2, ACCENT_RED),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(notice)
        story.append(Spacer(1, 10))

    severity = str(alert_data.get("severity") or "Unknown")
    sev_color = ACCENT_RED if severity in ("Critical", "High") else ACCENT_AMBER
    overview = [
        [Paragraph("<b>Incident ID:</b>", cell), Paragraph(f"ALERT-{alert_id:04d}", cell_bold),
         Paragraph("<b>Severity:</b>", cell),
         Paragraph(f"<font color='{sev_color.hexval()}'><b>{escape(severity.upper())}</b></font>", cell_bold)],
        [Paragraph("<b>Source:</b>", cell), Paragraph(_text(alert_data.get("source")), cell),
         Paragraph("<b>Status:</b>", cell), Paragraph(f"<b>{_text(alert_data.get('status')).upper()}</b>", cell_bold)],
        [Paragraph("<b>Rule ID:</b>", cell), Paragraph(_text(alert_data.get("rule_id")), cell),
         Paragraph("<b>MTTR:</b>", cell), Paragraph(escape(_mttr_text(alert_data.get("mttr_seconds"))), cell_bold)],
        [Paragraph("<b>Detected:</b>", cell), Paragraph(_text(str(alert_data.get("created_at") or "")[:19]), cell),
         Paragraph("<b>Response mode:</b>", cell), Paragraph(_text(alert_data.get("execution_mode"), "Not processed"), cell)],
        [Paragraph("<b>Threat:</b>", cell), Paragraph(_text(alert_data.get("threat_name")), cell),
         Paragraph("<b>Playbook:</b>", cell), Paragraph(_text(alert_data.get("playbook_name"), "None matched"), cell)],
    ]
    t_overview = Table(overview, colWidths=[90, 175, 90, 175])
    t_overview.setStyle(_grid_style(header=False, background=colors.HexColor("#f1f5f9")))
    story.append(t_overview)
    story.append(Spacer(1, 10))

    story.append(Paragraph("1. Triage Summary", section))
    story.append(Paragraph(_text(alert_data.get("triage_summary"), "No triage summary was recorded."), cell))
    story.append(Spacer(1, 6))

    story.append(Paragraph("2. MITRE ATT&amp;CK Mapping", section))
    mitre = alert_data.get("mitre_attack") or {}
    ids = list(mitre.get("id") or [])
    if ids:
        tactics = list(mitre.get("tactic") or [])
        techniques = list(mitre.get("technique") or [])
        rows = [[Paragraph("Technique ID", cell_header), Paragraph("Technique", cell_header),
                 Paragraph("Tactic", cell_header)]]
        for idx, technique_id in enumerate(ids):
            rows.append([
                Paragraph(_text(technique_id), cell_bold),
                Paragraph(_text(techniques[idx] if idx < len(techniques) else None, "-"), cell),
                Paragraph(_text(tactics[idx] if idx < len(tactics) else None, "-"), cell),
            ])
        t_mitre = Table(rows, colWidths=[110, 260, 160])
        t_mitre.setStyle(_grid_style())
        story.append(t_mitre)
        source = mitre.get("source")
        if source:
            story.append(Paragraph(
                "Source: " + ("alert telemetry (rule.mitre)" if source == "telemetry" else "matched playbook's technique"),
                cell_small,
            ))
    else:
        story.append(Paragraph("No MITRE ATT&amp;CK mapping was present in the telemetry or the matched playbook.", cell))
    story.append(Spacer(1, 6))

    story.append(Paragraph("3. Indicators of Compromise &amp; Threat Intelligence", section))
    if iocs:
        rows = [[Paragraph("Type", cell_header), Paragraph("Indicator", cell_header), Paragraph("Score", cell_header),
                 Paragraph("Verdict", cell_header), Paragraph("Evidence", cell_header)]]
        for ioc in iocs:
            verdict = ioc.get("verdict") or "Unknown"
            color = VERDICT_COLORS.get(verdict, MUTED)
            sources = ioc.get("evidence_sources") or []
            if sources:
                evidence = (f"{ioc['evidence_kind']}: " if ioc.get("evidence_kind") else "") + ", ".join(sources)
            else:
                evidence = f"no evidence ({ioc.get('enrichment_status') or 'not enriched'})"
            rows.append([
                Paragraph(_text(ioc.get("artifact_type")), cell_bold),
                Paragraph(_text(ioc.get("value")), cell),
                Paragraph(f"{int(ioc.get('threat_score') or 0)}/100", cell),
                Paragraph(f"<font color='{color.hexval()}'><b>{escape(verdict)}</b></font>", cell_bold),
                Paragraph(escape(str(evidence)), cell_small),
            ])
        t_ioc = Table(rows, colWidths=[50, 210, 50, 70, 150])
        t_ioc.setStyle(_grid_style())
        story.append(t_ioc)
    else:
        story.append(Paragraph("No indicators were extracted from this alert.", cell))
    story.append(Spacer(1, 6))

    story.append(Paragraph("4. Response Actions", section))
    if actions:
        rows = [[Paragraph("Time (UTC)", cell_header), Paragraph("Action", cell_header), Paragraph("Target", cell_header),
                 Paragraph("Connector / Mode", cell_header), Paragraph("Outcome", cell_header)]]
        for idx, act in enumerate(actions):
            status = str(act.get("status") or "Unknown")
            color = STATUS_COLORS.get(status, MUTED)
            note = act.get("error") or "; ".join(act.get("reasons") or []) or ""
            outcome = f"<font color='{color.hexval()}'><b>{escape(status)}</b></font>"
            if note:
                outcome += f"<br/><font size='7'>{escape(str(note)[:180])}</font>"
            mode = act.get("execution_mode")
            rows.append([
                Paragraph(_text(str(act.get("timestamp") or "")[:19].replace("T", " "), "-"), cell_small),
                Paragraph(_text(act.get("action_type")), cell_bold),
                Paragraph(_text(act.get("target"), "-"), cell),
                Paragraph(f"{_text(act.get('connector'), '-')} / "
                          f"{'<b>SIMULATED</b>' if mode == 'simulated' else _text(mode, '-')}", cell),
                Paragraph(outcome, cell),
            ])
        t_act = Table(rows, colWidths=[80, 105, 115, 95, 135])
        t_act.setStyle(_grid_style())
        story.append(t_act)
        story.append(Paragraph(
            "Modes: live = command accepted by the real system; simulated = connector not configured, nothing sent; "
            "skipped = not run; blocked = held or denied by policy; failed = the connector reported an error.",
            cell_small,
        ))
    else:
        story.append(Paragraph("No response actions have been recorded for this alert.", cell))
    story.append(Spacer(1, 6))

    story.append(Paragraph("5. Analyst Decision &amp; Next Steps", section))
    decision = alert_data.get("analyst_decision")
    resolved_by = alert_data.get("resolved_by")
    story.append(Paragraph(
        f"<b>Decision:</b> {_text(decision, 'No analyst decision recorded')}"
        + (f" &nbsp; <b>By:</b> {_text(resolved_by)}" if resolved_by else ""),
        cell,
    ))
    next_steps = []
    pending = [a for a in actions if a.get("status") in ("Failed", "Blocked", "Awaiting Approval", "Skipped")]
    if pending:
        next_steps.append(f"Review {len(pending)} action(s) that did not execute (failed, blocked, held for approval or skipped).")
    if simulated_actions:
        next_steps.append("Configure the relevant connectors and repeat the simulated actions to contain the threat for real.")
    unknown = [i for i in iocs if (i.get("verdict") or "Unknown") == "Unknown"]
    if unknown:
        next_steps.append(f"{len(unknown)} indicator(s) have no threat-intelligence verdict; investigate them manually.")
    next_steps.append("Preserve host and network telemetry for forensic analysis before remediation.")
    story.append(Spacer(1, 4))
    story.append(Paragraph("<br/>".join(f"{n}. {escape(s)}" for n, s in enumerate(next_steps, start=1)), cell))
    story.append(Spacer(1, 14))

    sign_table = Table([[
        Paragraph(f"<b>Response mode:</b> {_text(alert_data.get('execution_mode'), 'Not processed')}", cell),
        Paragraph("<b>Lead SOC Analyst Signature:</b> ___________________________", cell),
    ]], colWidths=[260, 270])
    story.append(KeepTogether([sign_table]))

    doc.build(story)
    return output_path
