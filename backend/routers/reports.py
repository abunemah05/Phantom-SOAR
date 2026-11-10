import os
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.database import get_db
from backend.models import User, Alert, AnalystActionLog, ContainmentAction, PlaybookExecution
from backend.schemas import AdminReportResponse, AnalystMetrics
from backend.dependencies import require_admin
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["Admin Reporting & SOC Performance Engine"])

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

def parse_date_range(period: str, start_str: Optional[str], end_str: Optional[str]):
    now = datetime.now(timezone.utc)
    if period == "day":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now
    elif period == "week":
        start = now - timedelta(days=7)
        end = now
    elif period == "month":
        start = now - timedelta(days=30)
        end = now
    elif period == "custom" and start_str:
        try:
            start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
        except Exception:
            start = now - timedelta(days=30)

        if end_str:
            try:
                end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
            except Exception:
                end = now
        else:
            end = now
    else:
        # Default to last 30 days
        start = now - timedelta(days=30)
        end = now

    return start, end

@router.get("/analysts")
def list_available_analysts(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Return list of all operators/analysts for the report filter dropdown.
    """
    users = db.query(User).order_by(User.username.asc()).all()
    return [
        {
            "user_id": u.user_id,
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active
        }
        for u in users
    ]

@router.get("/analyst-activity", response_model=AdminReportResponse)
def get_analyst_activity_report(
    analyst: Optional[str] = Query("all", description="Analyst username or 'all'"),
    period: Optional[str] = Query("month", description="'day', 'week', 'month', or 'custom'"),
    start_date: Optional[str] = Query(None, description="Start date (YYYY-MM-DD or ISO)"),
    end_date: Optional[str] = Query(None, description="End date (YYYY-MM-DD or ISO)"),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Advanced Reporting Dashboard:
    - Case activity handled by a specific SOC Analyst or across all analysts.
    - HITL actions breakdown (Take Action / Escalation, Continuous Monitoring, Dismissal).
    - Containment executions and MTTR efficiency.
    - Filterable by exact date-picker custom range, day, week, or month.
    """
    start_dt, end_dt = parse_date_range(period, start_date, end_date)

    # 1. Fetch action logs in range
    log_query = db.query(AnalystActionLog).filter(
        AnalystActionLog.timestamp >= start_dt,
        AnalystActionLog.timestamp <= end_dt
    )
    if analyst and analyst.lower() != "all":
        log_query = log_query.filter(AnalystActionLog.analyst_username == analyst.strip())
    action_logs = log_query.order_by(AnalystActionLog.timestamp.desc()).all()

    # 2. Fetch alerts in range or resolved in range
    alert_query = db.query(Alert).filter(
        (Alert.created_at >= start_dt) & (Alert.created_at <= end_dt) |
        (Alert.resolved_at >= start_dt) & (Alert.resolved_at <= end_dt)
    )
    if analyst and analyst.lower() != "all":
        alert_query = alert_query.filter(
            (Alert.resolved_by == analyst.strip()) | (Alert.assigned_analyst == analyst.strip())
        )
    matched_alerts = alert_query.order_by(Alert.created_at.desc()).all()

    # 3. Calculate MTTR from playbook executions
    alert_ids = [a.alert_id for a in matched_alerts]
    executions = db.query(PlaybookExecution).filter(PlaybookExecution.alert_id.in_(alert_ids)).all() if alert_ids else []
    avg_mttr = 0.0
    if executions:
        avg_mttr = round(sum(e.mttr_seconds for e in executions) / len(executions), 2)

    # 4. Containment actions count
    containment_count = db.query(ContainmentAction).filter(ContainmentAction.alert_id.in_(alert_ids)).count() if alert_ids else 0

    # 5. Group by analyst for per-operator metrics
    all_users = db.query(User).all()
    user_roles = {u.username: u.role for u in all_users}
    target_analysts = [analyst.strip()] if (analyst and analyst.lower() != "all") else list(user_roles.keys())

    analyst_summaries = []
    for uname in target_analysts:
        u_role = user_roles.get(uname, "SOC Analyst")
        u_alerts = [a for a in matched_alerts if a.resolved_by == uname or a.assigned_analyst == uname]
        u_logs = [l for l in action_logs if l.analyst_username == uname]
        
        escalated = sum(1 for l in u_logs if l.action_type == "take_action" or "escalat" in (l.decision or "").lower())
        monitored = sum(1 for l in u_logs if l.action_type == "keep_and_monitor" or "monitor" in (l.decision or "").lower())
        dismissed = sum(1 for l in u_logs if l.action_type == "dismiss" or "dismiss" in (l.decision or "").lower())

        u_alert_ids = [a.alert_id for a in u_alerts]
        u_execs = [e for e in executions if e.alert_id in u_alert_ids]
        u_mttr = round(sum(e.mttr_seconds for e in u_execs) / len(u_execs), 2) if u_execs else 0.0
        u_containments = db.query(ContainmentAction).filter(ContainmentAction.alert_id.in_(u_alert_ids)).count() if u_alert_ids else 0

        # Only include if user has actions or if specifically filtered
        if u_alerts or u_logs or analyst != "all":
            analyst_summaries.append(AnalystMetrics(
                analyst_username=uname,
                role=u_role,
                cases_assigned=len(u_alerts),
                cases_resolved=len([a for a in u_alerts if a.status in ["Contained", "Resolved", "Closed", "Monitoring"]]),
                escalated_count=escalated,
                monitored_count=monitored,
                dismissed_count=dismissed,
                containment_actions_taken=u_containments,
                avg_mttr_seconds=u_mttr
            ))

    return AdminReportResponse(
        period=period or "month",
        start_date=start_dt.isoformat(),
        end_date=end_dt.isoformat(),
        filtered_analyst=analyst if analyst != "all" else None,
        total_cases_reviewed=len(matched_alerts),
        total_containment_actions=containment_count,
        average_mttr_seconds=avg_mttr,
        analyst_breakdown=analyst_summaries,
        cases=[a.to_dict() for a in matched_alerts[:100]],
        action_logs=[l.to_dict() for l in action_logs[:100]]
    )

@router.get("/analyst-activity/pdf")
def export_analyst_activity_pdf(
    analyst: Optional[str] = Query("all"),
    period: Optional[str] = Query("month"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Generates a formal ReportLab PDF audit report of analyst metrics.
    """
    report_data = get_analyst_activity_report(
        analyst=analyst,
        period=period,
        start_date=start_date,
        end_date=end_date,
        db=db,
        admin=admin
    )

    filename = f"phantom_soar_audit_{period}_{analyst}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = os.path.join(REPORTS_DIR, filename)

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748b")
    )
    section_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e293b")
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155")
    )
    cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=cell_style,
        fontName="Helvetica-Bold"
    )

    story = []

    # Header
    story.append(Paragraph("Phantom SOAR — SOC Analyst Performance & Case Audit Report", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Generated by Administrator: <b>{admin.username}</b> ({admin.role}) | "
        f"Period: <b>{report_data.period.upper()}</b> ({report_data.start_date[:10]} to {report_data.end_date[:10]}) | "
        f"Filter: <b>{report_data.filtered_analyst or 'All Analysts'}</b>",
        subtitle_style
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3b82f6"), spaceAfter=12))

    # Executive Summary Metrics Table
    story.append(Paragraph("Executive KPI Summary", section_style))
    story.append(Spacer(1, 6))

    kpi_data = [
        [
            Paragraph("<b>Total Cases Reviewed</b>", cell_bold),
            Paragraph("<b>Containment Actions Taken</b>", cell_bold),
            Paragraph("<b>Average MTTR</b>", cell_bold),
            Paragraph("<b>Target Operators</b>", cell_bold)
        ],
        [
            Paragraph(f"<font size=12><b>{report_data.total_cases_reviewed}</b></font>", cell_style),
            Paragraph(f"<font size=12><b>{report_data.total_containment_actions}</b></font>", cell_style),
            Paragraph(f"<font size=12><b>{report_data.average_mttr_seconds}s</b></font>", cell_style),
            Paragraph(f"<font size=10><b>{report_data.filtered_analyst or 'All'}</b></font>", cell_style)
        ]
    ]
    kpi_table = Table(kpi_data, colWidths=[135, 135, 135, 135])
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#ffffff")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 14))

    # Per-Analyst Activity Breakdown Table
    story.append(Paragraph("Analyst Performance & Decision Matrix", section_style))
    story.append(Spacer(1, 6))

    breakdown_rows = [
        [
            Paragraph("<b>Analyst</b>", cell_bold),
            Paragraph("<b>Role</b>", cell_bold),
            Paragraph("<b>Assigned</b>", cell_bold),
            Paragraph("<b>Resolved</b>", cell_bold),
            Paragraph("<b>Escalated</b>", cell_bold),
            Paragraph("<b>Monitored</b>", cell_bold),
            Paragraph("<b>Dismissed</b>", cell_bold),
            Paragraph("<b>Avg MTTR</b>", cell_bold)
        ]
    ]

    for a in report_data.analyst_breakdown:
        breakdown_rows.append([
            Paragraph(a.analyst_username, cell_bold),
            Paragraph(a.role[:20], cell_style),
            Paragraph(str(a.cases_assigned), cell_style),
            Paragraph(str(a.cases_resolved), cell_style),
            Paragraph(str(a.escalated_count), cell_style),
            Paragraph(str(a.monitored_count), cell_style),
            Paragraph(str(a.dismissed_count), cell_style),
            Paragraph(f"{a.avg_mttr_seconds}s", cell_style)
        ])

    if len(breakdown_rows) == 1:
        breakdown_rows.append([Paragraph("No analyst actions recorded in selected period.", cell_style)] + [Paragraph("", cell_style)] * 7)

    breakdown_table = Table(breakdown_rows, colWidths=[80, 110, 50, 50, 60, 60, 60, 70])
    breakdown_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(breakdown_table)
    story.append(Spacer(1, 14))

    # Case Logs Sample Table
    story.append(Paragraph("Case Activity Audit Log (Recent Entries)", section_style))
    story.append(Spacer(1, 6))

    case_rows = [
        [
            Paragraph("<b>Alert ID</b>", cell_bold),
            Paragraph("<b>Rule / Event</b>", cell_bold),
            Paragraph("<b>Severity</b>", cell_bold),
            Paragraph("<b>Status</b>", cell_bold),
            Paragraph("<b>Resolved By</b>", cell_bold),
            Paragraph("<b>Decision</b>", cell_bold)
        ]
    ]

    for c in report_data.cases[:15]:
        case_rows.append([
            Paragraph(f"#{c.get('alert_id')}", cell_bold),
            Paragraph(str(c.get("rule_id", "N/A"))[:25], cell_style),
            Paragraph(str(c.get("severity", "Low")), cell_style),
            Paragraph(str(c.get("status", "New")), cell_style),
            Paragraph(str(c.get("resolved_by") or "Unassigned"), cell_style),
            Paragraph(str(c.get("analyst_decision") or "Autonomous")[:30], cell_style)
        ])

    if len(case_rows) == 1:
        case_rows.append([Paragraph("No cases found in this period.", cell_style)] + [Paragraph("", cell_style)] * 5)

    case_table = Table(case_rows, colWidths=[55, 120, 65, 75, 95, 130])
    case_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(case_table)

    # Build PDF document
    doc.build(story)

    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=filename
    )
