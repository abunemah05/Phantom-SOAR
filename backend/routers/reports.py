import io
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Tuple
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from backend.database import get_db
from backend.models import User, Alert, AnalystActionLog, ContainmentAction, PlaybookExecution
from backend.schemas import AdminReportResponse, AnalystMetrics
from backend.dependencies import require_admin
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from xml.sax.saxutils import escape

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["Admin Reporting & SOC Performance Engine"])

RESOLVED_STATUSES = {"Contained", "Resolved", "Closed", "Monitoring"}


def _parse_datetime(value: str, end_of_day: bool) -> Optional[datetime]:
    value = (value or "").strip()
    if not value:
        return None
    try:
        if len(value) == 10:  # YYYY-MM-DD
            day = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
            return day + timedelta(days=1) - timedelta(microseconds=1) if end_of_day else day
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def parse_date_range(period: str, start_str: Optional[str], end_str: Optional[str]) -> Tuple[datetime, datetime]:
    """UTC (start, end) for 'day' | 'week' | 'month' | 'custom' (default: last 30 days)."""
    now = datetime.now(timezone.utc)
    if period == "day":
        return now.replace(hour=0, minute=0, second=0, microsecond=0), now
    if period == "week":
        return now - timedelta(days=7), now
    if period == "custom" and start_str:
        start = _parse_datetime(start_str, end_of_day=False) or now - timedelta(days=30)
        end = _parse_datetime(end_str, end_of_day=True) if end_str else None
        return start, end or now
    return now - timedelta(days=30), now


def _naive(dt: datetime) -> datetime:
    """Columns are stored as naive UTC; compare with naive UTC on every backend."""
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _avg_mttr(executions: List[PlaybookExecution]) -> Tuple[float, int]:
    """Average over executions that actually completed with a measured MTTR (pending ones have none)."""
    measured = [e.mttr_seconds for e in executions if e.mttr_seconds and e.mttr_seconds > 0]
    if not measured:
        return 0.0, 0
    return round(sum(measured) / len(measured), 2), len(measured)


@router.get("/analysts")
def list_available_analysts(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] Operators for the report filter dropdown (service accounts excluded)."""
    users = db.query(User).order_by(User.username.asc()).all()
    return [
        {
            "user_id": u.user_id,
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active
        }
        for u in users if not u.is_service_account
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
    [Admin Only] Case activity per analyst, computed only from stored rows:
    alerts created or resolved in range, analyst decision logs, containment actions
    (broken down by execution mode) and measured playbook MTTR.
    """
    start_dt, end_dt = parse_date_range(period, start_date, end_date)
    start_q, end_q = _naive(start_dt), _naive(end_dt)
    analyst_filter = analyst.strip() if analyst and analyst.strip().lower() != "all" else None

    log_query = db.query(AnalystActionLog).filter(
        AnalystActionLog.timestamp >= start_q,
        AnalystActionLog.timestamp <= end_q
    )
    if analyst_filter:
        log_query = log_query.filter(AnalystActionLog.analyst_username == analyst_filter)
    action_logs = log_query.order_by(AnalystActionLog.timestamp.desc()).all()

    alert_query = db.query(Alert).filter(or_(
        and_(Alert.created_at >= start_q, Alert.created_at <= end_q),
        and_(Alert.resolved_at >= start_q, Alert.resolved_at <= end_q),
    ))
    if analyst_filter:
        alert_query = alert_query.filter(
            or_(Alert.resolved_by == analyst_filter, Alert.assigned_analyst == analyst_filter)
        )
    matched_alerts = alert_query.order_by(Alert.created_at.desc()).all()
    alert_ids = [a.alert_id for a in matched_alerts]

    executions = db.query(PlaybookExecution).filter(PlaybookExecution.alert_id.in_(alert_ids)).all() if alert_ids else []
    avg_mttr, mttr_samples = _avg_mttr(executions)

    actions = db.query(ContainmentAction).filter(ContainmentAction.alert_id.in_(alert_ids)).all() if alert_ids else []
    by_mode: Dict[str, int] = {}
    for act in actions:
        mode = act.execution_mode or "unrecorded"
        by_mode[mode] = by_mode.get(mode, 0) + 1

    user_roles = {u.username: u.role for u in db.query(User).all() if not u.is_service_account}
    if analyst_filter:
        target_analysts = [analyst_filter]
    else:
        # Include people who acted in the period even if their account was deleted since.
        seen = set(user_roles)
        seen.update(name for a in matched_alerts for name in (a.assigned_analyst, a.resolved_by) if name)
        seen.update(entry.analyst_username for entry in action_logs if entry.analyst_username)
        target_analysts = sorted(seen)

    analyst_summaries = []
    for uname in target_analysts:
        u_alerts = [a for a in matched_alerts if a.resolved_by == uname or a.assigned_analyst == uname]
        u_logs = [entry for entry in action_logs if entry.analyst_username == uname]
        if not (u_alerts or u_logs or analyst_filter):
            continue

        escalated = sum(1 for entry in u_logs if entry.action_type == "take_action" or "escalat" in (entry.decision or "").lower())
        monitored = sum(1 for entry in u_logs if entry.action_type == "keep_and_monitor" or "monitor" in (entry.decision or "").lower())
        dismissed = sum(1 for entry in u_logs if entry.action_type == "dismiss" or "dismiss" in (entry.decision or "").lower())

        u_alert_ids = {a.alert_id for a in u_alerts}
        u_mttr, _ = _avg_mttr([e for e in executions if e.alert_id in u_alert_ids])
        u_containments = db.query(ContainmentAction).filter(
            ContainmentAction.executed_by == uname,
            ContainmentAction.timestamp >= start_q,
            ContainmentAction.timestamp <= end_q,
        ).count()

        analyst_summaries.append(AnalystMetrics(
            analyst_username=uname,
            role=user_roles.get(uname, "Unknown account"),
            cases_assigned=len(u_alerts),
            cases_resolved=len([a for a in u_alerts if a.status in RESOLVED_STATUSES]),
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
        filtered_analyst=analyst_filter,
        total_cases_reviewed=len(matched_alerts),
        total_containment_actions=len(actions),
        containment_by_mode=by_mode,
        average_mttr_seconds=avg_mttr,
        mttr_sample_size=mttr_samples,
        analyst_breakdown=analyst_summaries,
        cases=[a.to_dict() for a in matched_alerts[:100]],
        action_logs=[entry.to_dict() for entry in action_logs[:100]]
    )


def _safe_filename_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", value or "all")[:40] or "all"


@router.get("/analyst-activity/pdf")
def export_analyst_activity_pdf(
    analyst: Optional[str] = Query("all"),
    period: Optional[str] = Query("month"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] The analyst activity report as a PDF (generated in memory, nothing written to disk)."""
    report_data = get_analyst_activity_report(
        analyst=analyst,
        period=period,
        start_date=start_date,
        end_date=end_date,
        db=db,
        admin=admin
    )

    generated_at = datetime.now(timezone.utc)
    filename = (
        f"phantom_soar_audit_{_safe_filename_part(period)}_{_safe_filename_part(analyst)}_"
        f"{generated_at.strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
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
    notice_style = ParagraphStyle(
        "Notice",
        parent=cell_style,
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#92400e"),
        backColor=colors.HexColor("#fef3c7"),
        borderPadding=6
    )

    def p(text, style=cell_style):
        return Paragraph(escape(str(text)), style)

    story = []

    story.append(Paragraph("Phantom SOAR — SOC Analyst Performance &amp; Case Audit Report", title_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Generated by Administrator: <b>{escape(admin.username)}</b> ({escape(admin.role)}) | "
        f"Generated at {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC | "
        f"Period: <b>{escape(report_data.period.upper())}</b> ({report_data.start_date[:10]} to {report_data.end_date[:10]}) | "
        f"Filter: <b>{escape(report_data.filtered_analyst or 'All Analysts')}</b>",
        subtitle_style
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#3b82f6"), spaceAfter=12))

    simulated = report_data.containment_by_mode.get("simulated", 0)
    if simulated:
        story.append(Paragraph(
            f"<b>SIMULATED:</b> {simulated} of {report_data.total_containment_actions} containment actions in this period "
            f"were simulated (no connector was configured); they did not change any real system.",
            notice_style
        ))
        story.append(Spacer(1, 10))

    story.append(Paragraph("Executive KPI Summary", section_style))
    story.append(Spacer(1, 6))

    mode_text = ", ".join(f"{mode}: {count}" for mode, count in sorted(report_data.containment_by_mode.items())) or "none"
    mttr_text = (
        f"{report_data.average_mttr_seconds}s (n={report_data.mttr_sample_size})"
        if report_data.mttr_sample_size else "No completed responses"
    )
    kpi_data = [
        [
            Paragraph("<b>Total Cases Reviewed</b>", cell_bold),
            Paragraph("<b>Containment Actions Recorded</b>", cell_bold),
            Paragraph("<b>Average MTTR</b>", cell_bold),
            Paragraph("<b>Target Operators</b>", cell_bold)
        ],
        [
            Paragraph(f"<font size=12><b>{report_data.total_cases_reviewed}</b></font>", cell_style),
            Paragraph(f"<font size=12><b>{report_data.total_containment_actions}</b></font><br/>{escape(mode_text)}", cell_style),
            Paragraph(f"<font size=11><b>{escape(mttr_text)}</b></font>", cell_style),
            Paragraph(f"<font size=10><b>{escape(report_data.filtered_analyst or 'All')}</b></font>", cell_style)
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

    story.append(Paragraph("Analyst Performance &amp; Decision Matrix", section_style))
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
            p(a.analyst_username, cell_bold),
            p(a.role[:24]),
            p(a.cases_assigned),
            p(a.cases_resolved),
            p(a.escalated_count),
            p(a.monitored_count),
            p(a.dismissed_count),
            p(f"{a.avg_mttr_seconds}s" if a.avg_mttr_seconds else "—")
        ])

    if len(breakdown_rows) == 1:
        breakdown_rows.append([p("No analyst actions recorded in selected period.")] + [p("")] * 7)

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
            p(f"#{c.get('alert_id')}", cell_bold),
            p(str(c.get("rule_id", "N/A"))[:25]),
            p(c.get("severity") or "—"),
            p(c.get("status") or "—"),
            p(c.get("resolved_by") or "Unassigned"),
            p(str(c.get("analyst_decision") or "No decision recorded")[:30])
        ])

    if len(case_rows) == 1:
        case_rows.append([p("No cases found in this period.")] + [p("")] * 5)

    case_table = Table(case_rows, colWidths=[55, 120, 65, 75, 95, 130])
    case_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(case_table)

    doc.build(story)

    return Response(
        content=buffer.getvalue(),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
