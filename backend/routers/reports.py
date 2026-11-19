import io
import logging
import re
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Optional, List, Dict, Sequence, Tuple
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func

from backend.database import get_db
from backend.models import User, Alert, AnalystActionLog, ContainmentAction, PlaybookExecution
from backend.schemas import AdminReportResponse, AnalystMetrics
from backend.dependencies import require_admin
from backend.engine.ingest import SEVERITIES
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from xml.sax.saxutils import escape

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["Admin Reporting & SOC Performance Engine"])

RESOLVED_STATUSES = {"Contained", "Resolved", "Closed", "Monitoring"}


# ---------------------------------------------------------------------------------------------------------
# Filters: time range and severity
#
# Time semantics (the single source of truth; mirrored in docs/ARCHITECTURE.md):
#   * Every instant is handled as an aware UTC datetime. Alert/log/action columns are UTC.
#   * An input with an offset ("...+02:00") or "Z" is converted to UTC.
#   * A naive input ("2026-01-01T10:00:00", no offset) is interpreted as UTC. The web UI never sends naive
#     values: it converts the operator's local date-time to UTC ("...Z") in the browser.
#   * A date-only input (YYYY-MM-DD) means a whole UTC day: start -> 00:00:00 UTC, end -> 23:59:59.999999 UTC.
#   * The range is a CLOSED interval [start, end]: a record stamped exactly at start or exactly at end is
#     included. Resolution is whatever the input carries (seconds in the UI; microseconds if supplied).
#   * Presets: "day" = since 00:00:00 UTC today, "week" = last 7x24h, "month" = last 30x24h (end = now).
#   * "relative" = the last N seconds/minutes/hours/days ending now. "custom" = explicit start/end
#     (end defaults to now when omitted).
#   * end must be after start and the span must not exceed MAX_RANGE_DAYS; violations are 422 responses.
# ---------------------------------------------------------------------------------------------------------
REPORT_TIMEZONE = "UTC"
MAX_RANGE_DAYS = 366
MIN_YEAR, MAX_YEAR = 2000, 2100
PRESET_PERIODS = ("day", "week", "month")
ALL_PERIODS = PRESET_PERIODS + ("custom", "relative")
RELATIVE_UNIT_SECONDS = {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}
_UNIT_ALIASES = {"second": "seconds", "sec": "seconds", "s": "seconds", "minute": "minutes", "min": "minutes",
                 "hour": "hours", "h": "hours", "day": "days", "d": "days"}
_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# A "+" in an un-encoded query string arrives as a space ("...T10:00:00 02:00"); restore it.
_SPACE_OFFSET = re.compile(r"^(.*T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?) (\d{2}:?\d{2})$")

# Most severe first: this is the order the report presents them in.
SEVERITY_DISPLAY_ORDER = tuple(reversed(SEVERITIES))


class ReportFilterError(ValueError):
    """An invalid report filter; the endpoints answer it with HTTP 422 and this message."""


@dataclass(frozen=True)
class ReportRange:
    start: datetime  # aware UTC
    end: datetime  # aware UTC
    mode: str  # "preset" | "absolute" | "relative"


def _parse_datetime(value: str, end_of_day: bool, field: str = "date") -> Optional[datetime]:
    """Parse one bound to aware UTC. Empty -> None. Unparseable/out-of-range -> ReportFilterError."""
    value = (value or "").strip()
    if not value:
        return None
    try:
        if _DATE_ONLY.match(value):
            day = datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
            parsed = day + timedelta(days=1) - timedelta(microseconds=1) if end_of_day else day
        else:
            m = _SPACE_OFFSET.match(value)
            if m:
                value = f"{m.group(1)}+{m.group(2)}"
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
            parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ReportFilterError(
            f"{field} '{value}' is not a valid date or ISO-8601 date-time "
            f"(use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS with an optional offset such as Z or +02:00)."
        )
    if not (MIN_YEAR <= parsed.year <= MAX_YEAR):
        raise ReportFilterError(f"{field} year must be between {MIN_YEAR} and {MAX_YEAR}.")
    return parsed


def normalise_relative_unit(unit: Optional[str]) -> str:
    key = (unit or "").strip().lower()
    key = _UNIT_ALIASES.get(key, key)
    if key not in RELATIVE_UNIT_SECONDS:
        raise ReportFilterError(f"last_unit must be one of {', '.join(RELATIVE_UNIT_SECONDS)}; got '{unit or ''}'.")
    return key


def _check_span(start: datetime, end: datetime) -> None:
    if end <= start:
        raise ReportFilterError("The end of the range must be after its start.")
    if end - start > timedelta(days=MAX_RANGE_DAYS):
        raise ReportFilterError(f"The range is too long: at most {MAX_RANGE_DAYS} days can be reported at once.")


def resolve_report_range(
    period: Optional[str],
    start_str: Optional[str] = None,
    end_str: Optional[str] = None,
    last_n: Optional[int] = None,
    last_unit: Optional[str] = None,
    now: Optional[datetime] = None,
) -> ReportRange:
    """The UTC range for a report request. See the semantics block above. Raises ReportFilterError."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    period = (period or "month").strip().lower() or "month"
    if period not in ALL_PERIODS:
        raise ReportFilterError(f"period must be one of {', '.join(ALL_PERIODS)}; got '{period}'.")
    if period == "day":
        return ReportRange(now.replace(hour=0, minute=0, second=0, microsecond=0), now, "preset")
    if period == "week":
        return ReportRange(now - timedelta(days=7), now, "preset")
    if period == "month":
        return ReportRange(now - timedelta(days=30), now, "preset")
    if period == "relative":
        unit = normalise_relative_unit(last_unit)
        if last_n is None:
            raise ReportFilterError("last_n is required for a relative range.")
        if last_n < 1:
            raise ReportFilterError("last_n must be at least 1.")
        if last_n * RELATIVE_UNIT_SECONDS[unit] > MAX_RANGE_DAYS * 86400:
            raise ReportFilterError(f"The range is too long: at most {MAX_RANGE_DAYS} days can be reported at once.")
        return ReportRange(now - timedelta(seconds=last_n * RELATIVE_UNIT_SECONDS[unit]), now, "relative")
    # custom
    start = _parse_datetime(start_str or "", end_of_day=False, field="start_date")
    if start is None:
        raise ReportFilterError("start_date is required for a custom range.")
    end = _parse_datetime(end_str or "", end_of_day=True, field="end_date") or now
    _check_span(start, end)
    return ReportRange(start, end, "absolute")


def parse_date_range(period: str, start_str: Optional[str], end_str: Optional[str],
                     last_n: Optional[int] = None, last_unit: Optional[str] = None,
                     now: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    """UTC (start, end) for 'day' | 'week' | 'month' | 'custom' | 'relative'. Raises ReportFilterError."""
    r = resolve_report_range(period, start_str, end_str, last_n, last_unit, now)
    return r.start, r.end


def parse_severity_filter(values: Optional[Sequence[str]]) -> List[str]:
    """Canonical severities (most severe first) from repeated and/or comma-separated values.

    Empty / absent / "all" means no severity filter (returns []). Matching is case-insensitive; an unknown
    value raises ReportFilterError, and so does "all" combined with specific severities.
    """
    tokens: List[str] = []
    for raw in values or []:
        tokens.extend(t.strip() for t in str(raw).split(",") if t.strip())
    if not tokens:
        return []
    lowered = [t.lower() for t in tokens]
    if "all" in lowered:
        if any(t != "all" for t in lowered):
            raise ReportFilterError("severity 'all' cannot be combined with specific severities.")
        return []
    canonical = {s.lower(): s for s in SEVERITIES}
    unknown = [t for t in tokens if t.lower() not in canonical]
    if unknown:
        raise ReportFilterError(
            f"Unknown severity {', '.join(repr(u) for u in unknown)}; valid values are "
            f"{', '.join(SEVERITY_DISPLAY_ORDER)} (or 'all')."
        )
    chosen = {canonical[t] for t in lowered}
    return [s for s in SEVERITY_DISPLAY_ORDER if s in chosen]


def severity_breakdown(alerts: Sequence[Alert]) -> Dict[str, int]:
    """Counts per severity (zeros included), most severe first; 'Other' only if an unexpected value exists."""
    counts = {s: 0 for s in SEVERITY_DISPLAY_ORDER}
    other = 0
    canonical = {s.lower(): s for s in SEVERITIES}
    for a in alerts:
        key = canonical.get((a.severity or "").strip().lower())
        if key:
            counts[key] += 1
        else:
            other += 1
    if other:
        counts["Other"] = other
    return counts


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
    period: Optional[str] = Query("month", description="'day', 'week', 'month', 'custom' or 'relative'"),
    start_date: Optional[str] = Query(None, description="custom: start, YYYY-MM-DD or ISO-8601 date-time (naive = UTC)"),
    end_date: Optional[str] = Query(None, description="custom: end (inclusive); defaults to now"),
    last_n: Optional[int] = Query(None, description="relative: how many units back from now"),
    last_unit: Optional[str] = Query(None, description="relative: seconds, minutes, hours or days"),
    severity: Optional[List[str]] = Query(None, description="Critical/High/Medium/Low; repeat or comma-separate; omit or 'all' for every severity"),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    [Admin Only] Case activity per analyst, computed only from stored rows:
    alerts created or resolved in range, analyst decision logs, containment actions
    (broken down by execution mode) and measured playbook MTTR. Every number and table honours the
    time range (UTC, to the second) and the optional severity filter; invalid filters answer 422.
    """
    try:
        rng = resolve_report_range(period, start_date, end_date, last_n, last_unit)
        severities = parse_severity_filter(severity)
    except ReportFilterError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    start_dt, end_dt = rng.start, rng.end
    start_q, end_q = _naive(start_dt), _naive(end_dt)
    analyst_filter = analyst.strip() if analyst and analyst.strip().lower() != "all" else None
    sev_values = [s.lower() for s in severities]

    def by_severity(query):
        """Restrict a query on a table joined to Alert to the selected severities (no-op without a filter)."""
        # lower(trim()) so the filter and severity_breakdown (strip().lower()) treat " High " and "high" alike.
        return query.filter(func.lower(func.trim(Alert.severity)).in_(sev_values)) if sev_values else query

    log_query = db.query(AnalystActionLog).filter(
        AnalystActionLog.timestamp >= start_q,
        AnalystActionLog.timestamp <= end_q
    )
    if sev_values:
        log_query = by_severity(log_query.join(Alert, Alert.alert_id == AnalystActionLog.alert_id))
    if analyst_filter:
        log_query = log_query.filter(AnalystActionLog.analyst_username == analyst_filter)
    action_logs = log_query.order_by(AnalystActionLog.timestamp.desc()).all()

    alert_query = db.query(Alert).filter(or_(
        and_(Alert.created_at >= start_q, Alert.created_at <= end_q),
        and_(Alert.resolved_at >= start_q, Alert.resolved_at <= end_q),
    ))
    alert_query = by_severity(alert_query)
    if analyst_filter:
        alert_query = alert_query.filter(
            or_(Alert.resolved_by == analyst_filter, Alert.assigned_analyst == analyst_filter)
        )
    matched_alerts = alert_query.order_by(Alert.created_at.desc()).all()
    alert_ids = [a.alert_id for a in matched_alerts]

    # Containment actions and playbook executions are selected by THEIR OWN timestamp inside the range (and by the
    # severity of their alert), not by the creation time of their alert: an action taken after the range ends, or
    # before it starts, is never counted, whenever its alert was created. The analyst filter means "executed by" for
    # actions (the same definition as the per-analyst figure) and "alert assigned to / resolved by" for executions
    # (an execution has no analyst of its own).
    exec_query = (db.query(PlaybookExecution, Alert.resolved_by, Alert.assigned_analyst)
                  .join(Alert, Alert.alert_id == PlaybookExecution.alert_id)
                  .filter(PlaybookExecution.executed_at >= start_q, PlaybookExecution.executed_at <= end_q))
    exec_query = by_severity(exec_query)
    if analyst_filter:
        exec_query = exec_query.filter(or_(Alert.resolved_by == analyst_filter, Alert.assigned_analyst == analyst_filter))
    exec_rows = exec_query.all()
    executions = [row[0] for row in exec_rows]
    exec_people = {row[0].execution_id: {row[1], row[2]} for row in exec_rows}
    avg_mttr, mttr_samples = _avg_mttr(executions)

    action_query = db.query(ContainmentAction).filter(ContainmentAction.timestamp >= start_q, ContainmentAction.timestamp <= end_q)
    if sev_values:
        action_query = by_severity(action_query.join(Alert, Alert.alert_id == ContainmentAction.alert_id))
    if analyst_filter:
        action_query = action_query.filter(ContainmentAction.executed_by == analyst_filter)
    actions = action_query.all()
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

        u_mttr, _ = _avg_mttr([e for e in executions if uname in exec_people.get(e.execution_id, ())])
        u_cont_query = db.query(ContainmentAction).filter(
            ContainmentAction.executed_by == uname,
            ContainmentAction.timestamp >= start_q,
            ContainmentAction.timestamp <= end_q,
        )
        if sev_values:
            u_cont_query = by_severity(u_cont_query.join(Alert, Alert.alert_id == ContainmentAction.alert_id))
        u_containments = u_cont_query.count()  # same definition as total_containment_actions: own timestamp, severity, executed_by

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
        period=(period or "month").strip().lower() or "month",
        start_date=start_dt.isoformat(),
        end_date=end_dt.isoformat(),
        timezone=REPORT_TIMEZONE,
        range_mode=rng.mode,
        generated_at=datetime.now(timezone.utc).isoformat(),
        filtered_analyst=analyst_filter,
        filtered_severities=severities,
        severity_breakdown=severity_breakdown(matched_alerts),
        total_cases_reviewed=len(matched_alerts),
        total_containment_actions=len(actions),
        containment_by_mode=by_mode,
        average_mttr_seconds=avg_mttr,
        mttr_sample_size=mttr_samples,
        analyst_breakdown=analyst_summaries,
        cases=[a.to_dict() for a in matched_alerts[:100]],
        action_logs=[entry.to_dict() for entry in action_logs[:100]]
    )


def _fmt_utc(iso: str) -> str:
    """'2026-11-19T10:00:05.123456+00:00' -> '2026-11-19 10:00:05' (the range is shown to the second)."""
    return escape(iso[:19].replace("T", " "))


def _safe_filename_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "_", value or "all")[:40] or "all"


@router.get("/analyst-activity/pdf")
def export_analyst_activity_pdf(
    analyst: Optional[str] = Query("all"),
    period: Optional[str] = Query("month"),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    last_n: Optional[int] = Query(None),
    last_unit: Optional[str] = Query(None),
    severity: Optional[List[str]] = Query(None),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """[Admin Only] The analyst activity report as a PDF (generated in memory, nothing written to disk)."""
    report_data = get_analyst_activity_report(
        analyst=analyst,
        period=period,
        start_date=start_date,
        end_date=end_date,
        last_n=last_n,
        last_unit=last_unit,
        severity=severity,
        db=db,
        admin=admin
    )

    generated_at = datetime.now(timezone.utc)
    sev_label = ", ".join(report_data.filtered_severities) or "All severities"
    filename = (
        f"phantom_soar_audit_{_safe_filename_part(report_data.period)}_{_safe_filename_part(analyst)}_"
        f"{_safe_filename_part('-'.join(report_data.filtered_severities).lower() or 'all-severities')}_"
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
        f"Generated at {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        subtitle_style
    ))
    story.append(Paragraph(
        f"Period: <b>{escape(report_data.period.upper())}</b> | "
        f"Range (inclusive, {escape(report_data.timezone)}): "
        f"<b>{_fmt_utc(report_data.start_date)}</b> to <b>{_fmt_utc(report_data.end_date)}</b> "
        f"{escape(report_data.timezone)} | "
        f"Analyst: <b>{escape(report_data.filtered_analyst or 'All Analysts')}</b> | "
        f"Severity: <b>{escape(sev_label)}</b>",
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
    story.append(Spacer(1, 10))

    sev_keys = list(report_data.severity_breakdown.keys())
    sev_rows = [
        [Paragraph(f"<b>{escape(k)}</b>", cell_bold) for k in sev_keys],
        [Paragraph(f"<font size=11><b>{report_data.severity_breakdown[k]}</b></font>", cell_style) for k in sev_keys],
    ]
    sev_table = Table(sev_rows, colWidths=[540 / len(sev_keys)] * len(sev_keys))
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(Paragraph("Cases by Severity", section_style))
    story.append(Spacer(1, 4))
    story.append(sev_table)
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
        breakdown_rows.append([p("No analyst actions recorded for the selected filters.")] + [p("")] * 7)

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
        case_rows.append([p("No cases found for the selected filters.")] + [p("")] * 5)

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
