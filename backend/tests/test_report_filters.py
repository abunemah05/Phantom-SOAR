"""Admin report filters: severity selection and second-precision / relative time ranges (UTC semantics)."""
from datetime import datetime, timedelta, timezone

import pytest

from backend.routers import reports
from backend.routers.reports import (
    ReportFilterError,
    parse_date_range,
    parse_severity_filter,
    resolve_report_range,
    severity_breakdown,
)

UTC = timezone.utc
NOW = datetime(2026, 6, 15, 12, 30, 45, 250000, tzinfo=UTC)
BASE = datetime(2019, 3, 4, 10, 0, 0, tzinfo=UTC)  # fixture day; far from anything else in the test database
ANALYST = "sevfilter_analyst"
URL = "/api/reports/analyst-activity"
PDF_URL = "/api/reports/analyst-activity/pdf"


# --------------------------------------------------------------------------- pure helpers: time ranges
def test_presets_are_unchanged_and_utc():
    day = resolve_report_range("day", now=NOW)
    assert (day.start, day.end, day.mode) == (datetime(2026, 6, 15, 0, 0, 0, tzinfo=UTC), NOW, "preset")
    assert parse_date_range("week", None, None, now=NOW) == (NOW - timedelta(days=7), NOW)
    assert parse_date_range("month", None, None, now=NOW) == (NOW - timedelta(days=30), NOW)
    # absent / empty period keeps the historic default of the last 30 days
    assert parse_date_range(None, None, None, now=NOW) == (NOW - timedelta(days=30), NOW)
    assert parse_date_range("", None, None, now=NOW) == (NOW - timedelta(days=30), NOW)


def test_date_only_custom_range_is_whole_utc_days_backward_compatible():
    start, end = parse_date_range("custom", "2020-01-01", "2020-01-02", now=NOW)
    assert start == datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)
    assert end == datetime(2020, 1, 2, 23, 59, 59, 999999, tzinfo=UTC)
    # a single day is a valid range (end-of-day is after start-of-day)
    start, end = parse_date_range("custom", "2020-01-01", "2020-01-01", now=NOW)
    assert end - start == timedelta(days=1) - timedelta(microseconds=1)
    # no end -> now
    assert parse_date_range("custom", "2026-06-01", None, now=NOW) == (datetime(2026, 6, 1, tzinfo=UTC), NOW)


def test_datetime_bounds_to_the_second_with_offsets_and_naive_as_utc():
    start, end = parse_date_range("custom", "2026-06-15T10:00:05Z", "2026-06-15T10:00:09Z", now=NOW)
    assert (start, end) == (datetime(2026, 6, 15, 10, 0, 5, tzinfo=UTC), datetime(2026, 6, 15, 10, 0, 9, tzinfo=UTC))
    # offsets convert to UTC
    start, end = parse_date_range("custom", "2026-06-15T12:00:05+02:00", "2026-06-15T05:00:09-05:00", now=NOW)
    assert start == datetime(2026, 6, 15, 10, 0, 5, tzinfo=UTC)
    assert end == datetime(2026, 6, 15, 10, 0, 9, tzinfo=UTC)
    # naive == UTC (deterministic, independent of the server's local zone), with or without seconds
    assert parse_date_range("custom", "2026-06-15T10:00:05", "2026-06-15T10:01", now=NOW) == (
        datetime(2026, 6, 15, 10, 0, 5, tzinfo=UTC), datetime(2026, 6, 15, 10, 1, 0, tzinfo=UTC))
    # fractional seconds survive; an un-encoded "+" arriving as a space is repaired
    start, _ = parse_date_range("custom", "2026-06-15T10:00:05.5 02:00", "2026-06-15T23:00:00Z", now=NOW)
    assert start == datetime(2026, 6, 15, 8, 0, 5, 500000, tzinfo=UTC)
    # a datetime end is NOT stretched to end-of-day: it is exactly the instant given
    assert parse_date_range("custom", "2026-06-15T00:00:00Z", "2026-06-15T10:00:00Z", now=NOW)[1].hour == 10


@pytest.mark.parametrize("unit,n,seconds", [
    ("seconds", 90, 90), ("second", 1, 1), ("minutes", 5, 300), ("min", 2, 120), ("HOURS", 3, 10800),
    ("hours", 1, 3600), ("days", 2, 172800), ("Day", 1, 86400),
])
def test_relative_units(unit, n, seconds):
    rng = resolve_report_range("relative", last_n=n, last_unit=unit, now=NOW)
    assert rng.end == NOW and rng.start == NOW - timedelta(seconds=seconds) and rng.mode == "relative"


def test_relative_limits():
    assert resolve_report_range("relative", last_n=366, last_unit="days", now=NOW).start == NOW - timedelta(days=366)
    for kwargs, fragment in [
        (dict(last_n=367, last_unit="days"), "too long"),
        (dict(last_n=9_000_000, last_unit="hours"), "too long"),
        (dict(last_n=0, last_unit="hours"), "at least 1"),
        (dict(last_n=-5, last_unit="hours"), "at least 1"),
        (dict(last_n=None, last_unit="hours"), "last_n is required"),
        (dict(last_n=5, last_unit=None), "last_unit"),
        (dict(last_n=5, last_unit="fortnights"), "last_unit"),
    ]:
        with pytest.raises(ReportFilterError, match=fragment):
            resolve_report_range("relative", now=NOW, **kwargs)


@pytest.mark.parametrize("start,end,fragment", [
    ("2026-06-15T10:00:05Z", "2026-06-15T10:00:05Z", "after its start"),  # zero-length
    ("2026-06-15T10:00:06Z", "2026-06-15T10:00:05Z", "after its start"),
    ("2026-06-15T12:00:05+02:00", "2026-06-15T10:00:05Z", "after its start"),  # same instant, different offset
    ("2026-06-20", "2026-06-10", "after its start"),
    ("2026-06-30", None, "after its start"),  # start in the future, end defaults to now
    ("2020-01-01", "2026-06-15", "too long"),
    ("2025-01-01", "2026-06-15", "too long"),
    ("not-a-date", None, "start_date"),
    ("2026-13-45", None, "start_date"),
    ("2026-06-15T25:00:00Z", None, "start_date"),
    ("1999-12-31", "2000-01-02", "year"),
    ("2026-06-01", "yesterday", "end_date"),
    (None, "2026-06-01", "start_date is required"),
    ("", None, "start_date is required"),
])
def test_invalid_custom_ranges_are_rejected(start, end, fragment):
    with pytest.raises(ReportFilterError, match=fragment):
        parse_date_range("custom", start, end, now=NOW)


def test_366_day_span_is_the_inclusive_limit():
    assert parse_date_range("custom", "2026-01-01", "2026-12-31", now=NOW)  # 365 days: still accepted
    with pytest.raises(ReportFilterError, match="too long"):
        parse_date_range("custom", "2025-06-14T12:30:45Z", "2026-06-15T12:30:46Z", now=NOW)  # 366d + 1s
    assert parse_date_range("custom", "2025-06-14T12:30:45Z", "2026-06-15T12:30:45Z", now=NOW)  # exactly 366d


def test_unknown_period_is_rejected():
    with pytest.raises(ReportFilterError, match="period must be one of"):
        resolve_report_range("fortnight", now=NOW)


# --------------------------------------------------------------------------- pure helpers: severity
def test_severity_filter_parsing():
    assert parse_severity_filter(None) == []
    assert parse_severity_filter([]) == []
    assert parse_severity_filter([""]) == []
    assert parse_severity_filter(["all"]) == []
    assert parse_severity_filter(["ALL"]) == []
    assert parse_severity_filter(["High"]) == ["High"]
    assert parse_severity_filter(["critical"]) == ["Critical"]
    # canonical order (most severe first), de-duplicated, comma lists and repeated params both work
    assert parse_severity_filter(["low", "CRITICAL", "low"]) == ["Critical", "Low"]
    assert parse_severity_filter(["high, medium", "Low"]) == ["High", "Medium", "Low"]


@pytest.mark.parametrize("values,fragment", [
    (["urgent"], "Unknown severity 'urgent'"),
    (["High", "bogus", "nope"], "'bogus', 'nope'"),
    (["all", "High"], "cannot be combined"),
    (["info"], "Critical, High, Medium, Low"),
])
def test_severity_filter_rejects_unknown_values(values, fragment):
    with pytest.raises(ReportFilterError, match=fragment):
        parse_severity_filter(values)


def test_severity_breakdown_counts_every_level_and_flags_unexpected_values():
    class A:
        def __init__(self, severity):
            self.severity = severity

    counts = severity_breakdown([A("High"), A("high"), A("Low"), A("Weird"), A(None)])
    assert list(counts) == ["Critical", "High", "Medium", "Low", "Other"]
    assert counts == {"Critical": 0, "High": 2, "Medium": 0, "Low": 1, "Other": 2}
    assert "Other" not in severity_breakdown([])


# --------------------------------------------------------------------------- endpoints
@pytest.fixture(scope="module")
def severity_fixture(client, admin_headers):
    """One resolved alert per severity at known seconds, each with a log, containment action and execution."""
    from backend.database import SessionLocal
    from backend.models import Alert, AnalystActionLog, ContainmentAction, PlaybookExecution

    plan = [  # severity, offset from BASE, mttr
        ("Critical", timedelta(seconds=0), 10.0),
        ("High", timedelta(seconds=5), 20.0),
        ("Medium", timedelta(seconds=10), 30.0),
        ("Low", timedelta(seconds=15, microseconds=123456), 40.0),
    ]
    db = SessionLocal()
    ids = {}
    try:
        for severity, offset, mttr in plan:
            when = BASE + offset
            alert = Alert(rule_id=f"SEVFILTER-{severity}", source="Wazuh", severity=severity, status="Contained",
                          assigned_analyst=ANALYST, resolved_by=ANALYST, resolved_at=when, created_at=when,
                          raw_payload={})
            db.add(alert)
            db.flush()
            ids[severity] = alert.alert_id
            db.add_all([
                PlaybookExecution(alert_id=alert.alert_id, status="Completed", mttr_seconds=mttr, executed_at=when),
                ContainmentAction(alert_id=alert.alert_id, action_type="block_ip", status="Simulated",
                                  execution_mode="simulated", executed_by=ANALYST, timestamp=when),
                AnalystActionLog(alert_id=alert.alert_id, analyst_username=ANALYST, action_type="take_action",
                                 decision="Escalated & Contained", timestamp=when),
            ])
        db.commit()
    finally:
        db.close()
    yield ids
    db = SessionLocal()
    try:
        for alert_id in ids.values():
            alert = db.get(Alert, alert_id)
            if alert:
                db.delete(alert)
        db.commit()
    finally:
        db.close()


def _get(client, headers, query, url=URL):
    return client.get(f"{url}?{query}", headers=headers)


DAY = "period=custom&start_date=2019-03-04&end_date=2019-03-04"


def _case_ids(report):
    return {c["alert_id"] for c in report["cases"]}


def test_no_severity_filter_includes_all_and_reports_breakdown(client, admin_headers, severity_fixture):
    r = _get(client, admin_headers, DAY)
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["total_cases_reviewed"] == 4
    assert rep["filtered_severities"] == []
    assert rep["severity_breakdown"] == {"Critical": 1, "High": 1, "Medium": 1, "Low": 1}
    assert list(rep["severity_breakdown"]) == ["Critical", "High", "Medium", "Low"]
    assert rep["total_containment_actions"] == 4
    assert rep["average_mttr_seconds"] == 25.0 and rep["mttr_sample_size"] == 4
    assert rep["timezone"] == "UTC" and rep["range_mode"] == "absolute"
    assert rep["start_date"] == "2019-03-04T00:00:00+00:00"
    assert rep["end_date"] == "2019-03-04T23:59:59.999999+00:00"
    assert rep["generated_at"]
    row = next(a for a in rep["analyst_breakdown"] if a["analyst_username"] == ANALYST)
    assert (row["cases_assigned"], row["cases_resolved"], row["escalated_count"], row["containment_actions_taken"]) == (4, 4, 4, 4)
    # "all" and an empty value are the same as no filter
    for q in ("severity=all", "severity=ALL", "severity="):
        assert _get(client, admin_headers, f"{DAY}&{q}").json()["total_cases_reviewed"] == 4


@pytest.mark.parametrize("severity,mttr", [("Critical", 10.0), ("High", 20.0), ("Medium", 30.0), ("Low", 40.0)])
def test_each_single_severity_filters_every_number(client, admin_headers, severity_fixture, severity, mttr):
    for spelling in (severity, severity.upper(), severity.lower()):
        rep = _get(client, admin_headers, f"{DAY}&severity={spelling}").json()
        assert rep["filtered_severities"] == [severity]
        assert rep["total_cases_reviewed"] == 1
        assert _case_ids(rep) == {severity_fixture[severity]}
        assert rep["severity_breakdown"] == {s: int(s == severity) for s in ("Critical", "High", "Medium", "Low")}
        assert rep["total_containment_actions"] == 1 and rep["containment_by_mode"] == {"simulated": 1}
        assert rep["average_mttr_seconds"] == mttr and rep["mttr_sample_size"] == 1
        assert [log["alert_id"] for log in rep["action_logs"]] == [severity_fixture[severity]]
        row = next(a for a in rep["analyst_breakdown"] if a["analyst_username"] == ANALYST)
        assert (row["cases_assigned"], row["cases_resolved"], row["escalated_count"]) == (1, 1, 1)
        assert row["containment_actions_taken"] == 1 and row["avg_mttr_seconds"] == mttr


def test_multiple_severities_repeated_and_comma_forms(client, admin_headers, severity_fixture):
    expected = {severity_fixture["Critical"], severity_fixture["High"]}
    for q in ("severity=High&severity=Critical", "severity=critical,HIGH", "severity=High,Critical,high"):
        rep = _get(client, admin_headers, f"{DAY}&{q}").json()
        assert rep["filtered_severities"] == ["Critical", "High"], q
        assert _case_ids(rep) == expected
        assert rep["total_cases_reviewed"] == 2 and rep["total_containment_actions"] == 2
        assert rep["average_mttr_seconds"] == 15.0 and rep["mttr_sample_size"] == 2
        assert rep["severity_breakdown"] == {"Critical": 1, "High": 1, "Medium": 0, "Low": 0}
        row = next(a for a in rep["analyst_breakdown"] if a["analyst_username"] == ANALYST)
        assert (row["cases_assigned"], row["containment_actions_taken"], row["escalated_count"]) == (2, 2, 2)
        assert len(rep["action_logs"]) == 2


def test_severity_with_no_matching_cases_is_an_empty_report_not_an_error(client, admin_headers, severity_fixture):
    # the fixture day has one case per severity; a different, empty day has none for any severity
    rep = _get(client, admin_headers, "period=custom&start_date=2019-03-05&end_date=2019-03-05&severity=Critical").json()
    assert rep["total_cases_reviewed"] == 0 and rep["cases"] == []
    assert rep["severity_breakdown"] == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}


def test_severity_combined_with_analyst_filter(client, admin_headers, severity_fixture):
    rep = _get(client, admin_headers, f"{DAY}&severity=Low&analyst={ANALYST}").json()
    assert rep["filtered_analyst"] == ANALYST and rep["total_cases_reviewed"] == 1
    assert [a["analyst_username"] for a in rep["analyst_breakdown"]] == [ANALYST]
    assert rep["analyst_breakdown"][0]["cases_assigned"] == 1
    other = _get(client, admin_headers, f"{DAY}&severity=Low&analyst=nobody_here").json()
    assert other["total_cases_reviewed"] == 0


@pytest.mark.parametrize("query,fragment", [
    ("severity=urgent", "Unknown severity 'urgent'"),
    ("severity=High&severity=bogus", "'bogus'"),
    ("severity=all&severity=High", "cannot be combined"),
    ("severity=Critical,,info", "'info'"),
])
def test_invalid_severity_is_422_with_clear_message(client, admin_headers, query, fragment):
    for url in (URL, PDF_URL):
        r = _get(client, admin_headers, f"{DAY}&{query}", url=url)
        assert r.status_code == 422, (url, r.text)
        assert fragment in r.json()["detail"]
        assert "Critical, High, Medium, Low" in r.json()["detail"] or "combined" in r.json()["detail"]


def test_filters_still_require_admin(client, severity_fixture):
    assert client.get(f"{URL}?{DAY}&severity=High").status_code in (401, 403)
    assert client.get(f"{PDF_URL}?{DAY}&severity=High").status_code in (401, 403)


# --- time to the second, through the API
def _range(start, end, extra=""):
    from urllib.parse import quote
    return f"period=custom&start_date={quote(start)}&end_date={quote(end)}{extra}"


def test_boundaries_are_inclusive_at_both_ends_to_the_second(client, admin_headers, severity_fixture):
    ids = severity_fixture
    c, h, m, lo = ids["Critical"], ids["High"], ids["Medium"], ids["Low"]
    # fixture instants: Critical 10:00:00, High 10:00:05, Medium 10:00:10, Low 10:00:15.123456
    cases = [
        ("2019-03-04T10:00:00Z", "2019-03-04T10:00:05Z", {c, h}),            # both bounds inclusive
        ("2019-03-04T10:00:00.000001Z", "2019-03-04T10:00:05Z", {h}),          # start 1 microsecond after Critical
        ("2019-03-04T10:00:00Z", "2019-03-04T10:00:04.999999Z", {c}),          # end 1 microsecond before High
        ("2019-03-04T10:00:05Z", "2019-03-04T10:00:10Z", {h, m}),
        ("2019-03-04T10:00:06Z", "2019-03-04T10:00:09Z", set()),               # between two alerts
        ("2019-03-04T10:00:15Z", "2019-03-04T10:00:16Z", {lo}),                # sub-second stamp inside the range
        ("2019-03-04T10:00:15.123457Z", "2019-03-04T10:00:20Z", set()),
        ("2019-03-04T10:00:00Z", "2019-03-04T10:00:15.123456Z", {c, h, m, lo}),  # end exactly on the microsecond
    ]
    for start, end, expected in cases:
        rep = _get(client, admin_headers, _range(start, end)).json()
        assert _case_ids(rep) == expected, (start, end)
        assert rep["total_cases_reviewed"] == len(expected)
        assert rep["range_mode"] == "absolute"


def test_timezone_offsets_and_naive_inputs_resolve_to_the_same_instants(client, admin_headers, severity_fixture):
    h = severity_fixture["High"]
    expected_utc = _get(client, admin_headers, _range("2019-03-04T10:00:05Z", "2019-03-04T10:00:06Z")).json()
    assert _case_ids(expected_utc) == {h}
    for start, end in [
        ("2019-03-04T12:00:05+02:00", "2019-03-04T12:00:06+02:00"),
        ("2019-03-04T05:00:05-05:00", "2019-03-04T05:00:06-05:00"),
        ("2019-03-04T15:30:05+05:30", "2019-03-04T15:30:06+05:30"),
        ("2019-03-04T10:00:05", "2019-03-04T10:00:06"),  # naive -> UTC
    ]:
        rep = _get(client, admin_headers, _range(start, end)).json()
        assert _case_ids(rep) == {h}, (start, end)
        assert rep["start_date"] == "2019-03-04T10:00:05+00:00" and rep["end_date"] == "2019-03-04T10:00:06+00:00"
        assert rep["timezone"] == "UTC"
    # the local-looking time without an offset is NOT shifted: 12:00:05 naive is 12:00:05 UTC, not 10:00:05
    assert _case_ids(_get(client, admin_headers, _range("2019-03-04T12:00:05", "2019-03-04T12:00:06")).json()) == set()
    # an unencoded "+" (a space after URL decoding) is repaired rather than misread
    raw = _get(client, admin_headers, "period=custom&start_date=2019-03-04T12:00:05+02:00&end_date=2019-03-04T12:00:06+02:00")
    assert _case_ids(raw.json()) == {h}


def test_date_only_range_still_covers_the_whole_utc_day(client, admin_headers, severity_fixture):
    assert _case_ids(_get(client, admin_headers, DAY).json()) >= set(severity_fixture.values())
    for day in ("2019-03-03", "2019-03-05"):
        assert not (_case_ids(_get(client, admin_headers, f"period=custom&start_date={day}&end_date={day}").json())
                    & set(severity_fixture.values()))


def test_relative_range_over_the_api(client, admin_headers):
    from backend.database import SessionLocal
    from backend.models import Alert

    now = datetime.now(UTC)
    db = SessionLocal()
    try:
        recent = Alert(rule_id="REL-RECENT", source="Wazuh", severity="Low", status="New", created_at=now - timedelta(seconds=20), raw_payload={})
        older = Alert(rule_id="REL-OLDER", source="Wazuh", severity="Low", status="New", created_at=now - timedelta(hours=3), raw_payload={})
        db.add_all([recent, older])
        db.commit()
        recent_id, older_id = recent.alert_id, older.alert_id
    finally:
        db.close()
    try:
        def ids(q):
            rep = _get(client, admin_headers, q).json()
            return _case_ids(rep), rep

        got, rep = ids("period=relative&last_n=120&last_unit=seconds&severity=Low")
        assert recent_id in got and older_id not in got
        assert rep["period"] == "relative" and rep["range_mode"] == "relative"
        start = datetime.fromisoformat(rep["start_date"])
        end = datetime.fromisoformat(rep["end_date"])
        assert end - start == timedelta(seconds=120) and rep["timezone"] == "UTC"
        got, _ = ids("period=relative&last_n=2&last_unit=minutes&severity=Low")
        assert recent_id in got and older_id not in got
        got, _ = ids("period=relative&last_n=4&last_unit=hours&severity=Low")
        assert {recent_id, older_id} <= got
        got, _ = ids("period=relative&last_n=10&last_unit=seconds&severity=Low")
        assert recent_id not in got
        got, _ = ids("period=relative&last_n=1&last_unit=days&severity=High")  # severity still applies
        assert not ({recent_id, older_id} & got)
    finally:
        db = SessionLocal()
        try:
            for i in (recent_id, older_id):
                row = db.get(Alert, i)
                if row:
                    db.delete(row)
            db.commit()
        finally:
            db.close()


@pytest.mark.parametrize("query,fragment", [
    ("period=custom&start_date=2019-03-04T10:00:05Z&end_date=2019-03-04T10:00:05Z", "after its start"),
    ("period=custom&start_date=2019-03-04T10:00:06Z&end_date=2019-03-04T10:00:05Z", "after its start"),
    ("period=custom&start_date=2010-01-01&end_date=2019-01-01", "too long"),
    ("period=custom&start_date=garbage", "start_date"),
    ("period=custom&end_date=2019-03-04", "start_date is required"),
    ("period=custom", "start_date is required"),
    ("period=relative&last_n=0&last_unit=hours", "at least 1"),
    ("period=relative&last_n=5", "last_unit"),
    ("period=relative&last_unit=hours", "last_n is required"),
    ("period=relative&last_n=5&last_unit=weeks", "last_unit"),
    ("period=relative&last_n=999&last_unit=days", "too long"),
    ("period=forever", "period must be one of"),
])
def test_invalid_ranges_are_422_with_clear_message_on_both_endpoints(client, admin_headers, query, fragment):
    for url in (URL, PDF_URL):
        r = _get(client, admin_headers, query, url=url)
        assert r.status_code == 422, (url, query, r.text)
        assert fragment in r.json()["detail"], r.json()
    assert _get(client, admin_headers, "period=relative&last_n=abc&last_unit=hours").status_code == 422  # not an integer


def test_existing_presets_still_return_a_utc_range(client, admin_headers):
    for period in ("day", "week", "month"):
        rep = _get(client, admin_headers, f"period={period}").json()
        assert rep["period"] == period and rep["range_mode"] == "preset" and rep["timezone"] == "UTC"
        assert datetime.fromisoformat(rep["end_date"]) > datetime.fromisoformat(rep["start_date"])
    assert _get(client, admin_headers, "").json()["period"] == "month"  # defaults unchanged


# --- PDF export with filters
def _capture_pdf_text(monkeypatch):
    """Record every Paragraph the PDF is built from (the PDF streams themselves are compressed)."""
    from reportlab.platypus import SimpleDocTemplate

    captured = []
    original = SimpleDocTemplate.build

    def spy(self, flowables, *a, **kw):
        def walk(items):
            for f in items:
                if hasattr(f, "_cellvalues"):
                    for row in f._cellvalues:
                        walk(row)
                elif hasattr(f, "text"):
                    captured.append(f.text)
        walk(flowables)
        return original(self, flowables, *a, **kw)

    monkeypatch.setattr(SimpleDocTemplate, "build", spy)
    return captured


def test_pdf_header_shows_exact_range_timezone_and_severity_filter(client, admin_headers, severity_fixture, monkeypatch):
    texts = _capture_pdf_text(monkeypatch)
    query = _range("2019-03-04T12:00:00+02:00", "2019-03-04T12:00:10+02:00", "&severity=high&severity=critical")
    r = _get(client, admin_headers, query, url=PDF_URL)
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF") and len(r.content) > 1000
    joined = "\n".join(texts)
    assert "2019-03-04 10:00:00</b> to <b>2019-03-04 10:00:10</b> UTC" in joined  # offset input shown in UTC, to the second
    assert "Severity: <b>Critical, High</b>" in joined
    assert "Range (inclusive, UTC)" in joined
    assert "Cases by Severity" in joined
    # the cases table lists exactly the filtered cases
    assert "#%d" % severity_fixture["Critical"] in joined and "#%d" % severity_fixture["High"] in joined
    assert "#%d" % severity_fixture["Medium"] not in joined and "#%d" % severity_fixture["Low"] not in joined
    disposition = r.headers["content-disposition"]
    assert "critical-high" in disposition and ".." not in disposition and "/" not in disposition.split("filename=")[1]


def test_pdf_without_severity_says_all_severities_and_relative_range(client, admin_headers, monkeypatch):
    texts = _capture_pdf_text(monkeypatch)
    r = _get(client, admin_headers, "period=relative&last_n=90&last_unit=minutes", url=PDF_URL)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    joined = "\n".join(texts)
    assert "Severity: <b>All severities</b>" in joined
    assert "Period: <b>RELATIVE</b>" in joined and "UTC" in joined
    assert "all-severities" in r.headers["content-disposition"]


def test_pdf_with_filters_but_no_data_still_renders(client, admin_headers, severity_fixture):
    r = _get(client, admin_headers, "period=custom&start_date=2019-03-05&end_date=2019-03-05&severity=Low", url=PDF_URL)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")


def test_report_module_documents_its_limits():
    assert reports.MAX_RANGE_DAYS == 366 and reports.REPORT_TIMEZONE == "UTC"


# --------------------------------------------------------------------------- every number honours range AND severity
WIN = datetime(2018, 5, 1, 10, 0, 0, tzinfo=UTC)  # moment no other test uses
WIN_ANALYST = "rangecheck_analyst"
WIN_DAY = "period=custom&start_date=2018-05-01T10:00:00Z&end_date=2018-05-01T10:00:10Z"  # exact seconds: the action 1 s earlier is outside


@pytest.fixture
def window_fixture(client, admin_headers):
    """Window = 2018-05-01 (UTC). One alert in it (High) and one (Low); a High alert's action 400 days later, an
    old alert's (High) action inside the window, an action 1 s before the window, and padded / lower-cased severities."""
    from backend.database import SessionLocal
    from backend.models import Alert, ContainmentAction, PlaybookExecution

    db = SessionLocal()
    alerts = []

    def alert(severity, created):
        a = Alert(rule_id=f"RANGECHK-{severity.strip()}", source="Wazuh", severity=severity, status="Contained",
                  assigned_analyst=WIN_ANALYST, resolved_by=WIN_ANALYST, created_at=created, resolved_at=created, raw_payload={})
        db.add(a)
        db.flush()
        alerts.append(a.alert_id)
        return a.alert_id

    def action(alert_id, when, mode="simulated", by=WIN_ANALYST):
        db.add(ContainmentAction(alert_id=alert_id, action_type="block_ip", status="Executed", execution_mode=mode,
                                 executed_by=by, timestamp=when))

    def execution(alert_id, when, mttr):
        db.add(PlaybookExecution(alert_id=alert_id, status="Completed", mttr_seconds=mttr, executed_at=when))

    try:
        high = alert("High", WIN)
        low = alert("Low", WIN + timedelta(seconds=1))
        padded = alert("  high ", WIN + timedelta(seconds=2))  # stored with padding and lower case
        old_high = alert("High", WIN - timedelta(days=40))  # created long before the window
        action(high, WIN + timedelta(seconds=5))  # counted
        action(low, WIN + timedelta(seconds=6), mode="live")  # counted (Low)
        action(padded, WIN + timedelta(seconds=7))  # counted (High after trim / lower)
        action(high, WIN + timedelta(days=400), mode="live")  # 400 days AFTER the window: never counted
        action(high, WIN - timedelta(seconds=1))  # one second BEFORE the window: never counted
        action(old_high, WIN + timedelta(seconds=8))  # alert is old, the ACTION is in the window: counted
        action(old_high, WIN - timedelta(days=39))  # alert old, action old: not counted
        execution(high, WIN + timedelta(seconds=5), 10.0)  # counted
        execution(high, WIN + timedelta(days=400), 9999.0)  # outside: must not skew the average
        execution(low, WIN + timedelta(seconds=6), 30.0)  # counted (Low)
        db.commit()
    finally:
        db.close()
    yield {"high": high, "low": low, "padded": padded, "old_high": old_high}
    db = SessionLocal()
    try:
        for alert_id in alerts:
            row = db.get(Alert, alert_id)
            if row:
                db.delete(row)
        db.commit()
    finally:
        db.close()


def test_containment_and_mttr_ignore_actions_outside_the_range(client, admin_headers, window_fixture):
    rep = _get(client, admin_headers, f"{WIN_DAY}&analyst={WIN_ANALYST}").json()
    # 4 actions inside the window (high, low, padded, old_high's); the +400 days and -1 s ones are not counted.
    assert rep["total_containment_actions"] == 4
    assert rep["containment_by_mode"] == {"simulated": 3, "live": 1}
    row = next(a for a in rep["analyst_breakdown"] if a["analyst_username"] == WIN_ANALYST)
    assert row["containment_actions_taken"] == rep["total_containment_actions"]  # the two figures agree
    assert rep["average_mttr_seconds"] == 20.0 and rep["mttr_sample_size"] == 2  # 9999.0 (400 days later) excluded
    assert row["avg_mttr_seconds"] == 20.0


def test_a_window_that_only_contains_the_late_action_counts_exactly_that_action(client, admin_headers, window_fixture):
    day = (WIN + timedelta(days=400)).strftime("%Y-%m-%d")
    rep = _get(client, admin_headers, f"period=custom&start_date={day}&end_date={day}&analyst={WIN_ANALYST}").json()
    assert rep["total_containment_actions"] == 1 and rep["containment_by_mode"] == {"live": 1}
    assert rep["average_mttr_seconds"] == 9999.0 and rep["mttr_sample_size"] == 1
    # ... while the cases of that window are none: cases are alerts created or resolved inside the range.
    assert rep["total_cases_reviewed"] == 0


def test_range_and_severity_apply_together_to_every_number(client, admin_headers, window_fixture):
    rep = _get(client, admin_headers, f"{WIN_DAY}&analyst={WIN_ANALYST}&severity=High").json()
    assert rep["total_cases_reviewed"] == 2  # "High" and "  high " (the old one was created outside the window)
    assert rep["total_containment_actions"] == 3  # high's, padded's and the old alert's action inside the window
    assert rep["containment_by_mode"] == {"simulated": 3}
    assert rep["average_mttr_seconds"] == 10.0 and rep["mttr_sample_size"] == 1
    row = next(a for a in rep["analyst_breakdown"] if a["analyst_username"] == WIN_ANALYST)
    assert row["containment_actions_taken"] == 3 and row["avg_mttr_seconds"] == 10.0
    low = _get(client, admin_headers, f"{WIN_DAY}&analyst={WIN_ANALYST}&severity=Low").json()
    assert low["total_cases_reviewed"] == 1 and low["total_containment_actions"] == 1 and low["containment_by_mode"] == {"live": 1}
    assert low["average_mttr_seconds"] == 30.0


def test_severity_filter_and_breakdown_treat_padding_and_case_alike(client, admin_headers, window_fixture):
    rep = _get(client, admin_headers, f"{WIN_DAY}&analyst={WIN_ANALYST}").json()
    assert rep["severity_breakdown"] == {"Critical": 0, "High": 2, "Medium": 0, "Low": 1}  # no "Other"
    filtered = _get(client, admin_headers, f"{WIN_DAY}&analyst={WIN_ANALYST}&severity=high").json()
    assert filtered["total_cases_reviewed"] == 2 and filtered["severity_breakdown"]["High"] == 2
    assert {c["alert_id"] for c in filtered["cases"]} == {window_fixture["high"], window_fixture["padded"]}


def test_the_pdf_uses_the_same_numbers(client, admin_headers, window_fixture):
    res = _get(client, admin_headers, f"{WIN_DAY}&analyst={WIN_ANALYST}&severity=High", url=PDF_URL)
    assert res.status_code == 200 and res.content.startswith(b"%PDF")
