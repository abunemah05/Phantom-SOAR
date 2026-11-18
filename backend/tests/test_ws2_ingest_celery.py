"""WS2: fast ingest path, Celery dispatch/retry, re-enrichment, defanging, IOC cap, demo seeding."""
import time
from typing import Any, Dict, List

import pytest

from backend import celery_app as celery_module
from backend.engine import ingest
from backend.integrations import tip

LAB_BAD_IP = "198.51.100.45"  # simulation-mode lab fixture: Malicious


def _payload(level: int = 3, **data) -> Dict[str, Any]:
    return {
        "rule": {"id": "5710", "level": level, "description": "ws2 test"},
        "agent": {"id": "001", "name": "host-ws2", "ip": "10.9.9.9"},
        "data": data,
    }


@pytest.fixture
def db(client):
    from backend.database import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _artifacts(db, alert_id):
    from backend.models import IocArtifact

    db.expire_all()
    return db.query(IocArtifact).filter(IocArtifact.alert_id == alert_id).all()


def _logs(db, needle: str):
    from backend.models import SystemLog

    db.expire_all()
    return [log for log in db.query(SystemLog).all() if needle in (log.message or "")]


# --- defanging and the IOC cap ---------------------------------------------------------

def test_defanged_indicators_are_refanged():
    payload = _payload(full_log="beacon to hxxps://evil-c2[.]example[.]com/gate and 203[.]0[.]113[.]9 then hxxp[:]//bad[.]example/x")
    iocs, dropped = ingest.extract_iocs(payload)
    found = {(i["artifact_type"], i["value"]) for i in iocs}
    assert ("URL", "https://evil-c2.example.com/gate") in found
    assert ("IP", "203.0.113.9") in found
    assert ("Domain", "evil-c2.example.com") in found
    assert ("URL", "http://bad.example/x") in found
    assert dropped == 0
    assert ingest.refang("a(.)b[dot]c user[@]x.example") == "a.b.c user@x.example"


def test_iocs_beyond_the_cap_are_counted_and_logged(db):
    ips = {f"ip{i}": f"203.0.113.{i}" for i in range(1, 31)}
    result = ingest.ingest_alert_with_details(db, _payload(**ips), "wazuh")
    assert result.iocs_dropped == 5
    assert len(_artifacts(db, result.alert.alert_id)) == ingest.MAX_IOCS_PER_ALERT
    entries = _logs(db, f"Alert #{result.alert.alert_id}: 5 indicator(s) exceeded")
    assert entries and entries[0].level == "WARNING"
    assert entries[0].details["iocs_dropped"] == 5 and len(entries[0].details["dropped_sample"]) == 5


# --- fast path and dispatch ------------------------------------------------------------

def test_fast_path_saves_pending_iocs_and_queues_instead_of_enriching(db, monkeypatch):
    queued: List[Any] = []
    monkeypatch.setattr(ingest, "_enqueue", lambda task, args, countdown=None: queued.append((task.name, args)) or True)
    monkeypatch.setattr(ingest, "enrich_and_process_alert", lambda a: pytest.fail("must not run inline when queued"))
    monkeypatch.setattr(tip.tip_client, "enrich_ioc", lambda *a, **k: pytest.fail("no TIP call on the webhook path"))

    result = ingest.ingest_alert_with_details(db, _payload(level=3, srcip=LAB_BAD_IP), "wazuh")

    assert result.processing == "celery" and result.celery_dispatched and result.enrichment_pending
    assert queued == [("tasks.enrich_and_process_alert", [result.alert.alert_id])]
    assert result.alert.status == "New" and result.alert.severity == "Low"
    assert result.escalated_from is None
    art = result.artifacts[0]
    assert art["value"] == LAB_BAD_IP and art["verdict"] == "Unknown" and art["enrichment_status"] == "pending"


def test_inline_fallback_enriches_escalates_once_and_processes(db, monkeypatch):
    monkeypatch.setattr(ingest, "_enqueue", lambda *a, **k: False)
    result = ingest.ingest_alert_with_details(db, _payload(level=3, srcip=LAB_BAD_IP), "wazuh")
    assert result.processing == "sync"
    assert result.alert.severity == "Medium" and result.escalated_from == "Low"
    assert result.artifacts[0]["verdict"] == "Malicious"
    assert result.alert.status != "New"  # the runner handled it


def test_dispatch_with_unreachable_broker_falls_back_inline_quickly(db):
    # conftest points the broker at 127.0.0.1:1 (connection refused).
    start = time.monotonic()
    result = ingest.ingest_alert_with_details(db, _payload(level=3, srcip=LAB_BAD_IP), "wazuh")
    assert time.monotonic() - start < 6  # no ~20 s result-backend retry loop
    assert result.processing == "sync" and result.artifacts[0]["verdict"] == "Malicious"


def test_enqueue_reports_success_and_failure():
    class Task:
        name = "t"

        def __init__(self, exc=None):
            self.exc, self.kwargs = exc, None

        def apply_async(self, **kwargs):
            self.kwargs = kwargs
            if self.exc:
                raise self.exc
            return object()

    ok = Task()
    assert ingest._enqueue(ok, [1], countdown=7) is True
    assert ok.kwargs["args"] == [1] and ok.kwargs["countdown"] == 7 and ok.kwargs["retry"] is True
    assert ok.kwargs["retry_policy"]["max_retries"] >= 1
    assert ingest._enqueue(Task(ConnectionError("down")), [1]) is False


def test_never_runs_both_celery_and_inline(db, monkeypatch):
    calls = []
    monkeypatch.setattr(ingest, "_enqueue", lambda *a, **k: True)
    monkeypatch.setattr(ingest, "enrich_and_process_alert", lambda a: calls.append(a))
    assert ingest.dispatch_alert_processing(123) == "celery"
    assert calls == []
    monkeypatch.setattr(ingest, "_enqueue", lambda *a, **k: False)
    assert ingest.dispatch_alert_processing(123) == "sync" and calls == [123]


def test_enrich_and_process_is_idempotent_and_escalates_once(db, monkeypatch):
    monkeypatch.setattr(ingest, "_enqueue", lambda *a, **k: True)  # leave the alert un-enriched
    result = ingest.ingest_alert_with_details(db, _payload(level=3, srcip=LAB_BAD_IP), "wazuh")
    alert_id = result.alert.alert_id
    first = ingest.enrich_and_process_alert(alert_id)
    second = ingest.enrich_and_process_alert(alert_id)  # redelivery
    assert first["escalated_from"] == "Low" and second["escalated_from"] is None
    assert second["iocs_enriched"] == 0
    db.expire_all()
    from backend.crud import get_alert
    assert get_alert(db, alert_id).severity == "Medium"  # one step only


# --- re-enrichment ---------------------------------------------------------------------

def _rate_limited(value, retry_after=7):
    return {
        "artifact_type": "IP", "value": value, "threat_score": 0, "verdict": "Unknown",
        "enrichment_status": "partial", "simulated": False, "incomplete": True,
        "providers": {"virustotal": {"status": "rate_limited", "retry_after_seconds": retry_after}},
    }


def _malicious(value):
    return {
        "artifact_type": "IP", "value": value, "threat_score": 90, "verdict": "Malicious",
        "enrichment_status": "enriched", "simulated": False,
        "providers": {"virustotal": {"status": "ok"}},
    }


def test_incomplete_helpers_use_defensive_field_names():
    assert ingest.result_is_incomplete({"incomplete": True})
    assert ingest.result_is_incomplete({"providers": {"a": {"status": "rate_limited"}}})
    assert not ingest.result_is_incomplete({"providers": {"a": {"status": "ok"}}})
    assert not ingest.result_is_incomplete({})
    assert ingest.result_retry_delay({"providers": {"a": {"status": "rate_limited", "retry_after_seconds": 90}}}) == 90
    assert ingest.result_retry_delay({"providers": {"a": {"status": "rate_limited", "retry_after_seconds": 99999}}}) == ingest.REENRICH_MAX_DELAY
    assert ingest.result_retry_delay({"providers": {"a": {"status": "rate_limited"}}}) == ingest.REENRICH_DEFAULT_DELAY
    assert ingest.result_retry_delay({"incomplete": True}) == ingest.REENRICH_DEFAULT_DELAY


def test_rate_limited_iocs_are_rescheduled_with_countdown_and_then_escalate_once(db, monkeypatch):
    scheduled: List[Any] = []

    def fake_enqueue(task, args, countdown=None):
        scheduled.append((task.name, args, countdown))
        return task.name == "tasks.re_enrich_iocs" or task.name == "tasks.enrich_and_process_alert"

    monkeypatch.setattr(ingest, "_enqueue", fake_enqueue)
    monkeypatch.setattr(tip.tip_client, "enrich_ioc", lambda t, v, settings=None: _rate_limited(v, 7))
    result = ingest.ingest_alert_with_details(db, _payload(level=3, srcip="203.0.113.50"), "wazuh")
    alert_id = result.alert.alert_id
    assert scheduled[0][0] == "tasks.enrich_and_process_alert"

    scheduled.clear()
    ingest.enrich_and_process_alert(alert_id)
    (name, args, countdown), = scheduled
    art = _artifacts(db, alert_id)[0]
    assert name == "tasks.re_enrich_iocs" and args == [alert_id, [art.artifact_id], 1] and countdown == 7
    assert art.enrichment_status == "partial"
    processed_status = db.query(type(result.alert)).get(alert_id).status
    assert processed_status != "New"  # processing did not wait for the delayed re-enrichment

    # Second attempt: still rate limited -> rescheduled as attempt 2; the third is the last.
    scheduled.clear()
    ingest.re_enrich_incomplete_iocs(alert_id, [art.artifact_id], 1)
    assert [a[1][2] for a in scheduled] == [2]
    scheduled.clear()
    ingest.re_enrich_incomplete_iocs(alert_id, [art.artifact_id], ingest.REENRICH_MAX_ATTEMPTS)
    assert scheduled == []

    # Now the verdict turns Malicious: artifact updated, severity escalated once, runner called.
    monkeypatch.setattr(tip.tip_client, "enrich_ioc", lambda t, v, settings=None: _malicious(v))
    runner_calls = []
    import backend.engine.runner as runner
    monkeypatch.setattr(runner, "process_alert", lambda a: runner_calls.append(a) or {"status": "x"})
    out = ingest.re_enrich_incomplete_iocs(alert_id, [art.artifact_id], 2)
    again = ingest.re_enrich_incomplete_iocs(alert_id, [art.artifact_id], 2)
    assert out["escalated_from"] == "Low" and again["escalated_from"] is None
    assert runner_calls == [alert_id, alert_id]  # idempotent runner, called per Malicious pass
    refreshed = _artifacts(db, alert_id)[0]
    assert refreshed.verdict == "Malicious" and refreshed.threat_score == 90
    db.expire_all()
    from backend.crud import get_alert
    assert get_alert(db, alert_id).severity == "Medium"


# --- Celery configuration and task wrapper ---------------------------------------------

def test_celery_configuration_is_production_sane():
    conf = celery_module.celery_app.conf
    assert celery_module.celery_app.main == "phantom_soar"
    assert conf.broker_connection_retry_on_startup is True
    opts = conf.broker_transport_options
    assert opts["socket_timeout"] >= 10  # never a 1 s timeout that breaks BRPOP
    assert 0 < opts["socket_connect_timeout"] <= 10
    assert opts["visibility_timeout"] > conf.task_time_limit
    assert conf.redis_socket_timeout >= 10
    assert conf.task_reject_on_worker_lost is True and conf.task_acks_late is True
    assert conf.result_expires and conf.task_soft_time_limit < conf.task_time_limit
    for name in ("tasks.process_alert", "tasks.enrich_and_process_alert", "tasks.re_enrich_iocs"):
        assert name in celery_module.celery_app.tasks
    assert celery_module.process_alert_task.name == "tasks.process_alert"
    # enqueue-only tasks never touch the result backend on publish
    assert celery_module.enrich_and_process_alert_task.ignore_result and celery_module.re_enrich_iocs_task.ignore_result


class _FakeTask:
    max_retries = 3

    class request:
        retries = 0

    def __init__(self, retries=0):
        self.request = type("R", (), {"retries": retries})()
        self.retry_countdown = None

    def retry(self, exc, countdown):
        self.retry_countdown = countdown
        return RuntimeError("retry-sentinel")


def _failure_logs(db, alert_id):
    return [l for l in _logs(db, f"Alert #{alert_id} ") if l.source == "AUTOMATION" and "Background task" in l.message]


def test_backoff_is_exponential_with_jitter_and_capped():
    for retries in range(8):
        ceiling = min(celery_module.RETRY_BACKOFF_MAX, celery_module.RETRY_BACKOFF_BASE * 2 ** retries)
        samples = {celery_module.backoff_seconds(retries) for _ in range(60)}
        assert all(1 <= s <= ceiling for s in samples)
    assert len({celery_module.backoff_seconds(5) for _ in range(60)}) > 1  # jittered


def test_transient_errors_retry_with_backoff_and_are_recorded(db):
    import httpx

    assert celery_module.is_transient_error(httpx.ConnectError("x"))
    assert celery_module.is_transient_error(ConnectionError("x"))
    assert not celery_module.is_transient_error(ValueError("bug"))

    task = _FakeTask(retries=1)

    def boom():
        raise httpx.ConnectError("tip down")

    with pytest.raises(RuntimeError, match="retry-sentinel"):
        celery_module.run_guarded(task, 880001, "enrich_and_process_alert", boom)
    assert 1 <= task.retry_countdown <= 10
    entries = _failure_logs(db, 880001)
    assert entries and entries[0].details["final"] is False and entries[0].level == "WARNING"


def test_non_transient_and_exhausted_failures_are_recorded_and_raised(db):
    task = _FakeTask()

    def bug():
        raise ValueError("bad data")

    with pytest.raises(ValueError):
        celery_module.run_guarded(task, 880002, "process_alert", bug)
    assert task.retry_countdown is None
    final = _failure_logs(db, 880002)
    assert final and final[0].details["final"] is True and final[0].level == "ERROR"
    assert "ValueError" in final[0].message

    exhausted = _FakeTask(retries=3)
    with pytest.raises(ConnectionError):
        celery_module.run_guarded(exhausted, 880003, "process_alert", lambda: (_ for _ in ()).throw(ConnectionError("down")))
    assert exhausted.retry_countdown is None
    assert _failure_logs(db, 880003)[0].details["final"] is True


def test_enrich_task_runs_the_pipeline_when_applied(db, monkeypatch):
    monkeypatch.setattr(ingest, "_enqueue", lambda *a, **k: True)
    result = ingest.ingest_alert_with_details(db, _payload(level=3, srcip=LAB_BAD_IP), "wazuh")
    outcome = celery_module.enrich_and_process_alert_task.apply(args=[result.alert.alert_id]).get()
    assert outcome["escalated_from"] == "Low" and outcome["iocs_enriched"] == 1


def test_broker_probe_is_false_when_unreachable():
    assert ingest.is_celery_broker_online() is False


# --- demo ------------------------------------------------------------------------------

def test_demo_seed_still_yields_processed_alerts(db):
    from types import SimpleNamespace
    from backend.routers.demo import seed_demo_data

    body = seed_demo_data(db=db, current_user=SimpleNamespace(username="ws2-test"))
    seeded = body["seeded_alerts"]
    assert len(seeded) == 4
    assert all(s["processing"] == "sync" and s["enrichment_pending"] is False for s in seeded)
    assert all(s["status"] != "New" for s in seeded)
    by = {s["scenario"]: s for s in seeded}
    assert by["ransomware"]["max_threat_score"] > 50
    assert any(v == "Malicious" for v in by["ransomware"]["ioc_verdicts"].values())
