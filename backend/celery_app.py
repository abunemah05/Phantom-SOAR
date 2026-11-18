"""Celery application and background tasks.

The enqueue-only tasks use ignore_result: the web process never waits on them (the database is
the source of truth, failures are written to the system log), and publishing then never touches
the result backend, whose subscribe-retry loop (~20 s) could otherwise stall the webhook.

Tasks (all safe to run twice: process_alert claims the alert atomically, enrichment only touches
IOCs still "pending", severity escalation is computed from the original payload):

  tasks.enrich_and_process_alert  threat-intel enrichment + escalation + playbook routing; queued
                                  by the webhook so the HTTP request returns quickly
  tasks.re_enrich_iocs            delayed re-enrichment of IOCs whose providers were rate limited
  tasks.process_alert             playbook routing only (kept for older callers)

Settings notes (Celery 5 / kombu 5 Redis transport):
  * visibility_timeout is how long an unacknowledged message waits before redelivery
    (default 1 hour). With acks_late it must exceed the longest task, and countdown/ETA tasks
    stay unacknowledged until they run, so countdowns must stay far below it.
    https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/redis.html
  * socket_timeout defaults to None in kombu (a publish on a dead connection waits forever); it
    must stay well above the 1 s BRPOP timeout, so it is 30 s, never 1 s. socket_connect_timeout
    keeps an unreachable broker from stalling the webhook.
"""
import logging
import random
from typing import Any, Callable, Dict, Optional

from celery import Celery
from backend.config import settings

logger = logging.getLogger(__name__)

# Seconds. A queued message not acknowledged within this window is redelivered (acks_late).
VISIBILITY_TIMEOUT = 3600
TASK_SOFT_TIME_LIMIT = 240
TASK_TIME_LIMIT = 300
RETRY_BACKOFF_BASE = 5      # seconds; doubles per retry
RETRY_BACKOFF_MAX = 300
MAX_TASK_RETRIES = 5

celery_app = Celery(
    "phantom_soar",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

_redis_transport_options = {
    "visibility_timeout": VISIBILITY_TIMEOUT,
    "socket_connect_timeout": 3,
    "socket_timeout": 30,
    "socket_keepalive": True,
    "health_check_interval": 25,
}

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_soft_time_limit=TASK_SOFT_TIME_LIMIT,
    task_time_limit=TASK_TIME_LIMIT,
    # Tasks are idempotent, so acknowledge only after they finish and re-queue them if the
    # worker process dies mid-task.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    broker_connection_retry_on_startup=True,
    broker_connection_timeout=4.0,
    broker_transport_options=_redis_transport_options,
    result_backend_transport_options={"visibility_timeout": VISIBILITY_TIMEOUT, "retry_policy": {"max_retries": 5, "interval_start": 0.2, "interval_step": 0.3, "interval_max": 1.5}},
    redis_socket_connect_timeout=3.0,
    redis_socket_timeout=30.0,
    redis_backend_health_check_interval=25,
)


# ----------------------------------------------------------------------------------------
# Retry / failure plumbing
# ----------------------------------------------------------------------------------------

def is_transient_error(exc: BaseException) -> bool:
    """True for errors worth retrying (network, broker, busy database); False for bugs."""
    import httpx
    from kombu.exceptions import OperationalError as KombuOperationalError
    from sqlalchemy.exc import DBAPIError, TimeoutError as SATimeoutError

    if isinstance(exc, (httpx.TransportError, ConnectionError, TimeoutError, KombuOperationalError, SATimeoutError)):
        return True
    if isinstance(exc, DBAPIError):  # includes sqlalchemy OperationalError (locked / dropped connection)
        return bool(exc.connection_invalidated) or exc.__class__.__name__ == "OperationalError"
    return False


def backoff_seconds(retries: int, base: int = RETRY_BACKOFF_BASE, maximum: int = RETRY_BACKOFF_MAX) -> int:
    """Exponential backoff with full jitter: random in [1, min(maximum, base * 2**retries)]."""
    ceiling = min(maximum, base * (2 ** max(0, retries)))
    return random.randint(1, max(1, ceiling))


def _record_failure(alert_id: Optional[int], task_name: str, exc: BaseException, attempt: int, final: bool) -> None:
    """Persist a clear failure entry (never raises)."""
    try:
        from backend.database import SessionLocal
        from backend.routers.logs import record_log

        db = SessionLocal()
        try:
            what = "failed permanently" if final else f"failed (attempt {attempt}), will be retried"
            record_log(
                db=db,
                source="AUTOMATION",
                level="ERROR" if final else "WARNING",
                message=(
                    f"Background task {task_name} for Alert #{alert_id} {what}: {type(exc).__name__}: {str(exc)[:200]}."
                    + (" The alert was not fully processed; an analyst should review it." if final else "")
                ),
                target=f"Alert #{alert_id}",
                details={"alert_id": alert_id, "task": task_name, "attempt": attempt,
                         "final": final, "error": f"{type(exc).__name__}: {str(exc)[:500]}"},
            )
        finally:
            db.close()
    except Exception:  # pragma: no cover - logging must not mask the original error
        logger.exception("Could not record task failure for Alert #%s", alert_id)


def run_guarded(task: Any, alert_id: Optional[int], task_name: str, fn: Callable[[], Any]) -> Any:
    """Run ``fn``; retry transient errors with backoff, record every failure, never swallow one.

    Non-transient errors and retry exhaustion are logged as a final failure and re-raised so the
    task ends in the FAILURE state.
    """
    retries = int(getattr(task.request, "retries", 0) or 0)
    try:
        return fn()
    except Exception as exc:
        if is_transient_error(exc) and retries < task.max_retries:
            _record_failure(alert_id, task_name, exc, retries + 1, final=False)
            logger.warning(f"[Celery] {task_name} Alert #{alert_id}: transient {type(exc).__name__}; retrying.")
            raise task.retry(exc=exc, countdown=backoff_seconds(retries))
        _record_failure(alert_id, task_name, exc, retries + 1, final=True)
        logger.error(f"[Celery] {task_name} Alert #{alert_id} failed: {exc}")
        raise


# ----------------------------------------------------------------------------------------
# Tasks
# ----------------------------------------------------------------------------------------

@celery_app.task(name="tasks.process_alert", bind=True, max_retries=MAX_TASK_RETRIES)
def process_alert_task(self, alert_id: int):
    """Route an ingested alert: autonomous (HOTL) playbook run or hand-off for analyst approval."""
    logger.info(f"[Celery] Processing Alert #{alert_id} in background worker.")

    def _run():
        from backend.engine.runner import process_alert
        return process_alert(alert_id)

    return run_guarded(self, alert_id, "process_alert", _run)


@celery_app.task(name="tasks.enrich_and_process_alert", bind=True, max_retries=MAX_TASK_RETRIES, ignore_result=True)
def enrich_and_process_alert_task(self, alert_id: int):
    """Enrich the alert's IOCs, escalate severity on Malicious evidence, then route the alert."""
    logger.info(f"[Celery] Enriching and processing Alert #{alert_id}.")

    def _run():
        from backend.engine.ingest import enrich_and_process_alert
        return enrich_and_process_alert(alert_id)

    return run_guarded(self, alert_id, "enrich_and_process_alert", _run)


@celery_app.task(name="tasks.re_enrich_iocs", bind=True, max_retries=MAX_TASK_RETRIES, ignore_result=True)
def re_enrich_iocs_task(self, alert_id: int, artifact_ids: list, attempt: int = 1):
    """Re-enrich IOCs whose threat-intel lookup was incomplete (rate limited); may reschedule itself."""
    logger.info(f"[Celery] Re-enriching {len(artifact_ids)} IOC(s) of Alert #{alert_id} (attempt {attempt}).")

    def _run():
        from backend.engine.ingest import re_enrich_incomplete_iocs
        return re_enrich_incomplete_iocs(alert_id, list(artifact_ids), attempt)

    return run_guarded(self, alert_id, "re_enrich_iocs", _run)
