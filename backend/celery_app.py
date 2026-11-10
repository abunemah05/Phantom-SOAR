import logging
from celery import Celery
from backend.config import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "phantom_soar",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,
    # process_alert is safe to re-run (already-processed alerts are skipped and finished
    # steps are never repeated), so acknowledge only after the task completes.
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_timeout=1.0,
    broker_connection_retry_on_startup=False,
    redis_socket_connect_timeout=1.0,
    redis_socket_timeout=1.0,
)

@celery_app.task(name="tasks.process_alert", bind=True, max_retries=2)
def process_alert_task(self, alert_id: int):
    """Route an ingested alert: autonomous (HOTL) playbook run or hand-off for analyst approval."""
    logger.info(f"[Celery] Processing Alert #{alert_id} in background worker.")
    from backend.engine.runner import process_alert
    try:
        return process_alert(alert_id)
    except Exception as exc:
        logger.error(f"[Celery] Error processing alert #{alert_id}: {exc}")
        raise self.retry(exc=exc, countdown=5)
