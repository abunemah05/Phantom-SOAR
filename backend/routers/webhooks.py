import json
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.dependencies import require_ingest_token
from backend.engine.ingest import IngestResult, ingest_alert_with_details

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/webhooks",
    tags=["Webhooks & Ingestion"],
    dependencies=[Depends(require_ingest_token)],
)

MAX_WEBHOOK_BODY_BYTES = 1024 * 1024

_JSON_OBJECT_BODY = {
    "requestBody": {
        "required": True,
        "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}},
    }
}


async def read_json_payload(request: Request) -> Dict[str, Any]:
    """Read the body as a JSON object, rejecting anything over 1 MB with 413."""
    declared = request.headers.get("content-length")
    if declared:
        try:
            declared_size = int(declared)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid Content-Length header.")
        if declared_size > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Alert payload exceeds {MAX_WEBHOOK_BODY_BYTES} bytes.",
            )

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Alert payload exceeds {MAX_WEBHOOK_BODY_BYTES} bytes.",
            )

    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Request body is not valid JSON.")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Request body must be a JSON object.")
    return payload


def _base_response(result: IngestResult, label: str) -> Dict[str, Any]:
    alert = result.alert
    message = f"{label} {alert.rule_id} ingested as Alert #{alert.alert_id}."
    if result.processing == "failed":
        message += " Automated triage failed; the alert is waiting for an analyst."
    return {
        "status": "Success",
        "message": message,
        "alert_id": alert.alert_id,
        "severity": alert.severity,
        "current_status": alert.status,
        "celery_background_dispatched": result.celery_dispatched,
        "processing": result.processing,
        "severity_basis": result.severity_basis,
        "escalated_from": result.escalated_from,
        "ioc_count": len(result.artifacts),
        "iocs_dropped": result.iocs_dropped,
        "iocs": result.artifacts,
    }


@router.post("/wazuh", status_code=status.HTTP_201_CREATED, openapi_extra=_JSON_OBJECT_BODY)
def ingest_wazuh_alert(payload: Dict[str, Any] = Depends(read_json_payload), db: Session = Depends(get_db)):
    """Ingest a Wazuh alert (JSON). Severity comes from rule.level only.

    Requires the X-Phantom-Ingest-Token header.
    """
    result = ingest_alert_with_details(db, payload, "wazuh")
    return _base_response(result, "Wazuh alert")


@router.post("/edr", status_code=status.HTTP_201_CREATED, openapi_extra=_JSON_OBJECT_BODY)
def ingest_edr_alert(payload: Dict[str, Any] = Depends(read_json_payload), db: Session = Depends(get_db)):
    """Ingest an EDR detection. Severity comes from the payload "severity" field
    (Critical/High/Medium/Low; anything else defaults to Medium).

    Requires the X-Phantom-Ingest-Token header.
    """
    result = ingest_alert_with_details(db, payload, "edr")
    response = _base_response(result, "EDR alert")
    response["target_host"] = result.identity.get("hostname")
    response["target_process"] = result.identity.get("process_name")
    return response


@router.post("/xdr", status_code=status.HTTP_201_CREATED, openapi_extra=_JSON_OBJECT_BODY)
def ingest_xdr_incident(payload: Dict[str, Any] = Depends(read_json_payload), db: Session = Depends(get_db)):
    """Ingest an XDR correlated incident. Severity comes from the payload "severity" field
    (Critical/High/Medium/Low; anything else defaults to Medium).

    Requires the X-Phantom-Ingest-Token header.
    """
    result = ingest_alert_with_details(db, payload, "xdr")
    response = _base_response(result, "XDR incident")
    response["correlated_layers"] = result.identity.get("correlated_layers", [])
    return response
