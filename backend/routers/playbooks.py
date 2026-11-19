import json
import os
from typing import Any, Dict, Literal, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from backend.crud import (
    create_playbook,
    delete_playbook,
    get_playbook,
    get_playbooks,
    toggle_playbook_status,
    update_playbook,
)
from backend.database import get_db
from backend.dependencies import get_current_user, require_admin, require_sec_eng_or_admin
from backend.engine import playbook_import
from backend.engine.actions import PSEUDO_STEPS, list_actions, validate_workflow_steps
from backend.engine.playbooks_catalog import PRECONFIGURED_PLAYBOOKS
from backend.models import Playbook, User
from backend.routers.logs import record_log
from backend.schemas import PlaybookCreate, PlaybookUpdate

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])

EXECUTION_MODES = {"HOTL", "HITL"}


def _normalize_workflow(workflow_logic: Any) -> Any:
    if isinstance(workflow_logic, str):
        try:
            workflow_logic = json.loads(workflow_logic)
        except ValueError:
            raise HTTPException(status_code=422, detail="workflow_logic must be a JSON object.")
    errors = validate_workflow_steps(workflow_logic)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"message": "Invalid playbook steps.", "errors": errors,
                    "allowed_actions": [a["name"] for a in list_actions()],
                    "pseudo_steps": sorted(PSEUDO_STEPS)},
        )
    return workflow_logic


def _normalize_mode(mode: Any) -> str:
    value = str(mode or "").strip().upper()
    if value not in EXECUTION_MODES:
        raise HTTPException(status_code=422, detail="execution_mode must be 'HOTL' or 'HITL'.")
    return value


@router.get("/templates")
def list_playbook_templates(current_user: User = Depends(get_current_user)):
    """Pre-configured SANS / MITRE playbook templates."""
    return PRECONFIGURED_PLAYBOOKS


@router.get("/actions")
def list_playbook_actions(current_user: User = Depends(get_current_user)):
    """Actions a playbook step may use, plus the pseudo-steps the runner understands."""
    return {"actions": list_actions(), "pseudo_steps": PSEUDO_STEPS}


# --- Import of playbook packs (administrators only) ---------------------------------------------------
# Imported playbooks are always created inactive and in HITL mode; see backend/engine/playbook_import.py
# and docs/PLAYBOOK_IMPORT.md. Preview validates and writes nothing; the import must repeat the preview's
# sha256 so what the administrator reviewed is exactly what gets imported.
MAX_IMPORT_BODY = playbook_import.MAX_PACK_BYTES * 2 + 8192  # JSON escaping can roughly double a text file


class PlaybookImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: Literal["file", "url", "starter"]
    content: Optional[str] = None  # the text of the uploaded file (source = "file")
    filename: Optional[str] = Field(default=None, max_length=300)
    url: Optional[str] = Field(default=None, max_length=playbook_import.MAX_URL)  # source = "url"
    on_duplicate: Literal["skip", "rename"] = "skip"
    expected_sha256: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")


async def _read_import_request(request: Request) -> PlaybookImportRequest:
    declared = request.headers.get("content-length")
    if declared:
        try:
            too_big = int(declared) > MAX_IMPORT_BODY
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.")
        if too_big:
            raise HTTPException(status_code=413, detail=f"The request is larger than {MAX_IMPORT_BODY} bytes.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_IMPORT_BODY:
            raise HTTPException(status_code=413, detail=f"The request is larger than {MAX_IMPORT_BODY} bytes.")
    try:
        parsed = PlaybookImportRequest.model_validate_json(bytes(body))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=[{"loc": e["loc"], "msg": e["msg"]} for e in exc.errors()])
    if parsed.source == "file" and (not parsed.content or parsed.url):
        raise HTTPException(status_code=422, detail="source 'file' needs 'content' and no 'url'.")
    if parsed.source == "url" and (not parsed.url or parsed.content):
        raise HTTPException(status_code=422, detail="source 'url' needs 'url' and no 'content'.")
    if parsed.source == "starter" and (parsed.url or parsed.content):
        raise HTTPException(status_code=422, detail="source 'starter' takes no 'url' or 'content'.")
    return parsed


def _safe_filename(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    base = os.path.basename(name.replace("\\", "/"))
    base = "".join(ch for ch in base if ch.isprintable())[:120].strip()
    return base or None


def _import_source(req: PlaybookImportRequest, db: Session, admin: User) -> Tuple[bytes, Dict[str, Any]]:
    """Get the pack bytes. A refused or failed URL is audited and reported without any detail beyond the reason.
    The raw URL is never logged or stored: only scheme + host + path (no credentials, query or fragment), truncated."""
    if req.source == "starter":
        return playbook_import.load_starter_pack(), {"kind": "starter", "filename": "starter_pack.json"}
    if req.source == "file":
        raw = (req.content or "").encode("utf-8")
        return raw, {"kind": "file", "filename": _safe_filename(req.filename)}
    try:
        raw = playbook_import.fetch_pack_from_url(req.url or "")
    except playbook_import.SourceError as exc:
        record_log(db, "PLAYBOOKS", "WARNING", f"Playbook import from URL refused: {exc}", target="playbook import",
                   details={"url": playbook_import.safe_url_for_log(req.url), "by": admin.username, "reason": str(exc)})
        raise HTTPException(status_code=422, detail={"message": f"Could not fetch the pack: {exc}"})
    return raw, {"kind": "url", "url": playbook_import.safe_url_for_log(req.url)}


def _existing_names(db: Session):
    return [row[0] for row in db.query(Playbook.name).all()]


@router.get("/import/info")
def playbook_import_info(admin: User = Depends(require_admin)):
    """Limits and allowed sources of the playbook import (administrators only)."""
    return {
        "format": playbook_import.PACK_FORMAT,
        "format_version": list(playbook_import.SUPPORTED_FORMAT_VERSIONS),
        "max_pack_bytes": playbook_import.MAX_PACK_BYTES,
        "max_playbooks": playbook_import.MAX_PLAYBOOKS,
        "max_steps": playbook_import.MAX_STEPS,
        "allowed_url_hosts": list(playbook_import.ALLOWED_URL_HOSTS),
        "forced": {"is_active": False, "execution_mode": "HITL"},
        "starter_pack": True,
    }


@router.post("/import/preview")
async def preview_playbook_import(request: Request, db: Session = Depends(get_db),
                                  admin: User = Depends(require_admin)):
    """Validate a pack and report what an import would do. Nothing is written (a URL is fetched, and logged)."""
    req = await _read_import_request(request)

    def work():
        raw, source = _import_source(req, db, admin)
        report = playbook_import.build_report(raw, _existing_names(db), req.on_duplicate, source)
        if source["kind"] == "url":
            record_log(db, "PLAYBOOKS", "INFO", f"Admin '{admin.username}' fetched a playbook pack for preview.",
                       target=report["pack"].get("name") or "playbook pack",
                       details={"url": source["url"], "sha256": report["sha256"], "by": admin.username})
        return playbook_import.public_report(report)

    return await run_in_threadpool(work)


@router.post("/import")
async def import_playbooks(request: Request, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Import a pack: every accepted playbook is created INACTIVE and in HITL mode. Requires the preview's sha256."""
    req = await _read_import_request(request)
    if not req.expected_sha256:
        raise HTTPException(status_code=422, detail="expected_sha256 (from the preview) is required to import.")

    def work():
        raw, source = _import_source(req, db, admin)
        report = playbook_import.build_report(raw, _existing_names(db), req.on_duplicate, source)
        if report["sha256"] != req.expected_sha256:
            record_log(db, "PLAYBOOKS", "WARNING", "Playbook import refused: the pack changed after the preview.",
                       target=report["pack"].get("name") or "playbook pack",
                       details={"by": admin.username, "source": source, "sha256": report["sha256"],
                                "expected_sha256": req.expected_sha256})
            raise HTTPException(status_code=409, detail="The pack changed since the preview. Preview it again.")
        if not report["ok"]:
            record_log(db, "PLAYBOOKS", "WARNING", "Playbook import rejected: the pack is not valid.",
                       target=report["pack"].get("name") or "playbook pack",
                       details={"by": admin.username, "source": source, "sha256": report["sha256"],
                                "errors": report["pack_errors"][:10]})
            raise HTTPException(status_code=422, detail={"message": "The pack is not valid.",
                                                        "report": playbook_import.public_report(report)})

        prov = playbook_import.provenance(report, admin.username)
        created = []
        for item in report["items"]:
            pb = item["playbook"]
            if pb is None:
                continue
            logic = {**pb["workflow_logic"], "imported_from": prov}
            row = Playbook(name=pb["name"], target_threat=pb["target_threat"], execution_mode="HITL",
                           workflow_logic=json.dumps(logic), is_active=False)
            db.add(row)
            created.append((item, row))
        db.commit()
        for _, row in created:
            db.refresh(row)

        counts = report["counts"]
        skipped = [i["name"] for i in report["items"] if i["status"] == "skipped_duplicate"]
        rejected = [{"name": i["name"], "errors": i["errors"][:3]} for i in report["items"] if i["status"] == "rejected"]
        forced_hitl = [i["final_name"] for i in report["items"] if i["playbook"] and i["requested_mode"] == "HOTL"]
        record_log(
            db, "PLAYBOOKS", "ACTION" if created else "WARNING",
            f"Admin '{admin.username}' imported {len(created)} of {counts['total']} playbook(s) from pack "
            f"'{report['pack'].get('name')}' (all inactive, HITL).",
            target=report["pack"].get("name"),
            details={"by": admin.username, "source": source, "sha256": report["sha256"], "license": prov["license"],
                     "pack_version": prov["pack_version"], "on_duplicate": req.on_duplicate,
                     "created": [{"playbook_id": r.playbook_id, "name": r.name} for _, r in created],
                     "skipped_duplicates": skipped, "rejected": rejected, "forced_to_hitl": forced_hitl},
        )
        return {
            "status": "Success",
            "message": f"Imported {len(created)} playbook(s), all inactive and in HITL mode. Review each one and enable it yourself.",
            "created": [{"playbook_id": r.playbook_id, "name": r.name, "is_active": r.is_active,
                         "execution_mode": r.execution_mode} for _, r in created],
            "report": playbook_import.public_report(report),
        }

    return await run_in_threadpool(work)


@router.get("")
def list_playbooks(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=200),
    active_only: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List registered playbooks."""
    playbooks = get_playbooks(db, skip=skip, limit=limit, active_only=active_only)
    return [p.to_dict() for p in playbooks]


@router.post("", status_code=status.HTTP_201_CREATED)
def create_new_playbook(
    playbook_in: PlaybookCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin),
):
    """Create a playbook (administrators and security engineers). Steps are validated against the action catalog."""
    playbook_in.workflow_logic = _normalize_workflow(playbook_in.workflow_logic)
    playbook_in.execution_mode = _normalize_mode(playbook_in.execution_mode)
    created = create_playbook(db, playbook_in)
    return created.to_dict()


@router.get("/{playbook_id}")
def get_single_playbook(playbook_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    playbook = get_playbook(db, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return playbook.to_dict()


@router.put("/{playbook_id}")
def update_existing_playbook(
    playbook_id: int,
    playbook_in: PlaybookUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin),
):
    """Update a playbook (administrators and security engineers)."""
    if playbook_in.workflow_logic is not None:
        playbook_in.workflow_logic = _normalize_workflow(playbook_in.workflow_logic)
    if playbook_in.execution_mode is not None:
        playbook_in.execution_mode = _normalize_mode(playbook_in.execution_mode)
    updated = update_playbook(db, playbook_id, playbook_in)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return updated.to_dict()


@router.delete("/{playbook_id}")
def remove_playbook(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin),
):
    """Delete a playbook (administrators and security engineers)."""
    if not delete_playbook(db, playbook_id):
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return {"status": "Success", "message": f"Playbook #{playbook_id} deleted"}


@router.patch("/{playbook_id}/toggle")
def toggle_status(
    playbook_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_sec_eng_or_admin),
):
    """Enable or disable a playbook (administrators and security engineers)."""
    updated = toggle_playbook_status(db, playbook_id)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Playbook #{playbook_id} not found")
    return {"status": "Success", "playbook_id": updated.playbook_id, "is_active": updated.is_active}
