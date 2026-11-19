"""Safe, bounded import of playbook packs (JSON files) into Phantom SOAR.

There is no vendor API that delivers ready-to-run playbooks for this tool (see docs/PLAYBOOK_IMPORT.md), so
import is built around a small, strictly validated JSON "pack" format that only uses Phantom's own action
vocabulary. Safety rules, all enforced here and not in the UI:

* Every playbook is validated against this schema and against backend.engine.actions (unknown actions,
  unknown or invalid parameters, aliases, `agent_id` overrides and oversize packs are rejected).
* Imported playbooks are ALWAYS created inactive and in HITL (analyst approval) mode. A pack that asks for
  HOTL or `is_active: true` is accepted but downgraded, with a warning in the report.
* A pack can come from an uploaded file, the bundled starter pack, or an https URL on an allow-listed
  GitHub host (raw.githubusercontent.com, api.github.com). URL fetches go through backend.netguard (public
  addresses only, re-checked at connect time), never follow redirects, and are bounded in size and time.
  No token or API key is ever sent.
* The pack's source, SHA-256 and license text are stored on every imported playbook and in the audit log.
"""
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlparse

import httpx

from backend import netguard
from backend.engine.actions import ACTION_CATALOG, PSEUDO_STEPS, validate_params

PACK_FORMAT = "phantom-playbook-pack"
SUPPORTED_FORMAT_VERSIONS = (1,)

# --- limits ---------------------------------------------------------------------------------
MAX_PACK_BYTES = 256 * 1024
MAX_PLAYBOOKS = 50
MAX_STEPS = 30
MAX_NAME = 150
MAX_THREAT = 100
MAX_URL = 2048
MAX_LICENSE = 1000
FETCH_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Hosts a pack may be fetched from, and the path shape each one must have.
ALLOWED_URL_HOSTS = ("raw.githubusercontent.com", "api.github.com")
_RAW_PATH = re.compile(r"^/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+\.json$")
_API_PATH = re.compile(r"^/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/contents/[A-Za-z0-9_./-]+\.json$")

STARTER_PACK_PATH = Path(__file__).resolve().parent.parent / "playbook_packs" / "starter_pack.json"

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Invisible Unicode format characters that can make a name look like something else on screen (display spoofing,
# "Trojan Source"): bidi embeddings / overrides / isolates (U+202A-202E, U+2066-2069), bidi marks (U+200E-200F,
# U+061C), zero-width characters (U+200B-200D, U+2060-2064, U+FEFF, U+180E), invisible interlinear annotation
# (U+FFF9-FFFB) and the Unicode "tag" block (U+E0000-E007F). Rejected in every text field and string parameter.
_INVISIBLE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u061c\u180e\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]")


def _has_unsafe_chars(value: str) -> bool:
    return bool(_CONTROL.search(value) or _INVISIBLE.search(value))


def _display_text(value: Any, limit: int = MAX_NAME) -> Optional[str]:
    """A rejected entry's name as shown in the report: no control or invisible characters, bounded length."""
    if not isinstance(value, str):
        return None
    cleaned = _INVISIBLE.sub("", _CONTROL.sub("", value))
    return " ".join(cleaned.split())[:limit] or None
_MITRE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

PACK_KEYS = {"format", "format_version", "pack", "playbooks"}
PACK_META_KEYS = {"name", "version", "author", "license", "source", "description"}
PLAYBOOK_KEYS = {"name", "target_threat", "execution_mode", "is_active", "description", "source_framework",
                 "workflow_logic"}
WORKFLOW_KEYS = {"mitre_id", "mitre_tactic", "mitre_technique", "picerl_phase", "keywords", "triggers", "steps"}
STEP_KEYS = {"order", "action", "connector", "params", "role", "note"}

ALLOWED_STEP_NAMES = tuple(ACTION_CATALOG) + tuple(PSEUDO_STEPS)


class PackError(ValueError):
    """The pack as a whole cannot be used (not valid JSON, wrong format, too large, ...)."""


class SourceError(ValueError):
    """The URL is not allowed or could not be fetched safely."""


# --- helpers ---------------------------------------------------------------------------------
def _clean_text(value: Any, field: str, max_len: int, errors: List[str], required: bool = False,
                min_len: int = 1) -> Optional[str]:
    if value is None:
        if required:
            errors.append(f"{field} is required.")
        return None
    if not isinstance(value, str):
        errors.append(f"{field} must be a string.")
        return None
    text = " ".join(value.split())
    if _has_unsafe_chars(value):
        errors.append(f"{field} contains control or invisible formatting characters (for example bidirectional overrides).")
        return None
    if not text:
        if required:
            errors.append(f"{field} must not be empty.")
        return None
    if len(text) < min_len:
        errors.append(f"{field} must be at least {min_len} characters.")
        return None
    if len(text) > max_len:
        errors.append(f"{field} is longer than {max_len} characters.")
        return None
    return text


def _clean_list(value: Any, field: str, max_items: int, max_len: int, errors: List[str]) -> Optional[List[str]]:
    if value is None:
        return None
    if not isinstance(value, list):
        errors.append(f"{field} must be a list of strings.")
        return None
    if len(value) > max_items:
        errors.append(f"{field} has more than {max_items} entries.")
        return None
    cleaned = []
    for i, item in enumerate(value, start=1):
        text = _clean_text(item, f"{field}[{i}]", max_len, errors, required=True)
        if text:
            cleaned.append(text)
    return cleaned


def _unknown_keys(obj: Dict[str, Any], allowed: set, where: str, errors: List[str]) -> None:
    extra = sorted(str(k) for k in obj if k not in allowed)
    if extra:
        errors.append(f"{where}: unknown field(s) {', '.join(repr(k) for k in extra)}.")


def _no_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def parse_pack_bytes(raw: bytes) -> Dict[str, Any]:
    """Size-check and parse a pack. Raises PackError."""
    if len(raw) > MAX_PACK_BYTES:
        raise PackError(f"The pack is {len(raw)} bytes; the limit is {MAX_PACK_BYTES} bytes.")
    if not raw.strip():
        raise PackError("The pack is empty.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise PackError("The pack is not valid UTF-8 text.")
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except RecursionError:
        raise PackError("The pack is nested too deeply.")
    except ValueError as exc:
        raise PackError(f"The pack is not valid JSON: {exc}")
    if not isinstance(data, dict):
        raise PackError("The pack must be a JSON object.")
    return data


def pack_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


# --- validation ---------------------------------------------------------------------------------
def _string_param_problem(value: Any, depth: int = 0) -> bool:
    """True when a string inside a parameter value (also inside lists / objects) is too long or has unsafe characters."""
    if isinstance(value, str):
        return len(value) > 500 or _has_unsafe_chars(value)
    if depth < 4 and isinstance(value, list):
        return any(_string_param_problem(v, depth + 1) for v in value)
    if depth < 4 and isinstance(value, dict):
        return any(_string_param_problem(k, depth + 1) or _string_param_problem(v, depth + 1) for k, v in value.items())
    return False


def validate_step(position: int, step: Any) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    where = f"step {position}"
    if not isinstance(step, dict):
        return None, [f"{where} must be an object."]
    _unknown_keys(step, STEP_KEYS, where, errors)

    action = step.get("action")
    if not isinstance(action, str) or action not in ALLOWED_STEP_NAMES:
        hint = ""
        if isinstance(action, str):
            hint = " Allowed: " + ", ".join(ALLOWED_STEP_NAMES) + "."
        errors.append(f"{where}: unknown action {action!r}.{hint}")
        return None, errors

    normalized: Dict[str, Any] = {"order": position, "action": action}
    order = step.get("order")
    if order is not None and (isinstance(order, bool) or not isinstance(order, int) or order < 1):
        errors.append(f"{where}: order must be a positive integer.")

    connector = step.get("connector")
    if connector is not None:
        spec = ACTION_CATALOG.get(action)
        if not isinstance(connector, str):
            errors.append(f"{where}: connector must be a string.")
        elif spec is not None and connector != spec["connector"]:
            errors.append(f"{where}: action {action} uses connector '{spec['connector']}', not {connector!r}.")
        elif spec is None and not re.fullmatch(r"[a-z][a-z0-9_]{0,29}", connector):
            errors.append(f"{where}: connector must be a short lowercase identifier.")
        else:
            normalized["connector"] = connector

    params = step.get("params")
    if params not in (None, {}):
        if action in PSEUDO_STEPS:
            errors.append(f"{where}: {action} does not take params.")
        elif not isinstance(params, dict):
            errors.append(f"{where}: params must be an object.")
        else:
            if "agent_id" in params:
                errors.append(f"{where}: 'agent_id' cannot be set by an imported playbook.")
            errors.extend(f"{where}: {p}" for p in validate_params(action, params))
            for key, value in params.items():
                if _string_param_problem(value):
                    errors.append(f"{where}: parameter '{key}' is too long or has control or invisible formatting characters.")
            if not errors:
                normalized["params"] = params

    role = _clean_text(step.get("role"), f"{where}: role", 60, errors)
    if role:
        normalized["role"] = role
    note = _clean_text(step.get("note"), f"{where}: note", 200, errors)
    if note:
        normalized["note"] = note
    return (None if errors else normalized), errors


def validate_playbook(position: int, entry: Any) -> Dict[str, Any]:
    """Validate one pack entry. Returns {"errors", "warnings", "playbook" (normalized or None), ...}."""
    errors: List[str] = []
    warnings: List[str] = []
    result: Dict[str, Any] = {"index": position, "name": None, "errors": errors, "warnings": warnings,
                              "playbook": None, "requested_mode": None, "steps": []}
    if not isinstance(entry, dict):
        errors.append("The entry must be an object.")
        return result
    _unknown_keys(entry, PLAYBOOK_KEYS, "playbook", errors)

    name = _clean_text(entry.get("name"), "name", MAX_NAME, errors, required=True, min_len=3)
    result["name"] = name or _display_text(entry.get("name"))
    threat = _clean_text(entry.get("target_threat"), "target_threat", MAX_THREAT, errors, required=True)
    description = _clean_text(entry.get("description"), "description", 1000, errors, required=True, min_len=10)
    framework = _clean_text(entry.get("source_framework"), "source_framework", 200, errors)

    requested = entry.get("execution_mode")
    if requested is None:
        mode_text = "HITL"
    elif isinstance(requested, str) and requested.strip().upper() in ("HOTL", "HITL"):
        mode_text = requested.strip().upper()
    else:
        mode_text = None
        errors.append("execution_mode must be 'HOTL' or 'HITL'.")
    result["requested_mode"] = mode_text
    if mode_text == "HOTL":
        warnings.append("Requested HOTL (autonomous); imported as HITL (analyst approval). Change it later in the editor if you decide to.")
    active = entry.get("is_active")
    if active is not None and not isinstance(active, bool):
        errors.append("is_active must be true or false.")
    elif active:
        warnings.append("Requested active; imported inactive. Review it and enable it yourself.")

    logic = entry.get("workflow_logic")
    normalized_logic: Dict[str, Any] = {}
    if not isinstance(logic, dict):
        errors.append("workflow_logic must be an object.")
    else:
        _unknown_keys(logic, WORKFLOW_KEYS, "workflow_logic", errors)
        mitre = _clean_text(logic.get("mitre_id"), "workflow_logic.mitre_id", 12, errors)
        if mitre and not _MITRE_ID.match(mitre):
            errors.append("workflow_logic.mitre_id must look like T1566 or T1566.001.")
        elif mitre:
            normalized_logic["mitre_id"] = mitre
        for key, limit in (("mitre_tactic", 60), ("mitre_technique", 100), ("picerl_phase", 60)):
            text = _clean_text(logic.get(key), f"workflow_logic.{key}", limit, errors)
            if text:
                normalized_logic[key] = text
        for key, limit_items, limit_len in (("keywords", 20, 60), ("triggers", 20, 80)):
            values = _clean_list(logic.get(key), f"workflow_logic.{key}", limit_items, limit_len, errors)
            if values:
                normalized_logic[key] = values

        steps = logic.get("steps")
        if not isinstance(steps, list) or not steps:
            errors.append("workflow_logic.steps must be a non-empty list.")
        elif len(steps) > MAX_STEPS:
            errors.append(f"workflow_logic.steps has more than {MAX_STEPS} steps.")
        else:
            checked = []
            seen_orders = set()
            for i, step in enumerate(steps, start=1):
                normalized_step, step_errors = validate_step(i, step)
                errors.extend(step_errors)
                declared = step.get("order") if isinstance(step, dict) else None
                if isinstance(declared, int) and not isinstance(declared, bool):
                    if declared in seen_orders:
                        errors.append(f"step {i}: duplicate order {declared}.")
                    seen_orders.add(declared)
                if normalized_step:
                    checked.append(normalized_step)
            if not errors and checked:
                normalized_logic["steps"] = checked
            result["steps"] = [s.get("action") for s in steps if isinstance(s, dict) and isinstance(s.get("action"), str)]

    if not errors:
        normalized_logic["description"] = description
        if framework:
            normalized_logic["source_framework"] = framework
        result["playbook"] = {
            "name": name,
            "target_threat": threat,
            "execution_mode": "HITL",
            "is_active": False,
            "workflow_logic": normalized_logic,
        }
    result["target_threat"] = threat
    return result


def validate_pack(data: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], List[Dict[str, Any]]]:
    """Returns (pack_meta, pack_errors, per-playbook results). Pack errors are fatal for the whole pack."""
    errors: List[str] = []
    _unknown_keys(data, PACK_KEYS, "pack", errors)
    if data.get("format") != PACK_FORMAT:
        errors.append(f"format must be '{PACK_FORMAT}'.")
    if data.get("format_version") not in SUPPORTED_FORMAT_VERSIONS or isinstance(data.get("format_version"), bool):
        errors.append(f"format_version must be one of {list(SUPPORTED_FORMAT_VERSIONS)}.")

    meta_raw = data.get("pack")
    meta: Dict[str, Any] = {}
    if not isinstance(meta_raw, dict):
        errors.append("pack (metadata) must be an object.")
    else:
        _unknown_keys(meta_raw, PACK_META_KEYS, "pack", errors)
        for key, limit, required in (("name", 100, True), ("version", 40, False), ("author", 100, False),
                                     ("license", MAX_LICENSE, True), ("source", MAX_URL, False),
                                     ("description", 1000, False)):
            value = _clean_text(meta_raw.get(key), f"pack.{key}", limit, errors, required=required)
            if value:
                meta[key] = value

    entries = data.get("playbooks")
    results: List[Dict[str, Any]] = []
    if not isinstance(entries, list) or not entries:
        errors.append("playbooks must be a non-empty list.")
    elif len(entries) > MAX_PLAYBOOKS:
        errors.append(f"The pack has {len(entries)} playbooks; the limit is {MAX_PLAYBOOKS}.")
    else:
        results = [validate_playbook(i, e) for i, e in enumerate(entries, start=1)]
    return meta, errors, results


def _unique_name(base: str, taken: set) -> str:
    for n in range(1, 1000):
        suffix = " (imported)" if n == 1 else f" (imported {n})"
        candidate = base[: MAX_NAME - len(suffix)].rstrip() + suffix
        if candidate.casefold() not in taken:
            return candidate
    raise PackError("Could not find a free name for a duplicate playbook.")


def build_report(raw: bytes, existing_names: List[str], on_duplicate: str = "skip",
                 source: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validate a pack and decide, per playbook, what an import would do. Never touches the database."""
    if on_duplicate not in ("skip", "rename"):
        raise PackError("on_duplicate must be 'skip' or 'rename'.")
    sha = pack_sha256(raw)
    report: Dict[str, Any] = {
        "ok": False, "sha256": sha, "size_bytes": len(raw), "on_duplicate": on_duplicate,
        "source": source or {}, "pack": {}, "pack_errors": [], "items": [],
        "counts": {"total": 0, "importable": 0, "renamed": 0, "skipped_duplicate": 0, "rejected": 0},
        "forced": {"inactive": True, "execution_mode": "HITL"},
    }
    try:
        data = parse_pack_bytes(raw)
    except PackError as exc:
        report["pack_errors"] = [str(exc)]
        return report
    meta, pack_errors, results = validate_pack(data)
    report["pack"] = meta
    report["pack_errors"] = pack_errors
    if pack_errors:
        return report

    taken = {n.casefold() for n in existing_names if isinstance(n, str)}
    counts = report["counts"]
    counts["total"] = len(results)
    for res in results:
        item = {
            "index": res["index"], "name": res["name"], "final_name": None, "target_threat": res.get("target_threat"),
            "requested_mode": res["requested_mode"], "steps": res["steps"], "errors": res["errors"],
            "warnings": res["warnings"], "status": "rejected", "playbook": None,
        }
        pb = res["playbook"]
        if pb is not None:
            key = pb["name"].casefold()
            if key in taken:
                if on_duplicate == "skip":
                    item["status"] = "skipped_duplicate"
                    item["warnings"] = item["warnings"] + [
                        "A playbook with this name already exists (or appears earlier in the pack); skipped."]
                else:
                    new_name = _unique_name(pb["name"], taken)
                    pb = {**pb, "name": new_name}
                    item["status"] = "renamed"
                    item["final_name"] = new_name
                    item["warnings"] = item["warnings"] + [f"Name already exists; imported as '{new_name}'."]
                    taken.add(new_name.casefold())
            else:
                item["status"] = "importable"
                item["final_name"] = pb["name"]
                taken.add(key)
            if item["status"] in ("importable", "renamed"):
                item["playbook"] = pb
        counts_key = {"importable": "importable", "renamed": "renamed", "skipped_duplicate": "skipped_duplicate",
                      "rejected": "rejected"}[item["status"]]
        counts[counts_key] += 1
        report["items"].append(item)
    report["ok"] = True
    return report


def provenance(report: Dict[str, Any], username: str) -> Dict[str, Any]:
    pack = report.get("pack") or {}
    source = report.get("source") or {}
    return {
        "pack_name": pack.get("name"),
        "pack_version": pack.get("version"),
        "pack_author": pack.get("author"),
        "license": pack.get("license"),
        "source_kind": source.get("kind"),
        "source": source.get("url") or source.get("filename") or source.get("kind"),
        "sha256": report.get("sha256"),
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "imported_by": username,
    }


def public_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """The report as sent to the client (drops the internal normalized payload, keeps a summary)."""
    items = []
    for item in report["items"]:
        shown = {k: v for k, v in item.items() if k != "playbook"}
        shown["step_count"] = len(item.get("steps") or [])
        items.append(shown)
    return {**report, "items": items}


# --- sources ---------------------------------------------------------------------------------
def load_starter_pack() -> bytes:
    return STARTER_PACK_PATH.read_bytes()


def validate_source_url(url: Any) -> str:
    """Allow-list check for a pack URL (no network). Raises SourceError with a reason for the admin."""
    if not isinstance(url, str) or not url.strip():
        raise SourceError("A URL is required.")
    url = url.strip()
    if len(url) > MAX_URL:
        raise SourceError("The URL is too long.")
    if _has_unsafe_chars(url) or " " in url:
        raise SourceError("The URL contains invalid characters.")
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        raise SourceError("The URL is not valid.")
    if parsed.scheme != "https":
        raise SourceError("Only https URLs are allowed.")
    if parsed.username or parsed.password:
        raise SourceError("URLs with embedded credentials are not allowed.")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_URL_HOSTS:
        raise SourceError("Only these hosts are allowed: " + ", ".join(ALLOWED_URL_HOSTS) + ".")
    if port not in (None, 443):
        raise SourceError("Only the default https port is allowed.")
    if parsed.fragment or parsed.params:
        raise SourceError("The URL must not contain a fragment or path parameters.")
    decoded = unquote(parsed.path)
    if "%" in decoded or "\\" in decoded or "//" in decoded or any(seg in ("..", ".") for seg in decoded.split("/")):
        raise SourceError("The URL path is not allowed.")
    if host == "raw.githubusercontent.com":
        if parsed.query:
            raise SourceError("Query strings are not allowed on raw.githubusercontent.com URLs.")
        if not _RAW_PATH.match(parsed.path):
            raise SourceError("Expected https://raw.githubusercontent.com/<owner>/<repo>/<ref>/<path>.json")
    else:
        if not _API_PATH.match(parsed.path):
            raise SourceError("Expected https://api.github.com/repos/<owner>/<repo>/contents/<path>.json")
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if any(k != "ref" or not re.fullmatch(r"[A-Za-z0-9_./-]{1,100}", v or "") for k, v in query) or len(query) > 1:
            raise SourceError("Only a 'ref' query parameter is allowed on api.github.com URLs.")
    return url


def safe_url_for_log(url: Any, limit: int = 200) -> str:
    """The URL as it may appear in logs, audit rows and provenance: scheme + host + path only.

    Never the userinfo (credentials), the query string or the fragment, never control or invisible characters, and
    always truncated. Unparseable input becomes a fixed placeholder, never the raw text."""
    if not isinstance(url, str):
        return "(no URL)"
    try:
        parsed = urlparse(url.strip())
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        scheme = parsed.scheme or ""
        path = parsed.path or ""
    except ValueError:
        return "(unparseable URL)"
    if not scheme or not host:
        return "(unparseable URL)"
    safe = _INVISIBLE.sub("", _CONTROL.sub("", f"{scheme}://{host}{port}{path}"))
    return safe if len(safe) <= limit else safe[: limit - 3] + "..."


def make_http_client() -> httpx.Client:
    """SSRF-guarded client (public addresses only, no redirects, no environment proxies). Patched in tests."""
    return netguard.guarded_client(timeout=FETCH_TIMEOUT)


def fetch_pack_from_url(url: str) -> bytes:
    """Fetch a pack from an allow-listed GitHub host. Raises SourceError. Sends no credentials."""
    url = validate_source_url(url)
    try:
        netguard.assert_public_url(url)
    except netguard.UnsafeURLError as exc:
        raise SourceError(str(exc))
    headers = {"User-Agent": "Phantom-SOAR-playbook-import", "Accept": "application/json, text/plain;q=0.9"}
    if urlparse(url).hostname.lower() == "api.github.com":
        headers["Accept"] = "application/vnd.github.raw+json"
    try:
        with make_http_client() as client:
            with client.stream("GET", url, headers=headers) as response:
                if 300 <= response.status_code < 400:
                    raise SourceError("The server answered with a redirect; redirects are not followed.")
                if response.status_code == 404:
                    raise SourceError("The file was not found (HTTP 404). Is the repository public?")
                if response.status_code in (403, 429):
                    raise SourceError(f"GitHub refused the request (HTTP {response.status_code}); "
                                      "the unauthenticated rate limit may be exhausted. Try again later.")
                if response.status_code != 200:
                    raise SourceError(f"The server answered HTTP {response.status_code}.")
                declared = response.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > MAX_PACK_BYTES:
                    raise SourceError(f"The file is larger than the {MAX_PACK_BYTES} byte limit.")
                chunks, total = [], 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_PACK_BYTES:
                        raise SourceError(f"The file is larger than the {MAX_PACK_BYTES} byte limit.")
                    chunks.append(chunk)
                return b"".join(chunks)
    except SourceError:
        raise
    except netguard.UnsafeURLError as exc:
        raise SourceError(f"Connection refused by the SSRF guard: {exc}")
    except httpx.TimeoutException:
        raise SourceError("The request timed out.")
    except httpx.HTTPError as exc:
        raise SourceError(f"The request failed: {exc.__class__.__name__}.")
