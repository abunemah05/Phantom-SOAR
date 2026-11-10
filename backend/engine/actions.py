"""Response action catalog and the single execution path for containment actions.

Playbooks, analysts and the AI-agent API all run actions through
execute_action(), which routes to the connector, records a ContainmentAction
with the honest outcome (live / simulated / skipped / failed) and writes a
telemetry log entry. Policy checks live in backend.engine.policy and must be
evaluated by the caller before execute_action is invoked.
"""
import logging
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.crud import create_containment_action
from backend.integrations import connector_base
from backend.integrations.edr import edr_client
from backend.integrations.firewall import firewall_client
from backend.integrations.iam import iam_client
from backend.integrations.itsm import itsm_client
from backend.models import Alert, ContainmentAction

logger = logging.getLogger(__name__)

_AGENT_ID_PARAM = {
    "type": "string",
    "description": "Wazuh agent id to run on; defaults to the alert's agent.id",
}

ACTION_CATALOG: Dict[str, Dict[str, Any]] = {
    "isolate_endpoint": {
        "connector": "edr",
        "target_type": "host",
        "impact": "high",
        "reversible": True,
        "description": "Network-isolate a host through a Wazuh active-response command.",
        "params": {"agent_id": _AGENT_ID_PARAM},
    },
    "unisolate_endpoint": {
        "connector": "edr",
        "target_type": "host",
        "impact": "low",
        "reversible": True,
        "description": "Lift network isolation from a host.",
        "params": {"agent_id": _AGENT_ID_PARAM},
    },
    "terminate_process": {
        "connector": "edr",
        "target_type": "process",
        "impact": "medium",
        "reversible": False,
        "description": "Kill a process (by name or image path) on the alert's host.",
        "params": {
            "agent_id": _AGENT_ID_PARAM,
            "pid": {"type": "integer", "minimum": 1, "description": "Process id, when known"},
        },
    },
    "quarantine_file": {
        "connector": "edr",
        "target_type": "file",
        "impact": "medium",
        "reversible": True,
        "description": "Move a file on the alert's host into quarantine.",
        "params": {
            "agent_id": _AGENT_ID_PARAM,
            "file_hash": {"type": "string", "description": "Expected hash of the file"},
        },
    },
    "block_ip": {
        "connector": "firewall",
        "target_type": "ip",
        "impact": "medium",
        "reversible": True,
        "description": "Drop traffic from an IP with the Wazuh firewall-drop active response.",
        "params": {
            "agent_id": _AGENT_ID_PARAM,
            "duration_hours": {"type": "integer", "minimum": 1, "maximum": 720},
            "direction": {"type": "string", "enum": ["inbound", "outbound", "both"]},
        },
    },
    "unblock_ip": {
        "connector": "firewall",
        "target_type": "ip",
        "impact": "low",
        "reversible": True,
        "description": "Remove a previously applied IP block.",
        "params": {"agent_id": _AGENT_ID_PARAM},
    },
    "apply_rate_limit": {
        "connector": "firewall",
        "target_type": "ip",
        "impact": "low",
        "reversible": True,
        "description": "Rate-limit traffic from an IP.",
        "params": {
            "agent_id": _AGENT_ID_PARAM,
            "rate": {"type": "string", "description": "e.g. '10/minute' or '5/second'"},
        },
    },
    "disable_account": {
        "connector": "iam",
        "target_type": "user",
        "impact": "high",
        "reversible": True,
        "description": "Suspend an identity-provider (Okta) account.",
        "params": {"reason": {"type": "string"}},
    },
    "revoke_user_sessions": {
        "connector": "iam",
        "target_type": "user",
        "impact": "medium",
        "reversible": False,
        "description": "Revoke all identity-provider sessions of a user.",
        "params": {},
    },
    "force_password_reset": {
        "connector": "iam",
        "target_type": "user",
        "impact": "medium",
        "reversible": False,
        "description": "Expire a user's password so it must be changed at next sign-in.",
        "params": {},
    },
    "create_ticket": {
        "connector": "itsm",
        "target_type": "none",
        "impact": "low",
        "reversible": True,
        "description": "Open an incident ticket in Jira for the alert.",
        "params": {
            "summary": {"type": "string"},
            "description": {"type": "string"},
            "priority": {"type": "string", "enum": ["Highest", "High", "Medium", "Low", "Lowest"]},
        },
    },
    "send_notification": {
        "connector": "itsm",
        "target_type": "none",
        "impact": "low",
        "reversible": False,
        "description": "Post a notification about the alert to Slack.",
        "params": {
            "title": {"type": "string"},
            "message": {"type": "string"},
            "level": {"type": "string", "enum": ["INFO", "WARNING", "CRITICAL"]},
        },
    },
}

# Names used by older playbooks and clients.
ACTION_ALIASES: Dict[str, str] = {
    "create_jira_ticket": "create_ticket",
    "terminate_session": "revoke_user_sessions",
    "disable_user_account": "disable_account",
    "notify": "send_notification",
}

# Playbook steps that are not connector actions.
#   gate: pause until an analyst approves
#   enrichment: TIP enrichment already happened at ingest, so this is a no-op
#   report: the incident report is generated when the playbook completes
PSEUDO_STEPS: Dict[str, str] = {
    "await_analyst_approval": "gate",
    "enrich_ioc": "enrichment",
    "query_abuseipdb": "enrichment",
    "query_virustotal": "enrichment",
    "query_virustotal_url": "enrichment",
    "query_otx": "enrichment",
    "generate_report": "report",
    "generate_pdf_report": "report",
}

TARGET_ENTITY_KEYS: Dict[str, str] = {
    "host": "hosts",
    "ip": "ips",
    "user": "users",
    "file": "files",
    "process": "processes",
}

CONTAINMENT_CONNECTORS = {"edr", "firewall", "iam"}
EXECUTED_STATUSES = {"Success", "Simulated"}

_LOG_SOURCE = {"edr": "EDR", "firewall": "FIREWALL", "iam": "IAM", "itsm": "ITSM"}
_LOG_LEVEL = {"Success": "ACTION", "Simulated": "INFO", "Skipped": "WARNING", "Failed": "ERROR"}
_JIRA_PRIORITY = {"Critical": "Highest", "High": "High", "Medium": "Medium", "Low": "Low"}
_JSON_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool}


def resolve_action_name(name: Optional[str]) -> Optional[str]:
    """Canonical catalog name for an action (aliases resolved), or None if unknown."""
    if not name or not isinstance(name, str):
        return None
    key = name.strip().lower()
    key = ACTION_ALIASES.get(key, key)
    return key if key in ACTION_CATALOG else None


def get_action_spec(name: Optional[str]) -> Optional[Dict[str, Any]]:
    canonical = resolve_action_name(name)
    return ACTION_CATALOG.get(canonical) if canonical else None


def pseudo_step_kind(name: Optional[str]) -> Optional[str]:
    if not name or not isinstance(name, str):
        return None
    return PSEUDO_STEPS.get(name.strip().lower())


def list_actions() -> List[Dict[str, Any]]:
    return [{"name": name, **spec} for name, spec in ACTION_CATALOG.items()]


def validate_params(action: str, params: Optional[Dict[str, Any]]) -> List[str]:
    """Check params against the action's schema; returns a list of problems (empty when valid)."""
    spec = get_action_spec(action)
    if spec is None:
        return [f"Unknown action '{action}'."]
    if params in (None, {}):
        return []
    if not isinstance(params, dict):
        return ["params must be a JSON object."]

    errors = []
    schema = spec.get("params", {})
    for key, value in params.items():
        prop = schema.get(key)
        if prop is None:
            errors.append(f"Unknown parameter '{key}' for {resolve_action_name(action)}.")
            continue
        expected = _JSON_TYPES.get(prop.get("type", "string"), str)
        if isinstance(value, bool) and prop.get("type") in ("integer", "number"):
            errors.append(f"Parameter '{key}' must be {prop['type']}.")
            continue
        if not isinstance(value, expected):
            errors.append(f"Parameter '{key}' must be {prop.get('type', 'string')}.")
            continue
        if "enum" in prop and value not in prop["enum"]:
            errors.append(f"Parameter '{key}' must be one of {prop['enum']}.")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in prop and value < prop["minimum"]:
                errors.append(f"Parameter '{key}' must be >= {prop['minimum']}.")
            if "maximum" in prop and value > prop["maximum"]:
                errors.append(f"Parameter '{key}' must be <= {prop['maximum']}.")
    return errors


def validate_workflow_steps(workflow_logic: Any) -> List[str]:
    """Validate a playbook's workflow_logic.steps against the catalog and pseudo-steps."""
    if workflow_logic is None:
        return []
    if not isinstance(workflow_logic, dict):
        return ["workflow_logic must be a JSON object."]
    steps = workflow_logic.get("steps")
    if steps is None:
        return []
    if not isinstance(steps, list):
        return ["workflow_logic.steps must be a list."]

    errors = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            errors.append(f"Step {index} must be an object.")
            continue
        name = step.get("action")
        if pseudo_step_kind(name):
            continue
        canonical = resolve_action_name(name)
        if canonical is None:
            errors.append(f"Step {index}: unknown action '{name}'.")
            continue
        params = step.get("params")
        # The playbook editor sends free-text params as a string; those are ignored at run time.
        if isinstance(params, dict):
            errors.extend(f"Step {index}: {problem}" for problem in validate_params(canonical, params))
    return errors


def alert_agent(alert: Alert) -> Dict[str, Optional[str]]:
    raw = alert.raw_payload or {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}
    agent_id = agent.get("id")
    return {
        "id": str(agent_id).strip() if agent_id not in (None, "") else None,
        "name": agent.get("name") or agent.get("hostname"),
        "ip": agent.get("ip"),
    }


def _agent_id_for(alert: Alert, action: str, target: Optional[str], params: Dict[str, Any]) -> Optional[str]:
    if params.get("agent_id"):
        return str(params["agent_id"])
    agent = alert_agent(alert)
    if ACTION_CATALOG[action]["target_type"] != "host":
        return agent["id"]
    # Host actions only map to the alert's own agent; another host needs an explicit agent_id.
    names = {str(v).lower() for v in (agent["name"], agent["id"], agent["ip"]) if v}
    return agent["id"] if target and target.lower() in names else None


def _alert_context(alert: Alert) -> Dict[str, Any]:
    raw = alert.raw_payload or {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    return {"phantom_alert_id": alert.alert_id, "rule_id": alert.rule_id, "rule_description": rule.get("description")}


def _default_ticket_text(alert: Alert) -> Dict[str, str]:
    raw = alert.raw_payload or {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    title = rule.get("description") or alert.rule_id
    lines = [
        f"Phantom SOAR alert #{alert.alert_id}",
        f"Rule: {alert.rule_id} - {title}",
        f"Source: {alert.source}",
        f"Severity: {alert.severity}",
        f"Status: {alert.status}",
    ]
    iocs = list(alert.ioc_artifacts or [])
    if iocs:
        lines.append("Indicators:")
        lines.extend(
            f"- {i.artifact_type} {i.value}: verdict {i.verdict or 'Unknown'} (score {i.threat_score})" for i in iocs
        )
    actions = list(alert.containment_actions or [])
    if actions:
        lines.append("Response actions so far:")
        lines.extend(
            f"- {a.action_type} on {a.target or 'n/a'}: {a.status} ({a.execution_mode or 'n/a'})" for a in actions
        )
    return {"summary": f"[Phantom SOAR #{alert.alert_id}] {title}", "description": "\n".join(lines)}


def _dispatch(alert: Alert, action: str, target: Optional[str], params: Dict[str, Any]) -> Dict[str, Any]:
    context = _alert_context(alert)
    agent_id = _agent_id_for(alert, action, target, params)

    if action == "isolate_endpoint":
        return edr_client.isolate_endpoint(target, agent_id=agent_id, alert_context=context)
    if action == "unisolate_endpoint":
        return edr_client.unisolate_endpoint(target, agent_id=agent_id, alert_context=context)
    if action == "terminate_process":
        return edr_client.terminate_process(target, agent_id=agent_id, pid=params.get("pid"), alert_context=context)
    if action == "quarantine_file":
        return edr_client.quarantine_file(target, agent_id=agent_id, file_hash=params.get("file_hash"), alert_context=context)
    if action == "block_ip":
        return firewall_client.block_ip(
            target, agent_id=agent_id, duration_hours=params.get("duration_hours"),
            direction=params.get("direction"), alert_context=context,
        )
    if action == "unblock_ip":
        return firewall_client.unblock_ip(target, agent_id=agent_id, alert_context=context)
    if action == "apply_rate_limit":
        return firewall_client.apply_rate_limit(
            target, rate=params.get("rate") or "10/minute", agent_id=agent_id, alert_context=context
        )
    if action == "disable_account":
        return iam_client.disable_account(target, reason=params.get("reason"))
    if action == "revoke_user_sessions":
        return iam_client.revoke_user_sessions(target)
    if action == "force_password_reset":
        return iam_client.force_password_reset(target)
    if action == "create_ticket":
        text = _default_ticket_text(alert)
        return itsm_client.create_ticket(
            alert.alert_id,
            summary=params.get("summary") or text["summary"],
            description=params.get("description") or text["description"],
            priority=params.get("priority") or _JIRA_PRIORITY.get(alert.severity, "Medium"),
        )
    if action == "send_notification":
        text = _default_ticket_text(alert)
        return itsm_client.send_notification(
            title=params.get("title") or text["summary"],
            message=params.get("message") or text["description"],
            level=params.get("level") or ("CRITICAL" if alert.severity == "Critical" else "WARNING"),
        )
    raise ValueError(f"No connector route for action '{action}'")


def _record_log(db: Session, source: str, level: str, message: str, target: Optional[str], details: Dict[str, Any]) -> None:
    try:
        from backend.routers.logs import record_log
        record_log(db, source, level, message, target, details)
    except Exception as exc:  # telemetry must never break response execution
        logger.debug(f"Could not record action log: {exc}")
        db.rollback()


def execute_action(
    db: Session,
    alert: Alert,
    action: str,
    target: Optional[str],
    params: Optional[Dict[str, Any]] = None,
    executed_by: str = "System",
) -> ContainmentAction:
    """Run one catalog action through its connector and record the honest outcome.

    Raises ValueError for an action that is not in the catalog. Connector errors never
    raise: they are recorded with status "Failed" / execution_mode "failed".
    """
    canonical = resolve_action_name(action)
    if canonical is None:
        raise ValueError(f"Unknown action '{action}'")
    spec = ACTION_CATALOG[canonical]
    params = params if isinstance(params, dict) else {}
    if spec["target_type"] == "none":
        target = None
    elif target is not None:
        target = str(target).strip()

    try:
        result = _dispatch(alert, canonical, target, params)
    except Exception as exc:
        logger.exception(f"Connector error running {canonical} for alert #{alert.alert_id}")
        result = connector_base.failed(canonical, target, spec["connector"], f"{exc.__class__.__name__}: {exc}")

    status = result.get("status", "Failed")
    mode = result.get("execution_mode", "failed")
    details = dict(result)
    if params:
        details["params"] = params

    record_target = f"Alert #{alert.alert_id}" if spec["target_type"] == "none" else target
    record = create_containment_action(
        db,
        alert.alert_id,
        canonical,
        status=status,
        executed_by=executed_by,
        target=record_target,
        connector=spec["connector"],
        execution_mode=mode,
        details=details,
    )

    label = "SIMULATED " if mode == "simulated" else ""
    _record_log(
        db,
        _LOG_SOURCE.get(spec["connector"], "AUTOMATION"),
        _LOG_LEVEL.get(status, "INFO"),
        f"{label}{canonical} on {record_target or 'n/a'}: {status} ({mode}) for Alert #{alert.alert_id}"
        + (f" - {result.get('error')}" if result.get("error") else ""),
        record_target,
        {"alert_id": alert.alert_id, "action_id": record.action_id, "executed_by": executed_by,
         "execution_mode": mode, "provider": result.get("provider")},
    )
    return record


def record_policy_block(
    db: Session,
    alert: Alert,
    action: str,
    target: Optional[str],
    decision: Any,
    executed_by: str = "System",
    params: Optional[Dict[str, Any]] = None,
) -> ContainmentAction:
    """Record an action that policy denied ("Blocked") or held for approval ("Awaiting Approval")."""
    canonical = resolve_action_name(action) or str(action)
    spec = ACTION_CATALOG.get(canonical, {})
    decision_dict = decision.to_dict() if hasattr(decision, "to_dict") else dict(decision)
    status = "Awaiting Approval" if decision_dict.get("allowed") and decision_dict.get("requires_approval") else "Blocked"
    details: Dict[str, Any] = {"policy": decision_dict, "reasons": decision_dict.get("reasons", [])}
    if params:
        details["params"] = params
    record = create_containment_action(
        db,
        alert.alert_id,
        canonical,
        status=status,
        executed_by=executed_by,
        target=target,
        connector=spec.get("connector"),
        execution_mode="blocked",
        details=details,
    )
    _record_log(
        db, "AUTOMATION", "WARNING",
        f"{canonical} on {target or 'n/a'} {status.lower()} by policy for Alert #{alert.alert_id}: "
        + "; ".join(decision_dict.get("reasons", [])),
        target,
        {"alert_id": alert.alert_id, "action_id": record.action_id, "policy": decision_dict},
    )
    return record
