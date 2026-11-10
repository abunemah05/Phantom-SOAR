"""Ticketing and notification connector (Jira Cloud REST, Jira webhook, Slack).

create_ticket uses the Jira REST API (POST {jira_base_url}/rest/api/2/issue with
basic auth jira_email:jira_api_token in project jira_project_key) and reports the
key and URL Jira actually returned. The issue type defaults to "Task"
(override with JIRA_ISSUE_TYPE). When only the legacy jira_webhook_url is set
the payload is POSTed there; a webhook returns no issue key, so none is claimed.

send_notification posts to a Slack incoming webhook (slack_webhook_url).
"""
import logging
from typing import Any, Dict, Optional

import httpx

from backend.integrations import connector_base as base

logger = logging.getLogger(__name__)

JIRA_REST_REQUIRED = ("jira_base_url", "jira_email", "jira_api_token", "jira_project_key")
VALID_PRIORITIES = {"Highest", "High", "Medium", "Low", "Lowest"}


class ITSMConnector:
    """Incident tickets and analyst notifications."""

    jira_provider = "Jira"
    slack_provider = "Slack"

    def create_ticket(
        self,
        alert_id: int,
        summary: str,
        description: str,
        priority: Optional[str] = "High",
    ) -> Dict[str, Any]:
        cfg = base.read_settings(*JIRA_REST_REQUIRED, "jira_webhook_url", "jira_issue_type")
        missing = base.missing_settings(cfg, JIRA_REST_REQUIRED)
        target = f"Alert #{alert_id}"
        if not missing:
            return self._create_jira_issue(cfg, alert_id, summary, description, priority)
        if cfg.get("jira_webhook_url"):
            return self._post_jira_webhook(cfg["jira_webhook_url"], alert_id, summary, description, priority)
        return base.unconfigured("create_ticket", target, self.jira_provider, missing, ticket_key=None, ticket_url=None)

    # Older name kept for callers that predate the action catalog.
    create_jira_ticket = create_ticket

    def _create_jira_issue(
        self, cfg: Dict[str, str], alert_id: int, summary: str, description: str, priority: Optional[str]
    ) -> Dict[str, Any]:
        root = cfg["jira_base_url"].rstrip("/")
        target = f"Alert #{alert_id}"
        fields: Dict[str, Any] = {
            "project": {"key": cfg["jira_project_key"]},
            "summary": summary[:250],
            "description": description,
            "issuetype": {"name": cfg.get("jira_issue_type") or "Task"},
            "labels": ["phantom-soar", f"phantom-alert-{alert_id}"],
        }
        if priority in VALID_PRIORITIES:
            fields["priority"] = {"name": priority}

        auth = (cfg["jira_email"], cfg["jira_api_token"])
        notes = []
        try:
            with base.http_client() as client:
                resp = client.post(f"{root}/rest/api/2/issue", auth=auth, json={"fields": fields})
                # Team-managed projects often reject the priority field; retry once without it.
                if resp.status_code == 400 and "priority" in fields and "priority" in resp.text.lower():
                    fields.pop("priority")
                    notes.append("Priority was rejected by the Jira project and omitted.")
                    resp = client.post(f"{root}/rest/api/2/issue", auth=auth, json={"fields": fields})
                resp.raise_for_status()
                issue = resp.json() or {}
        except httpx.HTTPError as exc:
            return base.failed("create_ticket", target, self.jira_provider, base.describe_http_error(exc),
                               ticket_key=None, ticket_url=None)
        except ValueError as exc:
            return base.failed("create_ticket", target, self.jira_provider, f"Jira returned a non-JSON response: {exc}",
                               ticket_key=None, ticket_url=None)

        key = issue.get("key")
        if not key:
            return base.failed("create_ticket", target, self.jira_provider, "Jira accepted the request but returned no issue key.",
                               ticket_key=None, ticket_url=None)
        url = f"{root}/browse/{key}"
        details = {"ticket_key": key, "ticket_id": issue.get("id"), "ticket_url": url, "api": issue.get("self")}
        if notes:
            details["notes"] = notes
        logger.info(f"[Jira] Created {key} for Alert #{alert_id}.")
        return base.live("create_ticket", target, self.jira_provider, details, ticket_key=key, ticket_url=url)

    def _post_jira_webhook(
        self, webhook_url: str, alert_id: int, summary: str, description: str, priority: Optional[str]
    ) -> Dict[str, Any]:
        target = f"Alert #{alert_id}"
        payload = {
            "phantom_alert_id": alert_id,
            "summary": summary,
            "description": description,
            "priority": priority,
        }
        try:
            with base.http_client() as client:
                resp = client.post(webhook_url, json=payload)
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            return base.failed("create_ticket", target, "Jira webhook", base.describe_http_error(exc),
                               ticket_key=None, ticket_url=None)
        details = {
            "http_status": resp.status_code,
            "message": "Delivered to the Jira webhook. A webhook does not return an issue key, so none is recorded.",
        }
        return base.live("create_ticket", target, "Jira webhook", details, ticket_key=None, ticket_url=None)

    def send_notification(self, title: str, message: str, level: str = "WARNING") -> Dict[str, Any]:
        cfg = base.read_settings("slack_webhook_url")
        missing = base.missing_settings(cfg, ("slack_webhook_url",))
        if missing:
            return base.unconfigured("send_notification", title, self.slack_provider, missing)

        text = f"[{level.upper()}] {title}\n{message}"
        try:
            with base.http_client() as client:
                resp = client.post(cfg["slack_webhook_url"], json={"text": text})
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            return base.failed("send_notification", title, self.slack_provider, base.describe_http_error(exc))
        return base.live(
            "send_notification", title, self.slack_provider,
            {"http_status": resp.status_code, "response": (resp.text or "")[:100], "level": level.upper()},
        )


itsm_client = ITSMConnector()
