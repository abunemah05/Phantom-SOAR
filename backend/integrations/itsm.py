"""Ticketing and notification connector (Jira Cloud REST, Jira webhook, Slack).

create_ticket uses the Jira REST API (POST {jira_base_url}/rest/api/{2|3}/issue with basic auth
jira_email:jira_api_token in project jira_project_key) and reports the key and URL Jira actually
returned. The issue type defaults to "Task" (setting jira_issue_type).

API version (setting jira_api_version, default "2"): v2 takes the description as plain text/wiki
markup and also works on Jira Server/Data Center; v3 requires the description to be an Atlassian
Document Format (ADF) document, which is built here. Minimal ADF shape:
https://developer.atlassian.com/cloud/jira/platform/apis/document/structure/

Idempotency: every issue carries the label ``phantom-alert-<id>``. Before creating, the connector
searches for an existing issue with that label (GET /rest/api/{ver}/search/jql, the replacement for
the removed /search endpoints; falls back to /rest/api/2/search for Server/DC), so re-running a
step that previously ended Failed after Jira had accepted the issue does not create a duplicate.
If that check itself fails, no issue is created (fail closed) and the result says why.

Rate limits: Jira Cloud answers 429 with Retry-After (seconds); it is honoured (bounded) before
reporting a failure. https://developer.atlassian.com/cloud/jira/platform/rate-limiting/

When only the legacy jira_webhook_url is set the payload is POSTed there; a webhook returns no
issue key, so none is claimed.

send_notification posts to a Slack incoming webhook (slack_webhook_url).
"""
import logging
from typing import Any, Dict, List, Optional

import httpx

from backend.integrations import connector_base as base
from backend.integrations import throttle

logger = logging.getLogger(__name__)

JIRA_REST_REQUIRED = ("jira_base_url", "jira_email", "jira_api_token", "jira_project_key")
VALID_PRIORITIES = {"Highest", "High", "Medium", "Low", "Lowest"}


def alert_label(alert_id: int) -> str:
    return f"phantom-alert-{alert_id}"


def to_adf(text: str) -> Dict[str, Any]:
    """Plain text as a minimal ADF document: one paragraph per non-empty line."""
    paragraphs: List[Dict[str, Any]] = [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in (text or "").splitlines() if line.strip()
    ]
    if not paragraphs:
        paragraphs = [{"type": "paragraph", "content": [{"type": "text", "text": "(no description)"}]}]
    return {"version": 1, "type": "doc", "content": paragraphs}


def _jql_quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _api_version(cfg: Dict[str, str]) -> str:
    return "3" if (cfg.get("jira_api_version") or "").strip() in ("3", "v3") else "2"


class JiraLookupError(Exception):
    """The existing-issue check could not be completed."""


class ITSMConnector:
    """Incident tickets and analyst notifications."""

    jira_provider = "Jira"
    slack_provider = "Slack"

    def _request(self, client: httpx.Client, method: str, url: str, *, idempotent: bool = True, **kwargs) -> httpx.Response:
        """The single place every Jira/Slack HTTP call goes through with bounded retries (connector_base.request_with_retry).

        ``idempotent=False`` marks calls that must never be auto-retried on timeouts or 5xx
        (Jira issue creation); the label check in create_ticket is the second line of defence.
        """
        return base.request_with_retry(
            client, method, url, idempotent=idempotent, retry_statuses=base.RETRY_STATUSES - {429}, **kwargs
        )

    def _call(self, client: httpx.Client, method: str, url: str, **kwargs) -> httpx.Response:
        return throttle.send_honouring_429(lambda: self._request(client, method, url, **kwargs))

    def create_ticket(
        self,
        alert_id: int,
        summary: str,
        description: str,
        priority: Optional[str] = "High",
    ) -> Dict[str, Any]:
        cfg = base.read_settings(*JIRA_REST_REQUIRED, "jira_webhook_url", "jira_issue_type", "jira_api_version")
        missing = base.missing_settings(cfg, JIRA_REST_REQUIRED)
        target = f"Alert #{alert_id}"
        if not missing:
            return self._create_jira_issue(cfg, alert_id, summary, description, priority)
        if cfg.get("jira_webhook_url"):
            return self._post_jira_webhook(cfg["jira_webhook_url"], alert_id, summary, description, priority)
        return base.unconfigured("create_ticket", target, self.jira_provider, missing, ticket_key=None, ticket_url=None)

    # Older name kept for callers that predate the action catalog.
    create_jira_ticket = create_ticket

    def _find_existing_issue(
        self, client: httpx.Client, root: str, auth, version: str, project: str, label: str
    ) -> Optional[Dict[str, Any]]:
        """An issue already carrying this alert's label, or None. Raises JiraLookupError on failure."""
        params = {"jql": f"project = {_jql_quote(project)} AND labels = {_jql_quote(label)}",
                  "fields": "key", "maxResults": "1"}
        resp = self._call(client, "GET", f"{root}/rest/api/{version}/search/jql", auth=auth, params=params)
        if resp.status_code in (404, 405, 410):  # Jira Server/DC has no /search/jql
            resp = self._call(client, "GET", f"{root}/rest/api/2/search", auth=auth, params=params)
        if resp.status_code >= 400:
            hint = throttle.retry_after_seconds(resp) if resp.status_code == 429 else None
            raise JiraLookupError(
                f"HTTP {resp.status_code}" + (f" (retry after about {int(hint)}s)" if hint is not None else "")
                + f": {(resp.text or '').strip()[:200]}"
            )
        try:
            issues = (resp.json() or {}).get("issues") or []
        except ValueError as exc:
            raise JiraLookupError(f"non-JSON search response: {exc}")
        for issue in issues:
            if isinstance(issue, dict) and issue.get("key"):
                return issue
        return None

    def _create_jira_issue(
        self, cfg: Dict[str, str], alert_id: int, summary: str, description: str, priority: Optional[str]
    ) -> Dict[str, Any]:
        root = cfg["jira_base_url"].rstrip("/")
        target = f"Alert #{alert_id}"
        version = _api_version(cfg)
        label = alert_label(alert_id)
        fields: Dict[str, Any] = {
            "project": {"key": cfg["jira_project_key"]},
            "summary": (summary or f"Phantom SOAR alert #{alert_id}")[:250],
            "description": to_adf(description) if version == "3" else description,
            "issuetype": {"name": cfg.get("jira_issue_type") or "Task"},
            "labels": ["phantom-soar", label],
        }
        if priority in VALID_PRIORITIES:
            fields["priority"] = {"name": priority}

        auth = (cfg["jira_email"], cfg["jira_api_token"])
        notes = []
        try:
            with base.http_client() as client:
                try:
                    existing = self._find_existing_issue(client, root, auth, version, cfg["jira_project_key"], label)
                except JiraLookupError as exc:
                    return base.failed(
                        "create_ticket", target, self.jira_provider,
                        f"Could not check Jira for an existing issue for this alert ({exc}); no issue was created "
                        "to avoid a duplicate.",
                        ticket_key=None, ticket_url=None,
                    )
                if existing:
                    key = existing["key"]
                    url = f"{root}/browse/{key}"
                    logger.info(f"[Jira] Alert #{alert_id} already has {key}; not creating another.")
                    return base.live(
                        "create_ticket", target, self.jira_provider,
                        {"ticket_key": key, "ticket_id": existing.get("id"), "ticket_url": url, "deduplicated": True,
                         "message": f"Existing Jira issue {key} already carries label {label}; no new issue was created."},
                        ticket_key=key, ticket_url=url,
                    )

                # NON-IDEMPOTENT: creating an issue must not be blindly retried on timeouts/5xx.
                resp = self._call(client, "POST", f"{root}/rest/api/{version}/issue", idempotent=False,
                                  auth=auth, json={"fields": fields})
                # Team-managed projects often reject the priority field; retry once without it.
                if resp.status_code == 400 and "priority" in fields and "priority" in resp.text.lower():
                    fields.pop("priority")
                    notes.append("Priority was rejected by the Jira project and omitted.")
                    resp = self._call(client, "POST", f"{root}/rest/api/{version}/issue", idempotent=False,
                                      auth=auth, json={"fields": fields})
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
        details = {"ticket_key": key, "ticket_id": issue.get("id"), "ticket_url": url, "api": issue.get("self"),
                   "api_version": version, "label": label}
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
                resp = self._call(client, "POST", webhook_url, idempotent=False, json=payload)
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
                resp = self._call(client, "POST", cfg["slack_webhook_url"], idempotent=False, json={"text": text})
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            # The webhook URL is a secret; describe_http_error reports only the host and status.
            return base.failed("send_notification", title, self.slack_provider, base.describe_http_error(exc))

        body = (resp.text or "").strip()
        # Slack incoming webhooks answer 200 "ok"; Workflow-style hooks answer JSON {"ok": true/false}.
        try:
            parsed = resp.json() if body.startswith("{") else None
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and parsed.get("ok") is False:
            return base.failed("send_notification", title, self.slack_provider,
                               f"Slack rejected the message: {str(parsed.get('error') or 'unknown error')[:100]}")
        return base.live(
            "send_notification", title, self.slack_provider,
            {"http_status": resp.status_code, "response": body[:100], "level": level.upper()},
        )


itsm_client = ITSMConnector()
