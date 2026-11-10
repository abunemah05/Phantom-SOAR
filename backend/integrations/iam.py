"""Identity connector backed by the Okta Users API.

Requires okta_domain (e.g. "dev-123456.okta.com") and okta_api_token. The
user is looked up by login (GET /api/v1/users/{login}); the action then calls:

    disable_account       POST   /api/v1/users/{id}/lifecycle/suspend
    revoke_user_sessions  DELETE /api/v1/users/{id}/sessions
    force_password_reset  POST   /api/v1/users/{id}/lifecycle/expire_password

Suspension is reversible in Okta (lifecycle/unsuspend).
"""
import logging
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx

from backend.integrations import connector_base as base

logger = logging.getLogger(__name__)

OKTA_REQUIRED = ("okta_domain", "okta_api_token")


def _okta_base_url(domain: str) -> str:
    domain = domain.strip().rstrip("/")
    if not domain.startswith(("http://", "https://")):
        domain = f"https://{domain}"
    return domain


def _okta_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        summary = body.get("errorSummary") or body.get("errorCode")
    except ValueError:
        summary = (resp.text or "").strip()[:200]
    return f"Okta returned HTTP {resp.status_code}: {summary}"


class IAMConnector:
    """Account containment through Okta."""

    provider = "Okta"

    def _user_action(self, action: str, username: str, method: str, path: str) -> Dict[str, Any]:
        cfg = base.read_settings(*OKTA_REQUIRED)
        missing = base.missing_settings(cfg, OKTA_REQUIRED)
        if missing:
            return base.unconfigured(action, username, self.provider, missing)

        root = _okta_base_url(cfg["okta_domain"])
        headers = {
            "Authorization": f"SSWS {cfg['okta_api_token']}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            with base.http_client() as client:
                lookup = client.get(f"{root}/api/v1/users/{quote(username, safe='')}", headers=headers)
                if lookup.status_code == 404:
                    return base.failed(action, username, self.provider, f"Okta user '{username}' was not found.")
                if lookup.status_code >= 400:
                    return base.failed(action, username, self.provider, _okta_error(lookup))
                user = lookup.json() or {}
                user_id = user.get("id")
                if not user_id:
                    return base.failed(action, username, self.provider, "Okta user lookup returned no id.")

                endpoint = path.format(id=user_id)
                resp = client.request(method, f"{root}{endpoint}", headers=headers)
                if resp.status_code >= 400:
                    return base.failed(
                        action, username, self.provider, _okta_error(resp),
                        details={"okta_user_id": user_id, "endpoint": endpoint},
                    )
        except httpx.HTTPError as exc:
            return base.failed(action, username, self.provider, base.describe_http_error(exc))
        except ValueError as exc:
            return base.failed(action, username, self.provider, f"Okta returned a non-JSON response: {exc}")

        details = {
            "okta_user_id": user_id,
            "okta_status_before": user.get("status"),
            "endpoint": f"{method} {endpoint}",
            "http_status": resp.status_code,
        }
        logger.info(f"[Okta] {action} succeeded for {username} ({user_id}).")
        return base.live(action, username, self.provider, details)

    def disable_account(self, username: str, reason: Optional[str] = None) -> Dict[str, Any]:
        result = self._user_action("disable_account", username, "POST", "/api/v1/users/{id}/lifecycle/suspend")
        if reason:
            result["details"]["reason"] = reason
        return result

    # Older name kept for callers that predate the action catalog.
    disable_user_account = disable_account

    def revoke_user_sessions(self, username: str) -> Dict[str, Any]:
        return self._user_action("revoke_user_sessions", username, "DELETE", "/api/v1/users/{id}/sessions")

    def force_password_reset(self, username: str) -> Dict[str, Any]:
        return self._user_action(
            "force_password_reset", username, "POST", "/api/v1/users/{id}/lifecycle/expire_password"
        )


iam_client = IAMConnector()
