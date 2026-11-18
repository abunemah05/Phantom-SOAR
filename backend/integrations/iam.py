"""Identity connector backed by the Okta Users API.

Requires okta_domain (e.g. "dev-123456.okta.com") and okta_api_token. The alert's user is
resolved to exactly one Okta user, then the action calls:

    disable_account       POST   /api/v1/users/{id}/lifecycle/suspend   (user must be ACTIVE)
    revoke_user_sessions  DELETE /api/v1/users/{id}/sessions
    force_password_reset  POST   /api/v1/users/{id}/lifecycle/expire_password

Suspension is reversible in Okta (lifecycle/unsuspend).

Resolution (never acts on more than the one user it resolves):
  1. ``GET /api/v1/users/{login}``: the path accepts a user id, a login, or an unambiguous login
     shortname (Okta Get User, https://developer.okta.com/docs/api/openapi/okta-management/management/tags/user/other/getuser).
     For a plain username or DOMAIN\\user the optional okta_login_domain setting builds
     ``user@okta_login_domain`` first.
  2. If that is 404, list users with ``search``/``filter`` on profile.email or
     ``profile.login sw "user@"`` (https://developer.okta.com/docs/api/openapi/okta-management/management/tags/user/other/listusers).
     Zero matches -> Failed "not found"; more than one -> Failed "ambiguous". Okta's own "me"
     alias (the API token's owner) is refused.
Rate limits: HTTP 429 is retried after Retry-After / X-Rate-Limit-Reset
(https://developer.okta.com/docs/reference/rl-best-practices), then reported as Failed.
"""
import logging
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote

import httpx

from backend.integrations import connector_base as base
from backend.integrations import throttle

logger = logging.getLogger(__name__)

OKTA_REQUIRED = ("okta_domain", "okta_api_token")
# Characters allowed in a login/username; quotes and backslashes would break the search expression.
_SAFE_IDENTITY = re.compile(r"^[\w.@+'\-]{1,200}$")


def _okta_base_url(domain: str) -> str:
    domain = domain.strip().rstrip("/")
    if not domain.startswith(("http://", "https://")):
        domain = f"https://{domain}"
    return domain


def _okta_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        summary = body.get("errorSummary") or body.get("errorCode")
    except (ValueError, AttributeError):
        summary = (resp.text or "").strip()[:200]
    if resp.status_code == 429:
        wait = throttle.retry_after_seconds(resp)
        return f"Okta rate limit (HTTP 429)" + (f"; retry after about {int(wait)}s" if wait is not None else "") + f": {summary}"
    return f"Okta returned HTTP {resp.status_code}: {summary}"


def parse_identity(raw: str, login_domain: str = "") -> Tuple[Optional[str], Optional[str], str]:
    """(login, shortname, problem) for an alert's user value.

    ``login`` is a full login/email when one is known or can be built; ``shortname`` is the bare
    username. ``problem`` is non-empty when the value cannot safely be sent to Okta.
    """
    value = (raw or "").strip()
    if "\\" in value:  # DOMAIN\user (Windows)
        value = value.rsplit("\\", 1)[1].strip()
    if not value or value.lower() == "me":
        return None, None, "the alert has no usable user name"
    if not _SAFE_IDENTITY.match(value):
        return None, None, f"'{value[:60]}' is not a valid login or user name"
    if "@" in value:
        return value, value.split("@", 1)[0], ""
    domain = (login_domain or "").strip().lstrip("@")
    return (f"{value}@{domain}" if domain else None), value, ""


class IAMConnector:
    """Account containment through Okta."""

    provider = "Okta"

    def _request(self, client: httpx.Client, method: str, url: str, *, idempotent: bool = True, **kwargs) -> httpx.Response:
        """The single place every Okta HTTP call goes through with bounded retries (connector_base.request_with_retry)."""
        return base.request_with_retry(
            client, method, url, idempotent=idempotent, retry_statuses=base.RETRY_STATUSES - {429}, **kwargs
        )

    def _call(self, client: httpx.Client, method: str, url: str, **kwargs) -> httpx.Response:
        return throttle.send_honouring_429(lambda: self._request(client, method, url, **kwargs))

    def _resolve_user(
        self, client: httpx.Client, root: str, headers: Dict[str, str], username: str, login_domain: str
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[str, str]]]:
        """Return (user, None) for exactly one Okta user, or (None, (reason_code, message))."""
        login, short, problem = parse_identity(username, login_domain)
        if problem:
            return None, ("invalid_user", f"Cannot resolve an Okta user: {problem}.")
        direct = login or short

        resp = self._call(client, "GET", f"{root}/api/v1/users/{quote(direct, safe='')}", headers=headers)
        if resp.status_code == 200:
            user = resp.json() or {}
            return self._verify(user, login, short, username)
        if resp.status_code != 404:
            return None, ("lookup_failed", _okta_error(resp))

        if login:
            params = {"search": f'profile.email eq "{login}"'}
        else:
            params = {"search": f'profile.login sw "{short}@"'}
        resp = self._call(client, "GET", f"{root}/api/v1/users", headers=headers, params={**params, "limit": "3"})
        if resp.status_code == 404:
            matches = []
        elif resp.status_code >= 400:
            return None, ("lookup_failed", _okta_error(resp))
        else:
            data = resp.json()
            matches = data if isinstance(data, list) else []
        if not matches:
            return None, ("user_not_found", f"Okta user '{username}' was not found.")
        if len(matches) > 1:
            return None, ("ambiguous_user", f"'{username}' matches {len(matches)} Okta users; refusing to act on an ambiguous identity.")
        return self._verify(matches[0] or {}, login, short, username)

    @staticmethod
    def _verify(user: Dict[str, Any], login: Optional[str], short: Optional[str], username: str):
        """Guard against acting on a user other than the one named (profile checked when present)."""
        profile = user.get("profile") if isinstance(user.get("profile"), dict) else None
        if profile and (profile.get("login") or profile.get("email")):
            known = {str(profile.get(k)).lower() for k in ("login", "email") if profile.get(k)}
            wanted = {login.lower()} if login else set()
            local_parts = {v.split("@", 1)[0] for v in known}
            if not (known & wanted or (short and short.lower() in local_parts and not login)):
                return None, ("identity_mismatch", f"Okta returned a user whose login does not match '{username}'; no action taken.")
        if not user.get("id"):
            return None, ("lookup_failed", "Okta user lookup returned no id.")
        return user, None

    def _user_action(self, action: str, username: str, method: str, path: str) -> Dict[str, Any]:
        cfg = base.read_settings(*OKTA_REQUIRED, "okta_login_domain")
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
                user, problem = self._resolve_user(client, root, headers, username, cfg.get("okta_login_domain", ""))
                if problem:
                    code, message = problem
                    return base.failed(action, username, self.provider, message, details={"reason": code})
                user_id = user["id"]

                endpoint = path.format(id=quote(str(user_id), safe=""))
                resp = self._call(client, method, f"{root}{endpoint}", headers=headers)
                if resp.status_code >= 400:
                    return base.failed(
                        action, username, self.provider, _okta_error(resp),
                        details={"okta_user_id": user_id, "endpoint": endpoint,
                                 **({"reason": "rate_limited"} if resp.status_code == 429 else {})},
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
