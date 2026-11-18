"""WS2: Okta user resolution / 429 handling and Jira idempotency / v3 ADF / Slack honesty."""
import json
import time

import httpx
import pytest

from backend import integration_config
from backend.integrations import connector_base, throttle
from backend.integrations.iam import iam_client, parse_identity
from backend.integrations.itsm import itsm_client, to_adf

OKTA = {"okta_domain": "dev-000.okta.test", "okta_api_token": "okta-token"}
JIRA = {
    "jira_base_url": "https://soc.atlassian.test",
    "jira_email": "soar@corp.test",
    "jira_api_token": "jira-token",
    "jira_project_key": "SOC",
}


@pytest.fixture
def settings(monkeypatch):
    overrides = {}
    original = integration_config.get_setting

    def fake(key_name, db=None, default=None):
        if key_name in overrides:
            return overrides[key_name]
        return original(key_name, db=db, default=default)

    monkeypatch.setattr(integration_config, "get_setting", fake)
    return overrides


@pytest.fixture
def http(monkeypatch):
    def install(handler):
        calls = []

        def recorder(request):
            calls.append(request)
            return handler(request)

        transport = httpx.MockTransport(recorder)
        monkeypatch.setattr(connector_base, "http_client", lambda verify=True: httpx.Client(transport=transport, timeout=5))
        return calls
    return install


@pytest.fixture
def sleeps(monkeypatch):
    waited = []
    monkeypatch.setattr(throttle, "_sleep", waited.append)
    return waited


def _writes(calls):
    return [(c.method, c.url.path) for c in calls if c.method != "GET"]


# --- Okta resolution ---------------------------------------------------------------------

def test_parse_identity_forms():
    assert parse_identity("jdoe@corp.test", "x.test") == ("jdoe@corp.test", "jdoe", "")
    assert parse_identity("CORP\\jdoe", "corp.test") == ("jdoe@corp.test", "jdoe", "")
    assert parse_identity("jdoe", "@corp.test") == ("jdoe@corp.test", "jdoe", "")
    assert parse_identity("jdoe", "") == (None, "jdoe", "")
    for bad in ("", "me", "ME", 'a"b', "a b", "x;y"):
        assert parse_identity(bad, "corp.test")[2]


def test_windows_name_uses_okta_login_domain(settings, http):
    settings.update(OKTA)
    settings["okta_login_domain"] = "corp.test"

    def handler(request):
        if request.method == "GET" and request.url.path == "/api/v1/users/jdoe@corp.test":
            return httpx.Response(200, json={"id": "00u1", "status": "ACTIVE", "profile": {"login": "jdoe@corp.test"}})
        return httpx.Response(200, json={})

    calls = http(handler)
    result = iam_client.disable_account("CORP\\jdoe")
    assert result["status"] == "Success" and result["details"]["okta_user_id"] == "00u1"
    assert _writes(calls) == [("POST", "/api/v1/users/00u1/lifecycle/suspend")]


def test_plain_username_falls_back_to_search_and_needs_exactly_one_match(settings, http):
    settings.update(OKTA)

    def one(request):
        if request.url.path == "/api/v1/users" and request.method == "GET":
            assert request.url.params["search"] == 'profile.login sw "jdoe@"'
            return httpx.Response(200, json=[{"id": "00u7", "status": "ACTIVE", "profile": {"login": "jdoe@corp.test"}}])
        if request.method == "GET":
            return httpx.Response(404, json={"errorSummary": "Not found"})
        return httpx.Response(200, json={})

    calls = http(one)
    assert iam_client.revoke_user_sessions("jdoe")["status"] == "Success"
    assert _writes(calls) == [("DELETE", "/api/v1/users/00u7/sessions")]

    def two(request):
        if request.url.path == "/api/v1/users" and request.method == "GET":
            return httpx.Response(200, json=[{"id": "00uA"}, {"id": "00uB"}])
        if request.method == "GET":
            return httpx.Response(404, json={})
        pytest.fail("must not act on an ambiguous identity")

    calls = http(two)
    result = iam_client.disable_account("jdoe")
    assert result["status"] == "Failed" and result["details"]["reason"] == "ambiguous_user"
    assert "2 Okta users" in result["error"] and _writes(calls) == []

    calls = http(lambda r: httpx.Response(200, json=[]) if r.url.path == "/api/v1/users" else httpx.Response(404, json={}))
    result = iam_client.disable_account("nobody")
    assert result["status"] == "Failed" and result["details"]["reason"] == "user_not_found" and _writes(calls) == []


def test_email_not_found_directly_is_searched_by_profile_email(settings, http):
    settings.update(OKTA)

    def handler(request):
        if request.url.path == "/api/v1/users" and request.method == "GET":
            assert request.url.params["search"] == 'profile.email eq "jdoe@corp.test"'
            return httpx.Response(200, json=[{"id": "00u9", "profile": {"login": "j.doe@corp.test", "email": "jdoe@corp.test"}}])
        if request.method == "GET":
            return httpx.Response(404, json={})
        return httpx.Response(200, json={})

    calls = http(handler)
    assert iam_client.force_password_reset("jdoe@corp.test")["status"] == "Success"
    assert _writes(calls) == [("POST", "/api/v1/users/00u9/lifecycle/expire_password")]


def test_unsafe_or_self_identities_never_reach_okta(settings, http):
    settings.update(OKTA)
    calls = http(lambda r: httpx.Response(200, json={"id": "00uSELF"}))
    for bad in ("me", 'x" or profile.login pr', ""):
        result = iam_client.disable_account(bad)
        assert result["status"] == "Failed" and result["details"]["reason"] == "invalid_user"
    assert calls == []


def test_user_whose_login_does_not_match_is_not_touched(settings, http):
    settings.update(OKTA)

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"id": "00uX", "profile": {"login": "someone.else@corp.test"}})
        pytest.fail("acted on the wrong user")

    http(handler)
    result = iam_client.disable_account("jdoe@corp.test")
    assert result["status"] == "Failed" and result["details"]["reason"] == "identity_mismatch"


def test_okta_429_retry_after_then_success(settings, http, sleeps):
    settings.update(OKTA)
    state = {"n": 0}

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"id": "00u1", "status": "ACTIVE"})
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "3"}, json={"errorSummary": "Too many requests"})
        return httpx.Response(200, json={})

    calls = http(handler)
    result = iam_client.disable_account("jdoe@corp.test")
    assert result["status"] == "Success" and sleeps == [3.0]
    assert len(_writes(calls)) == 2  # the same single user, retried once


def test_okta_429_uses_reset_epoch_and_reports_when_wait_is_too_long(settings, http, sleeps):
    settings.update(OKTA)

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"id": "00u1"})
        return httpx.Response(429, headers={"X-Rate-Limit-Reset": str(int(time.time()) + 600)}, json={"errorSummary": "Too many"})

    http(handler)
    result = iam_client.disable_account("jdoe@corp.test")
    assert result["status"] == "Failed" and "rate limit" in result["error"].lower()
    assert result["details"]["reason"] == "rate_limited" and sleeps == []


def test_throttle_retry_after_parsing():
    assert throttle.retry_after_seconds(httpx.Response(429, headers={"Retry-After": "12"})) == 12
    now = 1_000_000.0
    assert throttle.retry_after_seconds(httpx.Response(429, headers={"X-Rate-Limit-Reset": str(int(now) + 30)}), now=now) == 30
    assert throttle.retry_after_seconds(httpx.Response(429)) is None


# --- Jira ----------------------------------------------------------------------------------

def test_adf_document_shape():
    doc = to_adf("line one\n\nline two")
    assert doc["version"] == 1 and doc["type"] == "doc"
    assert [p["content"][0]["text"] for p in doc["content"]] == ["line one", "line two"]
    assert to_adf("")["content"][0]["content"][0]["text"]


def _jira_handler(existing=None, created_key="SOC-1", search_status=200, create_responses=None):
    seen = {"created": 0}

    def handler(request):
        if request.method == "GET":
            if search_status != 200:
                return httpx.Response(search_status, text="boom")
            return httpx.Response(200, json={"issues": [existing] if existing else []})
        seen["created"] += 1
        if create_responses:
            return create_responses.pop(0)
        return httpx.Response(201, json={"id": "1", "key": created_key})

    return handler, seen


def test_existing_issue_with_alert_label_is_reused_not_duplicated(settings, http):
    settings.update(JIRA)
    handler, seen = _jira_handler(existing={"id": "55", "key": "SOC-55"})
    calls = http(handler)
    result = itsm_client.create_ticket(alert_id=7, summary="s", description="d")
    assert result["status"] == "Success" and result["ticket_key"] == "SOC-55"
    assert result["details"]["deduplicated"] is True and seen["created"] == 0
    search = calls[0]
    assert search.url.path == "/rest/api/2/search/jql"
    assert 'labels = "phantom-alert-7"' in search.url.params["jql"] and 'project = "SOC"' in search.url.params["jql"]


def test_failed_run_then_rerun_does_not_duplicate(settings, http):
    settings.update(JIRA)
    # Attempt 1: Jira creates the issue but the response is lost (500) -> Failed.
    handler, _ = _jira_handler(create_responses=[httpx.Response(500, text="gateway")])
    http(handler)
    assert itsm_client.create_ticket(alert_id=8, summary="s", description="d")["status"] == "Failed"
    # Attempt 2: the label search now finds the issue Jira did create.
    handler, seen = _jira_handler(existing={"key": "SOC-8"})
    http(handler)
    again = itsm_client.create_ticket(alert_id=8, summary="s", description="d")
    assert again["status"] == "Success" and again["ticket_key"] == "SOC-8" and seen["created"] == 0


def test_label_is_set_and_v2_description_is_plain_text(settings, http):
    settings.update(JIRA)
    handler, _ = _jira_handler()
    calls = http(handler)
    itsm_client.create_ticket(alert_id=9, summary="s", description="plain\ntext")
    post = [c for c in calls if c.method == "POST"][0]
    body = json.loads(post.content)["fields"]
    assert post.url.path == "/rest/api/2/issue"
    assert body["description"] == "plain\ntext" and "phantom-alert-9" in body["labels"]


def test_v3_uses_adf_description_and_v3_search(settings, http):
    settings.update(JIRA)
    settings["jira_api_version"] = "3"
    handler, _ = _jira_handler()
    calls = http(handler)
    result = itsm_client.create_ticket(alert_id=10, summary="s", description="a\nb")
    assert result["status"] == "Success"
    assert calls[0].url.path == "/rest/api/3/search/jql"
    post = [c for c in calls if c.method == "POST"][0]
    assert post.url.path == "/rest/api/3/issue"
    desc = json.loads(post.content)["fields"]["description"]
    assert desc["type"] == "doc" and desc["version"] == 1 and len(desc["content"]) == 2


def test_server_without_search_jql_falls_back_to_legacy_search(settings, http):
    settings.update(JIRA)

    def handler(request):
        if request.method == "GET" and request.url.path == "/rest/api/2/search/jql":
            return httpx.Response(404, text="nope")
        if request.method == "GET" and request.url.path == "/rest/api/2/search":
            return httpx.Response(200, json={"issues": [{"key": "SOC-3"}]})
        pytest.fail("should reuse the issue found by the legacy search")

    http(handler)
    assert itsm_client.create_ticket(alert_id=11, summary="s", description="d")["ticket_key"] == "SOC-3"


def test_failed_duplicate_check_fails_closed_without_creating(settings, http):
    settings.update(JIRA)
    handler, seen = _jira_handler(search_status=500)
    http(handler)
    result = itsm_client.create_ticket(alert_id=12, summary="s", description="d")
    assert result["status"] == "Failed" and result["ticket_key"] is None
    assert "existing issue" in result["error"] and seen["created"] == 0


def test_jira_429_retry_after_then_created_once(settings, http, sleeps):
    settings.update(JIRA)
    handler, seen = _jira_handler(create_responses=[
        httpx.Response(429, headers={"Retry-After": "2"}, text="slow down"),
        httpx.Response(201, json={"id": "9", "key": "SOC-9"}),
    ])
    http(handler)
    result = itsm_client.create_ticket(alert_id=13, summary="s", description="d")
    assert result["ticket_key"] == "SOC-9" and sleeps == [2.0] and seen["created"] == 2


def test_jira_429_with_unreasonable_wait_is_reported_failed(settings, http, sleeps):
    settings.update(JIRA)
    handler, _ = _jira_handler(create_responses=[httpx.Response(429, headers={"Retry-After": "900"}, text="quota")])
    http(handler)
    result = itsm_client.create_ticket(alert_id=14, summary="s", description="d")
    assert result["status"] == "Failed" and "429" in result["error"] and sleeps == []


# --- Slack ---------------------------------------------------------------------------------

SLACK = "https://hooks.slack.test/services/T000/B000/SECRETVALUE"


def test_slack_success_and_failure_are_reported_honestly(settings, http, sleeps):
    settings["slack_webhook_url"] = SLACK
    http(lambda r: httpx.Response(200, text="ok"))
    assert itsm_client.send_notification("t", "m")["status"] == "Success"

    http(lambda r: httpx.Response(200, json={"ok": False, "error": "invalid_blocks"}))
    result = itsm_client.send_notification("t", "m")
    assert result["status"] == "Failed" and "invalid_blocks" in result["error"]

    http(lambda r: httpx.Response(404, text="no_service"))
    result = itsm_client.send_notification("t", "m")
    assert result["status"] == "Failed" and "no_service" in result["error"]
    assert "SECRETVALUE" not in json.dumps(result)

    http(lambda r: httpx.Response(500, text="oops"))
    assert itsm_client.send_notification("t", "m")["status"] == "Failed"

    def unreachable(request):
        raise httpx.ConnectError("refused", request=request)

    http(unreachable)
    result = itsm_client.send_notification("t", "m")
    assert result["status"] == "Failed" and "SECRETVALUE" not in json.dumps(result)


def test_slack_429_is_retried_after_retry_after(settings, http, sleeps):
    settings["slack_webhook_url"] = SLACK
    responses = [httpx.Response(429, headers={"Retry-After": "1"}, text="rate_limited"), httpx.Response(200, text="ok")]
    http(lambda r: responses.pop(0))
    assert itsm_client.send_notification("t", "m")["status"] == "Success" and sleeps == [1.0]
