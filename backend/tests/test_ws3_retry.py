"""request_with_retry: backoff, Retry-After, idempotency rules, attempts count (WS3)."""
import httpx
import pytest

from backend.integrations import connector_base as base


@pytest.fixture
def sleeps(monkeypatch):
    recorded = []
    monkeypatch.setattr(base, "sleep", recorded.append)
    monkeypatch.setattr(base, "jitter", lambda: 0.5)
    return recorded


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def _sequence(*items):
    """Handler that plays responses/exceptions in order and counts calls."""
    calls = []

    def handler(request):
        item = items[min(len(calls), len(items) - 1)]
        calls.append(request)
        if isinstance(item, Exception):
            item.request = request
            raise item
        return item
    handler.calls = calls
    return handler


def test_retries_503_then_succeeds_with_exponential_backoff_and_jitter(sleeps):
    handler = _sequence(httpx.Response(503), httpx.Response(502), httpx.Response(200, json={"ok": True}))
    resp = base.request_with_retry(_client(handler), "GET", "https://x.test/a")
    assert resp.status_code == 200
    assert len(handler.calls) == 3
    assert base.attempts_of(resp) == 3
    # attempt 1: 0.5 + 0.5*0.5 ; attempt 2: 1.0 + 1.0*0.5
    assert sleeps == [pytest.approx(0.75), pytest.approx(1.5)]


def test_gives_up_after_max_attempts_and_returns_last_response(sleeps):
    handler = _sequence(httpx.Response(503))
    resp = base.request_with_retry(_client(handler), "GET", "https://x.test/a", max_attempts=2)
    assert resp.status_code == 503
    assert len(handler.calls) == 2 and base.attempts_of(resp) == 2


def test_non_retryable_status_is_returned_immediately(sleeps):
    handler = _sequence(httpx.Response(500))
    resp = base.request_with_retry(_client(handler), "GET", "https://x.test/a")
    assert resp.status_code == 500 and len(handler.calls) == 1 and sleeps == []


def test_retry_after_is_honoured_and_capped(sleeps):
    handler = _sequence(httpx.Response(429, headers={"Retry-After": "2"}),
                        httpx.Response(429, headers={"Retry-After": "86400"}),
                        httpx.Response(200))
    resp = base.request_with_retry(_client(handler), "GET", "https://x.test/a", max_attempts=3)
    assert resp.status_code == 200
    assert sleeps == [2.0, base.RETRY_AFTER_CAP]


def test_retry_after_http_date_and_garbage():
    assert base.parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0  # in the past
    assert base.parse_retry_after("nonsense") is None
    assert base.parse_retry_after(None) is None
    assert base.parse_retry_after("-5") == 0.0


def test_connect_errors_and_timeouts_retry_for_idempotent(sleeps):
    handler = _sequence(httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), httpx.Response(200))
    resp = base.request_with_retry(_client(handler), "GET", "https://x.test/a")
    assert resp.status_code == 200 and base.attempts_of(resp) == 3


def test_final_exception_is_raised_with_attempt_count(sleeps):
    handler = _sequence(httpx.ConnectError("refused"))
    with pytest.raises(httpx.ConnectError) as info:
        base.request_with_retry(_client(handler), "GET", "https://x.test/a", max_attempts=3)
    assert base.attempts_of(info.value) == 3 and len(handler.calls) == 3


def test_non_idempotent_never_retries_after_read_timeout(sleeps):
    handler = _sequence(httpx.ReadTimeout("slow"), httpx.Response(200))
    with pytest.raises(httpx.ReadTimeout) as info:
        base.request_with_retry(_client(handler), "PUT", "https://x.test/a", idempotent=False)
    assert len(handler.calls) == 1 and base.attempts_of(info.value) == 1 and sleeps == []


def test_non_idempotent_retries_connect_error(sleeps):
    handler = _sequence(httpx.ConnectError("refused"), httpx.Response(200))
    resp = base.request_with_retry(_client(handler), "PUT", "https://x.test/a", idempotent=False)
    assert resp.status_code == 200 and len(handler.calls) == 2


def test_non_idempotent_retries_503_only_with_retry_after(sleeps):
    handler = _sequence(httpx.Response(503, headers={"Retry-After": "1"}), httpx.Response(200))
    resp = base.request_with_retry(_client(handler), "PUT", "https://x.test/a", idempotent=False)
    assert resp.status_code == 200 and sleeps == [1.0]

    handler = _sequence(httpx.Response(503), httpx.Response(200))
    resp = base.request_with_retry(_client(handler), "PUT", "https://x.test/a", idempotent=False)
    assert resp.status_code == 503 and len(handler.calls) == 1

    handler = _sequence(httpx.Response(502, headers={"Retry-After": "1"}), httpx.Response(200))
    resp = base.request_with_retry(_client(handler), "PUT", "https://x.test/a", idempotent=False)
    assert resp.status_code == 502 and len(handler.calls) == 1  # 502 may have been processed


def test_kwargs_are_passed_through_and_helpers_keep_signatures(sleeps):
    seen = {}

    def handler(request):
        seen["body"] = request.content
        seen["q"] = dict(request.url.params)
        return httpx.Response(200)

    base.request_with_retry(_client(handler), "PUT", "https://x.test/a", params={"a": "1"}, json={"k": "v"})
    assert seen["q"] == {"a": "1"} and b'"k"' in seen["body"]
    # compatible helper signatures other code relies on
    assert base.http_client(verify=True) is not None
    assert base.make_result("a", "t", "p", "live")["status"] == "Success"
