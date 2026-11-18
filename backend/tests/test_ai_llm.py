"""OpenRouter client: request shape, headers, error mapping, retries, and that the key never leaks."""
import json
import logging

import httpx
import pytest

from backend import integration_config
from backend.engine import ai_triage
from backend.integrations import connector_base, llm
from backend.tests.ai_helpers import FAKE_KEY, ai_cfg, completion, fake_openrouter, valid_reply  # noqa: F401


def _client() -> llm.OpenRouterClient:
    return llm.OpenRouterClient(FAKE_KEY, "openai/gpt-6.1-terra")


def _ask(client=None):
    return (client or _client()).chat_json("SYSTEM", "USER", ai_triage.proposal_json_schema())


def test_request_shape_and_headers(fake_openrouter):
    result = _ask()
    assert result.structured_output is True and json.loads(result.content)["verdict"] == "malicious"
    assert result.usage["total_tokens"] == 150 and result.finish_reason == "stop"
    (request,) = fake_openrouter.posts
    assert str(request.url) == "https://openrouter.ai/api/v1/chat/completions"
    assert request.headers["authorization"] == f"Bearer {FAKE_KEY}"
    assert request.headers["x-openrouter-title"] == "Phantom SOAR" and request.headers["x-title"] == "Phantom SOAR"
    body = fake_openrouter.bodies()[0]
    assert body["model"] == "openai/gpt-6.1-terra" and body["temperature"] == 0 and body["stream"] is False
    assert body["max_tokens"] == llm.MAX_TOKENS <= 4000
    assert [m["role"] for m in body["messages"]] == ["system", "user"]
    fmt = body["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["strict"] is True
    assert fmt["json_schema"]["schema"]["additionalProperties"] is False
    assert body["provider"] == {"require_parameters": True}
    assert "tools" not in body and "tool_choice" not in body  # the model can never call tools


def test_schema_falls_back_to_json_object_once(fake_openrouter):
    fake_openrouter.queue.append(httpx.Response(400, json={"error": {"code": 400, "message": "response_format unsupported"}}))
    result = _ask()
    assert result.structured_output is False
    first, second = fake_openrouter.bodies()
    assert first["response_format"]["type"] == "json_schema"
    assert second["response_format"] == {"type": "json_object"} and "provider" not in second


def test_fallback_that_also_fails_raises_and_stops(fake_openrouter):
    fake_openrouter.status = 404
    fake_openrouter.reply = {"error": {"code": 404, "message": "No endpoints found"}}
    with pytest.raises(llm.LLMBadRequest):
        _ask()
    assert len(fake_openrouter.posts) == 2  # schema attempt + exactly one fallback


@pytest.mark.parametrize("status,exc", [(401, llm.LLMAuthError), (402, llm.LLMInsufficientCredits), (403, llm.LLMForbidden),
                                         (429, llm.LLMRateLimited), (502, llm.LLMUnavailable), (408, llm.LLMTimeout)])
def test_http_errors_map_to_safe_exceptions(fake_openrouter, status, exc):
    fake_openrouter.status = status
    fake_openrouter.reply = {"error": {"code": status, "message": f"echo {FAKE_KEY} secret detail"}}
    with pytest.raises(exc) as info:
        _ask()
    assert info.value.http_status == status
    assert FAKE_KEY not in str(info.value) and FAKE_KEY not in (info.value.upstream_hint or "")
    assert str(info.value) == info.value.safe_message
    assert exc.retryable == (status in (429, 502, 408))


def test_error_inside_http_200_is_an_error(fake_openrouter):
    fake_openrouter.reply = {"error": {"code": 402, "message": "Insufficient credits"}}
    with pytest.raises(llm.LLMInsufficientCredits):
        _ask()


@pytest.mark.parametrize("payload", [["not", "an", "object"], {"choices": []}, {"choices": [{"message": {"content": None}}]},
                                     {"choices": [{"message": {"content": ["parts"]}}]}])
def test_unreadable_responses(fake_openrouter, payload):
    fake_openrouter.reply = payload
    with pytest.raises(llm.LLMBadResponse):
        _ask()


def test_non_json_and_oversized_responses(fake_openrouter):
    fake_openrouter.queue.append(httpx.Response(200, content=b"<html>gateway</html>"))
    with pytest.raises(llm.LLMBadResponse):
        _ask()
    fake_openrouter.queue.append(httpx.Response(200, content=b" " * (llm.MAX_RESPONSE_BYTES + 10)))
    with pytest.raises(llm.LLMBadResponse):
        _ask()


def test_read_timeout_is_never_resent(fake_openrouter):
    fake_openrouter.queue.append(httpx.ReadTimeout("slow"))
    with pytest.raises(llm.LLMTimeout):
        _ask()
    assert len(fake_openrouter.posts) == 1  # a request that may have been billed is not blindly repeated


def test_connect_error_and_429_with_retry_after_are_retried_once(fake_openrouter):
    # attempt 1: connect error (nothing was sent) -> retried; attempt 2: 429 + Retry-After, but attempts are used up
    fake_openrouter.queue.extend([httpx.ConnectError("down"), httpx.Response(429, headers={"Retry-After": "2"}, json={})])
    with pytest.raises(llm.LLMRateLimited) as info:
        _ask()
    assert info.value.retry_after == 2.0 and len(fake_openrouter.posts) == 2

    fake_openrouter.requests.clear()
    fake_openrouter.queue.extend([httpx.Response(429, headers={"Retry-After": "1"}, json={}),
                                  httpx.Response(200, json=completion(valid_reply()))])
    assert _ask().content and len(fake_openrouter.posts) == 2


def test_503_without_retry_after_is_not_resent_by_the_retry_layer(fake_openrouter):
    fake_openrouter.status = 503
    fake_openrouter.reply = {"error": {"code": 503, "message": "no provider"}}
    with pytest.raises(llm.LLMUnavailable):
        _ask()
    # one request per response_format form (schema, then the json_object fallback), nothing more
    assert [b["response_format"]["type"] for b in fake_openrouter.bodies()] == ["json_schema", "json_object"]


def test_network_failure_message_is_generic(fake_openrouter):
    fake_openrouter.queue.extend([httpx.ConnectError(f"boom {FAKE_KEY}")] * 2)
    with pytest.raises(llm.LLMUnavailable) as info:
        _ask()
    assert FAKE_KEY not in str(info.value) and "boom" not in str(info.value)


def test_key_is_never_logged_or_in_repr(fake_openrouter, caplog):
    caplog.set_level(logging.DEBUG)
    fake_openrouter.status = 401
    fake_openrouter.reply = {"error": {"code": 401, "message": f"bad {FAKE_KEY}"}}
    client = _client()
    with pytest.raises(llm.LLMAuthError):
        _ask(client)
    assert FAKE_KEY not in caplog.text and FAKE_KEY not in repr(client) and FAKE_KEY not in str(vars(llm.LLMAuthError()))


def test_missing_key_and_model_slug_rules(ai_cfg):
    ai_cfg["openrouter_api_key"] = ""
    with pytest.raises(llm.LLMNotConfigured):
        llm.load_client()
    with pytest.raises(llm.LLMNotConfigured):
        llm.OpenRouterClient("  ", "a/b")
    ai_cfg["openrouter_api_key"] = FAKE_KEY
    ai_cfg["openrouter_model"] = "not a slug"
    assert llm.load_client().model == llm.DEFAULT_MODEL  # an invalid stored slug never reaches the API
    ai_cfg["openrouter_model"] = "anthropic/claude-3.5-sonnet"
    assert llm.load_client().model == "anthropic/claude-3.5-sonnet"
    for good in ("openai/gpt-6.1-terra", "liquid/lfm-3-1.7b:free", "~deepseek/deepseek-pro-latest", "openrouter/auto"):
        assert llm.is_valid_model_slug(good), good
    for bad in ("", "gpt", "a/b c", "a/b;rm", "/x", "a//b", "x" * 300 + "/y", "https://x/y"):
        assert not llm.is_valid_model_slug(bad), bad


def test_default_model_is_consistent():
    assert integration_config.DEFAULTS["openrouter_model"] == llm.DEFAULT_MODEL
    assert llm.is_valid_model_slug(llm.DEFAULT_MODEL)


def test_check_key_is_read_only_and_hides_label(fake_openrouter):
    info = _client().check_key()
    (request,) = fake_openrouter.requests
    assert request.method == "GET" and request.url.path == "/api/v1/key" and not request.content
    assert "label" not in info and info["usage"] == 0.5
    fake_openrouter.status = 401
    fake_openrouter.key_info = {"error": {"code": 401, "message": "No auth"}}
    with pytest.raises(llm.LLMAuthError):
        _client().check_key()
