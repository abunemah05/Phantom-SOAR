"""OpenRouter client for the built-in AI triage (OpenAI-compatible chat completions).

Verified against the current OpenRouter documentation (checked 2026-11-18):

* Base URL, bearer authentication and the optional app-attribution headers
  https://openrouter.ai/docs/api-reference/overview
    - base URL ``https://openrouter.ai/api/v1``, endpoint ``POST /chat/completions``
    - ``Authorization: Bearer <key>``
    - optional ``HTTP-Referer`` (identifies the app) and ``X-OpenRouter-Title`` (``X-Title`` is also accepted)
    - request fields used here: ``model``, ``messages``, ``max_tokens``, ``temperature``, ``response_format``
    - response: ``choices[0].message.content`` (string), ``choices[0].finish_reason``, ``usage`` and ``model``
* JSON output  https://openrouter.ai/docs/features/structured-outputs
    - ``response_format = {"type": "json_schema", "json_schema": {"name", "strict": true, "schema"}}``
    - support is decided per endpoint, so ``provider.require_parameters = true`` routes only to endpoints that
      support the request; a model without support answers with an error. The overview page also documents
      ``{"type": "json_object"}``, which this client uses as ONE fallback request when the schema form is refused.
* Errors  https://openrouter.ai/docs/api-reference/errors
    - body ``{"error": {"code": int, "message": str, "metadata"?: {...}}}``; HTTP 400 invalid request, 401 invalid or
      disabled key, 402 insufficient credits, 403 forbidden (permission / guardrail / moderation), 408 timeout,
      429 rate limited, 502 model down or invalid upstream response, 503 no provider meets the routing requirements
    - a 200 response may still carry a top-level ``error`` object and no ``choices``: that is checked too
* Key check  https://openrouter.ai/docs/api-reference/limits
    - ``GET /api/v1/key`` (bearer key, read-only, no credits spent) returns ``{"data": {"label", "limit",
      "limit_remaining", "usage", "is_free_tier", ...}}``; it is used for the Configuration page "Test" button.
* Models  https://openrouter.ai/docs/api-reference/list-available-models
    - ``GET /api/v1/models?supported_parameters=structured_outputs`` lists models whose endpoints accept
      structured outputs; the default model below was confirmed in that list (see DEFAULT_MODEL).

Safety properties of this module:

* The API key is only ever placed in the Authorization header. It is never logged, never part of an exception
  message and never returned by any function here (the client's repr hides it).
* The base URL is a constant: it cannot be redirected to another host, and redirects are not followed, so the
  Authorization header can never be forwarded elsewhere.
* Requests are NOT idempotent (they cost money): connector_base.request_with_retry(idempotent=False) retries only
  connection failures and 429/503 answers that carry Retry-After; a read timeout is never blindly re-sent.
* Hard timeouts, a response size cap and a ``max_tokens`` cap bound time and cost.
* Every failure is mapped to a small exception hierarchy whose ``str()`` is a safe, generic message.
"""
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx

from backend import integration_config
from backend.integrations import connector_base

logger = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
CHAT_COMPLETIONS_PATH = "/chat/completions"
KEY_INFO_PATH = "/key"

# Confirmed present on 2026-11-18 via GET /api/v1/models?supported_parameters=structured_outputs and
# GET /api/v1/models/openai/gpt-6.1-terra/endpoints (all endpoints list "structured_outputs" and "response_format").
# Mid-priced ($0.5-1 per million input tokens) and 1M context. It is only a default: the operator can set
# any slug (OPENROUTER_MODEL / Configuration page) and should re-check it against https://openrouter.ai/models.
DEFAULT_MODEL = "openai/gpt-6.1-terra"

APP_TITLE = "Phantom SOAR"
MAX_TOKENS = 1500            # cost cap for one triage answer (a proposal is a few hundred tokens)
MAX_RESPONSE_BYTES = 1_000_000
MAX_ATTEMPTS = 2             # the first request plus one retry (contract: "one retry")
REQUEST_TIMEOUT = httpx.Timeout(45.0, connect=5.0, write=10.0, pool=5.0)
KEY_CHECK_TIMEOUT = httpx.Timeout(10.0, connect=5.0)

# Slugs look like "vendor/model", "vendor/model:variant" or "~vendor/alias" (rolling alias).
MODEL_SLUG_RE = re.compile(r"^~?[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")


def is_valid_model_slug(value: str) -> bool:
    return bool(MODEL_SLUG_RE.match(value or ""))


# --- Errors ------------------------------------------------------------------------------------

class LLMError(Exception):
    """Base class. ``str(exc)`` is always a safe, generic message (no key, prompt or response body)."""

    kind = "error"
    retryable = False
    default_message = "The AI model request failed."

    def __init__(self, message: Optional[str] = None, *, http_status: Optional[int] = None,
                 upstream_hint: Optional[str] = None, retry_after: Optional[float] = None):
        super().__init__(message or self.default_message)
        self.safe_message = message or self.default_message
        self.http_status = http_status
        self.upstream_hint = upstream_hint  # sanitised provider text, for the audit log only
        self.retry_after = retry_after


class LLMNotConfigured(LLMError):
    kind = "not_configured"
    default_message = "No OpenRouter API key is configured."


class LLMAuthError(LLMError):
    kind = "auth"
    default_message = "OpenRouter rejected the API key (HTTP 401). Check the key on the Configuration page."


class LLMInsufficientCredits(LLMError):
    kind = "credits"
    default_message = "OpenRouter reports insufficient credits for this key (HTTP 402). Add credits and try again."


class LLMForbidden(LLMError):
    kind = "forbidden"
    default_message = "OpenRouter refused the request (HTTP 403: key permission, guardrail or moderation)."


class LLMBadRequest(LLMError):
    kind = "bad_request"
    default_message = "OpenRouter rejected the request (HTTP 400/404). Check the model name on the Configuration page."


class LLMRateLimited(LLMError):
    kind = "rate_limited"
    retryable = True
    default_message = "OpenRouter is rate limiting this key (HTTP 429). Try again shortly."


class LLMTimeout(LLMError):
    kind = "timeout"
    retryable = True
    default_message = "The AI model did not answer in time."


class LLMUnavailable(LLMError):
    kind = "unavailable"
    retryable = True
    default_message = "OpenRouter or the selected model is temporarily unavailable."


class LLMBadResponse(LLMError):
    kind = "bad_response"
    retryable = True
    default_message = "OpenRouter returned a response that could not be read."


_STATUS_ERRORS = {
    400: LLMBadRequest, 404: LLMBadRequest, 401: LLMAuthError, 402: LLMInsufficientCredits, 403: LLMForbidden,
    408: LLMTimeout, 429: LLMRateLimited, 502: LLMUnavailable, 503: LLMUnavailable, 504: LLMUnavailable,
}


def _sanitise_hint(text: Any, api_key: str = "") -> Optional[str]:
    """Short provider message for the audit log: no key, no credentials, no newlines, at most 200 characters."""
    if not isinstance(text, str) or not text.strip():
        return None
    from backend.security import mask_text

    hint = text.replace("\r", " ").replace("\n", " ")
    if api_key:
        hint = hint.replace(api_key, "[REDACTED]")
    return mask_text(hint)[:200]


def error_for_status(status: int, body: Any = None, retry_after: Optional[float] = None, api_key: str = "") -> LLMError:
    """Map an HTTP status (or an in-body ``error.code``) to the matching exception."""
    cls = _STATUS_ERRORS.get(status)
    if cls is None:
        cls = LLMUnavailable if status >= 500 else LLMError
    hint = None
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        hint = _sanitise_hint(body["error"].get("message"), api_key)
    return cls(http_status=status, upstream_hint=hint, retry_after=retry_after)


# --- Result ------------------------------------------------------------------------------------

@dataclass
class LLMResult:
    content: str
    model: str
    finish_reason: Optional[str] = None
    usage: Dict[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None
    attempts: int = 1
    structured_output: bool = True   # False when the json_object fallback had to be used


def make_http_client(timeout: httpx.Timeout = REQUEST_TIMEOUT) -> httpx.Client:
    """Factory for the outbound client (tests replace it with a MockTransport client). Redirects are never followed."""
    return httpx.Client(timeout=timeout, follow_redirects=False)


def _retry_after_seconds(response: httpx.Response) -> Optional[float]:
    return connector_base.parse_retry_after(response.headers.get("Retry-After"))


def _json_body(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


class OpenRouterClient:
    """Minimal OpenRouter chat-completions client. One instance per call site; holds the key privately."""

    def __init__(self, api_key: str, model: str, *, max_tokens: int = MAX_TOKENS, referer: Optional[str] = None):
        if not (api_key or "").strip():
            raise LLMNotConfigured()
        self._api_key = api_key.strip()
        self.model = (model or "").strip() or DEFAULT_MODEL
        self.max_tokens = max(1, min(int(max_tokens), 4000))
        self._referer = referer

    def __repr__(self) -> str:  # never show the key
        return f"OpenRouterClient(model={self.model!r})"

    # -- request building --------------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-OpenRouter-Title": APP_TITLE,
            "X-Title": APP_TITLE,
        }
        if self._referer:
            headers["HTTP-Referer"] = self._referer
        return headers

    def _body(self, system: str, user: str, json_schema: Optional[Dict[str, Any]], schema_name: str) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "stream": False,
        }
        if json_schema is not None:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "strict": True, "schema": json_schema},
            }
            body["provider"] = {"require_parameters": True}
        else:
            body["response_format"] = {"type": "json_object"}
        return body

    # -- calls -------------------------------------------------------------------------------
    def chat_json(self, system: str, user: str, json_schema: Dict[str, Any], schema_name: str = "triage_proposal") -> LLMResult:
        """Ask for a JSON answer. Tries the strict schema first and, if the model/endpoint refuses that form
        (HTTP 400/404/503), makes one more request with ``json_object``. Raises an LLMError subclass."""
        try:
            return self._post(self._body(system, user, json_schema, schema_name))
        except LLMError as exc:
            if exc.http_status not in (400, 404, 503):
                raise
            logger.info(f"[llm] {self.model}: structured-output request refused (HTTP {exc.http_status}); "
                        "retrying once with json_object.")
        result = self._post(self._body(system, user, None, schema_name))
        result.structured_output = False
        return result

    def _post(self, body: Dict[str, Any]) -> LLMResult:
        url = OPENROUTER_BASE_URL + CHAT_COMPLETIONS_PATH
        try:
            with make_http_client() as client:
                response = connector_base.request_with_retry(
                    client, "POST", url, idempotent=False, max_attempts=MAX_ATTEMPTS,
                    headers=self._headers(), json=body,
                )
        except httpx.TimeoutException:
            raise LLMTimeout() from None
        except httpx.HTTPError:
            raise LLMUnavailable("Could not reach OpenRouter.") from None

        attempts = connector_base.attempts_of(response)
        payload = _json_body(response)
        if response.status_code != 200:
            raise error_for_status(response.status_code, payload, _retry_after_seconds(response), self._api_key)
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise LLMBadResponse("OpenRouter returned an unexpectedly large response.", http_status=200)
        if not isinstance(payload, dict):
            raise LLMBadResponse(http_status=200)

        error = payload.get("error")
        if isinstance(error, dict) and not payload.get("choices"):
            code = error.get("code")
            raise error_for_status(code if isinstance(code, int) else 502, payload, None, self._api_key)

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise LLMBadResponse("OpenRouter returned no completion.", http_status=200)
        first = choices[0]
        message = first.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise LLMBadResponse("The model returned no text content.", http_status=200)
        usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        return LLMResult(
            content=content,
            model=str(payload.get("model") or self.model)[:120],
            finish_reason=first.get("finish_reason") if isinstance(first.get("finish_reason"), str) else None,
            usage={k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens", "cost")
                   if isinstance(usage.get(k), (int, float))},
            request_id=str(payload["id"])[:100] if payload.get("id") else None,
            attempts=attempts,
        )

    def check_key(self) -> Dict[str, Any]:
        """Read-only key check (GET /key): spends no credits and sends no alert data. Raises LLMError on failure."""
        url = OPENROUTER_BASE_URL + KEY_INFO_PATH
        try:
            with make_http_client(KEY_CHECK_TIMEOUT) as client:
                response = connector_base.request_with_retry(
                    client, "GET", url, idempotent=True, max_attempts=2,
                    headers={"Authorization": f"Bearer {self._api_key}", "Accept": "application/json"},
                )
        except httpx.TimeoutException:
            raise LLMTimeout() from None
        except httpx.HTTPError:
            raise LLMUnavailable("Could not reach OpenRouter.") from None
        payload = _json_body(response)
        if response.status_code != 200:
            raise error_for_status(response.status_code, payload, _retry_after_seconds(response), self._api_key)
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise LLMBadResponse(http_status=200)
        # "label" is deliberately left out: OpenRouter labels can embed part of the key.
        return {k: data.get(k) for k in ("limit", "limit_remaining", "usage", "is_free_tier") if k in data}


# --- Settings ----------------------------------------------------------------------------------

def configured_model(db=None) -> str:
    model = integration_config.get_setting("openrouter_model", db=db)
    return model if is_valid_model_slug(model) else DEFAULT_MODEL


def load_client(db=None) -> OpenRouterClient:
    """Client from the stored settings (database value, else OPENROUTER_API_KEY). Raises LLMNotConfigured."""
    key = integration_config.get_setting("openrouter_api_key", db=db)
    if not key:
        raise LLMNotConfigured()
    return OpenRouterClient(key, configured_model(db), referer=None)
