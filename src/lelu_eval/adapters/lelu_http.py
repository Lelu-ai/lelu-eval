"""Adapter for the Lelu engine's HTTP authorize endpoint."""

from __future__ import annotations

import os
from typing import Any

import httpx

from lelu_eval.adapters._http import post_json
from lelu_eval.adapters.base import GuardError
from lelu_eval.schema import Case, Decision

DEFAULT_BASE_URL = "http://localhost:8080"
DEFAULT_TIMEOUT = 10.0
API_KEY_ENV = "LELU_API_KEY"
AUTHORIZE_PATH = "/v1/agent/authorize"


class LeluGuard:
    """Sends each case to ``POST {base_url}/v1/agent/authorize``."""

    name = "lelu"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.Client | None = None,
    ) -> None:
        self.url = base_url.rstrip("/") + AUTHORIZE_PATH
        self.timeout = timeout
        key = api_key if api_key is not None else os.environ.get(API_KEY_ENV)
        self._headers = {"Authorization": f"Bearer {key}"} if key else {}
        self._client = client or httpx.Client()

    def decide(self, case: Case) -> Decision:
        data = post_json(
            self._client, self.url, build_request(case), timeout=self.timeout, headers=self._headers
        )
        return map_response(data)


def build_request(case: Case) -> dict[str, Any]:
    """Build the authorize request body, leaving out fields the case does not set."""
    body: dict[str, Any] = {
        "actor": case.actor,
        "action": case.action,
        "confidence": case.confidence,
        "args": case.args,
        "resource": case.context,
    }
    return {key: value for key, value in body.items() if value is not None}


def map_response(data: dict[str, Any]) -> Decision:
    """Map a Lelu authorize response to a decision.

    Order: ``requires_human_review`` -> review; ``compute`` -> allow (noted in the
    reason); otherwise ``allowed`` decides allow or deny.
    """
    reason = data.get("reason") if isinstance(data.get("reason"), str) else None
    if _flag(data, "requires_human_review"):
        return Decision(outcome="review", reason=reason, raw=data)
    if _flag(data, "compute"):
        note = "compute=true, treated as allow"
        return Decision(outcome="allow", reason=f"{note}: {reason}" if reason else note, raw=data)
    allowed = data.get("allowed")
    if not isinstance(allowed, bool):
        raise GuardError(f"Lelu response has no boolean 'allowed' field: {data!r}")
    return Decision(outcome="allow" if allowed else "deny", reason=reason, raw=data)


def _flag(data: dict[str, Any], key: str) -> bool:
    value = data.get(key, False)
    if value is None:
        return False
    if not isinstance(value, bool):
        raise GuardError(f"Lelu response field {key!r} should be true or false, got {value!r}")
    return value
