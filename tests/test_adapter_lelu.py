from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pytest_httpx import HTTPXMock

from lelu_eval.adapters.base import Guard, GuardConfigError, GuardError
from lelu_eval.adapters.lelu_http import LeluGuard, build_request, map_response
from tests.conftest import CaseFactory

URL = "http://lelu.test/v1/agent/authorize"


def _guard(**kwargs: Any) -> LeluGuard:
    kwargs.setdefault("api_key", "secret-key")
    return LeluGuard(base_url="http://lelu.test/", **kwargs)


def test_satisfies_guard_protocol() -> None:
    assert isinstance(_guard(), Guard)


def test_request_body_and_auth_header(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_response(url=URL, method="POST", json={"allowed": True})
    case = make_case(
        actor="invoice_bot",
        action="approve_refunds",
        args={"amount": 5000},
        context={"note": "hi"},
        confidence=0.95,
    )
    _guard().decide(case)
    request = httpx_mock.get_request()
    assert request is not None
    assert request.headers["Authorization"] == "Bearer secret-key"
    assert json.loads(request.content) == {
        "actor": "invoice_bot",
        "action": "approve_refunds",
        "confidence": 0.95,
        "args": {"amount": 5000},
        "resource": {"note": "hi"},
    }


def test_unset_fields_are_omitted(make_case: CaseFactory) -> None:
    assert build_request(make_case(action="ls")) == {"action": "ls"}


def test_empty_args_are_sent_when_set(make_case: CaseFactory) -> None:
    assert build_request(make_case(action="ls", args={})) == {"action": "ls", "args": {}}


def test_api_key_from_environment(
    httpx_mock: HTTPXMock, make_case: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LELU_API_KEY", "from-env")
    httpx_mock.add_response(url=URL, json={"allowed": False})
    LeluGuard(base_url="http://lelu.test").decide(make_case())
    request = httpx_mock.get_request()
    assert request is not None
    assert request.headers["Authorization"] == "Bearer from-env"


def test_no_auth_header_without_key(
    httpx_mock: HTTPXMock, make_case: CaseFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LELU_API_KEY", raising=False)
    httpx_mock.add_response(url=URL, json={"allowed": True})
    LeluGuard(base_url="http://lelu.test").decide(make_case())
    request = httpx_mock.get_request()
    assert request is not None
    assert "Authorization" not in request.headers


@pytest.mark.parametrize(
    ("response", "outcome", "reason"),
    [
        ({"allowed": True, "reason": "ok"}, "allow", "ok"),
        ({"allowed": False, "reason": "policy"}, "deny", "policy"),
        ({"allowed": False, "requires_human_review": True}, "review", None),
        # review wins even when allowed or compute is also true
        ({"allowed": True, "requires_human_review": True, "compute": True}, "review", None),
        ({"allowed": False, "compute": True}, "allow", "compute=true, treated as allow"),
        (
            {"allowed": False, "compute": True, "reason": "sandbox"},
            "allow",
            "compute=true, treated as allow: sandbox",
        ),
        ({"allowed": True, "compute": None, "requires_human_review": None}, "allow", None),
    ],
)
def test_response_mapping(response: dict[str, Any], outcome: str, reason: str | None) -> None:
    decision = map_response(response)
    assert decision.outcome == outcome
    assert decision.reason == reason
    assert decision.raw == response


@pytest.mark.parametrize(
    "response",
    [{}, {"allowed": "yes"}, {"allowed": True, "compute": "true"}, {"reason": "x"}],
)
def test_malformed_response_is_guard_error(response: dict[str, Any]) -> None:
    with pytest.raises(GuardError):
        map_response(response)


def test_review_id_and_trace_id_kept_in_raw(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    body = {"allowed": False, "requires_human_review": True, "review_id": "r1", "trace_id": "t1"}
    httpx_mock.add_response(url=URL, json=body)
    assert _guard().decide(make_case()).raw == body


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failure_is_config_error(
    httpx_mock: HTTPXMock, make_case: CaseFactory, status: int
) -> None:
    httpx_mock.add_response(url=URL, status_code=status, json={"error": "nope"})
    with pytest.raises(GuardConfigError, match=f"HTTP {status}.*LELU_API_KEY"):
        _guard().decide(make_case())


def test_server_error_is_guard_error(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_response(url=URL, status_code=500, text="boom")
    with pytest.raises(GuardError, match="HTTP 500: boom"):
        _guard().decide(make_case())


def test_non_json_is_guard_error(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_response(url=URL, text="<html>")
    with pytest.raises(GuardError, match="not JSON"):
        _guard().decide(make_case())


def test_timeout_is_guard_error(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_exception(httpx.ReadTimeout("slow"), url=URL)
    with pytest.raises(GuardError, match=r"timed out after 2\.5s"):
        _guard(timeout=2.5).decide(make_case())


def test_connection_refused_is_config_error(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_exception(httpx.ConnectError("refused"), url=URL)
    with pytest.raises(GuardConfigError, match="cannot connect"):
        _guard().decide(make_case())
