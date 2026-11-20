from __future__ import annotations

import json

import pytest
from pytest_httpx import HTTPXMock

from lelu_eval.adapters.base import GuardConfigError, GuardError
from lelu_eval.adapters.generic_http import GenericHttpGuard
from tests.conftest import CaseFactory

URL = "http://guard.test/check"


def test_posts_case_json_without_unset_fields(
    httpx_mock: HTTPXMock, make_case: CaseFactory
) -> None:
    httpx_mock.add_response(url=URL, method="POST", json={"decision": "allow"})
    GenericHttpGuard(URL).decide(make_case(args={"path": "a.txt"}))
    request = httpx_mock.get_request()
    assert request is not None
    assert json.loads(request.content) == {
        "id": "c1",
        "action": "read_file",
        "expected": "allow",
        "category": "benign",
        "args": {"path": "a.txt"},
    }


@pytest.mark.parametrize(
    ("value", "outcome"), [("allow", "allow"), (" DENY ", "deny"), ("Review", "review")]
)
def test_reads_decision_field(
    httpx_mock: HTTPXMock, make_case: CaseFactory, value: str, outcome: str
) -> None:
    httpx_mock.add_response(url=URL, json={"decision": value, "reason": "because"})
    decision = GenericHttpGuard(URL).decide(make_case())
    assert decision.outcome == outcome
    assert decision.reason == "because"


def test_custom_decision_field(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_response(url=URL, json={"verdict": "deny", "decision": "allow"})
    assert GenericHttpGuard(URL, decision_field="verdict").decide(make_case()).outcome == "deny"


def test_missing_decision_field(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_response(url=URL, json={"result": "allow"})
    with pytest.raises(GuardError, match="no 'decision' field"):
        GenericHttpGuard(URL).decide(make_case())


@pytest.mark.parametrize("value", ["block", True, None, 1])
def test_unknown_decision_value(
    httpx_mock: HTTPXMock, make_case: CaseFactory, value: object
) -> None:
    httpx_mock.add_response(url=URL, json={"decision": value})
    with pytest.raises(GuardError, match="expected one of allow, deny, review"):
        GenericHttpGuard(URL).decide(make_case())


def test_json_array_response(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_response(url=URL, json=["allow"])
    with pytest.raises(GuardError, match="not an object"):
        GenericHttpGuard(URL).decide(make_case())


def test_unauthorized_is_config_error(httpx_mock: HTTPXMock, make_case: CaseFactory) -> None:
    httpx_mock.add_response(url=URL, status_code=401)
    with pytest.raises(GuardConfigError):
        GenericHttpGuard(URL).decide(make_case())
