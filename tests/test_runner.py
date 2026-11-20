from __future__ import annotations

import pytest

from lelu_eval.adapters.base import GuardConfigError, GuardError
from lelu_eval.runner import CaseResult, run_cases
from lelu_eval.schema import Case, Decision
from tests.conftest import CaseFactory


class ScriptedGuard:
    """Returns a fixed answer per case id; raises if the answer is an exception."""

    name = "scripted"

    def __init__(self, answers: dict[str, Decision | Exception]) -> None:
        self.answers = answers
        self.seen: list[str] = []

    def decide(self, case: Case) -> Decision:
        self.seen.append(case.id)
        answer = self.answers[case.id]
        if isinstance(answer, Exception):
            raise answer
        return answer


def test_records_decisions_and_errors(make_case: CaseFactory) -> None:
    cases = [make_case(id=i) for i in ("ok", "guard-err", "bug")]
    guard = ScriptedGuard(
        {
            "ok": Decision(outcome="deny", reason="rule 1"),
            "guard-err": GuardError("timed out"),
            "bug": KeyError("x"),
        }
    )
    seen: list[CaseResult] = []
    results = run_cases(guard, cases, on_result=seen.append)
    assert [(r.case.id, r.actual, r.explanation) for r in results] == [
        ("ok", "deny", "rule 1"),
        ("guard-err", "error", "timed out"),
        ("bug", "error", "KeyError: 'x'"),
    ]
    assert seen == results
    assert results[1].decision is None


def test_config_error_stops_the_run(make_case: CaseFactory) -> None:
    cases = [make_case(id="a"), make_case(id="b"), make_case(id="c")]
    guard = ScriptedGuard(
        {
            "a": Decision(outcome="allow"),
            "b": GuardConfigError("HTTP 401"),
            "c": Decision(outcome="allow"),
        }
    )
    with pytest.raises(GuardConfigError, match="401"):
        run_cases(guard, cases)
    assert guard.seen == ["a", "b"]


def test_error_is_never_correct(make_case: CaseFactory) -> None:
    for expected in ("allow", "deny", "review"):
        result = CaseResult(case=make_case(expected=expected), actual="error", error="x")
        assert not result.correct


def test_correct_when_actual_matches_expected(make_case: CaseFactory) -> None:
    assert CaseResult(case=make_case(expected="review"), actual="review").correct
    assert not CaseResult(case=make_case(expected="review"), actual="deny").correct
