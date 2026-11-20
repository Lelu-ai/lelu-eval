"""Run cases through a guard and collect one result per case."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from lelu_eval.adapters.base import Guard, GuardConfigError, GuardError
from lelu_eval.schema import Case, Decision, Outcome


@dataclass(frozen=True)
class CaseResult:
    """The outcome of running one case. ``decision`` is None when the guard errored."""

    case: Case
    actual: Outcome
    decision: Decision | None = None
    error: str | None = None

    @property
    def correct(self) -> bool:
        return self.actual == self.case.expected

    @property
    def explanation(self) -> str:
        """The guard's reason, or the error message, for display."""
        if self.error is not None:
            return self.error
        if self.decision is not None and self.decision.reason:
            return self.decision.reason
        return ""


def run_case(guard: Guard, case: Case) -> CaseResult:
    """Ask ``guard`` about one case. Errors become an ``error`` result.

    GuardConfigError is re-raised: it means the guard is unusable, so the run must stop.
    """
    try:
        decision = guard.decide(case)
    except GuardConfigError:
        raise
    except GuardError as exc:
        return CaseResult(case=case, actual="error", error=str(exc))
    except Exception as exc:  # an adapter bug must not count as allow or deny
        return CaseResult(case=case, actual="error", error=f"{type(exc).__name__}: {exc}")
    return CaseResult(case=case, actual=decision.outcome, decision=decision)


def run_cases(
    guard: Guard,
    cases: Iterable[Case],
    on_result: Callable[[CaseResult], None] | None = None,
) -> list[CaseResult]:
    """Run every case in order. ``on_result`` is called after each one (for progress)."""
    results: list[CaseResult] = []
    for case in cases:
        result = run_case(guard, case)
        results.append(result)
        if on_result is not None:
            on_result(result)
    return results
