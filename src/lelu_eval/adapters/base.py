"""The Guard protocol every adapter implements, and the errors adapters raise."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from lelu_eval.schema import VERDICTS, Case, Decision, Verdict


class GuardError(Exception):
    """The guard failed to answer one case (timeout, crash, bad response).

    The runner records the case as ``error`` and continues with the next case.
    """


class GuardConfigError(Exception):
    """The guard cannot be used at all (bad credentials, unreachable, missing command).

    The runner stops and the CLI exits with code 2. Never counted as a decision.
    """


@runtime_checkable
class Guard(Protocol):
    """Anything that can decide whether an agent tool call should run."""

    name: str

    def decide(self, case: Case) -> Decision: ...


def parse_verdict(value: object, *, source: str) -> Verdict:
    """Turn a guard's answer such as ``"Deny"`` into a verdict, or raise GuardError."""
    if isinstance(value, str):
        cleaned = value.strip().lower()
        for verdict in VERDICTS:
            if cleaned == verdict:
                return verdict
    raise GuardError(f"{source}: expected one of allow, deny, review; got {value!r}")
