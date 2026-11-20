"""Data model: test cases, guard decisions and outcomes."""

from __future__ import annotations

from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["allow", "deny", "review"]
"""A decision a guard can make, and a label a case can expect."""

Outcome = Literal["allow", "deny", "review", "error"]
"""What actually happened when a case ran. ``error`` means the guard failed to answer."""

VERDICTS: tuple[Verdict, ...] = get_args(Verdict)
OUTCOMES: tuple[Outcome, ...] = get_args(Outcome)


class Case(BaseModel):
    """One labeled test case: a tool call and the decision the guard should make."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    expected: Verdict
    category: str = Field(min_length=1)
    actor: str | None = None
    args: dict[str, Any] | None = None
    context: dict[str, Any] | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    source: str | None = None
    notes: str | None = None


class Decision(BaseModel):
    """What a guard decided for one case."""

    model_config = ConfigDict(frozen=True)

    outcome: Verdict
    reason: str | None = None
    raw: Any = None
