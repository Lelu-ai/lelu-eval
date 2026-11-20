"""Adapter for any guard that answers an HTTP POST with a JSON decision."""

from __future__ import annotations

import httpx

from lelu_eval.adapters._http import post_json
from lelu_eval.adapters.base import GuardError, parse_verdict
from lelu_eval.schema import Case, Decision

DEFAULT_DECISION_FIELD = "decision"
DEFAULT_TIMEOUT = 10.0


class GenericHttpGuard:
    """POSTs the case as JSON to ``url`` and reads the decision from ``decision_field``.

    The response must be a JSON object. Its ``decision_field`` must hold ``allow``,
    ``deny`` or ``review``. A string ``reason`` field, if present, is kept.
    """

    name = "http"

    def __init__(
        self,
        url: str,
        decision_field: str = DEFAULT_DECISION_FIELD,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.Client | None = None,
    ) -> None:
        self.url = url
        self.decision_field = decision_field
        self.timeout = timeout
        self._client = client or httpx.Client()

    def decide(self, case: Case) -> Decision:
        body = case.model_dump(mode="json", exclude_none=True)
        data = post_json(self._client, self.url, body, timeout=self.timeout)
        if self.decision_field not in data:
            raise GuardError(
                f"response from {self.url} has no {self.decision_field!r} field "
                f"(set --decision-field): {data!r}"
            )
        outcome = parse_verdict(data[self.decision_field], source=f"field {self.decision_field!r}")
        reason = data.get("reason")
        return Decision(
            outcome=outcome, reason=reason if isinstance(reason, str) else None, raw=data
        )
