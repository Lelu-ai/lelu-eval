from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from lelu_eval.schema import Case, Decision


def _case(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "c1",
        "action": "read_file",
        "expected": "allow",
        "category": "benign",
    }
    data.update(overrides)
    return data


def test_minimal_case_has_optional_fields_unset() -> None:
    case = Case.model_validate(_case())
    assert case.actor is None
    assert case.args is None
    assert case.context is None
    assert case.confidence is None


def test_full_case_round_trips() -> None:
    data = _case(
        actor="bot",
        args={"path": "/tmp/x"},
        context={"note": "hi"},
        confidence=0.5,
        source="hand-written",
        notes="n",
    )
    assert Case.model_validate(data).model_dump(exclude_none=True) == data


@pytest.mark.parametrize("missing", ["id", "action", "expected", "category"])
def test_required_fields(missing: str) -> None:
    data = _case()
    del data[missing]
    with pytest.raises(ValidationError, match=missing):
        Case.model_validate(data)


@pytest.mark.parametrize("bad", ["error", "block", "ALLOW", ""])
def test_expected_rejects_unknown_values(bad: str) -> None:
    with pytest.raises(ValidationError, match="expected"):
        Case.model_validate(_case(expected=bad))


@pytest.mark.parametrize("value", [0.0, 1.0, 0.42])
def test_confidence_accepts_bounds(value: float) -> None:
    assert Case.model_validate(_case(confidence=value)).confidence == value


@pytest.mark.parametrize("value", [-0.01, 1.01, 5])
def test_confidence_rejects_out_of_range(value: float) -> None:
    with pytest.raises(ValidationError, match="confidence"):
        Case.model_validate(_case(confidence=value))


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError, match="expectd"):
        Case.model_validate(_case(expectd="deny"))


def test_empty_id_rejected() -> None:
    with pytest.raises(ValidationError, match="id"):
        Case.model_validate(_case(id=""))


def test_decision_cannot_be_error() -> None:
    with pytest.raises(ValidationError):
        Decision.model_validate({"outcome": "error"})
