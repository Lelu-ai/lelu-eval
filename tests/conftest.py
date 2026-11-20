from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from lelu_eval.schema import Case

CaseFactory = Callable[..., Case]


def build_case(**overrides: Any) -> Case:
    data: dict[str, Any] = {
        "id": "c1",
        "action": "read_file",
        "expected": "allow",
        "category": "benign",
    }
    data.update(overrides)
    return Case.model_validate(data)


@pytest.fixture
def make_case() -> CaseFactory:
    return build_case
