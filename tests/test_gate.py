from __future__ import annotations

import pytest

from lelu_eval.gate import (
    EXIT_GATE_FAILED,
    EXIT_OK,
    GateFailure,
    Thresholds,
    check_gate,
    exit_code,
)
from lelu_eval.metrics import Ratio, compute_metrics
from tests.test_metrics import RESULTS, result

# RESULTS: attack miss 2 of 5 (40%), false block 2 of 5 (40%)
METRICS = compute_metrics(RESULTS)


def _names(thresholds: Thresholds) -> list[str]:
    return [f.name for f in check_gate(METRICS, thresholds)]


def test_no_thresholds_always_passes() -> None:
    assert check_gate(METRICS, Thresholds()) == []
    assert exit_code([]) == EXIT_OK


def test_miss_rate_exceeded() -> None:
    assert _names(Thresholds(max_miss_rate=0.39)) == ["attack miss rate"]


def test_rate_equal_to_threshold_passes() -> None:
    assert _names(Thresholds(max_miss_rate=0.4, max_false_block_rate=0.4)) == []


def test_false_block_rate_exceeded() -> None:
    assert _names(Thresholds(max_false_block_rate=0.05)) == ["false-block rate"]


def test_both_exceeded_gives_exit_1() -> None:
    failures = check_gate(METRICS, Thresholds(max_miss_rate=0.0, max_false_block_rate=0.0))
    assert [f.name for f in failures] == ["attack miss rate", "false-block rate"]
    assert exit_code(failures) == EXIT_GATE_FAILED


def test_failure_message_shows_denominator() -> None:
    [failure] = check_gate(METRICS, Thresholds(max_miss_rate=0.05))
    assert failure.message == "attack miss rate 2 of 5 (40.0%) exceeds the maximum of 5.0%"


def test_unmeasurable_rate_fails_with_explanation() -> None:
    only_benign = compute_metrics([result("b", "allow", "allow", "benign")])
    [failure] = check_gate(only_benign, Thresholds(max_miss_rate=0.05))
    assert failure == GateFailure("attack miss rate", Ratio(0, 0), 0.05)
    assert "cannot be checked" in failure.message


@pytest.mark.parametrize("bad", [-0.1, 1.5])
def test_threshold_must_be_a_fraction(bad: float) -> None:
    with pytest.raises(ValueError, match="between 0 and 1"):
        Thresholds(max_miss_rate=bad)
