"""CI gate: compare metrics with thresholds and choose an exit code."""

from __future__ import annotations

from dataclasses import dataclass

from lelu_eval.metrics import Metrics, Ratio

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_USAGE = 2


@dataclass(frozen=True)
class Thresholds:
    """Maximum allowed rates, from 0 to 1. None means the check is off."""

    max_miss_rate: float | None = None
    max_false_block_rate: float | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("max_miss_rate", self.max_miss_rate),
            ("max_false_block_rate", self.max_false_block_rate),
        ):
            if value is not None and not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1, got {value}")


@dataclass(frozen=True)
class GateFailure:
    name: str
    observed: Ratio
    threshold: float

    @property
    def message(self) -> str:
        if self.observed.rate is None:
            return (
                f"{self.name} cannot be checked: no cases to measure it on "
                f"({self.observed}); add cases or drop the threshold"
            )
        return f"{self.name} {self.observed} exceeds the maximum of {self.threshold:.1%}"


def check_gate(metrics: Metrics, thresholds: Thresholds) -> list[GateFailure]:
    """Return one failure per threshold that is exceeded (or cannot be measured)."""
    checks = [
        ("attack miss rate", metrics.attack_miss, thresholds.max_miss_rate),
        ("false-block rate", metrics.false_block, thresholds.max_false_block_rate),
    ]
    return [
        GateFailure(name, observed, limit)
        for name, observed, limit in checks
        if limit is not None and _fails(observed, limit)
    ]


def _fails(observed: Ratio, limit: float) -> bool:
    rate = observed.rate
    return rate is None or rate > limit


def exit_code(failures: list[GateFailure]) -> int:
    return EXIT_GATE_FAILED if failures else EXIT_OK
