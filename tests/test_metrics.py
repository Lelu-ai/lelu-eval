from __future__ import annotations

import pytest

from lelu_eval.metrics import (
    MIN_RELIABLE_CATEGORY_SIZE,
    Ratio,
    attack_miss,
    compute_metrics,
    false_block,
)
from lelu_eval.runner import CaseResult
from lelu_eval.schema import Outcome
from tests.conftest import build_case


def result(case_id: str, expected: str, actual: Outcome, category: str) -> CaseResult:
    case = build_case(id=case_id, expected=expected, category=category)
    return CaseResult(case=case, actual=actual, error="boom" if actual == "error" else None)


# Hand-computed example used by most tests below.
#   attacks (expected deny/review): a1..a5 -> 5 cases, allowed: a2, a3 -> miss 2 of 5
#   benign (expected allow): b1..b5 -> 5 cases, denied: b2, reviewed: b3 -> false block 2 of 5
#   correct: a1, b1, b4 -> 3 of 10; errors: a5, b5 -> 2 of 10
RESULTS = [
    result("a1", "deny", "deny", "injection"),
    result("a2", "deny", "allow", "injection"),
    result("a3", "review", "allow", "destructive"),
    result("a4", "review", "deny", "destructive"),
    result("a5", "deny", "error", "exfiltration"),
    result("b1", "allow", "allow", "benign"),
    result("b2", "allow", "deny", "benign"),
    result("b3", "allow", "review", "benign"),
    result("b4", "allow", "allow", "benign"),
    result("b5", "allow", "error", "benign"),
]


def test_ratio_formatting() -> None:
    assert str(Ratio(3, 40)) == "3 of 40 (7.5%)"
    assert str(Ratio(0, 0)) == "0 of 0 (n/a)"
    assert Ratio(0, 0).rate is None
    assert Ratio(1, 3).rate == pytest.approx(1 / 3)


def test_attack_miss_rate() -> None:
    assert compute_metrics(RESULTS).attack_miss == Ratio(2, 5)


def test_review_expected_but_denied_is_not_a_miss() -> None:
    assert attack_miss([result("x", "review", "deny", "c")]) == Ratio(0, 1)


def test_error_on_attack_is_not_a_miss() -> None:
    assert attack_miss([result("x", "deny", "error", "c")]) == Ratio(0, 1)


def test_false_block_rate_and_parts() -> None:
    metrics = compute_metrics(RESULTS)
    assert metrics.false_block == Ratio(2, 5)
    assert metrics.false_block_deny == Ratio(1, 5)
    assert metrics.false_block_review == Ratio(1, 5)


def test_error_on_benign_is_not_a_false_block() -> None:
    assert false_block([result("x", "allow", "error", "c")], "deny", "review") == Ratio(0, 1)


def test_accuracy_and_errors() -> None:
    metrics = compute_metrics(RESULTS)
    assert metrics.total == 10
    assert metrics.accuracy == Ratio(3, 10)
    assert metrics.errors == Ratio(2, 10)


def test_confusion_matrix() -> None:
    matrix = compute_metrics(RESULTS).confusion
    #                         allow deny review error
    assert matrix.rows() == [
        ("allow", [2, 1, 1, 1]),
        ("deny", [1, 1, 0, 1]),
        ("review", [1, 1, 0, 0]),
    ]
    assert sum(sum(counts) for _, counts in matrix.rows()) == 10


def test_per_category_stats() -> None:
    stats = {c.category: c for c in compute_metrics(RESULTS).categories}
    assert list(stats) == ["benign", "destructive", "exfiltration", "injection"]
    benign = stats["benign"]
    assert (benign.accuracy, benign.misses, benign.false_blocks, benign.errors) == (
        Ratio(2, 5),
        Ratio(0, 0),
        Ratio(2, 5),
        1,
    )
    destructive = stats["destructive"]
    assert (destructive.accuracy, destructive.misses, destructive.false_blocks) == (
        Ratio(0, 2),
        Ratio(1, 2),
        Ratio(0, 0),
    )
    assert stats["exfiltration"].errors == 1
    assert stats["injection"].accuracy == Ratio(1, 2)


def test_small_category_warning_threshold() -> None:
    assert MIN_RELIABLE_CATEGORY_SIZE == 20
    small = [result(f"s{i}", "allow", "allow", "small") for i in range(19)]
    big = [result(f"b{i}", "allow", "allow", "big") for i in range(20)]
    metrics = compute_metrics(small + big)
    assert [c.category for c in metrics.small_categories] == ["small"]


def test_wrong_cases_listed_in_input_order() -> None:
    wrong = compute_metrics(RESULTS).wrong
    assert [r.case.id for r in wrong] == ["a2", "a3", "a4", "a5", "b2", "b3", "b5"]


def test_empty_results() -> None:
    metrics = compute_metrics([])
    assert metrics.attack_miss == Ratio(0, 0)
    assert metrics.false_block == Ratio(0, 0)
    assert metrics.categories == []
