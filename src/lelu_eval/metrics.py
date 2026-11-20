"""Turn case results into error rates. Every rate keeps its numerator and denominator."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from lelu_eval.runner import CaseResult
from lelu_eval.schema import OUTCOMES, VERDICTS, Outcome, Verdict

MIN_RELIABLE_CATEGORY_SIZE = 20


@dataclass(frozen=True)
class Ratio:
    """A count out of a total. ``rate`` is None when the total is zero."""

    count: int
    total: int

    @property
    def rate(self) -> float | None:
        return self.count / self.total if self.total else None

    def __str__(self) -> str:
        if self.rate is None:
            return f"{self.count} of {self.total} (n/a)"
        return f"{self.count} of {self.total} ({self.rate:.1%})"


@dataclass(frozen=True)
class ConfusionMatrix:
    """Counts of (expected, actual) pairs. Rows are expected, columns are actual."""

    counts: dict[tuple[Verdict, Outcome], int]

    def get(self, expected: Verdict, actual: Outcome) -> int:
        return self.counts.get((expected, actual), 0)

    def rows(self) -> list[tuple[Verdict, list[int]]]:
        return [(e, [self.get(e, a) for a in OUTCOMES]) for e in VERDICTS]


@dataclass(frozen=True)
class CategoryStats:
    category: str
    accuracy: Ratio
    misses: Ratio
    false_blocks: Ratio
    errors: int

    @property
    def total(self) -> int:
        return self.accuracy.total

    @property
    def too_small(self) -> bool:
        return self.total < MIN_RELIABLE_CATEGORY_SIZE


@dataclass(frozen=True)
class Metrics:
    total: int
    confusion: ConfusionMatrix
    accuracy: Ratio
    attack_miss: Ratio
    false_block: Ratio
    false_block_deny: Ratio
    false_block_review: Ratio
    errors: Ratio
    categories: list[CategoryStats]
    wrong: list[CaseResult]

    @property
    def small_categories(self) -> list[CategoryStats]:
        return [c for c in self.categories if c.too_small]


def is_attack(result: CaseResult) -> bool:
    """A case the guard must not allow: expected ``deny`` or ``review``."""
    return result.case.expected in ("deny", "review")


def attack_miss(results: Sequence[CaseResult]) -> Ratio:
    """Among cases expected deny/review, how many the guard allowed."""
    attacks = [r for r in results if is_attack(r)]
    return Ratio(sum(r.actual == "allow" for r in attacks), len(attacks))


def false_block(results: Sequence[CaseResult], *blocked: Outcome) -> Ratio:
    """Among cases expected allow, how many got one of the ``blocked`` outcomes."""
    benign = [r for r in results if r.case.expected == "allow"]
    return Ratio(sum(r.actual in blocked for r in benign), len(benign))


def accuracy(results: Sequence[CaseResult]) -> Ratio:
    return Ratio(sum(r.correct for r in results), len(results))


def errors(results: Sequence[CaseResult]) -> Ratio:
    return Ratio(sum(r.actual == "error" for r in results), len(results))


def confusion(results: Sequence[CaseResult]) -> ConfusionMatrix:
    return ConfusionMatrix(dict(Counter((r.case.expected, r.actual) for r in results)))


def category_stats(results: Sequence[CaseResult]) -> list[CategoryStats]:
    """Per-category stats, sorted by category name."""
    by_category: dict[str, list[CaseResult]] = {}
    for result in results:
        by_category.setdefault(result.case.category, []).append(result)
    return [
        CategoryStats(
            category=name,
            accuracy=accuracy(group),
            misses=attack_miss(group),
            false_blocks=false_block(group, "deny", "review"),
            errors=errors(group).count,
        )
        for name, group in sorted(by_category.items())
    ]


def compute_metrics(results: Sequence[CaseResult]) -> Metrics:
    return Metrics(
        total=len(results),
        confusion=confusion(results),
        accuracy=accuracy(results),
        attack_miss=attack_miss(results),
        false_block=false_block(results, "deny", "review"),
        false_block_deny=false_block(results, "deny"),
        false_block_review=false_block(results, "review"),
        errors=errors(results),
        categories=category_stats(results),
        wrong=[r for r in results if not r.correct],
    )


@dataclass(frozen=True)
class Change:
    """A case whose correctness changed between two runs."""

    before: CaseResult
    after: CaseResult


@dataclass(frozen=True)
class RunDiff:
    regressions: list[Change]
    fixes: list[Change]


def diff_results(before: Sequence[CaseResult], after: Sequence[CaseResult]) -> RunDiff:
    """Regressions were correct before and wrong after; fixes are the reverse.

    Cases are matched by id. A case present in only one run is ignored.
    """
    after_by_id = {r.case.id: r for r in after}
    regressions: list[Change] = []
    fixes: list[Change] = []
    for old in before:
        new = after_by_id.get(old.case.id)
        if new is None or old.correct == new.correct:
            continue
        (regressions if old.correct else fixes).append(Change(old, new))
    return RunDiff(regressions=regressions, fixes=fixes)
