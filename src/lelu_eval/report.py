"""Render results as a terminal report, markdown or JSON.

All three formats are built from the same section helpers so they always agree.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from lelu_eval.gate import GateFailure, Thresholds
from lelu_eval.metrics import MIN_RELIABLE_CATEGORY_SIZE, Change, Metrics, Ratio, RunDiff
from lelu_eval.runner import CaseResult
from lelu_eval.schema import OUTCOMES

Rows = list[list[str]]


@dataclass(frozen=True)
class RunReport:
    guard: str
    cases_path: str
    metrics: Metrics
    thresholds: Thresholds = field(default_factory=Thresholds)
    failures: list[GateFailure] = field(default_factory=list)


# ---------------------------------------------------------------- sections

SUMMARY_HEADER = ["Metric", "Result"]
CONFUSION_HEADER = ["expected \\ actual", *OUTCOMES, "total"]
CATEGORY_HEADER = ["Category", "Cases", "Correct", "Missed attacks", "False blocks", "Errors"]
WRONG_HEADER = ["ID", "Category", "Expected", "Actual", "Reason"]
DIFF_HEADER = ["ID", "Category", "Expected", "Before", "After", "Reason (after)"]


def summary_rows(m: Metrics) -> Rows:
    return [
        ["Attack miss rate (expected deny/review, got allow)", str(m.attack_miss)],
        ["False-block rate (expected allow, got deny or review)", str(m.false_block)],
        ["  - denied", str(m.false_block_deny)],
        ["  - sent to review", str(m.false_block_review)],
        ["Accuracy (actual = expected)", str(m.accuracy)],
        ["Errors (guard did not answer)", str(m.errors)],
    ]


def confusion_rows(m: Metrics) -> Rows:
    return [
        [expected, *(str(n) for n in counts), str(sum(counts))]
        for expected, counts in m.confusion.rows()
    ]


def category_rows(m: Metrics) -> Rows:
    return [
        [
            c.category,
            str(c.total),
            str(c.accuracy),
            str(c.misses),
            str(c.false_blocks),
            str(c.errors),
        ]
        for c in m.categories
    ]


def wrong_rows(m: Metrics) -> Rows:
    return [[r.case.id, r.case.category, r.case.expected, r.actual, r.explanation] for r in m.wrong]


def diff_rows(changes: list[Change]) -> Rows:
    return [
        [
            c.after.case.id,
            c.after.case.category,
            c.after.case.expected,
            c.before.actual,
            c.after.actual,
            c.after.explanation,
        ]
        for c in changes
    ]


def warnings(m: Metrics) -> list[str]:
    notes: list[str] = []
    if m.small_categories:
        sizes = ", ".join(f"{c.category} ({c.total})" for c in m.small_categories)
        notes.append(
            f"Fewer than {MIN_RELIABLE_CATEGORY_SIZE} cases in: {sizes}. "
            "Rates for these categories are unreliable."
        )
    if m.errors.count:
        notes.append(
            f"The guard failed to answer {m.errors}. Errors count as neither allow nor deny, "
            "so they lower accuracy but not the miss or false-block rates. "
            "See the reasons in the wrong-case list."
        )
    return notes


def gate_lines(report: RunReport) -> list[str]:
    t = report.thresholds
    if t.max_miss_rate is None and t.max_false_block_rate is None:
        return ["No thresholds set (use --max-miss-rate / --max-false-block-rate)."]
    if not report.failures:
        return ["PASSED: all thresholds met."]
    return ["FAILED:", *(f"- {f.message}" for f in report.failures)]


# ---------------------------------------------------------------- markdown


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _md_table(header: list[str], rows: Rows) -> str:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(_md_cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def render_markdown(report: RunReport) -> str:
    m = report.metrics
    parts = [
        "# lelu-eval report",
        f"Guard: `{report.guard}`. Cases: `{report.cases_path}` ({m.total}).",
        "## Summary",
        _md_table(SUMMARY_HEADER, summary_rows(m)),
        "## Gate",
        "\n".join(gate_lines(report)),
        "## Confusion matrix",
        "Rows are the expected outcome, columns the actual outcome.",
        _md_table(CONFUSION_HEADER, confusion_rows(m)),
        "## Per category",
        _md_table(CATEGORY_HEADER, category_rows(m)),
    ]
    parts += [f"> Warning: {w}" for w in warnings(m)]
    parts.append(f"## Wrong cases ({len(m.wrong)})")
    parts.append(_md_table(WRONG_HEADER, wrong_rows(m)) if m.wrong else "None.")
    return "\n\n".join(parts) + "\n"


# ---------------------------------------------------------------- terminal


def _rich_table(title: str, header: list[str], rows: Rows) -> Table:
    table = Table(title=title, title_justify="left", show_lines=False)
    for name in header:
        table.add_column(name, overflow="fold")
    for row in rows:
        table.add_row(*(Text(cell) for cell in row))  # literal text: never parse guard output
    return table


def render_terminal(report: RunReport, console: Console) -> None:
    m = report.metrics
    console.print(
        f"[bold]lelu-eval report[/]  guard: {escape(report.guard)}  "
        f"cases: {escape(report.cases_path)}",
        highlight=False,
    )
    console.print(_rich_table("Summary", SUMMARY_HEADER, summary_rows(m)))
    console.print(
        _rich_table("Confusion matrix (rows: expected)", CONFUSION_HEADER, confusion_rows(m))
    )
    console.print(_rich_table("Per category", CATEGORY_HEADER, category_rows(m)))
    for note in warnings(m):
        console.print(f"[yellow]Warning:[/] {escape(note)}", highlight=False)
    if m.wrong:
        console.print(_rich_table(f"Wrong cases ({len(m.wrong)})", WRONG_HEADER, wrong_rows(m)))
    else:
        console.print("Wrong cases: none.")
    style = "red" if report.failures else "green"
    gate = escape("\n".join(gate_lines(report)))
    console.print(f"[bold {style}]Gate:[/] {gate}", highlight=False)


def render_diff_terminal(
    diff: RunDiff, before: RunReport, after: RunReport, console: Console
) -> None:
    table = Table(title="Before vs after", title_justify="left")
    for name in ("Metric", f"before ({before.guard})", f"after ({after.guard})"):
        table.add_column(Text(name), overflow="fold")
    for (label, old), (_, new) in zip(
        summary_rows(before.metrics), summary_rows(after.metrics), strict=True
    ):
        table.add_row(Text(label), Text(old), Text(new))
    console.print(table)
    for title, changes in (("Regressions", diff.regressions), ("Fixes", diff.fixes)):
        if changes:
            console.print(_rich_table(f"{title} ({len(changes)})", DIFF_HEADER, diff_rows(changes)))
        else:
            console.print(f"{title}: none.")


# ---------------------------------------------------------------- json


def _ratio(r: Ratio) -> dict[str, Any]:
    return {"count": r.count, "total": r.total, "rate": r.rate}


def _result(r: CaseResult) -> dict[str, Any]:
    return {
        "id": r.case.id,
        "category": r.case.category,
        "expected": r.case.expected,
        "actual": r.actual,
        "reason": r.explanation,
    }


def to_dict(report: RunReport) -> dict[str, Any]:
    m = report.metrics
    return {
        "guard": report.guard,
        "cases_path": report.cases_path,
        "total": m.total,
        "summary": {
            "attack_miss": _ratio(m.attack_miss),
            "false_block": _ratio(m.false_block),
            "false_block_deny": _ratio(m.false_block_deny),
            "false_block_review": _ratio(m.false_block_review),
            "accuracy": _ratio(m.accuracy),
            "errors": _ratio(m.errors),
        },
        "confusion": {
            e: dict(zip(OUTCOMES, counts, strict=True)) for e, counts in m.confusion.rows()
        },
        "categories": [
            {
                "category": c.category,
                "total": c.total,
                "correct": _ratio(c.accuracy),
                "missed_attacks": _ratio(c.misses),
                "false_blocks": _ratio(c.false_blocks),
                "errors": c.errors,
                "too_small": c.too_small,
            }
            for c in m.categories
        ],
        "warnings": warnings(m),
        "gate": {
            "passed": not report.failures,
            "max_miss_rate": report.thresholds.max_miss_rate,
            "max_false_block_rate": report.thresholds.max_false_block_rate,
            "failures": [f.message for f in report.failures],
        },
        "wrong": [_result(r) for r in m.wrong],
    }


def render_json(report: RunReport) -> str:
    return json.dumps(to_dict(report), indent=2) + "\n"
