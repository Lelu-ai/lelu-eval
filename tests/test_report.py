from __future__ import annotations

import io
import json

from rich.console import Console

from lelu_eval.gate import Thresholds, check_gate
from lelu_eval.metrics import compute_metrics
from lelu_eval.report import RunReport, render_json, render_markdown, render_terminal
from lelu_eval.runner import CaseResult
from lelu_eval.schema import Decision
from tests.conftest import build_case
from tests.test_metrics import RESULTS


def _report(thresholds: Thresholds | None = None) -> RunReport:
    metrics = compute_metrics(RESULTS)
    t = thresholds or Thresholds()
    return RunReport("fake", "cases.jsonl", metrics, t, check_gate(metrics, t))


def _terminal(report: RunReport) -> str:
    buffer = io.StringIO()
    render_terminal(report, Console(file=buffer, width=200, no_color=True))
    return buffer.getvalue()


def test_json_report_structure() -> None:
    data = json.loads(render_json(_report(Thresholds(max_miss_rate=0.1))))
    assert data["total"] == 10
    assert data["summary"]["attack_miss"] == {"count": 2, "total": 5, "rate": 0.4}
    assert data["summary"]["false_block_deny"] == {"count": 1, "total": 5, "rate": 0.2}
    assert data["confusion"]["allow"] == {"allow": 2, "deny": 1, "review": 1, "error": 1}
    assert data["gate"] == {
        "passed": False,
        "max_miss_rate": 0.1,
        "max_false_block_rate": None,
        "failures": ["attack miss rate 2 of 5 (40.0%) exceeds the maximum of 10.0%"],
    }
    assert [w["id"] for w in data["wrong"]] == ["a2", "a3", "a4", "a5", "b2", "b3", "b5"]
    assert data["wrong"][3] == {
        "id": "a5",
        "category": "exfiltration",
        "expected": "deny",
        "actual": "error",
        "reason": "boom",
    }
    assert all(c["too_small"] for c in data["categories"])


def test_markdown_escapes_pipes_and_newlines() -> None:
    case = build_case(id="x", expected="deny", category="c")
    result = CaseResult(case, "allow", Decision(outcome="allow", reason="a | b\nc"))
    metrics = compute_metrics([result])
    text = render_markdown(RunReport("g", "p", metrics))
    assert "| x | c | deny | allow | a \\| b c |" in text


def test_markdown_gate_states() -> None:
    assert "No thresholds set" in render_markdown(_report())
    assert "PASSED: all thresholds met." in render_markdown(_report(Thresholds(max_miss_rate=0.5)))
    failed = render_markdown(_report(Thresholds(max_false_block_rate=0.0)))
    assert "FAILED:\n- false-block rate 2 of 5 (40.0%) exceeds the maximum of 0.0%" in failed


def test_warnings_for_small_categories_and_errors() -> None:
    text = render_markdown(_report())
    assert "> Warning: Fewer than 20 cases in: benign (5), destructive (2)" in text
    assert "> Warning: The guard failed to answer 2 of 10 (20.0%)" in text


def test_terminal_lists_every_wrong_case_with_reason() -> None:
    text = _terminal(_report())
    assert "Wrong cases (7)" in text
    for case_id in ("a2", "a3", "a4", "a5", "b2", "b3", "b5"):
        assert f"│ {case_id} " in text
    assert "boom" in text


def test_terminal_does_not_interpret_markup_in_guard_output() -> None:
    case = build_case(id="[bold]x[/bold]", expected="deny", category="[red]c")
    result = CaseResult(case, "allow", Decision(outcome="allow", reason="[red]matched[/red]"))
    text = _terminal(RunReport("g", "p", compute_metrics([result])))
    assert "[red]matched[/red]" in text
    assert "[bold]x[/bold]" in text
    assert "[red]c (1)" in text
