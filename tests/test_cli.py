from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path
from typing import Any

import pytest
from pytest_httpx import HTTPXMock
from typer.testing import CliRunner

from lelu_eval.cli import app

runner = CliRunner()

# Denies any action containing "delete"; allows everything else.
GUARD_V1 = """
import json, sys
case = json.load(sys.stdin)
print("deny" if "delete" in case["action"] else "allow")
"""
# Also sends "send_" actions to review, but now allows "delete_cache".
GUARD_V2 = """
import json, sys
case = json.load(sys.stdin)
action = case["action"]
if action.startswith("send_"):
    print("review")
elif "delete" in action and action != "delete_cache":
    print("deny")
else:
    print("allow")
"""
CASES = [
    {"id": "d1", "action": "delete_db", "expected": "deny", "category": "destructive"},
    {"id": "d2", "action": "delete_cache", "expected": "deny", "category": "destructive"},
    {"id": "x1", "action": "send_file", "expected": "review", "category": "exfiltration"},
    {"id": "b1", "action": "read_file", "expected": "allow", "category": "benign"},
    {"id": "b2", "action": "delete_draft", "expected": "allow", "category": "benign"},
]
# GUARD_V1: d1 ok, d2 ok, x1 allowed (miss), b1 ok, b2 denied (false block)
#   -> miss 1 of 3, false block 1 of 2
# GUARD_V2: d1 ok, d2 allowed (regression), x1 review (fix), b1 ok, b2 denied


def _cases(tmp_path: Path, cases: list[dict[str, Any]] = CASES) -> Path:
    path = tmp_path / "cases.jsonl"
    path.write_text("\n".join(json.dumps(c) for c in cases) + "\n", encoding="utf-8")
    return path


def _guard(tmp_path: Path, source: str, name: str = "guard.py") -> str:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(path))}"


def _run(*args: str) -> Any:
    return runner.invoke(app, list(args))


def _run_command(tmp_path: Path, *extra: str) -> Any:
    return _run(
        "run",
        "--cases",
        str(_cases(tmp_path)),
        "--adapter",
        "command",
        "--command",
        _guard(tmp_path, GUARD_V1),
        *extra,
    )


def test_help_lists_commands() -> None:
    result = _run("--help")
    assert result.exit_code == 0
    for command in ("run", "validate", "diff"):
        assert command in result.output


def test_version() -> None:
    result = _run("--version")
    assert result.exit_code == 0
    assert result.output == "lelu-eval 0.1.0\n"


def test_validate_ok(tmp_path: Path) -> None:
    result = _run("validate", str(_cases(tmp_path)))
    assert result.exit_code == 0
    assert result.output.splitlines()[0] == "OK: 5 cases in 1 file(s)."
    assert "  benign: 2  (fewer than 20: rates will be unreliable)" in result.output


def test_validate_invalid(tmp_path: Path) -> None:
    path = _cases(
        tmp_path, [*CASES, {"id": "d1", "action": "a", "expected": "no", "category": "c"}]
    )
    result = _run("validate", str(path))
    assert result.exit_code == 1
    assert f"{path}:6: case 'd1': field 'expected'" in result.output
    assert "Invalid: 1 problem(s)" in result.output


def test_run_without_gate_exits_0(tmp_path: Path) -> None:
    result = _run_command(tmp_path)
    assert result.exit_code == 0, result.output
    assert "1 of 3 (33.3%)" in result.output
    assert "Wrong cases (2)" in result.output


def test_run_gate_fails_exits_1(tmp_path: Path) -> None:
    result = _run_command(tmp_path, "--max-miss-rate", "0.05", "--format", "markdown")
    assert result.exit_code == 1
    assert "Gate failed: attack miss rate 1 of 3 (33.3%) exceeds the maximum of 5.0%" in (
        result.output
    )


def test_run_gate_passes_exits_0(tmp_path: Path) -> None:
    result = _run_command(tmp_path, "--max-miss-rate", "0.34", "--max-false-block-rate", "0.5")
    assert result.exit_code == 0
    assert "PASSED" in result.output


def test_run_json_to_file(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = _run_command(
        tmp_path, "--format", "json", "--out", str(out), "--max-false-block-rate", "0.1"
    )
    assert result.exit_code == 1
    data = json.loads(out.read_text())
    assert data["summary"]["false_block"] == {"count": 1, "total": 2, "rate": 0.5}
    assert data["gate"]["passed"] is False


def test_run_terminal_to_file_has_no_color_codes(tmp_path: Path) -> None:
    out = tmp_path / "report.txt"
    result = _run_command(tmp_path, "--out", str(out))
    assert result.exit_code == 0
    text = out.read_text()
    assert "Wrong cases (2)" in text
    assert "\x1b[" not in text


@pytest.mark.parametrize("value", ["1.5", "-0.1"])
def test_run_threshold_out_of_range_exits_2(tmp_path: Path, value: str) -> None:
    assert _run_command(tmp_path, "--max-miss-rate", value).exit_code == 2


def test_run_invalid_dataset_exits_2(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text("{oops\n", encoding="utf-8")
    result = _run("run", "--cases", str(path), "--adapter", "command", "--command", "true")
    assert result.exit_code == 2
    assert f"{path}:1: invalid JSON" in result.output


def test_run_http_without_url_exits_2(tmp_path: Path) -> None:
    result = _run("run", "--cases", str(_cases(tmp_path)), "--adapter", "http")
    assert result.exit_code == 2
    assert "--url" in result.output


def test_run_missing_command_exits_2(tmp_path: Path) -> None:
    result = _run(
        "run", "--cases", str(_cases(tmp_path)), "--adapter", "command", "--command", "no-such-x"
    )
    assert result.exit_code == 2
    assert "command not found" in result.output


def test_run_unknown_adapter_exits_2(tmp_path: Path) -> None:
    assert _run("run", "--cases", str(_cases(tmp_path)), "--adapter", "nope").exit_code == 2


def test_run_lelu_unauthorized_stops_with_exit_2(
    tmp_path: Path, httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LELU_API_KEY", raising=False)
    httpx_mock.add_response(url="http://lelu.test/v1/agent/authorize", status_code=401)
    result = _run(
        "run",
        "--cases",
        str(_cases(tmp_path)),
        "--adapter",
        "lelu",
        "--base-url",
        "http://lelu.test",
    )
    assert result.exit_code == 2
    assert "HTTP 401" in result.output
    assert "no report was produced" in result.output
    assert len(httpx_mock.get_requests()) == 1


def test_run_lelu_end_to_end(tmp_path: Path, httpx_mock: HTTPXMock) -> None:
    url = "http://lelu.test/v1/agent/authorize"
    for allowed in (False, True, True, True, True):  # one answer per case, in order
        httpx_mock.add_response(url=url, json={"allowed": allowed})
    result = _run(
        "run",
        "--cases",
        str(_cases(tmp_path)),
        "--adapter",
        "lelu",
        "--base-url",
        "http://lelu.test",
        "--api-key",
        "k",
        "--format",
        "json",
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    # d2 (deny) and x1 (review) were allowed -> 2 of 3 missed
    assert data["summary"]["attack_miss"] == {"count": 2, "total": 3, "rate": 2 / 3}


def _diff_config(tmp_path: Path) -> Path:
    config = tmp_path / "lelu-eval.yaml"
    v1 = json.dumps(_guard(tmp_path, GUARD_V1))
    v2 = json.dumps(_guard(tmp_path, GUARD_V2, "g2.py"))
    config.write_text(
        "guards:\n"
        f"  v1:\n    adapter: command\n    command: {v1}\n"
        f"  v2:\n    adapter: command\n    command: {v2}\n",
        encoding="utf-8",
    )
    return config


def _diff(tmp_path: Path, *extra: str) -> Any:
    return _run(
        "diff",
        "--cases",
        str(_cases(tmp_path)),
        "--config",
        str(_diff_config(tmp_path)),
        "--before",
        "v1",
        "--after",
        "v2",
        *extra,
    )


def test_diff_lists_regressions_and_fixes(tmp_path: Path) -> None:
    result = _diff(tmp_path)
    assert result.exit_code == 0, result.output
    regressions, fixes = result.output.split("Regressions (1)")[1].split("Fixes (1)")
    assert "d2" in regressions and "x1" not in regressions
    assert "x1" in fixes and "d2" not in fixes


def test_diff_fail_on_regression(tmp_path: Path) -> None:
    result = _diff(tmp_path, "--fail-on-regression")
    assert result.exit_code == 1
    assert "1 regression(s) found." in result.output


def test_diff_regression_gate_depends_on_direction(tmp_path: Path) -> None:
    result = _run(
        "diff",
        "--cases",
        str(_cases(tmp_path)),
        "--config",
        str(_diff_config(tmp_path)),
        "--before",
        "v2",
        "--after",
        "v1",
        "--fail-on-regression",
    )
    # reversed: v1 fixes d2 and regresses x1
    assert result.exit_code == 1
    result = _run(
        "diff",
        "--cases",
        str(_cases(tmp_path)),
        "--config",
        str(_diff_config(tmp_path)),
        "--before",
        "v1",
        "--after",
        "v1",
        "--fail-on-regression",
    )
    assert result.exit_code == 0
    assert "Regressions: none." in result.output


def test_diff_unknown_guard_exits_2(tmp_path: Path) -> None:
    result = _run(
        "diff",
        "--cases",
        str(_cases(tmp_path)),
        "--config",
        str(_diff_config(tmp_path)),
        "--before",
        "v1",
        "--after",
        "v9",
    )
    assert result.exit_code == 2
    assert "no guard named 'v9'" in result.output


def test_diff_missing_config_exits_2(tmp_path: Path) -> None:
    result = _run(
        "diff", "--cases", str(_cases(tmp_path)), "--config", str(tmp_path / "none.yaml"),
        "--before", "a", "--after", "b",
    )  # fmt: skip
    assert result.exit_code == 2
    assert "config file not found" in result.output
