from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

import pytest

from lelu_eval.adapters.base import GuardConfigError, GuardError
from lelu_eval.adapters.command import CommandGuard
from tests.conftest import CaseFactory


def _script(tmp_path: Path, body: str) -> str:
    """Write a Python guard script and return a command line that runs it."""
    path = tmp_path / "guard.py"
    path.write_text("import json, sys\n" + body, encoding="utf-8")
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(path))}"


def test_case_is_sent_on_stdin(tmp_path: Path, make_case: CaseFactory) -> None:
    out = tmp_path / "received.json"
    command = _script(
        tmp_path,
        f"open({str(out)!r}, 'w').write(sys.stdin.read())\nprint('allow')\n",
    )
    CommandGuard(command).decide(make_case(args={"n": 1}))
    assert json.loads(out.read_text()) == {
        "id": "c1",
        "action": "read_file",
        "expected": "allow",
        "category": "benign",
        "args": {"n": 1},
    }


@pytest.mark.parametrize(
    ("printed", "outcome"), [("allow", "allow"), ("DENY", "deny"), ("  review  ", "review")]
)
def test_reads_decision_from_first_line(
    tmp_path: Path, make_case: CaseFactory, printed: str, outcome: str
) -> None:
    command = _script(tmp_path, f"print({printed!r})\n")
    decision = CommandGuard(command).decide(make_case())
    assert decision.outcome == outcome
    assert decision.reason is None


def test_extra_lines_become_reason(tmp_path: Path, make_case: CaseFactory) -> None:
    command = _script(tmp_path, "print('deny')\nprint('matched rule 7')\n")
    decision = CommandGuard(command).decide(make_case())
    assert decision.outcome == "deny"
    assert decision.reason == "matched rule 7"
    assert decision.raw == "deny\nmatched rule 7\n"


def test_unknown_output_is_guard_error(tmp_path: Path, make_case: CaseFactory) -> None:
    command = _script(tmp_path, "print('maybe')\n")
    with pytest.raises(GuardError, match="got 'maybe'"):
        CommandGuard(command).decide(make_case())


def test_empty_output_is_guard_error(tmp_path: Path, make_case: CaseFactory) -> None:
    command = _script(tmp_path, "")
    with pytest.raises(GuardError):
        CommandGuard(command).decide(make_case())


def test_nonzero_exit_is_guard_error(tmp_path: Path, make_case: CaseFactory) -> None:
    command = _script(tmp_path, "print('allow')\nsys.stderr.write('crashed')\nsys.exit(3)\n")
    with pytest.raises(GuardError, match="status 3: crashed"):
        CommandGuard(command).decide(make_case())


def test_timeout_is_guard_error(tmp_path: Path, make_case: CaseFactory) -> None:
    command = _script(tmp_path, "import time\ntime.sleep(5)\n")
    with pytest.raises(GuardError, match=r"timed out after 0\.3s"):
        CommandGuard(command, timeout=0.3).decide(make_case())


def test_missing_executable_is_config_error(make_case: CaseFactory) -> None:
    with pytest.raises(GuardConfigError, match="command not found"):
        CommandGuard("definitely-not-a-real-binary-xyz").decide(make_case())


def test_empty_command_is_config_error() -> None:
    with pytest.raises(GuardConfigError, match="empty"):
        CommandGuard("   ")
