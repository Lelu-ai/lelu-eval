"""Adapter for a guard run as a shell command: case JSON on stdin, decision on stdout."""

from __future__ import annotations

import shlex
import subprocess

from lelu_eval.adapters.base import GuardConfigError, GuardError, parse_verdict
from lelu_eval.schema import Case, Decision

DEFAULT_TIMEOUT = 10.0


class CommandGuard:
    """Runs ``command`` once per case.

    The case is written to stdin as one JSON object. The first line of stdout must be
    ``allow``, ``deny`` or ``review``; any further lines are kept as the reason. A
    non-zero exit status or a timeout is recorded as an error for that case.
    """

    name = "command"

    def __init__(self, command: str, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.argv = shlex.split(command)
        if not self.argv:
            raise GuardConfigError("--command is empty. Pass the command that runs your guard.")
        self.timeout = timeout

    def decide(self, case: Case) -> Decision:
        stdout = self._run(case.model_dump_json(exclude_none=True))
        first, _, rest = stdout.strip().partition("\n")
        outcome = parse_verdict(first, source=f"first line of stdout from {self.argv[0]!r}")
        return Decision(outcome=outcome, reason=rest.strip() or None, raw=stdout)

    def _run(self, payload: str) -> str:
        try:
            result = subprocess.run(
                self.argv,
                input=payload,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise GuardConfigError(
                f"command not found: {self.argv[0]!r}. Check --command and your PATH."
            ) from exc
        except PermissionError as exc:
            raise GuardConfigError(f"cannot execute {self.argv[0]!r}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise GuardError(f"command timed out after {self.timeout}s") from exc
        if result.returncode != 0:
            stderr = result.stderr.strip()[-300:]
            raise GuardError(f"command exited with status {result.returncode}: {stderr}")
        return result.stdout
