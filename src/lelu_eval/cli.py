"""Command-line interface: ``lelu-eval run | validate | diff``."""

from __future__ import annotations

import io
from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

from lelu_eval import __version__
from lelu_eval.adapters.base import GuardConfigError
from lelu_eval.adapters.generic_http import DEFAULT_DECISION_FIELD
from lelu_eval.adapters.lelu_http import DEFAULT_BASE_URL
from lelu_eval.config import (
    DEFAULT_CONFIG_FILE,
    DEFAULT_TIMEOUT,
    ConfigError,
    GuardConfig,
    build_guard,
    get_guard_config,
    load_guard_configs,
)
from lelu_eval.gate import EXIT_GATE_FAILED, EXIT_USAGE, Thresholds, check_gate
from lelu_eval.loader import Dataset, DatasetError, load_cases
from lelu_eval.metrics import MIN_RELIABLE_CATEGORY_SIZE, compute_metrics, diff_results
from lelu_eval.report import (
    RunReport,
    render_diff_terminal,
    render_json,
    render_markdown,
    render_terminal,
)
from lelu_eval.runner import CaseResult, run_cases

app = typer.Typer(
    help="pytest for agent guardrails: measure whether a guard allows, denies and "
    "escalates the right agent tool calls.",
    no_args_is_help=True,
    add_completion=False,
)
stdout = Console()
REPORT_FILE_WIDTH = 120


class Adapter(StrEnum):
    lelu = "lelu"
    http = "http"
    command = "command"


class Format(StrEnum):
    terminal = "terminal"
    markdown = "markdown"
    json = "json"


CasesOption = Annotated[
    Path, typer.Option("--cases", help="A .jsonl file or a directory of them.", show_default=False)
]


# ---------------------------------------------------------------- helpers


def _err(message: str) -> None:
    typer.echo(message, err=True)


def _fail(message: str, code: int = EXIT_USAGE) -> NoReturn:
    typer.secho("Error: ", fg="red", bold=True, err=True, nl=False)
    _err(message)
    raise typer.Exit(code)


def _print_problems(problems: list[str]) -> None:
    for problem in problems:
        _err(problem)


def _load(path: Path) -> Dataset:
    try:
        return load_cases(path)
    except DatasetError as exc:
        _print_problems(exc.problems)
        _fail(f"invalid dataset ({len(exc.problems)} problem(s)). Run `lelu-eval validate {path}`.")


def _run(config: GuardConfig, dataset: Dataset, api_key: str | None) -> list[CaseResult]:
    try:
        guard = build_guard(config, api_key=api_key)
        return run_cases(guard, dataset.cases)
    except (ConfigError, GuardConfigError) as exc:
        _fail(f"{exc}\nThe run was stopped; no report was produced.")


def _render(report: RunReport, output_format: Format, for_file: bool) -> str | None:
    """Return the report text, or None when it was printed straight to the terminal."""
    if output_format is Format.markdown:
        return render_markdown(report)
    if output_format is Format.json:
        return render_json(report)
    if not for_file:
        render_terminal(report, stdout)
        return None
    buffer = io.StringIO()
    render_terminal(report, Console(file=buffer, width=REPORT_FILE_WIDTH, no_color=True))
    return buffer.getvalue()


def _emit(report: RunReport, output_format: Format, out: Path | None) -> None:
    text = _render(report, output_format, for_file=out is not None)
    if text is None:
        return
    if out is None:
        typer.echo(text, nl=False)
        return
    try:
        out.write_text(text, encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write the report to {out}: {exc}")
    _err(f"Report written to {out}")


def _version(value: bool) -> None:
    if value:
        typer.echo(f"lelu-eval {__version__}")
        raise typer.Exit()


# ---------------------------------------------------------------- commands


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    """pytest for agent guardrails."""


@app.command()
def run(
    cases: CasesOption,
    adapter: Annotated[Adapter, typer.Option(help="Which guard adapter to use.")],
    command: Annotated[
        str | None,
        typer.Option(help="[command] Command run once per case, with the case JSON on stdin."),
    ] = None,
    url: Annotated[str | None, typer.Option(help="[http] URL to POST each case to.")] = None,
    decision_field: Annotated[
        str, typer.Option(help="[http] Response field holding allow, deny or review.")
    ] = DEFAULT_DECISION_FIELD,
    base_url: Annotated[str, typer.Option(help="[lelu] Lelu engine base URL.")] = DEFAULT_BASE_URL,
    api_key: Annotated[
        str | None,
        typer.Option(help="[lelu] API key. Defaults to the LELU_API_KEY environment variable."),
    ] = None,
    timeout: Annotated[
        float, typer.Option(min=0.001, help="Seconds to wait for each decision.")
    ] = DEFAULT_TIMEOUT,
    output_format: Annotated[Format, typer.Option("--format", help="Report format.")] = (
        Format.terminal
    ),
    out: Annotated[
        Path | None, typer.Option(help="Write the report to this file instead of stdout.")
    ] = None,
    max_miss_rate: Annotated[
        float | None,
        typer.Option(min=0.0, max=1.0, help="Exit 1 if the attack miss rate is above this."),
    ] = None,
    max_false_block_rate: Annotated[
        float | None,
        typer.Option(min=0.0, max=1.0, help="Exit 1 if the false-block rate is above this."),
    ] = None,
) -> None:
    """Run every case through a guard and report where it was wrong."""
    config = GuardConfig(
        adapter=adapter.value,
        timeout=timeout,
        base_url=base_url,
        url=url,
        decision_field=decision_field,
        command=command,
    )
    dataset = _load(cases)
    results = _run(config, dataset, api_key)
    metrics = compute_metrics(results)
    thresholds = Thresholds(max_miss_rate=max_miss_rate, max_false_block_rate=max_false_block_rate)
    failures = check_gate(metrics, thresholds)
    report = RunReport(adapter.value, str(cases), metrics, thresholds, failures)
    _emit(report, output_format, out)
    if failures:
        if output_format is not Format.terminal or out is not None:
            # the terminal report already shows the gate; other formats need it in the log
            for failure in failures:
                _err(f"Gate failed: {failure.message}")
        raise typer.Exit(EXIT_GATE_FAILED)


@app.command()
def validate(
    path: Annotated[Path, typer.Argument(help="A .jsonl file or a directory of them.")],
) -> None:
    """Check a dataset without running anything. Exit 1 if it has problems."""
    try:
        dataset = load_cases(path)
    except DatasetError as exc:
        _print_problems(exc.problems)
        _err(f"Invalid: {len(exc.problems)} problem(s) in {path}")
        raise typer.Exit(EXIT_GATE_FAILED) from None
    typer.echo(f"OK: {len(dataset.cases)} cases in {len(dataset.files)} file(s).")
    for category, count in sorted(Counter(c.category for c in dataset.cases).items()):
        small = count < MIN_RELIABLE_CATEGORY_SIZE
        note = f"  (fewer than {MIN_RELIABLE_CATEGORY_SIZE}: rates will be unreliable)"
        typer.echo(f"  {category}: {count}{note if small else ''}")


@app.command()
def diff(
    cases: CasesOption,
    before: Annotated[str, typer.Option(help="Name of the guard before the change.")],
    after: Annotated[str, typer.Option(help="Name of the guard after the change.")],
    config: Annotated[Path, typer.Option(help="YAML file that defines the named guards.")] = Path(
        DEFAULT_CONFIG_FILE
    ),
    fail_on_regression: Annotated[bool, typer.Option(help="Exit 1 if any case got worse.")] = False,
) -> None:
    """Run two configured guards on the same cases and list regressions and fixes."""
    try:
        configs = load_guard_configs(config)
        before_config = get_guard_config(configs, before, config)
        after_config = get_guard_config(configs, after, config)
    except ConfigError as exc:
        _fail(str(exc))
    dataset = _load(cases)
    before_results = _run(before_config, dataset, None)
    after_results = _run(after_config, dataset, None)
    changes = diff_results(before_results, after_results)
    render_diff_terminal(
        changes,
        RunReport(before, str(cases), compute_metrics(before_results)),
        RunReport(after, str(cases), compute_metrics(after_results)),
        stdout,
    )
    if changes.regressions and fail_on_regression:
        _err(f"{len(changes.regressions)} regression(s) found.")
        raise typer.Exit(EXIT_GATE_FAILED)
