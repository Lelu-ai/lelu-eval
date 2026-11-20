"""Load and validate cases from .jsonl files or directories of them."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError
from pydantic_core import ErrorDetails

from lelu_eval.schema import Case


class DatasetError(Exception):
    """The dataset is missing or invalid. ``problems`` lists every issue found."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("\n".join(problems))


@dataclass(frozen=True)
class Dataset:
    cases: list[Case]
    files: list[Path]


def find_case_files(path: Path) -> list[Path]:
    """Return the .jsonl files at ``path`` (a file, or a directory searched recursively)."""
    if not path.exists():
        raise DatasetError([f"{path}: no such file or directory"])
    if path.is_file():
        return [path]
    files = sorted(p for p in path.rglob("*.jsonl") if p.is_file())
    if not files:
        raise DatasetError([f"{path}: directory contains no .jsonl files"])
    return files


def load_cases(path: str | Path) -> Dataset:
    """Load every case under ``path``. Raises DatasetError listing all problems found."""
    files = find_case_files(Path(path))
    cases: list[Case] = []
    problems: list[str] = []
    first_seen: dict[str, str] = {}
    for file in files:
        for location, case in _parse_file(file, problems):
            if case.id in first_seen:
                problems.append(
                    f"{location}: duplicate id {case.id!r} (first used at {first_seen[case.id]})"
                )
                continue
            first_seen[case.id] = location
            cases.append(case)
    if problems:
        raise DatasetError(problems)
    if not cases:
        raise DatasetError([f"{path}: no cases found"])
    return Dataset(cases=cases, files=files)


def _parse_file(file: Path, problems: list[str]) -> list[tuple[str, Case]]:
    parsed: list[tuple[str, Case]] = []
    try:
        lines = file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        problems.append(f"{file}: cannot read file: {exc}")
        return parsed
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        location = f"{file}:{number}"
        case = _parse_line(line, location, problems)
        if case is not None:
            parsed.append((location, case))
    return parsed


def _parse_line(line: str, location: str, problems: list[str]) -> Case | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError as exc:
        problems.append(f"{location}: invalid JSON: {exc.msg} (column {exc.colno})")
        return None
    if not isinstance(data, dict):
        problems.append(f"{location}: each line must be a JSON object, got {type(data).__name__}")
        return None
    try:
        return Case.model_validate(data)
    except ValidationError as exc:
        label = f"case {data['id']!r}" if isinstance(data.get("id"), str) else "case"
        for error in exc.errors():
            field = ".".join(str(part) for part in error["loc"]) or "(root)"
            problems.append(f"{location}: {label}: field {field!r}: {_describe(error)}")
        return None


def _describe(error: ErrorDetails) -> str:
    if error["type"] == "extra_forbidden":
        return "unknown field (check the spelling; see docs/case-format.md)"
    return error["msg"]
