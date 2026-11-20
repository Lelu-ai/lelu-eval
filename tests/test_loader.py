from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lelu_eval.loader import DatasetError, load_cases


def _line(**overrides: Any) -> str:
    data: dict[str, Any] = {
        "id": "c1",
        "action": "read_file",
        "expected": "allow",
        "category": "benign",
    }
    data.update(overrides)
    return json.dumps(data)


def _write(path: Path, *lines: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _problems(path: Path) -> list[str]:
    with pytest.raises(DatasetError) as info:
        load_cases(path)
    return info.value.problems


def test_loads_file_and_skips_blank_lines(tmp_path: Path) -> None:
    file = _write(tmp_path / "a.jsonl", _line(id="a"), "", "   ", _line(id="b"))
    dataset = load_cases(file)
    assert [c.id for c in dataset.cases] == ["a", "b"]
    assert dataset.files == [file]


def test_loads_directory_recursively_in_sorted_order(tmp_path: Path) -> None:
    _write(tmp_path / "b.jsonl", _line(id="b1"))
    _write(tmp_path / "a.jsonl", _line(id="a1"))
    _write(tmp_path / "sub" / "c.jsonl", _line(id="c1"))
    _write(tmp_path / "ignored.txt", "not json")
    dataset = load_cases(tmp_path)
    assert [c.id for c in dataset.cases] == ["a1", "b1", "c1"]


def test_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "nope"
    assert _problems(missing) == [f"{missing}: no such file or directory"]


def test_directory_without_jsonl(tmp_path: Path) -> None:
    assert _problems(tmp_path) == [f"{tmp_path}: directory contains no .jsonl files"]


def test_empty_file(tmp_path: Path) -> None:
    file = _write(tmp_path / "a.jsonl", "")
    assert _problems(file) == [f"{file}: no cases found"]


def test_invalid_json_names_file_and_line(tmp_path: Path) -> None:
    file = _write(tmp_path / "a.jsonl", _line(id="a"), "{not json")
    [problem] = _problems(file)
    assert problem.startswith(f"{file}:2: invalid JSON")


def test_non_object_line(tmp_path: Path) -> None:
    file = _write(tmp_path / "a.jsonl", "[1, 2]")
    assert _problems(file) == [f"{file}:1: each line must be a JSON object, got list"]


def test_duplicate_id_names_both_locations(tmp_path: Path) -> None:
    first = _write(tmp_path / "a.jsonl", _line(id="dup"))
    second = _write(tmp_path / "b.jsonl", _line(id="ok"), _line(id="dup"))
    assert _problems(tmp_path) == [f"{second}:2: duplicate id 'dup' (first used at {first}:1)"]


def test_unknown_expected(tmp_path: Path) -> None:
    file = _write(tmp_path / "a.jsonl", _line(id="x", expected="block"))
    [problem] = _problems(file)
    assert problem.startswith(f"{file}:1: case 'x': field 'expected':")
    assert "'allow', 'deny' or 'review'" in problem


def test_confidence_out_of_range(tmp_path: Path) -> None:
    file = _write(tmp_path / "a.jsonl", _line(id="x", confidence=1.5))
    [problem] = _problems(file)
    assert problem.startswith(f"{file}:1: case 'x': field 'confidence':")
    assert "less than or equal to 1" in problem


def test_unknown_field_message(tmp_path: Path) -> None:
    file = _write(tmp_path / "a.jsonl", _line(id="x", categroy="benign"))
    assert _problems(file) == [
        f"{file}:1: case 'x': field 'categroy': "
        "unknown field (check the spelling; see docs/case-format.md)"
    ]


def test_reports_all_problems_not_just_first(tmp_path: Path) -> None:
    file = _write(
        tmp_path / "a.jsonl",
        _line(id="a", expected="nope"),
        "garbage",
        _line(id="c", confidence=-1),
    )
    problems = _problems(file)
    assert [p.split(": ")[0] for p in problems] == [f"{file}:1", f"{file}:2", f"{file}:3"]
