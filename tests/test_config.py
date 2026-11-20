from __future__ import annotations

from pathlib import Path

import pytest

from lelu_eval.adapters.command import CommandGuard
from lelu_eval.adapters.generic_http import GenericHttpGuard
from lelu_eval.adapters.lelu_http import LeluGuard
from lelu_eval.config import (
    ConfigError,
    GuardConfig,
    build_guard,
    get_guard_config,
    load_guard_configs,
)


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "lelu-eval.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_named_guards(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
guards:
  old:
    adapter: command
    command: python old.py
  new:
    adapter: http
    url: http://localhost:9000/check
    decision_field: verdict
    timeout: 2
""",
    )
    configs = load_guard_configs(path)
    assert configs["old"] == GuardConfig(adapter="command", command="python old.py")
    assert configs["new"].decision_field == "verdict"
    assert configs["new"].timeout == 2.0


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="config file not found"):
        load_guard_configs(tmp_path / "nope.yaml")


@pytest.mark.parametrize("text", ["", "guards: []", "other: 1", "guards: {}"])
def test_requires_guards_mapping(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError, match="'guards:' mapping"):
        load_guard_configs(_write(tmp_path, text))


def test_invalid_yaml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_guard_configs(_write(tmp_path, "guards: [unclosed"))


def test_api_key_cannot_be_stored_in_config(tmp_path: Path) -> None:
    path = _write(tmp_path, "guards:\n  g:\n    adapter: lelu\n    api_key: sk-123\n")
    with pytest.raises(ConfigError, match="guard 'g': api_key: Extra inputs"):
        load_guard_configs(path)


def test_unknown_adapter(tmp_path: Path) -> None:
    path = _write(tmp_path, "guards:\n  g:\n    adapter: magic\n")
    with pytest.raises(ConfigError, match="guard 'g': adapter"):
        load_guard_configs(path)


def test_unknown_guard_name_lists_known(tmp_path: Path) -> None:
    configs = {"a": GuardConfig(adapter="lelu"), "b": GuardConfig(adapter="lelu")}
    with pytest.raises(ConfigError, match=r"no guard named 'c' \(known: a, b\)"):
        get_guard_config(configs, "c", tmp_path / "x.yaml")


def test_build_each_adapter() -> None:
    assert isinstance(build_guard(GuardConfig(adapter="lelu")), LeluGuard)
    http = build_guard(GuardConfig(adapter="http", url="http://x"))
    assert isinstance(http, GenericHttpGuard)
    assert isinstance(build_guard(GuardConfig(adapter="command", command="true")), CommandGuard)


def test_http_requires_url() -> None:
    with pytest.raises(ConfigError, match="--url"):
        build_guard(GuardConfig(adapter="http"))


def test_command_requires_command() -> None:
    with pytest.raises(ConfigError, match="--command"):
        build_guard(GuardConfig(adapter="command"))


def test_lelu_api_key_read_from_named_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STAGING_KEY", "k1")
    guard = build_guard(GuardConfig(adapter="lelu", api_key_env="STAGING_KEY"))
    assert isinstance(guard, LeluGuard)
    assert guard._headers == {"Authorization": "Bearer k1"}
