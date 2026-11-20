"""Guard configuration: from CLI options or from named entries in a YAML file."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from lelu_eval.adapters.base import Guard
from lelu_eval.adapters.command import CommandGuard
from lelu_eval.adapters.generic_http import DEFAULT_DECISION_FIELD, GenericHttpGuard
from lelu_eval.adapters.lelu_http import API_KEY_ENV, DEFAULT_BASE_URL, LeluGuard

AdapterName = Literal["lelu", "http", "command"]
DEFAULT_CONFIG_FILE = "lelu-eval.yaml"
DEFAULT_TIMEOUT = 10.0


class ConfigError(Exception):
    """The guard configuration is missing or invalid."""


class GuardConfig(BaseModel):
    """How to reach one guard. API keys are read from an environment variable, never stored."""

    model_config = ConfigDict(extra="forbid")

    adapter: AdapterName
    timeout: float = Field(default=DEFAULT_TIMEOUT, gt=0)
    base_url: str = DEFAULT_BASE_URL
    api_key_env: str = API_KEY_ENV
    url: str | None = None
    decision_field: str = DEFAULT_DECISION_FIELD
    command: str | None = None


def build_guard(config: GuardConfig, api_key: str | None = None) -> Guard:
    """Create the adapter described by ``config``. ``api_key`` overrides the env var."""
    if config.adapter == "lelu":
        key = api_key if api_key is not None else os.environ.get(config.api_key_env)
        return LeluGuard(base_url=config.base_url, api_key=key, timeout=config.timeout)
    if config.adapter == "http":
        if not config.url:
            raise ConfigError("the http adapter needs a URL: pass --url (or set url: in config)")
        return GenericHttpGuard(
            url=config.url, decision_field=config.decision_field, timeout=config.timeout
        )
    if not config.command:
        raise ConfigError(
            "the command adapter needs a command: pass --command (or set command: in config)"
        )
    return CommandGuard(command=config.command, timeout=config.timeout)


def load_guard_configs(path: Path) -> dict[str, GuardConfig]:
    """Read the ``guards:`` mapping from a YAML config file."""
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}. Create it or pass --config.")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    guards = data.get("guards") if isinstance(data, dict) else None
    if not isinstance(guards, dict) or not guards:
        raise ConfigError(f"{path}: expected a top-level 'guards:' mapping of name -> settings")
    return {str(name): _parse_guard(path, str(name), raw) for name, raw in guards.items()}


def get_guard_config(configs: dict[str, GuardConfig], name: str, path: Path) -> GuardConfig:
    if name not in configs:
        known = ", ".join(sorted(configs))
        raise ConfigError(f"{path}: no guard named {name!r} (known: {known})")
    return configs[name]


def _parse_guard(path: Path, name: str, raw: object) -> GuardConfig:
    try:
        return GuardConfig.model_validate(raw)
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or '(root)'}: {e['msg']}" for e in exc.errors()
        )
        raise ConfigError(f"{path}: guard {name!r}: {details}") from exc
