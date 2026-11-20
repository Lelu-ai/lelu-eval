# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-20

### Added

- Case format (JSON Lines) with validation that reports every problem with file and line.
- `Guard` protocol and three adapters: `lelu` (Lelu engine over HTTP), `http` (any JSON endpoint) and `command` (any program that reads a case on stdin).
- Metrics: confusion matrix, attack miss rate, false-block rate (deny and review parts), accuracy, error count, per-category results with a warning under 20 cases. Every rate keeps its denominator.
- CI gate: `--max-miss-rate` and `--max-false-block-rate`, exit code 1 on failure, 2 on usage or configuration errors.
- Reports in terminal, markdown and JSON formats, including every wrong case with the guard's reason.
- `lelu-eval run`, `lelu-eval validate` and `lelu-eval diff` (regressions and fixes between two named guards from a YAML config).
- Sample dataset of 40 hand-written cases (CC BY 4.0) with a datasheet.
- Example keyword guard (`examples/fake_guard.py`) for trying the tool without a real guard.
