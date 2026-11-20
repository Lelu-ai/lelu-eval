# TODO

Ideas that came up while building 0.1.0 but were outside its scope. None of these exist yet.

## Correctness of the gate

- **`--max-error-rate` gate.** Errors count as neither allow nor deny, so a guard that errors on every attack case passes `--max-miss-rate`. A threshold on the error rate would close that gap. (A connection failure already stops the run, but timeouts and HTTP 5xx do not.)
- **Confidence intervals** next to rates, so small categories show how uncertain they are instead of only a warning.

## Adapters

- Auth headers (or a header option) for the generic `http` adapter.
- Dotted paths for `--decision-field` (for example `result.decision`).
- A `--reason-field` option for the `http` adapter.
- Retries with backoff for transient HTTP errors.
- Windows-friendly `--command` parsing (it currently uses POSIX shell splitting).

## CLI

- `lelu-eval run --guard NAME --config FILE` to run a named guard from the config file.
- Markdown and JSON output for `diff`, for posting to pull requests.
- A progress display for long runs.
- Running cases concurrently.
- Filtering cases by category or id.

## Dataset

- More cases per category (at least 20 each) with labels reviewed by a second person.
- Multi-turn cases: attacks that build up over several tool calls.

## Project

- Publish to PyPI.
- Test against the lowest supported versions of each dependency.
