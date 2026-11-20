# Adapters

An adapter connects `lelu-eval` to one guard. The core only knows the `Guard` protocol in [`src/lelu_eval/adapters/base.py`](../src/lelu_eval/adapters/base.py):

```python
class Guard(Protocol):
    name: str

    def decide(self, case: Case) -> Decision: ...
```

`Decision` has `outcome` (`allow`, `deny` or `review`), an optional `reason`, and `raw`, the guard's raw response.

Adapters report failures with two exceptions:

| Exception | When | Effect |
|---|---|---|
| `GuardError` | One case failed: timeout, HTTP 5xx, unreadable response, non-zero exit | The case is recorded as `error` and the run continues |
| `GuardConfigError` | The guard cannot be used at all: HTTP 401/403, cannot connect, command not found | The run stops, no report is written, exit code 2 |

Any other exception raised by an adapter is also recorded as `error`, so an adapter bug is never counted as allow or deny.

## `command`

```bash
lelu-eval run --cases PATH --adapter command --command "python my_guard.py" [--timeout 10]
```

For each case, `lelu-eval` starts the command (split like a POSIX shell would, without running a shell), writes the case as one JSON object to stdin and closes stdin. Fields the case does not set are left out.

The command must exit with status 0 and print the decision on the first line of stdout. Case and surrounding spaces are ignored (`Deny` works). Any further lines are kept as the reason.

```
deny
matched rule 'no-force-push'
```

A non-zero exit status, a timeout, or a first line that is not `allow`, `deny` or `review` is recorded as an error for that case, with the last part of stderr as the message.

## `http`

```bash
lelu-eval run --cases PATH --adapter http --url http://localhost:9000/check [--decision-field decision] [--timeout 10]
```

For each case, `lelu-eval` sends `POST <url>` with the case as a JSON body (unset fields left out). The response must be a JSON object. The decision is read from the top-level field named by `--decision-field` (default `decision`). A string `reason` field is kept if present.

```json
{"decision": "review", "reason": "amount above auto-approve limit"}
```

HTTP 401/403 or a connection failure stops the run. Other 4xx/5xx statuses, non-JSON bodies, a missing decision field or an unknown value are recorded as errors for that case.

## `lelu`

```bash
lelu-eval run --cases PATH --adapter lelu [--base-url http://localhost:8080] [--api-key KEY] [--timeout 10]
```

Request: `POST {base-url}/v1/agent/authorize` with header `Authorization: Bearer <key>` (from `--api-key`, otherwise `LELU_API_KEY`; no header if neither is set) and body:

```json
{"actor": "...", "action": "...", "confidence": 0.9, "args": {...}, "resource": {...}}
```

`resource` is the case's `context`. Fields the case does not set are left out.

Response mapping, checked in this order:

1. `requires_human_review` is true: `review`.
2. `compute` is true: `allow`, with `compute=true, treated as allow` added to the reason.
3. `allowed` is true: `allow`; `allowed` is false: `deny`.

If `allowed` is missing or not a boolean (and neither flag above is true), the case is recorded as an error. The full response, including `review_id` and `trace_id`, is kept as `raw`.

## Writing a new adapter

Implement `name` and `decide()`, raise `GuardError` for a failed case and `GuardConfigError` when nothing can work. The CLI only knows the three built-in adapters; to use your own class, call the library directly:

```python
from lelu_eval.loader import load_cases
from lelu_eval.runner import run_cases
from lelu_eval.metrics import compute_metrics
from lelu_eval.report import RunReport, render_markdown

results = run_cases(MyGuard(), load_cases("datasets/sample").cases)
print(render_markdown(RunReport("my-guard", "datasets/sample", compute_metrics(results))))
```
