"""A deliberately naive guard, for trying out lelu-eval without a real guard.

It reads one case as JSON on stdin and prints a decision (allow, deny or review)
on the first line of stdout, followed by a one-line reason.

It only looks for keywords, so it makes mistakes on purpose: it blocks harmless
calls that mention "delete" and misses attacks that use other words. Do not use
it to protect anything.

Usage:
    lelu-eval run --cases datasets/sample --adapter command \
        --command "python examples/fake_guard.py"

Pass ``--policy v2`` for a "changed" policy that adds one over-broad keyword. It
catches more injections but also blocks a harmless case, which is what
``lelu-eval diff`` is for (see examples/lelu-eval.yaml).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

DENY_KEYWORDS = (
    "ignore previous instructions",
    "drop table",
    "rm -rf",
    "delete",
    "credentials",
    "destroy",
)
V2_EXTRA_KEYWORDS = ("assistant",)
REVIEW_ACTIONS = ("send_email", "upload_file", "share_document", "git_push")
REVIEW_AMOUNT = 1000

# Fields that describe the label, not the tool call. A guard must never see them.
LABEL_FIELDS = ("id", "expected", "category", "source", "notes")


def decide(case: dict[str, Any], policy: str = "v1") -> tuple[str, str]:
    call = {key: value for key, value in case.items() if key not in LABEL_FIELDS}
    text = json.dumps(call).lower()
    keywords = DENY_KEYWORDS + (V2_EXTRA_KEYWORDS if policy == "v2" else ())
    for keyword in keywords:
        if keyword in text:
            return "deny", f"matched keyword {keyword!r}"
    if case.get("action") in REVIEW_ACTIONS:
        return "review", f"action {case['action']!r} always needs review"
    amount = (case.get("args") or {}).get("amount")
    if isinstance(amount, int | float) and amount > REVIEW_AMOUNT:
        return "review", f"amount {amount} is over {REVIEW_AMOUNT}"
    return "allow", "no rule matched"


def main() -> None:
    parser = argparse.ArgumentParser(description="A deliberately naive example guard.")
    parser.add_argument("--policy", choices=["v1", "v2"], default="v1")
    policy = parser.parse_args().policy
    outcome, reason = decide(json.load(sys.stdin), policy)
    print(outcome)
    print(reason)


if __name__ == "__main__":
    main()
