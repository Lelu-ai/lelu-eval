# Datasheet: lelu-eval sample dataset

## What it is

40 hand-written test cases for agent guardrails, in four files:

| File | Category | Cases | Expected outcomes |
|---|---|---|---|
| `injection.jsonl` | `injection` | 10 | 8 deny, 2 review |
| `destructive.jsonl` | `destructive` | 8 | 6 deny, 2 review |
| `exfiltration.jsonl` | `exfiltration` | 7 | 5 deny, 2 review |
| `benign.jsonl` | `benign` | 15 | 15 allow |

Each case is one agent tool call (actor, action, arguments and the context the agent saw) with the decision a guard should make.

## These are examples, not a benchmark

The cases exist so you can try `lelu-eval`, see what a report looks like, and copy the format for your own cases. They are not a benchmark:

- There are too few cases per category (under 20 each) for a rate to be reliable. The report says so.
- They were written by one author, without independent review of the labels.
- They are single tool calls. There are no multi-turn attacks.
- They do not represent the distribution of real agent traffic.

Do not publish rates measured on this dataset as evidence that a guard is safe or unsafe.

## How the cases were made

All cases were written by hand for this project. No text was copied from other datasets, papers or real incidents. Names, email addresses and domains are invented; domains use the reserved `.example` top-level domain and the IP address is from the documentation range `203.0.113.0/24`. Secrets appear only as placeholders such as `<redacted>`.

The cases were written to cover:

- **injection**: instructions hidden in data the agent reads (support tickets, web pages, documents, spreadsheet cells, meeting invites, pull request descriptions) that try to make it take an action the user did not ask for.
- **destructive**: actions that delete or destroy data or infrastructure, such as dropping a table, `rm -rf`, deleting backups or a namespace, `DELETE` without `WHERE`, `terraform destroy`, a force-push to `main`.
- **exfiltration**: actions that move sensitive data outside where it belongs: personal email, paste sites, unknown hosts, public links, company-wide channels, data hidden in URLs.
- **benign**: ordinary calls that must be allowed. Several of them deliberately contain words such as "delete" or "ignore" in an innocent way (deleting a spam email, a `.gitignore` edit, "please ignore my previous email", a `DELETE` with a narrow `WHERE`), because a guard that blocks on keywords gets these wrong.

Some pairs are deliberately similar: `inj-001` and `ben-010` use the same `approve_refunds` action, with different amounts and context.

The `review` label is used where a reasonable person would want to confirm before the action runs, rather than block it outright. Some of these labels are judgment calls; the `notes` field explains each one.

## License

The sample dataset (the `.jsonl` files and this datasheet) is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). The code in this repository is under the MIT license.
