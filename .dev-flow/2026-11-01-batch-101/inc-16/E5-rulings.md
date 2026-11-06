# Inc 16 — E5 rulings (orchestrator, 2026-11-06)

Inputs: `E5-mutants.md` (DeepSeek: **35/35 KILLED**, every row's negative control plus two E4 controls), `E5-code-review.md` (code-reviewer **PASS-WITH-NOTES**, 5 MINOR, 6 NIT; it carried the security lens — no separate security reviewer for a docs increment; security clean), `E5-coverage-audit.md` (qa-reviewer: 52 cases, 3 marks changed = 5.8 %, 4 git-history cases with no transcript). No BLOCKER/HIGH/MAJOR open. Rulings:

| Id | Ruling | Why |
|---|---|---|
| C-1 | Move every case's marks in `02-test-cases.md` to the audited values; cite `E5-mutants.md` for the 29 controls the audit marked pending (now all RED). | The record shows the audited state. |
| C-2 (F-1, design-gap) | Fix `docs/architecture.md:163` runtime dependencies (add `markdown-it-py`, as `pyproject.toml` declares) and §8's marker list (add `serial_timing`); amend the row(s) that state them. | Doc must match the shipped packaging and markers. |
| C-3 (F-2) | Replace the hard-coded counts (`== 3` dependencies, `== 15` example cases) with comparisons against the source of truth (`pyproject.toml` dependencies; the tracked example folders). | A correct future addition must not turn a guard RED. |
| C-4 (F-3) | DEV.11's guard checks all 13 window labels (read from the tracked source text, no import). | The guard must catch a dropped label. |
| C-5 (F-4) | ARCH.4/2 reads only the architecture doc, not `flow_screens.py`'s docstring; the stale docstring stays routed to Inc 9 (BACKLOG row I-7). | A docs guard must not break the next increment's legitimate docstring fix. |
| C-6 (F-5) | Fix the `CLAUDE.md:69` hex-renderer path to `s19_app/render/hexview.py`. | Accuracy. |
| C-7 (F-6 … F-11 NIT) | Fix the "XML" mention, the case_08 description and the dated file count; leave duplicated helpers; make the `root` false RED skip-proof only if it is a one-line change, else note it. | Cheap accuracy fixes; no test churn. |
| C-8 (audit REF.5/1 partial, ARCH.1/2 conflict, DEV.1/1 and ARCHIVE.2/2 text) | REF.5/1: per-occurrence check if local, else `partial` with the reason. ARCH.1/2: the case's expected text matches the validator's actual output (root `setup.py` is a known orphan line) — record correction, coverage `covered` when the test asserts that exact text. DEV.1/1, ARCHIVE.2/2: case text fixed to what the tests check. | Expected results must be exact. |
| C-9 (audit: 4 git-history cases with no transcript) | Run them on the LAN host and cite the transcripts. | A result counts only for a cited run. |
| C-10 (outside the diff) | 48 older `.dev-flow/` records hold a drive path and 14 the local account name; `BACKLOG-CODE.md` holds two cloud-drive path lines. → one backlog row (redaction pass over older batch records), flagged to the operator. | The repository is public; history keeps the text; out of this increment's rows. |

Corrective: one Opus pass (docs, guard tests, records; source edits stay comment-only). Re-audit: only the cases C-2 … C-9 touched.

## Re-audit rulings (2026-11-06)

Re-audit: **PASS-WITH-NOTES**, no mark changed.

- **RA-1 (ARCH.5/2):** stays `full`/`covered`; the three clauses' own negative controls are owed (the row's mutant was killed; the auditor's in-memory check is not a cited run and is not used as evidence). Recorded as owed in `04-validation.md` and as a backlog line. Why: the test asserts all three clauses; what is missing is a control, not coverage.
- **RA-2 (notes):** the `02-test-cases.md` header names who ran the tests; `e5c-10` is cited by commit hash in the close records.

## Close ruling (2026-11-06)

- **TR-1 (trace_check `1 gap`: TEST R-DOC-ARCHIVE.2):** ruled, not fixed. R-DOC-ARCHIVE.2 is local to this increment by E1 ruling D-1 (a one-time move, not folded into the canon). Its two cases are verified by E5 transcripts (`e5c-08` with its oracle control `e5c-09`, and the `git diff c2cba35` transcript for ARCHIVE.2/1). A standing test would re-check a past move against a fixed base commit, which a shallow CI clone cannot hold; naming the id in an unrelated test docstring would claim a verification that does not exist. Final trace line: `trace_check: 3 US, 32 active requirements (0 withdrawn), 1 gap(s)` — the one gap is this ruled row.
