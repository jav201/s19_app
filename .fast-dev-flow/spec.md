# fast-dev-flow spec — R-043-3: retire the dead-written issue-precompute path (batch-30)

- **Status:** draft 2026-07-09
- **Created:** 2026-07-09
- **Branch:** `claude/batch-30-retire-precompute` @ `7dcaa22` (origin/main = batch-29 merge)
- **Route:** /fast-dev-flow (dead-code cleanup follow-up; operator chose fast over full V-model — no new user behavior)
- **security_required:** false (see §6)

## 1. Objective
Retire the issue-DataTable precompute path that batch-29 orphaned. When batch-29 removed the `#validation_issues_list` DataTable and its `_populate_issues_datatable` consumer, `precompute_issue_datatable_payload` was deliberately KEPT as a tracked-orphan (follow-up **R-043-3**). It is now confirmed dead work: the load worker still calls it (`app.py:6525`, `:7037`) and writes `_validation_issue_cell_rows` / `_validation_issue_cell_styles` (`:6526`, `:6831`) + the prepared-payload dataclass fields `issue_cell_rows` / `issue_cell_styles` (`:432-433`), but a grep finds **no reader** — the grouped panel builds its own cells via `safe_text` + `css_class_for_severity`. Remove the whole dead chain.

## 2. Loose user story
As a maintainer, I want the orphaned issue-precompute + its caches + dataclass fields gone, so the load worker stops doing per-load formatting work whose output is never read and the codebase carries no dead path masquerading as live.

## 3. Scope
**IN (all verified dead on `7dcaa22`):**
- `precompute_issue_datatable_payload` — def `app.py:752`; calls `:6525`, `:7037`; docstring ref `:538`.
- prepared-payload dataclass fields `issue_cell_rows` / `issue_cell_styles` — `app.py:432-433` + population `:7068-69`.
- self attrs `_validation_issue_cell_rows` / `_validation_issue_cell_styles` — init `:934-935`; resets `:6219-20`, `:6314-15`; assigns `:6526-27`, `:6831-32`.
- orphaned formatter TCs — `test_tc021_precompute_payload_emits_related_cell` + the eight-columns-and-styles TC (across `test_tui_app.py` / `test_tui_directionb.py` / `test_tui_issues_view.py`; software-dev locates and retires only tests that exclusively exercise the removed symbols).

**OUT:** any behavior change to the Issues screen; the canonical-CI snapshot regen (separate track); R-044-6 (deferred); any engine-frozen module.

## 4. Acceptance criteria (observable)
- **AC-1 (behavior unchanged, black-box):** When an S19+A2L carrying validation issues is loaded and the Issues screen opened under Pilot, `#validation_issues_groups` renders the same `IssueRow` set (same codes + severities) as before the change. A pilot AT observes the shipped grouped surface.
- **AC-2 (dead code gone):** `grep -rn "precompute_issue_datatable_payload\|_validation_issue_cell_rows\|_validation_issue_cell_styles\|issue_cell_rows\|issue_cell_styles" s19_app/` returns **0 hits**.
- **AC-3 (frozen clean):** `git diff origin/main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py s19_app/validation s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py` is **EMPTY**.
- **AC-4 (suite green):** full suite passes (0 failed); the orphaned formatter TCs are removed; no remaining test references the deleted symbols (`grep` clean in `tests/`).

## 5. Design
Pure deletion, no new abstraction. Remove the dead chain: the two worker call-sites → the function → the dataclass fields + their population → the self-attrs (init/reset/assign) → the orphan tests. Confirm the live grouped path (`_render_validation_issues_groups` → `GroupedIssuesPanel`) is untouched. Likely 1–2 increments (`app.py` + up to 3 test files); watch `≤5 files`.

## 6. Security
**security_required: FALSE.** Sensitive-pattern scan (auth / secrets / external-integration / PII / destructive-DB / input-surface / network): **no match**. This is a pure internal deletion — it removes code and adds no surface. No security gate needed.

## 7. Route + authorization
Operator chose /fast-dev-flow (dead-code cleanup, no derivable new behavior — full V-model would be over-ceremony). Standing authorization for batch-30: run autonomously through commit → PR → independent code-review → MERGE to main, same guardrails as batch-29 (full suite + engine guards + code-review all GREEN before merge; 0 frozen diffs); report decisions at the end.
