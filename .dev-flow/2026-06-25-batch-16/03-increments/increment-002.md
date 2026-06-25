# Increment 2 (FINAL) — Per-variant assignment UI (US-017 / LLR-017.3)

**Batch:** 2026-06-25-batch-16 · **Branch:** claude/batch-16-gap2 · **Status:** awaiting gate · **Not committed.**

## 1. What changed
Added the operator UI that populates the composition Inc 1 already threads. `SaveProjectScreen` renders a project-wide `batch` `SelectionList` + one per variant (D-NEWPROJ-gated to existing-project re-save), offering ONLY top-level in-project `.json` change/check docs (excludes `project.json`, D-SCOPING). Each assignment key is sourced from `variant_id` (by row index into the variant set), NEVER `Path.stem` (D-KEY). `action_save_project` passes the variant ids + candidate files into the screen. The design fork resolved cleanly — `action_save_project` already has `self._variant_set` + the project dir in scope (no load-pipeline refactor).

## 2. Files (4; ≤5)
`s19_app/tui/screens.py` (SaveProjectScreen + `_collect_composition`), `s19_app/tui/app.py` (`action_save_project` wiring + `_assignment_candidate_files`), `s19_app/tui/styles.tcss` (`.assign-list`), `tests/test_tui_manifest_save.py` (TC-304/305/306).

## 3. How to test
`pytest tests/test_tui_manifest_save.py -q` · `pytest -q -m "not slow"` · `ruff check s19_app/tui/screens.py`.

## 4. Test results
test_tui_manifest_save.py **13 passed**; full non-slow **879 passed / 0 failed**; collection **929 → 932 (+3)**. screens.py ruff clean; app.py only pre-existing C-7 (not introduced). Spot-check: diff = 4 files (0 frozen/substrate), TC-304/305/306 + Inc1 AT-017.5 + duplicate-stem guard on disk.

## 5. Independent review
code-reviewer **APPROVE-WITH-NITS** (0 HIGH/0 MED/2 LOW). **D-KEY = YES** (`_collect_composition` keys from `variant.variant_id`, full filename on collision, no `Path.stem`); **D-NEWPROJ no-crash = YES** (gated; empty composition for new project, TC-306). 2 LOW: F1 (collision lacks an Inc-2 TC — but **AT-017.5 already ships in Inc 1**, confirmed on disk; F1 is moot); F2 (docstring nit). TC-305 genuinely asserts out-of-project + `project.json` exclusion.

## 6. Phase-3 complete (on approval)
2 increments: Inc1 (payload + handler threading + ATs, SCOPE-1 closed at the handler) / Inc2 (the UI). Ledger **922 → 932 (+10)**. 0 engine-frozen/substrate edits. US-017 end-to-end: operator assigns per-variant `.json` + batch at save → persists keyed by `variant_id` → re-reads 0-drift → applied by `plan_variant_executions`.

## Gate
0 HIGH; awaiting operator approval to commit Inc 2 → Phase 3 complete → Phase 4 (validation). Phase-4 carry: confirm AT-017.5 RED pre-fix / GREEN post-fix + reconcile provisional ids (V-5).
