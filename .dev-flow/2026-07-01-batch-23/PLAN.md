# PLAN.md — batch-23 (living compendium)

> **#8 patch-editor overhaul — FINAL story. US-028: inline variant dropdown** in `#patch_pane_variant` (the batch-22 2×2 bottom-right pane). Closes #8. Full `/dev-flow`. Inline-paste at gates.

## Where we are
- **Phase 6 — Documentation.** `awaiting-gate`. 06-docs complete (matrix zero-gap w/ current-tree re-verified anchors · functionality · 3 Mermaid flows · exec summary). Phase 5 `approved`: **C-15 ENCODED** (symbol-identity + sweep-back) + repo-hygiene sync-checklist line (operator-directed ×2); CC-3 watch stays at 2. docs-writer cross-read caught 2 sweep-back-class staleness items in our own artifacts → fixed (05 addendum, 05b note). BACKLOG refreshed (#8 CLOSED, #12 → P1 NEXT). Next: operator approval → commit ×2 → push → PR → operator merge → `/dev-flow-sync`.
- Phase 5 `approved` (scorecard 21 findings / 71% caught-P2; clean 1-iteration run; #8 closed).
- Phase 4 `approved` (PASS; 971/0-fail on f5f8111). qa-reviewer VERDICT **PASS**: V-5 reconciled 1:1 (11 real nodes), QC-3 catalog + bidirectional matrix ZERO gaps, thresholds audited against the actual asserts, gates black-box. §6.5 amendments recorded (A-6.5-1 Select.NULL spec-wide · A-6.5-2 AT-035b proj2 drive · A-6.5-3 TC-035.2 compositor-mapping) — body edited first, sentinel corrected across both artifacts (8 replacements).
- **Mid-batch concurrent-agent episode (operator-deployed, resolved):** PR #37 (change-file `Select.NULL` guard + regression) merged `a4ab8ba`; PR #38 de-conflicted to its unique AbDiff fix + test, merged `f5f8111`. Batch-23 branch ff'd `c6f75aa → f5f8111` (stash/pop, 1 docstring conflict merged); integration 138/138. FLAG: primary repo checkout left on the #38 branch by the 2nd agent (operator to restore).
- Phase 3 `approved` — COMPLETE (1/1 increments; 991→1002). Implemented per LLR-035.1–.7; code-reviewer APPROVE-WITH-NITS (F1/F2 folded, F3 observation); FULL suite 969/0-fail; **991 → 1002 (+11)**; frozen 0-diff; counterfactual RED captured. 2 verified deviations: **Select.NULL** (spec's `Select.BLANK` is a `False`-bool trap on textual 8.2.5 — pre-existing US-026 dead filter chipped as background task) + **AT-035b proj2 drive** (same-proj re-save dedup-collides; C-12 power intact). LLR-035.7 = suppress-while-loading. A-1 resolved by measurement (no sacrificial Label).
- Phase 2 `approved` (was `awaiting-gate`). PROCEED ×3 (architect/qa/security). 1 BLOCKER (F-1, resolved-by-verification) + 4 MAJOR + 9 MINOR — **all folded pre-gate** (§6.4, 9 rows). Requirements now **7 LLR** (new LLR-035.7 race guard) / 3 AT / TC-035.1–.7 canonical. `should`-scan post-fold 0 hits.
- Phase-2 headlines: **F-4** `set_options` resets selection → repopulate emits `Changed(BLANK)`+`Changed(active_id)` (framework-surprise class, caught pre-code); **SEC-F2** switch-during-load race → LLR-035.7 + TC-035.7; **qa-M1** my TC-fold-in claim incomplete → TC-035.1/.6 rows added; **R-1 resolved** (label app-global, hex needs workspace hop). Census PASS concrete. Containment: no US-026-F1 analogue needed (`copy_into_workarea` chokepoint stronger).
- Phase 1 `approved`. Phase 0 `approved` (Q1 disabled+placeholder · Q2 persist-on-save).
- Carries → BACKLOG at close: SEC-F1 symlink dead-option parity hardening (optional, pre-existing).

## Requirements skeleton (Phase 1)
- **HLR-035** — inline variant switch: dropdown → existing `_handle_select_variant` pipeline → label+image reflect chosen variant; `active_variant` persists only on next save.
- **LLR-035.1** compose (`#patch_variant_row` + `Select#patch_variant_select`, always present) · **.2** top-of-pane order (C-13 measured) · **.3** options refresh + active preselection (patch-screen activation, model order) · **.4** `VariantSelected` routing, wholesale guard reuse + BLANK/same-value echo-loop suppression · **.5** Q1 disabled/placeholder · **.6** Q2 no-new-write (byte-identical project.json pre-save).
- **AT-035a** C-10 switch (label `proj:b (2/2)` + hex content flips) · **AT-035b** C-12 persist chain (shipped save → re-read handler-written project.json → fresh-app load lands on `b`; direct-write test = guard only) · **AT-035c** negative (no-project + single-variant → disabled, state intact).
- **Inc plan:** single Inc1, 4–5 files (screens_directionb.py, app.py, NEW tests/test_tui_patch_variant.py, REQUIREMENTS.md §29, styles.tcss only-if-needed) + contingency split Inc1a/1b.

## C-13 MEASURED (2026-07-01 probe — replaces the `assumed` flag)
- `#patch_pane_variant` content_region: **35 × 3 rows @80×24** · **46 × 6 @120×30**.
- Existing execute group ≈4 rows; new Select group ≈3-4 rows → deficit ≈5 rows @80, ≈2 @120.
- Deficit-matched rung ALREADY SHIPPED: per-pane `overflow-y:auto` (batch-22) — unbounded vertical recovery.
- **Design consequence:** variant-select group composes ABOVE `#patch_execute_row` (affordance visible without scrolling @80×24). Width comfortable.
- Probe = temp pytest test (sync `asyncio.run` idiom), run + deleted; tree clean.

## Objective
Switch the project's active variant from a dropdown inside the patch editor — observable on the loaded image + project label, persisted as manifest `active_variant` on next project save (C-12 AT over the handler-written project.json). No modal round-trip.

## RC-1 base-currency gate — PASS
- `git fetch` → `origin/main` = **c6f75aa** (PR #36 hook fix merged). New branch `claude/batch-23-us028` cut at the tip; merge-base == tip.
- Carried (uncommitted → ride batch-23 first commit): batch-22 close snapshot (`.dev-flow/2026-07-01-batch-22/state-snapshot-at-close.json`) + the `obsidian_synced=true` state flip.
- Already-shipped check: REQUIREMENTS §11 = modal `SelectVariantScreen` (batch-07) + manifest persistence (batch-16) only — **no inline dropdown exists**. US-028 genuinely open.

## Verified intake facts (file:line)
- Activation path reusable wholesale: `_handle_select_variant` @app.py:2997 → `_pending_variant_id` @:3049 → load pipeline → `active_id` stamped @app.py:6146.
- Persistence free at save: manifest_writer.py:319 writes `"active_variant": variant_set.active_id`.
- Target pane `#patch_pane_variant` @screens_directionb.py:717-733 (currently: execute-over-variants row only).
- Pattern precedent: US-026 `Select#patch_doc_file_select` (options-rescan-on-show + `Select.Changed` → service).

## Key decisions
- Scope = US-028 only (operator: "vamos con /dev-flow para lo que sigue" → next queued P1 per BACKLOG sequence).
- Q1/Q2 pending at DoR gate (recommendations: disabled-with-placeholder; persist-on-save).

## Risks / watch-items
- **C-13:** Label+Select vertical cost (~3 rows) in the ~half-height pane @24-row terminal — `assumed — measure in Phase 1`.
- **C-10:** the AT must drive a NON-default variant and assert the change (label + image content), not confirm the default.
- **C-12:** persistence AT = dropdown switch → shipped save flow → re-read handler-written project.json → unmodified load consumes it. A direct-write manifest test is a guard, never the gate.
- Engine-frozen set untouched (pane + wiring only).

## Test ledger
- Base (origin/main c6f75aa): batch-22 closed at 991 collected non-slow; confirm at Phase-3 entry.

## Decision log
- 2026-07-01 P0: batch-23 init, US-028 scope, RC-1 PASS (c6f75aa), §2.6 written → DoR gate.
