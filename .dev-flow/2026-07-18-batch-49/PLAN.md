# PLAN.md — batch-49 (living compendium)

**Batch:** `2026-07-18-batch-49` · **Branch:** `feat/batch-49-issues-checks-reports` · **Base:** `origin/main` @ d2152ce (RC-1 clean, 0/0)

## Where we are
Phase 3 (implementation) — starting. Phase 2 triple review PASS-WITH-NOTES → PROCEED: 0 blockers, 3 major + 9 minor ALL folded (02-review.md + §6.4 REC-3); architect grep-verified all 40+ citations correct. Holding Inc-1 dispatch until the baseline suite confirms green (test-count ledger). Increment cut confirmed (Inc-1 Issues MID · Inc-2 CHECKS data+widgets · Inc-3 rail+screen+nav [owns full R-2 census] · Inc-4 render/hex/empty/wiring · Closeout regen).

## Phase-2 fold highlights (hardened before code)
- AT-082a: asymmetric 3/1/2 + independent oracle (bucket `_validation_issues` by `ValidationSeverity`, per-slot).
- AT-082f/084g: `.plain` verbatim AND `spans==[]` + dual-token payload (`[/nope]`+`[link=...]`).
- R-2 census (Inc-3): `test_tui_directionb.py` :449/:488/:493/:506/:513/:698/:741/:779/:881 all → 9.
- New TCs: TC-084.10 (DoS mount cap), TC-084.11 (uncheckable/outside-image hex).
- AT-084c: assert the address `0x102` (image all-`0x00`).

## Requirements summary (Phase-1 output)
- **HLR-082 (R-TUI-082) Issues MID:** severity strip + group-header glyph + pane border-titles + colored summary (render-only). LLR-082.1-.6.
- **HLR-083 (R-TUI-083) CHECKS rail+nav:** append rail key 9, `SCREEN_CONTAINER_IDS`, `9` binding, compose, `_compose_screen_checks`. LLR-083.1-.6. **C-26: rail-count==8 tests → 9.**
- **HLR-084 (R-TUI-084) CHECKS render:** `checks_view.py` (NEW), `check_display_rows()`+`CheckDisplayRow` accessor, `update_checks_view`, aggregate strip, hex peek, empty states (no-file vs no-run distinct), C-17. LLR-084.1-.8.
- Increment cut: Inc-1 Issues MID · Inc-2 CHECKS data+widgets · Inc-3 rail+screen+nav (owns C-26 test updates) · Inc-4 render/hex/empty/wiring · Closeout snapshot regen.

## Roadmap (provisional increment cut — re-cut after Phase-1/2)
- **Inc-0** — toolchain gate (ruff/mypy/pytest present) + base suite count; `insight_style.py` strip helpers (`build_issues_severity_strip`, `build_checks_aggregate_strip`) with unit TCs.
- **Inc-1 (US-082)** — Issues MID: severity strip in `_compose_screen_issues` + `update_validation_issues_view`; group-header glyph (`issues_view.py`); pane border-titles; colored summary. Files: app.py, issues_view.py, insight_style.py, styles.tcss (+test).
- **Inc-2 (US-083 rail+screen)** — rail append key 9 (`rail.py`), `SCREEN_CONTAINER_IDS`, `9` binding, `compose` insertion, `_compose_screen_checks` (app.py) + `checks_view.py` widgets. Files: rail.py, app.py, checks_view.py, styles.tcss (+test).
- **Inc-3 (US-083 wiring)** — `update_checks_view` + `_update_checks_hex_pane`; wire at load / post-run_checks / undo-redo / screen-activation; aggregate strip; empty-state registration + "no check run yet" note. Files: app.py, checks_view.py (+test).
- **Inc-4** — C-17 hostile-input ATs (both screens) + boundary/negative ATs; C-26 reverse-census + C-28 chrome/footer binding census; predicted snapshot-drift marks.
- **Final** — canonical-CI snapshot-regen follow-up PR.

## Objective
1. **Issues Report screen — MID visual insight upgrade** (render-only), matching the batch-47 Workspace/A2L/MAC cohort idiom (zebra, severity glyphs, colored counts, count strip, border titles). No engine/parse change.
2. **New dedicated CHECKS rail screen** — parallels the Issues Report screen: grouped pass/fail/uncheckable, colored, hex peek, empty state, rail nav binding.

## Standing authorization (per-batch, 2026-07-18)
- Operator: *"Do the issues report and checks report, go on autonomously."*
- **Autonomy:** end-to-end; agent self-approves every gate.
- **Merge authority:** interpreted as GRANTED (‘go on autonomously’ + post-48 precedent of autonomous self-merge). Merge gated on: green CI + final independent PR-level qa-reviewer pass over whole diff vs main. HIGH finding → blocks merge, returns to operator.
- **Decision recording:** every un-asked decision → this decision log + state.json + 05-postmortem, carried to vault at sync.

## Scope decisions (locked via AskUserQuestion, 2026-07-18)
- Issues Report → **MID** tier (not BIG, not export).
- Checks Report → **NEW dedicated CHECKS rail screen** (not export, not just a Patch Editor window upgrade).

## Key design decisions (RESOLVED)
- **CHECKS screen data source — RESOLVED (Agent A recon).** Sole source = `S19TuiApp._change_service.last_check_result` (`CheckRunResult | None`), via accessors `check_rows()` (colored rows) + `check_aggregates()` (pass/fail/uncheckable counts). Severity/color already flow through `css_class_for_severity` (pass→OK, fail→ERROR, uncheckable→WARNING). **Checks are NOT computed on load** — only after the Patch Editor `run_checks` action; reset to `None` on undo/redo. No expected-bytes to verify without a loaded check document → inherent.
  - **DESIGN:** CHECKS screen = **read-only grouped mirror** (option 1) — grouped fail→uncheckable→pass, colored, hex peek, honest "no check run yet" empty state. Reuses existing accessors + reset semantics; NO engine change. Parallels how Issues screen is the dedicated grouped view of `_validation_issues`.
- **Rail registration — RESOLVED.** Rail is a fixed 8-entry tuple keyed `1`–`8` (`rail.py:78`). **APPEND `"checks"` at key `9`** (order …flow, checks) to avoid renumbering keys 6–8. Every "eight screens" reference/binding/footer/help/empty-state/rail-count test drifts → C-26 reverse-census each touched symbol; C-28 chrome/footer census; snapshot regen canonical-CI only.
- **C-17:** `linkage_symbol`, `run_blocked_reason`, `ValidationIssue.symbol` file-derived + unscrubbed → new CHECKS surface MUST use `markup=False` / `safe_text` (mirror `screens_directionb.py:4770`).

## Conventions honored (from CLAUDE.md / handoff plan / engineering-rules)
- Engine-frozen set untouched (core/hexfile/range_index/validation/mac.py/color_policy.py; a2l.py unfrozen but not in scope). C-27 dual-guard each increment.
- New insight code in non-frozen `insight_style.py` (batch-47 module) + `styles.tcss`; render-only.
- C-17 markup-safety for all file-derived strings (issue codes/symbols/messages; check symbols/reasons) via `safe_text`.
- Severity color via frozen `css_class_for_severity` — no hard-coded hex in logic.
- Snapshot drift expected (massive) → regen ONLY in canonical CI (snapshot-regen.yml, textual==8.2.8), never local. Follow-up PR.
- Docstrings: Summary→Args→Returns→Raises→Data Flow→Dependencies→Example. Type hints mandatory.

## Roadmap (increments — provisional, re-cut after Phase 1)
- Inc-0: toolchain gate + any shared insight_style helper additions.
- Inc-1: Issues Report MID upgrade (render-only over GroupedIssuesPanel + summary + filters).
- Inc-2..N: CHECKS screen — compose + rail registration; grouped checks view widget; data wiring; hex peek; empty state; C-17 tests.
- Final: snapshot census + expected-drift marks (regen in CI).

## Risks / watch-items
- **Data-availability of checks** (crux above) — may force a "run checks to populate" empty state, or a load-time check computation.
- Rail registration touches many sites (bindings, footer, help panel, empty-state list, screen-switch) — reverse-census (C-26) each touched id.
- Snapshot baseline drift is large by design; must not regen locally.
- New screen = new bindings → footer/help-panel binding-drift census (C-28).

## Out-of-scope carries
- Issues filter/sort BIG-tier controls (operator picked MID). · Patch Editor CHECKS window is separate (already has pass/fail strip from batch-48). · Flow Builder CHECK blocks. · P-2 re-freeze a2l.py (separate item).

## Test ledger
- **Base (origin/main d2152ce, 2026-07-18):** `pytest -q -m "not slow"` → **1565 passed, 2 skipped, 20 deselected, 3 xfailed, 29 snapshots passed, EXIT=0** (~19 min). Clean green — no pre-existing failures. Toolchain: pytest 8.4.2, ruff 0.8.4, py3.14 local / py3.11 CI.
- Per-increment: `post = base − D + A`, reconciled each gate.

## Snapshot-drift carry (regen in canonical CI only, ONE pass at closeout)
- Inc-1: 6 Issues baselines drift — `issues-{compact,comfortable}-{80x24,120x30,160x40}` (containment proven: workspace/mac/a2l 18 passed). Inc-3 rail change will also drift these + all screens → single canonical regen after merge.

## Env learning
- Subagent `.output` files stay 0 bytes in this harness (results arrive via completion notification, not file growth) → byte-size liveness monitoring is a false signal. Use source-file mtime or the completion notification. (Save to memory at closeout.)

## Decision log
- 2026-07-18 · Phase 3 · Inc-1 (Issues MID) implemented: 4 files, +10/−0 tests, 13 passed, ruff clean, frozen dual-guard 0 diffs, directionb regression 24 passed, RED counterfactual captured (AT-082a/082c). code-reviewer gate in flight. 6 Issues snapshots expected-drift (CI regen owed).
- 2026-07-18 · Phase 0 · Scope locked via AskUserQuestion (Issues MID; new CHECKS screen). Branch cut off d2152ce. Authorization recorded (autonomy + merge-under-final-QA).
