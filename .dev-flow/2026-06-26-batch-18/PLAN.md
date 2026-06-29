# PLAN.md — batch-18 (living compendium)

## Where we are
**▶ RESUME POINT: Phase 3 — implementation, Increment 1.** Phases 0/1/2 DONE + gated. `state.json` = `phase 2, approved`. Branch `claude/batch-18` off `origin/main f3926b45` (RC-1 PASS). Spec ([01-requirements.md](01-requirements.md)) complete + cross-reviewed ([02-review.md](02-review.md)) + folds applied. **A new session resumes by running `/dev-flow`** (reads state.json → advances to Phase 3) or "continue batch-18".

### Resume cheat-sheet (everything a fresh agent needs)
- **Scope:** 2 stories — US-022 (Q1 report legend), US-023 (Q2 in-app Legend button + LegendScreen modal on A2L/MAC/Issues). One batch, **2 increments**: Inc1 = `s19_app/tui/legend.py` (NEW single source) + Q1 report legend + AT (≤5 files: legend.py, report_service.py, tests/test_tui_legend.py NEW, tests/test_report_service.py). Inc2 = Q2 LegendScreen + Legend button on 3 views + AT (screens.py, app.py, styles.tcss, test_tui_legend.py; + SVG snapshot regen in canonical CI only).
- **LOAD-BEARING constraint:** the shared `LEGEND_TABLE` lives in NEW `s19_app/tui/legend.py` — NOT `color_policy.py` (engine-frozen). Verify `git diff color_policy.py = 0` + keep the `tests/test_tui_directionb.py::_ENGINE_PATHS` (~:3745) frozen guard green (MAJOR-1).
- **THE RISK (C-13):** A2L button row `#a2l_tags_filters` already has 9 widgets (app.py:2390-2401) → a 10th Legend button at 80 cols is tight. MEASURE in Inc2 via `App.run_test(size=(80,N))`; fallback DECIDED: primary = shorten the A2L Legend label, last resort = key-binding. (MAC=2/Issues=3 → full "Legend" label fine.)
- **Per-increment discipline:** each AT shown RED under a counterfactual (C-10 assert verbatim colour→meaning content; C-12); independent `code-reviewer` per increment; ≤5 files; operator gate each increment; commits/PRs ONLY on operator approval.
- **Phase-3 test-authoring notes (from Phase-2):** operationalize "every row" = assert colour→MEANING pairing (blank-meaning legend must fail); TC-S2 compares the RENDERED row set of report vs modal (not just same constant).
- **Anchors (disk-verified):** report_service.py generate_project_report:913 / ReportOptions:141 (frozen+slots — bool field needs no __post_init__ change); screens.py ReportViewerScreen:472 (ModalScreen analog, modal-dialog/modal-buttons classes); app.py compose :2400/:2474/:1169, dispatch on_button_pressed:7433; color_policy.SEVERITY_CLASS_MAP:5 (frozen, READ); REQUIREMENTS.md §3 :356-391; styles.tcss sev-* :437-455.
- **Decisions baked:** module name `legend.py`; ONE shared modal (all 3 tables, not per-view filtered); modal over inline panel; `ReportOptions.include_legend` default True; diff-report run-kind colours OUT of scope.
- **Open carry (uncommitted, rides batch-18 first commit):** the batch-17 `obsidian_synced:true` flip is captured in `.dev-flow/2026-06-26-batch-17/state-snapshot-at-close.json` (untracked) + the batch-18 `.dev-flow/` scaffold is uncommitted — batch-18's first commit carries them (batch-13 pattern).

### Original Phase-0 context
RC-1 PASS off `origin/main f3926b45`; branch `claude/batch-18`. Feature #11 (Q1/Q2 legend) investigated.

## Objective
#11: surface the existing classification/colour semantics as a legend — (Q1) in the generated report, (Q2) via an in-app per-view "Legend" button. Content is DERIVED from the documented single source, never re-invented.

## Single source of truth (read-only inputs)
- `s19_app/tui/color_policy.py::SEVERITY_CLASS_MAP` (ENGINE-FROZEN) — severity→`sev-*` class.
- `styles.tcss:437-455` — the `sev-*` hex colours (green #5fb98a / red #e06c75 / orange #d9a35b / cyan #4ec9d4 / grey #6b7280).
- `REQUIREMENTS.md` §3 "Severity / colour conventions" — the A2L / MAC / Issues row semantics (Red/Green/White/Grey + MAC Orange).

## ⚠ Key Phase-0 finding (frozen-set constraint)
The natural home for a shared `LEGEND_TABLE` data structure is NOT `color_policy.py` — **that file is engine-frozen (read-only)**. The shared legend content must live in a **NEW non-frozen module** (proposed `s19_app/tui/legend.py`) that MIRRORS the documented semantics, consumed by both the report (Q1) and the in-app modal (Q2). This keeps one source without editing the frozen file. (The Explore agent's suggestion to extend `color_policy.py` would trip the engine-frozen guard.)

## Stories (Phase-0 classification)
| Story | What | Class | Size |
|-------|------|-------|------|
| US-022 (Q1) | legend section in the generated report (derived from `legend.py`) | **READY** | S–M (report_service.py + legend.py + test) |
| US-023 (Q2) | "Legend" button on the A2L / MAC / Issues views → a LegendScreen modal showing the classification tables | **READY** | M (screens + app.py + styles + test; 3 views + 1 modal) |

US-022c/d etc. — none. Scope is exactly Q1 + Q2.

## Surfaces (substrate map; frozen status)
- **Shared:** NEW `s19_app/tui/legend.py` — `LEGEND_TABLE` (A2L/MAC/Issues → {severity: (colour-name, meaning)}), mirroring REQUIREMENTS.md §3 + SEVERITY_CLASS_MAP. OUTSIDE frozen.
- **Q1:** `s19_app/tui/services/report_service.py` `generate_project_report` (+ a `_legend_lines` helper + `ReportOptions.include_legend`). OUTSIDE frozen.
- **Q2:** new `LegendScreen(ModalScreen)` (screens.py / screens_directionb.py) + a "Legend" button on `#screen_a2l` / `#screen_mac` / `#screen_issues` (app.py compose + on_button_pressed) + `styles.tcss`. OUTSIDE frozen. `color_policy.py` READ-ONLY.

## C-13 (geometry-budget) application
Q2 adds a button to each of three colour-coded views' button rows — verify each view's row has budget for one more button at the 80/120-col regimes (don't assume; measure), and the LegendScreen modal fits the small terminal. (The batch-17 lesson, now an encoded control.)

## Open decision (DoR gate)
1. **Scope shape:** (A) one batch, 2 increments — Inc1 = `legend.py` + Q1 report; Inc2 = Q2 (modal + 3 view buttons). (B) split Q1 and Q2 into separate batches. (C) one batch but Q2 per-view increments (legend.py+Q1, then A2L, MAC, Issues separately).
2. **Legend-data module name/placement** — proposed `s19_app/tui/legend.py` (confirm).

## Roadmap (pending gate)
Recommended: option A — Inc1 (legend.py single source + Q1 report legend + AT), Inc2 (Q2 LegendScreen + 3 view buttons + AT per view, C-13 geometry check).

## Conventions / controls in force
RC-1 (held), engine-frozen OFF-LIMITS (esp. color_policy.py — READ only), two-layer AT/TC + C-10/C-12, C-13 geometry-budget, draft-time verification, ≤5 files/increment, commits/PRs on approval.

## Risks / watch
- Frozen color_policy.py — legend data must NOT live there (finding above).
- C-13: 3 view button rows + modal geometry at narrow regimes.
- Single-source drift: Q1 + Q2 must read the SAME `legend.py` (don't duplicate the table in report vs modal).
- Snapshot SVG cells for the 3 views + report will shift → CI regen (G-1 pattern).

## Test ledger
Baseline (origin/main f3926b45): full non-slow 892 passed (carry forward; re-measure Phase 4).

## Decision log (mirror)
- 2026-06-26 — batch-18 init; Phase-0 done; frozen-constraint finding (legend.py not color_policy.py); awaiting DoR gate (scope shape).
