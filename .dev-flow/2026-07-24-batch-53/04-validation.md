# 04 — Validation · batch-53 (FB-P1 flow.json persistence)

**Verdict: PASS.** 0 batch-53 regressions; both final gates (security + qa) 0-HIGH; `tui-ci` green.

## Test ledger
| | count |
|---|---|
| tests_base (`4f4f20f`) | 1870 (non-slow; the 19 tc016s snapshots already failing at base) |
| tests_added (batch-53) | 47 (`test_flow_persistence.py` 40 + `test_tui_flow_persistence_ui.py` 7) |
| tests_deleted | 0 |
| tests_post (`87283db`) | 1917 passed / 2 skipped / 3 xfailed / **19 failed** |

## The 19 failures — proven pre-existing (not a batch-53 regression)
All 19 failures are `test_tc016s_density_layout_snapshot[...]` (workspace/a2l/mac/issues ×{compact,comfortable} @120x30+160x40, plus map/patch/diff comfortable-120x30). **Differential proof:** a fresh `git worktree` at the batch base `4f4f20f` (zero batch-53 code) runs the SAME 19 `tc016s` failures (19 failed, 10 passed). They are the batch-58/59 + #128 CRC-snapshot drift already tracked in `.dev-flow/BACKLOG.md` (a `continue-on-error`/advisory CI job). batch-53 touches none of those screens; its only global CSS change is *additive* new classes.

## Per-increment gates (all green)
| Increment | Commit | Gate |
|---|---|---|
| Inc-2 save/list/import | `2f9607b` | 37 tests; 2 move-aside RED-verified (C-12 discriminator, AMD-4 cap); ruff; frozen guards |
| Inc-3 UI | `a749054` | 6 pilots; **C-34 full `test_tui_directionb.py` = 185 pass 0-reg**; C-38 union sweep (3 isinstance sites handle ReportBlock); ruff |
| Inc-4 dirty-guard | `637dc9d` | AT-005 counterfactual RED-verified (Cancel-that-loads → RED); frozen guards |
| Hardening | `87283db` | 40 persistence tests; F1 V7 drive-relative arm RED-verified; ruff |

## Final gates (over the whole batch diff `4f4f20f..HEAD`, independent subagents)
- **security-reviewer: 0-HIGH — OK to ship.** Untrusted loader fail-closed whole-flow, size-cap-before-parse, type-strict + strict-keys, reused-not-forked guard, drive-relative READ-ref closed, write side contained by `sanitize_project_name` + size-bound `copy_into_workarea`, all UI file-derived strings `safe_text`+`markup=False`. 1 LOW (F1 V7 output_name drive-relative asymmetry) — **folded** into `87283db`.
- **qa-reviewer: 0-HIGH — PASS.** Every load-bearing arm non-vacuous (field-by-field AT-001, C-12 discriminator, AMD-6 census `battery_codes ⊇ REJECTING_CODES`, C-32 painted quarantine, C-17 literal-text + `spans==[]`, AT-005 counterfactual). RB scope honored (no test exercises report content generation). 3 MAJOR defense-in-depth: M-1 (per-branch output_name) + M-2 (cap boundaries) **folded** into `87283db`; M-3 (static `from_markup` scanner over `render_quarantine`) **deferred → FB-P1b** (behaviourally covered by AT-006 `spans==[]`).

## Evidence checklist
- [x] Full non-slow suite run @ merge tip — 1917 passed, differential-proven 0-regression.
- [x] Requirement ATs owned by tests (see `06-docs/traceability-matrix.md`).
- [x] Security 0-HIGH over the batch diff.
- [x] QA 0-HIGH over the batch diff.
- [x] `tui-ci` green on PR #129; `snapshot` advisory-fail expected (pre-existing 19).
- [x] Engine-frozen guards green (0 frozen files touched).
