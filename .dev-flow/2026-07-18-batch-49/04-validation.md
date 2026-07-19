# Validation — s19_app — Batch 2026-07-18-batch-49

> Phase 4 artifact. Two-layer model: Layer A white-box `TC-NNN`; Layer B black-box `AT-NNN`. Gate suite run + collected by the ORCHESTRATOR (C-25).

## ✅ Verdict (read first)
- **Gate:** **PROCEED to Phase 5.** 0 functional regressions; both validation layers green; all traceability chains complete.
- **Gate suite:** `pytest -q -m "not slow"` (orchestrator-run, 1159.76s / ~19min) → **1570 passed, 2 skipped, 20 deselected, 3 xfailed, 21 failed.** **All 21 failures are `test_tui_snapshot.py::test_tc016s_density_layout_snapshot` — the intended rail/strip visual drift (R-5/C-30), regenerated in canonical CI only.** 0 non-snapshot failures (grep-confirmed).
- **Baseline reconciliation:** base 1565 passed + ~26 new batch tests − 21 snapshots that flipped pass→(expected-drift)fail = **1570 passed** (exact).
- **Frozen guards:** `test_engine_unchanged.py` + `test_tc032` green across the batch — 0 engine source/test diffs.

## Layer A — white-box (TC → LLR/HLR)
Every LLR's TC executed green (per-increment + in the gate suite):
| LLR | TC | Result |
|---|---|---|
| 082.1–.6 | TC-082.1–.5 (+AT-082f C-17) | green (Inc-1: 75 passed affected suites) |
| 083.1–.6 | TC-083.* + R-2 census (test_tui_directionb.py 174 passed) | green |
| 084.1,.2,.4,.6 | TC-084.1/.2/.4/.10 + C-17 seed | green (Inc-2: 5 passed) |
| 084.3 | TC-084.3 (consumer guard TC-084.9) | green |
| 084.5,.7,.8 | AT-084c/f + TC-084.11 | green (Inc-4: 11 passed) |

## Layer B — black-box acceptance (AT → US, through the shipped surface)
| US | AT | Surface driven | Observed | Result |
|---|---|---|---|---|
| US-082 | AT-082a (GATE) | `#issues_severity_strip` | strip counts == independent `Counter(_validation_issues)` per-slot, asymmetric 3/1/2 | ✅ |
| US-082 | AT-082b/d/e | strip/summary | bar 0-arm; colored spans; zero-issues no-crash | ✅ |
| US-082 | AT-082c (GATE) | group headers | leading severity glyph | ✅ |
| US-082 | AT-082f (GATE, C-17) | issue cell | `.plain` verbatim + `spans==[]`, dual-token payload | ✅ |
| US-083 | AT-083a (GATE, C-10) | rail key `9` | active screen changed off default + `-active` marker | ✅ |
| US-083 | AT-083b | rail | other screen hides `#screen_checks` | ✅ |
| US-083 | AT-084a (GATE, C-12) | REAL `#patch_checks_run_button` → `#checks_grouped` | grouped fail→uncheckable→pass, distinct `sev-*`, fixture 2/1/3 first | ✅ |
| US-083 | AT-084b (GATE, C-31) | `#checks_aggregate_strip` | strip == `check_aggregates()` live | ✅ |
| US-083 | AT-084c (GATE, C-12) | `#checks_hex_pane` | fail-row select → aligned base `0x00000100` (AMD-2; TC-084.11 cross-checks `0x9000`) | ✅ |
| US-083 | AT-084d/e | `#screen_checks` | no-file EmptyStatePanel; file+no-run NO_RUN note (R-6 distinct) | ✅ |
| US-083 | AT-084f | `#screen_checks` | undo clears list+strip | ✅ |
| US-083 | AT-084g (GATE, C-17) | checks cell | `.plain` verbatim + `spans==[]` | ✅ |

**Bidirectional surface-reachability:** every input (loaded image, pasted check doc via real run button, injected `_validation_issues`, rail keypress, row-select) and every output (strip counts, grouped rows, hex peek, headers, empty states) exercised through the handler, not only service APIs. C-18: every AT maps to exactly one on-disk node.

## Snapshot-drift analysis (the 21 "failures" — NOT regressions)
All 21 are `test_tc016s_density_layout_snapshot[<screen>-<density>-<size>]`:
- workspace/a2l/mac ×4 (120/160 × compact/comfortable), map/patch/diff ×1 (comfortable-120) — **rail-only drift** (9th rail item redraws each screen at ≥120 cols; the rail is not rendered at 80×24, so those cells did not drift).
- issues ×6 (adds 80×24 both densities) — **rail + Inc-1 Issues MID strip/glyph/title drift**.
- The new `#screen_checks` is NOT in the density matrix (post-dates it) → no drift; its coverage is the behavioral AT-083/084 set. (Optional closeout: extend the matrix with `checks` cells.)
**Disposition:** regenerate these 21 baselines in canonical CI (`snapshot-regen.yml`, textual==8.2.8) — local regen forbidden (`reference_snapshot_regen_env`). This is the batch-closeout snapshot-regen step; expected + bounded (C-22/C-28 census predicted exactly this set).

## Feedback edges
None fired — 0 black-box failures, 0 white-box failures (excluding the intended snapshot drift). No `iterate-to-fix` / `iterate-to-refine`.

## Evidence checklist
- ✅ One complete gate-suite run, evidence read from its own output (C-19/C-25): 1570 passed / 21 snapshot-only failed / EXIT captured.
- ✅ 0 non-snapshot failures (grep `^FAILED | grep -v test_tui_snapshot` → empty).
- ✅ Every AT observed through the shipped surface with representative + boundary + negative evidence.
- ✅ Frozen dual-guard green.
- ✅ No unfilled template placeholders; results are executed, not intended.
