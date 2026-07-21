# 04 — Validation · batch-56 (alignment-aware padding sizing)

> **BLUF: PASS.** Both layers green. The orchestrator-owned gate suite (C-25) ran `pytest -q -m "not slow"` @ `6ba4c3b` → **1794 passed / 2 skipped / 3 xfailed / 19 failed (23:57)**. The 19 failures are ALL pre-existing `test_tc016s_density_layout_snapshot` cells (the batch-58/59 CRC-10th-rail chrome drift, cell-for-cell identical to batch-59's documented carry) — **0 are batch-56**; batch-56 added 0 snapshot drift, exactly as AT-114 predicted. Blocking CI (`tui-ci`, no snapshot plugin) is GREEN; the snapshot job is advisory (`continue-on-error`). 11 gate-blocking ATs realized to distinct on-disk nodes (C-18); both traceability chains complete.

## Layer B — behavioral (black-box), through `parse_a2l_file`
| AT | Outcome observed | Value | Node | Result |
|----|------------------|-------|------|--------|
| AT-113 | multi-class CURVE padded length + row memory-checkable | 16 (packed 13); grey→OK | `test_a2l_alignment_sizing.py` | ✅ (pre-fix RED = None captured) |
| AT-114 | demo unchanged + 0 drift | 25/51/12/None | " + snapshot census | ✅ (0 new drift; RED=MOD_COMMON→26) |
| AT-115 | R-A isolation | with 16 > without 13 ∧ without==13 | " | ✅ |
| AT-116 | unmodeled directive → None | None, no exc | " | ✅ |
| AT-117 | pad=0 boundary | 10 | " | ✅ |
| AT-118 | over-align (declared>natural) | 16 (RED 12) | " | ✅ |
| AT-119 | R-C no trailing pad | 17 (RED 24) | " | ✅ |
| AT-120 | DoS over cap | None, <1s | " | ✅ |
| AT-122 | hostile alignment value | `x`/`0`/`-4`→None, no exc | " | ✅ (zero-div guard) |
| AT-121 | re-freeze | — | PR-B | ⏳ post-merge |

**Bidirectional surface-reachability:** every input dimension {multi-class declared / packed / pad=0 / over-align / trailing geometry / unmodeled+alignment / oversized+alignment / hostile value} exercised through `parse_a2l_file`; outputs {padded length / packed length / None / A2L row severity} observed (AT-113 through the render consumer). Boundary (117/118/119) + negative (116/120/122) evidence present.

## Layer A — functional (white-box)
- TC-143 census (derived key-set AND value-set), TC-144 walk (16 + secondary 8), TC-145 collector (incl. `x`/`0`/`-4`→None), TC-146 `align_up` (incl. `a<=1` no-raise), TC-147 packed==batch-55, TC-148 MOD_COMMON-excl/full-span-or-None, TC-149 DoS, TC-150 R-C=17, TC-151 supersede (14/13/13), TC-152 unfreeze. **All green** (new suite 17 + batch-55 file 18 = 35 passed; targeted runs by software-dev AND code-reviewer independently).
- **C-18 realization gate:** every §2 AT maps to exactly ONE distinct on-disk node (code-reviewer hand-verified). 0 UNREALIZED.

## Frozen dual-guard (C-27)
- tc027/tc031 (source) + tc032 (test files): **7 passed**. a2l.py out of both `_ENGINE_PATHS` (unfreeze, PR-A); tc032-frozen `test_tui_a2l.py` untouched (empty diff vs main). Confirmed in the full gate run (tc031/engine-unchanged included and GREEN).

## Snapshot drift analysis (the 19 failures)
- All are `test_tc016s_density_layout_snapshot` on {workspace, a2l, mac, issues}×{compact,comfortable}×{120x30,160x40} + {map,patch,diff}-comfortable-120x30. This is the batch-58 CRC-10th-rail chrome shift (every screen's rail bar drifts), carried through batch-59 (its Phase-4 hit the identical 19). **NOT batch-56:** batch-56 touches only `_record_layout_full_span` sizing; the demo has no body `ALIGNMENT_*` so no A2L row value changes (AT-114 GREEN), and the drift spans screens batch-56 never touches (workspace/mac/issues/map/patch/diff). → the batch-58+59 canonical-CI snapshot-regen carry (BACKLOG TOP), local `--snapshot-update` FORBIDDEN.

## Gate (self-approved, autonomous)
- **Coverage:** dual traceability complete, 0 orphans (§2 registry). ✅
- **Certainty:** AT-113 counterfactual RED shown; hostile-input ATs (116/120/122) with negatives; TC-143 derived-set oracle; code-reviewer independent runs. ✅
- **Evidence:** gate run `_gate_run.txt` (re-runnable), code-review report, per-AT nodes cited. ✅
- No blocker (no batch-56 failure; the 19 are a pre-existing advisory carry). → `approve` → Phase 5.
