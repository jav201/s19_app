# Increment 2 — HLR-034 (US-031 geometry snapshot lock)

> Add the patch 80×24 snapshot cell + reconcile the existing 120×30 patch cell to lock the 2×2 layout; baseline regen CI-only. 1 file. Implemented directly by the orchestrator (small test-only edit; agent-stall avoidance) → `code-reviewer` independent pass.

## 1. What changed
Restructured `_SCAFFOLD_CELLS` in `test_tui_snapshot.py` so the `patch` scaffold carries **two** cells — `80x24` (NEW, the tight floor) + `120x30` — both `xfail(strict=False, reason="baseline regen pending in CI env (batch-22 US-031 2x2 relayout)")`; map/diff unchanged (120x30 only). The 2×2 relayout invalidates the old patch SVG, so its baseline (and the new floor cell) regenerate in the canonical CI env only. Matrix: 24 restyled + 4 scaffold = **28 cells** (was 27). **R3 confirmed:** `patch` is in `_SCAFFOLD_SCREENS`, NOT `_RESTYLED_SCREENS` — only the patch cells are affected.

## 2. Files modified (1)
- `tests/test_tui_snapshot.py` — `_SCAFFOLD_CELLS` comprehension (patch → 80x24 + 120x30, xfail); count comments (27→28) + module/test docstrings updated.

## 3. How to test
```
python -m pytest tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot --co -q   # 28 cells
python -m pytest tests/test_tui_snapshot.py -k patch -q                                     # 2 patch cells
python -m pytest -q -m "not slow"
```

## 4. Test results
- **28 cells collected** (was 27 — the patch-80x24 added). The 2 patch cells **skip locally** (`pytest-textual-snapshot` is a dev-only optional extra, absent here; in CI they run and `xfail`-until-baseline-regen). No false-fail. map/diff/restyled unaffected.
- **No new runnable counterfactual RED** — honest: the SVG baseline doesn't exist locally (regen CI-only), so there is no local snapshot pass OR fail to capture. The **behavioral counterfactual is Inc1's AT-033a** (revert grid → RED, already captured). US-031's snapshot is the CI-locked pixel follow-through; the local gate remains the Inc1 geometry AT. NO fabricated local snapshot pass.
- Full non-slow (confirmed): **958 passed / 30 skipped / 3 xfailed / 0 failed** = 990 → **991 collected (+1** = the new patch-80x24 param, skipped locally as the plugin is absent). Frozen 0. (The +1 skipped vs Inc1's 29 is exactly this cell.)
- **ruff:** my Inc2 changes are clean. `tests/test_tui_snapshot.py` carries **1 PRE-EXISTING F401** (`Optional` unused, line 57) that is on origin/main (13c06c4), NOT introduced by Inc2 — left per the surgical rule (flagged as a pre-existing carry, like batch-21 N1).
- **code-reviewer: APPROVE-WITH-NITS** (0 HIGH/MED). Verified: 4-cell scaffold set exact (map-120x30, patch-80x24, patch-120x30, diff-120x30), both patch cells `xfail(strict=False)`, no-fabricated-pass confirmed (skipif gates + Inc1 AT is the runnable verdict), F401 confirmed pre-existing. **F1 LOW FIXED by orchestrator:** two stale "27-baseline" labels (:12 module docstring, :365 banner) that I'd missed when updating the count → both → "28" (my own inconsistency; grep confirms none left, 28 cells collect).

## 5. Risks
- The patch baselines are unverified until the CI regen lands (by design — regen-in-CI-only convention). The locally-runnable proof of the 2×2 (Inc1 AT-033a/b/c) covers the behavior; the snapshot is the visual-regression lock that activates in CI.

## 6. Pending / next
- **Phase 3 COMPLETE** (Inc1 reparent + Inc2 snapshot). Next: Phase 4 validation.
- **CI action (post-merge):** regenerate the patch 80x24 + 120x30 baselines in the canonical CI env, then remove the `xfail` marks (a follow-on, per convention — not done locally).
- Pre-existing F401 (`Optional`) → optional cleanup, not batch-22's.
