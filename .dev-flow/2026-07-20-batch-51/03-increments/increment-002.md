# Increment 002 — Direction A "Pipeline Ledger" render

**Status:** APPROVED (self-approved autonomous, 2026-07-20). Independent code-review APPROVE-WITH-NITS → F1/F4 applied.

## 1. What changed
The Direction A render (LLR-088.1–.7) + the AMD-1 additive carrier.
- `flow_model.py`: `FlowRunResult.image_ranges` (additive, default-empty).
- `flow_execution_service.py`: populate `image_ranges` with the final `ranges` at `run_flow` end (None-guarded).
- `screens_directionb.py`: `render_result` mounts children into `VerticalScroll(#flow_result)` — flow-status banner (CLEAN/ISSUES/FAILED), one node/block with `sev-*` status gutter, N−1 bordered separators, a **single** memory ribbon from `image_ranges` + caption, written-path lines. Maps `_BLOCK_STATUS_SEV_CLASS`/`_FLOW_STATUS_BANNER`/`_BLOCK_STATUS_GLYPH` live here (NOT frozen `color_policy.py`). `_KIND_OPTIONS` adds CHECK + relabels SOURCE→"Load" (keeps `"source"` discriminator); `#flow_gating` Select (advisory|block-own-op) wired to `_make_flow_block`.
- `styles.tcss`: flow-scoped classes only; colour flows through the frozen `.sev-*`.

## 2. Files (7: 4 source ≤5 + app.py untouched; 3 test)
Source: `flow_model.py` · `flow_execution_service.py` · `screens_directionb.py` · `styles.tcss` (app.py untouched — the `render_result` call was unchanged, so production footprint is really 2 files).
Test: `tests/test_flow_builder_render.py` (NEW, budgeted 5th) · `tests/test_flow_execution_service.py` (+1 `image_ranges` TC, approved) · `tests/test_tui_directionb.py` (1 test C-26 consumer reconciliation — legitimate, frozen guards untouched).
**0 frozen files touched.**

## 3. Independent code-review (before gate)
Verdict **APPROVE-WITH-NITS, no HIGH**. Confirmed: all 5 markup sinks `safe_text`-wrapped; AT-088a/b non-vacuous + code-derived; `image_ranges` cleanly additive (0 Inc-1 regression); C-26 reconciliation legitimate (no tc031/tc032/_ENGINE_PATHS touch); frozen 0-diff; gating Select wired. Applied:
- **F1 (MEDIUM):** strengthened the markup-sink completeness guard to **3 layers** — marker==tested, AST `safe_text`-call-count==markers, and (the strong one) an AST walk asserting **no `Static(...)` passes a file-derived value without `safe_text`**. Non-vacuity proven: injecting `Static(block_result.summary)` (unwrapped) → guard fails; restored.
- **F4 (LOW):** `flow-flow-diag` → `flow-run-diag`.
- F2 (direct render_result injection for the hostile payload — justified, through-surface covered by AT-085a/088a) + F3 (gating visible for non-CHECK — batch-52 polish note) left as-is.

## 4. Test results (single complete runs)
- RED counterfactual (C-20 backup/revert/restore, no git stash): render-core reverted → 8 new tests fail (`AttributeError: image_ranges`, nodes==0, sinks, separators, ribbon, gating); restore verified.
- New render + full Inc-1 suite: **34 passed** (0 Inc-1 regression); after F1/F4: **11 passed** (render) / 174 with guard host.
- **C-34 full `tests/test_tui_directionb.py`: 174 passed** (one complete run, ~191s) — incl. the frozen `tc031` dual-guard + the `test_tc_042_10` markup source-scan.
- Frozen `test_engine_unchanged.py` 1 passed; `git diff` over 7 frozen paths empty.
- **Snapshots: 29 passed, 0 drift — NO canonical-CI regen needed** (no baseline navigates into `#screen_flow`; parametrized screens are workspace/a2l/mac/issues/map/patch/diff only; no rail/shared-chrome touched). Honestly supersedes the PLAN's drift expectation.
- Ruff clean.
- **Ribbon geometry MEASURED (C-13/C-23/C-29, not inherited — C-16):** 80×24 content width 70, ribbon 48 cells, 22-col margin, no overflow; 120×30 → 92; 160×40 → 132. `test_ribbon_geometry_measured_no_overflow` asserts `ribbon.region.width ≤ container content width` at 80×24 + 120×30.

## 5. Gate decision (axis check)
- **Coverage:** LLR-088.1–.7 each have a TC; AT-088a (3 banner states + node/sep/sev/ribbon) + AT-088b (5-sink, 3-layer guard) present; AT-085a/086a/087a re-observed through render. ✓
- **Certainty:** AT-088b guard non-vacuous (bypass-injection proven RED); AT-088a code-derived counts; geometry measured not assumed. ✓
- **Evidence:** one-run tails cited; frozen 0-diff; RED→GREEN; 0 snapshot drift measured. ✓
None unmet → **APPROVE. Phase 3 (implementation) COMPLETE.**

## 6. Pending / carries
- **batch-52:** CRC block + the ribbon "before" row (range-growth twin) + `before_ranges` carrier (AMD-1).
- **Polish note (F3):** hide/disable `#flow_gating` when kind≠CHECK.
- **Phase-4 name reconcile:** `test_flow_execution_service.py` (new) vs existing `test_flow_execution.py` (both kept, both green).
