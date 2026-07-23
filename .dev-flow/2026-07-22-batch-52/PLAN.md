# PLAN — batch-52 · Flow Builder CRC block (FB batch-52)

> Living compendium. Updated at every gate + checkpoint. BLUF-first.

## Where we are
- **Phase 0/1 (requirements)** — kicking off. Branch `feat/batch-52-crc-block` off `origin/main` `6e64c48` (RC-1 PASS, HEAD==tip).
- Autonomy: **end-to-end + self-merge** (per-batch grant). Language: **English**.

## Objective
A template-driven **CRC block** in the Flow Builder pipeline. In an ordered flow `SOURCE → PATCH → CRC → WRITE-OUT/CHECK`, the CRC block computes the CRC over the working (post-patch) image using a JSON template config, **injects** the CRC bytes, **grows** the `(mem_map, ranges)` when the output window lies outside loaded ranges, and threads the extended image forward. Ordering `PATCH → CRC` (a CRC before any PATCH = non-blocking WARN). This is the ADR §7 "CRC-into-loop seam" — de-risked because the pure inject stage already exists.

## Key de-risk (verified on disk, C-35)
- `inject_crcs(op_input, crc_regions) -> (working_mem_map, working_ranges, written_regions)` — `operations/crc.py:1081`. Copies (never mutates) mem_map/ranges, injects CRC LE at `output_bytes` width, grows ranges via `_extend_ranges`. Tested (TC-121/122).
- `check_regions(op_input: OperationInput, config: CrcConfig) -> list[CrcRegionResult]` — `crc.py:757`. Computes `computed_crc`/`output_address`/`output_bytes` per target.
- `parse_crc_config(text) -> (Optional[CrcConfig], list[str])` — `crc_config.py:385`.
- `OperationInput(mem_map, ranges, input_path, variant_id, file_type)` — `operations/model.py:27`.
- `run_flow` threads `mem_map/ranges`; `_resolve_manifest_entry(project_dir, ref, label, issues)` is the F1 containment guard reused by SOURCE/PATCH/CHECK; `_record_error(...)` sets `aborted`. `result.image_ranges` already carries the final footprint (LLR-088.4, AMD-1) — comment literally says "SOURCE footprint until the batch-52 CRC block first grows the image".
- **NO crc.py refactor needed** — compose the existing kernel in a new `_run_crc_block`. crc.py stays untouched (additive elsewhere).

## Roadmap / increment plan (≤5 files each)
- **Inc-1 — engine (headless):** `flow_model.py` (+`CrcBlock`, `BLOCK_CRC`, Union entry); `flow_execution_service.py` (+`_run_crc_block` + dispatch: resolve `config_ref` via `_resolve_manifest_entry`, `parse_crc_config`, build `OperationInput` from threaded image, `check_regions` → `inject_crcs`, **reassign** `mem_map`/`ranges`, ordering WARN, invalid-config → block error breaks image). Headless AT: `SOURCE→PATCH→CRC→WRITE-OUT` writes a file with CRC injected + ranges grown; RED pre-fix.
- **Inc-2 — UI:** `screens_directionb.py` `FlowBuilderPanel` — CRC in add-block dropdown + node render + status. width-narrow/density-compact, markup-safe.
- **Inc-3 — twin ribbon (AMD-1) + polish:** before/after memory ribbon that visibly grows on CRC (`before_ranges` carrier vs grown `image_ranges`) + F3 gating-hide-for-non-CHECK + G-1 empty-flow render TC.

## Reuse (do not fork)
Template library = the batch-58 CRC Designer templates in `.s19tool/templates/`, parsed by `parse_crc_config`. The CRC block `config_ref` points there. Share `parse_crc_config`/`check_regions`/`inject_crcs` across the Designer (preview-only) and the flow block (writes). Never fork the kernel.

## Security (security_required = TRUE)
`config_ref` is an untrusted JSON file → resolve via the 6 manifest guards (`_resolve_manifest_entry`, reuse never fork; absolute / escape-project-root / reparse-point) + `parse_crc_config` validation (malformed config → block error, fail-close). Phase-2 security gate covers traversal + malformed fail-close.

## Conventions honored
Engine-frozen set OFF-LIMITS (none of the targets are frozen); ≤5 files/increment; every behavioral change ships a black-box AT-NNN RED pre-fix; docstring section order; type hints; C-27 dual frozen-guard; C-36 fold-against-defined-vocabulary (status tokens ok/notices/error/skipped; flow ok/completed-with-issues/error — grep-verified in flow_model.py).

## Risks / watch-items
1. Reconcile two CRC surfaces → share kernel (mitigated).
2. Address-space growth in chain → `inject_crcs` proven (TC-121/122).
3. Ordering-WARN needs a "has a PATCH run upstream?" tracker in run_flow (new local state).
4. `check_regions` needs a stored value to compare, but the flow CRC block INJECTS (doesn't verify) — use the `computed_crc` from the results for inject; ignore `matched`. Confirm check_regions populates `computed_crc` even when no stored value present (it does — computes unconditionally).

## Out-of-scope carries
FB-P1 flow.json persistence (batch-53); FB-P2 PKI extraction (BLOCKED, operator-defining); FB-P3 CRC-as-subflow; multi-image scope. CRC-as-single-block here, not decomposed.

## Test ledger
- Inc-1 (engine): `tests/test_flow_crc_block.py` 12 · Inc-2 (UI): `tests/test_flow_crc_ui.py` 2 · Inc-3 (ribbon/F3/G-1): `tests/test_flow_crc_ribbon.py` 5 = **19 new**, all green. Combined flow+crc suite = 53 green. RED-verified: Inc-1 inject-threading, Inc-3 twin-ribbon. crc.py/crc_config.py diff-vs-main empty (frozen-safe).

## Phase-3 status (2026-07-23, resumed from the Phase-1 checkpoint 80c8be3)
- **Inc-1 DONE** `3022abd` — CrcBlock + BLOCK_CRC + pre_crc_ranges (flow_model); CRC branch in run_flow (compute→inject→thread, ordering WARN, fail-close). AT-123/124/125/126/127 + TC-346/347/351.
- **Inc-2 DONE** `ba9e138` — CRC in `_KIND_OPTIONS` + `_make_flow_block` + `_flow_block_label`. AT-128 + TC-356.
- **Inc-3 DONE** `71c7f13` — twin ribbon (shared-axis `window`), F3 gating-hide (on_mount/on_select_changed), G-1. AT-129 + TC-358/360/361.

## Decision log
- 2026-07-22 · Phase 0 kickoff · autonomy end-to-end + self-merge; plan approved as-is; batch-id 2026-07-22-batch-52 (free dir, FB stream).
- 2026-07-22 · Phase 1 · requirements + qa-catalog authored + reconciled (R-D1..D7); paused (weekly limit) before Phase 2.
- 2026-07-23 · Phase 2 · review + security gate PASS (inline, C-33); all spec anchors disk-verified accurate; `_resolve_manifest_entry` reuse confirms containment posture.
- 2026-07-23 · Phase 3 · **DESIGN NOTE (no requirement change):** the ribbon maps [low,high) across a FIXED 48 cells, so per-strip normalisation would REDUCE filled cells on growth. Resolved by rendering before+after over a COMMON axis (additive `window` param) so "after cells > before cells" (LLR-094.2 threshold) holds as intended. Implementation detail of LLR-094.1; §6.5 stays empty. AT-124b uses a patch at 0x1003 (in-region) so the no-grow config output at 0x1000 stays in-range.
