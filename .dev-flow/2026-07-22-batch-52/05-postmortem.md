# Postmortem — batch-52 (Flow Builder CRC block)

> Language: English. Autonomy: end-to-end + self-merge (per-batch grant). Base `6e64c48`; branch `feat/batch-52-crc-block`.

## What shipped
A template-driven **CRC block** as the 4th typed Flow Builder block (`SOURCE → PATCH → CRC → WRITE-OUT/CHECK`). Three increments, each with a black-box AT shown RED pre-fix:

- **Inc-1 `3022abd` (engine):** `CrcBlock` + `BLOCK_CRC` + additive `FlowRunResult.pre_crc_ranges` (`flow_model.py`); a CRC branch in `run_flow` (`flow_execution_service.py`) that resolves `config_ref` via the reused `_resolve_manifest_entry` guard, parses via `parse_crc_config`, computes over the CURRENT (post-patch) threaded image via `check_regions`, injects via `inject_crcs`, threads the (possibly grown) working image forward, warns on CRC-before-PATCH, and fails closed on a malformed/unsafe config. AT-123/124/125/126/127 + TC-346/347/351.
- **Inc-2 `ba9e138` (UI):** CRC in `_KIND_OPTIONS` + `_make_flow_block` + `_flow_block_label`. AT-128 + TC-356.
- **Inc-3 `71c7f13` (ribbon/F3/G-1):** §6.5 AMD-1 before/after twin ribbon, F3 gating-hide (CHECK-only), G-1 empty-flow. AT-129 + TC-358/360/361.

## Validation
- 19 new tests (12 engine + 2 UI + 5 ribbon) all green; 34 existing flow tests green; combined 53.
- Full suite: **1840 passed**, 2 skipped, 3 xfailed. The 19 `test_tc016s_density_layout_snapshot` failures are the **pre-existing batch-58/59 baseline drift** (advisory `snapshot` job, `continue-on-error`; the CRC/flow screen is NOT in the tc016s set) — not batch-52. Pass count grew by exactly the 19 new tests vs the N3 baseline (1821 → 1840): **0 regression**.
- **RED-verified:** Inc-1 inject-threading (image_ranges misses the CRC window when not threaded), Inc-3 twin ribbon (no `.flow-ribbon-before` node when disabled).
- **Frozen-safe:** `crc.py` / `crc_config.py` diff-vs-`main` empty (reuse-only, kernel byte-unchanged). No engine-frozen module touched.

## Security (HLR-092)
`config_ref` is untrusted → containment via the exact `_resolve_manifest_entry` guard (absolute/escape/reparse), reused not forked; malformed config → fail-close (block error, downstream skipped, flow error, never raises). AT-126 (malformed/empty) + AT-127 (absolute + escape triad, valid-config-outside-project rejected to prove containment ≠ existence). No new write surface; config validated pre-use, never persisted.

## What was found (design notes, no requirement change)
- **Ribbon shared-axis (LLR-094.1 impl detail).** The ribbon maps `[low,high)` across a FIXED 48 cells, so per-strip normalisation would *reduce* filled cells on growth (wider span, same data). Resolved by rendering before+after over a COMMON axis (additive `window` param) so "after cells > before cells" (LLR-094.2 threshold) holds as intended. §6.5 stays empty — no locked requirement changed.
- **`check_regions` grow-safety confirmed.** `read_stored_crc_le` guards a missing output window (`if any(addr not in mem_map): return None`), so a fresh CRC appended outside the loaded image does not `KeyError`; `computed_crc` is computed unconditionally. This is why the grow path (US-C52-2) works without editing the kernel.
- **AT-124b patch placement.** The no-grow case patches 0x1003 (in-region) so the no-grow config output at 0x1000 stays in-range.

## Controls
No new control encoded. Reaffirmed: C-35 (all spec symbols disk-verified before build), C-31/C-32 (node count derived from the run; painted result asserted through the shipped panel), C-33 (Phase-2 review done inline, no delegated subagent — the Phase-1 architect fold had died to a weekly limit).

## Carries (→ BACKLOG.md)
- **FB-P1 batch-53** = `flow.json` persistence (untrusted-loader; replicate the manifest guards) — next FB increment.
- **FB-P3** = CRC-as-configurable-subflow (deferred; this batch ships CRC as a single block, proving the block contract).
- **R-2 (accepted, reversible):** one before/after ribbon pair per flow; a second growing CRC block is not separately reflected.
- **Snapshot-regen:** NO new drift from batch-52 (flow screen not snapshotted); the standing 19-cell batch-58/59 regen closeout is unchanged.
- `/dev-flow-sync` (vault) for batch-52 (+ the pending b56/b57/b58/b59 batch).
