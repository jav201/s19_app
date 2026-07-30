# Phase 4 — Validation — batch-52

## Verdict: **PASS**

Full suite **1840 passed**, 2 skipped, 3 xfailed, 19 failed. The 19 failures are the **pre-existing batch-58/59 `test_tc016s_density_layout_snapshot` baseline drift** (advisory `snapshot` job, `continue-on-error`; the CRC/flow screen is NOT in the tc016s set). Pass count grew by exactly the 19 new batch-52 tests vs the prior N3 baseline (1821 → 1840): **0 regression, 0 new failure**. Blocking `tui-ci` (no snapshot plugin) green on PR #119.

## Test ledger

| | Count |
|---|---|
| tests_base (pre-batch-52) | 1821 |
| tests_added | 19 |
| tests_deleted | 0 |
| tests_post | 1840 |

New: `tests/test_flow_crc_block.py` (12, engine) · `tests/test_flow_crc_ui.py` (2, UI) · `tests/test_flow_crc_ribbon.py` (5, ribbon/F3/G-1).

## Acceptance evidence (black-box, per user story)

| US | AT | Result | Observed through |
|----|----|--------|------------------|
| US-C52-1 compute+inject over post-patch | AT-123 + TC-347 | ✓ | written file re-read; CRC bytes at output_address == kernel oracle over the PATCHED map (≠ source CRC discriminator) |
| US-C52-2 grow image | AT-124a/b | ✓ | `image_ranges` + written ranges include the CRC window (grow); footprint unchanged (no-grow) |
| US-C52-3 ordering WARN | AT-125a/b + TC-351 | ✓ | CRC-before-PATCH / no-PATCH → WARN + `completed-with-issues`, still runs; CRC-after-PATCH → clean OK |
| US-C52-4 fail-close | AT-126 (malformed/empty) + AT-127a/b (absolute/escape) | ✓ | block error + downstream skipped + flow error + no raise + nothing written; containment rejects a valid config outside the project |
| US-C52-5 add + render CRC | AT-128 + TC-356 | ✓ | CRC in dropdown; pre-run list shows `CRC <config_ref>`; post-run node renders crc kind + "injected N CRC region" summary |
| US-C52-6 twin ribbon | AT-129 + TC-358/360/361 | ✓ | `.flow-ribbon-before` filled-cells < `.flow-ribbon` (after) on growth; no before strip when not grown; gating hidden for non-CHECK; empty flow renders |

## RED-before-fix evidence

- **Inc-1 (inject threading):** disabling `mem_map, ranges = inject_crcs(...)` → AT-123 (CRC bytes absent) + AT-124a (`image_ranges` misses the CRC window) FAIL. Restored → GREEN.
- **Inc-3 (twin ribbon):** forcing `grown = False` → AT-129 fails (`NoMatches: #flow_result .flow-ribbon-before`). Restored → GREEN.

## Frozen / reuse verification

- `git diff main -- s19_app/tui/operations/crc.py s19_app/tui/operations/crc_config.py` → **empty** (kernel byte-unchanged, reuse-only).
- No engine-frozen module in the batch diff; `tests/test_engine_unchanged.py` green.

## Batch acceptance criteria (§5.3) — all met

100% LLR-089.x..094.x covered by ≥1 passing TC · every US has ≥1 passing AT with boundary + negative evidence · `run_flow` never raises across all fail-close cases · 0 engine-frozen edits · kernel byte-unchanged · each increment ≤5 files.
