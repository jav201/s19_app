# batch-57 — Validation (two layers)

## Layer A — functional (white-box), whole-suite (C-25, orchestrator-owned)
- **Pre-fix full gate suite** (`pytest -q -m "not slow"` @ `1341fd3`): **1730 passed, 2 skipped,
  21 deselected, 3 xfailed; 29 snapshots passed; exit 0** (23m26s). No regression anywhere — the
  batch is additive (two new modules), so the whole existing suite is untouched.
- **Post-fix targeted** (`test_crc_kernel.py` + `test_crc_designer_model.py` @ `063bea5`): **45 passed,
  ruff clean.** The `063bea5` delta over `1341fd3` is additive + one robustness fix (F1 guard, F2/F3
  tests) fully exercised by these 45 nodes; the post-fix full suite is confirming via the PR CI
  (`tui-ci.yml` runs `pytest -q`) and a local re-run — the merge is gated on that CI being green.
- **Frozen guards:** `test_engine_unchanged` + `test_tc031_*` green; `git diff` of the engine-frozen
  set vs `f2109cf` is **empty** (0 frozen diffs).

## Layer B — behavioral (black-box) acceptance, through the shipped headless surface
Every US observed through the real headless API (the surface batch-58's view will call), with
representative + boundary + negative inputs and the actual deliverable asserted:

| US | Black-box observation (node) | Evidence |
|----|----|----|
| US-CRC1 | KAT of `"123456789"` through `CrcAlgorithm.compute` == catalogue `check` for all 7 presets; seed == `zlib.crc32` (5 vectors incl. empty + 256-byte) | AT-CRC-DSN-011 / -010 |
| US-CRC2 | `gather_target` byte-window + `compute_target_crc` over a real sparse map: concat `0x9C5BCBBD` / fill `0x2A8A3950`; declared order authoritative; store LE/BE + narrow/wide | AT-CRC-DSN-013b / -014 |
| US-CRC3 | `evaluate_target` over a dirty filled gap: `abort`→refused/`crc=None`/addr named; `warn`→computes+diagnostic; `ignore`→computes+silent; clean→value-pinned. Negative: `gap_conflict` clean → `[]`, concat → `[]` | AT-CRC-DSN-017 / AT-E8-abort/warn/ignore |
| US-CRC4 | `crc_lut` (the path `compute` uses) == `crc_stream` oracle over 45 vectors × 7 presets + odd widths (12/24) + `refin≠refout`; KAT unchanged | TC-E7-LUT |
| (loader) | Malformed template/job (bad JSON, over-cap, missing field, bad policy, **non-object `algorithm`**) → exactly one collected error, never raises | F1 regression + collect-don't-abort ATs |

## Spec-AT realization (C-18) + counterfactuals
- Each gate-blocking AT → **exactly one** on-disk node driving the whole chain through the shipped
  surface (no satisfied-in-parts). Net-new modules → trigger-absent import RED is the counterfactual
  (C-20); the LUT differential + branch ATs are value-discriminating (a wrong table / no-op enforcement
  goes RED).
- **Ledger:** 34 (base keel) + 8 (Inc-2 LUT: differential/odd-width/refin≠refout/compute-route/cache)
  + 3 (Inc-3 enforcement branches) → 45 after the F1/F2/F3 fixes reconciled (F1 +2, F2 +1, F3 strengthen).

## Bidirectional surface-reachability
Every input dimension (width/poly/init/refin/refout/xorout; ranges/intra_gap/join/pad_byte/store_*;
on_gap_conflict; malformed JSON) and every output/deliverable (CRC value, stored bytes, tri-state
verdict, conflict list, diagnostics, collected error) is exercised/observed through the API. Complete.

## Gate
Axis: **Coverage** (0 orphans, dual chains complete) · **Certainty** (LUT proven+differential incl. odd
widths; branch ATs discriminating; F1 crash closed) · **Evidence** (1730-green pre-fix suite + 45 post-fix
+ 0 frozen diffs + reviewer proof). Post-fix full-suite confirmation gates the merge (CI). → **approve**.
