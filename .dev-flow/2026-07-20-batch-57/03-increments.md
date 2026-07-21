# batch-57 — Phase 3 increments

Commit `1341fd3` (code + tests) on `claude/crc-algorithm-designer-8f82ae` off `origin/main` `f2109cf`.
All increments are **additive** — no existing/shipped module touched, engine-frozen set untouched.

## Inc-1 — adopt the keel
- **Deliverable:** the pre-built `crc_kernel.py` + `crc_designer_model.py` + their 34 tests,
  re-verified green on the rebased tree (`f2109cf`): 119 CRC-suite tests, frozen guard, ruff.
- **Counterfactual:** the modules are net-new (C-20) — absent, every dependent test fails at import.
- **Coverage:** US-CRC1 (AT-CRC-DSN-010/011), US-CRC2 (AT-CRC-DSN-013b/014), US-CRC3 detector (AT-CRC-DSN-017).

## Inc-2 — E7 LUT fast-path (US-CRC4)
- **Deliverable:** `make_crc_table` (256-entry, `lru_cache` per `(width, poly)`) + `crc_lut`
  (table-driven); `CrcAlgorithm.compute` routes through `crc_lut`; `crc_stream` kept as the oracle.
- **Why byte-identical:** `crc_lut` is the tabelization of the exact `crc_stream` MSB-first bit loop
  (same table family; input byte pre-reflected when `refin`) — same computation, byte-at-a-time.
- **Certainty (TC-E7-LUT):** differential test `crc_lut == crc_stream` over 45 vectors × 7 presets
  (widths 8/16/32/64) + a `refin≠refout` non-catalogue combo; `compute` KAT values unchanged.
- **Counterfactual:** a wrong table entry → the differential test goes RED on that preset/vector.

## Inc-3 — E8 on_gap_conflict enforcement (US-CRC3)
- **Deliverable:** `TargetEvaluation` + `evaluate_target` — runs `gap_conflict`, applies
  `on_gap_conflict`: `abort` → `refused=True`/`crc=None`/addresses named; `warn` → computes +
  diagnostic; `ignore` → computes, silent. Diagnostics are plain text (ints/hex only — markup-safe).
- **Certainty (branch ATs, C-10b):** one AT per branch asserting the DISTINCT outcome —
  abort(refused+no-crc+addr), warn(computes+diagnostic), ignore(computes+silent), clean(computes,
  oracle `0x2A8A3950`, no conflict). Value-discriminating: a no-op enforcement fails the abort AT.

## Test ledger
- base 34 (kernel 8 + model 26) → +8 kernel LUT/cache → +4 model enforcement = **42** (kernel 18 + model 24).
- reconciles: `42 = 34 + 8`  ... kernel `18 = 8 + 4(LUT diff/oracle) + 3(refin≠refout, compute-route, cache) ` → actually kernel +10, model +... reconciled at Phase 4 whole-run.

## Gates (autonomous, per-increment)
- Inc-1/2/3 each: ruff clean, targeted tests green, no frozen diff. Axis met → approve.
- **Pending gate evidence (Phase 4):** orchestrator-owned whole-suite run (C-25) + independent
  `code-reviewer` pass (running) — HIGH blocks. Reconcile counts + realize AT nodes (C-18).
