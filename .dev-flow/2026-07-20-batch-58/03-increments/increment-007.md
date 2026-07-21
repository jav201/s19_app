# Increment 007 — coverage strip + per-policy preview + gap-conflict + preview-only guard (LLR-V6.1/V6.2/V7.1/V8.1)

**Gate: APPROVED (self, autonomous)** · code-reviewer OK (0 HIGH/MED, 2 LOW) · commit `181e747` · **CLOSES Phase-3 implementation** · 2026-07-21

## 1. What changed
- Coverage editor: `#crc_coverage_ranges` (ordered hex ranges) + intra_gap/join toggles + pad_byte + on_gap_conflict; builds a `CrcTarget` via the single-sourced `_build_target`. — LLR-V6.1
- Per-policy preview `#crc_coverage_preview`: with image loaded, shows BOTH concat + fill CRC over the real mem_map (`compute_target_crc`), marks active join; no image → graceful note. — LLR-V6.2
- Gap-conflict via `evaluate_target`: join=fill + abort+conflict → refusal (no CRC) + address; warn → CRC+diagnostic; ignore → silent; concat never conflicts. — LLR-V7.1
- fill-no-pad warn (3rd R-007 warn) into `_live_warnings_text`.
- Preview-only guard: reads mem_map, never mutates, no firmware-write symbol. — LLR-V8.1

## 2. Files (frozen census: 0 frozen diffs, static)
- `s19_app/tui/crc_designer_view.py` · `tests/test_crc_designer_view.py` (+7). 2 files. Commit `181e747`.

## 3–4. Tests
- RED (preview id broken): 6 behavioral Inc-7 tests fail. GREEN: `test_crc_designer_view.py 20 passed`; CRC regression `163 passed`; ruff clean.
- **AT-058-07 (C-31):** §3.2 fixture (bytes intersect ranges — not vacuous) → both `0x9C5BCBBD` (concat) + `0x2A8A3950` (fill) in mounted `#crc_coverage_preview`. Reviewer independently recomputed both via `compute_target_crc`. AT-CRC-DSN-013 single-range-skip == `compute_region_crc` `0x88AA689F`.
- **AT-058-08 / AT-CRC-DSN-017 (C-32):** dirty `0x800A=0x99` + abort → refusal notice + address + **both CRC hexes ABSENT**; warn → CRC+gap-safety; ignore → silent; concat never conflicts.
- **AT-058-10 (C-18 one node):** one session fires all 3 warns (fill-no-pad, store_width, check-mismatch), painted.
- **AT-058-09 (C-12):** mem_map object identity + contents unchanged before/after full interaction (edits+toggles+Save+bad Load); module grep confirms no `emit_s19`/mutation reachable.

## 5. code-reviewer findings (both LOW, carries)
- **F1 (LOW):** view imports loader-private `_build_target`; sanctioned single-sourcing seam (LLR-V6.1) but crosses the underscore boundary and leaks "target 1 …" wording into the single-target designer error string. → BACKLOG: add public `build_target(raw)` wrapper + strip the prefix.
- **F2 (LOW):** conflict-address "first 8" formatting duplicated between `evaluate_target` and the view refusal notice. → BACKLOG (optional).

## 6. Carries (→ postmortem/BACKLOG)
Inc-5 F1/F2, Inc-6 code-F1 + sec-F1/F2, Inc-7 F1/F2. All LOW, non-blocking.

## 7. Next
Phase-3 implementation CLOSED. → Phase 4 validation (orchestrator-owned full-suite per C-25; note: 19 snapshot baselines are expected-drift → canonical-CI regen at closeout; tc031/engine-unchanged are checkout-hazard, run uninterrupted or verify frozen statically), then dual-traceability reconciliation.
