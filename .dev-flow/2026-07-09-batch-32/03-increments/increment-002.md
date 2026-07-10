# Increment 002 — group compute + width codec (LLR-GRP-001.4/.5, LLR-WID-001.1/.2/.4)

1. **What changed** — `CrcTarget` + `normalized_targets` (the ONLY ordering/widening seam: legacy-first file order, single-span widening, width 4, is_group provenance flag); `compute_group_crc` (declared-order concat -> one crc32_stream, S-1/S-2); `encode_le`/`decode_le` width codec (encode_le32/decode_le32 stay as fixed-4 wrappers, KATs untouched); `read_stored_crc_le` gains `width=LE32_WIDTH` keyword (legacy callers unchanged).
2. **Files** — s19_app/tui/operations/crc.py, tests/test_crc_engine.py (2 of <=5).
3. **How to test** — `pytest tests/test_crc_engine.py -q`.
4. **Results** — 20 passed (9 base intact + 11 new: AT-045a zlib-oracle concat, AT-045b order sensitivity, AT-045e non-default params incl. must-differ-from-default guard, AT-045f duplicate span, B5 contiguity identity, AT-045d compute-half equivalence bridge, AT-045c compute-half gap semantics/B3, TC-202.8 normalizer order+widening, TC-202.9/.10 codec table + wrapper identity, TC-202.11 width read + B8 one-absent-byte tri-state both ends + legacy default call). **RED counterfactual**: stash crc.py -> collection error (group symbols absent, trigger-absent specced reason) -> pop -> 20 green. Ruff clean. All 4 CRC suites: 78 -> 79 passed (49 base + 30 new incl. Inc-1). Ledger: 49 base -> 79 (+30, -0).
5. **Risks** — none new; check/inject still legacy-only (groups computed but not yet wired — by design, Inc-3).
6. **Pending** — Inc-3 check/inject/result-model wiring + notes; Inc-1 code-review verdict FOLDED (F1 HIGH fixed, F2 docstring, F3 recorded, F4 partials).
7. **Next** — Inc-3.
