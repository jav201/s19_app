# Increment I1b — Headless CRC compute engine + co-located doc

**LLRs:** LLR-001.1 (parameterized CRC32 + chaining), LLR-001.2 (region assembly: sort/gap-split/no-gap-bytes/non-reset chain), LLR-001.3 (per-region CRC, no mutation), LLR-005.3 (REQ-crc.md). **TCs:** TC-101..107 + TC-106b (review F1) + no-mutation. **Headless** — no Textual, no I/O.

## 1. What changed
Implemented the pure-compute CRC32 engine (`crc.py`): a parameterized CRC32 (poly/init/reverse/final-XOR) where the DEFAULT params delegate to `zlib.crc32` and non-default params run a hand-rolled reflected bitwise loop; region byte assembly (ascending sort, gap-split on `current != previous+1`, no gap bytes, single non-resetting digest via concatenation, final XOR); a per-region entry point returning one CRC per range without mutating the input; and the fixed 4-byte LE codec (D-5). Created the co-located `REQ-crc.md` (C-7) and engine tests. No TUI/config/check/inject (those are I2/I5). The dev caught a real seed bug mid-build (`zlib.crc32(data, 0xFFFFFFFF)` ≠ standard; correct is `zlib.crc32(data)`) — the KAT did its job.

## 2. Files modified — EXACTLY 3, all NEW, 0 frozen edits
- `s19_app/tui/operations/crc.py` — engine (`crc32_stream`, `region_segments`, `compute_region_crc`, `compute_region_crcs`, `encode_le32`/`decode_le32`).
- `s19_app/tui/operations/requirements/REQ-crc.md` — co-located operation requirements doc (created the `requirements/` dir).
- `tests/test_crc_engine.py` — TC-101..107 + TC-106b + no-mutation.

## 3. Independent review (code-reviewer) + fixes
**Verdict: OK WITH FIXES — 1 HIGH (test-coverage gap, no code bug).**
- **F1 [HIGH, FIXED]:** the bitwise (non-default) CRC path had zero correctness coverage — only TC-106 (inequality-only) touched it; the reviewer mutation-tested a wrong-final-reflection bug that still passed TC-106. **Fix (test-only):** added `test_bitwise_path_reproduces_published_variant_kats` (TC-106b) pinning the bitwise loop against two published catalog KATs for `b"123456789"`: CRC-32/BZIP2 (`reverse=False`) = `0xFC891918`, CRC-32C (`poly=0x1EDC6F41`) = `0xE3069283`. Orchestrator independently confirmed the engine reproduces BOTH exactly before pinning them. Engine code unchanged (it was already correct).
- **F2 [LOW, FIXED]:** `compute_region_crc` Data Flow docstring described a non-existent `_state` chaining; corrected to the concatenate-once mechanism the code actually uses.

## 4. Test results
- `tests/test_crc_engine.py`: **9 passed** (TC-101..107 + TC-106b + no-mutation). KAT TC-101 green (`crc32_stream(b"123456789") == 0xCBF43926`).
- `pytest -q -m "not slow"`: **797 passed**, 29 skipped, 3 xfailed (exit 0). Engine-frozen guards inside that run pass.
- `ruff check`: clean.
- **Ledger:** lean 788→797 (+9: 8 engine + TC-106b), collection 841→850, D=0.

## 5. Risks
- **RK-3 (flagged, not closed):** absolute correctness of an arbitrary non-zlib *device* convention still needs an operator-sourced reference vector. TC-106b now pins TWO published catalog variants through the bitwise path (closing the "untested machinery" gap), but a bespoke device poly/convention remains "assumed — verify in Phase 3/4". REQ-crc.md records this honestly.
- Per-region byte concatenation allocates per region — fine at firmware scale; no stress test in I1b by design (A-4 census stress is a separate batch-12 post-mortem item).

## 6. Pending / next
- TC-106b not yet in §5.2 (added in Phase 3); reconcile into the coverage table at Phase 4 (V-5 TC ids are provisional-until-Phase-3, reconciled from the real tree at Phase 4).
- `REQUIREMENTS.md` reference to `REQ-crc.md` is a Phase-6 doc task.
- **I2** — config sourcing + check (LLR-004.1, LLR-002.1/.2): `examples/crc_config.example.json` dummy, JSON config reader (resolve + size-cap + collect-don't-abort), read-stored-4LE + compare + `crc_regions` population, consuming this engine.
