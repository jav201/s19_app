# Kimi brief — batch-99 Increment 2 · US-142 / HLR-153 · S0 is not image data

Read `BRIEF-COMMON.md` first. Its rules bind this increment.

## Requirement (grep these ids in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-153, LLR-153.1, LLR-153.2, LLR-153.3, LLR-153.4; TC-B99-04..07; AT-B99-02. Design: `design/design-proposal-b99.md` §2 (engine row) and §4 (B99-I1). Map: `docs/architecture.md` rationale R18 (one shared data-record predicate).

## SOURCE files (max 2): `s19_app/core.py`, `s19_app/render/hexview.py`
`core.py` is in the frozen engine layer (§7). The crossing is named in LLR-153.1. Change only what HLR-153 needs.

## What to build
1. ONE data-record predicate in `core.py` (e.g. `_is_data_record(record)` → True for S1/S2/S3 only). Use it in `S19File.get_memory_map`, `get_memory_ranges`, `get_record_for_address` and `_build_overlap_map`. `render/hexview.py` `build_mem_map_s19` and `build_range_validity_s19` import and use the same predicate. Grep for every other record walk that feeds the image, and report any you leave alone, with the reason.
2. The S0 text stays available as the header (`source_s0_header` / however the loader already carries it). Check that save-back and flow WRITE-OUT still emit the S0 as an S0 record for S19 output (LLR-153.3) and no data at undeclared addresses, for S19 and HEX output.

## Tests — `tests/test_b99_s0.py`
- TC-B99-04..07 as the LLRs state, over every S0-bearing S19 in the corpus (`tests/fixtures/synth/manifest.json`, from Inc 1) and `examples/**/*.s19`. Oracle = the manifest or `tests/support/independent_reader.py`.
- **AT-B99-02** (black-box, Textual pilot):
  1. `S19TuiApp(base_dir=tmp)` loads `examples/case_01_basic_valid/firmware.s19` through the Load file dialog (`l`).
  2. Open the Patch Editor (`p`) and add ONE entry that rewrites the bytes already at a data address (read them with the independent reader first).
  3. Apply, accept the save-back (offered only after ≥1 applied entry, premise P-23) and read the written file with the independent reader: no byte at `0x0..0xB`; data identical to the source everywhere.
  4. The Memory Map lists no range starting at `0x0`.
  5. A document whose only entry is at `0x0` shows that entry as skipped in the status line.

  RED on today's tree first (P-1: `extra=12@0x0..0xb`).
- Mutation: re-admit S0 in the predicate → TC-04/05/06 RED. Revert.

## Reverse census — this is the big part of the increment
Changing the predicate shifts range counts and footprints in many existing tests (qa census: 12+ test files, plus snapshot cells over S0-bearing examples). For every failing existing test:
- If it asserted the S0 phantom (a range or bytes at the S0 address, or a count including it), re-pin it to the new value. Record each one in the packet as `tests/x.py::node — old → new — LLR-153.x`.
- If it fails for any OTHER reason, STOP and write it in HANDOFF.md. Do not "fix" it.
- **Snapshot tests** (`tests/test_tui_snapshot.py` and any `snap_compare`): if a cell changes ONLY because the S0 range disappeared, regenerate just that cell with `--snapshot-update`. Prove in the packet, with a text diff of the SVG, that only the S0 range row or count changed. If anything else changed in the SVG, stop and report.
- Run: `tests/test_b99_s0.py`, `tests/test_b99_corpus.py`, every test file that greps for `get_memory_ranges|get_memory_map|build_mem_map_s19|build_range_validity_s19|get_record_for_address|_build_overlap_map|S0`, plus `tests/test_address_census.py`. Save each transcript.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-002.md` (copy the template from `increment-001.md`'s seed form in batch-97 if needed). REQ-ID `HLR-153`.
