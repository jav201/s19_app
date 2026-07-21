# batch-57 — Requirements (adoption + AT/TC registry)

**Normative source:** `docs/crc-algorithm-designer/01-requirements.md` (the design requirements,
adversarially refined across the design phase — 4 production observations resolved, R-CRC-DSN-001..011,
AT-CRC-DSN-010..017, engine E1..E8). This batch document **adopts** it and pins the batch-scoped
AT/TC registry + evidence checklist. No modal `should` inside any `shall` statement (verified).

## Scope of THIS batch (headless integration; view → batch-58)

| Item | Source req | Status coming in | This batch |
|---|---|---|---|
| Width-general engine (8–64), refin/refout split | E1 / R-CRC-DSN-002 | built (`crc_kernel.crc_stream`) | **adopt** (Inc-1) |
| KAT table (7 presets + zlib) | E2 / AT-CRC-DSN-010/011 | built (`test_crc_kernel`) | adopt (Inc-1) |
| Multi-range coverage intra×join | E3 / R-CRC-DSN-008 | built (`gather_target`) | adopt (Inc-1) |
| Store width/endianness | E4 / AT-CRC-DSN-014 | built (`store_word`) | adopt (Inc-1) |
| Template loader (collect-don't-abort) | E5 / R-CRC-DSN-005 | built (`read_template`/`parse_*`) | adopt (Inc-1) |
| **LUT fast-path** | E7 / RK-6 | NOT built | **Inc-2 (new)** |
| **`on_gap_conflict` enforcement** | E8 / R-CRC-DSN-011 / RK-7 | detector built; enforcement NOT | **Inc-3 (new)** |
| Job up-converter (legacy `crc_config`) | E6 | not built | **→ batch-58** |
| Variant B TUI view | R-CRC-DSN-001/002/008/009 | not built | **→ batch-58** |

## AT/TC registry (batch-scoped, C-21 pinned)

| Node | Story | Asserts (black-box / white-box) | Realized by |
|---|---|---|---|
| AT-CRC-DSN-011 | US-CRC1 | every seed preset's engine output over `"123456789"` == its `check` | `test_crc_kernel::test_every_preset_reproduces_its_catalogue_check` |
| AT-CRC-DSN-010 | US-CRC1 | seed CRC-32 == `zlib.crc32` (4+ vectors) | `test_crc_kernel::test_seed_algorithm_equals_zlib_crc32_over_many_vectors` |
| AT-CRC-DSN-013b | US-CRC2 | two-range concat `0x9C5BCBBD` / fill `0x2A8A3950` | `test_crc_designer_model::test_join_*_oracle` |
| AT-CRC-DSN-014 | US-CRC2 | store endianness LE/BE + narrow/wide | `test_crc_designer_model::test_store_word_*` |
| AT-CRC-DSN-017 | US-CRC3 | clean gap → `[]`; stray non-pad → `[addr]`; concat → `[]` | `test_crc_designer_model::test_gap_conflict_*` |
| **TC-E7-LUT** (new) | US-CRC4 | `crc_lut` output == `crc_stream` (oracle) over all presets + N random vectors, all widths | `test_crc_kernel::test_lut_matches_bitwise_oracle` (Inc-2) |
| **AT-E8-abort** (new) | US-CRC3 | `evaluate_target` with a dirty fill gap under `abort` → refused + names the addresses | `test_crc_designer_model::test_evaluate_target_aborts_on_conflict` (Inc-3) |
| **AT-E8-warn** (new) | US-CRC3 | same conflict under `warn` → proceeds + diagnostic; under `ignore` → silent | `test_crc_designer_model::test_evaluate_target_warn_and_ignore` (Inc-3) |

## Evidence checklist (Phase-1 gate)
- ✓ Normative requirements exist on disk (`docs/crc-algorithm-designer/01-requirements.md`).
- ✓ Every adopted node maps to a test that EXISTS on disk (34 tests, verified green @ f2109cf).
- ✓ Two NEW nodes (LUT differential, enforcement branches) specified with their owning increment (C-18/C-21).
- ✓ No `should`/`debería` as a modal inside a normative statement (design doc uses `SHALL` in R-* rows).
- ✓ Draft-time execution (C-35): the LUT-equivalence claim is a code-tabelization of the shipped
  `crc_stream` bit loop — verified by the Inc-2 differential test, not assumed.

**Phase-1 axis:** Coverage complete (every story → AT; every engine item → TC), Certainty (LUT is
result-identical by construction + differential test; enforcement has one AT per branch), Evidence
(all cited nodes exist or have an owning increment). → **approve**.
