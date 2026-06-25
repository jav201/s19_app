# Traceability Matrix — US-015 (batch-14)

> Phase 6 artifact. Owner: `docs-writer`. Dual-traceability for US-015 (16/32 S19
> record width + populated S0 header). All node ids are the REAL reconciled
> `def test_*` names from `04-validation.md` (V-5 reconciliation; grep-verified on
> the tree). US-016 is out of batch-14 scope (satisfied by batch-15, §20) and is
> NOT traced here.
>
> **Audience:** engineering / QA reviewers. **Purpose:** prove every US-015
> dimension is verified on BOTH layers — Layer A (white-box `LLR → TC`) and
> Layer B (black-box `US → AT`, observed through the shipped surface).
>
> **Result (from `04-validation.md`):** PASS-WITH-NOTES — 6/6 requirements pass,
> 4/4 Layer-B AT pass, 0 blocker fails, 0 engine-frozen edits.

---

## 1. Functional chain (Layer A) — `US → HLR → LLR → TC → status → evidence`

| US | HLR | LLR | Statement (abbrev.) | Realizing node id(s) (real, on disk) | Status | Evidence node / threshold |
|----|-----|-----|---------------------|--------------------------------------|--------|---------------------------|
| US-015 | HLR-015 | LLR-015.1 | `bytes_per_line ∈ {16,32}`, default 32, else `ValueError` | `test_changes_apply.py::test_tc212_default_emit_packs_32_byte_rows` · `::test_tc213_bytes_per_line_16_back_compat_byte_identical` · `::test_tc214_invalid_bytes_per_line_raises_and_emits_nothing` | **PASS** | default ≥1 line >16 & all ≤32; 16-mode byte-identical; `{0,24,64}` → ValueError, 0 lines |
| US-015 | HLR-015 | LLR-015.2 | populated S0 (preserve-or-synth, ≤252); 16-mode empty | `test_changes_apply.py::test_tc215_populated_s0_is_inert_to_data_and_empty_when_none` · `::test_c4_overlong_s0_header_raises` · `::test_build_loaded_s19_captures_source_s0_header` | **PASS** | 32-mode S0 len>0 & inert to data-record map; 16-mode empty; >252 → ValueError; load seam captures `b"CASE01_BASIC"`, None when absent |
| US-015 | HLR-015 | LLR-015.3 | thread selector + header through both save flows | `test_changes_apply.py::test_tc219_save_patched_image_threads_width_and_s0_header` · `::test_tc220_change_service_save_patched_threads_to_emitter` · `::test_tc220b_hex_save_unaffected_by_s19_only_kwargs` | **PASS** | both call-sites emit >16/≤32 + S0 + re-parse equal; default ⇒ 32; HEX unaffected (C1) |
| US-015 | HLR-015 | LLR-015.4 | reader-as-oracle + negative control + cross-format | `test_changes_apply.py::test_tc216_32_byte_emit_reparses_byte_equal` · `::test_tc217_16_byte_emit_reparses_byte_equal` · `::test_tc218_negative_control_corrupt_data_byte_detected` · `::test_tc226_cross_format_round_trip_integrity` | **PASS** | 32 & 16 re-parse delta 0, 0 errors; corrupt DATA byte detected (non-vacuous); 3 cross-format directions map-equal |
| US-015 | HLR-015 | LLR-015.5 | engine-frozen guard — 0 diffs vs main (7 frozen paths) | `test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` · `test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main` · `::test_tc031_engine_modules_have_no_name_only_diff_vs_main` · `::test_tc032_engine_test_files_unmodified_vs_main` | **PASS** | 4 guards green; `git diff origin/main` over 7 frozen paths = empty |

**Supplemental (AT-015.2 guard, Layer A):** `test_changes_apply.py::test_fq05_hex_emitter_unmodified_16_byte_rows` — **PASS** (`HEX_DATA_BYTES_PER_RECORD == 16`; emitted HEX rows ≤16; the S19 width change does not bleed into the Intel-HEX emitter).

---

## 2. Behavioral chain (Layer B) — `US → AT → observed outcome → status`

> Observed through the SHIPPED Patch Editor save-back surface (cycling Width
> selector → real `#patch_saveback_confirm_button` → written `.s19` read off disk
> via the frozen `S19File`), except AT-015.2 which is a verification-only
> cross-format round-trip at the 32 default.

| AT | US | Observed through (shipped surface) | Observed outcome | Real node id (on disk) | Status |
|----|----|-----------------------------------|------------------|------------------------|--------|
| AT-015.1 (32 pilot, post-F1) | US-015 | save-back: Width selector cycled OFF 32 and back (F1 discriminator), `#patch_saveback_confirm_button` → on-disk `.s19` | S3 records 16<len≤32; S0 populated; data-record map == intended; a wired-but-dead button now FAILS this AT | `test_tui_patch_editor_v2.py::test_saveback_width_32_packs_wide_records_and_populates_s0` | **PASS** |
| AT-015.1 PRESERVE leg (NEW, F2) | US-015 | same surface; source image carries a content-bearing S0 (`b"SRCHDR_PRESERVE_ME"`) | written S0 == source S0 bytes (NOT the synthesized filename); load-seam capture sanity-asserted (non-vacuous) | `test_tui_patch_editor_v2.py::test_saveback_width_32_preserves_source_s0_header` | **PASS** |
| AT-015.2 (cross-format integrity) | US-015 | verification-only round-trip at the 32 default | 0 byte delta + 0 errors across S19↔re-parse, HEX→S19(32), S19→HEX | `test_changes_apply.py::test_tc226_cross_format_round_trip_integrity` | **PASS** |
| AT-015.3 (16 pilot) | US-015 | same surface, Width selector cycled to 16 | all records ≤16; S0 empty (legacy); data-record map == intended | `test_tui_patch_editor_v2.py::test_saveback_width_16_caps_records_and_empties_s0` | **PASS** |

**Reverse-edge:** 0 failures — no Layer-B AT is red while its backing Layer-A TC
is green. The C3 concern (a wired-but-dead selector passing every service-level
TC) is closed by AT-015.1's F1 button-cycle discriminator plus the preserve-leg
AT.

---

## 3. C2 — CRC-inheritance row (accepted / uniform)

| Path | What it does | Re-parse verification | Disposition |
|------|--------------|-----------------------|-------------|
| `crc.py:879` `emit_s19_from_mem_map(working_mem, working_ranges)` (positional) | inherits the **32 default** — no CRC test asserts a row width | `test_crc_operation.py:345` re-parses the CRC-injected S19 via `S19File.get_memory_map()` and verifies the map round-trips (D2); `test_crc_operation.py` + `test_tui_crc_surface.py` = **21 passed** | **✓ accepted / uniform.** CRC output → 32 bytes/record is safe by re-parse equality; no pin-to-16. |

---

## 4. Acceptance-criteria disposition (§5.3)

| # | Criterion | Status |
|---|-----------|--------|
| 1 | 100% LLR-015.* covered by ≥1 passing TC; each row has EV node + threshold | **MET** |
| 2 | `pytest -q` green + `pytest -q -m "not slow"` green, 0 blocker fails | **MET** (890 / 0 full; 869 / 0 non-slow) |
| 4 | Reader-as-oracle: 32 (TC-216) + 16 (TC-217); neg control TC-218 | **MET** |
| 5 | 16-byte byte-identical to pre-change framing (TC-213) | **MET** |
| 6 | 32-byte S0 populated yet inert via data-record map (TC-215, Amendment B) | **MET** |
| 7 | Both save call-sites threaded (TC-219 + TC-220); default 32 | **MET** |
| 8 | Frozen-engine guard 0 diffs (TC-027 / TC-031 / TC-032) | **MET** |
| 10 | Dual traceability complete (Layer A + Layer B per story) | **MET** |
| 11 | Cross-format integrity D2 (TC-226), 0 delta all directions | **MET** |
| 3, 9 (US-016) | TC-224 pre-fix-fail / TC-225 no over-correction | **N/A** — US-016 satisfied by batch-15 |

---

## 5. Notes (non-blocking)

- **N-1 (C-7 carry):** pre-existing `app.py` + `change_service.py` ruff F401/F402
  — verified byte-identical on HEAD before any batch-14 edit, **0 introduced**.
  Backlog item, out of US-015 scope.
- **N-2 (V-5 reconciliation):** spec provisional ids (TC-212..226, engine-guard
  `TC-221`/`TC-031`, AT-NNN) reconciled to the real node names above. The spec's
  `test_tc031_engine_modules_unchanged_vs_main` node does not exist on disk; the
  live guard names are `..._have_no_diff_vs_main` / `..._have_no_name_only_diff_vs_main`.
  No behavioral impact.
