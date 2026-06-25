# Validation — s19_app — Batch 2026-06-23-batch-14 (Phase 4)

> Phase 4 artifact. Owner: `qa-reviewer`. Executes the validation strategy fixed in Phase 1. Language: English.
> **Scope:** US-015 only (16/32 S19 record width + populated S0 header). US-016 / HLR-016 / LLR-016.* / AT-016.* are SATISFIED-BY-BATCH-15 (main `9169130`, PR #20) — out of batch-14 scope, NOT validated here.
> **Branch:** `claude/batch-14-us015` (Phase 3 complete: Inc1+Inc2+Inc3 committed). **Phase-4 hardening F1/F2/F3 applied, NOT committed.** Base = `origin/main 9169130`.

## ✅ Verdict (read first)

- **Result:** **PASS-WITH-NOTES** (0 blocker fails → no iterate-to-fix; advance to Phase 5).
- **Requirements:** **6/6 pass** (HLR-015 + LLR-015.1/.2/.3/.4/.5) · **0 blocker fails**.
- **Layer B (black-box AT):** 4/4 pass (AT-015.1 post-F1, AT-015.1 preserve-leg [NEW F2], AT-015.2, AT-015.3) · **0 reverse-edge failures**.
- **Surface-reachability:** ✓ all US-015 dimensions reach the shipped save-back surface (no service-kwargs-only dimension).
- **Supersession inspection:** ✓ N/A — no superseded placeholder/marker in US-015 scope (additive feature, no deferral retired).
- **Test ledger:** ✓ reconciles — 903 base + 18 (Inc1+2+3) = 921 + 1 (F2 AT) = **922 collected**.
- **Engine-frozen:** ✓ **0 edits** vs `origin/main` over all 7 frozen paths (guards green).
- **Evidence checklist (qa-reviewer):** ✓ complete (12/12).
- **NOTES (non-blocking):** pre-existing `app.py` + `change_service.py` ruff F401/F402 (batch-15 carry **C-7**, NOT introduced); provisional spec ids (TC-212..226 / engine-guard TC-031→TC-027 / AT) reconciled to real node names.

> If every line is ✓, the Detail below is reference only. The two NOTES are non-blocking and documented in §Gaps.

---

## STEP 1 — Phase-4 hardening (3 binding items closed)

| Item | What was done | File(s) | Verify |
|---|---|---|---|
| **F1** | AT-015.1 (32-mode pilot) now cycles the Width selector OFF its current value and back (`exercise_toggle=True`), asserting the displayed value changed mid-cycle (`assert panel._saveback_width != start_width`). A wired-but-dead button now fails AT-015.1 directly — no longer relying on the default-32 value (AT-015.3 was the sole discriminator before). | `tests/test_tui_patch_editor_v2.py` (`_drive_saveback_width` + `test_saveback_width_32_packs_wide_records_and_populates_s0`) | file 16 passed |
| **F2** | NEW preserve-leg black-box AT: loads an S19 whose S0 has NON-EMPTY data (`b"SRCHDR_PRESERVE_ME"` via `_make_wide_s19_image_with_s0`), saves in 32-mode through the shipped selector, reads the written `.s19` off disk, asserts emitted S0 data == **source** S0 bytes (not the synthesized filename) + a load-seam-capture sanity guard (non-vacuous). One-line note added to the `app.py` save-back handler docstring: empty source S0 (falsy) → synthesized, same as `None` (`source_s0_header or synth`). Docstring-only prod touch; 0 behavior change. | `tests/test_tui_patch_editor_v2.py` (`test_saveback_width_32_preserves_source_s0_header`) + `s19_app/tui/app.py` (docstring ~L1446-1452) | new AT passes; full suite green |
| **F3** | Trimmed the misleading `_data_record_map` docstring (removed the overstated `get_memory_map`-folds-at-address-0 claim the test never relies on; now states only the firmware-payload-oracle purpose). | `tests/test_tui_patch_editor_v2.py` | comment-only |

**ruff on touched files:** `tests/test_tui_patch_editor_v2.py` → **All checks passed**. `s19_app/tui/app.py` → 6 errors, **all pre-existing** (verified byte-identical on `git stash`/HEAD round-trip: F401 imports L27/37/38/39/107 + F402 loop-var L7163; batch-15 carry **C-7**) — **0 introduced** by the F2 docstring edit (L1446-1452, far from any error). Increment discipline held: 1 test file + 1 prod docstring.

---

## STEP 2 — Authoritative suite run

| Run | Command | Result | Exit |
|---|---|---|---|
| Full | `python -m pytest -q` | **890 passed, 29 skipped, 3 xfailed, 0 failed** (922 collected, 769.68s) | **0** |
| Non-slow | `python -m pytest -q -m "not slow"` | **869 passed, 29 skipped, 21 deselected, 3 xfailed, 0 failed** (901 collected, 279.24s) | **0** |

Collected reconciliation: 890 + 29 skipped + 3 xfailed = **922** (full) ✓; 869 + 29 + 21 deselected + 3 = **922** (non-slow view) ✓. The 21 deselected = `slow`-marked stress tests; the 3 xfailed + 29 skipped are pre-existing, unrelated to US-015.

---

## Detail (reference)

### Per-requirement results (Layer A — functional, TC ↔ LLR)

All provisional ids reconciled to real `def test_*` names on disk (V-5 — file paths, `-k` selectors, and node ids all grep-verified on the tree).

| Req | Method | Real node id(s) (verified on disk) | Numeric threshold | Result | Evidence |
|-----|--------|------------------------------------|-------------------|--------|----------|
| **HLR-015** | test + analysis | (decomposed below; observed end-to-end by AT-015.1/.3 + TC-216/217/219/220/226) | 32-mode ≤32B records + populated S0, re-parse data-map byte-equal | **PASS** | 32 emits ≤32B S3 + S0; 16 preserves legacy; suite green |
| **LLR-015.1** bytes_per_line {16,32} def 32, ValueError else | test (unit) | `test_changes_apply.py::test_tc212_default_emit_packs_32_byte_rows`, `::test_tc213_bytes_per_line_16_back_compat_byte_identical`, `::test_tc214_invalid_bytes_per_line_raises_and_emits_nothing` | default ≥1 line >16 & ≤32; 16 byte-identical; invalid→ValueError 0 lines | **PASS** | validate-before-emit (F-S-03); `{0,24,64}`→ValueError |
| **LLR-015.2** populated S0 (preserve-or-synth, ≤252) | test (unit+int) | `::test_tc215_populated_s0_is_inert_to_data_and_empty_when_none`, `::test_c4_overlong_s0_header_raises`, `::test_build_loaded_s19_captures_source_s0_header` | 32 S0 len>0 & inert to data-map; 16 empty; >252→ValueError; 252 OK | **PASS** | Amendment A bound; load seam captures `b"CASE01_BASIC"`, None when absent |
| **LLR-015.3** thread selector+header through both save flows | test (int) | `::test_tc219_save_patched_image_threads_width_and_s0_header`, `::test_tc220_change_service_save_patched_threads_to_emitter`, `::test_tc220b_hex_save_unaffected_by_s19_only_kwargs` | both call-sites emit >16/≤32 + S0 + re-parse equal; default⇒32; HEX unaffected | **PASS** | two-hop F-A-05; C1 HEX branch isolated |
| **LLR-015.4** reader-as-oracle + neg control + cross-format | test (int) | `::test_tc216_32_byte_emit_reparses_byte_equal`, `::test_tc217_16_byte_emit_reparses_byte_equal`, `::test_tc218_negative_control_corrupt_data_byte_detected`, `::test_tc226_cross_format_round_trip_integrity` | 32 & 16 re-parse delta 0, 0 errors; corrupt data byte detected; cross-format map-equal all dirs | **PASS** | non-vacuous (F-Q-06 data byte); 3 cross-format directions |
| **LLR-015.5** engine-frozen guard (was provisional LLR-015.x / TC-221) | inspection | `test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main`, `test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main`, `::test_tc031_engine_modules_have_no_name_only_diff_vs_main`, `::test_tc032_engine_test_files_unmodified_vs_main` | 0 diffs vs main in 7 frozen paths | **PASS** | 4 guards green; `git diff origin/main` over 7 frozen paths = empty |

**F-Q-05 supplemental (AT-015.2 guard):** `::test_fq05_hex_emitter_unmodified_16_byte_rows` — PASS (`HEX_DATA_BYTES_PER_RECORD==16`, emitted HEX rows ≤16).

### Layer B — black-box acceptance (AT ↔ US), observed through the SHIPPED surface

| AT | Story | Observed through | Real node id (on disk) | Result | Evidence |
|---|---|---|---|---|---|
| **AT-015.1** (32 pilot, post-F1) | US-015 | Patch Editor save-back: selector cycled OFF 32 and back (F1), real `#patch_saveback_confirm_button` → written `.s19` read off disk via frozen `S19File` | `test_tui_patch_editor_v2.py::test_saveback_width_32_packs_wide_records_and_populates_s0` | **PASS** | S3 records 16<len≤32; S0 populated; data-map == intended; dead button now fails |
| **AT-015.1 PRESERVE leg** (NEW, F2) | US-015 | same shipped surface; source image carries content-bearing S0 | `::test_saveback_width_32_preserves_source_s0_header` | **PASS** | written S0 == `b"SRCHDR_PRESERVE_ME"` (source) not filename; capture sanity-asserted |
| **AT-015.3** (16 pilot) | US-015 | same shipped surface, selector cycled to 16 | `::test_saveback_width_16_caps_records_and_empties_s0` | **PASS** | all records ≤16; S0 empty (legacy); data-map == intended |
| **AT-015.2** (cross-format integrity) | US-015 | verification-only round-trip at the 32 default | `test_changes_apply.py::test_tc226_cross_format_round_trip_integrity` | **PASS** | 0 byte delta + 0 errors S19↔reparse / HEX→S19(32) / S19→HEX |

**Dual-traceability — BOTH chains confirmed for US-015:**
- **US→AT→outcome (Layer B):** US-015 → AT-015.1 (`test_saveback_width_32_packs...` + preserve-leg) / AT-015.2 (`test_tc226...`) / AT-015.3 (`test_saveback_width_16_caps...`) → observed on-disk through the shipped save-back widget.
- **US→HLR→LLR→TC (Layer A):** US-015 → HLR-015 → LLR-015.1/.2/.3/.4/.5 → the `test_tc212..220b` / `test_tc226` / `test_c4...` / engine-guard nodes above.

### Surface-reachability matrix (A-5, batch-11 SCOPE-1)

| US dimension | Shipped surface (call-site) | Service param reached | Through-surface node | Status |
|--------------|-----------------------------|-----------------------|----------------------|--------|
| bytes_per_line 16/32 — **save-back selector** | `#patch_saveback_width_button` → `SaveBackDecision` → `app.py` handler → `save_patched` | `emit_s19_from_mem_map(..., bytes_per_line=)` | AT-015.1 (`...packs_wide...`) + AT-015.3 (`...caps_records...`) on-disk | ✓ |
| bytes_per_line — `save_patched_image` | `save_patched_image(..., bytes_per_line=)` | same emitter kwarg | TC-219 | ✓ |
| bytes_per_line — `change_service.save_patched` (two-hop) | `ChangeService.save_patched(..., bytes_per_line=)` | forwarded two hops | TC-220 | ✓ |
| populated S0 (32) — **preserve** | save-back handler `source_s0_header or synth` | emitter `s0_header=` branch | AT-015.1 preserve leg (`...preserves_source_s0_header`) | ✓ |
| populated S0 (32) — **synthesize** | save-back handler `_synth_s0_header_from_filename` | emitter `s0_header=` branch | AT-015.1 (`...packs_wide...`, no source S0) + TC-219 | ✓ |
| **CRC inheritance (C2)** | `crc.py:879` `emit_s19_from_mem_map(working_mem, working_ranges)` positional → inherits **32 default** | emitter default path | `test_crc_operation.py:345` re-parses CRC output via `S19File.get_memory_map()` vs intended (`test_crc_operation.py` + `test_tui_crc_surface.py` = 21 passed) | ✓ accepted / uniform |

**C2 disposition:** CRC→32 is accepted as uniform output. No CRC test asserts a row width; `test_crc_operation.py:345` re-parses the CRC-injected S19 and verifies the map round-trips (D2), so the default flip is safe by re-parse equality. No pin-to-16.
**No story dimension is service-kwargs-only:** the operator's 16/32 choice and the S0 preserve/synthesize policy are both observed end-to-end through the Patch Editor save-back widget → on-disk file (AT-015.1/.3 + preserve leg), not merely via direct emitter kwargs. The `variant_execution_service.py:711` project-save path threads `bytes_per_line=32` (Inc2), exercised by its consumer suite (29 passed, Inc2 packet).

### Reverse-edge check

**0 reverse-edge failures.** No black-box AT fails while its white-box TC passes. All AT-015.* PASS; all backing TC-212..226 PASS. The C3 motivation (a wired-but-dead selector passing all service-level TCs) is closed by AT-015.1's F1 button-cycle discriminator + the preserve-leg AT.

### Invariants

| Invariant | Node(s) | Status | Evidence |
|---|---|---|---|
| Reader-as-oracle byte-equality (data-record map, Amendment B) | TC-216, TC-217, + AT-015.1/.3 pilots (`_data_record_map`) | **PASS** | 32 & 16 re-parse byte-equal; pilots assert `_data_record_map(reparsed) == intended` on-disk |
| Non-vacuous negative control (DATA byte not inert S0 — F-Q-06) | TC-218 | **PASS** | flips an S3 data byte → re-parsed map ≠ intended OR errors ≠ [] |
| Cross-format integrity (S19↔HEX all directions) | TC-226 | **PASS** | 0 byte delta + 0 errors, 3 directions at 32 default |
| C4 S0 ≤252 bound (Amendment A) | `test_c4_overlong_s0_header_raises` | **PASS** | >252→ValueError 0 records; 252 boundary accepted + re-parses 0 errors |
| C1 HEX-unaffected by S19-only kwargs | TC-220b | **PASS** | HEX save with `bytes_per_line=32` writes valid `.hex`, no TypeError, map-equal |
| S0 inertness to firmware payload (data-record map) | TC-215, AT-015.1/.3 | **PASS** | populated S0 adds 0 DATA addresses; firmware records round-trip byte-equal |
| **0 engine-frozen edits** vs origin/main | `git diff --name-only origin/main` over 7 frozen paths + TC-027/TC-031/TC-032 guards | **PASS** | diff empty; 4 guard tests green |

### Supersession-completeness inspection (batch-09 V-3)

| Superseded marker | grep result | All surviving refs negative? | Evidence |
|-------------------|-------------|------------------------------|----------|
| *(none in US-015 scope)* | N/A | N/A | US-015 is an **additive** feature (new `bytes_per_line` / `s0_header` params + new selector widget); no placeholder/deferral/"not-yet" constant was retired or superseded. The only premise correction (Amendment B, S0-inertness) is documented inline in TC-215 / `_data_record_map`, not a removed marker. |

### Signed-balance test ledger (batch-07 / 09)

| base | + Inc1 | + Inc2 | + Inc3 | = Phase-3 | + F2 | = post | actual collected | passed-full / lean | reconciles? |
|------|--------|--------|--------|-----------|------|--------|------------------|--------------------|-------------|
| 903 | +13 | +3 | +2 | 921 | +1 | **922** | **922** | 890 (full) / 869 (non-slow) | **yes** |

F1 added 0 nodes (modified an existing test's helper call to exercise the button); F3 is comment-only. F2 added exactly 1 node (`test_saveback_width_32_preserves_source_s0_header`).

### Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| N-1 | (cross-cutting) | Pre-existing ruff F401/F402: `app.py` 6 errors (F401 L27/37/38/39/107 + F402 L7163), `change_service.py:38` F401 `typing.List`. Verified byte-identical on HEAD before the Phase-4 docstring edit — **0 introduced this batch**. | minor (non-blocking) | Backlog **C-7** (standalone app.py ruff cleanup), out of US-015 scope. |
| N-2 | (V-5 reconciliation) | Spec provisional ids reconciled: engine guard `LLR-015.x`/`TC-221`/`-k engine_unchanged` → `test_tc027_engine_modules_unchanged_vs_main` + `test_tc031_*`/`test_tc032_*` (spec's `test_tc031_engine_modules_unchanged_vs_main` node name does not exist; live names are `..._have_no_diff_vs_main`); TC-212..220b/226/C4/F-Q-05 all in `test_changes_apply.py` (no `test_changes_io.py`); AT pilots in `test_tui_patch_editor_v2.py` with descriptive names. | minor (non-blocking) | Reconciled in this doc; Phase-6 may align spec text. No behavioral impact. |
| — | AT-016.* / TC-222..225 (US-016) | NOT validated — satisfied by batch-15 (main §20). | N/A | Out of batch-14 scope per `02-review.md`; §5.2 US-016 rows retained for traceability only. |

### Batch acceptance criteria (§5.3) — disposition

| # | Criterion | Status |
|---|---|---|
| 1 | 100% LLR-015.* covered by ≥1 passing TC; each row has EV node + threshold | **MET** |
| 2 | `pytest -q` green + `pytest -q -m "not slow"` green, 0 blocker fails | **MET** (890/0 + 869/0) |
| 4 | Reader-as-oracle: 32 (TC-216) + 16 (TC-217); neg control TC-218 | **MET** |
| 5 | 16-byte byte-identical to pre-change framing (TC-213) | **MET** |
| 6 | 32-byte S0 populated yet inert: data-record map (TC-215, Amendment B) | **MET** |
| 7 | Both save call-sites threaded (TC-219 + TC-220); default 32 | **MET** |
| 8 | Frozen-engine guard 0 diffs (TC-027/TC-031) | **MET** |
| 10 | Dual traceability complete (Layer A + Layer B per story) | **MET** |
| 11 | Cross-format integrity D2 (TC-226), 0 delta all directions | **MET** |
| *(3, 9 — US-016)* | TC-224 pre-fix-fail / TC-225 no over-correction | **N/A** — US-016 satisfied by batch-15 |

### Evidence checklist — qa-reviewer (full)

- [✓] Acceptance criteria use Given/When/Then equivalent — HLR-015/LLR-015.* are EARS (`Where/When … shall`); AT-015.* state observable outcome through the shipped surface. *(01-requirements.md §3/§4)*
- [✓] Test cases have explicit Expected, not vague "works" — every TC asserts numeric thresholds (≤32, >16, S0 len>0, map delta 0, ValueError). *(test_tc212..220b bodies)*
- [✓] Edge cases include empty/boundary/invalid/error — TC-214 invalid bpl→ValueError; C4 252-boundary + 253-overflow; TC-218 corrupt data byte; 16-mode empty S0. *(test_tc214, test_c4_overlong_s0_header_raises, test_tc218)*
- [✓] Regression checklist — full suite + CRC inheritance (21 passed) + HEX-unaffected (TC-220b) + engine guards (4 passed). *(890 passed full run)*
- [✓] Exit criteria stated — §5.3 disposition table above. *(this doc)*
- [✓] No real PII/secrets — fixtures only (`b"SRCHDR_PRESERVE_ME"`, `b"HDR"`, public `case_01_basic_valid/firmware.s19`). *(test sources)*
- [✓] Test results NOT left blank — suite actually run, exit 0 both runs. *(bp588on91 / bimszh385 task outputs)*
- [✓] Layer B black-box — every output-producing US-015 deliverable observed through the shipped save-back surface with boundary (16<len≤32, ≤16) + negative (dead-button via F1, vacuous-preserve sanity guard) evidence. *(AT-015.1/.3 + preserve-leg pilots)*
- [✓] Bidirectional surface-reachability — every input (bytes_per_line, S0 preserve/synth) AND output (on-disk `.s19` record width + S0) exercised through the handler, not only the service API. *(A-5 matrix)*
- [✓] No unfilled template — all `<…>`/`TC-NNN` provisional placeholders reconciled to real node ids; no empty required rows. *(per-req + Layer B tables)*
- [✓] Reverse-edge — 0 AT red while white-box green. *(Reverse-edge check)*
- [✓] 0 engine-frozen edits — `git diff --name-only origin/main` over 7 frozen paths empty + guards green. *(Invariants last row)*

---

## Final verdict: **PASS-WITH-NOTES**

US-015 is fully validated end-to-end through the shipped Patch Editor save-back surface across both record widths (16/32) and both S0 policies (preserve + synthesize), with reader-as-oracle byte-equality, a non-vacuous negative control, cross-format integrity, the C4 length bound, C1 HEX-isolation, and C2 CRC-inheritance all green. Full suite **890 passed / 0 failed**; non-slow **869 passed / 0 failed**; **0 engine-frozen edits**. The only NOTES are the pre-existing batch-15 C-7 ruff debt (not introduced) and the V-5 provisional-id reconciliation (no behavioral impact). **No blocker fails → no iterate-to-fix; advance to Phase 5 (post-mortem).**
