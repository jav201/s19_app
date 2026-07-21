# Validation Reconciliation — s19_app — Batch 58 (CRC Algorithm Designer "Variant B" view + engine prerequisites)

> Phase-4 validation. Two-layer model (Layer B black-box AT → shipped surface; Layer A white-box TC → LLR).
> Branch `feat/batch-58-crc-designer-view`, HEAD `b809c98`. Base `1e3125b`.
> Method: verified against the on-disk tree (test bodies read; AT-bearing files executed by node/file). Frozen-guard tests NOT run (checkout hazard) — verified statically.
> Gate suite counts are the orchestrator's C-25 run; the AT/TC node evidence below is this reviewer's independent execution.

---

## 1. Gate verdict — **PASS**

All three axes met:

- **Coverage** ✓ — every one of the 19 ATs reconciles to **exactly one** on-disk collected node that jointly drives the whole named chain through the shipped surface (§2). All 22 LLRs (§3) have ≥1 verifying test. No AT is "covered only in parts" → **0 UNREALIZED ATs**.
- **Certainty** ✓ — the 5 spot-checked ATs (016, 058-04, 058-05, 058-07, 058-06) are confirmed non-vacuous (§5).
- **Evidence** ✓ — 52 AT/TC nodes executed GREEN (§4); frozen set statically clean (0 diffs, §4.3); the 19 snapshot failures are all expected rail-drift, not functional regressions (§4.2); no non-snapshot functional failure remains.

No unmet axis. The only residual is the expected **canonical-CI snapshot regen** of the 19 rail-drift cells (a closeout PR, per C-22/C-28), which is baseline maintenance, not a defect.

---

## 2. Layer B — AT → single collected node (C-18 reconciliation)

19 ATs, each mapped to exactly one node that joins the full chain through the shipped surface (Textual Pilot on the mounted screen, or headless artifact/oracle for the engine stories). All PASS.

| # | AT | US / HLR | Single joined node (`file::test`) | Shipped-surface observation | Status |
|---|----|----------|-----------------------------------|------------------------------|--------|
| 1 | AT-CRC-DSN-014 | US-E4 | `test_crc_word_codec.py::test_at_crc_dsn_014_encode_word_endianness` | `crc.encode_word`/`encode_le` return asserted bytes; big MSB-first, little == `encode_le` | PASS |
| 2 | AT-CRC-DSN-015 (engine) | US-E5 | `test_crc_template_loader.py::test_collect_dont_abort_malformed_json` | `crc_template.read_template` (facade) → `(None, [one error])`, no raise | PASS |
| 3 | AT-CRC-DSN-012 | US-E5 | `test_crc_job_upconvert.py::test_at_crc_dsn_012_template_round_trip_is_identical` | `parse_template(emit_template(seed))[0] == seed`, `errors==[]` | PASS |
| 4 | AT-CRC-DSN-010 | US-E6 | `test_crc_job_upconvert.py::test_llr_e6_1_upconvert_digest_matches_compute_group_crc_semantics` | flat text → `parse_job` up-convert → `compute_target_crc == crc.compute_group_crc == 0x9C5BCBBD` (fidelity anchor, non-vacuous fixture) | PASS |
| 5 | AT-058-01 | US-E6 | `test_crc_job_upconvert.py::test_at_058_01_flat_upconvert_round_trips_through_emit_job` | flat `DUMMY_CONFIG_TEXT` → `parse_job` → `emit_job` → `parse_job` == equal job, `errors==[]` | PASS |
| 6 | AT-058-02 | US-V1 | `test_crc_designer_view.py::test_form_and_preset_populates_off_seed_without_mutating_catalogue` | mounted selector: seed→MODBUS measured delta (width 32→16, poly, xorout); `PRESETS` object+value unchanged | PASS |
| 7 | AT-CRC-DSN-011 | US-V2 | `test_crc_designer_view.py::test_live_verdict_every_preset_reads_match` | every `crc_kernel.PRESETS` (len≥7) → MATCH read from mounted `#crc_kat_verdict` | PASS |
| 8 | AT-CRC-DSN-016 | US-V2 | `test_crc_designer_view.py::test_live_verdict_transitions_on_single_field_events` | before/after single `Input.Changed`: MATCH→MISMATCH, MISMATCH→NO-EXPECTED, no Run between (transition asserted) | PASS |
| 9 | AT-058-03 | US-V3 | `test_crc_designer_view.py::test_custom_vector_ascii_and_hex_reproduce_kat` | ASCII + hex vectors → mounted `#crc_custom_vector_result` == `SEED_ALGORITHM.kat()` (0xCBF43926) | PASS |
| 10 | AT-058-04 | US-V4 | `test_crc_designer_view.py::test_json_preview_roundtrips_through_mounted_widget` | reads mounted `#crc_json_preview` content, `parse_template(that text)[0] == MODBUS template`, `errors==[]` | PASS |
| 11 | AT-058-05 | US-V5 | `test_crc_designer_view.py::test_save_then_load_roundtrip_through_view` | press Save → real `MyVariant.crc.json` on disk → perturb → press Load → every field == originals | PASS |
| 12 | AT-058-06 | US-V5 | `test_crc_designer_view.py::test_hostile_template_renders_literally_at_preview` | hostile `[bold]x[/]`+ANSI at `#crc_json_preview`: literal in `plain`, `render_markup is False`, `spans == []` | PASS |
| 13 | AT-CRC-DSN-015 (view) | US-V5 | `test_crc_designer_view.py::test_load_malformed_file_surfaces_one_error` | Load bad JSON via view → `#crc_loadsave_status` "Load failed:", verdict still MATCH (app alive) | PASS |
| 14 | AT-058-10 | US-V5 | `test_crc_designer_view.py::test_three_warn_conditions_through_view` | one session: fill-no-`pad_byte`, `store_width<ceil(width/8)`, `check` mismatch on Save each paint their warning | PASS |
| 15 | AT-CRC-DSN-013 | US-V6 | `test_crc_designer_view.py::test_coverage_single_range_skip_equals_region_crc` | single-range skip preview == `crc.compute_region_crc` (pinned 0x88AA689F) through `#crc_coverage_preview` | PASS |
| 16 | AT-CRC-DSN-013b | US-V6 | `test_crc_designer_view.py::test_coverage_preview_shows_both_policy_oracles` | §3.2 fixture, two-range fill: both `0x9C5BCBBD` (concat) + `0x2A8A3950` (fill) in mounted preview | PASS |
| 17 | AT-058-07 | US-V6 | `test_crc_designer_view.py::test_coverage_preview_shows_both_policy_oracles` (same node — identical behavioral claim, M5) | §3.2 oracle hexes READ from the mounted widget, not "two numbers render" | PASS |
| 18 | AT-CRC-DSN-017 | US-V7 | `test_crc_designer_view.py::test_gap_conflict_clean_previews_dirty_abort_refuses` | clean→CRC; dirty+abort→"refused"+addr `0x800A`, NO CRC; warn→CRC+diag; ignore→CRC silent; concat→CRC | PASS |
| 19 | AT-058-08 | US-V7 | `test_crc_designer_view.py::test_gap_conflict_clean_previews_dirty_abort_refuses` (same node — identical gap-conflict claim) | same painted-content assertions (C-32) | PASS |
| — | AT-058-09 | US-V8 | `test_crc_designer_view.py::test_preview_only_mem_map_unchanged` | 0 firmware-writer symbols in view source; after full interaction `mem_map` is same object + identical contents | PASS |

**Node count reconciliation.** 19 ATs → 17 distinct nodes: two AT pairs (013b/058-07 and 017/058-08) legitimately share one node because each pair is a single behavioral claim; C-18 ("each AT → exactly one node") holds — no AT is split across parts. AT-058-09 (US-V8) is the 19th surface (listed unnumbered above to keep the 19-row engine/view AT set clean); it is realized + passing.

> Note on AT-CRC-DSN-015 dual-listing: the AT appears in both HLR-E5 (engine facade) and HLR-V5 (view Load). Both surfaces have their own single joined node (rows 2 and 13). Neither is "covered in parts".

**UNREALIZED ATs: none.** Every AT has a single joined node observed through the shipped surface, all green.

---

## 3. Layer A — LLR → verifying TC (white-box)

All 22 LLRs trace to ≥1 real test node. Engine LLRs (E4/E5/E6) and view LLRs (V1..V8) below.

| LLR | Verifying node(s) (`file::test`) | Status |
|-----|----------------------------------|--------|
| E4.1 `encode_word` | `test_crc_word_codec.py::{test_at_crc_dsn_014_encode_word_endianness, test_tc_e4_1_wider_field_zero_extends, test_tc_e4_1_overflow_raises, test_tc_e4_1_unknown_endianness_raises}` | PASS |
| E4.2 `decode_word` | `test_crc_word_codec.py::test_tc_e4_2_decode_word_round_trip` (param little/big × w∈{1,2,4,8}) | PASS |
| E4.3 LE wrappers byte-identical | `test_crc_word_codec.py::test_tc_e4_3_le_wrappers_byte_identical` | PASS |
| E5.1 facade identity | `test_crc_template_loader.py::test_facade_identity_reexports_by_object_identity` (object `is`) | PASS |
| E5.2 collect-don't-abort | `test_crc_template_loader.py::{test_collect_dont_abort_malformed_json, _over_cap, _non_object_top_level, _missing_required_field, test_valid_template_reads_clean}` | PASS |
| E6.1 flat up-convert | `test_crc_job_upconvert.py::test_llr_e6_1_*` (6: zero-errors, field-mapping, region-target, group-target, digest-fidelity, groups-only) | PASS |
| E6.2 evolved + collect unchanged | `test_crc_job_upconvert.py::test_llr_e6_2_*` (4: algorithm_ref, inline, malformed-one-error, neither-regions-nor-groups) | PASS |
| E6.3 `emit_job` round-trip | `test_crc_job_upconvert.py::{test_at_058_01_flat_upconvert_round_trips_through_emit_job, test_llr_e6_3_emit_round_trip_two_targets_mixed_join}` | PASS |
| V1.1 screen scaffold + rail wiring | `test_crc_designer_view.py::test_routing_key_0_shows_crc_designer_hides_others` | PASS |
| V1.2 form fields + preset population | `test_crc_designer_view.py::test_form_and_preset_populates_off_seed_without_mutating_catalogue` | PASS |
| V2.1 recompute-on-change verdict | `test_crc_designer_view.py::{test_live_verdict_transitions_on_single_field_events, test_live_verdict_every_preset_reads_match}` | PASS |
| V2.2 compute-boundary fault guard | `test_crc_designer_view.py::test_verdict_fault_guard_out_of_range_width` | PASS |
| V3.1 custom vector parse+compute | `test_crc_designer_view.py::test_custom_vector_ascii_and_hex_reproduce_kat` | PASS |
| V4.1 emit+re-parse preview | `test_crc_designer_view.py::test_json_preview_roundtrips_through_mounted_widget` | PASS |
| V5.1 load through facade | `test_crc_designer_view.py::test_load_malformed_file_surfaces_one_error` | PASS |
| V5.2 save+KAT+name-normalize+roundtrip | `test_crc_designer_view.py::{test_save_then_load_roundtrip_through_view, test_save_all_symbol_name_writes_nothing_and_warns}` | PASS |
| V5.3 markup-safe (6 sinks incl. JSON preview) | `test_crc_designer_view.py::test_hostile_template_renders_literally_at_preview` (`spans==[]`) | PASS |
| V5.4 three warn conditions | `test_crc_designer_view.py::{test_three_warn_conditions_through_view, test_save_check_mismatch_warns_but_still_writes, test_store_width_too_small_warns_live}` | PASS |
| V6.1 coverage editor | `test_crc_designer_view.py::test_coverage_inverted_range_warns_not_crash` | PASS |
| V6.2 per-policy preview | `test_crc_designer_view.py::{test_coverage_preview_shows_both_policy_oracles, test_coverage_single_range_skip_equals_region_crc, test_coverage_no_image_shows_empty_state}` | PASS |
| V7.1 gap-conflict + policy branch | `test_crc_designer_view.py::test_gap_conflict_clean_previews_dirty_abort_refuses` | PASS |
| V8.1 no firmware-write path (negative) | `test_crc_designer_view.py::test_preview_only_mem_map_unchanged` (source inspection + behavioral) | PASS |

Supplementary (model/kernel layer, not the gate): AT-CRC-DSN-013b oracle also pinned in `test_crc_designer_model.py`; AT-CRC-DSN-010/011 anchored in `test_crc_kernel.py`. These reinforce but do not substitute for the through-surface nodes above.

---

## 4. Bidirectional surface-reachability matrix

Every named input dimension AND every output/deliverable is exercised/observed **through the mounted handler** (Textual Pilot) or **artifact-on-disk**, not only via a service API.

### 4a. Inputs → exercised through the handler

| Input dimension | Handler control (driven via Pilot) | Exercising node |
|-----------------|-------------------------------------|-----------------|
| Rail navigation | `pilot.press("0")` → `action_show_screen` | routing |
| Preset selection | `#crc_preset_select` (Select) | form_and_preset, every_preset, json_preview |
| Algorithm fields (width/poly/init/xorout/check) | `#crc_field_*` (Input) | verdict transitions, form_and_preset, save_roundtrip |
| Reflect switches (refin/refout) | `#crc_field_refin/refout` (Switch) | save_roundtrip (restore asserted) |
| Serialization (store_width/store_endianness) | `#crc_field_store_width/endianness` | store_width_too_small, three_warn |
| Custom vector + mode | `#crc_custom_vector` / `#crc_custom_vector_mode` | custom_vector |
| Coverage ranges/intra_gap/join/pad_byte/on_gap_conflict | `#crc_coverage_*` | coverage_preview, gap_conflict, three_warn, inverted_range |
| Save / Load / load-path | `#crc_save_btn` / `#crc_load_btn` (Button), `#crc_load_path` | save_roundtrip, load_malformed, hostile, save_all_symbol |

### 4b. Outputs / deliverables → observed through the shipped surface

| Output / deliverable | Observed via | Node |
|----------------------|--------------|------|
| KAT verdict (tri-state) | mounted `#crc_kat_verdict.content` | verdict transitions, every_preset, fault_guard |
| Custom-vector CRC | mounted `#crc_custom_vector_result` | custom_vector |
| JSON preview (round-trip + hostile literal) | mounted `#crc_json_preview` render/content + spans | json_preview, hostile |
| Coverage preview (oracle hexes, refusal, diagnostics, no-image) | mounted `#crc_coverage_preview` | coverage_preview, single_range, gap_conflict, no_image |
| Warnings | mounted `#crc_warnings` | store_width_too_small, three_warn |
| Load/Save status | mounted `#crc_loadsave_status` | save_roundtrip, load_malformed, save_all_symbol, mismatch |
| **`*.crc.json` template on disk** | `saved.exists()` under fixed `.s19tool/templates/` + re-Load | save_roundtrip, save_all_symbol (F2 negative) |
| **No firmware artifact / `mem_map` unchanged** | source inspection + `mem_map is` identity after full interaction | preview_only |

Both directions reach the handler; no output-producing story is asserted only white-box on the mechanism.

---

## 5. Certainty spot-check — 5 formerly-vacuous ATs confirmed non-vacuous

| AT | Vacuity risk | On-disk evidence it is now genuine | Verdict |
|----|--------------|-------------------------------------|---------|
| AT-CRC-DSN-016 | end-state-only | asserts `before=="MATCH"`, `after_break=="MISMATCH"`, `before != after_break`, then `after_clear=="NO-EXPECTED"`, `after_break != after_clear` — two real single-event TRANSITIONS captured with no Run between (view.py:214-224) | non-vacuous |
| AT-058-04 | reads `emit()` not widget | parses `str(query_one("#crc_json_preview").content)` READ FROM THE MOUNTED WIDGET, asserts `== CrcTemplate(MODBUS)` and `errors==[]` (view.py:313-321) | non-vacuous |
| AT-058-05 | headless round-trip | presses `#crc_save_btn` → asserts real `MyVariant.crc.json` exists on disk → perturbs form → presses `#crc_load_btn` → `restored == originals` incl. switches (view.py:398-441) | non-vacuous |
| AT-058-07 | fixture disjoint from ranges | `_fixture_mem()` populates `0x8000-0x8008` ∪ `0x8010-0x8018` (the exact target ranges); asserts BOTH `0x9C5BCBBD` and `0x2A8A3950` present — a disjoint fixture would digest `b''` and drop the oracles (view.py:670-688) | non-vacuous |
| AT-058-06 | crash-only ("no crash") | asserts `"[bold]x[/]" in plain` AND `render_markup is False` AND `spans == []` at `#crc_json_preview` — an interpreted `[bold]` would have produced a style span (view.py:485-490) | non-vacuous |

---

## 6. Gate-run evidence

### 6.1 Counts (orchestrator C-25 run)
- Full suite `pytest -q -m "not slow" -k "not tc031" --ignore=test_engine_unchanged.py` → **1757 passed, 2 skipped, 3 xfailed, 23 failed**.
  - **23 failed = 19 expected snapshot rail-drift + 4 census escapes (since FIXED at `b809c98`)**.
- Post-fix re-verification `test_tui_directionb.py + test_tui_patch_history_strip.py -k "not tc031"` → **179 passed, 0 failed** (the 4 census escapes closed). Independently re-run by this reviewer at `b809c98` (see §6.4).
- **Reviewer independent run:** `test_crc_word_codec.py test_crc_template_loader.py test_crc_job_upconvert.py test_crc_designer_view.py` → **52 passed, 0 failed** (all AT/TC nodes in §2–§3).

### 6.2 The 19 snapshot failures — expected rail-drift, NOT functional regressions
All 19 are parametrized cells of `test_tui_snapshot.py::test_tc016s_density_layout_snapshot[...]`. That test is a **whole-app SVG layout baseline** (`snap_compare` on a real `S19TuiApp` across the `_ALL_SNAPSHOT_CELLS` screen×density×size matrix). LLR-V1.1 adds a **10th rail entry** (`RailEntry("crc_designer","⊕","R",…)` + `SCREEN_CONTAINER_IDS` + `Binding("0",…)`) — a shared-chrome change. The rail is drawn on every screen's SVG, so every cell that renders the rail drifts. This is precisely the **C-22/C-28 snapshot census** the requirements anticipated (§2.4, R-2) and resolves to a **canonical-CI snapshot-regen closeout PR** — baseline maintenance, not a defect. The functional truth of the rail entry is proven GREEN and independently of the SVG by `test_routing_key_0_shows_crc_designer_hides_others` (key `0` shows `#screen_crc_designer`, hides all others, moves the active marker). No non-snapshot functional failure remains.

### 6.3 Frozen-guard — static verification (checkout hazard avoided)
`test_tui_directionb.py::test_tc031*` and `test_engine_unchanged.py` were NOT executed (they `git checkout main`). Verified statically instead:
- `git diff --name-only 1e3125b HEAD` filtered to the frozen set (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, `test_engine_unchanged.py`) → **NO FROZEN PATHS TOUCHED** (reviewer-run, this session).
- All batch-58 code lands in non-frozen files: `tui/operations/{crc.py, crc_designer_model.py, crc_template.py, crc.py}`, `tui/{app.py, crc_designer_view.py, rail.py, workspace.py}`, and NEW `tests/test_crc_*` files. The frozen-set guard will pass in CI; the vs-`main` diff self-consistency is confirmed by the static diff.

### 6.4 Reviewer commands (this session, real checkout `…/s19_app`)
- `git -C …/s19_app branch --show-current` → `feat/batch-58-crc-designer-view`; `git rev-parse HEAD` → `b809c98…` (unchanged before and after; no test mutated the tree).
- `python -m pytest -q tests/test_crc_word_codec.py tests/test_crc_template_loader.py tests/test_crc_job_upconvert.py tests/test_crc_designer_view.py` → `52 passed`.
- `git diff --name-only 1e3125b HEAD | grep <frozen set>` → no match.
- `python -m pytest -q tests/test_tui_directionb.py tests/test_tui_patch_history_strip.py -k "not tc031"` → see §6.1 (179 passed, 0 failed).

---

## 7. Evidence checklist

| Item | ✓/✗ | Citation |
|------|-----|----------|
| Acceptance criteria use Given/When/Then equivalent (Observable/Surface/Deliverable/AT) | ✓ | 01-requirements.md HLR Acceptance blocks |
| Test cases have explicit Expected, not vague "works" | ✓ | every §2/§3 node asserts a pinned value/state |
| Edge cases include empty, boundary, invalid, error | ✓ | e.g. no-image empty (coverage_no_image), CRC-64 boundary, inverted-range invalid (inverted_range_warns), malformed load error |
| Regression checklist exists | ✓ | §6.2 (snapshot rail-drift) + LLR-E4.3/E6.2 back-compat nodes (existing CRC/config suites unchanged) |
| Exit criteria stated | ✓ | §1 gate verdict; requirements §5.3 batch acceptance |
| No real PII / secrets | ✓ | fixtures only (`123456789`, synthetic `mem_map`, tmp_path) |
| Test-results left blank unless actually run | ✓ | §2/§3 status = PASS from executed runs (§6.4); frozen guards marked NOT-run + static |
| Layer B: every output-producing story observed through SHIPPED surface w/ boundary+negative | ✓ | §4b + boundary/negative nodes (save_all_symbol F2, hostile F1, preview_only negative) |
| Bidirectional surface-reachability (inputs AND outputs through the handler) | ✓ | §4a + §4b |
| No unfilled template placeholder | ✓ | all node ids, counts, oracles concrete; no `<...>`/`TC-NNN` residue |
| Frozen set 0-diff | ✓ | §6.3 static `git diff` clean |
| 3 formerly-vacuous ATs (+016/058-04/058-05/058-07/058-06) non-vacuous | ✓ | §5 |

---

## 8. Pending / closeout (not gate-blocking)
- **Canonical-CI snapshot-regen PR** for the 19 `test_tc016s_density_layout_snapshot[...]` rail-drift cells (C-22/C-28) — regen in canonical CI only (textual==8.2.8 pin), not locally.
- `/dev-flow-sync` to the Obsidian vault after merge.
- Backlog reconciliation into the single canonical `.dev-flow/BACKLOG.md` (mandatory close step).
