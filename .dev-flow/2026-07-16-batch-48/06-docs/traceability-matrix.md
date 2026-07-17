# Batch-48 (Patch Editor BIG) — Dual-Traceability Matrix

> **Batch:** `2026-07-16-batch-48` · **Branch:** `feat/batch-48-patch-big` · **HEAD:** `fccab02`
> **Purpose / audience:** the single canonical `US → HLR → LLR → TC[node] → AT[node]` map for batch-48, for a reviewer or a future maintainer who needs to confirm every requirement is verified by a real, collected test — without reading the seven increment docs (which are not synced to the vault).
> **Source of the resolved nodes:** `04-validation.md §1` (Phase-4 reconciliation) — cross-checked here, with a spot sample re-confirmed to collect via `pytest --collect-only` at HEAD `fccab02`.

---

## BLUF

**Coverage is complete and green. 8 requirements, 27 logical acceptance tests, 37 low-level requirements each with a 1:1 test case — zero orphan node, zero uncovered requirement.**

| Metric | Value |
|---|---|
| Requirements | **8** — 7 HLR (`R-TUI-075…081`) + `R-NEW-1` (the mid-batch C-17 `Select`-label class) |
| Acceptance tests (black-box) | **26 canonical** (`AT-075a…AT-081b`) **+ `AT-075f`** (3 nodes / 15 parametrised cases) = **27 logical ATs** |
| Low-level requirements | **37** LLRs (075.1–6 · 076.1–4 · 077.1–6 · 078.1–5 · 079.1–5 · 080.1–7 · 081.1–4) |
| Test cases (white-box) | **37** `TC-NNN`, 1:1 with the LLRs (each a `test` node, or a declared `inspection`/`analysis` that additionally carries a painted-result guard node) |
| Coverage | **100 %** — every requirement has ≥1 black-box (AT) and ≥1 white-box (TC/inspection/analysis) chain, all green |
| Orphan nodes | **0** — every extra node strengthens a named parent chain |
| Uncovered requirements | **0** |

Verification anchors held at HEAD: `_MUST_PRESERVE_IDS` count = **48** (intact); `tests/test_tui_patch_editor_v2.py` diff vs `main` = **0** (the glyph fold added no column); the six gate-blocking ATs + the headline card AT + the geometry AT each carry a recorded RED (not merely an assertion).

**One reconciliation, now closed (documentation-only):** `AT-076c`'s test file `tests/test_tui_patch_layout.py` was **modified** (+59/−11) under **§6.5 Amendment D** (the Inc-2 title de-dup), not "unmodified" as the Phase-1 gate wording said. The 48-id tuple is unchanged and the test is green. Amendment D is now folded into `01-requirements.md §6.5`.

---

## Full matrix — one block per requirement

Legend: ★ = security/contract-critical · ★★ = gate-blocking C-17 · **[G]** = one of the six §5.3 gate-blocking ATs · nodes cited `file::test`.

### R-TUI-075 / HLR-075 — window titles + subtitles · entries colour roles · variant+scope line (US-P1)

| Chain | Id | LLR(s) | Node (`file::test`) | Collected | Green |
|---|---|---|---|---|---|
| AT | AT-075a | LLR-075.1 | `test_tui_patch_big.py::test_at075a_titles` | ✓ | ✓ |
| AT | AT-075b | LLR-075.2 | `test_tui_patch_big.py::test_at075b_role_colours` | ✓ | ✓ |
| AT | AT-075c | LLR-075.3 | `test_tui_patch_big.py::test_at075c_variant_scope_line` | ✓ | ✓ |
| AT | AT-075d ★★ **[G]** | LLR-075.4 | `test_tui_patch_big.py::test_at075d_c17_variant` (5 payloads) | ✓ | ✓ |
| AT | AT-075e ★★ **[G]** | LLR-075.6 | `test_tui_patch_big.py::test_at075e_c17_entries_table` | ✓ | ✓ |
| TC | TC-075.1 | LLR-075.1 | subsumed into `test_at075a_titles` (Layer-A discharged by the same node) | ✓ | ✓ |
| TC | TC-075.2 | LLR-075.2 | subsumed into `test_at075b_role_colours` | ✓ | ✓ |
| TC | TC-075.3 | LLR-075.3 | subsumed into `test_at075c_variant_scope_line` | ✓ | ✓ |
| TC | TC-075.4 | LLR-075.4 | subsumed into `test_at075d_c17_variant` | ✓ | ✓ |
| TC | TC-075.5 | LLR-075.5 | analysis — C-29 subtitle/border-title budget, both axes | n/a | ✓ |
| TC | TC-075.6 ★★ | LLR-075.6 | `test_at075e_c17_entries_table` (all 5 cells `Text`-constructed) | ✓ | ✓ |

*RED evidence:* Inc-1 §4.1 — on the pre-fix HEAD `6551aed`, `[/nope]` raised `MarkupError` (variant line, AT-075d) and the entries table showed the `Text.from_markup` traceback (AT-075e, the live sink). The `isinstance(cell, Text)` tautology guard is present so an `== payload` assertion cannot pass vacuously.

### R-TUI-076 / HLR-076 — colour-grouped chip buttons, patch-scoped CSS (US-P1)

| Chain | Id | LLR(s) | Node | Collected | Green |
|---|---|---|---|---|---|
| AT | AT-076a | LLR-076.2 | `test_tui_patch_chips.py::test_at076a_docked_buttons_are_grouped_chips` | ✓ | ✓ |
| AT | AT-076b ★ | LLR-076.1 | `test_tui_patch_chips.py::test_at076b_c30_leak_probe_no_chip_rule_matches_outside_patch` | ✓ | ✓ |
| AT | AT-076c | LLR-076.3 | `test_tui_patch_layout.py::test_at063b_stacked_at_80` (asserts all 48 `_MUST_PRESERVE_IDS`) | ✓ | ✓ |
| TC | TC-076.1 | LLR-076.1 | `test_tui_patch_chips.py::test_tc076_1_every_chip_selector_is_panel_rooted` | ✓ | ✓ |
| TC | TC-076.2 | LLR-076.2 | `test_tui_patch_chips.py::test_tc076_2_group_assignment_on_docked_containers` | ✓ | ✓ |
| TC | TC-076.3 | LLR-076.3 | `test_tui_patch_layout.py` (48-id assertion; see AT-076c) | ✓ | ✓ |
| TC | TC-076.4 | LLR-076.4 | analysis — C-29 chip height, joint with `test_tc080_6` (AT-080d Form 1, no relaxation) | n/a | ✓ |

*Note (Amendment D):* `tests/test_tui_patch_layout.py` was modified +59/−11 under §6.5 Amendment D (title de-dup). The 48-id `_MUST_PRESERVE_IDS` tuple is **intact** (verified count = 48); the window-title assertions were delete-and-restated onto `border_title` in `test_tc46_1_window_structure_layout_agnostic`. AT-076c's substance holds.

### R-TUI-077 / HLR-077 — check glyph folded into the `Kind` cell (US-P2)

| Chain | Id | LLR(s) | Node | Collected | Green |
|---|---|---|---|---|---|
| AT | AT-077a | LLR-077.3 | `test_tui_patch_glyphs.py::test_at077a_branches` | ✓ | ✓ |
| AT | AT-077b | LLR-077.3 | `test_tui_patch_glyphs.py::test_at077b_no_run` | ✓ | ✓ |
| AT | AT-077c ★ **[G]** | LLR-077.2 | `test_tui_patch_glyphs.py::test_at077c_stale_provenance` | ✓ | ✓ |
| AT | AT-077d | LLR-077.1 | `test_tui_patch_glyphs.py::test_at077d_index_alignment` | ✓ | ✓ |
| AT | AT-077e ★ **[G]** | LLR-077.2 | `test_tui_patch_glyphs.py::test_at077e_image_generation_invalidates` | ✓ | ✓ |
| TC | TC-077.1 | LLR-077.1 | `test_tui_patch_glyphs.py::test_tc077_1_index_alignment` (+`_short_result_does_not_raise`) | ✓ | ✓ |
| TC | TC-077.2 ★ | LLR-077.2 | `test_tui_patch_glyphs.py::test_tc077_2_provenance` (+`_linkage_inputs_do_not_invalidate`) | ✓ | ✓ |
| TC | TC-077.3 | LLR-077.3 | `test_tui_patch_glyphs.py::test_tc077_3_glyph_map` | ✓ | ✓ |
| TC | TC-077.4 | LLR-077.4 | `test_tui_patch_glyphs.py::test_tc077_4_glyph_folded_into_kind` (`len(_ENTRIES_COLUMNS)==5`; v2 diff = 0) | ✓ | ✓ |
| TC | TC-077.5 | LLR-077.5 | inspection — 4 `refresh_entries` sites unchanged for the glyph (MJ-1 census) | n/a | ✓ |
| TC | TC-077.6 | LLR-077.6 | `test_tui_patch_glyphs.py::test_tc077_6_glyph_carries_no_file_derived_text` (C-17 N/A; span-only) | ✓ | ✓ |

*RED evidence:* Inc-3 M-4 (`glyphs[::-1]`) for index-alignment; M-2/M-3 (drop `document_signature`) for AT-077c; **M-1/M-7** (check-A → load-B → stale `✓` until the load-seam refresh) for AT-077e — the two-input staleness branch a document-only fingerprint would miss.

### R-TUI-078 / HLR-078 — CHECKS pass/fail strip (US-P3)

| Chain | Id | LLR(s) | Node | Collected | Green |
|---|---|---|---|---|---|
| AT | AT-078a | LLR-078.1/.4 | `test_tui_patch_checks_strip.py::test_at078a_counts` | ✓ | ✓ |
| AT | AT-078b | LLR-078.4 | `test_tui_patch_checks_strip.py::test_at078b_zero_total` | ✓ | ✓ |
| AT | AT-078c | LLR-078.3 | `test_tui_patch_checks_strip.py::test_at078c_cleared` | ✓ | ✓ |
| TC | TC-078.1 | LLR-078.1 | `test_tui_patch_checks_strip.py::test_tc078_1_strip_mounted` | ✓ | ✓ |
| TC | TC-078.2 | LLR-078.2 | `test_tui_patch_checks_strip.py::test_tc078_2_aggregates_param` (C-7 purity probe == 0) | ✓ | ✓ |
| TC | TC-078.3 | LLR-078.3 | `test_tui_patch_checks_strip.py::test_tc078_3_both_sites` | ✓ | ✓ |
| TC | TC-078.4 | LLR-078.4 | `test_tui_insight_style.py::test_tc078_4_microbar_unfloored` | ✓ | ✓ |
| TC | TC-078.5 | LLR-078.5 | inspection (C-17 N/A) + `test_tc078_5_strip_geometry_painted` (C-29, painted result) | ✓ | ✓ |

*RED evidence:* Inc-4 M-2 — 01b's 2/1/1 fixture was degenerate (label-swap invisible) → rebuilt asymmetric 2/1/3; Inc-4 M-1 — the zero-case oracle for `floor=False` was false → TC-078.4 grew a behavioural non-zero arm.

### R-TUI-079 / HLR-079 — JSON colouring + paste-cap gauge (US-P4)

| Chain | Id | LLR(s) | Node | Collected | Green |
|---|---|---|---|---|---|
| AT | AT-079a | LLR-079.4 | `test_tui_patch_json.py::test_at079a_gauge_tracks_buffer` | ✓ | ✓ |
| AT | AT-079b | LLR-079.1 | `test_tui_patch_json.py::test_at079b_structure_differentiated_in_place` | ✓ | ✓ |
| AT | AT-079c ★★ **[G]** | LLR-079.3 | `test_tui_patch_json.py::test_at079c_hostile_paste_renders_literally` | ✓ | ✓ |
| AT | AT-079d | LLR-079.1 | `test_tui_patch_json.py::test_at079d_feature_detect_fallback` | ✓ | ✓ |
| TC | TC-079.1 | LLR-079.1 | in-place `_highlights` probe → 3 pass-conditions MEASURED, subsumed into `test_at079b_*` (Inc-5 §2) | ✓ | ✓ |
| TC | TC-079.2 | LLR-079.2 | `test_tui_patch_json.py::test_tc079_2_non_ascii_byte_offsets` | ✓ | ✓ |
| TC | TC-079.3 ★★ | LLR-079.3 | `test_tui_patch_json.py::test_tc079_3_c17_oracle_discriminates` (+`_3b_inert_predicate`) | ✓ | ✓ |
| TC | TC-079.4 | LLR-079.4 | gauge vs `_CLIPBOARD_READ_CAP_CHARS` → subsumed into `test_at079a_*` | ✓ | ✓ |
| TC | TC-079.5 | LLR-079.5 | `test_tui_patch_json.py::test_tc079_5_magenta_hue_distance` (+`5b`,`5c`,`5d`) | ✓ | ✓ |

*Note on TC-079.5:* the shipped `test_tc079_5*` nodes are the **MAGENTA hue-reservation census** (Inc-2b), not the spec's original "C-29 both axes" wording — a re-pointing. The C-29 JSON-window geometry obligation migrated to `test_tc078_5`/`test_tc080_6`. HIGH-1 (a vacuous input set: the census hand-curated hues instead of sweeping them) was found in Inc-5b and closed — `test_tc079_5c` now sweeps every `#rrggbb` (claim-or-exclude-with-reason) and `5d` gives the flank rule teeth. *RED evidence:* Inc-5 BLOCKER-1 (AT-079c's span clause was dead) → anti-vacuity arm `test_tc079_3_c17_oracle_discriminates` RED-rejects a `from_markup` TextArea.

### R-TUI-080 / HLR-080 — live before/after card (US-P5, THE HEADLINE)

| Chain | Id | LLR(s) | Node | Collected | Green |
|---|---|---|---|---|---|
| AT | AT-080a | LLR-080.3 | `test_tui_patch_card.py::test_at080a_before_after` (+`_same_address_entries_are_index_joined`) | ✓ | ✓ |
| AT | AT-080b ★ | LLR-080.5 | `test_tui_patch_card.py::test_at080b_read_only` | ✓ | ✓ |
| AT | AT-080c | LLR-080.3 | `test_tui_patch_card.py::test_at080c_unmapped` | ✓ | ✓ |
| AT | AT-080d ★ **[G]** | LLR-080.6 | `test_tui_patch_card.py::test_at080d_reachable_with_card` (`[size0]`,`[size1]`) | ✓ | ✓ |
| TC | TC-080.1 | LLR-080.1 | `test_tui_patch_card.py::test_tc080_1_no_widget_name_collisions`, `_mounts`(×2), `_card_never_mounts_blank` | ✓ | ✓ |
| TC | TC-080.2 | LLR-080.2 | `test_tui_patch_card.py::test_tc080_2_c7_purity_probe`, `_param_is_defaulted…`, `_2a_retain_semantics`, `_2a_mount_selfcall…` | ✓ | ✓ |
| TC | TC-080.3 | LLR-080.3 | `test_tui_patch_card.py::test_tc080_3_before_after_derivation`, `_unmapped_token…`, `_3b_stub_row_shape…` | ✓ | ✓ |
| TC | TC-080.4 | LLR-080.4 | `test_tui_patch_card.py::test_tc080_4_no_image`, `_no_selection_and_out_of_range` | ✓ | ✓ |
| TC | TC-080.5 | LLR-080.5 | `test_tui_patch_card.py::test_tc080_5_no_apply_path_reachable` | ✓ | ✓ |
| TC | TC-080.6 | LLR-080.6 | `test_tui_patch_card.py::test_tc080_6_card_fits_its_measured_container` (×2) — C-29 both axes with the card | ✓ | ✓ |
| TC | TC-080.7 | LLR-080.7 | `test_tui_patch_card.py::test_tc080_7_card_inputs_are_ints`, `_renders_no_file_derived_row_text` | ✓ | ✓ |
| — | writer census | LLR-080.2 | `test_tui_patch_card.py::test_writer_census_every_app_site_pushes_mem_map`, `_panel_selfcall_supplies_none` (AST-derived) | ✓ | ✓ |

*RED evidence:* Inc-7 M-1 — the index→address join RED on a same-address fixture (row index ≠ 0); M-2 — `mem_map.get(addr,0)` invented `00` for an unmapped address; **M-6 — GEOMETRY not content**: `display:none` on the card turned AT-080d RED while all 22 content oracles stayed green (so AT-080d is a real geometry assertion, not a content assertion in disguise). `AT-080e` (hostile card header) correctly **never became a node** — the LLR-080.7 mechanical grep never fired (`test_tc080_7_card_inputs_are_ints` green), so no vacuous AT over a non-existent header.

### R-TUI-081 / HLR-081 — history strip (US-P6)

| Chain | Id | LLR(s) | Node | Collected | Green |
|---|---|---|---|---|---|
| AT | AT-081a | LLR-081.1 | `test_tui_patch_history_strip.py::test_at081a_position` | ✓ | ✓ |
| AT | AT-081b | LLR-081.1 | `test_tui_patch_history_strip.py::test_at081b_bounds` | ✓ | ✓ |
| TC | TC-081.1 | LLR-081.1 | `test_tui_patch_history_strip.py::test_tc081_1_derived` | ✓ | ✓ |
| TC | TC-081.2 | LLR-081.2 | `test_tui_patch_history_strip.py::test_tc081_2_strip` (C-7 purity probe == 0) | ✓ | ✓ |
| TC | TC-081.3 | LLR-081.3 | `test_tui_patch_history_strip.py::test_tc081_3_sites` | ✓ | ✓ |
| TC | TC-081.4 | LLR-081.4 | `test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff` (C-28 disposition: 0 App-level binding diffs) | ✓ | ✓ |
| — | extra | LLR-081.2 | `test_tui_patch_history_strip.py::test_tc081_5_strip_geometry_painted`, `_6_builder_returns_text` | ✓ | ✓ |

### R-NEW-1 — C-17 `Select`-label class (found mid-batch Inc-1/1b, beyond the original 7 HLRs)

| Chain | Id | Node | Collected | Green |
|---|---|---|---|---|
| AT | AT-075f ★★ | `test_tui_patch_big.py::test_at075f_c17_patch_variant_select_label` (5 payloads) | ✓ | ✓ |
| AT | AT-075f ★★ | `test_tui_patch_big.py::test_at075f_c17_patch_doc_file_select_label` (5 payloads; filenames from `workarea/patches/`) | ✓ | ✓ |
| AT | AT-075f ★★ | `test_tui_patch_big.py::test_at075f_c17_ab_diff_select_labels` (5 payloads; `AbDiffPanel.set_variants`, `screens_directionb.py:3903`) | ✓ | ✓ |

*RED evidence:* Inc-1 §1b.5 — on live code a project-file-derived `Select` option label reached `SelectCurrent.update` (a markup-enabled `Static`) and rendered `Content('PWNED', spans=[Span(0,5,'red')])`. Probed to **exactly 3 sites**, all fixed in-batch with literal Rich `Text` labels. `AT-075f` is an honest **addition** for `R-NEW-1`, not a silent mint — the canonical registry moves 26 → 26 + AT-075f.

---

## Spot-check (re-run at HEAD `fccab02`)

`pytest --collect-only` confirmed the following representative nodes collect: `test_at075a_titles`, `test_at075e_c17_entries_table`, `test_at076a_docked_buttons_are_grouped_chips`, `test_at077e_image_generation_invalidates`, `test_at080a_before_after`, `test_at080d_reachable_with_card[size0/size1]`, `test_at081a_position`, `test_at079c_hostile_paste_renders_literally`, and the three `test_at075f_*` families (15 parametrised cases). `_MUST_PRESERVE_IDS` count verified = 48; `tests/test_tui_patch_layout.py` diff vs base `6551aed` = +59/−11 (Amendment D).

## Interim / carried

- **Suite:** `pytest -q -m "not slow"` = **1540 passed / 0 failed / 5 xfailed** (baseline 1449); full unfiltered `pytest -q` = **1560 passed / 0 failed / 5 xfailed**, `EXIT=1` traced to a **pre-existing** syrupy "unused-snapshot" session artifact present on the base tree, not introduced by this batch (`04-validation.md §7`).
- **2 xfail patch snapshot cells** (`patch-comfortable-80x24` / `-120x30`, `strict=False` while drifting) — a canonical-CI regen follow-up PR is owed post-merge (`snapshot-regen.yml`, `textual==8.2.8`; local regen forbidden).
