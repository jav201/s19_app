# Phase 4 — Dual-Traceability Reconciliation & Validation — batch-48 (Patch Editor BIG)

> **Batch:** `2026-07-16-batch-48` · **Branch:** `feat/batch-48-patch-big` · **HEAD:** `ef7fe74` (7 increments shipped)
> **Author:** qa-reviewer (Phase 4). Read-only on `s19_app/**` and `tests/**`.
> **Canonical id space:** `01-requirements.md` §5.2 (the pinned-26 AT registry + the TC table). `01b` re-numbers onto it (BL-2).
> **Method:** every AT/TC id resolved to a real collected pytest node via `pytest --collect-only`; counterfactual (RED) evidence read from the 7 increment docs and spot-verified at HEAD.

---

## 0. BLUF verdict

**The dual-traceability matrix is COMPLETE and GREEN on all three axes — Coverage, Certainty, Evidence — with ONE named reconciliation gap that is documentation-only (iterate-to-refine), not a broken or vacuous chain.**

- **Coverage — PASS.** All **26** canonical ATs (`AT-075a…AT-081b`) resolve to on-disk nodes; every HLR/LLR has ≥1 green TC (or a declared inspection/analysis method). **Zero requirement without a verifying node. Zero orphan** (every extra node strengthens an existing chain). One **added** AT — `AT-075f` (3 nodes) — traces cleanly to **R-NEW-1** (the C-17 `Select`-label class), so the shipped AT count is 26 + AT-075f.
- **Certainty — PASS.** All 6 gate-blocking ATs + the headline card AT + the geometry AT + the (twice-vacuous) hue census carry a **recorded RED** (pre-fix tree or named mutation), not merely an assertion. The batch's 9 vacuous checks were each caught and the shipped replacements are demonstrably non-vacuous (spot-verified: `test_tc079_3_c17_oracle_discriminates`, `test_tc079_5c/5d`, `AT-080d` geometry vs the 22 blind content tests).
- **Evidence — PASS.** Every axis cites a re-runnable node id / file:line / command output. Interim suite count = **gate.txt 1540 passed / 0 failed / 5 xfailed**; the full unfiltered run is still executing (known-carry §5).

**The one named gap (NOT a gate-blocker):** the §5.3 gate criterion *"`tests/test_tui_patch_layout.py` passes **unmodified**"* and the §5.2 `AT-076c` note *"(existing, unmodified)"* are **STALE** — the file was legitimately modified (+59/−11) under a **batch-48 §6.5 Amendment D** (title de-dup) that was recorded in `REQUIREMENTS.md` + `increment-02.md` but **never folded back into `01-requirements.md` §6.5** (which still lists only Amendments A/B/retired-C and says Amendment A "Deleted — none"). **The substance of AT-076c holds** — the 48-id `_MUST_PRESERVE_IDS` tuple is intact (verified count = 48) and the test is green — so this is a doc-hygiene reconciliation for Phase 6, not a code defect. Flagged in §4.

---

## 1. Full dual-traceability matrix

Legend: ★ = security/contract-critical · ★★ = gate-blocking C-17 · **[G]** = on the §5.3 gate list (6 total) · RED-src = the increment doc + mechanism that captured the counterfactual.

### R-TUI-075 / HLR-075 — window titles + subtitles · entries colour roles · variant+scope line (US-P1)
| Chain | Id | Node (`file::test`) | Collected | Green | RED / counterfactual |
|---|---|---|---|---|---|
| AT | AT-075a | `test_tui_patch_big.py::test_at075a_titles` | ✓ | ✓ | live subtitle count-update asserted (Inc-1 §4) |
| AT | AT-075b | `…::test_at075b_role_colours` | ✓ | ✓ | role style non-empty on string+bytes rows |
| AT | AT-075c | `…::test_at075c_variant_scope_line` | ✓ | ✓ | reads active variant + cycled scope |
| AT | AT-075d ★★ **[G]** | `…::test_at075d_c17_variant` (5 payloads) | ✓ | ✓ | Inc-1 §4.1 — `[/nope]`→`MarkupError` on pre-fix HEAD `6551aed` |
| AT | AT-075e ★★ **[G]** | `…::test_at075e_c17_entries_table` | ✓ | ✓ | **Inc-1 §4.1 — the live sink**: `MarkupError` + `Text.from_markup` traceback locals on pre-fix HEAD; the tautology guard (`isinstance Text`) is present |
| TC | TC-075.1–075.6 | subsumed into `test_at075a/b/c/d/e` (Layer-A discharged by the same nodes) + LLR-075.5 analysis | ✓ | ✓ | LLR-075.6 = AT-075e (all 5 cells `Text`) |

### R-TUI-076 / HLR-076 — colour-grouped chip buttons, patch-scoped CSS (US-P1)
| Chain | Id | Node | Collected | Green | RED / counterfactual |
|---|---|---|---|---|---|
| AT | AT-076a | `test_tui_patch_chips.py::test_at076a_docked_buttons_are_grouped_chips` | ✓ | ✓ | structural invariant enumerated from live tree (Inc-2) |
| AT | AT-076b ★ | `…::test_at076b_c30_leak_probe_no_chip_rule_matches_outside_patch` | ✓ | ✓ | the falsifiable C-30 leak probe |
| AT | AT-076c | `test_tui_patch_layout.py` (48-id assertion, node `test_at063*/tc46_*` set) | ✓ | ✓ | 48-id tuple intact (count=48) — see §4 re "unmodified" |
| TC | TC-076.1 | `…::test_tc076_1_every_chip_selector_is_panel_rooted` | ✓ | ✓ | |
| TC | TC-076.2 | `…::test_tc076_2_group_assignment_on_docked_containers` | ✓ | ✓ | |
| TC | TC-076.3 | `test_tui_patch_layout.py` (see AT-076c) | ✓ | ✓ | |
| TC | TC-076.4 | analysis (C-29 chip height, joint with `test_tc080_6`) | n/a | ✓ | AT-080d Form 1 (no relaxation) |

### R-TUI-077 / HLR-077 — check glyph folded into the `Kind` cell (US-P2)
| Chain | Id | Node | Collected | Green | RED / counterfactual |
|---|---|---|---|---|---|
| AT | AT-077a | `test_tui_patch_glyphs.py::test_at077a_branches` | ✓ | ✓ | Inc-3 M-4 (`glyphs[::-1]`) RED |
| AT | AT-077b | `…::test_at077b_no_run` | ✓ | ✓ | |
| AT | AT-077c ★ **[G]** | `…::test_at077c_stale_provenance` | ✓ | ✓ | **Inc-3 M-2/M-3** — drop `document_signature` → FAIL; arm-(c) count-equality isolated |
| AT | AT-077d | `…::test_at077d_index_alignment` | ✓ | ✓ | Inc-3 M-4 RED; **01b's palindrome fixture was vacuous → rebuilt asymmetric-4** |
| AT | AT-077e ★ **[G]** | `…::test_at077e_image_generation_invalidates` | ✓ | ✓ | **Inc-3 M-1/M-7** — the BL-4 branch: check-A→load-B → stale `✓` rendered until the load-seam refresh added |
| TC | TC-077.1 | `…::test_tc077_1_index_alignment` (+`_short_result_does_not_raise`) | ✓ | ✓ | |
| TC | TC-077.2 ★ | `…::test_tc077_2_provenance` (+`_linkage_inputs_do_not_invalidate`) | ✓ | ✓ | two-part stamp `(document_signature, image_generation)` |
| TC | TC-077.3 | `…::test_tc077_3_glyph_map` | ✓ | ✓ | M-6 RED (4-token totality) |
| TC | TC-077.4 | `…::test_tc077_4_glyph_folded_into_kind` | ✓ | ✓ | `len(_ENTRIES_COLUMNS)==5`; **v2 diff = 0** (verified) |
| TC | TC-077.5 | inspection — 4 `refresh_entries` sites unchanged for glyph (MJ-1 census) | n/a | ✓ | |
| TC | TC-077.6 | `…::test_tc077_6_glyph_carries_no_file_derived_text` | ✓ | ✓ | C-17 N/A (span-only; cell covered by LLR-075.6) |

### R-TUI-078 / HLR-078 — CHECKS pass/fail strip (US-P3)
| Chain | Id | Node | Collected | Green | RED / counterfactual |
|---|---|---|---|---|---|
| AT | AT-078a | `test_tui_patch_checks_strip.py::test_at078a_counts` | ✓ | ✓ | **01b's 2/1/1 fixture was degenerate (5th vacuous) → rebuilt asymmetric 2/1/3** (Inc-4) |
| AT | AT-078b | `…::test_at078b_zero_total` | ✓ | ✓ | zero-total, no divide-by-zero |
| AT | AT-078c | `…::test_at078c_cleared` | ✓ | ✓ | post-undo cleared |
| TC | TC-078.1 | `…::test_tc078_1_strip_mounted` | ✓ | ✓ | |
| TC | TC-078.2 | `…::test_tc078_2_aggregates_param` | ✓ | ✓ | C-7 purity probe == 0 |
| TC | TC-078.3 | `…::test_tc078_3_both_sites` | ✓ | ✓ | both call sites push aggregates |
| TC | TC-078.4 | `test_tui_insight_style.py::test_tc078_4_microbar_unfloored` | ✓ | ✓ | **Inc-4 M-1: 01b's zero-case oracle was FALSE; grew a behavioural non-zero arm** (5% → 1 cell if floored) |
| TC | TC-078.5 | inspection — C-17 N/A | n/a | ✓ | + `test_tc078_5_strip_geometry_painted` (C-29, painted) |

### R-TUI-079 / HLR-079 — JSON colouring + paste-cap gauge (US-P4)
| Chain | Id | Node | Collected | Green | RED / counterfactual |
|---|---|---|---|---|---|
| AT | AT-079a | `test_tui_patch_json.py::test_at079a_gauge_tracks_buffer` | ✓ | ✓ | gauge vs `_CLIPBOARD_READ_CAP_CHARS` (chars) |
| AT | AT-079b | `…::test_at079b_structure_differentiated_in_place` | ✓ | ✓ | **re-pointed to painted `_render_line(y)`** (Inc-5 RULING-1); `or` STRUCK (F-16); in-place rung 1 shipped, Amd B not needed |
| AT | AT-079c ★★ **[G]** | `…::test_at079c_hostile_paste_renders_literally` | ✓ | ✓ | **twice-vacuous → fixed**: span clause was dead (Inc-5 BLOCKER-1) + cursor-line masking (Inc-5b item 8); now anti-vacuity arm `test_tc079_3_c17_oracle_discriminates` (M-2: rejects a `from_markup` TextArea) |
| AT | AT-079d | `…::test_at079d_feature_detect_fallback` | ✓ | ✓ | monkeypatch forces the branch CI can't reach (M-4 RED) |
| TC | TC-079.1 | in-place `_highlights` probe → subsumed into AT-079b (3 pass-conditions MEASURED, Inc-5 §2) | ✓ | ✓ | |
| TC | TC-079.2 | `…::test_tc079_2_non_ascii_byte_offsets` | ✓ | ✓ | byte (not codepoint) offsets |
| TC | TC-079.3 ★★ | `…::test_tc079_3_c17_oracle_discriminates` (+`_3b_inert_predicate`) | ✓ | ✓ | the discrimination proof, now a shipped test |
| TC | TC-079.4 | gauge vs cap → subsumed into AT-079a | ✓ | ✓ | |
| TC | TC-079.5 | `…::test_tc079_5_magenta_hue_distance` (+`5b`,`5c`,`5d`) | ✓ | ✓ | **HIGH-1: vacuous INPUT SET → fixed**: `5c` sweeps all `#rrggbb` (claim-or-exclude-with-reason), `5d` flank-rule teeth |

*Note: the shipped `test_tc079_5*` nodes are the **hue census** (Inc-2b reservation guard), not the spec's original "C-29 both axes" wording for TC-079.5 — see §4 reconciliation. C-29 JSON-window geometry is discharged by the strip/card geometry pilots (`test_tc078_5`, `test_tc080_6`).*

### R-TUI-080 / HLR-080 — live before/after card (US-P5, THE HEADLINE)
| Chain | Id | Node | Collected | Green | RED / counterfactual |
|---|---|---|---|---|---|
| AT | AT-080a | `test_tui_patch_card.py::test_at080a_before_after` (+`_same_address_entries_are_index_joined`) | ✓ | ✓ | **Inc-7 M-1** — index→address join RED on the same-address fixture (row index ≠ 0) |
| AT | AT-080b ★ | `…::test_at080b_read_only` | ✓ | ✓ | mem_map + document unchanged after N selects |
| AT | AT-080c | `…::test_at080c_unmapped` | ✓ | ✓ | **Inc-7 M-2** — `mem_map.get(addr,0)` RED (invented `00`) |
| AT | AT-080d ★ **[G]** | `…::test_at080d_reachable_with_card` (size0/size1) | ✓ | ✓ | **Inc-7 M-6 — GEOMETRY, not content**: `display:none` RED while all 22 content tests PASSED (Inc-4 F2 class reproduced). AT-080d Form 1 (no relaxation → no vacuity risk) |
| TC | TC-080.1 | `…::test_tc080_1_no_widget_name_collisions`, `_mounts`(×2), `_card_never_mounts_blank` | ✓ | ✓ | `dir(Widget)` oracle corrected (Inc-7 §4) |
| TC | TC-080.2 | `…::test_tc080_2_c7_purity_probe`, `_param_is_defaulted…`, `_2a_retain_semantics`, `_2a_mount_selfcall…` | ✓ | ✓ | **Inc-7 M-3/M-4** — retain semantics + the 4th (census-missed) site RED |
| TC | TC-080.3 | `…::test_tc080_3_before_after_derivation`, `_unmapped_token…`, `_3b_stub_row_shape…` | ✓ | ✓ | **M-7** — delete `encoded_bytes` from the real dataclass → `3b` RED (the input-set/HIGH-1 class code-mutation can't reach) |
| TC | TC-080.4 | `…::test_tc080_4_no_image`, `_no_selection_and_out_of_range` | ✓ | ✓ | |
| TC | TC-080.5 | `…::test_tc080_5_no_apply_path_reachable` | ✓ | ✓ | **M-5** — `value_text` reaching the card path → RED |
| TC | TC-080.6 | `…::test_tc080_6_card_fits_its_measured_container` (×2) | ✓ | ✓ | C-29 both axes with card |
| TC | TC-080.7 | `…::test_tc080_7_card_inputs_are_ints`, `_renders_no_file_derived_row_text` | ✓ | ✓ | **the MJ-7 mechanical grep gate became a real test**; `AT-080e` never fired (no non-`int` input) |
| — | writer census | `…::test_writer_census_every_app_site_pushes_mem_map`, `_panel_selfcall_supplies_none` | ✓ | ✓ | AST-derived; M-4 names `app.py:8054` |

### R-TUI-081 / HLR-081 — history strip (US-P6)
| Chain | Id | Node | Collected | Green | RED / counterfactual |
|---|---|---|---|---|---|
| AT | AT-081a | `test_tui_patch_history_strip.py::test_at081a_position` | ✓ | ✓ | 2 edits → 1 undo → back=1/fwd=1 + hints |
| AT | AT-081b | `…::test_at081b_bounds` | ✓ | ✓ | fresh empty state; `_HISTORY_MAX` saturation |
| TC | TC-081.1 | `…::test_tc081_1_derived` | ✓ | ✓ | derived depths |
| TC | TC-081.2 | `…::test_tc081_2_strip` | ✓ | ✓ | C-7 purity probe == 0 |
| TC | TC-081.3 | `…::test_tc081_3_sites` | ✓ | ✓ | 3 sites push depths |
| TC | TC-081.4 | `…::test_tc081_4_no_binding_diff` | ✓ | ✓ | C-28 disposition (0 App-level binding diffs) |
| — | extra | `…::test_tc081_5_strip_geometry_painted`, `_6_builder_returns_text` | ✓ | ✓ | painted-result geometry (Inc-4 F2 general control) |

### R-NEW-1 — C-17 `Select`-label class (found mid-batch Inc-1/1b, beyond original spec)
| Chain | Id | Node | Collected | Green | RED / counterfactual |
|---|---|---|---|---|---|
| AT | AT-075f ★★ | `test_tui_patch_big.py::test_at075f_c17_patch_variant_select_label` (5 payloads) | ✓ | ✓ | Inc-1 §1b.5 — `Content('PWNED', spans=[Span(0,5,'red')])` on live code (3 sites × 3 discriminators = 6 RED) |
| AT | AT-075f ★★ | `…::test_at075f_c17_patch_doc_file_select_label` (5) | ✓ | ✓ | filenames from `workarea/patches/` |
| AT | AT-075f ★★ | `…::test_at075f_c17_ab_diff_select_labels` (5) | ✓ | ✓ | `AbDiffPanel.set_variants` (`screens_directionb.py:3903`) |

---

## 2. Exit-criteria axis verdicts

### 2.1 Coverage — PASS
- **N requirements = 7 HLR (R-TUI-075…081) + R-NEW-1 = 8.** Every one has both a black-box (AT) and white-box (TC/inspection/analysis) chain, all green.
- **N ATs = 26 canonical + AT-075f (3 nodes) = 27 logical ATs.** All resolve to on-disk nodes (`pytest --collect-only`, confirmed at HEAD `ef7fe74`). C-18 satisfied: each AT = one test function (parametrized where noted — `AT-075d`×5, `AT-075f`×15, `AT-080d`×2, `AT-077*` params — one function id each).
- **N TCs:** every `test`-method LLR has a node; every `inspection`/`analysis` LLR is declared as such and (in every case) additionally has a painted-result guard node. No LLR is uncovered.
- **Zero requirement without a verifying node. Zero orphan** — the extra nodes (`test_at080a_same_address`, `test_tc079_3b`, `test_tc079_5b/c/d`, `test_tc078_5`, `test_tc081_5/6`, `test_writer_census_*`, `test_tc080_3b`) each strengthen a named parent chain; none is unmapped.
- **Registry discipline held:** the pinned-26 (F-16) is exact; `AT-075f` is an honest **addition** for R-NEW-1 (a class found beyond spec, folded in-batch per MEMORY backlog 1b), not a silent mint. `AT-080e` correctly **never became a node** (the LLR-080.7 grep never fired — `test_tc080_7_card_inputs_are_ints` is green).

### 2.2 Certainty — PASS (non-vacuity SHOWN, not asserted)
The batch surfaced **9 vacuous checks**; every one was caught and the shipped replacement carries a recorded RED:

| Vacuous check | How caught | Shipped non-vacuous evidence |
|---|---|---|
| 1. AT-077d palindrome fixture | Inc-3 | rebuilt asymmetric-4; M-4 `glyphs[::-1]` RED |
| 2. AT-078a 2/1/1 degenerate | Inc-4 M-2 | rebuilt 2/1/3; label-swap now visible |
| 3. AT-078b zero-case oracle false | Inc-4 M-1 | TC-078.4 grew a non-zero behavioural arm |
| 4. `floor=False` justification false | Inc-4 M-1 | conclusion survives; reasoning corrected in TC-078.4 docstring |
| 5. AT-079b `.spans` unsatisfiable | Inc-5 BLOCKER-1 | re-pointed to painted `_render_line`; `or` struck |
| 6. AT-079c span clause dead | Inc-5 BLOCKER-1 | anti-vacuity arm `test_tc079_3_c17_oracle_discriminates` (M-2 RED) |
| 7. AT-079c cursor-line masking | Inc-5b item 8 | payload moved off line 0; masking measured + defeated |
| 8. hue census vacuous INPUT SET (HIGH-1) | Inc-5b F1 | `test_tc079_5c_hue_census_is_complete` sweeps all 29 `#rrggbb`; `5d` flank teeth |
| 9. TC-080.1 `vars(card)&dir(Widget)` wrong oracle | Inc-7 §4 | anchored to app-existing private names |

- **Spot-check confirmations at HEAD (`ef7fe74`), all green:** `AT-075e`, `AT-075d`, `AT-077c`, `AT-077e`, `AT-079c`, `test_tc079_3_c17_oracle_discriminates`, `test_tc079_5c_hue_census_is_complete`, `test_tc079_5d_flank_rule_has_teeth`, `AT-080a`, `AT-080d`, `test_tc080_6` → **17 passed in 38s**.
- **AT-079c (the task's flagged twice-vacuous C-17):** now discharged by the render path (`get_line().plain`/`.spans`) with a dedicated discriminator arm that RED-rejects a `from_markup` TextArea. Non-vacuity is SHOWN.
- **AT-080d (the task's flagged geometry-not-content concern):** confirmed geometry — Inc-7 M-6 (`display:none`) turned it RED while the 22 content oracles stayed green. It is not a content assertion masquerading as geometry.
- **Hue census `test_tc079_5*` (HIGH-1):** the fix is structural (sweep-and-classify, not hand-curate); a new unclassified literal fails the guard. Non-vacuous.

### 2.3 Evidence — PASS
- Every matrix row cites a re-runnable node id. Gate-blocking RED evidence cites the increment doc section + mutation id (Inc-1 §4.1, Inc-3 M-1/M-2/M-4/M-7, Inc-5 BLOCKER-1 + RULING-1, Inc-5b F1/item-8, Inc-7 M-1/M-2/M-6/M-7).
- **Interim suite:** `scratchpad/gate.txt` = **1540 passed / 2 skipped / 20 deselected / 5 xfailed / 0 failed** (reduced suite `-m "not slow"`, Inc-7 gate). Baseline `scratchpad/baseline.txt` = 1514. 2 of the 5 xfailed are the patch snapshot cells (strict=False while drifting — post-merge regen, §5).
- **Structural gates verified at HEAD:** `_MUST_PRESERVE_IDS` count = **48** (intact); `tests/test_tui_patch_editor_v2.py` diff vs `main` = **0** (the BL-3 fold free-signal held — the fold added no column); `tests/test_tui_patch_layout.py` green (9 passed).
- No checklist item is marked from intent.

---

## 3. §6.4 id reconciliation

| Item | Spec id | Shipped node | Status |
|---|---|---|---|
| **BL-2 off-by-one** (`01b` pre-D-2 numbering vs `01` §5.2 canonical) | §5.2 = authority | `01b` re-numbered onto §5.2 in the same pass (F-2/F-16) | **CLOSED** — every AT node name matches the §5.2 provisional path exactly (e.g. `test_at077e_image_generation_invalidates`) |
| **HLR-080 ↔ HLR-081 clash** (brief said history strip = HLR-080) | HLR-080 = card, HLR-081 = history | Inc-6 built the history strip as **HLR-081** (`test_tui_patch_history_strip.py`), Inc-7 built the card as **HLR-080** (`test_tui_patch_card.py`); commit `f856934` records "HLR-081, NOT 080 — the brief's id was wrong" | **CLOSED** — final ids consistent; `01b` §0.1 recorded `AT-080a history → AT-081a` |
| **AT-077e split from AT-077c** (BL-4, parallel-fold divergence) | §5.2 pins both | `test_at077c_stale_provenance` (document arms) + `test_at077e_image_generation_invalidates` (image arm) — distinct nodes | **CLOSED** — registry pinned at 26 (F-16); both green |
| **AT-079b `or` struck** (F-16, self-voiding disjunct) | single pass condition | `test_at079b_structure_differentiated_in_place` (in-place rung 1 shipped; Amd B not triggered) | **CLOSED** |
| **AT-079b/c re-pointed to painted result** (Inc-5 RULING-1) | observe `_render_line(y)` not `ta.text` | shipped nodes observe the render path; `test_tc079_3` is the discriminator | **CLOSED** |
| **5-site `refresh_entries` census** (MJ-1: 4 sites, + the load-seam 5th for AT-077e) | §6.4 writer-census | `test_writer_census_*` (AST-derived) + Inc-3 R-3-1 (load-seam refresh) + Inc-7 M-4 (`app.py:8054`) | **CLOSED** |
| **hue census `test_tc079_5*`** (HIGH-1, vacuous input set) | spec TC-079.5 = "C-29 both axes" | shipped `test_tc079_5*` = the **hue-reservation census** (Inc-2b) — a **re-pointing**, not the geometry it was named for | **CLOSED but note**: the geometry obligation migrated to `test_tc078_5`/`test_tc080_6`; TC-079.5's spec text is now stale wording |
| **AT-075f / R-NEW-1** (Select-label class, beyond original 7 HLRs) | not in the pinned-26 | 3 nodes `test_at075f_*` (15 param cases) | **ADDED in-batch** — traces to R-NEW-1; not an orphan; registry moves 26 → 26+AT-075f |
| **⚠ Amendment D** (title de-dup) | **NOT in `01-requirements.md` §6.5** | recorded in `REQUIREMENTS.md` + `increment-02.md`; drove `test_tui_patch_layout.py` +59/−11 | **OPEN (doc-only)** — see §4 |

---

## 4. The one named gap — Amendment D not reconciled into §6.5 (iterate-to-refine, doc-only)

**What:** `01-requirements.md` §5.3 gates on *"`tests/test_tui_patch_layout.py` passes **unmodified**"* and §5.2 `AT-076c` says *"(existing, **unmodified**)"*. In fact Inc-2 **modified** that file (+59/−11) under a **batch-48 §6.5 Amendment D** — a "title de-dup": Inc-1 added `border_title ¹PATCH SCRIPT` etc. to the three windows, duplicating pre-existing in-window title statics, so Amendment D **deleted the three redundant statics** and the layout test's title assertions were **DELETE-AND-RESTATE**d (the window now self-describes on its own border title). `increment-02.md:379` itself flags that this also supersedes Amendment A's "Deleted — none".

**Why it is NOT a code/coverage gap:**
- The `_MUST_PRESERVE_IDS` tuple is **intact at 48** (verified) — Amendment D touched window-title assertions, not the id set.
- `AT-076c`'s substance (48 ids present + in role) holds and is green.
- The change was recorded through the **sanctioned amendment mechanism** (Before/After in `REQUIREMENTS.md`, delete-and-restate not hide) — the honest form.

**Why it must be surfaced:** Amendment D was recorded in `REQUIREMENTS.md`/`increment-02.md` but **never folded back into `01-requirements.md` §6.5** (which still shows only A / B / retired-C and Amendment A's now-superseded "Deleted — none"), and the §5.2/§5.3 "unmodified" wording was never updated. A future reader of the canonical requirements doc would see a gate that the shipped tree does not satisfy.

**Classification: iterate-to-refine (Phase 1 doc), Phase-6 action** — fold Amendment D into `01-requirements.md` §6.5, correct Amendment A's "Deleted — none", and re-word §5.2 `AT-076c` + §5.3 from "unmodified" to "passes (modified under Amendment D; 48-id tuple unchanged)". **No code change; does not block the gate.**

---

## 5. Known-carry ledger (explicitly deferred, not silently skipped)

1. **Full unfiltered `pytest -q` suite** (the orchestrator's C-25 background run, `scratchpad/phase4_full.txt`): **still executing at Phase-4 authoring time (~50%, no `EXIT=` yet)**. Interim authority = `scratchpad/gate.txt` reduced-suite **1540 passed / 0 failed / 5 xfailed** (baseline 1514). **Action:** read the final count from `phase4_full.txt` when it lands (`EXIT=` sentinel) and confirm 0 failed before merge; the `slow`/deselected stress-perf tests are the delta not exercised by the gate.
2. **Canonical-CI snapshot regen** (post-merge PR): the **2** patch cells `patch-comfortable-80x24` / `patch-comfortable-120x30` are `xfail(strict=False)` while drifting (Inc-7 predicts they ABSORB; the batch's visible repaints must be baked into the SVG baselines and the `_batch48_patch_drift_marks` xfail retired) — run in `snapshot-regen.yml` at `textual==8.2.8` only. **Local regen FORBIDDEN.**
3. **`a2l.py:926` frozen F841** — pre-existing, cannot fix while `tui/a2l.py` is engine-frozen (C-27); carried, not introduced by this batch.
4. **Backlog carry (Inc-1 §4):** fix the false `sensor[unclosed` counterfactual claim at its batch-47 origin (`tests/test_tui_a2l_detail.py:24-26,49`) — a doc/comment correction, not a defect.
5. **Named-colour census widen** (Inc-5b stated gap): the hue sweep resolves named styles' *values* but the *set of names* (`orange3`,`green`,`red`) is still hand-enumerated; a new named chromatic style added elsewhere would not be caught. Out of batch-48 scope; honest next step.

---

## Evidence checklist (Phase-4 completion)

- [x] **Every AT resolves to exactly one on-disk node (C-18)** — 26 canonical + AT-075f, all confirmed via `pytest --collect-only` at HEAD `ef7fe74`.
- [x] **Every HLR/LLR has a TC or declared inspection/analysis** — §1 matrix; no uncovered LLR.
- [x] **Zero orphan node** — every extra node maps to a named parent chain (§2.1).
- [x] **Gate-blocking + headline ATs are non-vacuous** — recorded RED for AT-075d/e/f, AT-077c/e, AT-079c, AT-080d, hue census (§2.2); spot-run 17 passed.
- [x] **Coverage / Certainty / Evidence each have a verdict + evidence** — §2.
- [x] **§6.4 id reconciliation complete** — BL-2, HLR-080↔081, AT-077e split, AT-079b `or`, 5-site census, hue re-pointing, AT-075f/R-NEW-1 (§3).
- [x] **Known-carry ledger stated** — full suite / snapshot regen / a2l F841 (§5).
- [x] **Structural gates verified at HEAD** — 48-id tuple, v2 0-diff, layout green.
- [x] **No real PII / secrets** — synthetic C-17 payloads only.
- [ ] **Full unfiltered suite green** — DEFERRED to the background run's `EXIT=` (§5.1); interim gate 1540/0.
- [x] **One gap named, not hidden** — Amendment D §6.5 reconciliation (§4), classified iterate-to-refine (doc-only).

---

## §7 — Authoritative full-suite run: EXIT=1 investigated and CLEARED (orchestrator, C-25)

**Verdict: EXIT=1 carries ZERO real test failures. It is a PRE-EXISTING syrupy "unused-snapshot" session artifact, present in batch-48's base (`6551aed`) and NOT introduced by this batch. Phase-4 evidence stands.**

### The authoritative run
`python -m pytest -q -p no:randomly` @ `ef7fe74` → **1560 passed / 2 skipped / 5 xfailed / 0 failed**, `EXIT=1` (1349s). Re-run with `-rfE --tb=line` (explicit fail/error listing): the short-test-summary is **EMPTY** — `RFE_EXIT=1`, again 1560 passed / 0 failed. **Three independent proofs of zero real failures:** (a) `grep -E "^(FAILED|ERROR)"` = nothing; (b) summary `0 failed`; (c) `-rfE` explicit list = empty.

### Every subset exits 0 — only the complete run exits 1
`-m "not slow"` (1540) = **0** · slow-only (20) = **0** · snapshot-only (30+2xfail) = **0** · snapshot+pilot-gif (45+2xfail) = **0** · **full (1560) = 1**. `1540 + 20 = 1560`; no test fails in any subset.

### Mechanism (named, not inferred)
`pytest-textual-snapshot` is built on **syrupy**. Syrupy fails the session on **unused snapshots**, but ONLY when `SnapshotReport.selected_all_collected_items()` is true — i.e. `collected.keys() == selected.keys()`, a COMPLETE unfiltered run (`syrupy/report.py:195`). Any filtered run (`-m "not slow"` deselection, or explicit test paths) makes `selected != collected` → the unused check is **skipped** → exit 0. This exactly matches the observed filtered-vs-full split.

### The 2 unused snapshots — identified, benign, pre-existing
`test_tc036s_entropy_modal_snapshot[entropy-comfortable-80x24].svg` and `[entropy-comfortable-120x30].svg`. The test `test_tc036s_entropy_modal_snapshot` **no longer collects anywhere** — it was intentionally RETIRED in **batch-45** (`4608953`, "retire entropy pop-up"; baselines last touched batch-37 `5a6c45b`). Only a code COMMENT (`test_tui_snapshot.py:440`) still names it. The 2 orphan baselines were never cleaned up and are **on `main`**.

### batch-48 is exit-code-neutral on this axis
- `git diff 6551aed -- tests/__snapshots__/` (batch-48 vs its true base) = **EMPTY** — batch-48 touched zero baselines and introduced zero new orphans.
- (The `git diff main -- __snapshots__` "29 files" is a phantom: local `main`=`768f70a` is STALE, predating batch-48's base `6551aed`=PR#87 regen. It is the batch-47 regen, not batch-48.)
- Therefore `pytest -q` (full) exits 1 on the base tree too; batch-48 does not change it.

### CI impact: NONE on the blocking path
The PR-blocking gate is `pytest -q -m "not slow"` (`tui-ci.yml:47`) → filtered → **exit 0** (reduced gate = 1540 passed). The snapshot layout-drift oracle is a separate **non-blocking** job (`tui-ci.yml:53`); the regen workflow already uses `|| true` (`snapshot-regen.yml:42`, "pytest exits non-zero when it updates a snapshot"). The project is built around this plugin's non-zero exits.

### Carry (NOT a batch-48 blocker)
The **post-merge canonical-CI snapshot-regen follow-up** (already owed for the 2 xfail patch drift cells) should ALSO delete the 2 orphan `test_tc036s` baselines — it already owns `tests/__snapshots__/` changes. Deliberately NOT cleaned in batch-48: pre-existing cruft, out of the patch-editor scope, and snapshot-dir hygiene belongs with the regen (surgical-changes rule). Recorded in PLAN.md carries + MEMORY.md backlog.

**Phase-4 exit axes (final): Coverage PASS · Certainty PASS · Evidence PASS.** The one open item (§4 stale "unmodified" doc claim under Amendment D) is Phase-6 doc reconciliation. Zero iterate-to-fix, zero iterate-to-refine on code.
