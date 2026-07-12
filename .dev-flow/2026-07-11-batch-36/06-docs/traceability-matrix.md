# Traceability Matrix — 2026-07-11-batch-36

> Phase 6 (Documentation). Author: docs-writer. Complete US → HLR → LLR → TC/AT trace for the
> three shipped stories of batch-36 (US-058 patch-editor paste box · US-059 hex-view colour legend ·
> US-060 fixture relocation). On-disk node ids are the **reconciled** ids from
> `04-validation.md` §2/§3 (each AT = exactly one node, C-18). Sourced from
> `.dev-flow/2026-07-11-batch-36/01-requirements.md` (§4 HLR/LLR, §5 traceability) and
> `04-validation.md`. Every row status = **Automated** — all nodes ran GREEN in the one complete
> gate run (`1343 passed, 5 xfailed, 0 failed`, exit 0; `04-validation.md` §1).

**Audience:** engineering / QA (traceability audit). **Purpose:** prove zero coverage gaps
before merge. **Coverage summary:** 3 US → 3 HLR → 11 LLR → 5 ATs + 3 new TCs (+ 2 survivor TCs
rerun as regression). Every US has ≥1 black-box AT through the shipped surface; every LLR maps to
a named on-disk node. **0 gaps.**

---

## 1. Behavioral chain — US → AT → observable outcome (black-box)

Each AT is ONE on-disk node that drives the whole named chain through the shipped surface, asserts
the deliverable content (not merely non-empty), and carries a measured RED counterfactual
(`04-validation.md` §3).

| US | Observable outcome (shipped surface) | AT | On-disk node (file:line) | Status |
|----|--------------------------------------|----|--------------------------|--------|
| US-058 | Paste editor's first line in-viewport at `scroll_y==0` with ≥ N_w measured lines (N_80=1, N_120=4); `#patch_paste_row` reparented out of `#patch_pane_changefile`, region disjoint from the change-file cluster, no right-edge clip @80 and @120 | AT-058a | `tests/test_tui_patch_layout.py::test_at058a_paste_editor_in_viewport_and_separated` (:532) | **Automated** |
| US-058 | All 15 `patch_*` ids resolve to exactly one widget; AT-032a help-token span survives; pressing `#patch_checks_run_button` posts a real `Checks:` status line (handler side-effect, C-12) | AT-058b | `tests/test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent` (:2461) | **Automated** |
| US-059 | `LegendScreen` modal `#legend_body` carries a `Hex` section with the two exact overlay-colour meaning strings (Yellow = search/goto-focus, Orange3 = MAC overlay) | AT-059a | `tests/test_tui_legend.py::test_at059a_hex_legend_present_in_modal` (:368) | **Automated** |
| US-059 | Generated `reports/*.md` file bytes contain `### Hex` + both meaning strings — handler writes, test re-reads the file off disk (output-then-consume, C-12) | AT-059b | `tests/test_tui_report_seam.py::test_at059b_hex_legend_present_in_report` (:1570) | **Automated** |
| US-060 | `tmp/stress_smoke/` gone (disk + git index); `examples/case_07_stress_smoke` loads to a `LoadedFile` with non-empty `mem_map` via the real service layer; 54 MB duplicate absent; 36 MB `case_06_large_nested_a2l/firmware.a2l` retained | AT-060a | `tests/test_examples_smoke.py::test_at060a_fixtures_relocated_heavy_duplicate_pruned` (:170) | **Automated** |

---

## 2. Functional chain — US → HLR → LLR → TC/AT (white-box)

| US | HLR | LLR | Test case / AT | On-disk node (file:line) | Status |
|----|-----|-----|----------------|--------------------------|--------|
| US-058 | HLR-058 | LLR-058.1 (dedicated paste region; 3-col reflow rejected by 80-col budget; N re-derived from measured vertical budget, F-01) | AT-058a | `tests/test_tui_patch_layout.py::test_at058a_paste_editor_in_viewport_and_separated` (:532) | **Automated** |
| US-058 | HLR-058 | LLR-058.2 (paste group reparented + sibling-disjoint from cluster, no clip @80/@120) | AT-058a | `tests/test_tui_patch_layout.py::test_at058a_paste_editor_in_viewport_and_separated` (:532) | **Automated** |
| US-058 | HLR-058 | LLR-058.3 (zero behaviour change: 15-id census + wiring, compose + CSS only) | AT-058b | `tests/test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent` (:2461) | **Automated** |
| US-058 | HLR-058 | LLR-058.4 (patch snapshot rebaseline deferred to canonical CI) | TC-321 | `tests/test_tui_snapshot.py::test_tc321_batch36_patch_xfail_set` (:606) | **Automated** |
| US-059 | HLR-059 | LLR-059.1 (add `Hex` block to `LEGEND_TABLE` sourced from shipped overlay styles) | TC-322 | `tests/test_tui_legend.py::test_tc322_hex_block_coupled_to_overlay_styles` (:406) | **Automated** |
| US-059 | HLR-059 | LLR-059.2 (one added block reaches BOTH legend surfaces — single-source, C-12) | AT-059a + AT-059b | `tests/test_tui_legend.py::test_at059a_hex_legend_present_in_modal` (:368) · `tests/test_tui_report_seam.py::test_at059b_hex_legend_present_in_report` (:1570) | **Automated** |
| US-059 | HLR-059 | LLR-059.3 (anti-drift: Hex block decoupled from `COLOUR_SEVERITY`, coupled to overlay styles) | TC-322 | `tests/test_tui_legend.py::test_tc322_hex_block_coupled_to_overlay_styles` (:406) | **Automated** |
| US-060 | HLR-060 | LLR-060.1 (relocate `tmp/stress_smoke/` into a discoverable `examples/` case) | AT-060a | `tests/test_examples_smoke.py::test_at060a_fixtures_relocated_heavy_duplicate_pruned` (:170) | **Automated** |
| US-060 | HLR-060 | LLR-060.2 (prune 54 MB slow duplicate, retain 36 MB large A2L; I-060-1 construct-census gate) | AT-060a + I-060-1 gate | `tests/test_examples_smoke.py::test_at060a_fixtures_relocated_heavy_duplicate_pruned` (:170); gate recorded `increment-002.md` §I-060-1 | **Automated** |
| US-060 | HLR-060 | LLR-060.3 (test edits + coverage-preservation map; `SLOW_CASE_IDS` empty) | TC-323 | `tests/test_examples_smoke.py::test_tc323_discovery_and_coverage_map` (:229) | **Automated** |
| US-060 | HLR-060 | LLR-060.4 (measured size reduction 96 M → ~42 M; `tmp/` cleanup) | AT-060a | `tests/test_examples_smoke.py::test_at060a_fixtures_relocated_heavy_duplicate_pruned` (:170) | **Automated** |

---

## 3. Regression survivors rerun inside the gate (no new coverage, invariants pinned)

| Invariant | LLR / US | On-disk node (file:line) | Status |
|-----------|----------|--------------------------|--------|
| 15-id census + `#patch_doc_file_row` internal child order invariant under the paste reparent | LLR-058.3 supersession pin | `tests/test_tui_patch_layout.py::test_tc319_regroup_section_structure_census` (:351) | **Automated (survives)** |
| Variant `Select` group stays above the execute row (Inc-3 `1fr 2fr 2fr` weight chosen to keep this green) | US-058 vertical-budget dependency | `tests/test_tui_patch_variant.py::test_tc_035_2_variant_group_above_execute_row` (:413) | **Automated (survives)** |
| Legend report↔modal render the same rows (single-source parity) | LLR-059.2 anti-drift | `tests/test_tui_legend.py::test_tc_s2_report_and_modal_render_same_rows` (:454) | **Automated (survives)** |

---

## 4. Gap check

- **Every US** (US-058/059/060) has ≥1 black-box AT observing its outcome through the shipped
  surface: US-058 → AT-058a/AT-058b; US-059 → AT-059a/AT-059b; US-060 → AT-060a. ✓
- **Every HLR** traces to exactly one US; **every LLR** (11) traces to its parent HLR and to a
  named on-disk node. ✓
- **Every AT/TC node** confirmed present on disk and GREEN in the one complete gate run
  (`04-validation.md` §1/§2/§3). ✓
- **New nodes this batch:** AT-058a, AT-058b, AT-059a, AT-059b, AT-060a (5 ATs); TC-321, TC-322,
  TC-323 (3 TCs). Ledger `--collect-only == 1370` (base 1362 + 8 net; `04-validation.md` §1). ✓

**Result: 0 gaps.** Every US → HLR → LLR → TC/AT chain is complete and Automated.
