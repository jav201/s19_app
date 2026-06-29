# Validation — s19_app — Batch 2026-06-26-batch-18

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`); for Spanish batches translate headers/labels.
> Phase 4 artifact. Owner: `qa-reviewer`. Executes the validation strategy fixed in Phase 1.

## ✅ Verdict (read first)

- **Result:** **PASS**
- **Requirements:** 2 US / 2 HLR / 5 LLR — all covered on BOTH layers · **0** blocker fails
- **Black-box acceptance (Layer B):** ✓ every story's `AT` observes its outcome through the shipped surface (report file on disk for US-022; Pilot key/button + rendered modal for US-023), each with boundary + negative evidence
- **Surface-reachability (bidirectional):** ✓ all named inputs AND outputs/deliverables reached/observed at the shipped surface
- **Supersession inspection:** ✓ N/A — this batch adds net-new surfaces; it supersedes no placeholder/marker constant (no deferral notice retired)
- **Test ledger:** ✓ reconciles (`892 − 0 + 16 = 908`)
- **Engine-frozen / ruff:** ✓ `color_policy.py` diff vs `main` = 0 lines; `test_tui_directionb` frozen guard green; ruff clean on all changed Python
- **Evidence checklist (qa-reviewer):** ✓ complete
- **§6.5 amendment A1 (C-13: A2L button → `k` key):** ✓ reflected in AT-023a/e + TC-023.2 below

> One minor process note (G-1) — SVG snapshot baselines for the 3 views skip locally and must regen in canonical CI at PR. Not a blocker; PR `tui-ci` is authoritative.

---

## Detail (reference)

### Layer A — functional (white-box): per-requirement results

| Req | Method | Executed verification (real reconciled node) | Numeric threshold | Result | Evidence |
|-----|--------|-----------|-------------------|--------|----------|
| HLR-022 | test | `pytest tests/test_report_service.py -k legend` + `tests/test_tui_legend.py` | legend + every LEGEND_TABLE row present; 0 missing | **pass** | report carries `## Legend` + all 12 rows |
| LLR-022.1 (shared `legend.py`) | test (unit) + inspection | `test_legend_table_covers_all_severities`, `test_legend_table_has_documented_artifacts_and_rows`, `test_legend_data_not_in_frozen_color_policy` | 3 artifacts; 5 severities reachable; `color_policy.py` diff=0 | **pass** | TC-S1 + TC-frozen-diff green; diff empty |
| LLR-022.2 (report emitter) | test (unit+integration) | `test_legend_lines_renders_shared_table`, `test_include_legend_default_true_and_validated` | True→legend present, False→absent; reads table | **pass** | TC-022.1/.2 green |
| HLR-023 | test (pilot) | `pytest tests/test_tui_legend.py -k 023` | 3/3 views open modal; fits 80 & 120; 0 clipped | **pass** | AT-023a–f green |
| LLR-023.1 (`LegendScreen`) | test (pilot) | `test_tc023_1_modal_renders_all_table_rows` | mounts all 3 artifact tables; reads LEGEND_TABLE | **pass** | TC-023.1 green; headers == `list(LEGEND_TABLE)` |
| LLR-023.2 (buttons + dispatch + `k` binding) | test (pilot) | `test_tc023_2_mac_issues_buttons_present_a2l_absent` + AT-023a/b/c | MAC/Issues button=1, A2L button=0; each affordance opens modal | **pass** | TC-023.2 green; §6.5 A1 |
| LLR-023.3 (C-13 geometry) | analysis + inspection | `test_at023e_c13_geometry_at_80_cols` | MAC/Issues btn on-screen @80; A2L 0 buttons; modal within 80×30 | **pass** | measured: MAC right=23, Issues=69 ≤80; A2L btn off-screen→keybinding |
| Single-source anti-drift | test (pilot) | `test_tc_s2_report_and_modal_render_same_rows` | report rows == modal rows; equal cardinality | **pass** | TC-S2 green |

### Layer B — behavioral (black-box) acceptance

| US | Acceptance test (real node) | Surface driven | Deliverable observed | repr · boundary · negative | Result |
|----|----------------------------|----------------|----------------------|----------------------------|--------|
| US-022 | `test_report_includes_legend_with_documented_rows` (AT-022a) | `generate_project_report` → `reports/<ts>-report.md` | report file text contains `## Legend` + every row meaning | ✓·✓ (`include_legend` on/off)·✓ (AT-022b) | **pass** |
| US-022 | `test_report_omits_legend_when_disabled` (AT-022b) | same, `include_legend=False` | legend section absent | — · ✓ · ✓ | **pass** |
| US-023 | `test_at023a_a2l_legend_opens_via_key` (AT-023a) | A2L view → `pilot.press("k")` | rendered `LegendScreen` carries A2L rows | ✓·✓ (C-13 key)·— | **pass** |
| US-023 | `test_at023b/c_*_legend_button_opens` (AT-023b/c) | MAC/Issues `#*_legend_button` press | modal carries that artifact's rows | ✓·✓·— | **pass** |
| US-023 | `test_at023d_close_dismisses_modal` (AT-023d) | `#legend_close` press | modal popped (back to view) | — · — · ✓ (dismiss) | **pass** |
| US-023 | `test_at023e_c13_geometry_at_80_cols` (AT-023e) | 80-col render of 3 views + modal | btn regions / A2L absence / modal bounds | — · ✓ (80-col) · ✓ (no clipped) | **pass** |
| US-023 | `test_at023f_legend_shows_without_file_loaded` (AT-023f) | no file → `pilot.press("k")` | static legend (12 rows) still shows | — · ✓ (empty) · — | **pass** |

### Bidirectional surface-reachability matrix

| Direction | US dimension / deliverable | Producer / param | Reached/observed at surface? | TC / AT | Status |
|-----------|---------------------------|------------------|------------------------------|---------|--------|
| output | report legend section | `_legend_lines` via `generate_project_report` | yes — report file on disk | AT-022a | ✓ |
| input | `include_legend` on/off | `ReportOptions.include_legend` | yes — both states through the report surface | AT-022a/b, TC-022.2 | ✓ |
| output | in-app legend modal | `LegendScreen` via `action_show_legend` | yes — rendered modal queried | AT-023a/b/c, TC-023.1 | ✓ |
| input | per-view affordance (A2L key / MAC,Issues button) | `k` binding + 2 button ids | yes — each affordance drives the modal | AT-023a/b/c, TC-023.2 | ✓ |
| input | 80-col regime (C-13) | `App.run_test(size=(80,30))` | yes — measured region bounds | AT-023e | ✓ |

### Supersession-completeness inspection
N/A — batch-18 adds net-new modules/surfaces (`legend.py`, `LegendScreen`, report legend section, `k` binding). It retires no placeholder/marker constant; there is no superseded-reference class to grep. Change-first census (Phase 2) confirmed the only frozen file in blast radius is `color_policy.py`, kept READ-only (diff=0).

### Signed-balance test ledger

| base | − D | + A | = post | actual collected (non-slow) | passed-full | reconciles? |
|------|-----|-----|--------|------------------------------|-------------|-------------|
| 892 | 0 | 16 | 908 | 908 passed / 29 skipped / 3 xfailed / 21 deselected | 908 | **yes** |

`+A` = Inc1 (7: AT-022a/b, TC-022.1/.2, TC-S1 ×2, TC-frozen-diff) + Inc2 (9: AT-023a–f, TC-023.1/.2, TC-S2).

### Gaps detected

| ID | Requirement | Gap | Severity | Proposed action |
|----|-------------|-----|----------|-----------------|
| G-1 | LLR-023.3 / HLR-023 | SVG snapshot cells for `#screen_a2l`/`#screen_mac`/`#screen_issues` (+ footer with the new `k` binding) skip locally (CI-gated) | minor (process) | Regenerate baselines in canonical CI at PR (never local — `reference_snapshot_regen_env`); PR `tui-ci` is authoritative |

### Counterfactual RED evidence (QC-2 value-discrimination — captured at Phase 3)

| AT/TC | Counterfactual applied | Pre-fix RED kind | Result under counterfactual | Restored |
|-------|------------------------|------------------|------------------------------|----------|
| AT-022a | report emit gated off (`if False and …`) | value (no `## Legend`) | RED (AT-022b/TCs stay green) | ✓ |
| TC-S1 | drop `NEUTRAL` from `COLOUR_SEVERITY` | value (severity unreachable) | RED | ✓ |
| AT-023b/c | button dispatch ids renamed `_DISABLED` | value (modal never opens) | RED (A2L key path stays green) | ✓ |
| TC-S2 / TC-023.1 / AT-023c | modal drops the `Issues` artifact | value (row-set inequality) | RED | ✓ |

All four REDs are value-discriminating (the post-fix assertion keys on the right payload — meaning text / severity reachability / row-set), not mere shape wiring.

### Evidence checklist — qa-reviewer

- ✓ Both layers present for every requirement (Layer A TCs + Layer B ATs) — tables above.
- ✓ Every AT drives the SHIPPED surface (report file on disk; Pilot key/button + rendered modal), references no internal symbol in its assertion of the outcome (asserts colour→meaning content).
- ✓ Boundary + negative evidence present (include_legend off; empty/no-file; dismiss; 80-col regime).
- ✓ Provisional AT/TC ids (V-5) reconciled to real collected nodes — every id in this doc is a real `pytest` node.
- ✓ Signed-balance ledger reconciles (892−0+16=908); full non-slow suite 908 passed / 0 failed.
- ✓ Engine-frozen untouched (`color_policy.py` diff=0; directionb guard green); ruff clean.
- ✓ §6.5 amendment A1 reflected in acceptance (AT-023a observes the `k` key; AT-023e + TC-023.2 assert the A2L button absence).
- ✓ Single-source coupling validated at the rendered layer (TC-S2: report vs modal row-set equality).
