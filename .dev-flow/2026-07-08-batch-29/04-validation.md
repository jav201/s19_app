# 04 — Validation · batch-29 · clipboard read cap + legacy Issues DataTable retirement

**BLUF — verdict: PASS-WITH-NOTES.** Both stories ship verified through their shipped surfaces.
Full suite (orchestrator, ~18 min, at Inc4): **1157 passed · 2 skipped · 23 xfailed · 0 failed · exit 0**
(1182 collected); **Inc5 then added AT-043-c17 (+1 → 1158 passed / 1183 collected)** — its file verified
green, confirmed by the final pre-merge full-suite run. Every provisional `AT-`/`TC-` id in the v2 spec
reconciles to a real on-disk `def test_…` node, and each is **green**. Engine-frozen diff **empty**;
`#validation_issues_list` grep in `s19_app/` = **0 source hits**. The "notes" are two deferred, disclosed
items — none a production regression (the third, the AT-043-c17 gap, was CLOSED in Inc5):
1. **23 snapshot xfails** (20 Issues/workspace cells absorbing batch-28 restyle drift + 3 pending
   baselines) → cleared only by canonical-CI regen (pinned `textual==8.2.8`); local regen FORBIDDEN.
2. **R-043-3 dead-write follow-up** — `precompute_issue_datatable_payload` still worker-invoked, its
   caches now dead-written every load (never read); retirement is a named follow-up batch.
3. **AT-043-c17 gap — CLOSED in Inc5 (orchestrator decision under standing auth).** The spec's
   *file-derived* multi-REF C-17 AT was initially unrealized; rather than ship-with-note, it was closed by
   adding `test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal` (`test_tui_a2l_issue_recolor.py:326`):
   two hostile no-whitespace GROUP-REF tokens (`MAP_Model[bold]`, `x[link=file:///etc]`) driven through the
   REAL load chain → verified (load-bearing positive guard) to round-trip verbatim into `issue.symbol` via the
   frozen lexer → asserted LITERAL in the rendered grouped `.issue-detail`. Counterfactual: a markup-parsing
   node consumes both tokens (`Text.from_markup('MAP_Model[bold]').plain == 'MAP_Model'`; `[link=…]` vanishes).
   The seeded `test_at_039e_c17_…` is retained as the companion. C-17 strengthening now realized.

Route: full /dev-flow. Language: English. This phase RECORDS + RECONCILES the validation executed
across Inc1–Inc4; it re-implements nothing.

---

## 1. Suite-level evidence (cited)

| Check | Command / source | Result |
|---|---|---|
| Full suite | orchestrator `pytest -q` (~18 min) | **1157 passed, 2 skipped, 23 xfailed, 0 failed** (1182 collected), exit 0 |
| Snapshot subset | within full suite (`test_tui_snapshot.py`) | 20 "mismatched" cells are batch-28 `xfail(strict=False)` — within the xfail envelope, **0 hard fail, 0 ERROR** |
| Engine-frozen (diff) | `git diff main -- core.py hexfile.py range_index.py validation/ tui/a2l.py tui/mac.py tui/color_policy.py` | **EMPTY** |
| Engine-frozen (guard) | `tests/test_engine_unchanged.py` + `test_tui_directionb.py::test_tc031_*` | **pass** |
| Retirement grep | `#validation_issues_list` / `_populate_issues_datatable` / `_issue_row_key_to_index` / `_jump_to_validation_issue_by_index` in `s19_app/` | **0 source hits** (verified this phase) |
| Restored node | `s19_app/tui/issues_view.py:186–189` — `.issue-related` built via `safe_text` | present |

Ledger: 1171 (base) → 1180 (Inc1) → 1181 (Inc2) → 1181 (Inc3, rewrites-in-place, Δ0) → **1182 (Inc4)**.
Collected 1182 = 1157 passed + 2 skipped + 23 xfailed.

---

## 2. Layer A — functional (white-box `TC` ↔ LLR)

Each LLR mapped to its real collected node (grepped from `tests/`), Result = pass. Where a LLR is
verified by inspection/grep (CSS/column removal, engine-frozen, corollary), that is stated.

### US-042 — clipboard cap (all nodes in `tests/test_loadfilescreen_input.py`)

| LLR | Real node (`def …`) | Line | Mechanism | Result |
|---|---|---|---|---|
| LLR-044.1 | `test_tc042_1_cap_constant_is_positive_int_at_least_4096` | 775 | `_CLIPBOARD_READ_CAP_CHARS` exists, positive int (not bool), ≥4096 | pass |
| LLR-044.2 | `test_tc042_2_bound_helper_behavior` | 785 | `_bound_clipboard_text`: ≤CAP unchanged; longer → `[:CAP]`; `""`/`None` no-raise | pass |
| LLR-044.2/.3 | `test_tc042_3_read_os_clipboard_bounds_selected_strategy_result` | 809 | `read_os_clipboard` bounds the selected strategy result (caller-independent) | pass |
| LLR-044.4 | (functional, via AT-042f — splitlines[0] of already-capped) | — | see Layer B | pass |
| LLR-044.5 | **by-inspection (corollary of LLR-044.2)** — `_bound_clipboard_text` runs *before* the `len=%d` debug-log funnel (`os_clipboard_input.py`), so the logged length is post-cap. arch-m4: non-independent, no separate node. | — | inspection | n/a |
| LLR-044.6 | **DEFERRED (named-not-built)** — bounded `Popen(...).stdout.read(CAP+1)` source bound; not this batch | — | — | deferred |

### US-043 — retirement (R1–R7) + restoration (R8)

| LLR | Real node / method | File · line | Mechanism | Result |
|---|---|---|---|---|
| LLR-043.R1 (=TC-043-retire.1) | `test_tc023_grouped_panel_is_primary_content_of_screen_issues` | `test_tui_directionb.py:1841` | inverted TC-023: `_compose_screen_issues` yields no `DataTable(id=validation_issues_list)`; `GroupedIssuesPanel` is primary child of `#issues_list_stack` | pass |
| LLR-043.R2 | **by-inspection / grep** — both CSS rules + compat comment removed from `styles.tcss`; grep `#validation_issues_list` in `s19_app/` = 0; `.issue-*` + `#validation_issues_summary` preserved; snapshot-neutral (display:none had zero layout) | `styles.tcss` | grep + snapshot | pass |
| LLR-043.R3 | **by-inspection / grep** — `#validation_issues_list` column-init try/except gone; MAC/A2L init intact (grep 0 source hits) | `app.py` | grep | pass |
| LLR-043.R4 (=TC-043-retire.2) | `test_update_validation_issues_view_empty_state` (+ `…_pages_large_issue_list`) | `test_tui_app.py:836` / `:876` | empty + populated paths route only through `_render_validation_issues_groups`; no `query_one("#validation_issues_list")` / `_populate_issues_datatable`; summary kept. Orphan `_populate_issues_datatable` grep = 0 | pass |
| LLR-043.R5 (=TC-043-retire.3) | `test_on_data_table_row_selected_dispatches_by_id` | `test_tui_app.py:1542` | issues branch dropped from `on_data_table_row_selected` (MAC+A2L intact); `_issue_row_key_to_index` + `_jump_to_validation_issue_by_index` grep = 0 | pass |
| LLR-043.R6 | **by-retention** — recolor suites + AT-039* green: existing `IssueRow` code-chip + `.issue-detail` markup-safety, `#issues_hex_pane`, paging, summary, `_GROUP_DISPLAY_MAX=40` unchanged | `issues_view.py:51` | retention | pass |
| LLR-043.R7 | `tests/test_engine_unchanged.py` + `git diff main -- <frozen set>` EMPTY | — | frozen guard | pass |
| LLR-043.R8 (=TC-043-restore.1) | `test_tc043_restore1_related_node_is_markup_safe` | `test_tui_issues_view.py:227` | `IssueRow.compose` yields one `.issue-related` node; plain text `", ".join(related_artifacts) or "-"` via `safe_text`; hostile `["a2l[bold]","x[link=file:///etc]"]` renders **literal** (no `MarkupError`, brackets intact, `[link=…]` not consumed) | pass |
| LLR-043.R4/R7 (=TC-043-retire.4) | **by-inspection / grep** — dead-code census: `_populate_issues_datatable` gone; no *consumer* of cached rows remains (`use_precomputed` block deleted); `precompute_issue_datatable_payload` may still be worker-invoked (dead-written, R-043-3); frozen diff 0 | `app.py` | grep + retired `test_populate_issues_datatable_records_filtered_index` | pass |

---

## 3. Layer B — behavioral (black-box `AT`, observed through the SHIPPED surface)

Each AT observes the deliverable through the shipped handler surface (not a service API), and each
carries a shown counterfactual.

### US-042 — surface: `read_os_clipboard()` return + `OsClipboardInput.value` after a real `ctrl+v`
All nodes in `tests/test_loadfilescreen_input.py`.

| AT | Real node | Line | Surface observed | Counterfactual shown |
|---|---|---|---|---|
| AT-042a | `test_at042a_read_os_clipboard_caps_huge_single_line_blob` | 639 | `read_os_clipboard(strategies=huge)` return → len `== CAP`, `== blob[:CAP]` | pre-cap returns full multi-MB blob → len `== CAP+5M` (FAIL) |
| AT-042b | `test_at042b_ctrl_v_inserts_capped_value_via_real_read` | 657 | inject at `os_clip_mod._STRATEGIES` (BELOW the cap, per B-1 fix), real `press("ctrl+v")` → `action_paste` → `input.value` len `<= CAP`, `== blob[:CAP]` | pre-cap `input.value` len `== CAP+5M` (FAIL) |
| AT-042c | `test_at042c_boundary_at_cap_is_unchanged` | 691 | `"p"*CAP` → value unchanged, len `CAP` (inclusive) | over-aggressive cap would truncate at CAP → FAIL |
| AT-042d | `test_at042d_boundary_over_cap_by_one_drops_last_char` | 704 | `"p"*CAP+"X"` → len `CAP`, last char `"p"` (X dropped) | off-by-one keeps X → FAIL |
| AT-042e | `test_at042e_real_path_passes_through_untouched` | 718 | real ~120-char path via `ctrl+v` → `value ==` exact path | over-aggressive cap corrupts a real path → FAIL |
| AT-042f | `test_at042f_multiline_clipboard_inserts_only_first_line` | 747 | `"first\nsecond\nthird"` via `ctrl+v` → `value == "first"` | splitlines policy broken → FAIL |

Perf (V-5): "doesn't scale" is proven **structurally** by the length bound (`len == CAP`), not a
flaky wall-clock timer — AT-042a/b are the length-bound proof.

### US-043 — surface: widget tree, grouped nodes, `#issues_hex_pane`

| AT | Real node | File · line | Surface observed | Counterfactual shown |
|---|---|---|---|---|
| AT-043a | `test_at043a_datatable_retired_grouped_panel_populated` | `directionb:1943` | seed err/warn/info; open Issues → `query("#validation_issues_list")==0` AND `query("#validation_issues_groups")==1` with ≥1 `IssueRow` | pre-retirement `query 1` (hidden DataTable mounted) → FAIL |
| AT-043b | `test_at043b_selection_preserved_after_retirement` | `directionb:1980` | focus addressed `IssueRow`, `Enter` → `on_issue_row_selected` → `#issues_hex_pane` shows `0x…` bytes and CHANGES; `address None` → neutral, no stale bytes | pre-fix relied on retired row-key path → no repaint |
| AT-043c | `test_at043c_no_datatable_orphan_on_any_screen` | `directionb:2024` | boot; tree query on `#screen_issues` AND `#screen_workspace` → `query("#validation_issues_list")==0` on both | pre-retirement `1` on a rail screen → FAIL |
| AT-021 (RESTORED) | `test_at021_issues_list_shows_related_artifacts` | `issues_view:174` | seed one `related_artifacts=["a2l","mac"]` + one bare; rows ordered by `SEVERITY_ORDER` → multi row `.issue-related` plain text `== "a2l, mac"`; bare row `== "-"` — read via the dedicated `.issue-related` selector, not the payload formatter | pre-restore `IssueRow` has no related node → FAIL |
| AT-043-c17 (C-17) | `test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal` (`test_tui_a2l_issue_recolor.py:326`) — file-derived hostile REF → frozen lexer → grouped `.issue-detail` literal render; + retained seeded `test_at_039e_c17_…` + `TC-043-restore.1` | pass | hostile `MAP_Model[bold]` / `x[link=file:///etc]` | brackets/link literal, not consumed |
| AT-039e (retained seeded) | `test_at_039e_c17_hostile_code_symbol_message_render_literal` | `directionb:6250` | seed hostile `code='MAP_Model[bold]'`, `symbol='…\x1b[31m'`, `message='…[link=file:///etc]'` → grouped panel renders literal: `.issue-code-chip` plain contains `MAP_Model[bold]` (brackets intact); `.issue-detail` plain contains `[link=file:///etc]` (token NOT consumed → no OSC-8/style leak, no `MarkupError`) | if `safe_text` bypassed, `[bold]`/`[link]` raises `MarkupError` or the token is consumed → FAIL |

---

## 4. Bidirectional surface-reachability matrix

Every named INPUT dimension AND every named OUTPUT/deliverable is exercised **through the handler**
(Pilot `ctrl+v` / `action_paste`, `on_issue_row_selected`, `update_validation_issues_view`,
`IssueRow.compose` on the mounted panel), not only a service API.

### Inputs → handler → observed

| Input dimension | Through the handler (node) | Observed |
|---|---|---|
| oversized clipboard (single-line) | `read_os_clipboard` (AT-042a) + `action_paste` via `ctrl+v` (AT-042b) | return / `.value` capped |
| at-cap clipboard | `read_os_clipboard` (AT-042c) | len == CAP unchanged |
| over-cap-by-one | `read_os_clipboard` (AT-042d) | len CAP, X dropped |
| short/real path | `ctrl+v` → `action_paste` (AT-042e) | exact `.value` |
| multi-line clipboard | `ctrl+v` → `action_paste` (AT-042f) | `.value == "first"` |
| err/warn/info issue mix | Issues screen render (AT-043a; census #12 `test_tc024_issues_severity_filters_…`; AT-036*/037*) | grouped rows + header counts |
| addressed vs address-None | `Enter` → `on_issue_row_selected` (AT-043b; census #16 `test_tc024_issues_row_select_jumps_to_source`) | `#issues_hex_pane` repaint vs neutral |
| hostile file-derived symbol | **split (see §6):** grouped-surface via SEEDED `test_at_039e_c17_…`; file-derived *emission* via service `test_validate_a2l_structure_detects_broken_references` (`test_validation_a2l.py:22`) | literal render (seeded) / `A2L_BROKEN_REFERENCE` emitted (service) — never joined in one AT |
| related_artifacts present vs empty | `IssueRow.compose` on mounted panel (AT-021; TC-043-restore.1) | `.issue-related` `"a2l, mac"` vs `"-"` |

### Outputs / deliverables → observed through the surface

| Deliverable | Observed through (node) |
|---|---|
| `OsClipboardInput.value` | AT-042b/e/f (real `ctrl+v`) |
| grouped `IssueRow` / `IssueGroupHeader` | AT-043a, AT-021, census #12/#13/#15, AT-036*/037* |
| `.issue-code-chip` | `test_at_039e_c17_…` (chip render), census #9 `_query_issues_panel_codes` re-pointed to `.issue-code-chip` |
| `.issue-related` | AT-021, TC-043-restore.1 |
| `.issue-detail` | `test_at_039e_c17_…` (detail render), TC-043-retire guards (R6 by-retention) |
| `#issues_hex_pane` | AT-043b, census #16 |
| `#validation_issues_summary` | census #4 `test_update_validation_issues_view_empty_state`, #5 pages-large, #6 paging-actions (all through `update_validation_issues_view`) |

---

## 5. V-5 reconciliation — provisional spec id → real collected node

| Spec id | Real on-disk node | File · line | Note |
|---|---|---|---|
| AT-042a | `test_at042a_read_os_clipboard_caps_huge_single_line_blob` | `test_loadfilescreen_input.py:639` | 1:1 |
| AT-042b | `test_at042b_ctrl_v_inserts_capped_value_via_real_read` | `:657` | B-1 fix applied (inject `_STRATEGIES`) |
| AT-042c | `test_at042c_boundary_at_cap_is_unchanged` | `:691` | 1:1 |
| AT-042d | `test_at042d_boundary_over_cap_by_one_drops_last_char` | `:704` | 1:1 |
| AT-042e | `test_at042e_real_path_passes_through_untouched` | `:718` | 1:1 |
| AT-042f | `test_at042f_multiline_clipboard_inserts_only_first_line` | `:747` | 1:1 |
| TC-042.1 | `test_tc042_1_cap_constant_is_positive_int_at_least_4096` | `:775` | 1:1 |
| TC-042.2 | `test_tc042_2_bound_helper_behavior` | `:785` | 1:1 |
| TC-042.3 | `test_tc042_3_read_os_clipboard_bounds_selected_strategy_result` | `:809` | 1:1 |
| AT-021 | `test_at021_issues_list_shows_related_artifacts` | `test_tui_issues_view.py:174` | migrated to `.issue-related` (was `get_row_at`) |
| TC-043-restore.1 | `test_tc043_restore1_related_node_is_markup_safe` | `test_tui_issues_view.py:227` | 1:1 (merges arch-M2 + security-F1) |
| AT-043a | `test_at043a_datatable_retired_grouped_panel_populated` | `test_tui_directionb.py:1943` | 1:1 |
| AT-043b | `test_at043b_selection_preserved_after_retirement` | `test_tui_directionb.py:1980` | 1:1 |
| AT-043c | `test_at043c_no_datatable_orphan_on_any_screen` | `test_tui_directionb.py:2024` | 1:1 |
| TC-043-retire.1 | `test_tc023_grouped_panel_is_primary_content_of_screen_issues` | `test_tui_directionb.py:1841` | **inverted** TC-023 (was: DataTable IS primary) |
| TC-043-retire.2 | `test_update_validation_issues_view_empty_state` (+ `…_pages_large_issue_list`) | `test_tui_app.py:836` / `:876` | census #4/#5 re-point |
| TC-043-retire.3 | `test_on_data_table_row_selected_dispatches_by_id` | `test_tui_app.py:1542` | census #8 re-point |
| TC-043-retire.4 | grep-clean + `test_engine_unchanged.py` + retired `test_populate_issues_datatable_records_filtered_index` | `app.py` (grep) | by-inspection |
| AT-043-c17 | `test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal` (`test_tui_a2l_issue_recolor.py:326`) — realized in Inc5; companion seeded `test_at_039e_c17_…` (`directionb:6250`) retained | pass | closed |
| AT-039e (retained) | `test_at_039e_c17_hostile_code_symbol_message_render_literal` | `test_tui_directionb.py:6250` | retained; observes `.issue-code-chip` + `.issue-detail` on grouped panel |

Census content-migration nodes (C-14, all green post-retirement): #12 `test_tc024_issues_severity_filters_narrow_through_dedicated_screen`, #13 `test_tc024_issues_filter_buttons_route_through_dedicated_screen`, #14 `test_tc024_issues_paging_advances_through_dedicated_screen` (unchanged), #15 `test_tc024_issues_severity_color_round_trips`, #16 `test_tc024_issues_row_select_jumps_to_source` (all `test_tui_directionb.py`); #17 AT-037a/b (`test_tui_a2l_issue_recolor.py:198/:252`); #18 AT-036a/b/c (`test_validation_service_supplemental.py:217/:273/:316/:341`).

---

## 6. In-flight catches (process evidence — NOT escaped-to-prod bugs)

There were **zero production regressions**. These are catches the process made *before* the gate:

1. **Inc3 async double-count (test bug, fixed pre-gate).** Census #12 `test_tc024_issues_severity_filters_…`
   first ran 60/40 because a whole-DOM `query(IssueRow)`/`query(IssueGroupHeader)` between a grouped-panel
   re-render and the next `pilot.pause()` counted not-yet-removed rows. Fixed by awaiting `pilot.pause()`
   before summing `IssueGroupHeader.issue_count`; re-run green. Latent trap noted for all whole-DOM counts
   (AT-043a/b now pause after the triggering render).
2. **Inc4 census-missed white-box test (retired).** `test_populate_issues_datatable_records_filtered_index`
   directly called the now-removed `_populate_issues_datatable` — it would `AttributeError`. Not in the
   original C-14 census (18 rows); caught during Inc4, its removal is mandatory not discretionary (drove the
   `−1` ledger deviation vs the task's expected `+2`).
3. **Inc4 `_drive_panel` dedup (cap accommodation).** `TestCrossFileCompatibilityPanelRender._drive_panel`
   flooded the error group with `MAP/MAC_PARSE_ERROR` past `_GROUP_DISPLAY_MAX=40`, hiding sparse cross-codes;
   re-seeded one representative real issue per distinct code so each engine-emitted code co-renders through
   the shipped grouped surface. Honest caveat recorded (Inc4 §5): it no longer proves "all N instances render"
   (a DataTable-era property the 40-cap makes impossible) — fails loudly if distinct-code count > 40.

Also disclosed (not a defect): pre-existing **F841** (`before` unused, `test_loadfilescreen_input.py:174`,
untouched function) — left in place per surgical-changes discipline; production files ruff-clean.

---

## 7. Deferred / notes

- **23 snapshot xfails → canonical-CI regen (local FORBIDDEN).** The 20 Issues/workspace cells are batch-28
  `xfail(strict=False)` absorbing US-039 grouped-dense + this batch's `.issue-related` node drift + the
  DataTable removal (SVG-neutral: `display:none` had zero layout); plus 3 pending baselines. Local textual
  ≠ pinned 8.2.8 → no local regen. Clears when the operator regenerates in `snapshot-regen.yml` (textual 8.2.8).
- **R-043-3 precompute dead-write follow-up.** `precompute_issue_datatable_payload` (`app.py:752`) still
  worker-invoked (`app.py:6525/:7037`); its caches (`_validation_issue_cell_rows`/`_validation_issue_cell_styles`)
  are dead-written every load, never read. Named follow-up batch: retire the worker calls + caches + the
  `test_tc021_precompute_payload_emits_related_cell` / `…_emits_eight_columns_and_styles` formatter TCs that
  pin them. Left surgically in place this batch.
- **R-044-1 functional-not-source memory bound.** The post-read cap bounds all *downstream* use; each reader
  (tk/ctypes/PS) still transiently materializes the full string before the cap. Disclosed; deferred LLR-044.6.
- **R-044-6 deferred Popen bound.** True source bound via `subprocess.Popen(...).stdout.read(CAP+1)` — named,
  not built (operator's pragmatic scope).
- **AT-043-c17 — CLOSED in Inc5 (was a gap; orchestrator decision under standing auth).** The v2 spec (§3,
  folded from qa-M-1) planned a *file-derived* C-17 AT: load an A2L with multiple hostile no-whitespace `REF_*`
  entries → shipped chain emits `A2L_BROKEN_REFERENCE` carrying the literals → assert on the grouped
  `.issue-detail` node, proving the token survives the **frozen `a2l.py` lexer** end-to-end. Inc2–4 covered the
  two legs only separately (seeded render + service-level emission), never joined. **Inc5 realized the joined
  AT:** `test_at_043_c17_file_derived_hostile_ref_symbol_renders_literal` (`test_tui_a2l_issue_recolor.py:326`)
  drives `MAP_Model[bold]` + `x[link=file:///etc]` through the REAL load chain, positively guards (load-bearing)
  that both round-trip verbatim into `issue.symbol` via the frozen lexer, then asserts the rendered grouped
  `.issue-detail` plain contains both literally (brackets intact, `[link=…]` not consumed). Counterfactual
  demonstrated (a markup-parsing node consumes both). The seeded `test_at_039e_c17_…` is retained as companion.
  **The spec's C-17 strengthening is now realized on disk.** (Rationale for closing vs noting: a mandatory
  Phase-2-reviewed security control left unrealized is a Certainty-axis miss; cost was one test.)

---

## 8. Evidence checklist

- [✓] Acceptance criteria use Given/When/Then equivalent — §3 ATs are input/mechanism/observed-deliverable with counterfactuals (spec §3 is the G/W/T source).
- [✓] Test cases have explicit Expected, not vague "works" — §2/§3 tables state the exact observed predicate (e.g. `len == CAP`, `query==0`, `.issue-related == "a2l, mac"`).
- [✓] Edge cases include empty, boundary, invalid, error — empty: `test_update_validation_issues_view_empty_state`; boundary: AT-042c/d; invalid/hostile: `test_at_039e_c17_…` + TC-043-restore.1; address-None: AT-043b.
- [✓] Regression checklist exists — C-14 18-row census migrated (Inc3 #12–18, Inc4 #1/4/5/6/8/9/10) all green; engine-frozen guard pass.
- [✓] Exit criteria stated — 0 failed + every AT/TC green in the 1182-collected run; PASS-WITH-NOTES with 3 disclosed deferrals.
- [✓] No real PII / secrets — synthetic A2L/S19 fixtures + public `case_04`/`large_project`; clipboard logging is length-only (verified `os_clipboard_input.py`).
- [✓] Test results filled from the actual run, not intent — 1157 passed / 2 skipped / 23 xfailed / 0 failed (orchestrator); node ids grepped from `tests/`, not inferred from titles.
- [✓] Layer B (black-box) — every output-producing story observed through the SHIPPED surface with boundary + negative evidence: US-042 via `read_os_clipboard` return + `.value` after real `ctrl+v` (AT-042a–f); US-043 via widget tree + `.issue-related`/`#issues_hex_pane` (AT-043a/b/c, AT-021, AT-039e). C-17 file-derived leg gap disclosed §6.
- [✓] Bidirectional surface-reachability — §4: every named input dimension AND output/deliverable exercised through the handler (`ctrl+v`/`action_paste`, `on_issue_row_selected`, `update_validation_issues_view`, mounted `IssueRow.compose`), not only a service API. One split (hostile file-derived symbol) flagged §4/§6.
- [✓] No unfilled template — every `AT-`/`TC-` reconciled to a real `def test_…` node (§5) or explicitly recorded as by-inspection/unrealized; no `TC-NNN` placeholder, no empty required row.
