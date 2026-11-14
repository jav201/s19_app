# Inc 7 — E1 slice: the functions to add or change

Base `2dbd7d5a`; lines "as of `2dbd7d5a`" (re-mapped to `9ffe019d`, the base of E4, in §6: only `a2l_view.py:1577` moved, to `:1582`). **After E3R1: 44 functions: 33 new, 11 changed** (E1: 40, 29 new; E2: 42), in **5 source files** split into **2 file groups** (D-1; each ≤ 4 files; `app/patch.py` stays out, E3A-07), plus 1 stylesheet rule set. Requirement ids: `01-requirements.md`. Contracts and examples: `codewire/graph-inc7.md` (E2, corrected at E3R1). The existing tests E4 must retarget: §5 (E3R1).

## 1. Files and groups (D-1 A)

| Group | File | State | Functions |
|---|---|---|---|
| G-L | `s19_app/tui/a2l_label_list.py` | new | 28 (E3R1: + L29, L30) |
| G-L | `s19_app/tui/os_clipboard_input.py` | changed (I-1 hook, D-5 A) | 1 new, 2 changed |
| G-V | `s19_app/tui/app/a2l_view.py` | changed | 3 new, 8 changed |
| G-V | `s19_app/tui/app/compose_screens.py` | changed | 1 changed |
| G-V | `s19_app/tui/styles.tcss` | changed | the `#a2l_panes` / `#a2l_tags_pane` / `#a2l_hex_pane` rules (D-2 A) |

Not changed (read, reused): `a2l_parameter_picker.py` (`parse_parameter_list`, I-5), `services/label_match.py` (I-3), `app/navigation.py` (`on_input_changed` → `_schedule_a2l_filter_refresh`, `:1494-1497`; row highlight / select → `A2LDetailCard.show_tag` / `_jump_to_tag_by_data`, `:1332-1421`), `app/core.py` (mode buttons → `_refresh_a2l_filtered_tags`, `:1108-1116`), `app/shared.py` (`A2LDetailCard`, `_a2l_detail_card_text`: subclassed in G-L, not edited).

## 2. The slice

| # | Function | File | State | Requirements |
|---|---|---|---|---|
| L1 | `is_list_text` | a2l_label_list.py | new | .001, .006, .062 |
| L2 | `display_text` | a2l_label_list.py | new | .076, .077 |
| L3 | `resolve_label_list` | a2l_label_list.py | new | .002–.005 |
| L4 | `list_summary_texts` | a2l_label_list.py | new | .017, .018, .022, .024, .046, .048 |
| L5 | `list_row_cells` | a2l_label_list.py | new | .011–.015 |
| L6 | `LabelRanker.prepare` | a2l_label_list.py | new | .072, .074 |
| L7 | `LabelRanker.request` | a2l_label_list.py | new | .071, .073 |
| L8 | `LabelRanker._deliver` | a2l_label_list.py | new | .052, .071, .074 |
| L9 | `LabelSuggestBox.show_ranked` | a2l_label_list.py | new | .063–.067 |
| L10 | `LabelSuggestBox.move` | a2l_label_list.py | new | .068 |
| L11 | `ListAwareFilterInput._take_paste` | a2l_label_list.py | new | .033, .034 |
| L12 | `ListAwareFilterInput.action_esc` | a2l_label_list.py | new | .032, .070 |
| L13 | `ListAwareFilterInput.action_complete` | a2l_label_list.py | new | .069 |
| L14 | `LabelListPasteModal.compose` | a2l_label_list.py | new | .043, .044, .045 |
| L15 | `LabelListPasteModal.on_mount` | a2l_label_list.py | new | .041, .042 |
| L16 | `LabelListPasteModal._preview` | a2l_label_list.py | new | .046, .047, .048, .051, .059 |
| L17 | `LabelListPasteModal._on_similar` | a2l_label_list.py | new | .049, .050, .052 |
| L18 | `LabelListPasteModal.on_input_submitted` | a2l_label_list.py | new | .057, .058 |
| L19 | `LabelListPasteModal.action_apply` | a2l_label_list.py | new | .053, .054 |
| L20 | `LabelListPasteModal.action_cancel` | a2l_label_list.py | new | .055, .070 |
| L21 | `LabelListPasteModal.refresh_tags` | a2l_label_list.py | new | .056 |
| L22 | `list_card_text` | a2l_label_list.py | new (E2: the card subclass moved to G-V as V13; see `codewire/graph-inc7.md` E2-1) | .027–.030 |
| L23 | `A2LExplorerBody.on_resize` | a2l_label_list.py | new | .047, .080, .081, R-TUI-069.6 |
| L24 | `A2LExplorerBody.action_paste_list` | a2l_label_list.py | new | .040 |
| L25 | `A2LExplorerBody.action_mode_all` | a2l_label_list.py | new | .026 |
| L26 | `OsClipboardInput._take_paste` | os_clipboard_input.py | new | R-PASTE.1, R-TUI-043.4, R-PASTE.29 |
| L27 | `OsClipboardInput._on_paste` | os_clipboard_input.py:926 | changed | R-PASTE.1, .033 |
| L28 | `OsClipboardInput.action_paste` | os_clipboard_input.py:1038 | changed | R-TUI-043.4, R-PASTE.29, .033 |
| V1 | `ComposeScreensMixin._compose_screen_a2l` | compose_screens.py:629 | changed | .007, .008, .010, .040, .080, .081 |
| V2 | `A2lViewMixin._a2l_list_names` | a2l_view.py | new | .006, R-A2L-007.2 |
| V3 | `A2lViewMixin._filter_a2l_tags` | a2l_view.py:1437 | changed | .005, .006, R-A2L-007.1, .6, .7, .8 |
| V4 | `A2lViewMixin._refresh_a2l_filtered_tags` | a2l_view.py:827 | changed | .025, .019 |
| V5 | `A2lViewMixin._paint_a2l_filter_chips` | a2l_view.py | new | .007, .008, .017–.023 |
| V6 | `A2lViewMixin.update_a2l_tags_view` | a2l_view.py:1000 | changed | .009, .014, .016, R-TUI-042a.4 |
| V7 | `A2lViewMixin._fit_a2l_tag_cells` | a2l_view.py:1163 | changed | .036 |
| V8 | `A2lViewMixin._repaint_a2l_tag_cells` | a2l_view.py:1246 | changed | .036 |
| V9 | `A2lViewMixin.update_a2l_view` | a2l_view.py:938 | changed | .072 |
| V10 | `A2lViewMixin._schedule_a2l_filter_refresh` | a2l_view.py:1548 | changed | .060, .062, .074 |
| V11 | `A2lViewMixin.a2l_open_label_list` | a2l_view.py | new | .040, .041, .053, .054 |
| V12 | `A2lViewMixin._refresh_a2l_dependent_views` | a2l_view.py:871 | changed | .056 |
| V13 | `ListAwareDetailCard.show_tag` | a2l_view.py | new (E2; subclass of `A2LDetailCard`, `shared.py:540`; in G-V because `a2l_label_list.py` may not import `s19_app.tui.app`) | .027–.030 |
| L6b | `LabelRanker._install` | a2l_label_list.py | new (E2: the index hand-over on the UI thread) | .072, .074, .084 |
| L29 | `ListAwareFilterInput.action_move_choice` | a2l_label_list.py | new (E3R1, E3A-03 (a): the ↑/↓ bindings) | .068 |
| L30 | `LabelRanker._work` | a2l_label_list.py | new (E3R1, E3A-05: the one worker body; errors and teardown) | .084, .085, .072, .073 |
| — | `styles.tcss` A2L pane rules (`:440-456`) | styles.tcss | changed | .080, .081, .082, .083, R-TUI-037.1/.2 (changed: the short body), R-TUI-069.6, R-TUI-069.7 |

E3R1 also re-pointed these rows' functions (`codewire/graph-inc7.md`, lines tagged E3R1): L2 + .019/.025/.066 (short text), L3 + .036 (rows), L7/L8 + .075/.085 (keyed, coalesced, guarded), L9 + .077, L11 + .033/4, L16 + .078/.086/.075, L23 + .082/.083/R-TUI-037.1/.2, L26–L28 (I-1 placement), V2 + .008, V4/V8 + .036 (in place), V9 + .008/.023, V10 + .085, V13 + .085/.036.

Count at E1: 40 functions (29 new, 11 changed). At E2: 42 nodes (31 new, 11 changed) — G-L 29 (L1–L28 with L22 now `list_card_text`, plus L6b `LabelRanker._install`: 27 new, 2 changed), G-V 13 (V1–V13: 4 new, 9 changed); `codewire/graph-inc7.md` §Size, E2-1. **After E3R1: 44 nodes (33 new, 11 changed)** — G-L 31 (+ L29, L30), G-V 13.

## 3. Real callers of every changed function (Code-Wire extractor, baseline)

Extractor: `C:\Users\<user>\Github\code-wire` at **`v3.1.0-8-gb6cd30d`** (`git describe --tags`), core only. Run: marks `# node: <name>` on 21 baseline defs in a throwaway copy (`git archive 2dbd7d5a s19_app` outside the worktree, deleted after), graph `codewire/baseline-extract.md`, `python -I -B tools/codewire_extract.py --repo <copy> --graph baseline-extract.md --out extractor-baseline` → `marks=21 graph_nodes=21 calls=13 findings=0 parse_failures=0` (`codewire/extractor-baseline/diff-report.md`; its line numbers are in the marked copy, so each is shifted by the marks above it in the same file; the base lines below are from `git grep` on `2dbd7d5a`).

| Changed function | Real callers at `2dbd7d5a` |
|---|---|
| `_refresh_a2l_filtered_tags` | `update_a2l_view` `a2l_view.py:997`; `_set_a2l_filter_field` `:1546`; the debounce closure of `_schedule_a2l_filter_refresh` `:1577`; mode buttons `core.py:1110`, `:1113`, `:1116`; the write route `patch.py:1847` (`preserve_anchor=True`) |
| `_filter_a2l_tags` | `_refresh_a2l_filtered_tags` `a2l_view.py:857` (only caller) |
| `update_a2l_tags_view` | paging `a2l_view.py:366`, `:392`; find `:506`; `_refresh_a2l_filtered_tags` `:864`, `:869`; `update_a2l_view` `:983`; `_fit_a2l_tag_cells` `:1209`; page-size setting `navigation.py:1483` |
| `_fit_a2l_tag_cells` | `update_a2l_tags_view` (`call_after_refresh`) `a2l_view.py:1104`; `on_a2l_tag_table_measured` `:1244` |
| `_repaint_a2l_tag_cells` | the write route `patch.py:1851` |
| `update_a2l_view` | `_refresh_a2l_dependent_views` `a2l_view.py:910` (only static caller; the common refresh of Inc 5) |
| `_refresh_a2l_dependent_views` | `file_load.py:887`, `loaded_state.py:418`, `:827`, `project_load.py:1653` (the four A2L transition routes) |
| `_schedule_a2l_filter_refresh` | `NavigationMixin.on_input_changed` `navigation.py:1497` (only caller) |
| `_compose_screen_a2l` | `S19TuiApp.compose` `core.py:552` |
| `OsClipboardInput._on_paste` | Textual's paste dispatch (no static caller); every `OsClipboardInput` box |
| `OsClipboardInput.action_paste` | the `ctrl+v` binding; the right-click route `os_clipboard_input.py:975`; `CappedTextArea` has its own (`capped_text_area.py:329`, not changed) |

**E3R1 re-run** (code-wire `v3.1.0-8-gb6cd30d`, the 11 existing functions whose contract E3R1 changes or reuses, `codewire/e3r1-extract.md`; marks by `codewire_marks.py` in a throwaway clone of `1d47d12f` on <runner>; `codewire/extractor-e3r1/run.txt`: `marks=11 graph_nodes=11 calls=5 findings=0 parse_failures=1`, exit 1 for the one parse failure, `tools/mutation_harness.py`, outside the slice). The extractor's own sites, with their enclosing function named by `codewire/e3r1-callers.py` (`codewire/extractor-e3r1/callers.txt`), agree with the table above for `_filter_a2l_tags`, `update_a2l_view`, `update_a2l_tags_view` (a2l_view.py sites) and `action_paste` (`:975`, `OsClipboardInput._on_mouse_down`). It saw **no** site in `core.py` (`:552`, `:1110`, `:1113`, `:1116`), `patch.py` (`:1847`, `:1851` in `PatchMixin._refresh_a2l_values_after_write`) or `navigation.py` (`:1374`, `:1483`, `:1497`): its name-based resolution reports 35 ambiguous names. `git grep` on `2dbd7d5a` supplies them; the callers that matter to E3R1:

| Changed contract (E3R1) | Callers it must keep working (file:line at `2dbd7d5a`) |
|---|---|
| `_refresh_a2l_filtered_tags` list mode with `preserve_anchor=True` (E3A-07) | only `PatchMixin._refresh_a2l_values_after_write` `patch.py:1847` passes `True`; `update_a2l_view` `a2l_view.py:997`, `_set_a2l_filter_field` `:1546`, the debounce `_apply_filter` `:1577`, the mode buttons `core.py:1110`, `:1113`, `:1116` pass `False` (unchanged path) |
| `_repaint_a2l_tag_cells` list mode in place (E3A-07) | `PatchMixin._refresh_a2l_values_after_write` `patch.py:1851` (only caller) |
| `update_a2l_view` absent branch clears the resolution (E3A-08) | `_refresh_a2l_dependent_views` `a2l_view.py:910` (the four A2L transition routes above) |
| `update_a2l_tags_view` maps `a2l:<i>` → `resolution.rows[i]` (E3A-02) | paging `:366`, `:392`; find `:506` (`_focus_a2l_tag_absolute_index`); `_refresh_a2l_filtered_tags` `:864`, `:869`; `update_a2l_view` `:983`; `_fit_a2l_tag_cells` `:1209`; page size `navigation.py:1483` |
| `ListAwareDetailCard.show_tag` finds the entry (E3A-02) | `NavigationMixin.on_data_table_row_highlighted` `navigation.py:1421` (passes the row dict); `_refresh_a2l_dependent_views` `a2l_view.py:924` (`None`); `A2LDetailCard.on_mount` `shared.py:580` (`None`) |
| `_jump_to_tag_by_data` on a missing row (E3A-13, unchanged code) | `A2lViewMixin._jump_to_tag` `a2l_view.py:441`; `NavigationMixin.on_data_table_row_selected` `navigation.py:1374` |
| `OsClipboardInput._on_paste` / `.action_paste` (I-1 placement, E3S-03) | Textual's paste dispatch (no static caller); `OsClipboardInput._on_mouse_down` `os_clipboard_input.py:975`; `CappedTextArea` has its own `action_paste` (`capped_text_area.py:329`, unchanged) |
| `_compose_screen_a2l` (I-7 constructors) | `S19TuiApp.compose` `core.py:552` |
| `_schedule_a2l_filter_refresh` (keyed request, held widget) | `NavigationMixin.on_input_changed` `navigation.py:1497` |

Reused, unchanged: `A2LDetailCard.show_tag` (`navigation.py:1421`, `a2l_view.py:924`, `shared.py:580`), `_a2l_detail_card_text` (`shared.py:625`), `_build_a2l_table_cells` (`a2l_view.py:1080`, `:1205`, `:1302`), `_jump_to_tag_by_data` (`navigation.py:1374`), `parse_parameter_list` (`screens.py:1019`), `build_label_index` / `rank` (no product caller yet: Inc 7 is I-3's first consumer).

## 4. Risks the slice carries

- `_fit_a2l_tag_cells` and `_repaint_a2l_tag_cells` write text-mode cells by column index (`[2]` is Tag); in list mode they must re-render the list page instead (R-A2L-LIST.036), or a resize paints `Address` text into `#`.
- `A2LDetailCard` is queried by type in `_refresh_a2l_dependent_views` (`a2l_view.py:919-925`) and `navigation.py:1418`: the list-aware card must subclass it (L22) so both keep working.
- The filter box's id `#a2l_tags_filter_input` is read by `update_a2l_view` (`:995`) and Inc 5/Inc 12 tests; the new box keeps it (V1). It is also Box A of the Inc 1a/1b clipboard suite: §5 (E3R1, E3A-01).

## 5. E4 retarget list (E3R1: E3A-01, E3A-09, E3A-11)

**Relevo-11:** the lines below are as of `2dbd7d5a`; on `9ffe019d` the moved ones, the P-002 test and one wrong premise (F-R11-1) are in §6.3.

**Owner and order (E3-rulings E3A-01, DF-10).** These are Inc 7's E4 edits, because Inc 7 changes R-PASTE.1, R-TUI-043.4 and R-PASTE.29 and the layout rows. Inc 7's E4 starts only after `b103-inc1b` is final (its WinCI rounds closed, PENDING P-001 / P-002) and builds on that final tree; no two writers touch the Inc 1a/1b test files at the same time. The WinCI re-run at Inc 7 E5 (D-5 ruling) covers Box A on Windows, and its FAILED set is compared with Inc 1b's last run **after** this retarget, not before. Snapshots are never regenerated locally (HT-09).

### 5.1 Box A of the clipboard suite (E3A-01, HIGH): the 13 nodes that go RED (E3 Probe B, Linux)

Box A moves from `#a2l_tags_filter_input` (now a `ListAwareFilterInput`, which takes a list text) to `#a2l_tag_find_input` (a stock `OsClipboardInput` of the same screen, no `restrict`, `compose_screens.py:679-681`): in both `_box_a` helpers (`tests/test_b103_clipboard_core.py:92`, `tests/test_b103_clipboard_windows.py:97`; E3R2, E3A-R2: not `tests/support/b103_clipboard.py`, which does not name the box), the matrix (`tests/test_b103_clipboard_matrix.py:54`, `:210`), TC-B102-01's box map (`tests/test_b102_clipboard.py:86`, `"a2l_tags_filter_input": "a2l"`) and the WinCI manifest (`tests/support/b103_winci_manifest.json`) — every Inc 1a/1b clipboard test that names the box, not only the 13 that fail. Inline `query_one("#a2l_tags_filter_input")` sites (`git grep` at `e5bf4432`): `test_b103_clipboard_core.py` 34 (Linux-run), `test_b103_clipboard_tail.py:463`, `:2303`, `test_b103_copy_paste_matrix.py:298`, and the **WinCI-only** sites of `tests/test_b103_clipboard_windows.py`, which no Linux run can show failing: `:99`, `:294`, `:366`, `:1055`, `:1095`, `:1250`, `:1287`, `:1550`, `:2072`, `:2105`, `:2138`, `:2183`, `:2220`, `:2498` (14; the re-review counted the first 10).

| # | Node | Row it cites (changed by Inc 7) | New expectation |
|---|---|---|---|
| 1 | `tests/test_b103_clipboard_core.py::test_r_paste_1_1_terminal_paste_single_line_takes_first_line` | R-PASTE.1 | Box A = `#a2l_tag_find_input`; first line `L1`, unchanged |
| 2 | `…core.py::test_r_paste_1_2_terminal_paste_first_line_non_codepage` | R-PASTE.1 | the same box; `Ñoño Ж 漢字 😀` |
| 3 | `…core.py::test_r_paste_34_1_terminal_paste_single_line_strips_unsafe` | R-PASTE.1 (with R-PASTE.34) | the same box; `L1[2J` |
| 4 | `…core.py::test_r_paste_34_3_app_clipboard_fallback_single_line_strips` | R-TUI-043.4 (with R-PASTE.34) | the same box; `L1[2J` |
| 5 | `…core.py::test_r_paste_34_4_right_click_paste_single_line_strips` | R-PASTE.29 (with R-PASTE.34) | the same box; `L1[2J` |
| 6 | `…core.py::test_r_tui_044_1_18_every_single_line_box_is_os_clipboard_input` | R-PASTE.1, R-TUI-043.4, R-PASTE.29 (the census of the boxes they cover) | count by `isinstance(box, OsClipboardInput)`, or list `ListAwareFilterInput` as an `OsClipboardInput` kind: 40 boxes |
| 7 | `…core.py::test_r_paste_19_1_and_33_1_every_text_box_is_the_two_classes` | R-PASTE.1 (as 6) | as 6 |
| 8 | `tests/test_b103_clipboard_matrix.py::test_r_tui_044_1_walk_single_line_round_trip[a2l]` | R-PASTE.1, R-TUI-043.4 | the `a2l` cell on `#a2l_tag_find_input` |
| 9 | `tests/test_b103_copy_paste_matrix.py::test_copy_paste_acceptance_cell[AT-I1b-1/1-T1-P1]` | R-PASTE.1 (`P1` is one line with spaces: a list text) | the cell's paste target = `#a2l_tag_find_input`; `W1-COPY-1 Ñoño Ж 漢字 😀` |
| 10 | `…[AT-I1b-2/1-T1-P1]` | R-PASTE.1 | as 9 |
| 11 | `…[AT-I1b-3/1-T1-P1]` | R-PASTE.1 | as 9 |
| 12 | `…[AT-I1b-6/1-T1-P1]` | R-PASTE.1 | as 9 |
| 13 | `…[AT-I1b-7/1-T1-P1]` | R-PASTE.1 | as 9 |

The filter box itself gets Inc 7's own cases: a one-name paste still follows R-PASTE (R-PASTE.1/3, R-TUI-043.4/3, R-PASTE.29/3 with `P_CTRL`) and a list paste follows R-A2L-LIST.033 (/1–/3), one per route (`02-test-cases-L.md`).

### 5.2 The session census (E3A-09)

| Node | Row | New expectation |
|---|---|---|
| `tests/test_b100_session_reset.py` TC-B100-09 (`SNAPSHOT_EXCLUSIONS`, `:111`; the census `:324-336`) | — (the census of app attributes; Inc 7 adds two) | `SNAPSHOT_EXCLUSIONS["_a2l_label_ranker"] = "one worker host per app; not session state (Inc 7)"`, `["_a2l_list_resolution"] = "derived from the filter text and the enriched tags at every refresh (Inc 7)"` (a G-T-V test edit; no product file; sound with E3A-08's reset) |

### 5.3 Layout tests and snapshots (E3A-10, E3A-11)

| Node | Row | New expectation |
|---|---|---|
| `tests/test_tui_directionb.py:1373` `test_tc019_a2l_hex_pane_three_sevenths_at_wide_sizes` (120×30, 160×40) | R-TUI-037.1/.2 (changed: the short body) | re-run, unchanged: both sizes are short bodies (P3: 96×15, 136×25) |
| `:1415` `test_tc019_a2l_hex_pane_three_sevenths_at_min_size` (80×24) | R-TUI-037.1/.2 | re-run, unchanged (short body 74×9) |
| `:1451` `test_tc019_a2l_pane_order_table_then_hex` (120×30) | R-TUI-037.1/.2 | re-run, unchanged (tags pane left of the hex pane in the short body) |
| `:1607` `test_tc020_a2l_renderers_populate_through_restyled_screen`, `:1647` `test_tc020_a2l_filtering_narrows_through_restyled_screen` | R-A2L-007.1 (text mode) | re-run; expected unaffected |
| the six `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-{comfortable,compact}-{80x24,120x30,160x40}].svg` | R-TUI-037.1/.2 (split kept), R-A2L-LIST.007/.008 (mode tag), .019–.021 (chips lines), .040 (the button) | the split is the same, the filter row and the chips change: **regenerated only by the canonical CI**, with the batch-47 `xfail(strict=False)` bridge (`tests/test_tui_snapshot.py:604-640`) on these six until it does (HT-09) |
| `tests/test_b103_inc12_tag_table.py` (R-TUI-042a.5 at 80–118) | R-TUI-042a.4/.5 | re-derived from the measured width (the table is wider at 118×54, a stacked body; unchanged at 80, a short body); never typed |

## 6. Prep onto b103-base2 (relevo-11)

**Base.** `b103-inc7` was rebased onto `b103-base2` tip `9ffe019d` (= a95d0ea9 batch-modular + the `patch_editor` split + Inc 1b final + the P-002 guard): `git rebase --onto 9ffe019d 2dbd7d5a b103-inc7`, 9 record-only commits, no conflict. `git diff 9ffe019d..HEAD --stat -- s19_app tests` is empty. Evidence (read only: `ast` and `git archive` into a scratch folder outside every work tree, nothing from `s19_app` imported): `evidence-remap/i7-remap-census.py` + `i7-remap-census-transcript.txt`; on the runner (`~/work/zq-p7/`, isolated env, `HOME` basename `runner_iso`, `timeout 300`, load 2.4): a `pytest --collect-only` of the four clipboard files + the teardown test (154 nodes collected, `s19_app` imported from the archive, `evidence-remap/i7-remap-collect.txt`); `i7-remap-trace_check.txt`. No Code-Wire extractor re-run: the only changed body is V10 (below), and the graph's callers were extracted at `2dbd7d5a` (§3).

### 6.1 Re-map: what 2dbd7d5a -> 9ffe019d changed for Inc 7

`2dbd7d5a` is already the modular tree (`app/*.py` mixins, `app/a2l_view.py`, `app/compose_screens.py`); the slice and graph never cited the monolithic `app.py` or `patch_editor.py` (Inc 7 touches neither). Files whose bytes differ: **one source file**, `s19_app/tui/app/a2l_view.py` (+5 lines), the `patch_editor` split (9 files, not read by Inc 7) and 15 test files (§6.3).

| Item | Result |
|---|---|
| Graph nodes | 44 (33 new, 11 changed), as at E3R2. **33 new:** 28 in `a2l_label_list.py` (the module is absent at both bases; L1–L25, L6b, L29, L30), `OsClipboardInput._take_paste` (class at `os_clipboard_input.py:849-1112`), V2, V5, V11, V13 (`A2lViewMixin` at `a2l_view.py:239-1584`; V13 `ListAwareDetailCard` is a new module-level class in the same file). No new name clashes with an existing one at either base. |
| 11 changed nodes at 9ffe019d | `OsClipboardInput._on_paste` `os_clipboard_input.py:926-951`, `.action_paste` `:1038-1112`; `ComposeScreensMixin._compose_screen_a2l` `compose_screens.py:629-742`; `A2lViewMixin`: `_refresh_a2l_filtered_tags` `a2l_view.py:827-869`, `_refresh_a2l_dependent_views` `:871-936`, `update_a2l_view` `:938-998`, `update_a2l_tags_view` `:1000-1113`, `_fit_a2l_tag_cells` `:1163-1217`, `_repaint_a2l_tag_cells` `:1246-1333`, `_filter_a2l_tags` `:1437-1454`, `_schedule_a2l_filter_refresh` `:1548-1584` |
| **DIFF (body differs between the bases)** | **One: `A2lViewMixin._schedule_a2l_filter_refresh`** (V10), +5 lines: the docstring bullet "Drop the refresh when it comes due after the app stopped running (Inc 1b E5, R-COPY.26)" and, in the closure `_apply_filter`, `if not self.is_running: return` after the token check (`a2l_view.py:1580-1581`; the closure's last line `:1577` -> `:1582`). The other 10 changed nodes have the same AST (docstring included) at both bases; only lines after `:1560` moved, by +3 / +5, and no other function sits there. |
| Citations | 237 `file:line` citations of the Inc 7 records that name a file under `s19_app/` or `tests/` (the Base cells of `01-requirements.md` included; the script lists the 83 in changed files): 154 are in files whose bytes did not change; the other 83 map by their enclosing def to a line with the same text. 13 moved: 2 source citations (`a2l_view.py:1577` -> `:1582`, E1-slice §3, the `_apply_filter` closure) and 11 test-site citations (§6.3). The Base cells need no change (their behaviours are on both bases); `01-requirements.md` §"Deferred work after teardown" now says the P-002 guard **is** on the base (edited). |
| `compose_screens.py` | `#a2l_tag_find_input` is still `OsClipboardInput(placeholder="Find in tag table", id="a2l_tag_find_input")` at `:679-681`, no `restrict`: the Box A target of §5.1 holds. |

### 6.2 Constraint the P-002 guard adds to V10

`tests/test_b103_a2l_filter_teardown.py` (new, Inc 1b: `test_r_copy_26_1_filter_refresh_due_after_teardown_is_dropped`) names `#a2l_tags_filter_input` (`:4`, `:51`) and captures the debounce callback by `getattr(callback, "__name__", "") == "_apply_filter"` through a spy on `app.set_timer`, expects exactly one call per input change, runs it live (`No A2L tags match 'KEEP'.`) and again after the app closed (no exception). V10 therefore keeps the closure named `_apply_filter`, keeps one `set_timer(0.15, _apply_filter)` per change, keeps the `is_running` guard before everything V10 adds (the `"filter"` ranking request included), and the live run with `KEEP` (one name: text mode) must still end in the R-A2L-007 summary. No edit to that test; it joins the E4 re-run set.

### 6.3 §5 retarget list re-checked on 9ffe019d

**§5.1: exact.** All 13 nodes exist on 9ffe019d (collect-only, 154 nodes: core 7 + matrix `[a2l]` 1 + the five `AT-I1b-{1,2,3,6,7}/1-T1-P1` cells; `i7-remap-collect.txt`), none changed in body. The `core` and `matrix` files are byte-identical to 2dbd7d5a; `test_b103_clipboard_windows.py` (+4 lines after `:1715`), `test_b103_clipboard_tail.py` (+461) and `test_b103_copy_paste_matrix.py` (+19) differ, and their Box A sites moved:

| Site (E3A-01) | at 2dbd7d5a | at 9ffe019d |
|---|---|---|
| `_box_a` helpers | core `:92` (query `:100`); windows `:97` (query `:99`) | same |
| matrix box map, TC-B102-01 map | `test_b103_clipboard_matrix.py:54`, `:210`; `test_b102_clipboard.py:86` | same |
| `test_b103_clipboard_tail.py` | `:463` (`_show_box`), `:2303` (`_unrelated_view_box_observation.drive`) | **`:472`**, **`:2702`** |
| `test_b103_copy_paste_matrix.py` | `:298` (`_prepare_target`) | **`:317`** |
| windows inline, WinCI-only (14) | `:99 :294 :366 :1055 :1095 :1250 :1287 :1550` | same |
| | `:2072 :2105 :2138 :2183 :2220 :2498` | **`:2076 :2109 :2142 :2187 :2224 :2502`** |
| core inline (Linux-run) | 34 + the helper | same (35 hits in the file) |
| WinCI manifest `b103_winci_manifest.json` | listed by E3A-01 | **names no box id** (the cell `a2l` only, `"ids": ["workspace","a2l",...]`): no manifest edit is owed; its counts (260 / 216) change only if E4 adds or removes nodes of the six clipboard families, and Inc 7's new test files are not in them |

New site, no edit: the teardown test above (65 inline `#a2l_tags_filter_input` hits in `tests/` now, 63 at 2dbd7d5a). Other tests that set the box by `.value` (`test_b103_a2l_refresh.py:665,725`, `test_b102_a2l_refresh.py:207`, `test_b101_inplace_views.py:588`, `test_b103_copy_quit_dialog.py:579`) use one-name texts (`"  Alpha  "`, `"  32  "`, `Missing`, `[red]`, `225`) and stay in text mode: re-run only.

**§5.2 (E3A-09): exact.** `tests/test_b100_session_reset.py` (unchanged): `SNAPSHOT_EXCLUSIONS` `:111`, the census assertions `:324-336`.

**§5.3 (E3A-11): one finding.**
- **F-R11-1 (MINOR, wrong premise).** The "batch-47 `xfail(strict=False)` bridge (`tests/test_tui_snapshot.py:604-640`)" is **retired**: `_batch47_a2l_drift_marks` (`:616-640`) returns `()` before any mark ("RETIRED (batch-47 regen PR)"), as does the latest one, `_batch94_inc001_drift_marks` (`:1055-1075`). There is no live bridge to reuse. The rule that applies is §5.3's own (the six `a2l-*` cells are regenerated only by the canonical CI, HT-09): E4 adds a **live** `_batch103_inc7_a2l_drift_marks(screen, density, size_key)` (`xfail(strict=False)`, `screen == "a2l"` only, reason citing R-A2L-LIST.007/.008/.019–.021/.040 and "canonical-CI regen pending", with a retirement note, since a stale mark XPASSes silently) and appends it to the `marks=` sum of `_RESTYLED_CELLS` (`:1100-1115`). That puts `tests/test_tui_snapshot.py` in the E4 retarget set (G-T-R3).
- The remaining items exist unchanged at the same lines (`test_tui_directionb.py` `:1373 :1415 :1451 :1607 :1647`, the six `test_tc016s_density_layout_snapshot[a2l-…]` SVGs, `test_b103_inc12_tag_table.py`): re-run only.

### 6.4 E4 groups (Inc 1b is final and merged into the base, so no other writer holds these files)

Implementation: 5 source files plus the stylesheet; each group at most 3 files (cap 4); `app/patch.py` stays out (E3A-07). The unit of one DeepSeek call is at most 6 functions and one file (MD-03): units of one file run in order, units of different files may run in parallel.

| Group | Files | Units (functions, slice ids) |
|---|---|---|
| **G-L** (31 nodes: 28 new in the module, 1 new + 2 changed in the hook) | `s19_app/tui/a2l_label_list.py` (new), `s19_app/tui/os_clipboard_input.py` (2 files) | **U-L1** `is_list_text`, `display_text`, `resolve_label_list`, `list_summary_texts`, `list_row_cells`, `list_card_text` (L1–L5, L22; with the constants and the `LabelListEntry` / `LabelListResolution` dataclasses). **U-L2** `LabelRanker.prepare`, `._install`, `.request`, `._deliver`, `._work` (L6, L6b, L7, L8, L30). **U-L3** `LabelSuggestBox.show_ranked`, `.move`; `ListAwareFilterInput._take_paste`, `.action_esc`, `.action_complete`, `.action_move_choice` (L9–L13, L29). **U-L4** `LabelListPasteModal.compose`, `.on_mount`, `._preview`, `._on_similar`, `.on_input_submitted`, `.action_apply` (L14–L19). **U-L5** `LabelListPasteModal.action_cancel`, `.refresh_tags`; `A2LExplorerBody.on_resize`, `.action_paste_list`, `.action_mode_all` (L20, L21, L23–L25). **U-L6** (other file, parallel with U-L1…U-L5) `OsClipboardInput._take_paste` (new), `._on_paste` (`:926-951`), `.action_paste` (`:1038-1112`) (L26–L28) |
| **G-V** (13 nodes: 4 new + 9 changed) | `s19_app/tui/app/a2l_view.py`, `s19_app/tui/app/compose_screens.py`, `s19_app/tui/styles.tcss` (3 files) | **U-V1** `_a2l_list_names` (V2, new), `_filter_a2l_tags` (V3, `:1437-1454`), `_refresh_a2l_filtered_tags` (V4, `:827-869`), `_paint_a2l_filter_chips` (V5, new). **U-V2** `update_a2l_tags_view` (V6, `:1000-1113`), `_fit_a2l_tag_cells` (V7, `:1163-1217`), `_repaint_a2l_tag_cells` (V8, `:1246-1333`), `update_a2l_view` (V9, `:938-998`). **U-V3** `_schedule_a2l_filter_refresh` (V10, `:1548-1584`, the guard of §6.2 kept), `a2l_open_label_list` (V11, new), `_refresh_a2l_dependent_views` (V12, `:871-936`), `ListAwareDetailCard.show_tag` (V13, new). **U-V4** (files 2 and 3, parallel with U-V1…U-V3) `_compose_screen_a2l` (V1, `compose_screens.py:629-742`) and the `#a2l_panes` / `#a2l_tags_pane` / `#a2l_hex_pane` rules of `styles.tcss` |

G-V needs G-L's module to run its examples; U-V4 and U-L6 depend on nothing else. Order inside E4: G-L and G-V in parallel against the pinned I-7, then the integrator (§1).

Tests (not capped; counted from the case files: L 105, V 116, AT 10 = 231; the graph's "103" for L is the E1 figure):

| Group | Files | Covers |
|---|---|---|
| **G-T-L** | `tests/test_b103_label_list.py` (new; R-A2L-LIST.078/3 `serial_timing`) | `02-test-cases-L.md` (105 cases), I-7 checks |
| **G-T-V** | `tests/test_b103_a2l_list_view.py` (new; R-A2L-LIST.035 `serial_timing`) | `02-test-cases-V.md` (116 cases) |
| **G-T-AT** | `tests/test_b103_a2l_list_at.py` (new) | `02-test-cases-AT.md` (10 cases) |
| **G-T-R1** (retarget, clipboard core) | `tests/test_b103_clipboard_core.py` (`_box_a` + 34 inline sites; rows 1-7), `tests/test_b103_clipboard_windows.py` (`_box_a` + 14 WinCI-only sites) | §5.1 rows 1-7 and the windows sites; Box A -> `#a2l_tag_find_input`; the census rows 6, 7 by `isinstance` |
| **G-T-R2** (retarget, matrix) | `tests/test_b103_clipboard_matrix.py` (`:54`, `:210`; row 8), `tests/test_b103_copy_paste_matrix.py` (`:317`; rows 9-13), `tests/test_b103_clipboard_tail.py` (`:472`, `:2702`), `tests/test_b102_clipboard.py` (`:86`, docstring `:9`) | §5.1 rows 8-13, the tail and TC-B102-01 box maps |
| **G-T-R3** (census, layout) | `tests/test_b100_session_reset.py` (`:111`), `tests/test_tui_snapshot.py` (F-R11-1: the new live mark, `:1100-1115`) | §5.2, §5.3 |
| re-run only | `tests/test_tui_directionb.py` (5 nodes), `tests/test_b103_inc12_tag_table.py`, `tests/test_b103_a2l_filter_teardown.py`, the one-name filter tests of §6.3 | no edit |

R-PASTE.1/3, R-TUI-043.4/3, R-PASTE.29/3 and R-A2L-LIST.033 (/1–/3) on the filter box are Inc 7's own cases (G-T-L / G-T-V), not retargets.

### 6.5 trace_check on 9ffe019d

`python trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-7/01-requirements.md --base 9ffe019d --src s19_app`:
`trace_check: 4 US, 96 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 93 gap(s)` = 92 TEST (rows no test names before E4) + 1 EVID (no `04-validation.md` before E5); US 0, CASE 0, SLICE 0. Identical to E3R2's run (`evidence-e1/trace_check-e3r2.txt`, base 2dbd7d5a). Output: `evidence-remap/i7-remap-trace_check.txt`.
