# Inc 7 — E1 slice: the functions to add or change

Base `2dbd7d5a`; lines "as of `2dbd7d5a`". **40 functions: 29 new, 11 changed**, in **5 source files** split into **2 file groups** (D-1; each ≤ 4 files), plus 1 stylesheet rule set. Requirement ids: `01-requirements.md`. Contracts and examples: `codewire/graph-inc7.md` (E2).

## 1. Files and groups (D-1 A)

| Group | File | State | Functions |
|---|---|---|---|
| G-L | `s19_app/tui/a2l_label_list.py` | new | 25 |
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
| L6b | `LabelRanker._install` | a2l_label_list.py | new (E2: the index hand-over on the UI thread) | .072, .074 |
| — | `styles.tcss` A2L pane rules (`:440-456`) | styles.tcss | changed | .080, .081, R-TUI-037.1/.2 (retired), R-TUI-069.6 |

Count at E1: 40 functions (29 new, 11 changed). **At E2: 42 nodes (31 new, 11 changed)** — G-L 29 (L1–L28 with L22 now `list_card_text`, plus L6b `LabelRanker._install`: 27 new, 2 changed), G-V 13 (V1–V13: 4 new, 9 changed); `codewire/graph-inc7.md` §Size, E2-1.

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

Reused, unchanged: `A2LDetailCard.show_tag` (`navigation.py:1421`, `a2l_view.py:924`, `shared.py:580`), `_a2l_detail_card_text` (`shared.py:625`), `_build_a2l_table_cells` (`a2l_view.py:1080`, `:1205`, `:1302`), `_jump_to_tag_by_data` (`navigation.py:1374`), `parse_parameter_list` (`screens.py:1019`), `build_label_index` / `rank` (no product caller yet: Inc 7 is I-3's first consumer).

## 4. Risks the slice carries

- `_fit_a2l_tag_cells` and `_repaint_a2l_tag_cells` write text-mode cells by column index (`[2]` is Tag); in list mode they must re-render the list page instead (R-A2L-LIST.036), or a resize paints `Address` text into `#`.
- `A2LDetailCard` is queried by type in `_refresh_a2l_dependent_views` (`a2l_view.py:919-925`) and `navigation.py:1418`: the list-aware card must subclass it (L22) so both keep working.
- The filter box's id `#a2l_tags_filter_input` is read by `update_a2l_view` (`:995`) and Inc 5/Inc 12 tests; the new box keeps it (V1).
