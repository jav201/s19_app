# Code-Wire extractor report

- Marks found: 21
- Graph nodes parsed: 54
- Real calls between marked nodes: 13
- Findings: 37 (33 drift, 4 info)
- Ambiguous call resolutions (a name matched several defs): 9
- Files that failed to parse: 0

Type normalisation: spaces and quotes dropped; `List/Dict/Tuple/Set` -> builtins; `X | None` and graph `X?` -> `Optional[X]`; graph `(Callable) A->B` -> `Callable[[A], B]`; graph `tuple(A a, B b)` -> `tuple[A, B]`. A bare graph container (`dict`) against a parameterised code type (`dict[str, Any]`) is info (loose match), not drift.

Call resolution is name-based (`f()`, `Class()` -> `__init__`, `self.m()`, `x.m()` -> top-level `m` or a marked method `m`); dynamic calls and callables passed as values are not seen. Tests excluded.

## Counts

| Kind | Count |
|---|---|
| Graph node without mark (no code yet) | 33 |
| Info: nodes replaced by a later graph (`--layered`) | 1 |
| Info: graph names the bare container only (loose match) | 3 |

## Real calls between marked nodes

| Caller | Callee | Sites |
|---|---|---|
| `A2LDetailCard.show_tag` | `_a2l_detail_card_text` | s19_app/tui/app/shared.py:625 |
| `A2lViewMixin._filter_a2l_tags` | `A2lViewMixin._tag_matches_filter` | s19_app/tui/app/a2l_view.py:1458 |
| `A2lViewMixin._refresh_a2l_dependent_views` | `A2LDetailCard.show_tag` | s19_app/tui/app/a2l_view.py:927 |
| `A2lViewMixin._refresh_a2l_dependent_views` | `A2lViewMixin.update_a2l_view` | s19_app/tui/app/a2l_view.py:913 |
| `A2lViewMixin._refresh_a2l_filtered_tags` | `A2lViewMixin._filter_a2l_tags` | s19_app/tui/app/a2l_view.py:859 |
| `A2lViewMixin._refresh_a2l_filtered_tags` | `A2lViewMixin.update_a2l_tags_view` | s19_app/tui/app/a2l_view.py:866, s19_app/tui/app/a2l_view.py:871 |
| `A2lViewMixin._schedule_a2l_filter_refresh` | `A2lViewMixin._refresh_a2l_filtered_tags` | s19_app/tui/app/a2l_view.py:1586 |
| `A2lViewMixin.update_a2l_tags_view` | `A2lViewMixin._build_a2l_table_cells` | s19_app/tui/app/a2l_view.py:1085 |
| `A2lViewMixin.update_a2l_view` | `A2lViewMixin._refresh_a2l_filtered_tags` | s19_app/tui/app/a2l_view.py:1001 |
| `A2lViewMixin.update_a2l_view` | `A2lViewMixin.update_a2l_tags_view` | s19_app/tui/app/a2l_view.py:987 |
| `NavigationMixin.on_data_table_row_highlighted` | `A2LDetailCard.show_tag` | s19_app/tui/app/navigation.py:1423 |
| `OsClipboardInput._on_paste` | `_strip_paste_controls` | s19_app/tui/os_clipboard_input.py:947, s19_app/tui/os_clipboard_input.py:953 |
| `OsClipboardInput.action_paste` | `_strip_paste_controls` | s19_app/tui/os_clipboard_input.py:1104, s19_app/tui/os_clipboard_input.py:1108 |

Top-level sites (no marked node above them):

- `A2LDetailCard.show_tag`: s19_app/tui/app/shared.py:581
- `A2lViewMixin._build_a2l_table_cells`: s19_app/tui/app/a2l_view.py:1210, s19_app/tui/app/a2l_view.py:1307
- `A2lViewMixin._jump_to_tag_by_data`: s19_app/tui/app/a2l_view.py:441
- `A2lViewMixin._refresh_a2l_filtered_tags`: s19_app/tui/app/a2l_view.py:1554
- `A2lViewMixin.update_a2l_tags_view`: s19_app/tui/app/a2l_view.py:1214, s19_app/tui/app/a2l_view.py:366, s19_app/tui/app/a2l_view.py:392, s19_app/tui/app/a2l_view.py:507
- `OsClipboardInput.action_paste`: s19_app/tui/os_clipboard_input.py:977
- `_a2l_detail_card_text`: s19_app/tui/app/shared.py:600
- `_strip_paste_controls`: s19_app/tui/capped_text_area.py:169, s19_app/tui/capped_text_area.py:238
- `parse_parameter_list`: s19_app/tui/screens.py:1019

## Graph node without mark (no code yet)

- `s19_app/tui/a2l_label_list.py` — `is_list_text`
- `s19_app/tui/a2l_label_list.py` — `display_text`
- `s19_app/tui/a2l_label_list.py` — `resolve_label_list`
- `s19_app/tui/a2l_label_list.py` — `list_summary_texts`
- `s19_app/tui/a2l_label_list.py` — `list_row_cells`
- `s19_app/tui/a2l_label_list.py` — `list_card_text`
- `s19_app/tui/a2l_label_list.py` — `LabelRanker.prepare`
- `s19_app/tui/a2l_label_list.py` — `LabelRanker._install`
- `s19_app/tui/a2l_label_list.py` — `LabelRanker.request`
- `s19_app/tui/a2l_label_list.py` — `LabelRanker._deliver`
- `s19_app/tui/a2l_label_list.py` — `LabelSuggestBox.show_ranked`
- `s19_app/tui/a2l_label_list.py` — `LabelSuggestBox.move`
- `s19_app/tui/a2l_label_list.py` — `ListAwareFilterInput._take_paste`
- `s19_app/tui/a2l_label_list.py` — `ListAwareFilterInput.action_esc`
- `s19_app/tui/a2l_label_list.py` — `ListAwareFilterInput.action_complete`
- `s19_app/tui/a2l_label_list.py` — `LabelListPasteModal.compose`
- `s19_app/tui/a2l_label_list.py` — `LabelListPasteModal.on_mount`
- `s19_app/tui/a2l_label_list.py` — `LabelListPasteModal._preview`
- `s19_app/tui/a2l_label_list.py` — `LabelListPasteModal._on_similar`
- `s19_app/tui/a2l_label_list.py` — `LabelListPasteModal.on_input_submitted`
- `s19_app/tui/a2l_label_list.py` — `LabelListPasteModal.action_apply`
- `s19_app/tui/a2l_label_list.py` — `LabelListPasteModal.action_cancel`
- `s19_app/tui/a2l_label_list.py` — `LabelListPasteModal.refresh_tags`
- `s19_app/tui/a2l_label_list.py` — `A2LExplorerBody.on_resize`
- `s19_app/tui/a2l_label_list.py` — `A2LExplorerBody.action_paste_list`
- `s19_app/tui/a2l_label_list.py` — `A2LExplorerBody.action_mode_all`
- `s19_app/tui/os_clipboard_input.py` — `OsClipboardInput._take_paste`
- `s19_app/tui/app/a2l_view.py` — `A2lViewMixin._a2l_list_names`
- `s19_app/tui/app/a2l_view.py` — `A2lViewMixin._paint_a2l_filter_chips`
- `s19_app/tui/app/a2l_view.py` — `A2lViewMixin._fit_a2l_tag_cells`
- `s19_app/tui/app/a2l_view.py` — `A2lViewMixin._repaint_a2l_tag_cells`
- `s19_app/tui/app/a2l_view.py` — `A2lViewMixin.a2l_open_label_list`
- `s19_app/tui/app/a2l_view.py` — `ListAwareDetailCard.show_tag`

## Info: nodes replaced by a later graph (`--layered`)

- `graphs` — 7 replaced by a later graph: `OsClipboardInput._on_paste`, `OsClipboardInput.action_paste`, `ComposeScreensMixin._compose_screen_a2l`, `A2lViewMixin._filter_a2l_tags`, `A2lViewMixin._refresh_a2l_filtered_tags`, `A2lViewMixin.update_a2l_tags_view`, `A2lViewMixin._schedule_a2l_filter_refresh`

## Info: graph names the bare container only (loose match)

- `s19_app/tui/app/a2l_view.py:1004` — `tags`: graph `list` vs code `list[dict]`
- `s19_app/tui/app/a2l_view.py:1443` — `tags`: graph `list` vs code `list[dict]`
- `s19_app/tui/app/a2l_view.py:1443` — output: graph `list` vs code `list[dict]`
