# Inc 7 baseline extractor graph (E1/E2; generated from the signatures at 2dbd7d5a)

Each node is an existing function the increment reuses or changes; `func:` says baseline. Marks sat only in a
throwaway copy outside the worktree. Run: `codewire_extract.py --repo <copy> --graph baseline-extract.md --out extractor-baseline`.

## Nodes

parse_parameter_list
req: R-A2L-LIST.001
in: str text
out: list result
module: s19_app/tui/a2l_parameter_picker.py
func: baseline (unchanged at s19_app/tui/a2l_parameter_picker.py:70 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

_strip_paste_controls
req: R-A2L-LIST.034
in: str text; bool multiline
out: str result
module: s19_app/tui/os_clipboard_input.py
func: baseline (unchanged at s19_app/tui/os_clipboard_input.py:506 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

OsClipboardInput._on_paste
req: R-A2L-LIST.033
in: events.Paste event
out: None
module: s19_app/tui/os_clipboard_input.py
func: baseline (unchanged at s19_app/tui/os_clipboard_input.py:928 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

OsClipboardInput.action_paste
req: R-A2L-LIST.033
in: (none)
out: None
module: s19_app/tui/os_clipboard_input.py
func: baseline (unchanged at s19_app/tui/os_clipboard_input.py:1041 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin._jump_to_tag_by_data
req: R-A2L-LIST.031
in: dict tag
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:444 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin._refresh_a2l_filtered_tags
req: R-A2L-LIST.006
in: bool preserve_anchor
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:829 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin._refresh_a2l_dependent_views
req: R-A2L-LIST.056
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:874 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin.update_a2l_view
req: R-A2L-LIST.072
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:942 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin.update_a2l_tags_view
req: R-A2L-LIST.009
in: list[dict] tags; Optional[str] empty_message = None
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:1005 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin._build_a2l_table_cells
req: R-A2L-LIST.014
in: dict tag; Optional[int] name_width = None
out: tuple[Text, ...] result
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:1341 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin._filter_a2l_tags
req: R-A2L-LIST.005
in: list[dict] tags
out: list[dict] result
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:1444 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin._tag_matches_filter
req: R-A2L-007.2
in: dict tag; str text
out: bool result
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:1464 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2lViewMixin._schedule_a2l_filter_refresh
req: R-A2L-LIST.060
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (unchanged at s19_app/tui/app/a2l_view.py:1557 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

ComposeScreensMixin._compose_screen_a2l
req: R-A2L-LIST.080
in: (none)
out: Container result
module: s19_app/tui/app/compose_screens.py
func: baseline (unchanged at s19_app/tui/app/compose_screens.py:630 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

NavigationMixin.on_data_table_row_selected
req: R-A2L-LIST.031
in: DataTable.RowSelected event
out: None
module: s19_app/tui/app/navigation.py
func: baseline (unchanged at s19_app/tui/app/navigation.py:1333 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

NavigationMixin.on_data_table_row_highlighted
req: R-A2L-LIST.027
in: DataTable.RowHighlighted event
out: None
module: s19_app/tui/app/navigation.py
func: baseline (unchanged at s19_app/tui/app/navigation.py:1379 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

NavigationMixin.on_input_changed
req: R-A2L-LIST.060
in: Input.Changed event
out: None
module: s19_app/tui/app/navigation.py
func: baseline (unchanged at s19_app/tui/app/navigation.py:1497 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

_a2l_detail_card_text
req: R-A2L-LIST.029
in: Optional[dict] tag
out: Text result
module: s19_app/tui/app/shared.py
func: baseline (unchanged at s19_app/tui/app/shared.py:321 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

A2LDetailCard.show_tag
req: R-A2L-LIST.027
in: Optional[dict] tag
out: None
module: s19_app/tui/app/shared.py
func: baseline (unchanged at s19_app/tui/app/shared.py:603 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

build_label_index
req: R-A2L-LIST.072
in: Iterable[str] names
out: LabelIndex result
module: s19_app/tui/services/label_match.py
func: baseline (unchanged at s19_app/tui/services/label_match.py:124 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md

rank
req: R-A2L-LIST.060
in: str query; LabelIndex index; int limit
out: list[LabelMatch] result
module: s19_app/tui/services/label_match.py
func: baseline (unchanged at s19_app/tui/services/label_match.py:251 in 2dbd7d5a)
examples: (baseline) see graph-inc7.md
