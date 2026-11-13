# Inc 7 E3R1 extractor graph (the existing functions whose contract E3R1 changes, at `2dbd7d5a`)

Each node is an existing function; `func:` says baseline. Purpose: the real callers of every existing function
whose contract the E3R1 corrections change (`../E3-rulings.md` §E3R1 corrections). Marks sit only in a throwaway
`git archive` copy outside any worktree, written by `codewire_marks.py` from this file. Run (code-wire
`v3.1.0-8-gb6cd30d`, core only): `codewire_marks.py --repo <copy> --graph e3r1-extract.md`, then
`codewire_extract.py --repo <copy> --graph e3r1-extract.md --out extractor-e3r1`; `e3r1-callers.py` names the
enclosing function of every call site (`extractor-e3r1/callers.txt`).

## Nodes

OsClipboardInput._on_paste
req: R-PASTE.1, R-A2L-LIST.033
in: events.Paste event
out: None
module: s19_app/tui/os_clipboard_input.py
func: baseline (E3R1: the I-1 hook placement, E3S-03)
examples: (baseline) see graph-inc7.md

OsClipboardInput.action_paste
req: R-TUI-043.4, R-PASTE.29, R-A2L-LIST.033
in: (none)
out: None
module: s19_app/tui/os_clipboard_input.py
func: baseline (E3R1: the I-1 hook placement, E3S-03, E3A-16)
examples: (baseline) see graph-inc7.md

ComposeScreensMixin._compose_screen_a2l
req: R-A2L-LIST.040, R-A2L-LIST.080
in: (none)
out: Container section
module: s19_app/tui/app/compose_screens.py
func: baseline (E3R1: the I-7 constructors, E3A-03)
examples: (baseline) see graph-inc7.md

A2lViewMixin._filter_a2l_tags
req: R-A2L-LIST.006
in: list[dict] tags
out: list[dict] rows
module: s19_app/tui/app/a2l_view.py
func: baseline (E3R1: rows from the resolution, E3A-02, E3A-07)
examples: (baseline) see graph-inc7.md

A2lViewMixin._refresh_a2l_filtered_tags
req: R-A2L-LIST.036
in: bool preserve_anchor
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (E3R1: list mode in place on preserve_anchor, E3A-07; capped echo, E3S-02)
examples: (baseline) see graph-inc7.md

A2lViewMixin.update_a2l_view
req: R-A2L-LIST.072
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (E3R1: the absent branch clears the resolution, E3A-08)
examples: (baseline) see graph-inc7.md

A2lViewMixin.update_a2l_tags_view
req: R-A2L-LIST.009
in: list[dict] tags; str? empty_message = None
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (E3R1: the row map from the resolution's rows, E3A-02)
examples: (baseline) see graph-inc7.md

A2lViewMixin._repaint_a2l_tag_cells
req: R-A2L-LIST.036
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (E3R1: list mode written in place, E3A-07)
examples: (baseline) see graph-inc7.md

A2lViewMixin._schedule_a2l_filter_refresh
req: R-A2L-LIST.060
in: (none)
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (E3R1: the keyed request, a held widget reference, E3A-04, E3A-05)
examples: (baseline) see graph-inc7.md

A2lViewMixin._jump_to_tag_by_data
req: R-A2L-LIST.031
in: dict tag
out: None
module: s19_app/tui/app/a2l_view.py
func: baseline (reused unchanged; E3A-13 cites its missing-row return)
examples: (baseline) see graph-inc7.md

A2LDetailCard.show_tag
req: R-A2L-LIST.027
in: dict? tag
out: None
module: s19_app/tui/app/shared.py
func: baseline (reused unchanged; the parent of ListAwareDetailCard, E3A-02)
examples: (baseline) see graph-inc7.md
