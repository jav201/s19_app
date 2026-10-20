# Code-Wire graph: widths derived at mount and on resize (batch-97, PDR)

> Format B, Code-Wire draft v2.5, forward direction (PDR baseline). The node name is the code qualname (C11 rule of this project).
> Design source: `design/design-proposal.md` D5, D21, D22 and the §3 width table. Requirements: HLR-149, LLR-149.1, LLR-149.5, LLR-144.8.
> Scope: only the widths that Python computes (D21: DataTable columns, painted cards, the strip `max_bytes`, the Fields name). The CSS splits (`fr`, `%`) are not functions and are not nodes.
> The example values come from the §3 table, which the proposal calls illustrative (C-23). So every line of a NEW node is `synthetic`. The shipped card thread is `TC-B94-10` (`extract/trace-patch.json`).
> Convention: an edge from a node with no port to a port means that the node computes that value in its own body (annex, M-3).

## Nodes

patch_layout
req: LLR-149.1, LLR-144.8
in: int table_content_w; int inspector_content_w
out: PatchLayout layout {value_col_w, strip_max_bytes}
func: gives the Value/bytes column the table width that the four other columns leave, and the strip as many bytes as the inspector fits: `(inspector_w − 8) // 3`
module: s19_app/tui/screens_directionb.py
examples: (D21, synthetic) inspector_content_w 44 → strip_max_bytes 12; inspector_content_w 86 → strip_max_bytes 26

check_layout
req: LLR-149.1, LLR-145.2, LLR-145.3
in: int table_content_w; int card_content_w
out: CheckLayout layout {address_w, parameter_w, fields_name_w}
func: keeps Address at 10 cells and gives Parameter the rest of the table (at least 42). The Fields name gets the card width less 14 (at least 24)
module: s19_app/tui/screens_directionb.py
examples: (D21, synthetic) card_content_w 41 → address_w 10; fields_name_w 27; at 118x54 parameter_w 42, at 220x60 about 105

pipeline_layout
req: LLR-149.1, LLR-149.5
in: int avail_w; int n_cards
out: PipelineLayout layout {card_w}
func: card width `max(21, (avail − 4·(n−1)) // n)`. The remainder goes one cell each to the first cards
module: s19_app/tui/flow_screens.py
examples: (D21, synthetic) avail_w 108; n_cards 4 → card_w (24, 24, 24, 24); avail_w 208; n_cards 4 → card_w (49, 49, 49, 49)

lane_layout
req: LLR-149.1, LLR-147.12
in: int viewport_w; int n_cards
out: LaneLayout layout {card_w, scrolls}
func: the same card rule as the Builder. When 21 cells for each card and the cables do not fit, cards stay 21 and the lanes area scrolls
module: s19_app/tui/flow_screens.py
examples: (D21, synthetic) viewport_w 110; n_cards 6 → card_w 21; scrolls True; viewport_w 216; n_cards 4 → card_w 51; scrolls False

PatchEditorPanel._apply_layout
req: LLR-149.1
in: PatchEditorPanel self
out: None
func: reads the measured content widths, computes the layout and sets the column widths. It adds no column and no widget
module: s19_app/tui/screens_directionb.py
modify: [Data: PatchEditorPanel layout] (replace); [Interface: column widths] (replace)
inner: patch_layout
examples: (TC-B97-34, synthetic) resize 118x54 → 220x60 → strip_max_bytes 12 → 26; back to 118x54 → 12

PatchEditorPanel.on_resize
req: LLR-149.1
in: events.Resize event
out: None
func: re-applies the layout on each resize. After D22 it no longer calls `_apply_window_geometry`
module: s19_app/tui/screens_directionb.py
inner: PatchEditorPanel._apply_layout
examples: (TC-B97-34, synthetic) four resizes in one session → four layouts

CheckEditorPanel._apply_layout
req: LLR-149.1
in: CheckEditorPanel self
out: None
func: reads the measured widths, computes the layout and sets the Address, Parameter and Fields widths
module: s19_app/tui/screens_directionb.py
modify: [Interface: column widths] (replace)
inner: check_layout
examples: (TC-B97-34, synthetic) 118x54 → 220x60 → parameter_w 42 → about 105

FlowBuilderPanel._apply_layout
req: LLR-149.1
in: FlowBuilderPanel self
out: None
func: reads the rail width and the card count, computes the card widths and sizes the cards
module: s19_app/tui/flow_screens.py
modify: [Interface: card widths] (replace)
inner: pipeline_layout
examples: (AT-B97-16, synthetic) 4 cards at 220x60 → each card 49 cells; no void over 2 cells

FlowExecutionPanel._apply_layout
req: LLR-149.1, LLR-147.12
in: FlowExecutionPanel self
out: None
func: reads the lanes viewport and the card count of each lane, computes the card widths and sizes the cards
module: s19_app/tui/flow_screens.py
modify: [Interface: card widths] (replace)
inner: lane_layout
examples: (AT-B97-15, synthetic) 6 cards at 118x54 → cards 21; `#fx_lanes_scroll` scrolls; 4 cards at 220x60 fill the width

PatchEditorPanel._render_before_after_card
req: LLR-144.8
in: int? index = None
out: None
func: joins the highlighted row to its entry by position and reads the before bytes from the retained image map. It passes the layout byte count to the card
module: s19_app/tui/screens_directionb.py
inner: BeforeAfterCard.show_entry
examples: (TC-B94-10) index 0 → None; the card call that follows is the show_entry line of this thread
examples: (TC-B97-39, synthetic) index 1 at 220x60 → the card receives max_bytes 26 from the retained layout

BeforeAfterCard.show_entry
req: LLR-144.8
in: int? address; Sequence[int?]? before; Sequence[int] after; int max_bytes = CARD_BYTES_MAX
out: None
func: updates the strip for one entry. The byte count comes from the layout
module: s19_app/tui/screens_directionb.py
inner: before_after_card_text
examples: (TC-B94-10) address 0x100; before None; after (0xDE, 0xAD, 0xBE, 0xEF) → None; the strip shows the no-image line
examples: (TC-B97-39, synthetic) max_bytes 26 at 220x60 → up to 26 byte cells

before_after_card_text
req: LLR-144.8
in: int? address; Sequence[int?]? before; Sequence[int] after; int max_bytes = CARD_BYTES_MAX
out: Text strip
func: composes the before and after rows. A changed byte carries bold as well as its colour (D5)
module: s19_app/tui/screens_directionb.py
examples: (TC-B94-10) address 0x100; before None; after (0xDE, 0xAD, 0xBE, 0xEF) → strip "No image loaded"
examples: (TC-B97-39, synthetic) before (0x01, 0x02); after (0xAA, 0x02) → byte 1 bold and coloured; byte 2 plain

## Entities

[Data: PatchEditorPanel layout]
in: PatchLayout
desc: the last computed layout of the Patch Editor. The card reads the strip byte count from here (proposed by this graph, see H-W2)
sequence:
  mount: refresh_entries → _render_before_after_card (!) → _apply_layout wins (after the first refresh, D21)
  resize: on_resize → _apply_layout wins (no card repaint follows)
  highlight: _render_before_after_card reads the layout

[Interface: panel regions]
in: int
desc: the measured content widths of the table, the inspector, the card, the rail and the lanes viewport

[Interface: column widths]
in: int
desc: the DataTable column widths of the two editors

[Interface: card widths]
in: int
desc: the painted card widths of the Builder rail and of the Execution lanes

## Edges

[Interface: panel regions] ──▶ PatchEditorPanel._apply_layout
[Interface: panel regions] ──▶ CheckEditorPanel._apply_layout
[Interface: panel regions] ──▶ FlowBuilderPanel._apply_layout
[Interface: panel regions] ──▶ FlowExecutionPanel._apply_layout
PatchEditorPanel._apply_layout ──▶ patch_layout.table_content_w
PatchEditorPanel._apply_layout ──▶ patch_layout.inspector_content_w
CheckEditorPanel._apply_layout ──▶ check_layout.table_content_w
CheckEditorPanel._apply_layout ──▶ check_layout.card_content_w
FlowBuilderPanel._apply_layout ──▶ pipeline_layout.avail_w
FlowBuilderPanel._apply_layout ──▶ pipeline_layout.n_cards
FlowExecutionPanel._apply_layout ──▶ lane_layout.viewport_w
FlowExecutionPanel._apply_layout ──▶ lane_layout.n_cards
patch_layout.layout ──▶ [Data: PatchEditorPanel layout]
check_layout.layout ──▶ [Interface: column widths]
pipeline_layout.layout ──▶ [Interface: card widths]
lane_layout.layout ──▶ [Interface: card widths]
[Data: PatchEditorPanel layout] ──▶ PatchEditorPanel._render_before_after_card
PatchEditorPanel._render_before_after_card ──▶ BeforeAfterCard.show_entry.max_bytes
BeforeAfterCard.show_entry.max_bytes ──▶ before_after_card_text.max_bytes

## Findings

H-W1
anchor: lane_layout
what: D21 freezes `<screen>_layout(width) -> NamedTuple`. But the §3 formulas need more inputs. They need the card count (`lane_layout(viewport_w, n)` in §3), the inspector width and the table width
evidence: `design-proposal.md:66` (D21) against `:144-147` (§3 table); C12 on each NEW node
consequence: with one `width` input, Python must re-compute the CSS splits (`3fr`/`2fr`, `max(41, 38%)`). That is a second definition of each split, and the CSS can change it with no test failing. The TC-B97-34 layer-0 arms need the real input list
decision: changes D21. Fix the input list of each layout function (this graph proposes one). The inputs are measured content widths, not the terminal width

H-W2
anchor: [Data: PatchEditorPanel layout] ──▶ PatchEditorPanel._render_before_after_card
what: D21 says `_apply_layout` "sets widths only". The strip byte count, the clipped card text, the Fields name and the full-name line are painted text whose content depends on the width. No step repaints them on resize
evidence: the card renders from `refresh_entries` and from a highlight only (`screens_directionb.py:6229`, `:6231-6268`); recorded TC-B94-10: 11 card renders, all from those two paths
consequence: after 118x54 → 220x60 the strip keeps 12 bytes until the cursor moves. TC-B97-34 ("each width strictly greater at 220") and AT-B97-16 (void) can be RED for painted content while the column widths pass. QA Q-2 covers the DataTable repaint, not painted Static content
decision: changes D21: `_apply_layout` also re-renders each width-dependent painted widget, or each such widget reads the layout at paint time and `_apply_layout` asks for that paint

H-W3
anchor: BeforeAfterCard.show_entry
what: D5 derives `max_bytes` from the inspector width, but `show_entry` takes no `max_bytes`. Only the pure composer does
evidence: `screens_directionb.py:4271-4276` against `:4119-4124`
consequence: a signature change on a shipped method that §2 and §4 do not list. Small, but Inc-4 reviewers will not look for it
decision: none. List it in the Inc-4 scope
