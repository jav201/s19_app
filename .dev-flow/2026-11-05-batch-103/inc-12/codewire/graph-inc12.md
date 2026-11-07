# Code-Wire graph — Inc 12 (A2L tag table: no glued or cut values), batch-103

Stage E2 of `dev-flow-v3-beta`. Graph only: no stub, mark or declaration in any tree. Base `e67656bb` on `batch-103` (product tree `main` `e07fb00`). Requirements `../01-requirements.md` (R-TUI-042a.2 … .5; .6 and .7 since the E3 correction), cases `../02-test-cases.md` (16 + 2 AT; 25 + 2 AT since the E3 correction), E3 correction authority `../E3-rulings.md` (2026-11-07), rulings `../E1-rulings.md` (its "Orchestrator rulings": D-1 A, D-2 A, D-3 A), slice `../E1-slice.md`. Context: `../../inc-11/codewire/graph-inc11.md` (its two `app.py` nodes, `moved (Inc 12)`, are drawn again here), `../../inc-11/evidence-e3/corr2-e3c2-*` (source F), `../../design/operator-report-a2l-reader.md` (the field case; no operator data is used). Notation: Code-Wire v3.1.0 (`C:\Users\jjgh8\Github\code-wire`, tag `v3.1.0` = `e436a08`), `docs/Notation-Grammar.md`; layout as `b101-inc12:.dev-flow/2026-11-01-batch-101/inc-12/codewire/graph-inc12.md`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Context nodes (unchanged) are here because the design depends on what they do, or because the E1 slice named them and the measurements took them out (E2-1, E2-2).
- Sources of the examples: the case ids of `../02-test-cases.md`; **P** = this stage's probes of the real app, headless on cachyos-rtx (`evidence-e2/i12e2-probe.py`, transcripts `evidence-e2/i12e2-probe-<variant>-<scenario>-transcript.txt`; variant `design` is this graph, written into a throwaway copy of the clone by `evidence-e2/i12e2-mkproto.py`; `base` is the read-only clone at `e07fb00`; the other variants are the negative controls of the triggers, listed in `i12e2-mkproto.py`); **S** = `evidence-e2/i12e2-shorten-transcript.txt`; **X** = the extractor, `evidence-e2/i12e2-extract-transcript.txt` (callers) and `../evidence-e1/i12e1-callers-transcript.txt`; **F**, **V**, **W** = Inc 11's sources as `../01-requirements.md` names them; **R** = read in the code at `e07fb00` or in textual 8.2.8 on the runner, not run; **E3A**, **E3S** = the E3 reviews' probes on cachyos-rtx (`../E3-architect.md` tags `[O <scenario>]`, `[C]`; `../E3-security.md` tags `[U …]`, `[Z]`, `[H …]`, `[K]`), review instruments in the review session's scratchpad, not committed. Every example states the Inc 12 target unless it says "base" or "holds on base".
- The probe gained scenarios during the stage (`flipbar`, `rehide`, the card lines, the masked home path); its `report()` check did not change, and each transcript's first lines name its variant, scenario, commit and Python. Every variant's copy is rebuilt identically by the last setup (`evidence-e2/i12e2-setup-transcript.txt`: `design` and `widgetnoshow` both 88 changed lines). The runner scratch `/tmp/b103-e2-12/` is deleted; the scripts rebuild it.
- Fixtures SYNMAP, LONGMAP(n), PAGE64(n), PAGE64W(n) (and MANY(k, n) since E3) are `../02-test-cases.md`'s; MANY = the probe's page of a SYNMAP-shaped MAP plus n-character MEASUREMENTs at 32-bit addresses (`page_many`, one 64-bit address at index 215 in the `flip` scenario). Painted rows are `render_line(y).text` of `#a2l_tags_list`; every one starts with the Address column's padding blank.
- *w* is the name width of CTX-A2L-SCREEN; "the 34-cell form" is R-TUI-042a.3's (16 + `…` + 17).

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns |
|---|---|---|
| G1 app | `s19_app/tui/app.py` (the one source file) | all 12 changed and new nodes (9 at E2; `_a2l_detail_card_text`, `_card_field` and the rebase's one-line change of `_repaint_a2l_tag_cells` at E3); the docstrings of `_compose_screen_a2l` (its `cell_padding=0` sentence) and `_build_a2l_table_cells` (the order, index 0 → Address) |
| G-T1 tag-table tests | new `tests/test_b103_inc12_tag_table.py`; re-pointing of the E2-6 list (with E2-6's E3 note: AT-069b, AT-069c, b101 Inc 10b's and Inc 1b's tests); cases R-TUI-042a.2/1 … R-TUI-042a.7/3 and AT-B103-I12-1 | — |
| E5 | AT-B103-I12-2 (captures, operator verdict); the 6 `a2l-*` snapshot baselines regenerated in the canonical CI env (`snapshot-regen.yml`, textual 8.2.8), never locally | — |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 (PLAN; consumed) | the copy from the tag table takes the tag's full name, `self._a2l_row_key_to_tag[<row key>]["name"]`, never the painted Tag cell (D-3 A, recorded in `../../inc-1b/E1-rulings.md`); row keys stay `a2l:<absolute index>`; the Tag cell moves from index 0 to index 2 | Inc 12 → Inc 1b's E2 |
| I-12.1 the cell tuple (PROPOSED change of an existing signature) | `S19TuiApp._build_a2l_table_cells(self, tag: dict, name_width: Optional[int] = None) -> tuple[Text, ...]`: 16 `Text` cells in CTX-A2L-SCREEN order — 0 Address, 1 Length, 2 Tag, 3 Source, 4 Raw, 5 Physical, 6 InMem, 7 Region, 8 Limits, 9 Unit, 10 Bits, 11 Endian, 12 Virt, 13 Func, 14 Access, 15 Dtype; `name_width=None` gives the 34-cell form | G1 → `update_a2l_tags_view`, `_fit_a2l_tag_cells`, b101 Inc 10b's `_repaint_a2l_tag_cells`, which passes `self._a2l_tag_name_width(table)` (G1 makes the one-line change at the rebase; E3A-01), the E2-6 tests |
| I-12.2 the widget | `#a2l_tags_list` is an `A2LTagTable`, a subclass of `DataTable` (every `query_one("#a2l_tags_list", DataTable)` in 10 test files keeps working), with `cell_padding == 1`, `fixed_columns == 2`, `zebra_stripes=True`, `cursor_type="row"`; its message `A2LTagTable.Measured(Message, namespace="a2l_tag_table")` is handled by `S19TuiApp.on_a2l_tag_table_measured`. One class chain (E3A-03): `class A2LTagTable(_CopyRowTable)` once Inc 1b lands (Inc 1b's right-click handler in its base), or that handler in `A2LTagTable` itself; never two `DataTable` subclasses for the one widget (recorded in `../../inc-1b/E1-rulings.md`) | G1 → G-T1, Inc 1b |
| I-12.3 no new app attribute | Inc 12 adds no `self.<name> =` in `S19TuiApp`: `tests/test_b100_session_reset.py:1144-1157` pins the census over the 12b base to `{"_quit_pending"}`, and `_SESSION_SNAPSHOT_NAMES` (`app.py:2595`) is unchanged. The fit keeps no state: the painted Tag cells are compared | G1 → the census test (unchanged) |
| I-12.4 Inc 11 (consumed) | the Length cell is `str(tag["length"])` or `n/a`, the Address cell `0x{addr:08X}` or `n/a` (`app.py:20428-20430`), both unchanged; Inc 11 produces `tag["length"]`. Bounds R-TUI-042a.4 relies on, Inc 11 outputs (E3A-07): the Address cell at most 18 characters (`0x` + 16 digits: Inc 11's R-A2L-READ.69 gives an address word above 0xFFFFFFFFFFFFFFFF no address) and the Length cell at most 7 (R-A2L-READ.38: lengths of 1 to 1,048,576) | Inc 11 → Inc 12 |
| PLAN I-2 … I-5 | n/a — no definition model, matcher, label-list parser here; the A2L refresh entry (I-4, Inc 5) reaches this table through `update_a2l_view` → `update_a2l_tags_view`, whose signature is unchanged | — |

Order: Inc 12 merges after Inc 11 (the "after" captures of AT-B103-I12-2 are Inc 12 on Inc 11, D-2 A). Inc 7 starts from this increment's column order (PLAN backlog 5). Sequencing (E3A-01 (3)): Inc 12's E4 starts only on `batch-103` rebased onto a `main` that holds b101 Inc 10b, so `_repaint_a2l_tag_cells` and this graph's line numbers are real.

### Baseline: the existing functions in scope at `e07fb00` and their real callers (X: `evidence-e2/i12e2-callers-transcript.txt`, Code-Wire v3.1.0 over a throwaway `git archive e07fb00 s19_app` copy, 1,996 marks)

| Function | `file:line` | Real callers (`file:line` of the call) | Here |
|---|---|---|---|
| `S19TuiApp._compose_screen_a2l` | `app.py:8456` (the table `:8516-8521`) | `S19TuiApp.compose` (`app.py:3385`) | changed |
| `S19TuiApp._setup_datatable_columns` | `app.py:8693` (the tag table `:8733-8751`) | `S19TuiApp.on_mount` (`app.py:8644`) | changed |
| `S19TuiApp.update_a2l_tags_view` | `app.py:20286-20387` | `_apply_viewer_setting` (`:20605`), `_focus_a2l_tag_absolute_index` (`:16603`), `_refresh_a2l_filtered_tags` (`:20217`, `:20222`), `action_a2l_tags_page_next` (`:11102`), `action_a2l_tags_page_prev` (`:11128`), `update_a2l_view` (`:20269`); every one passes `self._a2l_filtered_tags`, `update_a2l_view` `[]` when no A2L is loaded (R) | changed |
| `S19TuiApp._build_a2l_table_cells` | `app.py:20389-20473` | `S19TuiApp.update_a2l_tags_view` (`app.py:20357`); tests call it directly (E2-6); on `b101-inc10` (`aedeaddf`) also `S19TuiApp._repaint_a2l_tag_cells` (`app.py:21061`; E3A-01, the extractor per branch: 2 callers there, 1 on `main`) | changed |
| `S19TuiApp._repaint_a2l_tag_cells` (b101 Inc 10b; not on `e07fb00`) | `b101-inc10` `app.py:21009-21090` | `_refresh_a2l_values_after_write` (`:18913`), run after every image write (`:18808`) (E3A-01) | changed at the rebase (E3A-01) |
| `S19TuiApp.on_resize` | `app.py:10864-10893` | none marked (a textual event handler) | context (unchanged; slice #5, E2-1) |
| `S19TuiApp.action_show_screen` | `app.py:9969` | `on_rail_selected` (`app.py:10308`), `action_view_main` (`:10755`), `action_view_alt` (`:10759`), `action_view_mac` (`:10763`), `on_memory_map_panel_open_in_hex_requested` (`:19577`), `SplitJoinWindow.action_close_window` (`segment_split_view.py:2199`); keys `1` … `9` and the palette through `BINDINGS` | context (unchanged, E2-2) |
| `S19TuiApp.on_data_table_row_highlighted` | `app.py:16315` | none marked (textual dispatch of `DataTable.RowHighlighted`) | context |
| `_a2l_detail_card_text` | `app.py:1278` | `A2LDetailCard.show_tag` (`app.py:1402`), `S19TuiApp._compose_screen_a2l` (`app.py:8528`) | changed (E3S-02; context at E2) |
| `_card_field` | `app.py:1245-1275` | `_a2l_detail_card_text` (`app.py:1320`, `:1330`, `:1331`; R, `grep`) | changed (E3S-02) |

Read and unchanged: `_a2l_row_key_to_tag` is read by row key (`coordinate_to_cell_key((row, 0))`, `app.py:9763`, the key only); no product code outside `app.py` names `#a2l_tags_list` (R, `grep`). The house clip seam `S19TuiApp._clip_to` (`app.py:20829`, called by `_compose_context_line` `:20928-20929`) is the model of `_shorten_tag_name`, not a caller of it.

## Nodes

S19TuiApp._compose_screen_a2l
req: R-TUI-042a.2, R-TUI-042a.4
in:
out: Container screen
func: changed. was: `DataTable(id="a2l_tags_list", zebra_stripes=True, cursor_type="row", cell_padding=0)` (`app.py:8516-8521`): adjacent cells paint with no gap and no column is fixed. / now: `A2LTagTable(id="a2l_tags_list", zebra_stripes=True, cursor_type="row", cell_padding=1, fixed_columns=2)` (I-12.2); the `density-compact` class, the pane padding and every other widget of the screen unchanged. The first two columns (Address, Length) stay at their own x under a horizontal scroll; the others scroll under them.
module: s19_app/tui/app.py
examples: (R-TUI-042a.2/1, AT-B103-I12-1, P design syn) SYNMAP at 220×50 → the row paints ` 0x1C2D3E00  2266    ✓ SYN_MAP_W  formula  1792  1792      yes    unknown  0..4095  %.0` …; `0x1C2D3E002266`, `SYN_MAP_W0x1C2D3E00`, `17921792` and `unknown0..` painted `0` times at 220, 160 and 118 (base: `✓ SYN_MAP_W0x1C2D3E002266  formula17921792    yes  unknown0..4095%.0`, P base syn)
examples: (R-TUI-042a.2/2, P design syn) SYNMAP at 100×50 → ` 0x1C2D3E00  2266    ✓ SYN_MAP_W  formula  1792`; at 80×50 → ` 0x1C2D3E00  2266    ✓ SYN_MAP_W  form` (the Source cell cut at the pane edge, after a blank) (base at 80: `✓ SYN_MAP_W0x1C2D3E002266  formula1792`)
examples: (R-TUI-042a.4/1, P design p64) PAGE64(n), n = 20, 28, 34, 48, 100, at 80, 85, 90, 95, 100, 118, 160, 220 columns, unscrolled → Address `0x1C2D3E00`, `0x1C2D3E004026`, `0x00001000` and Length `2266`, `2`, `1048576` painted whole in the first two columns, 40/40 (base at 118, PAGE64(48): ` · SYN_V64_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD0x1C2D3E00` — the 64-bit address cut to the MAP's address at the pane edge, P base p64-few)
examples: (R-TUI-042a.4/2, P design p64) the same 40 cases scrolled fully right → 40/40; PAGE64(48) at 80×54, `scroll_x` `123` → ` 0x1C2D3E004026  2              UWORD` (base: ` 65535%.0           no            UWORD`, no address shown)
examples: (R-TUI-042a.4/3, P design p64w) PAGE64W(48) at 80×54 → ` 0xFEDCBA9876543210  2        · SY…CD` (Address column `20` cells), whole unscrolled and at `scroll_x` `127`, 2/2
examples: (R-TUI-042a.2 neg) mutant `cell_padding=0` → `0x1C2D3E002266` painted at 5/5 widths → RED; (R-TUI-042a.4 neg) mutant `fixed_columns=0` → scrolled right, the Address cell not shown (F config C: 0/40) → RED
examples: (holds on base, AT-038b) `#a2l_tags_pane` keeps the class `density-compact`

S19TuiApp._setup_datatable_columns
req: R-TUI-042a.4, R-A2L-006.1
in:
out: None
func: changed. was: the tag table's labels `Tag`, `Address`, `Length`, `Source`, … (`app.py:8733-8751`). / now: `Address`, `Length`, `Tag`, then `Source`, `Raw`, `Physical`, `InMem`, `Region`, `Limits`, `Unit`, `Bits`, `Endian`, `Virt`, `Func`, `Access`, `Dtype` unchanged (CTX-A2L-SCREEN, changed). Installed once at mount as today; the MAC and Issues tables unchanged.
module: s19_app/tui/app.py
examples: (R-TUI-042a.4/4, P design order) SYNMAP at 118×54 → `ordered_columns` labels `['Address', 'Length', 'Tag', 'Source', 'Raw', 'Physical', 'InMem', 'Region', 'Limits', 'Unit', 'Bits', 'Endian', 'Virt', 'Func', 'Access', 'Dtype']`, 16/16; header line ` Address     Length  Tag          Source   Raw   Physical  I` — `Address` from x `1`, after the padding cell (E2-5) (base: `['Tag', 'Address', 'Length', …]`, `Address` at x `11`, P base order)
examples: (R-TUI-042a.4 neg) today's order → 13/40 whole unscrolled, 0/40 scrolled right (F config B) → RED
examples: (holds, TC-N8-04) every one of the 16 labels keeps its legend line: `tests/test_legend_n8.py:523-536` reads `table.columns.values()`, which is order-free

S19TuiApp.update_a2l_tags_view
req: R-TUI-042a.3, R-TUI-042a.5
in: list[dict] tags; str? empty_message = None
out: None
func: changed. was: clears the table (`clear(columns=False)`), slices one page (`_a2l_window_start`, page size ≤ 200), builds each row with `_build_a2l_table_cells(tag)` (`:20357`) and the row's severity style, adds it under the key `a2l:<absolute index>`, then writes the summary (`app.py:20286-20387`). / now: the same, plus (1) once per page, before the rows, `name_width = self._a2l_tag_name_width(a2l_table)` — measured on the layout the table has at that moment, the previous page's — and every row gets `_build_a2l_table_cells(tag, name_width)`; (2) after the summary, `self.call_after_refresh(self._fit_a2l_tag_cells)`, so a page whose Address or Length widths, or whose vertical scrollbar, differ from the previous page's is fitted once its own layout exists (E2-3; the toolkit's own after-dimensions idiom, textual 8.2.8 `_data_table.py:1209-1212`, `:1254-1258`). The empty path (`tags == []`) is unchanged and schedules nothing. Signature unchanged; the 6 callers unchanged (X).
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/1, P design long) LONGMAP(48), loaded while the A2L Explorer is hidden (`name_width` `None`: the 34-cell form), then key `2` at 80×54 → painted Tag cell `✓ SYN_MA…LLL_END`, ending at x `37` of a visible width `38`; builds `3` (2 while hidden, 1 by the fit)
examples: (R-TUI-042a.5/8 since E3, E2-3, P design flip) MANY(230, 48): 230 MEASUREMENTs, page 2 holds the one 64-bit address, 80×54: `plus` → the Address column `12` → `16` cells, *w* `12` → `8`, the visible Tag cells in the *w* = 8 form after the fit, 28/28; `minus` → page 1, 28/28 (neg: no fit after a build → page 2 0/28, P widgetonly flip, widgetnopost flip)
examples: (R-TUI-042a.5/9 since E3, E2-3, P design flipbar) MANY(219, 48): 220 tags at 32-bit addresses, 80×54: page 1 (200 rows, vertical scrollbar, visible `36`) *w* `12` → `✓ SYN_M…LL_END`; `plus` → page 2 (20 rows, no scrollbar, visible `38`) *w* `14`, 20/20; `minus` → *w* `12`, 28/28 (neg: no fit after a build → page 2 0/20, and back on page 1 `✓ SYN_MA…LLL_END` painted past the visible width, 0/28, P widgetnopost flipbar)
examples: (holds on base) row keys `a2l:0`, `a2l:1`, …; `tags == []` → summary `No A2L tags.`
examples: (cost, P design flip) one 200-row page build `15.2` ms median of 5; the fit after it, when no Tag cell differs, `5.9` ms

S19TuiApp._build_a2l_table_cells
req: R-TUI-042a.3, R-TUI-042a.5, R-TUI-042a.4
in: dict tag; int? name_width = None
out: tuple[Text, ...] cells
func: changed (I-12.1, PROPOSED: the input `name_width`). was: 16 cells with the Tag cell first, `safe_text(f"{glyph} {name_text}", style=VALUE)` holding the whole name (`:20457`), then Address `0x{addr:08X}` or `n/a` (`:20430`), Length, Source … (`app.py:20389-20473`). / now: the same 16 cells in CTX-A2L-SCREEN's order — Address (0), Length (1), Tag (2), Source (3) … Dtype (15) — and the Tag cell `safe_text(f"{glyph} {_shorten_tag_name(name_text, 34 if name_width is None else min(34, name_width))}", style=VALUE)`. The formats, every other cell, `safe_text` and the accent styles unchanged; the detail card keeps the full name (`_a2l_detail_card_text`). One rule serves both rows: `min(34, w)` is 34 while *w* ≥ 34 (R-TUI-042a.3) and *w* below (R-TUI-042a.5); at *w* = 34 both give 16 + `…` + 17.
module: s19_app/tui/app.py
examples: (R-TUI-042a.3/1, P design long) LONGMAP(46), (48), (50), (54) with `name_width` `36` (118×54) → cells[2] `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END` (36 cells), cells[0] `0x1C2D3E00`, cells[1] `2266`, both painted whole, 4/4 (base: the whole name; with padding 1, `0x1C2D3` painted for n = 48 at 118, V [V w=118 pad=1 name_len=48])
examples: (R-TUI-042a.3/2, P design long) LONGMAP(100), `name_width` `84` (220×60) → cells[2] `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END`
examples: (R-TUI-042a.3/3, P design long) LONGMAP(34), `36` → `✓ SYN_MAP_LLLLLLLLLLLLLLLLLLLLLL_END` (whole, no `…`); LONGMAP(35) → `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END`
examples: (R-TUI-042a.5/1, P design long) LONGMAP(48), `name_width` `14`, `22`, `25` → `✓ SYN_MA…LLL_END`, `✓ SYN_MAP_LL…LLLLLLL_END`, `✓ SYN_MAP_LLLL…LLLLLLLL_END`
examples: (R-TUI-042a.5/2, P design long) LONGMAP(20), `14` → `✓ SYN_MA…LLL_END`
examples: (R-TUI-042a.5/3, P design p64) PAGE64(48)'s MAP, `9`, `17`, `20`, `31` → `✓ SYN_…ABCD`, `✓ SYN_MAP_…6789ABCD`, `✓ SYN_MAP_A…456789ABCD`, `✓ SYN_MAP_ABCDEFG…Z0123456789ABCD`; its MEASUREMENTs the same with `· SYN_V64_` and `· SYN_BIG_`
examples: (R-TUI-042a.5/4, P design long, p64) `84` (LONGMAP(48)), `79` (PAGE64(48)) at 220 → `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END`, `✓ SYN_MAP_ABCDEFGH…XYZ0123456789ABCD` (36 cells each)
examples: (R-TUI-042a.5/5, P design p64w) PAGE64W(48), `5` → `✓ SY…CD`, then `· SY…CD` for the 3 MEASUREMENTs
examples: (TC-067.1 re-pointed, R-TUI-042a.4) `in_memory` True → cells[2] starts `✓ `; False → `· `; cells[0] starts `0x`; `len(cells)` `16`
examples: (R-TUI-042a.5 neg) the fixed 34-cell form alone (`name_width` ignored) → at 118 on PAGE64(48) the 38-cell Tag column has 35 cells left, its last 3 cut with no mark (F [A N48 W118]) → RED; (R-TUI-042a.3 neg) no cut → at 118 the 48-character name's Tag cell (50 cells) runs past the pane edge → RED

_shorten_tag_name
req: R-TUI-042a.3, R-TUI-042a.5, R-TUI-042a.6
in: str name; int width
out: str shown
func: new (pure, module level, beside `_a2l_detail_card_text`). First shows each character of `name` outside U+0021 … U+007E as U+FFFD (R-TUI-042a.6; the rule of Inc 11's R-A2L-READ.66 and Inc 2's R-A2L-DEF.137), so every character of the shown name `p` is one cell. Then `p` itself when `len(p) <= width`; else `p[:h] + "…" + p[len(p) - t:]` with h = ⌊(width − 1)/2⌋ and t = width − 1 − h: plain slicing, O(*w*), exactly `width` cells. A `width` below 1 is taken as 1 (`…` alone; widths under 80 columns are not supported, R-TUI-042a.2). The house clip seam (`S19TuiApp._clip_to`, `app.py:20829-20853`; `_clip_to_cells`, `a2l_parameter_picker.py:109`) cuts at the end; this one cuts in the middle. (At E2 the cut measured the raw name in cells, `set_cell_size`, with a pad space where a double-width character straddles the cut: quadratic in a zero-width tail, 33.6 s per call at 16,000 × U+200B, re-run on every fit; E3S-01.)
module: s19_app/tui/app.py
examples: (R-TUI-042a.3, S) `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.COLUMN_DIR` (44 cells), `34` → `ASAM.C.ARRAY.SWO…IM_3_4.COLUMN_DIR`; `ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR` (41) → `ASAM.C.ARRAY.SWO…X_DIM_3_4.ROW_DIR` — distinct by their ends, D-1 A's reason
examples: (R-TUI-042a.5, S) the same two, `14` → `ASAM.C…UMN_DIR` and `ASAM.C…ROW_DIR`; `9` → `ASAM…_DIR` for both (E2-7)
examples: (R-TUI-042a.6, E3S-01; was at E2, S: `ＡＢＣ… ＨＩＪ`) `ＡＢＣＤＥＦＧＨＩＪ` (10 fullwidth letters) → shown as 10 × U+FFFD; `14` → the 10 × U+FFFD whole; `9` → 4 × U+FFFD, `…`, 4 × U+FFFD
examples: (R-TUI-042a.6/1, E3S-01 [U cost tail], [U fix model]) a 47-character ASCII name + 16,000 × U+200B, `14` → its first 6 characters, `…`, 7 × U+FFFD; modelled at 0.026 ms (the E2 form: 33.6 s per call; with 4,000 × U+200B, 1.8 s)
examples: (R-TUI-042a.6/2, E3S-01 [U cost tail]) the same name + 16,000 × U+0301, or + 16,000 × ESC, `14` → the same form, no U+0301 and no ESC (the E2 form: 33.7 s and 24.1 s)
examples: (R-TUI-042a.6/3) LONGMAP(48)'s name (ASCII), `14` → `SYN_MA…LLL_END`, unchanged
examples: (R-TUI-042a.3/3) a 34-cell name, `34` → the name; a 35-cell name → its first 16 cells, `…`, its last 17
examples: (S) a 44-cell name, `1` → `…`; `0` → `…`

S19TuiApp._a2l_tag_name_width
req: R-TUI-042a.5
in: DataTable a2l_table
out: int? name_width
func: new. The name width *w* of CTX-A2L-SCREEN: `a2l_table.scrollable_content_region.width` (the visible width: the content region minus a shown scrollbar) minus the render widths (`Column.get_render_width`) of `ordered_columns[0]` and `[1]` (Address and Length, each with its 2 padding cells) minus `2 * a2l_table.cell_padding + 2` (the Tag column's padding, the glyph and the blank after it). `None` when the visible width is `0`: a hidden table has a null region. Reads only. The widths are the table's actual ones, which textual 8.2.8 grows and never shrinks across `clear(columns=False)` (E2-4).
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/1, R-TUI-042a.5/4, P design long) LONGMAP(48): visible `38`, `46`, `49`, `60`, `108` at 80, 95, 100, 118, 220 columns, Address `12`, Length `8` → `14`, `22`, `25`, `36`, `84`
examples: (R-TUI-042a.5/3, P design p64) PAGE64(48): the same visible widths, Address `16`, Length `9` → `9`, `17`, `20`, `31`, `79`
examples: (R-TUI-042a.5/5, P design p64w) PAGE64W(48) at 80: Address `20`, Length `9` → `5`
examples: (P design flipbar) a 200-row page at 80×54: the vertical scrollbar takes 2 cells, visible `36` → `12` (E2-5)
examples: (P design rehide) the A2L Explorer hidden: region width `0`, size `(0, 0)` → `None`

S19TuiApp._fit_a2l_tag_cells
req: R-TUI-042a.5, R-TUI-042a.3
in:
out: None
func: new. Runs after the refresh that follows every page build, and on `A2LTagTable.Measured`. Measures *w*; returns when it is `None`, when the page has no rows, or when the row count differs from `_a2l_row_key_to_tag`; else compares each painted Tag cell (`get_row_at(i)[2].plain`) with `_build_a2l_table_cells(tag, w)[2].plain`, and only when one differs calls `self._repaint_a2l_tag_cells()`, the in-place repaint, given *w* through I-12.1 (E3A-01 (4), E3A-06; at E2: `update_a2l_tags_view` of the same page, with the cursor, `scroll_x` and `scroll_y` kept and restored and `move_cursor`; those steps leave the node, since an in-place repaint moves neither the cursor nor the scroll). It keeps no state of its own (I-12.3). It cannot loop: a repaint changes only cells; the table's size does not depend on its content (`#a2l_tags_list { height: 1fr }`, `styles.tcss:694-696`; its width is the `4fr` pane's), so a repaint delivers no Resize. It terminates because *w* depends only on the visible width and the Address and Length widths, which a rewrite does not change (E2-4); a resize step may deliver two Resizes (the width regime's intermediate layout, E3A-09 [O order]); each fit reads the region current when it runs. These hold for textual `>=8.2.8,<9`, the run-time pin (`pyproject.toml:52`; E3S-07). The P design examples below were measured on the E2 rebuild form (at most 1 fit rebuild per trigger in every scenario); E4 measures them on the in-place form.
module: s19_app/tui/app.py
modify: [Data: A2L Explorer tag table rows] (replace)
examples: (R-TUI-042a.5/6, P design resize) LONGMAP(48) shown at 220×60 (`✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END`), `pilot.resize_terminal(80, 54)`, no key → 1 fit rebuild → `✓ SYN_MA…LLL_END`, ending at x `37` of `38`; back to 220×60 → `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END`; cursor row `0` throughout
examples: (R-TUI-042a.5/6, P design resize) PAGE64(48), cursor on row `2`, scrolled right at 220 → after 220→80 the cursor row `2`, Address and Length whole 3/3; at `scroll_x` `0` the Tag cells `✓ SYN_…ABCD`, `· SYN_…ABCD`, `· SYN_…ABCD`, 3/3
examples: (E2-2, P design rehide) shown at 80×54, key `1`, the A2L reloaded while hidden (Tag cell `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END`), key `2` at the same size → `✓ SYN_MA…LLL_END`, 1/1 (neg: the fit from `App.on_resize` and no table resize, P noshow rehide: 0/1)
examples: (P design syn) every painted Tag cell already in its form (SYNMAP's 9-character name) → `0` fit rebuilds at all 5 widths
examples: (R-TUI-042a.5/6 neg, P full resize) the fit scheduled only from `App.on_resize` with `call_after_refresh` → it runs before the table's region changes: `0` fit rebuilds, after 220→80 the Tag cell `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END` painted past the visible width → RED
examples: (E3A-06, E3A [O inplace]) a 200-row page, cursor on row `150`, 80→118, the repaint given *w*: `0` RowHighlighted, every frame at scroll `(0, 123)`, cursor `150` kept, `46`–`61` ms per 200-row repaint at runner load 17–21 (the E2 rebuild form, E3A [O deep], [O find]: one frame at scroll `(0, 0)` with the cursor off screen, the card re-pointed to `a2l:0` and back, 4 RowHighlighted for one find)

S19TuiApp._repaint_a2l_tag_cells
req: R-TUI-042a.5
in:
out: None
func: changed at the rebase (b101 Inc 10b's method; not on `e07fb00`; E3A-01). was (`b101-inc10` `aedeaddf`, `app.py:21009-21090`): rebuilds each shown row with `self._build_a2l_table_cells(tag)` (`:21061`), the 34-cell form, and writes every cell whose text differs with `update_cell_at(…, update_width=True)`; called by `_refresh_a2l_values_after_write` (`:18913`) after every image write (`:18808`), which sends no Resize and builds no page, so nothing re-fits after it. / now: the same, with `self._build_a2l_table_cells(tag, self._a2l_tag_name_width(table))` (I-12.1; G1's one-line change at the rebase), and it is also the fit's rewrite step (E3A-01 (4)). In place: no `clear()`, so the cursor, the scroll offsets and the card stay (E3A-06); with `update_width=True` the Tag column also shrinks to its cells (38 → 16 cells at 80, E3A [O inplace]).
module: s19_app/tui/app.py
modify: [Data: A2L Explorer tag table rows] (replace)
examples: (R-TUI-042a.5/7, E3A [O repaint10b]) LONGMAP(48) shown at 80×54, an image write → with the width, the Tag cell `✓ SYN_MA…LLL_END`, 1/1; without it (10b as on `b101-inc10`), `✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END` ending at x `57` of `38`, painted `✓ SYN_MAP_LLLLLLL` with no `…` visible, 0/1 → RED
examples: (R-TUI-042a.5/7, E3A [O repaint10b]) PAGE64(48) shown at 118×54, an image write → with the width 3/3; without it 0/3 (ends at `62` of `60`, `…789AB` shown for `…789ABCD`)

A2LTagTable.on_resize
req: R-TUI-042a.5
in: events.Resize event
out: None
func: new, with its class `A2LTagTable(DataTable)` (`app.py`, module level, beside `A2LDetailCard`; its base `_CopyRowTable` once Inc 1b lands, one class chain per I-12.2, E3A-03) and its nested message `class Measured(Message, namespace="a2l_tag_table")` (the handler `on_a2l_tag_table_measured`; without the namespace textual names it `on_a2ltag_table_measured`, R). Posts `self.Measured()`. `events.Resize` does not bubble, so the table re-emits its own resize as a bubbling message: the house idiom `BandBar.Measured` (`screens_directionb.py:1580-1647`, batch-77/93), adopted there after a `call_after_refresh` read stale widths on CI. The table gets a Resize when a terminal resize changes its size and when it is shown, since a hidden table's size is `(0, 0)` (E2-1, E2-2). Only `on_resize` is defined: textual dispatches one of `_on_resize` / `on_resize` per class of the MRO (`message_pump.py:794-797`), so a private `_on_resize` here would replace DataTable's own.
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/6, P design resize) 220×60 → 80×54 with the A2L Explorer shown → one Resize of the table → one `Measured` → one fit rebuild
examples: (E2-2, P design rehide) key `2` after a rebuild while hidden → the table's Resize with size `(38, 30)` and visible width `38` → `Measured`
examples: (P design syn) page builds at an unchanged size → no Resize (builds `2`, fits `2`, both from the builds)

S19TuiApp.on_a2l_tag_table_measured
req: R-TUI-042a.5
in: A2LTagTable.Measured event
out: None
func: new. `event.stop()`, then `self._fit_a2l_tag_cells()` directly: when the table gets its Resize the screen has been laid out, so the region the fit reads is current (P design rehide: visible `38` at the Resize).
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/6, P design resize) each resize step → 1 `Measured` → fit rebuilds `1` (after 220→80), `2` in all (after 80→220)

S19TuiApp.on_resize
req: R-TUI-042a.5
in: events.Resize event
out: None
func: unchanged (a deviation from `../E1-slice.md` #5, E2-1). Applies the width and diff regimes and calls `call_after_refresh(update_project_labels)` (`app.py:10864-10893`). A fit scheduled here would run before the table's region changes: textual 8.2.8 forwards the terminal Resize to the screen only after a 1/120 s timer (`app.py:4352-4356`, `:5023-5037` of textual, R), so the tag table's own resize carries the trigger.
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/6 neg, P full resize) adding `if self._active_screen_key == "a2l": self.call_after_refresh(self._fit_a2l_tag_cells)` here as the only resize trigger → after 220→80 fit rebuilds `0`, LONGMAP(48)'s Tag cell painted past the visible width, 0/1, and PAGE64(48)'s 0/3 → RED
examples: (holds on base, TC-B79-04) the context line is recomposed after a resize

S19TuiApp.action_show_screen
req: R-TUI-042a.5
in: str screen_key
out: None
func: unchanged (E2-2). Swaps the `.hidden` class of the rail screens (`app.py:9969-10070`). Showing the A2L Explorer gives the tag table a Resize, so no `a2l` branch is added.
module: s19_app/tui/app.py
examples: (P design long) key `2` after a load while hidden → the fit rebuild comes from `A2LTagTable.Measured`: builds `3` at 80, 95 and 100 columns, the Tag cell in the *w* form, 1/1 each

S19TuiApp.on_data_table_row_highlighted
req: R-TUI-042a.5
in: DataTable.RowHighlighted event
out: None
func: unchanged. Shows the highlighted row's tag in the detail card (`app.py:16315-16360`); the fit's in-place repaint does not move the cursor, so the card shows the same tag (E3A-06 [O inplace]: 0 RowHighlighted; at E2 the rebuild moved the cursor back to the kept row).
module: s19_app/tui/app.py
examples: (R-TUI-042a.5/6, P design resize) PAGE64(48) with the cursor on row `2` → after the resize rebuild the cursor row `2`

_a2l_detail_card_text
req: R-TUI-042a.3, R-TUI-042a.7
in: dict? tag
out: Text text
func: changed (E3S-02, R-TUI-042a.7; context at E2). was: the card is built from the tag dict with `Text.append`, so file text reaches the terminal with ESC and U+009B intact (`app.py:1278-1342`; E3S-02 [H row3]). / now: every file-derived value (the display identifier or name, unit, conversion, limits, and each `_card_field` value) appended as `safe_text(…, style=…)`, which deletes C0 and C1 characters (`utils.py:32-99`); the layout, the styles and the address unchanged. The card is built from the tag dict, so it keeps the full name (its non-control projection) and the address; the card wraps at its own width.
module: s19_app/tui/app.py
examples: (AT-B103-I12-1, P design syn) SYNMAP → first painted line `✓ SYN_MAP_W  0x1C2D3E00` at 220, 160, 118, 100 and 80 columns (card `78`, `53`, `42`, `35`, `26` cells wide); no `0x` run in the card other than a declared address
examples: (R-TUI-042a.3/4, P design long) LONGMAP(48) at 118×54, card `42` cells wide → painted lines `✓`, `SYN_MAP_LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL`, `LL_END  0x1C2D3E00`: the name whole across the wrap and the address whole; holds on base, the card's text for a plain name being unchanged (the case's "first line" text: E2-5, corrected at E3)
examples: (R-TUI-042a.7/1, E3S-02 [H row3]) a name holding a synthetic ESC-introduced sequence and a U+009B-introduced one, no display identifier, the cursor on its row at 118×54 → the card's text holds neither character and the name's other characters in order; the screen output (`render_full_update().render_segments`) holds neither sequence (base, at 118 and 80: it holds the ESC sequence; the table cell of the row is clean, `safe_text`)
examples: (R-TUI-042a.7/2) the same two sequences in the DISPLAY_IDENTIFIER word → the same
examples: (R-TUI-042a.7 neg) raw `Text.append` (base) → the ESC sequence in the screen output → RED (a mutant of E5's table)

_card_field
req: R-TUI-042a.7
in: Text text; str label; object value
out: None
func: changed (E3S-02). was: skips `None` and `""`, else appends `"\n"`, the label and `str(value)` with `Text.append` (`app.py:1245-1275`). / now: the value appended as `safe_text(str(value), style=VALUE)`; the skip, the label and the line end unchanged.
module: s19_app/tui/app.py
examples: (R-TUI-042a.7/3) a long identifier holding the two sequences → the `desc` line holds neither character and the description's other characters in order; the screen output holds neither sequence
examples: (holds on base) `None` or `""` → no line

## Entities

[Interface: A2L Explorer tag table]
desc: `#a2l_tags_list`, an `A2LTagTable(DataTable)` (`A2LTagTable(_CopyRowTable)` once Inc 1b lands) with `cell_padding=1` and `fixed_columns=2` (I-12.2); 16 columns in CTX-A2L-SCREEN order; one page of at most 200 rows (`a2l_tags_page_size`, `app.py:2809`).

[Data: A2L Explorer tag table rows]
desc: the painted page; the form of its Tag cells is the only state the fit compares (I-12.3).
sequence:
  loadWhileHidden: S19TuiApp.update_a2l_tags_view (name width None: the 34-cell form) → S19TuiApp._fit_a2l_tag_cells (no width: returns)
  key2: A2LTagTable.on_resize → S19TuiApp.on_a2l_tag_table_measured → S19TuiApp._fit_a2l_tag_cells → S19TuiApp._repaint_a2l_tag_cells wins
  terminalResize: S19TuiApp.on_resize (regimes and context line only) → A2LTagTable.on_resize → S19TuiApp.on_a2l_tag_table_measured → S19TuiApp._fit_a2l_tag_cells → S19TuiApp._repaint_a2l_tag_cells wins
  pageChange: S19TuiApp.update_a2l_tags_view (w from the previous page's layout) → S19TuiApp._fit_a2l_tag_cells → S19TuiApp._repaint_a2l_tag_cells wins (only when Address, Length or the vertical scrollbar changed)
  imageWrite: _refresh_a2l_values_after_write (b101 Inc 10b) → S19TuiApp._repaint_a2l_tag_cells wins (w measured on the current layout, E3A-01)

[Data: A2L tag table columns]
desc: `ordered_columns` and their content widths. textual 8.2.8 sets `content_width = max(content_width, cell width)` for every new row (`_data_table.py:1441`) and `clear(columns=False)` keeps the columns (`:1582-1607`), so a width only grows while the app runs (E2-4).

[Data: S19TuiApp._a2l_row_key_to_tag]
desc: `a2l:<absolute index>` → the tag dict, in row order (`app.py:20355`); read by the fit and by `coordinate_to_cell_key((row, 0))` users through the row key (`app.py:9763`); Inc 1b's copy source (I-1).

[Data: S19TuiApp._a2l_filtered_tags]
desc: the list all 6 callers of `update_a2l_tags_view` pass (or `[]` with no A2L, X); the fit rebuilds the page from it.

[Data: _SESSION_SNAPSHOT_NAMES]
desc: `app.py:2595`; with `tests/test_b100_session_reset.py:1144-1157` it forbids a new `self.<name> =` in `S19TuiApp` (I-12.3).

[Interface: A2L detail card]
desc: `#a2l_detail_card`, `A2LDetailCard` with `_a2l_detail_card_text(tag)`: the full name and address of the highlighted row.

[Outside: terminal resize]
desc: the operator resizes Windows Terminal; textual forwards it to the screen after a 1/120 s timer.

[Outside: rail key 2]
desc: key `2` (or the rail click, or the palette) runs `action_show_screen('a2l')`.

## Edges

[Outside: terminal resize] ──▶ A2LTagTable.on_resize
when: the A2L Explorer is shown, so the table's size changes
[Outside: rail key 2] ──▶ A2LTagTable.on_resize
when: the tag table was hidden, its size (0, 0)
A2LTagTable.on_resize ──▶ S19TuiApp.on_a2l_tag_table_measured
S19TuiApp.on_a2l_tag_table_measured ──▶ S19TuiApp._fit_a2l_tag_cells
S19TuiApp.update_a2l_tags_view ──▶ S19TuiApp._fit_a2l_tag_cells
when: after the next refresh, for a page with rows
S19TuiApp._fit_a2l_tag_cells ──▶ S19TuiApp._repaint_a2l_tag_cells
when: a painted Tag cell differs from the form for the measured w (at E2 the target was S19TuiApp.update_a2l_tags_view; E3A-01 (4))
[Data: A2L tag table columns] ──▶ S19TuiApp._a2l_tag_name_width
[Data: S19TuiApp._a2l_row_key_to_tag] ──▶ S19TuiApp._fit_a2l_tag_cells
[Data: S19TuiApp._a2l_filtered_tags] ──▶ S19TuiApp._fit_a2l_tag_cells
S19TuiApp.update_a2l_tags_view ──▶ [Data: A2L Explorer tag table rows]
S19TuiApp._repaint_a2l_tag_cells ──▶ [Data: A2L Explorer tag table rows]
S19TuiApp._build_a2l_table_cells ──▶ [Interface: A2L Explorer tag table]
[Data: S19TuiApp._a2l_row_key_to_tag] ──▶ S19TuiApp.on_data_table_row_highlighted

## Findings

> E2-1 (deviation from `../E1-slice.md`, for E3). The resize trigger is not `S19TuiApp.on_resize` (slice #5, now unchanged) but the tag table's own resize: a new class `A2LTagTable(DataTable)` whose `on_resize` posts a bubbling `Measured`, handled by the new `S19TuiApp.on_a2l_tag_table_measured`. Measured: a fit scheduled from `App.on_resize` through `call_after_refresh` runs before the table's region changes (textual forwards the terminal Resize to the screen after a 1/120 s timer), so the 220→80 step kept the 220 form, painted past the visible width, 0 fit rebuilds (P full resize); with the table's resize, 1 fit rebuild and every Tag cell right (P design resize). The project met the same trap before and fixed it the same way (`BandBar.Measured`, `screens_directionb.py:1580-1647`). Slice after E2: 1 source file; 4 changed functions (`_compose_screen_a2l`, `_setup_datatable_columns`, `update_a2l_tags_view`, `_build_a2l_table_cells`), 4 new functions or methods (`_shorten_tag_name`, `_a2l_tag_name_width`, `_fit_a2l_tag_cells`, `on_a2l_tag_table_measured`) and 1 new class with 1 method (`A2LTagTable.on_resize`); `on_resize` taken out. The slice allowed one new helper; E3 rules on the rest.
> E2-2 (for E3). No show trigger: `action_show_screen` stays unchanged. A hidden table's size is `(0, 0)` (P design rehide), so showing the A2L Explorer always gives it a Resize. Measured: a page rebuilt while hidden and then shown at the same size is fitted (P design rehide 1/1; P widgetnoshow rehide 1/1, P widgetonly rehide 1/1); with the fit only from `App.on_resize`, 0/1 (P noshow rehide). The trigger also covers every route that shows the screen without naming it: the rail, keys `1` … `9`, the palette, the Split / Join window's close and the map's "open in hex" (X: 6 callers of `action_show_screen`). An earlier rehide run that put its spy on the subclass shadowed the subclass's `on_resize` (one of `_on_x` / `on_x` per class); the spy was moved to `DataTable` and the runs repeated (the transcripts kept are the repeated ones).
> E2-3 (for E3). The fit after every page build is needed, besides the resize: a page that widens the Address column (a 64-bit address on page 2) or that toggles the vertical scrollbar (200 rows → 20) changes *w* after the build measured it. Without it: page 2 0/28 (P widgetonly flip, P widgetnopost flip, P nopostfit flip), page 2 0/20 and back on page 1 0/28 with the Tag cell painted past the visible width (P widgetnopost flipbar). With it: 28/28, 28/28, 20/20, 28/28 (P design flip, P design flipbar). Cost: the comparison runs once per build, `5.9` ms on a 200-row page; a rebuild repeats one page build (`15.2` ms median).
> E2-4 (for E3; a decision, nothing PROPOSED). Column widths only grow (textual 8.2.8, R): after a page or a file with a 64-bit address, the Address column stays 16 cells wide for every later page and file in the session, so *w* on later 32-bit pages is 4 smaller (P design flip: page 1 *w* 12 before visiting page 2, 8 after). Every row still holds (*w* is computed from the actual widths), and the Tag column already behaves so on base (the widest name ever shown sets its width; P design long at 80: Tag column `38` cells for a 16-cell Tag cell). Options: (a) accept and record (recommended: no requirement asks otherwise, the cases use one page per app); (b) reset each column's content width to its label's at every build, which writes textual's `Column.content_width` (a dataclass field, not a documented setter).
> E2-5 (for E3: case texts that the measurements contradict; the requirement rows hold). (a) R-TUI-042a.3/4 expects "the card's first line holds the 48-character name whole and `0x1C2D3E00`": at 118×54 the card is 42 cells wide and wraps, on base too — `✓` / `SYN_MAP_LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL` / `LL_END  0x1C2D3E00`. Proposed case text: "the card's painted lines hold the 48 characters of the name in order and `0x1C2D3E00` whole". (b) R-TUI-042a.4/4 expects the header to paint `Address` "from its column 0": with `cell_padding=1` it starts at x 1. Proposed: "the header line's first cell is `Address` (x 1, after its padding cell)". (c) Pages of more than about 28 rows at 80×54 have a vertical scrollbar (2 cells), so tracked files show *w* 2 cells smaller than F's numbers: at 80 columns names longer than 12 cells are shortened, not 14 (`../01-requirements.md` "What else the operator sees", AT-B103-I12-2's labels). The cases' "recompute from the measured visible width" rule already covers the tests.
> E2-6 (E4 work: tests that change; R, `git grep` at `e07fb00`, plus the column arithmetic). Column-0 readers, to move to the column found by its label `Tag` (the idiom of `tests/test_b101_inc11_acceptance.py:510-512`): `tests/test_tui_a2l_detail.py:206` (`_name_cells`), `:324` (the hostile name cell; a hostile name wider than *w* is now cut in the middle, so the payload-presence loop is re-checked against the full name in the card or against a name under 34 cells), `:357-364` (TC-067.1: `cells[0]` → `cells[2]`); `tests/test_validation_service_supplemental.py:179-186`; `tests/test_tui_a2l_issue_recolor.py:178-189`; `tests/test_b102_a2l_refresh.py:137` (`:143` reads index 6, InMem, which stays). Painted-row reader found here: `tests/test_b99_a2l_encode.py:559-571` asserts at 118×40 that the painted rows hold the Physical values (`30.0`, `4113` twice, `40.0`); with the padding and the new order the Physical column starts at x ≥ 59 of a visible 60 (Address 12 + Length 8 + Tag ≥ 23 + Source 10 + Raw ≥ 6), so it is expected RED (R, not run) and moves to the cells read by label, or to the describe modal that the test's arms at both widths already read. Unaffected (R): `tests/test_b101_inc11_acceptance.py:424-426`, `:452-456` (row keys), `:510-512` (by label); `tests/test_legend_n8.py:523-536`; `tests/test_tui_directionb.py:7488-7530`; `tests/test_tui_app.py:540-580` (the view is stubbed); `tests/test_b100_session_reset.py:1144-1157` (I-12.3). The 6 snapshot baselines `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[a2l-{comfortable,compact}-{80x24,120x30,160x40}].svg` drift and are regenerated in the canonical CI env only. A run of these files on the design copy was stopped after 48 tests because the runner's `/tmp` (tmpfs, 16 GB) was full; its partial result is not evidence and is not kept. **E3 note (`../E3-rulings.md` E2-6, E3S-06, E3S-02):** the list is complete for its files (E3A §4, executed: 16 RED on the design, green on base; `test_b99_a2l_encode` RED as expected). Added: b101 Inc 10b's tests of `_repaint_a2l_tag_cells` (re-checked at the rebase for column-0 reads and the Tag text) and Inc 1b's right-click cases (Tag cell by label; R-COPY.4/3 per `../../inc-1b/E1-rulings.md`). The `:324` re-point offered above is withdrawn: AT-069c stays on the Tag cell, with payloads placed where they fit and one across the cut, asserting the exact shortened text, no spans and no control character (E3S-06). AT-069b (`tests/test_tui_a2l_detail.py:279-283`) re-points to each payload's non-control projection (E3S-02).
> E2-7 (for E3, the operator's captures; no row). At *w* ≤ 9 the middle cut no longer keeps names that share a long prefix and a short suffix apart: V161's `….COLUMN_DIR` and `….ROW_DIR` both read `ASAM…_DIR` at *w* = 9 (S), the width of a page with a 64-bit address at 80 columns. The cursor row, the detail card (full name) and Inc 1b's copy (full name) still identify the tag; no requirement asks for distinct cells. **Corrected at E3 (E3S-03, E3A-04; ruled: no floor):** names read alike much earlier than *w* ≤ 9. On one 200-row page of the tracked files (E3S [K]): 46 names in 4 files at *w* = 34, 319 in 5 files at *w* = 12 (V171 88 of 118, V161 59 of 75, BalanceTube 98 of 111, from_source 72 of 72); per file over 234,648 tracked tags (E3A [C]): 46 at *w* = 34, 293 at *w* = 14, 220,359 at *w* = 12, the ordinary 80-column page with a vertical scrollbar. The Address cell (whole, first) and the card (safe once R-TUI-042a.7 lands) tell the rows apart; AT-B103-I12-2 shows it to the operator.
> E2-8. Size: 4 rows; 13 nodes — changed 4, new 5 (one of them the method of the new class `A2LTagTable`), removed 0, context 4 (`on_resize` and `action_show_screen`, unchanged after the measurements; `on_data_table_row_highlighted`; `_a2l_detail_card_text`); 9 entities, 12 edges; 1 source file. Under the 40-node cap; no split.
> E3 correction (2026-11-07, `../E3-rulings.md`). Size: 6 rows; 15 nodes — changed 7 (+ `_a2l_detail_card_text`, from context, and `_card_field`, E3S-02; + `_repaint_a2l_tag_cells`, b101 Inc 10b's, changed at the rebase, E3A-01), new 5 (`_shorten_tag_name` now projects to U+FFFD and slices, E3S-01; `_fit_a2l_tag_cells` now repaints in place, E3A-01 (4), E3A-06, E3A-09, E3S-07), removed 0, context 3; 9 entities, 13 edges; 1 source file, `app.py`. E3S-04 is closed by R-TUI-042a.6. Under the 40-node cap; no split.

### Coverage (every requirement and case → node and example)
| Requirement or case | Nodes | Examples (source) |
|---|---|---|
| R-TUI-042a.2 | `_compose_screen_a2l` | R-TUI-042a.2/1 (220, 160, 118: 0 glued strings), R-TUI-042a.2/2 (100, 80), neg `cell_padding=0` (P design syn, P base syn) |
| R-TUI-042a.3 | `_build_a2l_table_cells`, `_shorten_tag_name`, `_fit_a2l_tag_cells`, `_a2l_detail_card_text` | /1 (n = 46 … 54 at 118, 4/4), /2 (n = 100 at 220), /3 (34 whole, 35 cut), /4 (the card; E2-5 (a)) (P design long; S) |
| R-TUI-042a.4 | `_compose_screen_a2l`, `_setup_datatable_columns`, `_build_a2l_table_cells` | /1 40/40 unscrolled, /2 40/40 scrolled right (P design p64), /3 PAGE64W 2/2 (P design p64w), /4 the 16 labels in order (P design order; E2-5 (b)); neg F configs B and C |
| R-TUI-042a.5 | `_a2l_tag_name_width`, `_build_a2l_table_cells`, `_shorten_tag_name`, `update_a2l_tags_view`, `_fit_a2l_tag_cells`, `A2LTagTable.on_resize`, `on_a2l_tag_table_measured` (context: `on_resize`, `action_show_screen`, `on_data_table_row_highlighted`) | /1 *w* 14, 22, 25 (P design long), /2 LONGMAP(20) at 80, /3 *w* 9, 17, 20, 31 (P design p64), /4 *w* 84 and 79 at 220, /5 *w* 5 (P design p64w), /6 220→80→220 with no key (P design resize); /7 the repaint after an image write (`_repaint_a2l_tag_cells`; E3A [O repaint10b]); /8, /9 the page-change fits (P design flip, flipbar); also the hidden rebuild (P design rehide) and the in-place repaint (E3A [O inplace]); negs: the fixed 34-cell form (F), the App.on_resize trigger (P full resize), no fit after a build (P widgetnopost flip, flipbar), the repaint without the width (E3A [O repaint10b]) |
| R-TUI-042a.6 | `_shorten_tag_name` | /1 the U+200B tails, /2 the combining-mark and ESC tails, /3 plain ASCII unchanged (E3S [U cost tail], [U fix model]); neg the E2 raw-name `cell_len` loop (33.6 s) |
| R-TUI-042a.7 | `_a2l_detail_card_text`, `_card_field` | /1 the name, /2 the display identifier, /3 the description (E3S [H row3], the base state); neg raw `Text.append` |
| AT-B103-I12-1 | `_compose_screen_a2l`, `_build_a2l_table_cells`, `_a2l_detail_card_text` | every `0x[0-9A-F]+` run painted in the table and the card is a declared address, and every Tag cell ends inside the visible width, in every P design transcript (syn, long, p64, p64w, resize, flip, flipbar, rehide: "painted 0x runs not declared: none"); the card line `✓ SYN_MAP_W  0x1C2D3E00` |
| AT-B103-I12-2 | — | not coverable in the graph: its expected result is the operator's verdict on real captures at E5 (D-2 A); E2-5 (c) and E2-7 (corrected at E3: E3S-03, E3A-04, E3A-05) are for its labels |

> Every row of `../01-requirements.md` and every case of `../02-test-cases.md` except AT-B103-I12-2 has at least one concrete example.
