# Inc 12b E4 tester G-T3 (39 re-pointed nodes, 13 files) - notes

State: **executed**. Files edited: the 13 of `E1-slice.md` section 5 (tests only, no product file, no new node, node names unchanged). RED/GREEN run: base = `origin/main` `2f54c7de` (Inc 9 in), LAN Linux host 2, prefix `s19_i12t3`, `-n 8 --dist loadfile`; the 39 nodes expand to 54 pytest items (parametrised TC-B97-49, TC-B97-62 and AT-B97-14). Result on base: **54 passed in 206.93s, exit 0** (one complete run, read from its own output). Transcript: `.dev-flow/2026-11-01-batch-101/evidence/inc-12b/base-01-g-t3.txt` (redacted, grep-checked). Oracle controls: `.../base-01-g-t3-mutants.txt`.

Guards also run on the same host with the edited files in: `tests/test_address_census.py` + `tests/test_suite_hygiene.py` = 90 passed.

I-3 grep over `tests/` on the local edited tree (`git grep -n -w -e flow_help -e flow_canvas -e flow_blocks -e flow_kind -e flow_ext_session -e fx_help -e _flow_block_label -e _blocks_text -e _canvas_text -e _block_rows -e _Grid -e _plc_block -e _chip -e _wire_bend -e _wire_drop -e _block_width -e _short_ext -e _CANVAS_COLS -e _BLOCK_W -e _EXT_BLOCK_W -e _S_WIRE -e _S_LABEL -e _S_VALUE -e _S_HEAD -- tests`) printed **no line** (it was 58 lines on the tree before my edits: 57 in my 13 files plus Inc 9's helper line). `git grep -n -e '\._layout(' -- tests`: no line. (Run over all of `tests/`, so it also covers G-T4's new file at that moment.)

## How the nodes read and drive

- A kind is chosen by pressing `#flow_palette_<kind>` and waiting for that chip's `chip-selected` mark (the visible sign). In `test_b97_flow_builder.py` this is the shared helper `selected_kinds(panel)` (kinds whose chip carries the mark; exactly one expected) used by `choose_kind`; elsewhere a four-line local wait. No node sets or reads a kind select.
- The chain is read from `#flow_pipeline` (`render().plain` / `.spans`; note `render()` returns a Textual `Content`); the empty chain reads `No blocks yet`; the session from `#flow_name_strip` (tail of the path, so assertions compare the tail segments).
- Where a model-only emulation set `panel._blocks`, the node now calls `panel._refresh_blocks()` to repaint the pipeline (AT-128).
- "Hidden widget stays hidden" assertions are dropped (TC-B97-13, TC-B97-49, TC1804 comment); their guard is G-T4's walks (R-TUI-059.25/1, R-FX-SCR.4/1).

## Nodes: file | before | now | base result (all PASSED)

| Node (file) | Read or set before | Reads or does now |
|---|---|---|
| `test_tc_b97_13_pipeline_cards_and_cables_replace_list_and_canvas` (b97_flow_builder) | list and canvas hidden (asserted) | assertion dropped (walks guard it); cards, cables, kind order, empty line unchanged |
| `test_tc_b97_14_palette_offers_every_kind_in_order` | each click sets the kind select | each click marks exactly that chip `chip-selected` (`{k: [k]}`, stronger: also "only it") |
| `test_tc_b97_15_...`, `_17_...`, `_58_add_with_an_empty_field...`, `_58_add_notice_clears...`, `_51_space_presses...`, `_49_ribbon_paints_saved_then_unsaved`, `test_at_b97_07_...` | kind via `choose_kind` (waited on the select) | same helper, now waits on the chip mark (no line of their own changed) |
| `test_tc_b97_49_session_on_the_ribbon` | "session line not displayed" + ribbon tail | hidden assertion dropped; ribbon tail assertion kept |
| `test_tc_b97_51_keyboard_order_keys_and_chip_states` | `enter`/`space` on a chip sets the select | sets the chip mark (`selected_kinds == [kind]`) |
| `test_tc_b97_62_nul_pasted_into_the_add_form_is_refused` (9 params) | kind set by assigning the select | `choose_kind` presses the chip; NUL paste, refusal line, unchanged chain, Run without `ValueError` unchanged |
| `test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject` | via `choose_kind` | same helper; hostile card text, NUL refusal, kept chain unchanged |
| `test_at_b94_15_fb_a_surface_and_wired_patch_run` | canvas glyphs, 88 cols, canvas width | pipeline: cards `╭╮╰╯`, `in · `/`out` rows, 3 cards and 2 cables counted, lines within the pipeline width (92 at 120x30), rail <= 96, screen box 96x17 kept; canvas-only glyphs (stubs, bends, grid dots) dropped, gone with the canvas |
| `test_at_b94_16_a2b_wiring_rule_and_report_provenance` | `#2.out` on the canvas | `#2.out` on the A2B card |
| `test_at_b94_17_template_save_listing_import_and_dedup` | kind select via helper | chip press via helper `_add_ref_block` (now async, waits on the mark) |
| `test_at_b94_18_hostile_names_render_literally` | canvas text | A2B card: see Security below |
| `test_tc_b94_20_fb_a_composition_census` | one canvas, canvas glyphs, widths | one `#flow_pipeline`; cards, cables, `No blocks yet`; widths as AT-15; 80x24 floor kept |
| `test_at088b_check_ref_label_renders_literally` | `#flow_blocks` + `spans == []` | CHECK card; see Security |
| `test_at088_gating_selector_appends_block_own_op_check` | kind select | CHECK chip (new local helper `_choose_kind_chip`) |
| `test_flow_block_label_covers_check` | `_flow_block_label(...)` text | `pipeline_text([...], 24)` card: `✓ CHECK` / `◉ LOAD` head and the ref in the card (the function is gone; no hostile input in this node; the hostile CHECK ref is AT-088b's, which takes over) |
| `test_at006_report_bearing_flow_shows_report_row`, `test_at006_quarantine_card_painted_and_flow_unchanged`, `test_at005_dirty_guard_cancel_keeps_blocks_confirm_replaces` | `#flow_blocks` text | `#flow_pipeline` text (REPORT card head; kept ref `keep.s19`; before/after equality) |
| `test_r_flow_file_12_1_save_after_clear_holds_own_name`, `test_r_fb_save_8_1_refused_home_status`, `test_at_i9_3_linked_homes_refuse_saves` (Inc 9 file) | helper `_add_load_block` waited on the kind select == source | helper waits on the LOAD chip `chip-selected` (one line); the three nodes untouched |
| `test_tc_b97_32_flow_help_names_every_label`, `test_at_b97_14_help_chip_opens_a_body_covering_the_screen` (4 params) | wait on the select == kind | wait on the chip mark |
| `test_tc358_empty_flow_renders_without_crash` | `(no blocks yet)` in the list | `No blocks yet` in the pipeline |
| `test_tc361_gating_control_hidden_for_non_check` | set the kind select | press SOURCE, CRC, CHECK chips; `#flow_gating` display False/False/True unchanged |
| `test_at128_crc_node_renders_and_shows_status` | list updated from `_blocks_text()` | `_refresh_blocks()` then the CRC card in the pipeline (`CRC` and `crc.json`) |
| `test_tc356_crc_in_dropdown_and_builder` | `_flow_block_label(block) == "CRC  crc.json"` | CRC card: `⊕ CRC` head, `in · tpl` row, `crc.json` row |
| `test_at_flow_add_blocks_and_run_renders_result` (directionb) | `#flow_blocks` text | pipeline text, plus the new clause that LOAD, PATCH, WRITE-OUT heads are in order |
| `test_at_flow_block_label_markup_safe` (directionb) | `#flow_blocks` contains `evil[red].s19` | card `in · file` value row; see Security |
| `test_tc_b100_31_flow_session_folder_follows_q` | `W/Q` in the session line, `W/P` not | ribbon ends with `workarea/Q` tail (and not `workarea/P`) |
| `test_tc_b102_file_02_browse_beside_every_ref_field` | kind select = A2B | A2B chip pressed; wait on `#flow_ref_a` shown |
| `test_tc1804_builder_palette_select_and_config_row_gate` | EXT-STEP via select; session line `session: `; canvas `TERMINAL` | EXT-STEP chip; ribbon holds `session` and the project folder name; pipeline holds `EXT-STEP` and `terminal · human` (the card's mode tag) |
| `test_tc1817_builder_funnel_table_edits` | `.value = "source"` | LOAD chip pressed and awaited |

Imports tidied where a name became unused (`Select` in b94 and b102; `_flow_block_label` replaced by `pipeline_text`).

## Security nodes (E3 S-2, S2-2): hostile input before and after

All hostile inputs still fit a card whole at the nodes' sizes, so none was shortened; every kind is kept.

| Node | Input | Kinds before | Kinds after | Painted-text assertion |
|---|---|---|---|---|
| `test_tc_b97_62_nul_pasted_into_the_add_form_is_refused` | NUL in the add input (not a card) | NUL | NUL (unchanged) | one `FLOW-UNSAFE-REF` line naming kind and field; chain count unchanged; Run paints no `ValueError` |
| `test_at_b97_08_...` | hostile flow + NUL paste | markup, C0, C1, DEL, sentinel, NUL | same (unchanged) | card text equals `clip_tail(safe_text(payload))` whole, 0 control chars, no foreign span; one refusal line; chain kept |
| `test_at088b_check_ref_label_renders_literally` | `[bold red]sensor\x1b[31m[/]x[link=file:///etc/passwd]` (49 cells after scrub; fits the one card at 80x24) | markup tags, ESC | same, whole | `_HOSTILE_SCRUBBED` in the card text; the old `spans == []` could not stay (cards carry rule and colour spans): now no span cuts the text and exactly one span covers it; 0 control bytes (newline excepted) |
| `test_at_b94_18_hostile_names_render_literally` | `_HOSTILE_SYMBOL` minus NUL (34 cells after scrub; 2 cards at 120x30) | sentinel, markup, ESC, BEL, C1 x2, DEL | same, whole | the whole scrubbed payload in the A2B card, sentinel and `_evil[red]` literal, 0 control bytes, no cutting span, one covering span |
| `test_at_flow_block_label_markup_safe` | `evil[red].s19` | markup | same | literal on the `in · file` value row of the card, no cutting span, one covering span |

Finding while writing (fixed in the test): the product paints a ref twice, on the card's file row and again in the origin annotation row (`missing: <ref>`, through `safe_text`). A bare containment of the ref in the whole pipeline passed under the mutant that scrubs the card row with `Text.from_markup`. The directionb node now asserts on the card's own `in · file` value row.

Oracle controls run on a scratch copy of `flow_screens.py` (restored after each; log in `base-01-g-t3-mutants.txt`):
- `nul_add_refusal` returns `None`: 10 failed (the 9 TC-B97-62 params and AT-B97-08), RED as S-2 requires.
- card refs through `Text.from_markup` (the `scrub` lambda in `_card_rows`): 4 failed (AT-088b, AT-B94-18, AT-B97-08, the directionb markup node), RED. The directionb node was GREEN under this mutant before the row-precise fix.

## Standing guards and limits

- The 39 pass on base by design (visible oracles exist there). They prove the re-point did not change what each node checks on the base tree; they cannot show what changes after DeepSeek's removal. The first run on the edited `flow_screens.py` is the integrator's.
- Dropped clauses, with their guard: list/canvas/session line hidden (TC-B97-13, TC-B97-49, TC1804) are carried by G-T4's walks; canvas stubs/bends/grid dots (b94_15, b94_20) went with the canvas.
- Not run here: the full suite (orchestrator's one gate run); the I-3 command (1) over `s19_app` (needs DeepSeek's edit); `EXPECTED_SCANNED_TEST_FILES` in `test_id_registry.py` (integration).
- Widths are measured, not estimated: at 120x30 the rail is 94 wide, the pipeline 92 (3 cards of 28); at 80x24 the rail is 72, one card takes it.

## Findings for the integrator

1. Duplicate ref paint: the card row and the origin annotation both show a file ref (see above); any test that checks a hostile ref by containment in the whole pipeline text can pass on the annotation alone. Not a defect, but the S-2 mutant for E5 should be the `scrub` lambda in `_card_rows` (it is RED on all four nodes now).
2. `_refresh_blocks()` is called directly by `test_at128_crc_node_renders_and_shows_status` (replacing `.update(panel._blocks_text())`); it is in 12b's "changed" list, not removed, so it survives. If DeepSeek renames it, that node needs the new name.
3. Each file kept its own working-copy line endings; Git warns "LF will be replaced by CRLF" for two files (autocrlf), not a change of mine.
