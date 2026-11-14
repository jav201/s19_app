# Inc 7 E4 — implementation record (conductor C7, Sonnet driving DeepSeek v4-pro)

Tree `b103-inc7`, base `63791549`. One DeepSeek call per unit, fresh session, `timeout 2700`; at most two calls at once, on different files. Verification on <runner> (isolated env, `HOME` basename `runner_iso`, `timeout 300`, load 3-7, nothing timed). Examples were run as asserts in scratch scripts (not committed; deleted). The conductor wrote product code only to fix verified DeepSeek defects (listed).

| Unit | Commit | DeepSeek outcome | Verification (<runner>) |
|---|---|---|---|
| U-L6 `_take_paste`, `_on_paste`, `action_paste` | 022a16b8 | delivered | subclass host: stock box False and first line kept; subclass takes stripped text; `restrict` box never calls the hook; Ctrl+V path with the read patched: hook gets the stripped text. Held. |
| U-L1 L1-L5, L22 + constants, dataclasses | 38686e50 | delivered | 43 asserts (graph examples of is_list_text, display_text, resolve_label_list incl. equality, list_summary_texts incl. 4,906-name case, list_row_cells incl. KeyError, list_card_text). Held. |
| U-V4b styles.tcss | 993487b0 | delivered | rule set parsed by Textual in the app smoke; regions match P3/P4 (below). |
| U-L2 LabelRanker | 22871207 | delivered | basic delivery on a worker thread, limit capped at 20, per-key tokens, stale drop, empty generation; coalescing (2 `rank` calls for 6 requests); build failure then one retry, then 2 builds in all; teardown with a held build: 0 deliveries. Held. |
| U-L3 LabelSuggestBox, ListAwareFilterInput | 250cfef2 | delivered, **fixed by conductor** | rows/title/key lines/highlight/no-match/257-char/1,024-char/hostile rows, move clamp, tab/esc/up/down incl. SkipAction, `_take_paste` incl. 32,768 names (98,302 chars), `list_enabled` False. Held. Defects: (1) helper named `_render` clashed with Textual's `Widget._render` (crash at layout); renamed `_rows_text`. (2) no closed state: the box took space when closed; added `DEFAULT_CSS` (display none / `-open` block, `overlay: screen`). |
| U-V1 V2-V5 helpers | b0d90215 | delivered | smoke below. |
| U-L4 LabelListPasteModal (6 nodes + helpers) | 90ef1a61 | delivered | counts, ribbon, 12 preview rows, missing line, two similar lines in order, note, labels, add line + enter, 4,906 names -> 200 rows + more line, apply (alt+f) result, wide columns, hostile row. Held. DeepSeek added `#a2l_list_ribbon` (the ribbon had no id in I-7). |
| U-L5 cancel, refresh_tags, A2LExplorerBody | 81f357bd | delivered | regimes at body 130x60 stacked, 230x70 wide, 80x24 / 120x30 / 109x39 short, 160x40 stacked; alt+p, button, alt+a; esc closes dropdown then window; refresh_tags -> `10 found`, `1 missing`. Held. |
| U-V2 V6-V9 | 34cf4ece | delivered, **fixed by conductor** | smoke below. Defect: `_a2l_table_column_labels` iterated `DataTable.columns` (dict of keys); now `ordered_columns` (fix committed with U-V3). |
| U-V4a `_compose_screen_a2l` | a3d4a490 | delivered | smoke below. Split in two helpers by DeepSeek. |
| U-V3 V10-V13 | 65e2c88f | delivered | smoke below; `tests/test_b103_a2l_filter_teardown.py`: 1 passed. |

U-V4 was run as two calls (U-V4a compose_screens, U-V4b styles.tcss) to keep one file per call (MD-03); the slice lists it as one unit.

## App smoke (real app, case 08 from `tools/synth/make_release_case.py --seed 20260001`, 462 tags)
- 118x54: the G2 list typed into the filter -> 9 list columns, 12 rows (row 7 `✗ MAP_0024`, row 10 `dup of #1`, row 11 `✗ CURVE_0071`), chips and missing lines as the graph, summary `LIST  rows 1-12 / 12 in pasted order`; body 112x39 stacked, tags pane 112x25, hex pane 112x14, hex box 86 wide. Card on row 7 `✗ MAP_0024  not in this A2L / pasted #7 / closest —`; row 10 ends `duplicate of pasted #1`; mode Invalid: row 1 `◐ VALUE_0002 hidden: Invalid`, card ends `hidden by the active filter mode`, chips `◐ 9 hidden by mode`. `0017` -> dropdown open, first choice `MAP_0017`, text-mode table 5 rows. alt+p opens `LabelListPasteModal`; alt+f applies; Esc returns to text mode (`FILTER`).
- 220x60: `-wide`, body 196, tags pane 106, hex pane 90, card height 2.
- 120x30: `-short`, tags pane 54x15, hex pane 42, card 3 lines, table region 2 rows (>= 1, R-A2L-LIST.083/1).

## Not run / open
- Full pytest files of the clipboard retargets, the tc016s SVGs, Inc 12 tag-table tests: not run (E4 tests are the testers' and the integrator's). `tests/test_b103_a2l_refresh.py` + `tests/test_b102_a2l_refresh.py` hit `timeout 300` on a loaded runner with no verdict (111 items): not a result.
- U-V2/U-V1 were verified through the integrated smoke only (they need the whole module), after commit.
- Not checked: write-route rows (R-A2L-LIST.036/3-5), `refresh_tags` through `_refresh_a2l_dependent_views`, 080/083 at 160x40 and 80x24, markup AST guard file list, id registry count.
- Open questions for the orchestrator: (1) `LabelSuggestBox` is an `overlay: screen` box with no explicit offset; whether it sits under the filter row in the real terminal is for the capture round. (2) `_a2l_mode_keeps` duplicates the shipped mode test of the text-mode filter (two places must stay equal). (3) `ListAwareDetailCard` is imported at module level by `compose_screens.py` (no cycle at present).
