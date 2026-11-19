# U-MM — R-TUI-062.10.2 (Memory Map inspector subtitle) + R-TUI-062.10.3 test

Common files: frontB/FB-common.md, units2/TA2-common.md, and the U-MM unit brief.
HEAD: 4f76d9144890fe86c31a3c9400d7781267bb5dd2
Start: Thu Nov 19 04:36:36 PM CST 2026

| row | file:function | change (one line) | negative-control mutation (file:line, one line) | command | RED line under mutation | GREEN result after change | OPEN? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-TUI-062.10.2 | s19_app/tui/screens_directionb/memory_map.py:MemoryMapPanel.render_ranges (subtitle) + compose docstring text | border_subtitle "↑↓ · ↵ hex" -> "↑↓ move · ↵ inspect" (code + docstring) | memory_map.py:454 restore "↑↓ · ↵ hex" (one line) | pytest -q tests/test_b101_help_legend_docs.py::test_r_tui_062_10_2_1_inspector_subtitle_names_only_handled_keys | `E       assert '↑↓ · ↵ hex' == '↑↓ move · ↵ inspect'` | 1 passed (of 6-node final run) | no |
| R-TUI-062.10.3 | tests/test_b101_help_legend_docs.py::test_r_tui_062_10_3_1_row_glyph_is_enter_and_enter_inspects (new) | new test: each region row ends in "↵" and Enter inspects the focused row | map_parts.py:940 `if event.key == "enter":` -> `if event.key == "ctrl+enter":` (one line) | pytest -q tests/test_b101_help_legend_docs.py::test_r_tui_062_10_3_1_row_glyph_is_enter_and_enter_inspects | `E       AssertionError: {'enter_inspects': False, 'glyph_ends': [True, True, True, True], 'navs': [], 'screen': 'map'}` | 1 passed (of 6-node final run) | no |

## Deviations

1. Snapshot drift (left as-is per brief step 7, orchestrator regenerates): `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-120x30].svg` still paints the old subtitle (`↵&#160;hex&#160;`).
   Evidence: `grep -o '.\{0,10\}hex.\{0,10\}' "tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-120x30].svg"` -> `60;↵&#160;hex&#160;</te`
2. `s19_app/tui/styles.tcss:973` comment still quotes the old text (`subtitle `↑↓ · ↵ hex``) — left unchanged per brief step 7.
   Evidence: `grep -n "↵ hex" s19_app/tui/styles.tcss` -> `973: * is the full-height right "Inspector — 0xADDR" pane (subtitle `↑↓ · ↵ hex`).`

## Open questions

None.

## Final

git diff --stat:
```
 s19_app/tui/screens_directionb/memory_map.py |  4 +-
 tests/test_b101_help_legend_docs.py          | 78 ++++++++++++++++++++++++++++
 tests/test_tui_map_big.py                    |  2 +-
 3 files changed, 81 insertions(+), 3 deletions(-)
```

CR count: `git diff | grep -c $'\r'` -> 0

Final run (N0 + 2):
```
6 passed in 23.02s
```
(nodes: test_r_tui_062_10_2_1…, test_r_tui_062_10_3_1…, test_tc656_chrome_pane_titles_and_subtitles, test_r_tui_062_10_1_1…, test_r_tui_062_10_1_2…, test_r_tui_062_10_1_3…)

UNIT_DONE U-MM
