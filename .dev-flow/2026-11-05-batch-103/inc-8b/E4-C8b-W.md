# Inc 8b E4 — C8b-W hand-back (group W)

Model Sonnet (claude-sonnet-5-5). Files: `patch_editor/sheet.py`, `patch_editor/bench_sheet.py` (`_bench_geometry` only), `a2l_parameter_picker.py`, `window_help.py` (4 of 4). No tests written.

## Procedure
DeepSeek v4-pro was tried for unit 1: `opencode run` returned "Insufficient Balance" (no quota). Done by me directly (MD-01 fallback).

## Done (graph nodes)
`compose` (plain `Container` `#patch_sheet_grid`, bar outside), `DEFAULT_CSS` + `BINDINGS` (home, end), `action_scroll_grid`, `_view_width`, `_detail_geometry`, `_paint`, `_fit_window`, `_SheetBody.on_resize` (ancestors), `ArrayBenchSheet._bench_geometry`, picker label `▽ Pick`, help line.

## Deviations
1. `action_scroll_grid` uses `scroll_to(x=…, animate=False, immediate=True)`. Without `immediate`, Textual defers the scroll, and x read right after the call is 0 (R-PE-DEF.94/6 RED). The example wins.
2. Added `StagingSheet.on_resize` (repaint). Finding: a width-only resize (118x54 -> 80x54) leaves the body at 143x52 and Textual sends it no Resize, so nothing repainted (paints 0). E3-8b-11's premise is wrong; the case R-PE-DEF.81/6 needs this handler. No interface change.
3. `header_rule` as landed by S takes `widths` (graph: `header_rule()`); W calls `header_rule(widths)`. Interface mismatch S vs graph: integrator to decide; testers must not call `header_rule()`.

## Examples run (rtx, HT-02 env, tree = HEAD a361893d product, SheetApp harness, load 0.4)
- G3: scrollbar True at 118x54 and 80x24 (virtual 143), False at 220x60; scroller class is `Container`, can_focus False. Held.
- G4/G6: harness V = full width (118/80/220, no chrome), so End gives 25/63/0 = 143 - V; the app's V (111/73/195) gives 32/70/0 by the same formula. x read right after End, no pause: held. Home -> 0 held. Key end/home through pilot held. Real-app 111/73 NOT run (needs the full app; AT tester).
- G6: ENUM_0001 + `right` -> pending `RUN`, scroll x 0. Held. Tab order: input/body only, grid never focused. Held.
- W1 harness 118x54: grid 53, body 52, room 49 (visible 50). Held. 80x24: 23/22. 220x60: 59/59 (no bar takes its row).
- W2 `_detail_geometry` arithmetic matches the graph (107,17), (69,5), (191,17) by reading; not executed with those body heights. `_bench_geometry` not executed (no bench smoke): NOT RUN.
- Resize: 118->220->80 repaints; width-only 118->80->220->118 repaints after deviation 2.
- P1/P2: help line holds `↑↓ enter ←→ home end esc`; picker source has the compact label. Runtime region at 80x24 (113/2) NOT RUN. `tests/test_b97_chips_help.py` was started on rtx (result not collected).

Scratch `~/work/zq-e4-8b-C8b-W` deleted.
