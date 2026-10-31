# Inc 9a — E13 captures (real Windows Terminal, truecolor)

Scenario `wa-files` (new in `tools/e13/run.py`, wired in `tools/e13/capture_all.ps1` as closed-panel only): project `P` (case 01) loaded, the Load-result panel dismissed. The temp folder holds seven files made through the long-path prefix: `plain.s19`, `[b]markup[red]text.s19`, `fw` + U+202E + `gpj.s19`, a 130-`x` name + `.s19`, `del` + U+007F + `name.s19`, `dot.s19.` and `space.s19 `.

Captures (`evidence/inc-9a/e13/`): `wa-files-closed.118x54.png`, `wa-files-closed.220x60.png`, `wa-files-closed.99x54.png`. Run with `capture_all.ps1 -Only wa-files`; `DONE failures=0`. The selftest printed `s19_app.__file__` inside the worktree.

Observed at 220x60 (Workarea Files panel):
- 5 rows, sorted by casefold: `[b]markup[red]text…` (literal brackets, no bold or red: LLR-172.6), `delname.s19` (U+007F removed), `fwgpj.s19` (U+202E removed; no reversed text), `plain.s19`, `xxxx…` (clipped by the panel width).
- No row for `dot.s19.` or `space.s19 ` (LLR-172.4d).
- No crash and no markup error in the status lines.

Observations (not 9a defects; routed to the backlog):
- OBS-9a-1: the panel is about 20 columns wide even at 220 columns, so long names are cut by the widget before the 120-character clip of `painted_names` is visible. The clip is proven by `tc_b100_39_rows_paint_names_literally`, not by the capture.
- OBS-9a-2: the status line of the scenario says "1 problem - details: p" for a clean project. It comes from the scenario's seed or from pre-existing project-check code, not from 9a; read from the capture only, not investigated.
