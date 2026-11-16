# Inc 8b — E3 rulings (orchestrator relevo-15)

Review: `E3-review.md` (08bc1674), verdict FAIL, 4 MAJOR, 4 MEDIUM, 4 MINOR, 3 INFO. One corrector applies the accepted fixes with targeted edits (no rewrite); no re-review unless a fix changes an interface beyond the ones named below (skill E3; rule DF-03).

| Finding | Severity | Ruling | Action |
|---|---|---|---|
| E3-8b-01 | MAJOR | Accept. Inc 9b keeps R-PE-BENCH.94–.106 (its graph and cases already use them). | Renumber Inc 8b's .94 → **.107**, .95 → **.108** in every place listed in `E3-review.md` answer 3; regenerate the E1 trace transcript, never hand-edit it. |
| E3-8b-02 | MAJOR | Accept the proposed fix. | Pin `StagingSheet._detail_geometry()` in the graph; `ArrayBenchSheet._bench_geometry` (`bench_sheet.py`) uses it; add `bench_sheet.py` (that one function) to the slice, group W; requirement and example so R-PE-BENCH.36 holds. |
| E3-8b-03 | MAJOR | Accept. | Pin a plain `Container` (no focus, no bindings) for the scroller; state in the graph which widget owns ←/→ and Home/End; example: ←/→ on an enum row choose an entry, Home/End do not animate. |
| E3-8b-04 | MAJOR | Accept. | Add R-PE-DEF.114 (`If` the current or new value is NaN or infinite, then the limits cell shows a fixed no-position form; exact text pinned), cases, graph guard and example (erased FLOAT32 `FF FF FF FF`). |
| E3-8b-05 | MEDIUM | Accept. | Pin the body's height rule under the scroller in group W; example of `visible` at 118×54. |
| E3-8b-06 | MEDIUM | Accept. | Card widths counted in terminal cells; title and option texts cut with `…` by cells; hostile-text `If` rows (control, wide characters) for the card, with examples. |
| E3-8b-07 | MEDIUM | Accept. | Collision rule for the two marks that never moves a mark onto the `┤` at offset 25 (e.g. the second mark moves left at the right end); example at cell 16. |
| E3-8b-08 | MEDIUM | Accept; owner is Inc 9b. | Inc 9b's E4 measures O-E against Inc 8b's merge (and at its own tip), not 09001bbc. The orchestrator carries it into the Inc 9b E4 brief and records it in `inc-9b` at its E4 open. No Inc 8b edit. |
| E3-8b-09 | MINOR | E4 addendum. | Listed in `E3-addenda.md` for the tester. |
| E3-8b-10 | MINOR | E4 addendum. | Same. |
| E3-8b-11 | MINOR | E4 addendum. | Same. |
| E3-8b-12 | MINOR | Accept as a visible change. Widening GREEN inside `#patch_editor_panel` to "passed or staged (`●`)" restates an earlier operator rule, so it needs the operator's verdict (DF-09). | Corrector writes it into the CTX-PE-DEF style table (not only §4 of `E1-rulings.md`); orchestrator adds it to the operator page as **V8b-13**. |
| E3-8b-13 | INFO | Noted. | E4 group S: one implementer, two testers (render rows; card and limits). |
| E3-8b-14 | INFO | Noted. | E5 checks the 220-column seam against `D.off.sheet.220x60.png`. |
| E3-8b-15 | INFO | Noted. | Batch end: merge both CTX-PE-BENCH amendments in the canon fold-in. |

E4 order (confirmed by E3 answer 8): Inc 8b first; it owns the `bench_sheet.py` edit at `_bench_geometry` only (`:138`, `:288`, `:592` hold unchanged). Inc 9b's E4 starts from Inc 8b's merge. E4 groups: **S** `definition_sheet.py`; **B** `definition_bench.py`, `insight_style.py`; **W** `sheet.py`, `bench_sheet.py` (`_bench_geometry` only), `a2l_parameter_picker.py`, `window_help.py`. W holds 4 source files, at the cap.
