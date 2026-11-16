# Inc 9 E5 — real Windows Terminal captures (X9, HT-10)

Commit `811198b5`, taken 2026-11-14 08:03–08:27 (CST, from `date`) by X9's capture worker (Sonnet) under the capture lock
`wt-capture.lock` (acquired 08:00:31, released 08:29:23). 78 PNG + 78 sidecars in `evidence/e5/captures/` (`<scene>.<WxH>.png`,
`.png.txt`); factual index `evidence/e5/captures/INDEX-facts.md`; scripts `evidence/e5/captures/scripts/` (adapted from CAP8).
Every scene at 118x54 and 220x60; V-14 at 80x24. Fixture data only (DEFC `make_release_case.py --case definitions`, hand-made
VB1D / NTC_BLK / TAB_VB / F32_BLK / REF_BLK, LARGE). Four scenes hold I-2 `decode_values` / `encode_values` until the PNG is taken
(`v2-summary`, `v6-decoding`, `v13-decoding`, `v10-encoding`), so a millisecond state is visible; results unchanged.

**Every verdict below is provisional, awaiting the operator's confirmation on the final page (P-059, DF-09).** "Keep" = the
capture matches the requirement and the ruling; "change" = a finding (listed in `E5-review.md`).

| V | Scene | Files | Provisional verdict | Reason |
|---|---|---|---|---|
| V-1 | bench open: subtitle, LANDS IN 6 rows | `v1.*`, `i8v13.*`, `v7-nofocus.*` | keep | Subtitle `enter edit · ↑↓ row · arrays open the bench`, `-bench` class, LANDS IN 6 rows with border (R-PE-DEF.1.2). `↑ <k> more rows above` never paints: R-PE-BENCH.2 is withdrawn (E3A-04), so §6's text is stale, not a defect. |
| V-2 | array rows | `v2.*`, `v2-summary.*`, `v2-large.*` | change (MINOR) | `MAP 4x3`, strips, `◆`/`●`, `max \|Δ\|`, limits as specified. But VB1D / LARGE paint a 16-cell strip and hide the count (`… `) where R-PE-BENCH.18's formula gives 14 cells and the count; where the count fits it runs into the New cell (`4·`, `41 cells`). F-X9-5. |
| V-3 | curve chart | `v3.*` | keep | Real DEFC values, edited bars in the edit colour, old level, ticks `242.500 pt`, legend; C9's D-6 chart look reads clearly. |
| V-4 | map grid | `v4.*` | keep | Shaded cells, `*` on edited cells, axis texts `224 577 648 909` / `10 15 20` as breakpoints (D-6 A). |
| V-5 | VAL_BLK 1-D and 2-D | `v5a.*`, `v5b.*` | change (MINOR) | Layouts right (16 columns with row offsets; 3x2 with `0 1 2` / `0 1`). The 2-D op-line label loses its closing `]` (`VAL_BLK_DEF_0001[x0..1,y0..1 op =`) at 118 and 220. F-X9-6. |
| V-6 | large object | `v6-decoding.*`, `v6-window.*`, `v6-paged.*` | keep | `decoding 1048576 values …`, window line `rows 0..16 of 65536 · cols 0..15 of 16 · pgup/pgdn page`, paging moves the window. |
| V-7 | cursor, selection, focus, Escape | `v7-focus.*`, `v7-escape.*`, `v7-nofocus.*` | keep | `▸`, selection bar / underline, Escape drops the bench focus (D-2 A). |
| V-8 | tool row and results | `v8-interp.*`, `v8-smooth.*` | keep | Tool row with the current tool highlighted; Interpolate and Smooth give the D-7 A / D-9 A values. |
| V-9 | op line verdicts and cut | `v9-ok.*`, `v9-notice.*`, `v9-refused.*`, `v9-cut.*` | keep (wording note) | `✓`, `▲ 1 notices`, `✗ …`, cut with `…`. `1 notices` / `1 cells` follow the requirement text literally; plural agreement is a wording question for P-026 (F-X9-7). |
| V-10 | bytes line | `v9-ok.*`, `v10-cut.*`, `v10-encoding.*`, `v9-refused.*` | keep | `<k> of <n> B differ +0x…`, `encoding …`, `✗ refused: …`, cut with `…`. |
| V-11 | definition line with layout word | `v1.*`, `v3.*`, `v4.*`, `v5a.*`, `v5b.*` | keep | Layout word (`RL_U16`, `RL_DEF_MAP`, …) on every bench row (C-6). |
| V-12 | record stage | `v12-staged.*`, `v12-notice.*`, `v12-refused.*`, `v12-empty.*` | keep | Row stays selected `▶●` (D-3 A), `staged as 2 values (12 B at 0x800090)`, notice and refusal statuses, edit kept on refusal. |
| V-13 (Inc 9) | tool statuses | `v13-decoding.*`, `v13-undo.*`, `v13-nan.*`, `v13-texts.*`, `v13-novalue.*`, `v13-columns.*`, `v13-columns-smooth.*` | keep | All six statuses reached with their texts. |
| V-14 | bench at 80x24 | `v14-map.80x24`, `v14-large.80x24`, `v1.80x24`, `v9-cut.80x24`, `v10-cut.80x24`, `v10-encoding.80x24` | change (MINOR) | Narrow grid right (5-cell columns, window line), but the op line / formula bar is below the visible screen (the panel scrolls, scrollbar shown) in five of six scenes, and the tool row is cut `shi…`. R-PE-BENCH.5 holds by its letter (widths, room); the operator cannot see the op line without scrolling. F-X9-8. |
| Inc 8 V-13 | bench subtitle + LANDS IN 6 rows | `i8v13.*` | keep | Same facts as V-1; deferred by CAP8 because Inc 8 had no bench. |
| W-8 extra | after a refused decode | `x-refused-decode.*`, `x-refused-row.*` | change (provisional W-8 ruling) | REF_BLK: Current `--` (R-PE-BENCH.14 holds) but the bench keeps `decoding 6 values …` after the refusal — a false progress line. F-X9-4. |

Not captured: R-PE-BENCH.14's "no image" case (only the missing-last-byte case); V-14 at 118/220 (not asked).
Windows: 78 launcher windows closed by the launcher; 4 orphan windows (`v6-decoding`, `v13-decoding` at 118 and 220) closed with
WM_CLOSE by their own GUID titles; the shared Windows Terminal host process was not killed.

## Re-check X9r (relevo-14): V-2, V-5, W-8 and the O-B JSON view after FX9b, FX9c, FX9d

Commit `ab62093b` (control: `b21d5517`, the tree before FX9d's O-B), taken 2026-11-14 14:54–14:59 (CST, from `date`) by X9r under
the capture lock `wt-capture.lock` (acquired 14:54:51, released 15:00:30). 11 PNG + 11 sidecars `evidence/e5/captures/r-*`
(no X9 file overwritten). Same method and fixtures as X9 (`scripts/capture_i9.ps1`, `scripts/build_fixtures_i9.py`, isolated
HOME / XDG / LOCALAPPDATA, OS clipboard stubbed); the driver copy with two added scenes and the runner are in
`evidence/e5/captures/scripts-x9r/`. Every window was closed by its own launcher PID; none left open. Verdicts are
provisional, awaiting the operator's confirmation on the final page (P-059, DF-09).

| V | Scene | Files | Provisional verdict | Reason |
|---|---|---|---|---|
| V-2 (F-X9-5) | defc page: MAP pending, VB staged | `r-v2.118x54`, `r-v2.220x60` | keep | `▅▇▄█▁ 5`, `████ 12`, `███ 6`: count after the strip, nothing runs into New (`1 cell`). |
| V-2 (F-X9-5) | hand page: VB1D (40 elements, 16 columns) summarised | `r-v2-vb1d.118x54`, `r-v2-vb1d.220x60` | 118 keep; **220 change (F-X9r-1)** | 118: `████████ 40` = CTX-PE-BENCH's 18 − 1 − 2 − 1 = 14 cells, k = 2, 8 blocks, count visible. 220: also 8 blocks, where the Current cell is 44 wide (strip width 40, k = 1, 16 blocks; X9's pre-FX9b 220 captures painted 16). The strip is sized from a width read before the sheet's layout (likely the `or 118` fallback in `_start_next`). |
| V-5 (F-X9-6) | 2-D VAL_BLK, selection x0..1, y0..1 | `r-v5b.118x54`, `r-v5b.220x60` | keep | `VAL_BLK_DEF_00…[x0..1,y0..1] op =`: the where stays whole with its `]`; the name gives way with one `…`. |
| W-8 | REF_BLK, the image misses its last byte, Enter | `r-x-refused-decode.118x54`, `r-x-refused-decode.220x60` | keep | `✗ refused: REF_BLK: 1 of its 6 bytes are not in the image` in place of the decoding line; Current `--` (R-PE-BENCH.14). The message's `1 … bytes are` is I-2's text, not Inc 9's. |
| O-B | staged VB record, JSON tab, cursor on the `{` at (7, 4), view scrolled so its match `}` (12, 4) is on screen | `r-ob-json.118x54`, `r-ob-json.220x60`; control `r-ob-json-pre-fx9d.118x54` | keep (visible change, for the page) | Head: class `ReadOnlyJsonView`, `_matching_bracket_location=None`, the `}` paints plain. Control on `b21d5517`: class `TextArea`, match `(12, 4)`, the `}` paints with the bracket-match background. Textual's own scan would still find `(12, 4)` (sidecar). |
