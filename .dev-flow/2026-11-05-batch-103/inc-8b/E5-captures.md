# Inc 8b E5 real Windows Terminal captures (CAP8b)

- Worker: CAP8b, mechanical capture worker under the E5 reviewer X8b (relevo-16). Model: Sonnet 5.5.
- Tip: `7c4e377c` (branch `b103-inc8b`), run from a throwaway `git archive` copy (`python -I -B`, `PYTHONDONTWRITEBYTECODE=1`); the worktree got no `__pycache__`.
- Taken: 2026-11-15 02:58 to 03:06 (from `Get-Date`; the first scene was re-taken at 03:00 after the fixture change, see Notes).
- Method: adapted Inc 9 `capture_i9.ps1` / driver (scripts in `evidence/e5/captures/scripts/`: `build_fixtures_8b.py`, `capture_8b.ps1`, `capture_8b_driver.py`, `run_all_8b.ps1`). One real Windows Terminal window per PNG (own GUID title), truecolor (`NO_COLOR` removed, `COLORTERM=truecolor`), isolated `HOME`/`XDG_*`/`LOCALAPPDATA`, OS clipboard stubbed, keys through `App._press_keys`, window closed through the launcher PID it wrote (graceful release first, `Stop-Process -Id` fallback; never by name). Sidecars are sanitised (`<user>`).
- Fixture `grid8b` (temp only): DEFC seed 20260001 plus `TEXT_0001` (ASCII, 42 B) and `NAN_0001` (FLOAT32, image `FF FF FF FF`); `CURVE_DEF_0001` and `VAL_BLK_DEF_0001` dropped so the 7-row `_0001` page (number, enum, two bit masks, array, text, NaN) and the selected row's detail fit in the body window.
- Lock: `wt-capture.lock` taken 02:58:53 (`CAP8b (X8b-e5, relevo-16)`), deleted 03:06:11 after the last window closed.
- 22 PNG + 22 `.png.txt` (118x54: 1724x1608 px; 220x60: 3152x1776 px; 80x24: 1192x768 px), all opened and in colour (blue/purple/orange UI, not monochrome), all `surface=ready`. Plus one extra pair `x-grid-9rows.118x54` (first take, see Notes).

## Captures

Verdicts are against the approved look (`3db20532` D/B) and the requirement ids named; the reviewer decides.

| scene | files | verdict | reason |
|---|---|---|---|
| grid | `grid.118x54`, `grid.220x60`, `grid.80x24` | matches | Header, `━┿` rule and `│` gutters present; Limits starts at the same cell on all 7 rows (R-PE-DEF.104); at 118 the grid is cut at the view (scrollbar shown), at 220 the Limits tracks end with `┤` and the Δ column is visible. |
| end | `end.118x54`, `end.220x60`, `end.80x24` | matches | After End at 118 the grid starts at Kind's last cell and Current ... Δ are visible with the track fully drawn; at 80x24 the horizontal scrollbar is shown and Unit ... Δ are visible; at 220 End does not move (no scrollbar) (R-PE-DEF.92-.94). |
| home | `home.118x54`, `home.220x60` | matches | Back to x = 0, identical to `grid` (118: scroll_x 0). |
| enum | `enum.118x54`, `enum.220x60` | matches | `ENUM_0001 · choose one` framed card with `(●) 1 IDLE`, `↔ choose · enter stage`, under the `└ TAB_VERB` line (R-PE-DEF.108/1, R-PE-DEF.33). |
| bit | `bit.118x54`, `bit.220x60` | matches | `bit editor · other bits kept` card, nibble guides `│` every 4 bits, `■` on the 0FF0 mask bits, before/mask/after rows and hex column (R-PE-DEF.108/2). |
| text | `text.118x54`, `text.220x60` | matches | `text editor · 16 B per row` hex/ASCII grid: `off │ +0..+7 │ +8..+F │ ASCII`, rows `+00 +10 +20`, `·` for non-printable bytes, ASCII guide at the same column on every row (R-PE-DEF.35, .110, .111). |
| expanded | `expanded.118x54`, `expanded.220x60` | matches | MASK_BIT_0001 expanded between ENUM_0001 above and MASK_FIELD_0001 below: `  ┊ ` bar, expanded ground band behind the object, neighbouring rows keep the plain ground (V-11, R-PE-DEF.108). At 220 the ground band runs to the window edge, not to the grid edge (see (c)). |
| filter | `filter.118x54`, `filter.220x60` | matches | Filter row shows `7 of 7 shown  <  Page 1/1  >  ▽ Pick  Add list`; the compact include chip reads `▽ Pick` (R-PE-DEF.113/1, V-2). |
| array | `array.118x54`, `array.220x60` | matches | MAP_DEF_0001 Current cell shows the strip `▃▇▃ 12` in light grey, short bars, no ground block, no full-height `█` (F-R14-1, R-PE-BENCH.107/3). The bench below (shade legend, cell bars) is the array's bench canvas, not the summary strip. |
| nan | `nan.118x54`, `nan.220x60` | matches | `NAN_0001` Current `nan`; Limits cell `-40 ├──────?──────┤ 150` at 220 (`?` at cell +16, no `●`), the same cut form at 118 (R-PE-DEF.114/1, R-PE-BENCH.108). |

## Measurements

(a) Limits column at 118x54 (`grid.118x54.png.txt`): the gutter `│` before the Limits column is at screen cell 92 and the column starts at cell 93 (grid x 87) on all six row kinds: number (DISPLAY_0001), enum (ENUM_0001), bit mask (MASK_BIT_0001, MASK_FIELD_0001), text (TEXT_0001), array (MAP_DEF_0001), NaN (NAN_0001). All equal: yes, aligned. Inside the cell, relative to its start: `├` at +8 on number, enum, bit mask and NaN rows; `…` at +16 on the array row; `-` at +16 on the text row; `?` at +16 on the NaN row; at 220 `┤` at +25 on every track row. First printed characters: `0` at +5 (enum, bit mask), `-40` at +3 (number, NaN), `-1.00k` at +1 (array).

(b) Horizontal scroll (`grid:` line of each sidecar; the grid is 143 cells wide):
- 118x54: after End scroll_x = 33, view width V = 110 (= 143 - 33; widget 110x22, max_scroll_x 33). First visible grid column: Kind, only its last cell (the `E` of `VALUE`; Kind spans x 29..38); Current is the first fully visible column; Δ the last. WT shows 110, not the 111 of the earlier WT base capture.
- 80x24: scroll_x = 73, V = 70 (widget 70x9, max 73). The first visible cells are the last 4 cells of New (x 73..76), then its gutter at x 77, then Unit, Limits, Δ.
- 220x60: V = 194 (widget 194x28), max_scroll_x 0, no scrollbar; End leaves x = 0.
- Home from End at 118 returns to scroll_x 0.
These equal the headless values (110 / 70 / 194).

(c) 220x60 right seam vs `D.off.sheet.220x60` (`3db20532`): the grid is the same 143 cells (trailing `│` after Δ at the same pixel column, about x 1493 of the 2000-wide view in both); the rows end there and the area to the right is empty ground in both. Same seam. Difference: in the approved D the expanded object's ground band stops at the grid edge (about x 1497); in this build the band (definition line and card rows) runs to the sheet's right edge at 220 (see `expanded.220x60`, `enum.220x60`), so the detail ground is wider than the grid above it. Other differences from D, all expected from Inc 8b: Limits cells are slot-aligned (`0 ├` and `-40 ├` no longer shift), the array strip is short grey bars instead of tall white bars, and the New/Δ cells are empty because no edit is staged in this fixture.

## Notes (facts, no verdict)

- First take of `grid.118x54` used the full 9-row page (`x-grid-9rows.118x54.png(.txt)`, kept as evidence): after selecting array rows the body window had scrolled so that ENUM_0001 was above the first painted row, and it did not scroll back when the selection returned to DISPLAY_0001 (no `↑ k more rows above` line). The final captures use the 7-row page, `sheet_top = 0`.
- At 80x24 the `grid` scene shows the selected row first (`sheet_top` 3), as the window follows the selection.
- At 118x54 the Limits track's right end (`┤`, upper limit) is outside the view until End (view 110 of 143).

## Cleanup

Deleted (created by this run): `%TEMP%\cap8b_work\` (tree copy, fixtures, proto8 comparison files, helper scripts, run log), the per-capture scratch folders `%TEMP%\zq_cap8b_*` (removed by the launcher, none left), the empty folder `clde\s19-relevo15-work\x8b\cap8b-tmp\`, and `clde\s19-relevo12-work\wt-capture.lock`. Windows: 23 opened, 23 closed (0 left, checked by title); the shared Windows Terminal host process was not touched. Kept in the repo tree: this file, the 23 PNG + sidecars, and `scripts/`.
