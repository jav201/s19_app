# Inc 8b E5 — review (X8b)

Batch `2026-11-05-batch-103`, increment 8b, E5 reviewer X8b, model Opus (claude-opus-5-5), orchestrator relevo-16.
Card: SKILL.md § E5 + `roles/reviewer.md` (one reviewer, code and security, one pass). Diff reviewed:
`git diff 48af05ff..7c4e377c -- s19_app tests` (29 files; product: `definition_sheet.py`, `sheet.py`,
`bench_sheet.py`, `definition_bench.py`, `insight_style.py`, `window_help.py`, `a2l_parameter_picker.py`).
I did not write the code under review. Fix commits (each test first): `a63f1841` (tests, RED by mutant or on
the tip), `13ac75d6` (RED evidence, records), `ab0aa3d0` (product fix, R-PE-DEF.117/4).

## Findings

| id | sev | tag | where | problem | disposition |
|---|---|---|---|---|---|
| E5-8b-1 | MAJOR | design-gap | `definition_sheet.py` `_position` | Limits `0 … 5e-324` (finite, upper > lower): `upper/2 − lower/2` is 0, so `_has_position` raises `ZeroDivisionError` in the sheet paint for a value in range. CTX said "a finite span never overflows" but the halves vanish for a subnormal span. A hostile A2L stops the paint. | **Fixed** test first: R-PE-DEF.117/4 (2 nodes) RED on the tip `a63f1841` (`evidence/e5/runs/out-red/tip-s1.txt`: 2 failed, `ZeroDivisionError`), GREEN after `ab0aa3d0` (halves only when `upper − lower` overflows; identical results for every normal span, both forms round once). CTX line, .117 row and case /4 updated. |
| E5-8b-2 | MAJOR | impl (test) | `bw::81_6` | P-81_6 survived every group: the node widens 118→220, the scrollbar disappears, the body's own height grows and `_SheetBody.on_resize` repaints. The node could not see `StagingSheet.on_resize`. | **Diagnosed, handler kept** (it is needed): new node `81_6_b` (200→220, V 174→194, no scrollbar either side, body height equal) fails without the handler (`out-red/mut/P-81_6.txt`: lines stay 174 cells, V 194). |
| E5-8b-3 | MAJOR | impl (test) | `at::1/2/3`, R-PE-DEF.94/6 | N-94c (`animate=True`) survived: Pilot's `press` waits for the animator before it returns, so "x right after the key" is read after the animation. On a real terminal the operator would watch the grid slide. | **Fixed**: node `94_6` runs the End/Home actions and reads x with no loop turn; RED under N-94c (`out-red/mut/N-94c.txt`), GREEN on the tip. Proof that Pilot settles: the same mutant passes `at::1` and fails `94_6`. |
| E5-8b-4 | MAJOR | impl (test) | R-PE-DEF.103 card half | `■` and the underlined cells under NO_COLOR had no test (integrator's open item). | **Fixed**: `103_1_the_card_cues_survive_without_colour` (bit card, New 255; SGR-parsed underline cells equal mono vs colour; `■` present); RED under C-103a (`■` → coloured space) and C-103b (underline → hue) (`out-red/mut/C-103a.txt`, `C-103b.txt`). |
| E5-8b-5 | MINOR | impl (test) | `s1::91_1`, `s1::101_1..3`, `s1::103_1` | N-91, N-101, N-103 were killed only by Inc 8 neighbour rows (a glyph that appears twice on a line; the rule checked on the function only). | **Fixed**: `bw::91_1` (body line 2 = `G.header_rule`), `_glyph_in_hue` (the glyph itself in the hue), mark-column check in 103/1. Each kills its control on its own row (`N-91.txt`, `N-101.txt`, `N-103.txt`). |
| E5-8b-6 | MINOR | impl (test) | `card_lines` / N-115b | Equivalent for the shipped callers — **confirmed** (`_enum_options` applies `plain`; `bit_table` and `hex_grid` paint generated text), but the card's own contract had no direct test. | **Fixed**: `s2::115_2_card_lines_cleans_a_raw_row_it_is_handed`, RED under N-115b. |
| E5-8b-7 | MINOR | impl (test) | `bench_detail` / P-B5_5 | Equivalent at width ≥ 12 — **confirmed** (every later path ends in `lines[:room]`); observable under 12 cells. | **Fixed**: `s2::bench_5_5_room_zero_at_a_narrow_view…` (view 12), RED under P-B5_5. |
| E5-8b-8 | MINOR | — | R-PE-BENCH.82/1 | 0.891 s against the 1.0 s operator bound at load 0.91 (margin 10.9 %, flagged LOW by QC-TM). Within the bound. | PENDING: watch at the batch-end suite. |
| E5-8b-9 | MINOR | — | `plain()` (Inc 8 rule) | Bidi format characters (U+202A…U+202E, U+2066…U+2069) pass `plain` and reach the cells and cards. The probe below shows the grid geometry holds; Windows Terminal does not reorder. Not new in Inc 8b (CTX plain text is C0/C1). | PENDING (DF-04 c: defer). |
| E5-8b-10 | MINOR | — | `bit_table` | The `?` for a bit the image does not hold has no test (integrator's note). | PENDING. |
| E5-8b-11 | MINOR | — | `row_window` (Inc 8, unchanged by 8b) | Real capture `x-grid-9rows.118x54`: after the selection visited the array rows and came back up to DISPLAY_0001, the window kept top = 1, so ENUM_0001 stays hidden while 11 body lines below are blank (no "rows above" cue). Not an R-PE-DEF.81 breach (the selected row is painted); the code is Inc 8's. | PENDING (DF-04 c: a "pull back when the page fits" rule is new). |
| E5-8b-12 | note | — | captures, 220×60 | The expanded ground runs to V (194) where the approved prototype `D.off.sheet.220x60` stopped at the grid edge (143). The build follows R-PE-DEF.107 / R-PE-BENCH.5 (`max(G, V)`, changed at E1). | Operator verdict on the capture page (DF-09); no code change. |

No BLOCKER. Every MAJOR is fixed in the increment, test first; none touches an interface another increment uses
(`_position` is private), so no re-review.

## Security (hostile A2L text) — run, not asserted

Probe `evidence/e5/runs/probe/test_x8b_probe.py` (scratch copy of the fix tip, never in `tests/`): names, units
and enum texts set to wide (CJK × 40), ESC/BEL/CSI (`\x1b[2J`, `\x07`, `\x9b`), bidi (U+202E), 100 000 chars,
markup `[@click=app.quit]X[/]`, NUL, combining + ZWJ; kinds number, enum, bit mask, array; views 70/110/194:
every row line is 143 cells with the 7 gutters at the header's cells (selected and odd), every expanded line is
`max(143, V)` cells, no control character is painted, no span carries `@click`. **84 passed**
(`evidence/e5/runs/probe/probe.txt`). Hostile limits: E5-8b-1 (fixed); ±1.7e308 and 2**1100 are R-PE-DEF.117/1–/3.

## Mutant survivors (M8b, `E4-mutants.md`) — rulings

All seven are killed on their own rows now (table above); plus the two new card-half controls C-103a/b.
Score on the row's own tests: **70 / 70** (68 E4 controls + 2 E5), `evidence/e5/runs/out-red/mut/` (driver
`x8b-mut-driver.py`; one hard-link copy per mutant, HT-09).

## Checks not run, and why

- `test_b97_width`, `test_tui_snapshot`, `test_b97_chips_help`, `tui_directionb`: not touched since I8b's GREEN on
  `0bf2373b` (the E5 diff is tests + `_position`); not in the brief's battery.
- `w_jobs::26_2`: times out at 300 s on the tip and on base (I8b, the traced decode); not re-run.
- Timing ran on `7c4e377c`, before `ab0aa3d0`; the fix touches only `_position` (limits cell), not the timed paths.
