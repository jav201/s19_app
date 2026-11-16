# Inc 8b E4 — integration (I8b)

Batch `2026-11-05-batch-103`, increment 8b, E4 integrator I8b, model Opus (claude-opus-5-5), orchestrator relevo-15.
Card: `roles/integrator.md` + SKILL.md § E4. Base for RED: `48af05ff`. Runner: rtx, HT-02 env (HOME basename
`<runner-home>`), `-n 2`, `timeout 300` per file, `s19_app.__file__` first in every transcript; laws on exact git
clones (HT-03) of the branch and of `48af05ff`. Transcripts under `evidence-e4/i8b/` (`-text`, sanitized: `~`,
`<user>`, `<runner-home>`).

## Merge

- `439614dd` — `b103-inc8b` (implementers, up to `0bbc6f79`) + `b103-inc8b-tests` (`f626d0ba`, five testers).
  One conflict, `steps.log`: every line of both sides kept, in time order (the C8b-B line carries an unexpanded
  `$(date …)`; its commit time is 06:11:39Z, placed there). The T8b-AT start line is absent from its side (an
  omission of that worker, noted, not invented).
- `ast.parse` of every changed `.py`: 0 failures. Staged CR count (python): 0 on every commit (`0bf2373b` fixes
  the one CR the lint transcript brought into `3802349d`).

## Commits after the merge

| sha | step |
|---|---|
| `fd1c7458` | test and record fixes; R-PE-DEF.117 written, its tests RED on the tip (`evidence-e4/i8b/red-117.txt`) |
| `86da7273` | R-PE-DEF.117 code fix (`definition_sheet.py`: `_as_float`, `_position`) |
| `3802349d` | two Inc 8 retargets, registry bound, HT-11 redaction, graph rulings |
| `0bf2373b` | lint transcript to LF |

## GREEN (fresh clone of the final tip)

Tree: a fresh git clone of `0bf2373b` (`fin`), plus the w_stage retarget (I11) shipped as one file before its
re-run (`f3-w_stage`, committed in the commit that adds this record). Host load 4–6 during the battery, 1.0 for the
`f3-*` / `b4-*` re-runs (`uptime` heads each transcript). Per-file transcripts `f1-<file>.txt`, `f2-<file>.txt`;
summaries `f1.summary.txt`, `f2.summary.txt`.

| group | file → result |
|---|---|
| new Inc 8b | `inc8b_s1` 95 passed · `inc8b_s2` 36 passed · `inc8b_bw` 30 passed · `inc8b_at` 12 passed |
| Inc 8 (14) | a1_service 23 · a2_app 23 · a3_help 9 · at_help 2 · at 11 · p_layout 31 · p_ledger 10 · p_wiring 12 · s1_detail 43 · s1 122 · s2_picker_definitions 6 · s2_sheet_formula 27 · s2_sheet_keys 22 · s2_sheet_rows 35 — all passed |
| Inc 9 (13) | a9 29 · b_canvas 42 · b_cells 40 · b_detail 54 · b_model 20 · b_tools 59 · i 3 · ob_json_view 2 · w_keys 19 · w_mutants 29 · w_select 14 — passed; **w_stage** 1 failed / 10 passed → I11 below → `f3-w_stage.txt` **11 passed**; **w_jobs** over 300 s as one file → 3 chunks (`cj-*`): 00 4 passed, 02 2 passed, 01 timeout (`26_2`, `28_1`, `28_2`, `29_1`); alone at load 1.0: `28_1` 1 passed (`f3-w_jobs_28_1`), `26_2` times out at 300 s on the tip **and on base** (`b4-w_jobs_26_2`, the traced decode, `TRACED_WAIT_S = 1800`); `28_2`, `29_1` not run (slow / timing arm, HT-08) |
| T8b-R retargeted | inside the rows above (14 files) + `test_tui_patch_json` |
| `test_tui_patch_json` (hue census) | 14 passed, 3 failed: ac1, ac3, ac5 — base-identical (`b3-tui_patch_json`); `tc079_5c` passes |
| `test_b97_chips_help` | 78 passed, 1 failed: `tc_b97_32_patch_help_names_every_label` — base-identical (`b3-`; Inc 8's open item O-1) |
| `test_b97_width` | over 300 s as one file → 4 chunks (`cw-*`): 145 passed; base the same (`bw-*`, 145 passed) |
| `test_tui_patch_layout` 9 · `test_tui_directionb` 184 (incl. the `tc031` engine nodes) · `test_b97_key_bar` 38 | passed |
| `test_tui_snapshot` | 25 passed, 2 xfailed, 6 failed — the same 6 nodes fail on base (`b3-tui_snapshot`); snapshots are regenerated only by CI (HT-09) |

## Failures found on the merged tree → cause → fix

| # | node(s) | cause | side | fix | req |
|---|---|---|---|---|---|
| I1 | `s1::99_1_2[25.5]`, `99_3` | the test read the mark glyph at column 2; the mark column is 2 cells (selector 0, glyph 1) | test | `plain[1]` | R-PE-DEF.99 |
| I2 | `s1::99_1_2[175]` | the test expected New `175`; New shows the preview's value text, `175.0` (R-PE-DEF.24; `a2_app:280` "staged as 175.0") | test | parametrized `new` | R-PE-DEF.99/2 |
| I3 | `s1::98_3` | staged array Δ asked with `blank_state()`: the bench computes `max \|Δ\| … staged` from the state's values and staged decode (R-PE-BENCH.16/2) | test | `staged_values` + `view_state(o, staged=…)` | R-PE-DEF.98/3 |
| I4 | `bw::92_93[118,80]`, `bw::81_6`, `at::1,2,3,4` | E1 assumed V = 111/73/195 at 118/80/220 columns (7 cells of chrome; the requirements' Data note said "measured at E4"). Measured through the real Patch Editor: **V = 110 / 70 / 194, identical on base and tip** (`probe-geometry-base.txt`, `-tip.txt`) | requirement record | script tuple corrected, transcript regenerated (`G.view.*`, `G.end.*` = 33/73/0); rows .93, .94, BENCH.5 and cases .94/1,/3,/6, BENCH.5/1–/3 restated; CTX scroll range note | R-PE-DEF.92–.94, .81/6, R-PE-BENCH.5 |
| I5 | `at::2`, `at::9[80x24]` | at 80×24 the selected ENUM_0001's card fills the row window (room = body − 3), so DISPLAY_0001 is not painted; the page wait and `select_row` read the painted lines (`probe-80x24-page-tip.txt`) | test | wait / navigate on `sheet.rows` (`page_names`) | R-PE-DEF.81 |
| I6 | `inc8_a2_app::62_2` | B's card title names the row, so "name in line" matched two lines | test | match the Parameter cell | R-PE-DEF.62 |
| I7 | `inc8_s1_detail::35` (one style) | graph `hex_grid`: zero bytes are dim; the Inc 8 test wanted one style | test | one style per byte class, none underlined | R-PE-DEF.35 |
| I8 | `id_registry` ×4 | 5 new scanned modules; `…square_at_79_cells` read as `AT-79` | test | bound 344 → 349 with the list; name `…in_79_cells` | registry law |
| I9 | `suite_hygiene::r_tst_070_2` (new offender) | `E4-t8b-s2.md` spelled the runner HOME basename | record | redacted to `<runner-home>` with a note in the line (HT-11); the base offender (a "Home / End" phrase in `steps.log` line 4) is base-identical and left (PP-06) | HT-11 |
| I10 | R-PE-DEF.117 (new) | hostile limits: `isfinite` on an enum bound 2**1100 raised `OverflowError`; limits ±1.7e308 span to inf, so the mark had no position | code | `_as_float` (beyond the float range → ±inf → range form), `_position` on halves | R-PE-DEF.117 |
| I11 | `inc9_w_stage::15_16_18` | the test looked for ` 1 cell ` with spaces; the grid puts `│` right after each cell | test | read the New cell between gutters | R-PE-BENCH.15 |

## Rulings applied

1. `header_rule(widths)` wins: graph §Interfaces and `E1-slice.md` S3 corrected (the node's `in:` already said
   `SheetWidths widths`). Lint: `not read=0 nodes=34 entities=5 edges=9`, `exit=0` (`evidence-e4/i8b/cw-lint-e4.txt`).
2. Recorded in the graph (DF-04 b): node `StagingSheet.on_resize` (width-only resize; E3-8b-11's premise corrected),
   `scroll_to(…, immediate=True)` on `StagingSheet.action_scroll_grid`, node `_definition_line` (`└` rule, the rest
   dim, per the sheet-styles table). Node count 32 → 34.
3. Hostile limits (DF-04 a): **R-PE-DEF.117** (If; next free id, checked over every `b103*` branch: max was .116),
   cases /1–/3, tests `s1::test_r_pe_def_117_1_3_*` (2 nodes) and `…117_2_*`, RED on the tip `fd1c7458` (/1 and /2
   by assertion and `OverflowError`; /3 is the lower-end boundary, holds on the tip), GREEN after `86da7273`.
   R-PE-DEF.114/2 withdrawn into .117/1 (that input now has a position); CTX `pos` line says "on halves".
4. Record corrections: R-PE-BENCH.36/5 case says "down" (with the reason); R-PE-DEF.97/8 example is `00 33` from the
   new script key `S.after_bytes.DISPLAY_0001.25.5` (regenerated, the test asserts it); R-PE-DEF.113/2 names its
   seven controls (from AT-B103-I8B-8's list).
5. `ramp_step`, `ramp_style`, `_RAMP_LO/_HI`: **kept** — callers exist (`definition_bench_view.py:47-48`, `:155`,
   `:421`, the bench canvas; E1-rulings already said so). Rule use/defer/delete → used, stays.

## Laws vs base

Laws on exact clones (`fin` = tip, `base` = `48af05ff`), the same files, `f2-*` vs `b3-*`:

| law | tip | base |
|---|---|---|
| engine_unchanged 1, deps_seam_law 6, docs_canon 2, no_private_tokens 2, filename_markup_safety 2, b101_doc_hygiene 45, b101_help_legend_docs 71, report_markup_safety 166, b97_key_bar 38 | passed | passed |
| id_registry | 12 passed (after I8) | 12 passed |
| suite_hygiene | 66 passed, 1 failed `r_tst_070_2` | the same node, **identical `E` lines** (offender `inc-8b/steps.log`: a "Home / End" phrase that the law reads as a home path, an E1-era record line; PP-06: not edited) |
| requirements_canon | 10 passed, 1 failed `canon_rows_hold_the_obligation_word_once` | identical |
| address_census | 22 passed, 1 failed `at_b83_08_tree_holds_no_assembled_selectors` | identical |

No new law failure; every remaining failure was measured on the merge-base `48af05ff`, never on a fix tip.
Re-checked on a fresh clone of the record commit `a42c5420` + `cf1c4d47`: `r_tst_070_2` holds only the base offender (`f5-hyg070.txt`); id_registry 12, requirements_canon 10 + the base node, docs_canon, no_private_tokens, w_stage 11 (`f4-laws.txt`: 37 passed, 1 failed = the base canon node).

## Examples the implementers could not run (re-run on the merged tree)

Each example is exercised by its cases' tests in the battery above, all passed: EX-8B-L5 (`R-PE-BENCH.17/1–/3`,
`L.bench.*`, `inc8b_s1`/`inc9_b_cells`), G2 (`R-PE-DEF.89`, `.90`, `inc8b_s1`), G3 (`.92`/`.93`, `inc8b_bw`,
`inc8b_at` 1–3), G5 (`.95`, `inc8b_at` 9 at 80/118/220), G6 (`.92/3`, `.94/6`, `.33/3`, `inc8b_bw`, `inc8b_at` 5),
W1/W2 (`.81/1–/6`, `R-PE-BENCH.36/4–/5`, `inc8b_bw`), bench-row E2 (`R-PE-BENCH.5/1–/5`, `inc8b_s2`), F1/F2
(`R-PE-BENCH.11`, `.107/1–/2`, `.108`, `inc8b_bw`, `inc9_b_cells`). Not run: F3 (`R-PE-BENCH.107/3`, an E5 real
capture). R-PE-DEF.81/5 at GREEN: the harness body 52 rows, painted lines − 2 = 50 (`inc8b_bw` passed).

## trace_check (`evidence-e4/i8b/trace_check-e4.txt`)

```
$ python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md --base 48af05ff --src s19_app
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md
trace_check: 1 US, 43 active requirements (2 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 1 gap(s)
```

## For the mutant worker (base-holding nodes; each needs a mutant that turns it RED, on a tree copy, HT-09)

| node | proposed mutant |
|---|---|
| `bw::test_r_pe_bench_36_4_*` (right, down) | revert `ArrayBenchSheet._bench_geometry` to the base (body width, visible = height − 1) |
| `bw::test_r_pe_bench_36_5_*` (right, down) | the same revert |
| `s1::test_r_pe_def_103_1_every_cue_survives_without_colour` | draw the pending `◆` of `_mark` as a space on a PURPLE ground |
| `s2::test_r_pe_def_108_4_a_number_row_has_no_card` | give `_scalar_ops("number", …)` the enum's card detail |
| `bw::test_r_pe_def_113_2_*` (80×24 seven controls) | `#patch_param_bulk_button` `display: none` (or width 0) in the picker CSS |
| `s2::test_r_pe_bench_5_5_room_zero_*` | `bench_detail` ignores `room` (paints the canvas when room = 0) |
| `bw::test_r_pe_def_81_6_*` (width-only resize) | delete `StagingSheet.on_resize` |
| `s1::test_r_pe_def_117_1_3_*[span_overflow.lower_end]` | `_track_index`: `max(1, …)` → `max(2, …)` |
| `at::test_at_b103_i8b_4_*` (Home and End in the input) | bind `home`/`end` with `priority=True` on StagingSheet |

## Lines for the next workers

- Mutant worker: V is 110 / 70 / 194 at 118 / 80 / 220 (measured, base and tip); never write 111/73/195 for a
  terminal size. Run mutants on a tree copy, not the clone the battery reads.
- E5: R-PE-DEF.103's card half (`■` and the underlined cells under NO_COLOR) and the bit-table `?` for a bit the
  image does not hold have no test; R-PE-BENCH.107/3 and the 1-cell gap between the headless V (110) and the WT
  base capture (111) are E5 capture items.
- E5: `test_tui_patch_json` ac1/ac3/ac5 and the three laws below fail identically on base `48af05ff`.
