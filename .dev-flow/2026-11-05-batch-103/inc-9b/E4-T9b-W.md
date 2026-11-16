# Inc 9b E4 - T9b-W hand-back (tester, recovered)

File: `tests/test_b103_inc9b_w.py` (18 unparametrised case nodes + 3 parametrisations of .105/1-3 + one .95/0
control = 22 collected nodes). Base: `bcb22640` (P9b tip, no Inc 9b product code). This is a recovered hand-back: the
tester's session was lost after the runs, the documents below are rebuilt from the final transcripts
`redN3.txt` (base) and `stand1.txt` (stand-in), filed as:

- `.dev-flow/2026-11-05-batch-103/inc-9b/evidence-e4/t9bw/red-base.txt`
- `.dev-flow/2026-11-05-batch-103/inc-9b/evidence-e4/t9bw/standin-check.txt`

## Run shape (both runs)

Runner `<runner>`, HT-02 isolation, one node per process (`-n 0`), `timeout 300`, `-p no:cacheprovider`:
`pytest -p no:cacheprovider -n 0 -q -rf -v <node>`; `s19_app.__file__` under `~/work/zq-e4-9b-t9bw/tree/…`.
`uptime` is printed beside every node (HT-08); the base run walked the load from 1.04 to 0.81, the stand-in run from
0.32 to 0.89 with one out-of-bound stand-in observation at load 0.86, not a timing verdict.

Test source identity, local and remote: `tests/test_b103_inc9b_w.py` SHA-256
`d26e8c31692f6547d4ea3d265bb9087d169a74060a80838e0988e87124247c44` on both sides - matched.

## Base run (`bcb22640`): 22 nodes, 20 failed, 2 passed

No failure is an import error. Every one of the 20 is an assertion that the busy cue is absent: the painted top border
of `#patch_sheet_win` is read through the compositor (`painted_rows` / `painted_style`), the product's new functions
are never touched, and the existing entry points (selection keys, apply keys, `show_page`, `record_done`) are driven
to reach them. The two passes are the negative guards of R-PE-BENCH.95, negative by design: on a base that never
paints the cue they hold vacuously - which is exactly why the `.95/0` oracle control exists and must fail.

| Node | Case | Base | Reason (one line) |
|---|---|---|---|
| `test_r_pe_bench_94_4_a_queued_decode_shows_its_cue_while_another_rows_summary_runs` | R-PE-BENCH.94/4 | RED | no cue `decode MID` within 0.5 s of its ask while LARGE's summary ran; border `╭─ STAGING SHEET …╮`, corner `#91abec` |
| `test_r_pe_bench_95_0_control_a_decode_held_past_the_grace_does_paint_the_cue` | control (no case row) | RED | no busy cue `decode MAP_DEF_0001` (#f5c26b) within 3.0 s of the ask; its stand-in PASS paired with this base RED proves that the reader can see the cue |
| `test_r_pe_bench_95_1_a_decode_that_ends_inside_the_grace_never_paints_the_cue` | R-PE-BENCH.95/1 | PASS | negative guard: no amber at any paint of a decode that ends inside the grace - vacuous on base |
| `test_r_pe_bench_95_2_summaries_of_a_page_turn_are_not_busy_jobs` | R-PE-BENCH.95/2 | PASS | negative guard: idle look at every poll of a page turn whose summaries are held - vacuous on base |
| `test_r_pe_bench_96_1_the_busy_title_reads_spinner_busy_job_name_seconds_and_keys_still_work` | R-PE-BENCH.96/1 | RED | no cue `decode LARGE` within 3.0 s; title never reaches `BUSY · decode LARGE · 1.7 s · keys still work` |
| `test_r_pe_bench_96_2_the_pill_is_bold_dark_on_amber_and_the_title_keeps_its_colour` | R-PE-BENCH.96/2 | RED | same absent cue: there is no pill segment to read bold `#0a0e1b` on `#f5c26b` |
| `test_r_pe_bench_96_3_the_job_words_are_preview_and_stage` | R-PE-BENCH.96/3 | RED | no cue `preview VAL_BLK_DEF_0001` within 3.0 s (the `stage` word is never reached) |
| `test_r_pe_bench_97_2_the_frames_follow_the_cycle_one_step_per_tick_none_skipped` | R-PE-BENCH.97/2 | RED | no cue `decode LARGE`: no frame of `◐ ◓ ◑ ◒` is ever painted |
| `test_r_pe_bench_100_1_the_cue_leaves_within_0_3_s_of_a_decode_result_and_the_values_show` | R-PE-BENCH.100/1 | RED | no cue `decode LARGE` to leave; the 0.3 s exit bound is a precondition assertion on base |
| `test_r_pe_bench_100_2_the_cue_leaves_within_0_3_s_of_a_preview_result` | R-PE-BENCH.100/2 | RED | no cue `preview VAL_BLK_DEF_0001`; same precondition |
| `test_r_pe_bench_101_1_a_preview_refusal_returns_the_idle_look_within_0_3_s` | R-PE-BENCH.101/1 | RED | no cue `preview VAL_BLK_DEF_0001` before the refusal: the 0.3 s idle bound is never reached |
| `test_r_pe_bench_101_6_a_decode_whose_worker_raises_returns_the_idle_look_within_0_3_s` | R-PE-BENCH.101/6 | RED | no cue `decode MAP_DEF_0001` before the raise; same precondition |
| `test_r_pe_bench_102_1_leaving_the_row_for_a_scalar_returns_the_idle_look_while_the_worker_runs` | R-PE-BENCH.102/1 | RED | no cue `decode VAL_BLK_DEF_0001` before `down` to the scalar; the exit bound is a precondition |
| `test_r_pe_bench_102_2_a_filter_that_drops_the_row_returns_the_idle_look_within_0_3_s` | R-PE-BENCH.102/2 | RED | no cue `decode MAP_DEF_0001` before the filter keystroke; same precondition |
| `test_r_pe_bench_103_1_a_markup_name_is_shown_literally_with_no_link` | R-PE-BENCH.103/1 | RED | no busy cue for the row `[@click=app.quit]X[/]`; the literal-name and no-link checks are never reached |
| `test_r_pe_bench_103_2_brackets_in_a_name_are_shown_literally` | R-PE-BENCH.103/2 | RED | no busy cue for the row `A[b]B` |
| `test_r_pe_bench_104_1_an_escape_sequence_in_a_name_is_painted_as_fffd` | R-PE-BENCH.104/1 | RED | no busy cue for the row `A\x1b[2J`; no `A�[2J` is painted |
| `test_r_pe_bench_104_2_a_c1_control_in_a_name_is_painted_as_fffd` | R-PE-BENCH.104/2 | RED | no busy cue for the row `B\x85C` |
| `test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[80x24]` | R-PE-BENCH.105/1 | RED | no busy cue; at 80x24 the probed top row is blank (corner `None`) |
| `test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[118x54]` | R-PE-BENCH.105/2 | RED | no busy cue for the 300-character row; border `╭─ STAGING SHEET …╮`, corner `#91abec` |
| `test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[220x60]` | R-PE-BENCH.105/3 | RED | same absent cue at 220 columns; the cut to B = 190 is never exercised |
| `test_r_pe_bench_105_4_a_one_character_name_is_not_cut` | R-PE-BENCH.105/4 | RED | no busy cue for the row `N`; at 80x24 the probed top row is blank |

Reading of the two passes: .95/1 and .95/2 assert an absence, so they cannot fail on a base that paints nothing -
that base pass is expected and they are kept as negative guards for GREEN (a cue that blinks on a quick decode, or on
a page turn, must fail them). `.95/0` is their oracle, and it is the pairing that carries the proof: the base failure
of `.95/0` alone does not prove the reader can see a cue - the stand-in PASS of `.95/0` together with its base RED
is what proves it, protected by that control.

## Stand-in ticker run: NOT product GREEN

A stand-in tree (`…/tree_g`) exercised the same 22 nodes one per process, same shape, as a read of the harness only;
`standin-check.txt` files only the base and stand-in `s19_app.__file__` paths and the run transcripts, no checksum.

- 21 passed, 1 failed.
- The failure is `test_r_pe_bench_102_1_…_while_the_worker_runs`: idle look **0.397 s** after the key against the
  case's own **0.3 s** bound, at load 0.86 (`timing_bound(0.3)`).
- Stated plainly: this is a **stand-in result, not product GREEN**. The ticker's exit latency on real code is
  undecided and is the integrator's to measure; the stand-in only shows the other 21 nodes are satisfiable by a
  reader that paints the cue.

Timing decides only on a quiet host (HT-08). The stand-in run's first nodes were taken at load 0.32-0.78 rising to
0.9, so even its one number is not a verdict - it is a flag for the integrator, not a product defect.

## Coverage and trace

- `trace_check` for ids `R-PE-BENCH.94,.95,.96,.97,.100,.101,.102,.103,.104,.105`, invoked as:
  `python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-9b/01-requirements.md --tests
  tests --ids R-PE-BENCH.94 R-PE-BENCH.95 R-PE-BENCH.96 R-PE-BENCH.97 R-PE-BENCH.100 R-PE-BENCH.101
  R-PE-BENCH.102 R-PE-BENCH.103 R-PE-BENCH.104 R-PE-BENCH.105` (there was no `--base` or `--src` argument in
  this invocation): printed `trace_check: 10 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)`.
- All Group W cases are covered by a node: .94/4, .95/1, .95/2, .96/1, .96/2, .96/3, .97/2, .100/1, .100/2,
  .101/1, .101/6, .102/1, .102/2, .103/1, .103/2, .104/1, .104/2, .105/1-3 (three sizes), .105/4 - plus the extra
  .95/0 oracle control.
- Nothing outside Group W is claimed here: .94/1-3, .97/1, .97/3, .100/3, .101/2-5, .98, .99, .106 belong to the AT
  and S hand-backs.
- No interface change: the file adds no product symbol and reads no product function; it drives the shipped
  `S19TuiApp` through Pilot and the existing keys/entry points, and reads the painted border through
  `tests.b97_probes`. Support modules used unchanged: `tests/support/b103_inc9_w.py`, `b103_inc8_p.py`,
  `tests/support/timing.py`.

## Gaps for the integrator

1. Real GREEN is pending: 20 of 22 nodes are RED on `bcb22640` for one reason (the cue is absent), and no run on
   Inc 9b code exists yet. Every one of them must pass before the requirement set is called GREEN.
2. Timing is decided only on a quiet host. .94/4 (0.5 s), .100/1-2, .101/1, .101/6, .102/1-2 (0.3 s) and the
   .95/0 oracle (3.0 s cue sighting) are load-sensitive; the base and stand-in loads printed here are context, not
   verdicts.
3. `.102/1` on the stand-in measured 0.397 s against the 0.3 s bound at load 0.86 - an out-of-bound stand-in
   observation, not a timing verdict. It must be remeasured on real code on a quiet host, and the integrator must
   then diagnose test versus product on that real code; the 0.3 s bound is never to be loosened.
4. .95/1 and .95/2 pass on base by construction; at GREEN they must still pass while .95/0 proves the reader sees
   amber - a GREEN run that passes .95/1-2 with .95/0 failing is vacuous and must be re-decided.
5. The negative controls named in the node docstrings (grace 0, summaries counted as busy jobs, padded seconds, pill
   without background, one job word, fixed frame, cue keyed on the running worker, name parsed as markup, uncut
   name) are for the mutant worker; this hand-back does not claim them.
