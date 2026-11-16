# Inc 9b E4 - T9b-AT hand-back

Tester T9b-AT (Sonnet 5.5). File: `tests/test_b103_inc9b_at.py` (10 nodes, black box: keys and the painted top border row of `#patch_sheet_win` at 118 x 54). Base for RED: `bcb22640` (Inc 8b merged, no Inc 9b code). Runner `<runner>`, HT-02 env, `-n 0`, `timeout 300`, load 1.4-3.1 (NOT quiet: every number below is a record, HT-08). GREEN is the integrator's.

## Case -> node -> RED on base

| Case | Node | Base result | Kind |
|---|---|---|---|
| .94/1 | `test_r_pe_bench_94_1_large_selected_shows_the_busy_border_and_title_within_half_a_second` | RED: no `decode LARGE` busy title within 6 s of the key | assertion on absent cue |
| .94/2 | `test_r_pe_bench_94_2_a_gated_preview_shows_the_busy_title_within_half_a_second_of_enter` | RED: control passed (encode held), no `preview` title in 1 s | assertion on absent cue |
| .94/3 | `test_r_pe_bench_94_3_a_gated_record_stage_shows_the_busy_title_within_half_a_second_of_alt_s` | RED: control passed (encode held, nothing written), no `stage` title in 1 s | assertion on absent cue |
| .97/1 | `test_r_pe_bench_97_1_every_tick_of_larges_real_decode_paints_a_different_title` | RED: no busy title | assertion on absent cue |
| .97/3 | `test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds` | RED: no busy title | assertion on absent cue |
| .98/1 | `test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record` | RED: no busy title after the write | assertion on absent cue |
| .99/1 | `test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second` | RED twice on a LOADED host: `down` handled 1.070 s and 1.130 s after the write (load 2.2); the quiet-host base block is 0.67 s, so on a quiet host this is expected to pass: a guard, load-sensitive, unverified | assertion, load-sensitive |
| .100/3 | `test_r_pe_bench_100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step` | RED: control passed (encode held), precondition: no `stage` cue while held | assertion on absent cue |
| .101/2 | `test_r_pe_bench_101_2_a_record_refused_by_its_encode_returns_the_window_to_its_idle_look_within_0_3_s` | RED: same precondition | assertion on absent cue |
| .101/5 | `test_r_pe_bench_101_5_a_record_made_stale_by_an_undo_returns_the_window_to_its_idle_look_within_0_3_s` | RED: same precondition | assertion on absent cue |

No node fails by import error or AttributeError. Every RED is an assertion that the cue (title and amber corner) is painted; the base has no cue, so "absent" is the honest kind (nothing at base to assert a wrong value of).

## Transcript (last full runs; head of each: `uptime`)

```text
5 nodes (94/2 94/3 100/3 101/2 101/5), load 2.01:   5 failed in 49.41s
  :275 no `preview VAL_BLK_DEF_0001` busy title within 1.0 s of Enter; last top row '╭─ STAGING SHEET ───…╮'
  :306 no `stage VAL_BLK_DEF_0001` busy title within 1.0 s of alt+s; last top row '╭─ STAGING SHEET ───…╮'
  :492 / :542 / :589 precondition: no `stage VAL_BLK_DEF_0001` cue while held
3 nodes (94/1 97/1 97/3), load 1.37:                3 failed in 128.58s
  :238 / :332 / :358 no `decode LARGE` busy title within 6 s of the key; last top row '╭─ STAGING SHEET ───…╮'
98/1, load 1.79:                                    1 failed in 143.79s  "no busy title after the write"
99/1, load 1.79 then 2.19:                          1.070 s / 1.130 s over the 1.0 s bound ("load-sensitive, unverified")
```

## What was checked about the tests themselves (they cannot be GREEN here)

- The gate really holds the paths: 94/2, 94/3, 100/3, 101/2, 101/5 assert `gate.entered` before the cue assertion, and the controls passed on base.
- With the cue precondition removed in a scratch copy, 100/3, 101/2 and 101/5 run end to end on base (gate released, refusal, Undo, stale) and pass their idle bounds (0.000 / 0.013 / 0.019 s): their only RED on base is the absent cue, as intended.
- The painted-border reader and the title parser were validated against a stand-in that paints an amber `round` border and the pill (`border_title` as `Text`) on the real screen: first title read at 0.22 s, corner `#f5c26b`, 18 title changes in 2 s, median gap 0.098 s, `take()` 1.6 ms. (Scratch, not committed.)

## Coverage

AT group 10 of 10 cases have a node. Uncovered by this file by design (other groups): .94/4, .95, .96, .97/2, .98/2, .100/1-2, .101/1, /3, /4, /6, .102-.106.

## Gaps and notes for the integrator

- All 10 nodes are `serial_timing`; 94/1, 97/1, 97/3, 98/1, 99/1 are also `slow` (a real LARGE decode, about 11 s). Run apart, `-n 0`, on a quiet host.
- The sampler reads the screen every 0.01 s: a measured gap can exceed the true gap by up to that. .97/3 uses the case's own bounds (median 0.2, max 0.5).
- .97/1 is asserted as: at least 10 distinct busy titles in the 5 s window (the .97/3 max-gap bound turned into a count), the spinner glyph differs between successive painted titles, the pending time never goes back. It does not assert the glyph ORDER (that is .97/2, W).
- .98/1 measures from the instant the record's write lands in the change document (a thread watches `document.entries`), through each changed `stage LARGE` title, to the first idle reading.
- .99/1: key sent by that same thread at the write; handled time = the sheet's `action_move` returning (wrapper, as Inc 9's `keys_until`). On a quiet base it should pass (0.67 s block): GREEN for it is only meaningful with the spec's negative control (a 1.3 s stall in one refresh step).
- .100/3: "within 0.3 s of the refresh's last step" is read as: idle look within 0.3 s of the last painted change of the rest of the screen (the step's own paint is the only observable).
- .101/5 presses `#patch_undo_button` (as Inc 9's 78/1) after a first staged record, then a held second record.
- `take()` uses the compositor's private `_render_chops` for one row (cost: the full render is 5 ms and a query 5 ms, which would load the UI thread the cue ticks on). Same content as `render_strips` (checked equal on a real screen).
- No interface change proposed.
