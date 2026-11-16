# Inc 9b E4 - mechanical mutant run (M9b)

Run record: `2026-11-15T19:47:03.411419-06:00`; source `b103-inc9b` at `2e80b0d68370c0d4c3eebbc5cf6e325b712769d0`.
Population: 26 runnable controls in 23 fresh-copy groups, 43 resolved node arms; three declared coverage holes are MISSING, not run and not scored as kills or survivors.

## Method and harness proof

- Every group used a newly extracted copy of the exact source archive under `~/work/zq-m9b/groups/`; no real worktree was mutated. A mutant was scored only after its full node union resolved to the required arm count and passed on the unmutated copy; an invalid baseline is BAD and applies no mutant.
- Exact old-expression anchors matched once per edit; zero or multiple matches were application failures. Mutation receipts are in `results.json`; `anchor-check.txt` covers all 23 groups before execution.
- Pytest used the isolated HT-02/HT-03 environment, `PYTHONDONTWRITEBYTECODE=1`, `timeout 300`, `-n 0`, no cache provider, and an import-location probe at the head of every transcript. Every baseline and mutant preflight required one-minute load < 1.0 and zero other test/Q9b jobs.
- Recorded pre-run one-minute loads ranged from 0.11 to 0.99. No loaded-host verdict was accepted. Host cleanup used only recorded PID/SID values; `host_m9b.sh` builds its verification pattern at runtime.
- Per-arm verdicts were parsed from JUnit, never inferred from a process exit code. `selftest.txt` proves rejection of zero application and empty selection, plus KILLED/CRASH/SURVIVED classification on synthetic known-answer inputs.
- `validation.txt` independently reconciles the 23-group/26-control/43-arm census, GREEN baselines, quiet preflight, mutation receipts, control aggregates, and every reported arm against raw JUnit. Its deliberately corrupted result and empty-census controls are rejected.

Test aliases: `W` = `tests/test_b103_inc9b_w.py`; `S` = `tests/test_b103_inc9b_s.py`; `AT` = `tests/test_b103_inc9b_at.py`. Evidence paths below are relative to `inc-9b/`.

## Control table

| control id | requirement | mutation (file:line, one line) | tests run | verdict | evidence line |
|---|---|---|---|---|---|
| N-94a | R-PE-BENCH.94 | bench_sheet.py:526: key the cue to the active running job | `W::test_r_pe_bench_94_4_a_queued_decode_shows_its_cue_while_another_rows_summary_runs` | KILLED | `evidence-e4/mutants/G01-mutant.txt` — 3 failed in 24.01s; per-arm `summary.tsv` |
| N-102 | R-PE-BENCH.102 | bench_sheet.py:526: key the cue to the active running worker | `W::test_r_pe_bench_102_1_leaving_the_row_for_a_scalar_returns_the_idle_look_while_the_worker_runs`<br>`W::test_r_pe_bench_102_2_a_filter_that_drops_the_row_returns_the_idle_look_within_0_3_s` | KILLED | `evidence-e4/mutants/G01-mutant.txt` — 3 failed in 24.01s; per-arm `summary.tsv` |
| N-94b | R-PE-BENCH.94 | bench_sheet.py:119-120: omit busy-timer creation | `AT::test_r_pe_bench_94_1_large_selected_shows_the_busy_border_and_title_within_half_a_second` | KILLED | `evidence-e4/mutants/G02-mutant.txt` — 1 failed in 41.66s; per-arm `summary.tsv` |
| N-95a | R-PE-BENCH.95 | bench_sheet.py:48: reduce busy grace to zero | `W::test_r_pe_bench_95_1_a_decode_that_ends_inside_the_grace_never_paints_the_cue` | KILLED | `evidence-e4/mutants/G03-mutant.txt` — 1 failed in 8.50s; per-arm `summary.tsv` |
| N-95b | R-PE-BENCH.95 | bench_sheet.py:56,154: count summary jobs as busy at both sites | `W::test_r_pe_bench_95_2_summaries_of_a_page_turn_are_not_busy_jobs` | SURVIVED | `evidence-e4/mutants/G04-mutant.txt` — 1 passed in 7.15s; per-arm `summary.tsv` |
| N-96a | R-PE-BENCH.96 | definition_bench_view.py:538: pad seconds to width four | `W::test_r_pe_bench_96_1_the_busy_title_reads_spinner_busy_job_name_seconds_and_keys_still_work` | KILLED | `evidence-e4/mutants/G05-mutant.txt` — 1 failed in 15.11s; per-arm `summary.tsv` |
| N-96b | R-PE-BENCH.96 | definition_bench_view.py:544: remove the busy-pill background | `W::test_r_pe_bench_96_2_the_pill_is_bold_dark_on_amber_and_the_title_keeps_its_colour` | KILLED | `evidence-e4/mutants/G06-mutant.txt` — 1 failed in 7.68s; per-arm `summary.tsv` |
| N-97a | R-PE-BENCH.97 | bench_sheet.py:538-540: paint the busy title only on frame zero | `AT::test_r_pe_bench_97_1_every_tick_of_larges_real_decode_paints_a_different_title` | KILLED | `evidence-e4/mutants/G07-mutant.txt` — 1 failed in 45.83s; per-arm `summary.tsv` |
| N-97b | R-PE-BENCH.97 | bench_sheet.py:192,233: run bench jobs synchronously with direct completion | `AT::test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds` | CRASH | `evidence-e4/mutants/G08-mutant.txt` — EXIT_CODE 4; per-arm `summary.tsv` |
| N-98a | R-PE-BENCH.98 | patch.py:411-413: run the write and full refresh in one UI-thread call | `AT::test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record`<br>`S::test_r_pe_bench_98_2_the_stepped_stage_writes_the_base_bytes_and_yields_between_write_and_refresh` | KILLED | `evidence-e4/mutants/G09-mutant.txt` — 2 failed in 157.89s (0:02:37); per-arm `summary.tsv` |
| N-98b | R-PE-BENCH.98 | patch.py:731-732: add a 1.3-second stall to the sheet refresh step | `AT::test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record` | BAD | `evidence-e4/mutants/G10-baseline.txt` — see transcript and per-arm summary; baseline invalid; mutation not applied |
| N-99 | R-PE-BENCH.99 | patch.py:731-732: add a 1.3-second stall to the sheet refresh step | `AT::test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second` | BAD | `evidence-e4/mutants/G10-baseline.txt` — see transcript and per-arm summary; baseline invalid; mutation not applied |
| N-100a | R-PE-BENCH.100 | bench_sheet.py:546-547: leave the inline busy-border rules installed | `W::test_r_pe_bench_100_1_the_cue_leaves_within_0_3_s_of_a_decode_result_and_the_values_show`<br>`W::test_r_pe_bench_100_2_the_cue_leaves_within_0_3_s_of_a_preview_result`<br>`AT::test_r_pe_bench_100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step` | KILLED | `evidence-e4/mutants/G11-mutant.txt` — 3 failed in 54.43s; per-arm `summary.tsv` |
| N-100b | R-PE-BENCH.100 | bench_sheet.py:548: leave the last busy title in place | `W::test_r_pe_bench_100_1_the_cue_leaves_within_0_3_s_of_a_decode_result_and_the_values_show`<br>`W::test_r_pe_bench_100_2_the_cue_leaves_within_0_3_s_of_a_preview_result`<br>`AT::test_r_pe_bench_100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step` | KILLED | `evidence-e4/mutants/G12-mutant.txt` — 3 failed in 54.50s; per-arm `summary.tsv` |
| N-101a | R-PE-BENCH.101 | bench_sheet.py:282,310 and patch.py:406-408: preserve busy state on unsuccessful results | `W::test_r_pe_bench_101_1_a_preview_refusal_returns_the_idle_look_within_0_3_s`<br>`AT::test_r_pe_bench_101_2_a_record_refused_by_its_encode_returns_the_window_to_its_idle_look_within_0_3_s`<br>`S::test_r_pe_bench_101_3_a_record_stage_refused_at_its_write_with_the_a2l_unloaded_returns_to_the_idle_look`<br>`S::test_r_pe_bench_101_4_a_record_stage_refused_at_its_write_by_a_running_session_action_returns_to_the_idle_look`<br>`AT::test_r_pe_bench_101_5_a_record_made_stale_by_an_undo_returns_the_window_to_its_idle_look_within_0_3_s`<br>`W::test_r_pe_bench_101_6_a_decode_whose_worker_raises_returns_the_idle_look_within_0_3_s` | KILLED | `evidence-e4/mutants/G13-mutant.txt` — 5 failed, 1 passed in 68.35s (0:01:08); per-arm `summary.tsv` |
| N-101b | R-PE-BENCH.101 | patch.py:406-408: keep the record hold after a refusal | `S::test_r_pe_bench_101_3_a_record_stage_refused_at_its_write_with_the_a2l_unloaded_returns_to_the_idle_look`<br>`S::test_r_pe_bench_101_4_a_record_stage_refused_at_its_write_by_a_running_session_action_returns_to_the_idle_look` | KILLED | `evidence-e4/mutants/G14-mutant.txt` — 2 failed in 25.97s; per-arm `summary.tsv` |
| N-103 | R-PE-BENCH.103 | bench_sheet.py:538-540: assign the busy title as a markup string | `W::test_r_pe_bench_103_1_a_markup_name_is_shown_literally_with_no_link`<br>`W::test_r_pe_bench_103_2_brackets_in_a_name_are_shown_literally` | KILLED | `evidence-e4/mutants/G15-mutant.txt` — 2 failed in 14.92s; per-arm `summary.tsv` |
| N-104 | R-PE-BENCH.104 | definition_bench_view.py:540: use the raw busy-name string | `W::test_r_pe_bench_104_1_an_escape_sequence_in_a_name_is_painted_as_fffd`<br>`W::test_r_pe_bench_104_2_a_c1_control_in_a_name_is_painted_as_fffd` | KILLED | `evidence-e4/mutants/G16-mutant.txt` — 2 failed in 15.01s; per-arm `summary.tsv` |
| N-105 | R-PE-BENCH.105 | definition_bench_view.py:541-542: omit busy-name truncation | `W::test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[80x24]`<br>`W::test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[118x54]`<br>`W::test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[220x60]` | KILLED | `evidence-e4/mutants/G17-mutant.txt` — 3 failed in 21.53s; per-arm `summary.tsv` |
| N-106 | R-PE-BENCH.106 | patch.py:755: ignore the document token on later refresh steps | `S::test_r_pe_bench_106_1_an_undo_between_two_refresh_steps_leaves_the_undone_document_everywhere`<br>`S::test_r_pe_bench_106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere` | KILLED | `evidence-e4/mutants/G18-mutant.txt` — 2 failed in 18.91s; per-arm `summary.tsv` |
| I-CHAIN-98 | R-PE-BENCH.98 | patch.py:766: replace timer separation with call_after_refresh | `AT::test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record` | BAD | `evidence-e4/mutants/G19-baseline.txt` — see transcript and per-arm summary; baseline invalid; mutation not applied |
| I-CHAIN-99 | R-PE-BENCH.99 | patch.py:766: replace timer separation with call_after_refresh | `AT::test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second` | BAD | `evidence-e4/mutants/G19-baseline.txt` — see transcript and per-arm summary; baseline invalid; mutation not applied |
| I-TOKEN-DROP | R-PE-BENCH.106 | patch.py:779: remove write generation from the document token | `S::test_r_pe_bench_106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere` | KILLED | `evidence-e4/mutants/G20-mutant.txt` — 1 failed in 9.49s; per-arm `summary.tsv` |
| I-NO-INCREMENT | R-PE-BENCH.106 | patch.py:1872: stop the in-place-write generation increment | `S::test_r_pe_bench_106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere` | KILLED | `evidence-e4/mutants/G21-mutant.txt` — 1 failed in 9.45s; per-arm `summary.tsv` |
| I-LATER-RAISE | R-PE-BENCH.98/2 | patch.py:762-764: omit cleanup when a later refresh step raises | `S::test_r_pe_bench_98_2_a_later_step_raise_releases_record_done_exactly_once` | CRASH | `evidence-e4/mutants/G22-mutant.txt` — EXIT_CODE 4; per-arm `summary.tsv` |
| I-PANEL-GONE | R-PE-BENCH.98/2 | patch.py:758: return immediately when the panel is gone | `S::test_r_pe_bench_98_2_a_panel_gone_skips_the_tail_and_releases_record_done_exactly_once` | KILLED | `evidence-e4/mutants/G23-mutant.txt` — 1 failed in 4.15s; per-arm `summary.tsv` |
| I-APPLY-SYNC | R-PE-DEF.62 / batch-48 LLR-081.3 | Declared copy-only mutation not applied; no discriminating node | none — declared HOLD | MISSING | No existing node drives bytes-entry Apply and asserts same-call ledger/JSON/sheet repaint. |
| I-LOAD-SYNC | R-PE-DEF.62 / batch-48 LLR-081.3 | Declared copy-only mutation not applied; no discriminating node | none — declared HOLD | MISSING | No existing node drives the change-document load caller and asserts same-call repaint. |
| I-MOUNT-ONCE | C9b-W mount contract | Declared copy-only mutation not applied; no discriminating node | none — declared HOLD | MISSING | No existing node counts StagingSheet.on_mount executions and asserts exactly once. |

## Score

- Runnable controls: **19 KILLED / 26** (73.1%), 1 SURVIVED, 2 CRASH, 4 BAD.
- Resolved node arms: **43 total** — 35 KILLED, 2 SURVIVED, 2 CRASH, 4 BAD. A control with a killing arm and another green arm remains KILLED at control level; every green arm stays visible below.
- Three MISSING controls are excluded from the kill denominator: I-APPLY-SYNC, I-LOAD-SYNC, I-MOUNT-ONCE.

## Per-arm verdicts

The machine-readable ledger is `evidence-e4/mutants/summary.tsv`; the same verdicts are enumerated here.

| group | control | resolved node | verdict |
|---|---|---|---|
| G01 | N-94a | `W::test_r_pe_bench_94_4_a_queued_decode_shows_its_cue_while_another_rows_summary_runs` | KILLED |
| G01 | N-102 | `W::test_r_pe_bench_102_1_leaving_the_row_for_a_scalar_returns_the_idle_look_while_the_worker_runs` | KILLED |
| G01 | N-102 | `W::test_r_pe_bench_102_2_a_filter_that_drops_the_row_returns_the_idle_look_within_0_3_s` | KILLED |
| G02 | N-94b | `AT::test_r_pe_bench_94_1_large_selected_shows_the_busy_border_and_title_within_half_a_second` | KILLED |
| G03 | N-95a | `W::test_r_pe_bench_95_1_a_decode_that_ends_inside_the_grace_never_paints_the_cue` | KILLED |
| G04 | N-95b | `W::test_r_pe_bench_95_2_summaries_of_a_page_turn_are_not_busy_jobs` | SURVIVED |
| G05 | N-96a | `W::test_r_pe_bench_96_1_the_busy_title_reads_spinner_busy_job_name_seconds_and_keys_still_work` | KILLED |
| G06 | N-96b | `W::test_r_pe_bench_96_2_the_pill_is_bold_dark_on_amber_and_the_title_keeps_its_colour` | KILLED |
| G07 | N-97a | `AT::test_r_pe_bench_97_1_every_tick_of_larges_real_decode_paints_a_different_title` | KILLED |
| G08 | N-97b | `AT::test_r_pe_bench_97_3_the_gaps_between_changed_titles_stay_within_the_bounds` | CRASH |
| G09 | N-98a | `AT::test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record` | KILLED |
| G09 | N-98a | `S::test_r_pe_bench_98_2_the_stepped_stage_writes_the_base_bytes_and_yields_between_write_and_refresh` | KILLED |
| G10 | N-98b | `AT::test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record` | BAD |
| G10 | N-99 | `AT::test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second` | BAD |
| G11 | N-100a | `W::test_r_pe_bench_100_1_the_cue_leaves_within_0_3_s_of_a_decode_result_and_the_values_show` | KILLED |
| G11 | N-100a | `W::test_r_pe_bench_100_2_the_cue_leaves_within_0_3_s_of_a_preview_result` | KILLED |
| G11 | N-100a | `AT::test_r_pe_bench_100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step` | KILLED |
| G12 | N-100b | `W::test_r_pe_bench_100_1_the_cue_leaves_within_0_3_s_of_a_decode_result_and_the_values_show` | KILLED |
| G12 | N-100b | `W::test_r_pe_bench_100_2_the_cue_leaves_within_0_3_s_of_a_preview_result` | KILLED |
| G12 | N-100b | `AT::test_r_pe_bench_100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step` | KILLED |
| G13 | N-101a | `W::test_r_pe_bench_101_1_a_preview_refusal_returns_the_idle_look_within_0_3_s` | KILLED |
| G13 | N-101a | `AT::test_r_pe_bench_101_2_a_record_refused_by_its_encode_returns_the_window_to_its_idle_look_within_0_3_s` | KILLED |
| G13 | N-101a | `S::test_r_pe_bench_101_3_a_record_stage_refused_at_its_write_with_the_a2l_unloaded_returns_to_the_idle_look` | KILLED |
| G13 | N-101a | `S::test_r_pe_bench_101_4_a_record_stage_refused_at_its_write_by_a_running_session_action_returns_to_the_idle_look` | KILLED |
| G13 | N-101a | `AT::test_r_pe_bench_101_5_a_record_made_stale_by_an_undo_returns_the_window_to_its_idle_look_within_0_3_s` | SURVIVED |
| G13 | N-101a | `W::test_r_pe_bench_101_6_a_decode_whose_worker_raises_returns_the_idle_look_within_0_3_s` | KILLED |
| G14 | N-101b | `S::test_r_pe_bench_101_3_a_record_stage_refused_at_its_write_with_the_a2l_unloaded_returns_to_the_idle_look` | KILLED |
| G14 | N-101b | `S::test_r_pe_bench_101_4_a_record_stage_refused_at_its_write_by_a_running_session_action_returns_to_the_idle_look` | KILLED |
| G15 | N-103 | `W::test_r_pe_bench_103_1_a_markup_name_is_shown_literally_with_no_link` | KILLED |
| G15 | N-103 | `W::test_r_pe_bench_103_2_brackets_in_a_name_are_shown_literally` | KILLED |
| G16 | N-104 | `W::test_r_pe_bench_104_1_an_escape_sequence_in_a_name_is_painted_as_fffd` | KILLED |
| G16 | N-104 | `W::test_r_pe_bench_104_2_a_c1_control_in_a_name_is_painted_as_fffd` | KILLED |
| G17 | N-105 | `W::test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[80x24]` | KILLED |
| G17 | N-105 | `W::test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[118x54]` | KILLED |
| G17 | N-105 | `W::test_r_pe_bench_105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[220x60]` | KILLED |
| G18 | N-106 | `S::test_r_pe_bench_106_1_an_undo_between_two_refresh_steps_leaves_the_undone_document_everywhere` | KILLED |
| G18 | N-106 | `S::test_r_pe_bench_106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere` | KILLED |
| G19 | I-CHAIN-98 | `AT::test_r_pe_bench_98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record` | BAD |
| G19 | I-CHAIN-99 | `AT::test_r_pe_bench_99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second` | BAD |
| G20 | I-TOKEN-DROP | `S::test_r_pe_bench_106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere` | KILLED |
| G21 | I-NO-INCREMENT | `S::test_r_pe_bench_106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere` | KILLED |
| G22 | I-LATER-RAISE | `S::test_r_pe_bench_98_2_a_later_step_raise_releases_record_done_exactly_once` | CRASH |
| G23 | I-PANEL-GONE | `S::test_r_pe_bench_98_2_a_panel_gone_skips_the_tail_and_releases_record_done_exactly_once` | KILLED |

## Survivors and missing coverage

- **N-95b (R-PE-BENCH.95) SURVIVED:** show_page appends summary jobs directly to _page (bench_sheet.py:594-598), bypassing the mutated _enqueue; the busy timer stays paused, so the selected node cannot observe the roster mutation.
- **N-101a surviving arm AT::test_r_pe_bench_101_5_a_record_made_stale_by_an_undo_returns_the_window_to_its_idle_look_within_0_3_s:** the stale generation is dropped in `_job_done` (bench_sheet.py:254-266) before `RecordStageRequested`; none of the three mutated refusal/result cleanup paths executes, although sibling arms kill the control.
- **I-APPLY-SYNC MISSING:** No existing node drives bytes-entry Apply and asserts same-call ledger/JSON/sheet repaint.
- **I-LOAD-SYNC MISSING:** No existing node drives the change-document load caller and asserts same-call repaint.
- **I-MOUNT-ONCE MISSING:** No existing node counts StagingSheet.on_mount executions and asserts exactly once.

## CRASH and BAD outcomes

- **N-97b CRASH:** Textual raises WorkerDeclarationError while importing the mutant because thread=False is invalid on this synchronous worker; no test executed. See `G08-mutant.txt` when present; otherwise the invalid-baseline transcript and `retries.txt`.
- **N-98b BAD:** The two-node baseline union timed out at 300 seconds after one completed arm in both the initial fresh copy and the low-load fresh retry; no mutant was applied, so this is neither a kill nor a survivor. See `G10-mutant.txt` when present; otherwise the invalid-baseline transcript and `retries.txt`.
- **N-99 BAD:** The two-node baseline union timed out at 300 seconds after one completed arm in both the initial fresh copy and the low-load fresh retry; no mutant was applied, so this is neither a kill nor a survivor. See `G10-mutant.txt` when present; otherwise the invalid-baseline transcript and `retries.txt`.
- **I-CHAIN-98 BAD:** The two-node baseline union timed out at 300 seconds after one completed arm in both the initial fresh copy and the low-load fresh retry; no mutant was applied, so this is neither a kill nor a survivor. See `G19-mutant.txt` when present; otherwise the invalid-baseline transcript and `retries.txt`.
- **I-CHAIN-99 BAD:** The two-node baseline union timed out at 300 seconds after one completed arm in both the initial fresh copy and the low-load fresh retry; no mutant was applied, so this is neither a kill nor a survivor. See `G19-mutant.txt` when present; otherwise the invalid-baseline transcript and `retries.txt`.
- **I-LATER-RAISE CRASH:** Deleting the complete except block leaves try without except/finally, so Python raises SyntaxError at import; no test executed. See `G22-mutant.txt` when present; otherwise the invalid-baseline transcript and `retries.txt`.

## Evidence and limits

- `anchor-check.txt`, `selftest.txt`, `validation.txt`, `results.json`, `summary.tsv`, `DONE`, every executed-phase transcript, and preserved first-attempt/retry records are stored byte-for-byte under `evidence-e4/mutants/` (`-text` inherited from the batch rule).
- The mutation, driver, host, retry, and independent validator/render scripts make the execution and PID/SID-scoped cleanup auditable. `cleanup.txt` confirms both recorded drivers had exited and `~/work/zq-m9b` was removed by the explicit created-path list in `host_m9b.sh`.
- An initial archive transfer was rejected as empty before anchor checks or test execution. Its scratch was explicitly deleted and re-created; no result from that attempt is included.
- Timing nodes were used only as mutation oracles on a quiet host. This record does not change any timing bound or make a separate performance decision.
