# Inc 9b E5 — independent review (X9b)

Batch `2026-11-05-batch-103`, Inc 9b. One reviewer, one pass; code, security and test strength. Base `e4485817d7ac3706c77f14a4c2a8cf784fe35038`; E5 start `3194ccea0840ad22bd12530157c6cabaa123d1ce`. Reviewed `git diff e4485817..3194ccea -- s19_app tests`, its callers, M9b and the E5 fixes. I did not write the reviewed implementation.

## Findings

| id | severity | kind | location | problem | disposition |
|---|---|---|---|---|---|
| E5-9b-1 | MAJOR | impl | `definition_bench_view.py::busy_title` | Character-count truncation ignored terminal cells: CJK could crop seconds/`keys still work`; combining text could be cut while it fit. | Fixed test first. Painted CJK/combining nodes added at `f1161ee7`; both RED (`evidence/e5/runs/red-unicode.txt`). `d05b5180e5f48d4a167d13e7fb45b24586293eb6` reuses cell-aware `clip`; six Unicode/ASCII nodes GREEN (`green-unicode.txt`). |
| E5-9b-2 | MAJOR | impl (test) | HOLD-APPLY, bytes-entry Apply caller | No node asserted same-call ledger/JSON/sheet repaint. | `8539c371` adds the real handler oracle. The roster's return-after-`_note_image_bytes_written` is equivalent for these views because that hook already calls `_patch_editor_load_tail`; it PASSes and is not mislabelled KILLED. Removing hook+common refresh is RED; product and stated control GREEN (`control-hold-apply.txt`). |
| E5-9b-3 | MAJOR | impl (test) | HOLD-LOAD, `_patch_editor_load` | No same-call load-tail oracle. | `a211b3d6` adds a real bytes-document caller check; baseline PASS and early-return control RED (`control-hold-load.txt`). |
| E5-9b-4 | MAJOR | impl (test) | HOLD-MOUNT, Textual MRO | No node counted actual `StagingSheet.on_mount` executions. | `0acff83a` counts the real base method: baseline one/PASS, double-`super()` two/RED (`control-hold-mount.txt`). |
| E5-9b-5 | MAJOR | design-gap | R-PE-BENCH.99 negative control | A later sheet-step stall begins after the key-at-write can be handled; it does not control the stated bound. | Existing AT kept; corrected the control to the first serialize step. Original sheet-stall observation PASS 0.662 s (loaded preflight, not a timing verdict); corrected control RED 1.585 s after quiet preflight 0.13 (`control-m9b-residuals.txt`, `control-corrected.txt`). Requirement and graph corrected at `fff4d94a`; 1.0 s bound unchanged. |
| E5-9b-6 | MAJOR | impl (test) | `.98/1`, `test_b103_inc9b_at.py` | The first BUSY reading after write counted as a title change even without a later tick. | `d34a00de` requires two distinct painted BUSY titles. `title-once` is RED (`control-oracles.txt`); exact-final GREEN is listed below. CAP9b independently holds post-write refresh and captures two frames. |
| E5-9b-7 | MAJOR | impl (test) | `.102/2`, filter caller | Assigning `Input.value` did not exercise the stated filter keystroke. | `bf486a9d` focuses the filter and sends `c` through the terminal driver from a thread. Product PASS; active-job control RED (`control-oracles.txt`). |
| E5-9b-8 | MAJOR | impl (capture) | CAP9b PNG/report pairing | The first decode idle sidecar said idle while its real PNG still painted BUSY: compositor readiness preceded WT presentation. | Contradiction preserved as `decode.118x54.pre-hold.*`; not counted. `b1dd999c` holds the real cue timer only between report/ACK, verifies a stable painted row, then resumes. Re-captured decode PNGs and sidecars agree, including idle. Unique per-sequence ACKs remove the observed shared-file race. |

No BLOCKER. No product interface changed by E5; `busy_title` is private to the increment's pure renderer, so no interface re-review was required. The only design-gap fix updates `01-requirements.md` and `codewire/graph-inc9b.md` together.

## M9b reconciliation and every non-kill

M9b remains the authority for its original outcome: **19/26 runnable controls KILLED (73.1%)**, 1 SURVIVED, 2 CRASH, 4 BAD; **43 node arms = 35 KILLED, 2 SURVIVED, 2 CRASH, 4 BAD**. Three MISSING controls are outside that denominator. E5 does not rewrite those labels. Copy-only follow-up evidence is under `evidence/e5/runs/`.

| item | original verdict / node | E5 ruling |
|---|---|---|
| N-95b | SURVIVED; W `.95/2` | **Equivalent for shipped callers, code-proved.** `show_page` assigns `job="summary"` and appends directly to `_page` (`bench_sheet.py:584-598`); there is no `_enqueue("summary")` caller. The mutated `_enqueue` arm is unreachable, so the timer change cannot affect this path. Functional page-turn node remains GREEN; no false KILLED claim. |
| N-101a arm | control KILLED, but AT `.101/5` arm SURVIVED | **Non-discriminating arm, explicitly ruled.** Stale generation returns in `_job_done` before any of the three mutated refusal/result cleanup sites. Five sibling arms kill the control; the stale-case functional oracle still exercises its actual path. No new hole assigned to that arm. |
| N-97b | CRASH; AT `.97/3` | `thread=False` is rejected at import by Textual, so no M9b test ran. A valid synchronous-worker control (decorator removed, direct completion) makes the existing AT RED; original CRASH preserved (`control-m9b-residuals.txt`). |
| N-98b | BAD; AT `.98/1` | Original two-node union hit 300 s before mutation. Per-process baseline PASS; 1.3 s sheet-step stall RED at 1.671 s (`control-m9b-residuals.txt`). Closed by the existing painted AT. |
| N-99 | BAD; AT `.99/1` | Original union was BAD; the stated later-step stall was then observed GREEN and is not called a kill. E5-9b-5 corrects the design control to serialize; that existing AT is RED. |
| I-CHAIN-98 | BAD; AT `.98/1` | Per-process chain AT was GREEN (0.281 s), an E5 survivor observation, not a kill. The named scheduler node `S::test_r_pe_bench_98_2_a_later_step_raise_releases_record_done_exactly_once` is RED on the same chain copy because no timer callback is captured (`control-corrected.txt`). The strengthened `.98/1` and CAP9b add painted proof. |
| I-CHAIN-99 | BAD; AT `.99/1` | Per-process chain mutation is RED: key handled 1.074 s > 1.0 s; baseline PASS (`control-m9b-residuals.txt`). |
| I-LATER-RAISE | CRASH; S later-step contract | The roster deletion left invalid Python. A syntactically valid removal of `on_done()` is RED with calls `['first', 'raise']`; the product's exactly-once node remains the oracle (`control-m9b-residuals.txt`). |
| I-APPLY-SYNC / HOLD-APPLY | MISSING | Closed by the named E5 same-call Apply node at `8539c371`; stated mutation is equivalent by the executed call-chain proof in E5-9b-2, not counted as KILLED. |
| I-LOAD-SYNC / HOLD-LOAD | MISSING | Closed by the named E5 same-call load node at `a211b3d6`; stated early-return mutation RED. |
| I-MOUNT-ONCE / HOLD-MOUNT | MISSING | Closed by the named E5 mount-count node at `0acff83a`; double-`super()` RED. |

## Thirty-six case-to-node mappings, full/partial re-check

All 36 specified cases have the following executed nodes. After E5-9b-6/7, none is marked “covered in parts”: every row's objective is asserted by its named node. The separate `.95/0` cue-reader control and the five E5 additions are extra, not substitutes for a case row.

| case | node (abbreviated `test_r_pe_bench_`) | mark |
|---|---|---|
| .94/1 | AT `94_1_large_selected_shows_the_busy_border_and_title_within_half_a_second` | full |
| .94/2 | AT `94_2_a_gated_preview_shows_the_busy_title_within_half_a_second_of_enter` | full |
| .94/3 | AT `94_3_a_gated_record_stage_shows_the_busy_title_within_half_a_second_of_alt_s` | full |
| .94/4 | W `94_4_a_queued_decode_shows_its_cue_while_another_rows_summary_runs` | full |
| .95/1 | W `95_1_a_decode_that_ends_inside_the_grace_never_paints_the_cue` (+ `.95/0` reader control) | full |
| .95/2 | W `95_2_summaries_of_a_page_turn_are_not_busy_jobs` | full |
| .96/1 | W `96_1_the_busy_title_reads_spinner_busy_job_name_seconds_and_keys_still_work` | full |
| .96/2 | W `96_2_the_pill_is_bold_dark_on_amber_and_the_title_keeps_its_colour` | full |
| .96/3 | W `96_3_the_job_words_are_preview_and_stage` | full |
| .97/1 | AT `97_1_every_tick_of_larges_real_decode_paints_a_different_title` | full; no invented QC-TM margin |
| .97/2 | W `97_2_the_frames_follow_the_cycle_one_step_per_tick_none_skipped` | full |
| .97/3 | AT `97_3_the_gaps_between_changed_titles_stay_within_the_bounds` | full |
| .98/1 | AT `98_1_the_cue_keeps_ticking_through_the_write_and_refresh_of_a_large_record` | full after E5-9b-6 |
| .98/2 | S `98_2_the_stepped_stage_writes_the_base_bytes_and_yields_between_write_and_refresh` | full |
| .99/1 | AT `99_1_a_key_pressed_when_the_write_step_ends_is_handled_within_one_second` | full after E5-9b-5 |
| .100/1 | W `100_1_the_cue_leaves_within_0_3_s_of_a_decode_result_and_the_values_show` | full |
| .100/2 | W `100_2_the_cue_leaves_within_0_3_s_of_a_preview_result` | full |
| .100/3 | AT `100_3_a_written_record_returns_the_window_to_its_idle_look_within_0_3_s_of_the_last_step` | full |
| .101/1 | W `101_1_a_preview_refusal_returns_the_idle_look_within_0_3_s` | full |
| .101/2 | AT `101_2_a_record_refused_by_its_encode_returns_the_window_to_its_idle_look_within_0_3_s` | full |
| .101/3 | S `101_3_a_record_stage_refused_at_its_write_with_the_a2l_unloaded_returns_to_the_idle_look` | full |
| .101/4 | S `101_4_a_record_stage_refused_at_its_write_by_a_running_session_action_returns_to_the_idle_look` | full |
| .101/5 | AT `101_5_a_record_made_stale_by_an_undo_returns_the_window_to_its_idle_look_within_0_3_s` | full; surviving N-101a arm ruled above |
| .101/6 | W `101_6_a_decode_whose_worker_raises_returns_the_idle_look_within_0_3_s` | full |
| .102/1 | W `102_1_leaving_the_row_for_a_scalar_returns_the_idle_look_while_the_worker_runs` | full |
| .102/2 | W `102_2_a_filter_that_drops_the_row_returns_the_idle_look_within_0_3_s` | full after E5-9b-7 |
| .103/1 | W `103_1_a_markup_name_is_shown_literally_with_no_link` | full |
| .103/2 | W `103_2_brackets_in_a_name_are_shown_literally` | full |
| .104/1 | W `104_1_an_escape_sequence_in_a_name_is_painted_as_fffd` | full |
| .104/2 | W `104_2_a_c1_control_in_a_name_is_painted_as_fffd` | full |
| .105/1, /2, /3 | W `105_1_to_3_a_300_character_name_is_cut_with_an_ellipsis_and_the_title_fits[80x24/118x54/220x60]` | full, three arms |
| .105/4 | W `105_4_a_one_character_name_is_not_cut` | full |
| .106/1 | S `106_1_an_undo_between_two_refresh_steps_leaves_the_undone_document_everywhere` | full |
| .106/2 | S `106_2_an_apply_between_two_refresh_steps_leaves_the_applied_document_everywhere` | full |

Additional E5 nodes: two painted Unicode robustness cases, HOLD-APPLY, HOLD-LOAD and HOLD-MOUNT. Final expected collection is W 25, S 10, AT 10 = **45 nodes**.

## Backlog and inherited dispositions

- **BL-9b-1:** cancellation/single-job queue remains PENDING; a discarded decode runs to completion. Q9b measured the queue cause; the asked-job cue covers the wait. No scope expansion.
- **BL-9b-2:** Undo/Redo/Apply/other synchronous refresh sites remain PENDING; their synchronous behavior is guarded, not converted to the stepped runner.
- **BL-9b-3:** jobs outside the bench remain PENDING/out of scope.
- **BL-9b-4 / O-A:** process-offload/GIL work remains PENDING. R-PE-BENCH.29/2 and .82/1 retain 1.0 s; Q9b does not support 0.5 s.
- **BL-9b-5:** MINOR census role note remains PENDING: `test_tui_patch_json.py` still calls amber only “edited-cell foreground”, although the busy border/pill reuse it. No new literal and no law relaxation.
- **Inherited `w_jobs 26_2`:** 300 s timeout on both product and `e4485817`; not a PASS and not rerun as a replacement timing measurement.
- **Inherited callers:** E4's card `test_tc080_2_c7_purity_probe`, B94 `test_at_b94_03_expanded_editor_primary_surface`, and JSON `ac1/ac3/ac5` failures are base-identical; no Inc 9b regression assigned. Final E5 reruns the JSON/hue file after the renderer fix; other inherited evidence is not rewritten.
- **Inherited laws:** address-census `at_b83_08`, requirements-canon's three double-`shall` rows, and the Inc 8b home-path suite-hygiene red must remain node-for-node base-identical. No inherited record was edited to make a law pass.
- **Full repository suite:** batch-end scope, not claimed here.

## Q9b authority (not rerun)

All 35 Inc 9b timing runs passed. Cue p50/max: decode `.287/.307 s`, preview `.259/.306 s`, stage `.266/.315 s`. Changed-title median-gap p50 `.098 s`; maximum-gap p50/worst `.206/.236 s`. Stage write-to-leave maximum-gap p50/worst `.377/.470 s` against 0.5 s: **5.9% worst margin**, a low-margin note only. Key-at-write p50/max `.280/.664 s` against 1.0 s. `.97/1` has five assertion passes but no QC-TM margin. Corrected write+refresh block is `1.146 s`; serialize `.167`, ledger `.218`, sheet `.254`, tail `.004 s` are nested/component observations, never summed as disjoint work. **Q9b was not rerun.**

## Final validation and captures

**Review verdict: PASS-WITH-NOTES; no BLOCKER/MAJOR remains open.** Exact clone `6a8cfb0a9bb64b95dd9969fb08e05ae85c1bd6b4` collected the expected **45 nodes**: W **25/25**, S **10/10**, and AT **10/10 in ten separate processes**, all PASS. `test_tui_patch_json.py` is 14 PASS plus the same inherited `ac1/ac3/ac5` failures. Full law evidence and base comparison are itemized in `04-validation.md` and `evidence/e5/runs/final/`.

CAP9b is **22 sequences / 54 PNG + 54 sidecars, PASS**: every busy sequence has a valid two-frame spinner pair; all ten job sequences restore idle; hostile literals/replacements and all name cuts pass; both stage-refresh sequences prove post-write BUSY and exactly one resumed callback. Every PNG was opened. The three orphan windows from failed capture attempts and their dead PIDs are disclosed in `E5-captures.md`; final windows closed, scratch was deleted and the capture lock is absent. **Q9b was not rerun.**

## Checks not run and why

- No Q9b script, gap scenario, O-E repetition, FX9c probe, timing distribution or replacement timing statistic was run; completed Q9b is the authority.
- No full repository suite or snapshot regeneration: batch-end scope / canonical CI only (HT-09).
- Inherited `w_jobs 26_2` was not rerun; its base/product 300 s timeouts already exist.
- No push.
