# Confirmation run triage — `75f947a` (final tree)

Transcript: `suite-full-75f947a.txt` — **12 failed, 3755 passed, 3 skipped, 3 xfailed** in 1:58:07, in the clean worktree `s19_app-b99-suite` (no `prototypes/`). Its header names the command, the tree and the start time. 12 + 3755 + 3 + 3 = **3773**, equal to `pytest --collect-only` on main. This is the one complete run of the final tree that G-001 asked for, so every node changed by Increments 012 and 013 is now inside one transcript.

**Verdict: no product defect, no HIGH.** 8 failures are baseline ids failing for their recorded causes. 4 are intermittent test nodes, and all 4 fail on the pre-batch tree `a293213` too, or pass in isolation on both trees. The two stale pins that Increment 013 re-measured now pass.

## Against the gate run on `e7732f6`

| Group | Gate run `e7732f6` | Confirmation `75f947a` |
|---|---|---|
| Baseline ids (11 at `a293213`) | 9 fail, 2 pass (tc328, at063c) | 8 fail, 3 pass (tc328, at063c, `tc024_report_trigger_surfaces_paths`) |
| Stale pins (tc653 census, snapshot `patch-comfortable-120x30`) | 2 fail | **0 fail** — Increment 013 confirmed in the full run |
| Gate-run flakes (tc_b97_64, tc024_invalid_dest, saveback_width_32_packs) | 3 fail | 0 fail |
| New intermittent nodes | — | 4 fail (below) |

`tc024_report_trigger_surfaces_paths` is a baseline id that passed in this run. It is listed as passing here, not removed from the baseline set: one pass does not show that its cause is gone.

## The 4 nodes that failed only in this run

Re-runs: `flake-confirmation-75f947a-x5.txt` (the 4 nodes together, 5 runs per tree), `flake-at057b-x15.txt` (at057b alone, 15 runs per tree, trees alternating), `probe-at057b-patient.txt`.

| Node | Full-run error | Isolated re-runs | Verdict |
|---|---|---|---|
| `test_before_after_report::test_tc330_before_after_row_reveal_hide_state_machine` | `WorkerFailed: NoMatches('#log_line_1')` — a worker read the log widget before it was mounted | 5/5 pass on head, 5/5 on base | ordering/load flake. It did not fail in the gate run on the same product (`git diff e7732f6 75f947a -- s19_app` is empty) |
| `test_tui_patch_editor_v2::test_saveback_width_32_preserves_source_s0_header` | `the 32-byte confirm must write a file` | 5/5 pass on head; **fails 1/5 on base** | pre-batch flake, the same family as the gate run's `saveback_width_32_packs` |
| `test_tui_patch_editor_v2::test_at064c_edit_json_disabled_for_file_backed_document` | `assert False is True` | 5/5 pass on head, 5/5 on base | pre-batch flake: it failed on `a293213` in `flake-patch-editor-v2-base-vs-head.txt` (run 1) |
| `test_tui_patch_editor_v2::test_at057b_regroup_wiring_and_binding_regression` | `Load must populate the table` (`0 == 2`) | **head 10/15 fail, base 3/15 fail** | single-pause test race (below) |

### at057b — a test race that the batch made more frequent

The node presses five buttons and reads each result after **one** `pilot.pause()`. It fails on both trees, at different steps each time (Load, Validate, Apply, Run checks), which is the signature of reading one hop too early rather than of a missing behaviour.

The patient probe repeats the same presses, but each step waits on its observable for up to 40 pauses. **Every step completed on both trees, 15 of 15 runs each, and no step needed more than 2 pauses.** A step needed a second pause in 4 of 75 steps on base and 6 of 75 on head.

So the product posts every result. The batch made a step land after the first pause somewhat more often, and a test that allows exactly one pause is sensitive to that. The failure rate rose (3/15 → 10/15), and this is recorded as a fact, not explained away: the routed fix is the same bounded wait loop the backlog already carries for `at030c` / `at068b`, and `at057b` is added to that item.

## Not a HIGH

No node shows a behaviour the product fails to deliver. Each of the 4 either fails on the pre-batch tree, passes in isolation on both trees, or, for at057b, always delivers when waited on. The batch's stop rule (stop on a HIGH finding) is not triggered.
