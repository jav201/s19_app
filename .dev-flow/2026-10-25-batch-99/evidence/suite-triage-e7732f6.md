# Full-suite triage — main `e7732f6` (all 12 increments)

Transcript: `suite-full-e7732f6.txt` — **14 failed, 3756 passed, 3 skipped, 3 xfailed** in 2:05:30, run in the clean worktree `s19_app-b99-suite` (no `prototypes/`, because that folder is untracked). Compared against the baseline set at `a293213` (PLAN.md test ledger, 11 ids).

## Baseline ids

| Baseline id | On `e7732f6` |
|---|---|
| `test_changes_file_notation_help::test_tc1802_…` | fails, same cause: `prototypes/…/help_sections.md` absent in a clean worktree |
| `test_tui_commandbar::test_at_b78_03_…` | fails, same cause as on the baseline |
| `test_tui_diff_screen::test_tc024_report_trigger_surfaces_paths` | fails, same |
| `test_tui_diff_screen::test_at_b78_32_…` | fails, same (the BINDINGS block drift predates the batch) |
| `test_tui_patch_editor_v2::test_at031b_…` | fails, same |
| `test_tui_patch_editor_v2::test_tc328_…` | **passes** |
| `test_tui_patch_layout::test_at063c_…` | **passes** |
| `test_tui_report_filter_surface::test_at_056e_…` | fails, same |
| `test_unified_write::test_tc018_existing_name_is_dedup_suffixed` | fails, same |
| `test_window_usage_help::test_tc707_copy_matches_…` | fails, same (`help_sections.md` absent) |
| `test_window_usage_help::test_tc707_numbering_…` | fails, same |

## Non-baseline failures (5)

| Node | Re-run alone | Verdict |
|---|---|---|
| `test_b97_flow_execution::test_tc_b97_64_a_new_set_run_restarts_the_dwell` | passes on main | known timing flake (routed to BACKLOG-CODE at the DDR) |
| `test_tui_diff_screen::test_tc024_report_trigger_invalid_dest_refused` | passes alone in the suite worktree and on main | ordering/load flake: under the full run the notice read `Compared A.s19 vs B.s19: 1 runs.` before the refusal painted; whole-file re-runs below |
| `test_tui_patch_editor_v2::test_saveback_width_32_packs_wide_records_and_populates_s0` | passes alone in the suite worktree and on main | ordering/load flake: `_saveback_width stayed at 32` after the selector press under load; whole-file re-runs below |
| `test_import_census::test_tc653_safe_text_import_census` | **fails on main** | real, caused by Inc-6 (`87dcd3a`): `segment_split_view` imports `safe_text` (LLR-160.2) and the census was not re-measured → Increment 013 F1 |
| `test_tui_snapshot::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]` | **fails on main** | real, caused by Inc-11 (`5021bb6`): the Bytes placeholder text changed (LLR-161.2) and the cell was not regenerated → Increment 013 F2 |

Snapshot bisect (one cell, s19env, worktree `s19_app-b99-suite`):

```
a293213 1 passed
c62c842 1 passed
5021bb6 1 failed
9d7fb18 1 failed
725d474 1 failed
c58b02d 1 failed
f1ba70c 1 failed
7ffad92 1 failed
```

## Why the increment gates missed the two real ones

Each increment ran its affected test files, chosen by a reverse census of the changed symbols. Neither failure is reachable that way. The import census reads module imports, not a symbol. The snapshot reads rendered text, not the placeholder constant. Both are whole-tree guards, and they are found only by a full run. Recorded for the post-mortem.
