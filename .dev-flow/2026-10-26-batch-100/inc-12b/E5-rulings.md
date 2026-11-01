# Inc 12b — E5 rulings (orchestrator, Opus)

## Code review (review-increment-022.md: FAIL, BLOCK-UNTIL CR12b-1; 0 HIGH / 1 MAJOR / 2 MINOR / 1 NIT)
| Id | Sev | Ruling | Route |
|---|---|---|---|
| CR12b-1 | MAJOR | Accepted. `created_home` joins `created_dirs` before `write_change_document` (base rule A3R2-8); regression arm from the reviewer's probe, RED on 81ac4c0. | Corrective pass (app.py + arm); reviewer re-reads the diff. |
| CR12b-2 | MINOR | Accepted (= SR12b-2). Guard `validate_project_files` and the size `stat()` in `load_a2l_from_path` with the existing refusal text, before any busy run begins; arm for the vanished project folder. | Corrective pass. |
| CR12b-3 | MINOR | Accepted. The report viewer's Generate stores `_declared_regions` only when no session action runs; the report still runs. Arm. | Corrective pass. |
| CR12b-4 | NIT | Accepted: `os.fstat` only when a callback is given (output already byte-identical). | Corrective pass (a2l.py, one line). |
| SR12b-6 | — | Residual risk accepted on the reviewer's reading (every after-commit step is pure, guarded or absolute-path); a retry recovers. | BACKLOG-CODE at close. |

## Security review (security-increment-022.md: PASS-WITH-NOTES; 0 HIGH / 1 MAJOR / 1 MINOR / 2 NIT, all design-gap)
| Id | Sev | Ruling | Route |
|---|---|---|---|
| SE5-12b-1 | MAJOR | Accepted. A confirmed quit is withdrawn (`_quit_pending = False`) when a successful Save leaves in-memory work unsaved: `outcome.document_lines` not empty, or the "has unsaved edits" line was added. The manifest-mismatch case is not added (no in-memory loss). Arms for scenario A and scenario B. | Corrective pass. |
| SE5-12b-2 | MINOR | Merged into CR12b-2. Both calls refuse with the existing refusal text (the size `stat()` does not fall back to 0, so the over-cap rule is never bypassed). The two project sync helpers (app.py ~14593, ~14701) are outside 12b. | Corrective pass; sync helpers to BACKLOG-CODE. |
| SE5-12b-3 | NIT | Accepted: re-word 12a's R-B1 (the open now happens on a worker; the A2L pick parses in place). | Close records. |
| SE5-12b-4 | NIT | Accepted as documentation: record in interfaces S-d that only a run's own handler ends it, so the install handlers may write before the generation check. No code. | Close records. |
| SR12b-6 | — | Both reviewers agree: residual risk, no guard. | BACKLOG-CODE at close. |

## CI (main 4dfb5a1)
| Id | Sev | Ruling | Route |
|---|---|---|---|
| CI12a-1 | — | test_b100_reuse.py AT-B100-01 [size0/1]: the newest-line oracle is stale since 12a (the end line `Loaded <name>` paints after the sync line). Oracle re-pinned to the lines painted since a mark; wait made time-bounded. | Done in the corrective pass (test-only). |

## Done (corrective pass, software-dev; details in E5-corrective-notes.md)
- CR12b-1 — Done: `app.py:11664`–`:11668` (`created_home` recorded before `write_change_document`; the post-success append removed). Arm `test_b100_save_guards.py::test_tc_b100_07_pasted_document_home_created_then_write_fails_no_folder_left[no-space|placement-refused]` — RED on 81ac4c0, GREEN.
- CR12b-2 / SE5-12b-2 — Done: `app.py:15164`–`:15178` (`validate_project_files` → `A2L NOT loaded: project '<name>' could not be read — …`, coordinator's split ruling) and `:15189`–`:15194` (size `stat()` → `A2L file not found: <path>`), both before the begin. Arm `test_b100_workers.py::test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished[project_folder|a2l_size]` — RED, GREEN.
- CR12b-3 — Done: `app.py:6042`–`:6044`. Arm `test_b100_workers.py::test_tc_b100_53_report_generate_keeps_the_regions_of_a_running_save` — RED, GREEN.
- CR12b-4 — Done: `a2l.py:194`. Arm `test_b100_a2l_progress.py::test_tc_b100_73_no_fstat_without_a_callback` (0 `fstat` without a callback, result equal; 1 with) — RED, GREEN.
- SE5-12b-1 — Done: `app.py:12244`–`:12246`, `:12272`, `:12287`–`:12288`. Arms `test_b100_workers.py::test_tc_b100_53_confirmed_quit_is_withdrawn_when_pasted_entries_were_not_saved` (scenario B) and `::test_tc_b100_53_confirmed_quit_is_withdrawn_when_editor_edits_stay_unsaved` (scenario A) — RED, GREEN.

## Re-review (code-reviewer, c026bd2): PASS-WITH-NOTES; BLOCK-UNTIL CR12b-1 lifted
| Id | Sev | Ruling | Route |
|---|---|---|---|
| CR12b-5 | NIT | Accepted as a cautious choice: any change-document line withdraws a confirmed quit, also lines about records already on disk (nothing lost; the user quits again). Fail-safe direction; not narrowed. | Close records (declared). |

## Round 2 (mutant survivors)
| Id | Sev | Ruling | Route |
|---|---|---|---|
| R2-F1 | MAJOR | Accepted and fixed by the orchestrator: no result panel on a routed install when a quit is confirmed. | Done (green-08). |
| R2-F2 | MINOR | Residual (handler-defect only). | BACKLOG-CODE at close. |
