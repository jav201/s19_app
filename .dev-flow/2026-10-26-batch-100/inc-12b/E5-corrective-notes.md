# Inc 12b — E5 corrective notes (software-dev, the one corrective pass)

Tree `C:/Users/jjgh8/Github/s19_app-b100-inc12b`, branch `b100-inc12b`, on `81ac4c0` (no commit made). Source edits: `s19_app/tui/app.py`, `s19_app/tui/a2l.py`. `styles.tcss` is untouched. Rows done: every "corrective" row of `E5-rulings.md` (CR12b-1, CR12b-2 = SE5-12b-2, CR12b-3, CR12b-4, SE5-12b-1). Rows not touched, as ruled: SE5-12b-3, SE5-12b-4 (close records), SR12b-6 and the two sync helpers (BACKLOG-CODE).

## Source sha256[:16] (after the pass)

| File | sha256[:16] |
|---|---|
| `s19_app/tui/app.py` | `46f7ee6aa8a0fbfb` |
| `s19_app/tui/a2l.py` | `73c3820fe0d6ecd2` |
| `s19_app/tui/styles.tcss` | `f7b4f75911b296a4` (unchanged) |

CRLF kept in both edited source files (python byte count: `\r\n` == `\n`).

## Per id

| Id | What changed | Where (after the pass) | New arm(s) | RED on 81ac4c0 | GREEN |
|---|---|---|---|---|---|
| CR12b-1 | `created_home` joins `created_dirs` **before** `write_change_document`, not after a successful write (base A3R2-8, "either way"). The rollback removes it only while it is empty, so recording it early is safe on success. P1-66's single `except OSError` is unchanged. | `app.py:11664`–`:11668` (added); the old append after the two `continue` exits is removed | `tests/test_b100_save_guards.py::test_tc_b100_07_pasted_document_home_created_then_write_fails_no_folder_left[no-space]`, `[placement-refused]` (the reviewer's `p2.py` probe as an arm; a vacuity check proves the home was made) | both FAILED: `folders == ['freshd', 'patches', 'temp']` | both PASSED: `['patches', 'temp']` |
| CR12b-2 / SE5-12b-2 | `load_a2l_from_path`: `validate_project_files(project_dir)` and the size `normalized.stat()` each in `try/except OSError`, both before any begin. Wording per the coordinator's split ruling (below). | `app.py:15164`–`:15178` (project folder), `:15189`–`:15194` (size stat) | `tests/test_b100_workers.py::test_tc_b100_54_a2l_attach_refuses_when_its_folder_or_file_vanished[project_folder]`, `[a2l_size]` (exact line, 0 begins, no run, app running, nothing raised) | FAILED: `FileNotFoundError left load_a2l_from_path` / `OSError left load_a2l_from_path` | PASSED |
| CR12b-3 | The report viewer's Generate stores `_declared_regions` only when `_running_session_action()` is `None`; the report request still runs. No log line added (optional in the review; not ruled). | `app.py:6042`–`:6044` | `tests/test_b100_workers.py::test_tc_b100_53_report_generate_keeps_the_regions_of_a_running_save` (held Save: regions unchanged, report still asked; idle: regions stored) | FAILED: `Generate wrote the regions during the Save` | PASSED |
| CR12b-4 | `os.fstat` only when a callback is given: `total = os.fstat(...).st_size if progress is not None else 0`. | `a2l.py:194` | `tests/test_b100_a2l_progress.py::test_tc_b100_73_no_fstat_without_a_callback` — with an `os` stand-in whose `fstat` raises: no-callback parse equals the pre-stand-in result and makes 0 `fstat` calls; with a callback the stand-in is called once (positive control). Byte identity of the no-callback parse is also covered by the existing `test_tc_b100_73_small_a2l_reports_once_and_parses_the_same` / `..._case06_...` (re-run in green-04). | FAILED: `OSError: [Errno 5] synthetic fstat failure` from the no-callback parse | PASSED (the `ERROR … reason=os_error` log line in the GREEN transcript is the positive-control call, expected) |
| SE5-12b-1 | `_on_project_saved` committed arm: `unsaved_work_left = bool(outcome.document_lines)`, set `True` where the "has unsaved edits" line is appended; just before `end_busy`, `if unsaved_work_left: self._quit_pending = False`. The manifest-mismatch case is not added (ruling). | `app.py:12244`–`:12246`, `:12272`, `:12287`–`:12288` | `tests/test_b100_workers.py::test_tc_b100_53_confirmed_quit_is_withdrawn_when_pasted_entries_were_not_saved` (scenario B: patches placement `OSError(28)`, save commits, last line is the document line, entry kept, quit not pending) and `::test_tc_b100_53_confirmed_quit_is_withdrawn_when_editor_edits_stay_unsaved` (scenario A: doc bound to `P/patches/changes.json`, second entry through the panel, second save held; last line "has unsaved edits", panel dirty, 2 entries, quit not pending). Negative control for the unchanged path: `test_tc_b100_53_confirmed_quit_waits_for_the_end[save]` still exits (green-04). | both FAILED: `the app exited over a save that left … unsaved` | both PASSED |

### CR12b-2 wording ruling (coordinator, recorded as the ruling)

Split by subject:
- size `stat()` `OSError` → `A2L file not found: <path>` (the same form as the use-time look; the A2L file is the subject).
- `validate_project_files` `OSError` (open project folder gone or unreadable) → not the A2L line. Through `safe_text(...).plain` and `_TYPED_REFUSAL_TOKENS["unreadable"]`: `A2L NOT loaded: project '<painted_names([current_project])>' could not be read — check that the folder can be opened, then load again.` Log: `A2L load refused (project folder could not be read): %r` with `project_dir`. No `{exc}` in the status line (S12b-02).
Both refusals happen before any busy run begins.

## Evidence

- `evidence/inc-12b/red-03-corrective.txt` — the 8 new test nodes on `base12bc` (detached clean tree at `81ac4c0`, source untouched, the three test files copied in); `s19_app.__file__` = `…\scratchpad\base12bc\s19_app\__init__.py`. Result: **8 failed**, each for its intended reason (listed above).
- `evidence/inc-12b/green-03-corrective.txt` — the same 8 nodes in the worktree; `s19_app.__file__` = `C:\Users\jjgh8\Github\s19_app-b100-inc12b\s19_app\__init__.py`. Result: **8 passed in 38.13s**.
- `evidence/inc-12b/green-04-new-and-guards.txt` — `tests/test_b100_workers.py` and `tests/test_b100_a2l_progress.py` whole, `tests/test_b100_save_guards.py -k tc_b100_07` (every save-rollback arm, the new CR12b-1 arm included), the quit arms outside workers (`test_b100_load_question.py::test_tc_b100_66_busy_line_and_quit_question_hold_no_decision_ids`, `test_b100_session_reset.py::test_tc_b100_09_twelve_b_adds_exactly_the_quit_flag`), and the guards `tests/test_id_registry.py`, `tests/test_b99_staging.py`. Result: **162 passed, 29 deselected (the non-TC-07 save_guards arms), 1 xfailed (the pre-existing `…a_source_that_vanished_under_the_dialog…`, design silent, Inc 11 O-1), 1 error in 1346.05s**. The one error is the session-teardown recent-store guard (`tests/conftest.py:74`), attributed to the last test. Cause, verified by timestamp: my debug script `corr12b/dbg_reuse.py` (for CI12a-1, run outside pytest, so outside the guard) wrote `recent_sources.json` under the shared scratch `LOCALAPPDATA` at 13:19:46Z, while this session ran (it began 12:59:01Z). No test failed. My error, not the product's.
- `evidence/inc-12b/green-04b-guards-rerun.txt` — after removing that stray scratch file: `tests/test_id_registry.py` + `tests/test_b99_staging.py` alone → **44 passed in 94.51s**, no teardown error.
- No timing arm failed in any run, so no timing re-run was needed.
- TC-027 (`test_engine_unchanged.py`) not counted: owed after the merge to main.

## For the code reviewer (CR12b-1 re-read; verdict was BLOCK-UNTIL CR12b-1)

Regression arm: `tests/test_b100_save_guards.py::test_tc_b100_07_pasted_document_home_created_then_write_fails_no_folder_left` (params `no-space`, `placement-refused`; `tests/test_b100_save_guards.py:2110`).

Exact diff hunks (`git diff -U2 -- s19_app/tui/app.py`):

```diff
@@ -11660,4 +11662,9 @@ class S19TuiApp(App):
                         "entries stay in the Patch Editor"
                     )
+                    # CR12b-1 (base A3R2-8): recorded either way, because the
+                    # placement mkdirs the home before a copy that can fail;
+                    # the rollback removes it only while it is empty.
+                    if created_home is not None:
+                        created_dirs.append(created_home)
                     try:
                         written, issues = write_change_document(
@@ -11685,6 +11692,4 @@ class S19TuiApp(App):
                         document_write_failure = failure
                         continue
-                    if created_home is not None:
-                        created_dirs.append(created_home)
                     placed = landed_doc[0]
                     pasted_placed = placed
```

## Extra row CI12a-1 (coordinator, test-only)

CI on main `4dfb5a1` (Linux) failed `tests/test_b100_reuse.py::test_at_b100_01_repeated_loads_reuse_and_name_existing_variant[size0]` and `[size1]` with `did not settle: the first load's added-variant status`.

1. **Wait re-pin** (`tests/test_b100_reuse.py:100`, `_wait_for`): it was 150 bare `pilot.pause()` calls (the F-17 / SR12b-7 pattern: a count, not time, and a tight loop). It is now bounded by the wall clock (60 s), with `await asyncio.sleep(0.05)` between checks. It is the only wait helper in the module; every caller waits on a positive condition, so what each call proves is unchanged. With only this change, both ids still FAILED locally (2 failed in 148.89s). So the cause was not starvation.
2. **Diagnosis** (debug dump at the failed wait, no run open): the log tail was `Project 'P' now opens firmware.s19` / `Added variant 'firmware' to project 'P'` / `Loaded firmware.s19`. Since Inc 12a, the file-load run's end line `Loaded <name>` is painted after the project-sync line. The test read only the newest painted line (`#log_line_4`), so it never saw the variant line.
3. **Oracle re-pin, approved by the coordinator ruling** ("the 12a design makes `Loaded <name>` the action's last line (end_busy tail); the newest-line oracle is stale since 12a, not the product"):
   - every line passes through `app._append_log_line` and is recorded in order (`log_lines` keeps only 4);
   - each load takes a mark, then waits until the `file_load` run has ended and the expected line is among the lines painted since the mark;
   - first loads expect `Added variant 'firmware' / 'firmware_1' to project 'P'`;
   - repeat loads expect `Variant '…' already in project 'P'`, and assert that no `Added variant` line was painted since the mark. This is tighter than before, which only checked the newest line.
   - The docstring cites the ruling (CI12a-1, the 12a end-line order).
   - Where: `tests/test_b100_reuse.py:1378`–`:1455`.
4. **RED:** none owed. This is a test-only wait and oracle re-pin, and the product is unchanged.
5. **Evidence:**
   - `evidence/inc-12b/green-05-ci12a1-reuse.txt` (worktree): **2 passed in 93.98s**.
   - `evidence/inc-12b/green-05-ci12a1-reuse-base.txt` (base12bc at `81ac4c0`, so no corrective source is involved): **2 passed in 94.40s**.
   - The first, failed, wait-only run's transcript was overwritten by the worktree GREEN run under the same file name. Its result (2 failed, 148.89s, the same `did not settle` message) is recorded here only.

## Not done / open

- Mutant survivors from the orchestrator: none received during this pass.
- `tests/test_engine_unchanged.py` TC-027: owed after the merge to main (not counted, per the brief).
- Full `tests/test_b100_busy.py`, run once at the end after the targeted runs were green: **109 passed, 2 skipped in 357.52s** (`evidence/inc-12b/green-06-busy-full.txt`). One skip is Windows-only (the name cannot be created). The `WorkerFailed` traces in the transcript are captured output of passing raise arms.
- No pytest of mine left running. The two pytest processes seen at the end belong to other agents (mut12b and an unrelated repo).
- `base12bc` still holds my copies of the four test files (`test_b100_save_guards.py`, `test_b100_workers.py`, `test_b100_a2l_progress.py`, `test_b100_reuse.py`). Its source is untouched (`git diff HEAD -- s19_app` is empty).
