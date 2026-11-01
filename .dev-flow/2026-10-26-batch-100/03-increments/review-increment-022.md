# Code Review — Increment 022 (batch-100 Inc 12b, stage E5)

**Verdict: FAIL** (BLOCK-UNTIL: CR12b-1): 0 HIGH · 1 MAJOR · 2 MINOR · 1 NIT. CR12b-1 is a rollback regression against the base, and its fix is one moved statement. Once that fix and a regression arm are applied and re-read, the verdict becomes PASS-WITH-NOTES. The MINOR and NIT findings do not block.

Reviewer role: code-reviewer (correctness, simplicity, reuse, conformance to the approved design, and above all concurrency correctness of the three new workers). I worked on my own and reviewed read-only. I did not edit the source tree. My probes live only under the scratchpad folder `rev12b-code-reviewer/`.

## Scope reviewed

- Tree `C:/Users/jjgh8/Github/s19_app-b100-inc12b`, branch `b100-inc12b` at `81ac4c0` (merge of `main` after the Inc 12a close). Diff: `git diff main...b100-inc12b -- s19_app tests`. In `git diff -w`, the source part is `app.py` +1602/-1224 (hunks) and `a2l.py` +32. `styles.tcss` does not differ from the merge base.
- I read these in full in the merged tree:
  - the seam `begin_busy` … `_progress_forwarder` (`app.py:20142`–`:20448`), plus the constants, the request and result dataclasses, and `_save_failure_outcome` (`:426`–`:590`);
  - `parse_a2l_cached` (`:877`);
  - the project load: `_handle_load_project`, `_project_load_worker`, `_prepare_project_load`, `_on_project_loaded`, `_install_prepared_project`, `_on_project_load_failed`, `_parse_data_file` (`:13276`–`:13810`);
  - the Save: `_commit_project_save`, `_save_project_worker`, `_save_project_files`, `_on_project_saved` (`:11436`–`:12283`) and `_abort_save` (`:10361`);
  - the A2L route: `load_from_path`, `load_a2l_from_path`, `_a2l_attach_worker`, `_on_a2l_attached`, `_install_attached_a2l`, `_on_a2l_attach_failed` (`:15019`–`:15306`);
  - `_load_workarea_file`, `_confirm_then_load`, `_handle_select_variant`, `_handle_save_dialog`, and the tail of `_start_load_worker` / `_handle_load_error`;
  - the whole `a2l.py` diff.
- AST censuses (scratch scripts, executed):
  - `self.*` reads and writes of every function the workers run;
  - every `_refuse_if_busy` site;
  - every `action_*` / `on_*` handler that reaches a session write without passing a refusal.
- Base for parity: `main:s19_app/tui/app.py`, saved to the scratchpad and read.
- Design: `inc-12b/codewire/interfaces-12b.md`, `proto-12b-load-save.md`, `proto-12b-a2l-refusal.md`, `E3-architect.md` (the refused set), `E4-app-notes.md`, and `E4-integration-notes.md` (F-1…F-23, SR12b-1…7 and the orchestrator rulings).
- Tests: I did not review them line by line. I read the arms that bear on my findings (`test_b100_save_guards.py` `_force_stage`, `…gather_home_created_then_copy_fails_no_folder_left`, `…r3_failed_write_carries_the_target_document`). I did not re-run the evidence transcripts.

## Findings

| Id | Sev | Tag | Where | Defect | Evidence | Fix |
|---|---|---|---|---|---|---|
| CR12b-1 | MAJOR | impl | `app.py:11642`–`:11688` (`_save_project_files`, the pasted-document arm); base `main:app.py:11381`–`:11388` | **A pasted-document write that fails after creating its home leaves that home behind when the save is rolled back. The rollback then cannot remove a new project folder.** The base appended `created_home` to `created_dirs` "either way" (A3R2-8, comment at base `:11383`). 12b appends it only on success (`:11687`), after both `document_write_failure = failure; continue` exits (`:11675`, `:11685`). `place_into_workarea` mkdirs the destination before its staging copy (`workspace.py:1183`). So in the disk-full shape (ENOSPC on the document copy, then any later abort) `S/patches/` stays. `project_dir.rmdir()` then fails silently in `_abort_save`, and the partial project folder survives. This is the same shape that R5-1 pinned for gather homes (`test_tc_b100_07_gather_home_created_then_copy_fails_no_folder_left`), but nothing pins it for the pasted document. The D2 deviation kept the detection and dropped the "either way". F-13 then reshaped the detection only. | Probe **executed** (`rev12b-code-reviewer/p2.py`). Load case_01 `firmware.s19`, `add_entry` (a pasted 1-entry document), patch `app_module.place_into_workarea` to mkdir and raise `WorkareaPlacementError` for the `patches` home only, force `manifest-refused`, Save new `freshd`. Output: `last lines: ['Manifest write failed', 'Project NOT saved: … project.json was not written. check the folder.']`, `left in workarea: ['freshd', 'freshd\\patches', 'patches']`. Base by reading: the home joins the rollback before the failure test, so `freshd` is removed. | Move `if created_home is not None: created_dirs.append(created_home)` to just before the `try: written, issues = write_change_document(…)`. The rollback removes folders only while they are empty, so recording the home early is safe on success too, and P1-66's single `except OSError` is unchanged. Add a regression arm: the probe above, asserting `folders == ['patches', 'temp']`. It must be RED on `81ac4c0`. |
| CR12b-2 | MINOR | design-gap | `app.py:15150`–`:15164` (`load_a2l_from_path` project guard and size stat); SR12b-2 | **When the open project's folder is gone, an A2L load raises out of the request, and from a dialog or deferred callback that exits the app.** This is the routed SR12b-2. `validate_project_files(project_dir)` runs `project_dir.iterdir()` unguarded. The open project's folder can be renamed or removed in Explorer at any time, and no microsecond race is needed. `normalized.stat()` (`:15164`) is the narrower case. This is base behaviour (unchanged lines), but SE5-12a-4's intent ("must not exit the app on OSError at the use-time look") covers it. | Probe **executed** (`rev12b-code-reviewer/probe_a2l.py`). `current_project='gone'`, `current_project_dir=W/gone` (absent), `load_a2l_from_path(case_01 firmware.a2l)` → `raised out of load_a2l_from_path: FileNotFoundError [WinError 3] …\workarea\gone`. No run is begun, so the cost is the exit. | Guard both. Wrap `validate_project_files` in `except OSError` and paint the existing `could not be read` refusal for the project, or the `A2L file not found` line. Wrap `normalized.stat()` in `except OSError` and paint `A2L file not found: <typed>`. Both sit before the begin, so no run and no end are involved. Sibling for the batch-end census (not 12b): `_handle_save_dialog`'s `resolve_input_path(Path(payload.parent_folder), …)` (`:10645`) is the same unguarded class. |
| CR12b-3 | MINOR | design-gap | `app.py:6042` (`on_report_viewer_screen_generate_requested`); `E3-architect.md:41` (the refused set) | **The report viewer's Generate writes `_declared_regions`, a session field, during a running project load or Save.** The busy rule does not cover it. E3's refused-set census counted writers of the image, the document and the project, and classified the report viewer as non-writing. But `_declared_regions` is in the base's session set (baseline U4), Save records it in `project.json`, and project load replaces it. On the base the window did not exist, because both actions blocked the loop. Scenario 1: a case_06 project load is running on its worker. The user opens the report viewer, types regions R and presses Generate. `_declared_regions = R`, then `_install_prepared_project` sets it to the manifest's regions, so R is gone without a line. Scenario 2: R is entered during a Save, so the saved `project.json` lacks R while the session holds it. | By reading (AST handler census, executed: the only `action_*` / `on_*` handler that reaches a session write without a refusal). | Capture only while idle: `if self._running_session_action() is None: self._declared_regions = …`. Keep the report generate itself, since reports overlap by design (Q2), and optionally add one log line. Or rule it residual and record it at close. |
| CR12b-4 | NIT | impl | `a2l.py:194` | **The callback-free parse is not strictly the base parse.** `os.fstat(handle.fileno())` now runs inside the `try` even with `progress=None`. If it raised OSError, the parse would log and re-raise where the base parsed. On a just-opened regular-file handle this cannot realistically happen, so every output is byte-identical in practice. | By reading | `total = os.fstat(handle.fileno()).st_size if progress is not None else 0`. Or leave it as is. |

## Seam rulings (the orchestrator asked for a view)

- **SR12b-2: guard both calls.** See CR12b-2. The `validate_project_files` half is not a microsecond window. It fires whenever the open project folder has been moved or deleted outside the app, which is an ordinary user action, and the result is an app exit. Each guard is one `try` before the begin, with the existing refusal text, so it adds no new seam and no new line wording. If the corrective pass is held to a minimum, guard `validate_project_files` at least. `normalized.stat()` is the microsecond residual and could go to BACKLOG-CODE.
- **SR12b-6: residual risk is acceptable. If a guard is added, it belongs inside `_save_project_files`, not in the worker's outer catch.** By reading, every C5 statement (`app.py:12064`–`:12150`) is one of three things:
  - pure string or path arithmetic (`painted_names`, `PurePosixPath`, set or tuple building);
  - guarded already (`document_row.landing.relative_to(project_dir.resolve())` catches `(ValueError, OSError)`);
  - operations on absolute paths (`request.document_source_path.absolute()` returns `self` for an absolute path without `getcwd`; every producer I found builds it from `project_dir.absolute()` or the workarea). The one theoretical raise is `.absolute()` on a relative `document_source_path` with a deleted working directory.
  The consequence would be a false `Project NOT saved … unexpected error` over a committed folder, with the session not rebound. A retry would then save into the existing project, so no data is lost. If a guard is wanted, the smallest correct one wraps the C5 block in `try/except Exception`. It logs with `logger.exception` and returns the committed `SaveOutcome` with `skipped_links`, `source_gone` and `document_source_path` set to `None`, so the outcome stays true and only the optional tail lines are lost. That adds no `except OSError`, so P1-66 holds. My recommendation: BACKLOG-CODE as residual risk, with this sketch attached.

## Checked and fine

All by reading unless marked as a probe or a census.

- **No session or widget write off the main thread.** AST census (executed) of `self.*` in every function the three workers run: `_project_load_worker`, `_prepare_project_load`, `_parse_data_file`, `_load_mac_file`, both merge helpers, `_log_loaded_file_summary`, `_save_project_worker`, `_save_project_files`, `_copy_project_subfolders`, `_abort_save`, `_restore_manifest`, `_keep_previous_manifest`, `_write_manifest_for_save`, `_unrecorded_document_lines`, `_a2l_attach_worker`, `_progress_forwarder`.
  - **Writes:** 0. The functions above write no `self.*` attribute at all.
  - **Reads:** only `logger`, bound methods, and `call_from_thread` / `step_busy`. Every `step_busy`, end and handler call from a worker goes through `call_from_thread`.
  - **Fresh objects:** the worker mutates only objects it made itself (`variant_set.active_id`, `image.variant_id`, `state.document.source_path` on the freshly read state).
  - **Explicit inputs:** `_parse_data_file` takes `existing` explicitly, so the project worker merges the MAC with its own image (the P1-19 negative control holds).
- **Immutable requests.**
  - The request and result types are `frozen`.
  - The pasted document goes to the worker as `copy.deepcopy`. A file-backed document row is skipped by the worker (`row.source is not None` → `continue`), so the live document is never read there.
  - `SaveImageInput.derived` and `summary` are live objects, but the worker only reads them. The `summary` writes happen in `_on_project_saved` on main. Every Patch Editor writer is refused while the Save runs (census below).
- **Generation and staleness.** The install handlers (`_install_prepared_project`, `_install_attached_a2l`, `_on_project_saved`) do not compare generations. As designed (proto R-6), they rely on no session action overlapping another. The census found no path that begins a session key without a refusal first:
  - `_load_workarea_file`'s `go` begins `file_load` directly, but only behind `_confirm_then_load`'s refusal. The re-check before the deferred call was removed by A12b-03, with its reasoning recorded.
  - Every step and end is gen-checked (`step_busy`, `end_busy`, `_busy_fail`), so a replaced run paints nothing.
- **Busy rule.** Census (executed): `_refuse_if_busy` is the first statement of the 16 entry points and the 4 continuations listed in `E4-app-notes.md`, and of the start functions (`_confirm_then_load`, `_commit_project_save`, `_handle_load_project`, `load_from_path`, `load_a2l_from_path`). The two `LoadGuardScreen` `_answer` closures refuse in their accept arm. The only handler reaching a session write without a refusal is CR12b-3.
  - `_refuse_if_busy` writes one status line and a log line, and nothing else.
  - `_running_session_action` reads `runs` newest-first and filters on `SESSION_ACTION_KEYS`, so reports still overlap.
- **Quit question.**
  - `action_quit` exits when idle, ignores a second `ctrl+q` while the question is on the stack (Q-c2), and otherwise asks with the painted label.
  - `_answer_quit` sets `_quit_pending = bool(quit)`, so the last answer wins (C12b-26 b; SR12b-3 accepted).
  - `end_busy` calls `_exit_if_quit_pending()` only on an effective end, after the hand-back. A stale end returns `False` first.
  - The session failure arms clear `_quit_pending` before their end: `_on_project_saved` failure, `_on_project_loaded` refusal, `_on_project_load_failed`, both `_on_a2l_attach_failed` arms, and `_handle_load_error`. The `_busy_fail` crash paths keep it, which is loud either way.
  - In every main-thread end handler the end call is the last statement.
- **Every exit reaches one end.**
  - Each kickoff wraps request building and worker start in `except BaseException: _busy_fail; raise`.
  - Each worker splits step failures (`except Exception` → the failure handler on main) from defects (`except BaseException` → `_busy_fail` on main, then re-raise, which triggers Textual's `exit_on_error`).
  - A raise inside `_on_project_saved` propagates back through `call_from_thread` into the worker's outer guard. There the run is already ended by the CR12a-1 arm, so `_busy_fail` does nothing and the re-raise stays loud (SR12b-1 as ruled).
- **Save rollback after mkdir (apart from CR12b-1).**
  - `total` and the forwarder are computed before `mkdir` (S12b-06). The statements between `mkdir` and the `try` are pure (`_PlacedFiles()`, `document_home_for_kind` is a token comparison, `next(…)`, `dict.get`).
  - Every cross-thread call after `mkdir` sits inside the rollback `try` (S12b-07). An app shutdown mid-save (`call_from_thread` → `RuntimeError`) is caught by the `except Exception` arm and rolled back, since nothing is committed before the manifest write.
  - All 11 abort exits return `_save_failure_outcome(…)` after `_abort_save`. The early aborts pass no `kept_copies`, as in the base, because none exist yet.
  - The F-1 fix (`prepared.target_carry`) and the F-13 form (`os.path.lexists`) are correct.
  - The document placement now joins `placed_files` the moment it lands (inside `_place_doc`), which is at least as tight as the base.
- **CR12a-1 committed tail.** `saved_line` is composed first. `tail[:-1]` is painted, then `end_busy(tail[-1])`. On a raise, an open run ends with `saved_line`, or with no line when the tail already painted it, and the error is re-raised. This matches SR12b-1.
- **Project load.**
  - The cheap refusals stay in the request frame, unchanged from the base.
  - `read_only=True` is set after the begin and cleared on every removal of the `project_load` run (`end_busy`), including the refusal and failure ends and `_busy_fail`.
  - The install is deferred with `call_after_refresh` after the step-4 paint. The run stays open in that gap, so a second session request is refused.
  - The A2L parse failure on the worker becomes a `not readable` problem and the load continues, as in the base.
- **A2L attach.**
  - The recent-source decision is made on main and the store happens in the install (P2-9).
  - `copy=False` is used only by the work-area pick, after its `lstat` re-check.
  - A containment refusal and a read failure take separate arms.
- **The A2L parse with no callback.**
  - `parse_a2l_cached` calls `parse_a2l_file(path)` without the keyword when `progress is None` (fixed Q-f2).
  - `build_section_tree` adds only `if progress is not None` guards and the `fstat` (CR12b-4). The tree, errors and tags are built by the same statements.
  - `handle.buffer.tell()` on the binary buffer is legal during text iteration (the `TextIOWrapper.tell()` restriction does not apply). It never decreases and is at most the file size, and the final `progress(total, total)` closes the step.
- **Progress forwarder.** It forwards at most once per percent change, plus every report at or past `total`. `total == 0` forwards `(0, 0)`, and `step_busy` maps that to fraction 0. The closure reads no session attribute.
- **SE5-12a-4 code.** `load_from_path` and `load_a2l_from_path` wrap the use-time `resolve_input_path` in `(OSError, ValueError, RuntimeError)` → the existing not-found line before any begin. CR12b-2 covers the remaining calls.
- **OBS-12a-1.** `ProgressBar(…, show_eta=False)`. The 29 snapshots are owed to the CI regeneration (SR12b-5 ruling).
- **Simplicity and reuse.**
  - There is one module-level cache seam (`parse_a2l_cached`) that replaces `_load_a2l_data_with_cache`.
  - There is one failure-outcome builder.
  - The three retired functions have no remaining callers (grep).
  - No speculative parameters. `routed` replaces the base's identity test in `_route_load_project`.

## Evidence states

- CR12b-1: probe `executed` (RED shape reproduced on `81ac4c0`); base parity `by reading`; fix `planned` (not mine to apply).
- CR12b-2: probe `executed`; fix `planned`.
- CR12b-3: census `executed`; scenario `by reading` (no probe run).
- CR12b-4: `by reading`.
- Evidence transcripts `green-01`, `green-02`, `guards-01`: `not-run` by me (read the integrator's counts only).

## Evidence checklist

- [✓] Diff read in full for the source (`git diff -w main...b100-inc12b -- s19_app`); the line ranges are listed above.
- [✓] Correctness pass: edge, None and error paths. CR12b-1 (rollback), CR12b-2 (unguarded OSError).
- [✓] Concurrency pass: worker `self.*` census and the generation and overlap reasoning.
- [✓] Simplicity pass: no premature abstraction found.
- [✓] Reuse and duplication checked: one cache seam, one failure builder, the retired helpers have no callers.
- [✗] Tests reviewed for intent: sampled only. Gap found: no arm pins the pasted-document home rollback (CR12b-1).
- [✓] Verdict explicit: FAIL, BLOCK-UNTIL CR12b-1 (applied and verified on the diff).

## Re-review (c026bd2)

**Final verdict: PASS-WITH-NOTES.** BLOCK-UNTIL CR12b-1 is discharged: I re-read the fix on the diff. The corrective hunks bring in no new defect that blocks. One new NIT (CR12b-5) does not block.

Scope: `git diff 81ac4c0..c026bd2 -- s19_app tests`. HEAD is `c026bd2` and `s19_app/` matches it, so the working tree is clean there. Source: `app.py` +40/-2 and `a2l.py` 1 line. Tests: the new regression arms in `test_b100_save_guards.py`, `test_b100_workers.py` and `test_b100_a2l_progress.py`. Evidence read: `red-03-corrective.txt`, `green-03-corrective.txt`, and `E5-rulings.md`. I did not re-run anything, because a mutation run is still on the host.

| Id | Status | Re-read |
|---|---|---|
| CR12b-1 | **closed (`approved`)** | `app.py:11664`–`:11668`: `created_dirs.append(created_home)` now sits before `write_change_document`, and the append after the success was removed. The rollback removes folders only while they are empty, so recording the home early is harmless on success. P1-66 is unchanged, with no new `except OSError`. The regression arm `test_tc_b100_07_pasted_document_home_created_then_write_fails_no_folder_left[no-space, placement-refused]` is my probe's shape. It has a vacuity check (the home was made, under `freshd`), the status is checked, `folders == ['patches', 'temp']`, and the pasted entry stays in the Patch Editor. It is RED on the base copy (`red-03`: `['freshd', 'patches', 'temp']`, `s19_app.__file__` = the base copy) and GREEN on `c026bd2` (`green-03`: 2 passed). The `no-space` arm raises a bare `OSError(28)`, which reaches the `except OSError` in `write_change_document`, so both failure classes are covered. |
| CR12b-2 | closed | `load_a2l_from_path`: `validate_project_files` is in `try/except OSError`, with the existing `unreadable` tokens and the project name passed through `painted_names` and `safe_text`. `normalized.stat()` is in `try/except OSError` → `A2L file not found: <typed>`. It never falls back to a size of 0, so the size rule cannot be bypassed. Both refusals come before the begin, so no run is open and no end is owed. Arms `test_tc_b100_54_…vanished[project_folder, a2l_size]` are RED, then GREEN. |
| CR12b-3 | closed | The regions are captured only when `_running_session_action() is None`. The report is still generated with `message.declared_regions`, so the report itself keeps the regions the user typed and only the session field is protected. Arm `…report_generate_keeps_the_regions_of_a_running_save` is GREEN. |
| CR12b-4 | closed | `total = … if progress is not None else 0`. Without a callback, `total` is never read. Arm `test_tc_b100_73_no_fstat_without_a_callback` (fstat patched to raise) is RED, then GREEN. |
| SE5-12b-1 (security review) | applied; one NIT below | `_on_project_saved` sets `_quit_pending = False` before the final `end_busy` when `outcome.document_lines` is not empty or the "has unsaved edits" line was added. The placement is correct: the withdrawal comes before the end, whose quit check then reads it. The CR12a-1 `except` arm does not withdraw, and that path re-raises loudly anyway. Arms for scenario A and scenario B are GREEN. |

### New finding

| Id | Sev | Tag | Where | Defect | Evidence | Fix |
|---|---|---|---|---|---|---|
| CR12b-5 | NIT | design-gap | `app.py:12244`–`:12246` (`unsaved_work_left = bool(outcome.document_lines)`); `E5-rulings.md` SE5-12b-1 | **The trigger is wider than the ruling's "in-memory work unsaved".** `document_lines` also carries lines about records on disk, where no in-memory work is lost: `prepared.carried_document_line` (a damaged recorded document dropped from the manifest, or an `io_error` record that "stays recorded", built at `app.py:11025`–`:11041`), the kept-manifest "record … was dropped … kept as …" line, and `_unrecorded_document_lines` for a file-backed document that is already on disk. Scenario: the user confirms the quit during a merge Save into a project whose recorded document is damaged. The Save succeeds and its only document line is the drop note, yet the app stays open and the user has to quit again. Nothing is lost; the cost is one extra keypress. | By reading | Leave it as a conservative choice and record it at close. Or narrow the trigger: set the flag only where a memory-held entry was not written (`document_write_failure`, the "link or outside the work area" line, and the "has unsaved edits" line), for example by having the worker report a `memory_work_unsaved: bool` fact in `SaveOutcome`. |

### Re-review evidence checklist

- [✓] Corrective diff read in full for the source (`app.py` 6 hunks, `a2l.py` 1 hunk).
- [✓] CR12b-1 fix applied, and verified on the diff and by its RED → GREEN arm.
- [✓] No new HIGH or MAJOR in the corrective hunks.
- [✓] Verdict explicit: PASS-WITH-NOTES. Open notes: CR12b-5 (NIT); SR12b-6 is residual risk, as ruled.
