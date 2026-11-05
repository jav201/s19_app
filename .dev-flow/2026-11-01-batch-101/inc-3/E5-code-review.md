# Inc 3 — E5 code review

Batch 2026-11-01-batch-101, increment 3. Reviewer: code-reviewer (independent of the implementer, the tester and the integrator). Tree: worktree `b101-inc3`, head `6355565`. Scope: `git diff main...HEAD -- s19_app tests` (9 files, +812/-41). Read-only review: no test was run here. On this host the operator's rule sends test runs to the LAN Linux host, and another E5 agent owns the mutants and the LAN runs. Result claims are read from the integrator's and the tester's transcripts. Evidence states follow `/dev-flow` §*Evidence states*.

## Verdict

**PASS-WITH-NOTES.** There is no BLOCKER and no MAJOR finding. The product change is exactly the graph's: three functions in two source files, with no signature or text change. The refusal lines are canon text, and the tests assert them as independent literals. The R-TST-110…113 verifiers measure what their rows say and none can pass vacuously on its main path. Seven MINOR findings and one NIT remain. CR-1, CR-4 and CR-5 are cheap test-only fixes that make an existing check discriminate. They are recommended before merge but do not block it.

## Findings

| Id | Tag | Severity | Where | Finding | Suggested fix |
|---|---|---|---|---|---|
| CR-1 | impl | MINOR | `tests/test_b100_project_check.py:836`, `:890` (both call `_summary_laid_out`, `:796`) | **The verifier's observer shares the arm's "laid out" predicate.** The graph node `_StampObserver` says the observer stamps "by the same rule as `_watch_panel_paint`, written separately", and I-7 says it shares nothing with the arm. Both callbacks call the one helper `_summary_laid_out`. Scenario: an edit makes the helper `return summary is not None`, dropping the height check. Both stamps move to the first publish after mount, together, and the verifier stays green. The F4 row-count assert catches this only if the rows mount after the summary. Shared state: none. Shared logic: yes. | Inline the observer's own check in `_StampObserver._push._on_layout`: `s = screen.query_one_optional("#result_summary"); if observer.paint is None and s is not None and s.size.height > 0: …`. |
| CR-2 | design-gap | MINOR | `tests/support/suite_census.py:23-35`, `tests/test_suite_hygiene.py:147-152`; `tests/test_b97_flow_execution.py:1574-1575` and the other `pilot.pause(0.6)` + `press("c")` sites (`:572`, `:796`, `:1281`, `:1490`, `:1627`, `:1657/1670`, `:1740`, `:1877`) | **OR-5: the hand entry fits the guard's mechanism, but it covers 1 of about 10 arms of the same form.** It is consistent with R-TST-002's guard. The pin `set(SAMPLED_TIMING_ARMS) == _SAMPLED_PIN` (`test_suite_hygiene.py:388`) makes every hand addition explicit and reviewed. A renamed or deleted entry leaves an unmarked arm in `arm_set`, so the guard goes red and the entry cannot go stale silently. What it does not do is close the census gap it names. `test_tc_b97_64_two_external_steps_end_ok` performs the identical `press("c", "c")` after a 0.6 s dwell and stays in the parallel lane. So does every other dwell-and-press arm of TC-B97-64 and TC-B97-55. A slow xdist worker can fail them the same way CI run 42037470050 failed the burst arm. The gap is not hidden, because the comment says "listed by hand until the census learns", but the backlog row does not name the siblings. Naming: the constant is now called "sampled" but also holds a press-burst arm. | The backlog row for the census press-burst form names the sibling nodes above (or the pattern `pause(<dwell>)` followed by `press`). Optionally rename the constant to `HAND_LISTED_TIMING_ARMS` when the census learns the form. No Inc 3 change required. |
| CR-3 | design-gap | MINOR | `tests/test_b100_project_check.py:1655` (`_STAMP_TOLERANCE_S = 0.001`) | **The 1 ms equality is measured robust only on one Windows host, 6 node runs.** OR-1 has the right root cause: a full `query` walk sat between the paired stamps. The fix is right too: `query_one_optional`, stamps first, and observer callbacks ordered first. Residual gaps are 33-48 µs for the panel and 2.7-4.1 µs for the append (`int-01-verifier-diag.txt`, executed), about 20x under the tolerance. Nothing protects the two paired-stamp windows from a gen-2 GC pass or a GIL hand-off to a live worker thread. The heap holds about 1 000 widgets and a 6 000-entry manifest, so one such pause would be a false RED on a GREEN tree. The mutants are 50 ms or more off (M-6 0.54 s, M-7 0.41 s), so a 5 ms tolerance would lose no discrimination. Known coupling: `[scene]` also inherits the `sec6_5 load` flake through `_assert_sec6_5_bounded` (OR-4, integration failure 4). | Leave the ruling at 1 ms. E5's LAN and CI runs should record the arm-minus-observer gap, as int-01 did. If any gap exceeds 0.5 ms (N-3's trigger), raise the tolerance to 5 ms by ruling, or run the scene under `gc.disable()`/`gc.enable()`. Evidence state of LAN 3/3: `not-run` here. |
| CR-4 | impl | MINOR | `tests/test_project_gather.py:725`, `:794-795` | **R-PROJ-GATHER.12 arm 3 cannot see the fold.** The spy records `normcase(normpath(path))`, so "1 check, on the lexically folded path" holds whether or not the product folds. That is why mutant M-9 (fold removed) survives on Windows: the Win32 layer folds `..` itself, so the outcome assert passes as well. It discriminates on POSIX only, through the outcome. | Record the raw text as well: `raw.append(os.path.normcase(str(path)))`. Assert `raw == [os.path.normcase(str(fold_dir / "x.json"))]`. Head passes (`Path(os.path.normpath(...))` has no `..`). M-9 records `…\missing\..\x.json` and fails on both platforms. Base (`resolve()`) passes, as the row requires. |
| CR-5 | impl | MINOR | `tests/test_b100_workers.py:4038-4041` | **R-PROJ-002.14 s19/hex/mac can pass without reaching the sync.** These arms discard `lines` and assert only `exists is False`. Scenario: a later change makes the load refuse or fail before the sync is posted. Then the folder is absent and the node passes, while R-PROJ-002.12's node fails. The a2l arm already guards this with `lines[-1] == "A2L loaded: firmware.a2l"`. | Keep `lines` and assert `lines.count(SYNC_REFUSAL) == 1 and lines[-1] == f"Loaded other.{kind}"` before `exists is False`. |
| CR-6 | impl | MINOR | `s19_app/tui/services/project_gather_service.py:593-596` (Data Flow), `:654-660` | **Convention: the rule is not stated where a reader would undo it.** The docstring's Data Flow still says only "project-dir hit → already home". The loop carries no comment explaining why it skips repeats and avoids `resolve()`. The reasons are performance (R-PROJ-GATHER.12) and link loops (R-PROJ-GATHER.13), and neither is obvious. Restoring `.resolve()` "for safety" looks harmless, yet it is mutant M-1. | Add one Data Flow clause: "each distinct name text once (R-PROJ-GATHER.12), on the lexically folded join, links not resolved: a link loop falls to the library (R-PROJ-GATHER.13)". Optionally add the same as a one-line comment above `in_project = …`. |
| CR-7 | impl | MINOR | `tests/test_b100_project_check.py:1576-1577` | **The R-TST-110 node's docstring states the rule it replaces.** It reads "starts at the install stamp, whichever came later: the click or the install", which is the retired `max` rule. The code and R-TST-110 say install stamp, always. The asserts are correct (`10.0` for install 10 and click 12). | "The panel paint clock starts at the install stamp, never at the click, whichever came later." |
| CR-8 | impl | NIT | `tests/test_b100_project_check.py:1658-1667` (third copy of `_folders`, also `:1280`, `:1305`); `tests/test_project_gather.py:715` (each arm stacks a new `Path.is_file` spy over the previous one; correct because the prefixes differ); `tests/test_b100_active_variant.py:88` (import placed between two `b100_load_dialog` imports) | Small duplication and ordering. | Optional. |

## Checks asked for

1. **Code matches the graph and the requirements: yes, exactly.**
   - `project_gather_service.py:655-660`: a `checked_names` set keyed on the exact text, then `Path(os.path.normpath(resolved_project / name)).is_file()`. No `resolve()`, no new import. Order is unchanged, the first occurrence is kept, and limbs 2a/2b and `_schedule` are untouched.
   - `app.py`: only the two `mkdir` lines go. The `try`, `validate_project_files` and the `except OSError` refusal are unchanged.
   - Out-of-slice functions untouched (`_reject_unsafe_entry`, `_EntryWalk`, `_entry_text`): verified, since the diff touches no other `s19_app` file.
2. **Correctness of the gather change.**
   - Same file, different texts (`x.json`, `./x.json`, `x/../x.json`, and on Windows `X.json` and `sub\x.json`): each text gets its own check. All fold to the same path, so all get the same answer. Nothing can be gathered twice, because `_schedule` de-duplicates by resolved source exactly as at base.
   - A missing name cannot be hidden. Only an identical text is skipped, and it would get the identical answer. Two different texts naming one missing file give two findings, as at base.
   - `normpath` without `resolve` gives the same booleans as base on Windows, where Win32 folds lexically (E3-r2 executed 16 names). On POSIX it differs only for a link before `..` (I-1, E1-D8, N-1).
   - NUL name: `is_file()` swallows `ValueError` on 3.11 and 3.12, giving one finding and then the writer's refusal (N-2, admitted in I-1).
   - Removed `mkdir`: the only product callers are the file-load worker's `call_from_thread` (`app.py:18451`) and the A2L install (`:15673`). Neither reads a return value. `current_project`/`current_project_dir` are assigned only after a save or load into an existing folder (`:12600`, `:14007`).
   - Test census (F10) of `current_project = ` and `current_project_dir = `: every site that loads a data file afterwards creates the folder first (before_after_report, report_logging, segment_split, open_folder_chips, directionb `_flow_project`). The sites without a folder (commandbar, directionb:981) trigger no sync.
   - Refusal lines: the tests use the literal `Project sync NOT done: project 'P2' could not be read — check that the folder can be opened, then load again.` and the A2L twin (`test_b100_workers.py:3277`, `:3883-3884`), equal to canon R-PROJ-002.12/.13.
3. **R-TST-110…113 verifiers.**
   - 110: rule asserted both ways, plus a missing-stamp failure. The 3 sites are checked by AST: partial, but the 111 verifier covers the values.
   - 111/112: the arm values pass through the real `report_margin` (I-6), compared against class-level observer stamps (I-7) with `math.isclose(abs_tol=0.001)`. The verifier cannot pass vacuously:
     - a missing label fails;
     - a missing observer stamp fails;
     - an empty `stamps` list fails;
     - an install that lands after the paint leaves `observer.installed` unset, so it fails.
   - M-5 to M-8 were RED in the tester's run (`red-01-tester-base.txt`). M-6/M-7 were re-checked on the final file by the integrator; no transcript was kept (`executed`, unarchived).
   - OR-1's explanation (paired stamps first, `query_one_optional`) is verified in code at `:835`, `:889`, `:1092` and the observer's `_status`. The residual risks are CR-1 and CR-3.
   - 113: an AST check that fails closed. A keyword-form or moved call counts 0 sites and is flagged. The planted 1.5 s copy is flagged inside the node.
4. **OR-5:** see CR-2. The hand entry is consistent with the guard and stays visible through the pin. The gap of sibling arms in the same form is real and should be named in the backlog row.
5. **Exact expected results.** The new nodes assert exact lines and counts, exact `gathered` dicts, `lexists` False, `runs == []` and app alive. The exceptions are CR-4, CR-5, and `test_r_proj_gather_13_*`, which assert `gathered` but not `issues == []` (acceptable: the row's threshold names only `gathered`).

Security observations are left to `E5-security.md`, coverage gaps to `E5-coverage-audit.md`, and mutants to `E5-mutants.md`.

## What I read

- Diff `main...6355565` for `s19_app/tui/services/project_gather_service.py`, `s19_app/tui/app.py`, and the tests `test_project_gather.py`, `test_b100_workers.py`, `test_b100_active_variant.py`, `test_b100_project_check.py`, `test_b97_flow_execution.py`, `test_suite_hygiene.py` and `support/suite_census.py`.
- Context read in full:
  - `gather_project_artifacts` (`:525-720`);
  - both sync functions (`app.py:14897-15085`) and `_active_project_dir`;
  - the arm wrappers and `_assert_sec6_5_bounded`;
  - `wait_until`;
  - the R-TST-002 guard (`test_suite_hygiene.py:381-396`);
  - the TC-B97-64 family.
- Records: `01-requirements.md`, `E1-slice.md`, `codewire/graph-inc3.md`, `E1-rulings.md`, `E3-rulings.md` (with round 2 N-1…N-3), `E3-r2.md` (N-rows), `E4-impl-notes.md`, `E4-tester-notes.md`, `E4-integration-notes.md`.
- Transcripts: `int-01-verifier-diag.txt`, `int-05-verifier-3of3.txt`, `int-06-serial-lane-rerun.txt` (tail), `red-01-tester-base.txt` (result lines).

## Evidence checklist

- ✓ Diff read in full: `project_gather_service.py:654-660`, `app.py:14937-14940` / `:15059-15062`, all 7 test-file hunks.
- ✓ Correctness pass: exact-text key, `normpath`, NUL, the callers of the removed `mkdir`, the refusal literals (check 2).
- ✓ Simplicity pass: the product change is minimal. The test helpers are proportionate. Duplication NIT in CR-8.
- ✓ Reuse checked: `wait_until`, `report_margin` and `b100_links`/`b100_projects` are reused. The `_folders` copy is the one exception (CR-8).
- ✓ Tests reviewed for intent: each new node carries a "why" and a negative control. CR-4 and CR-5 are where a check can't fail on the change it guards.
- ✓ Verdict explicit: PASS-WITH-NOTES. No HIGH/BLOCKER is open, so none needs applied-and-verified evidence.
