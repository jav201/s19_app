# Inc 3 — E5 corrective notes

Batch 2026-11-01-batch-101, increment 3. Author: E5 corrective agent (Opus). Input: the rulings C-1 … C-11 of `E5-rulings.md`. Tree: branch `b101-inc3`, head `6355565` plus the E5 records. Evidence states follow `/dev-flow` §*Evidence states*.

Where each run ran:

- **LAN Linux host** (Python 3.11.18, `s19ci`): every test run, unless noted. It ran in a private remote worktree of `9f9f6af` with this working tree's diff applied (re-synced after each edit). `s19_app.__file__` is printed in each transcript. The worktree is removed at the end.
- **Windows PC** (s19env, Python 3.11.15): only the exceptions — the junction arms, C-2's M-9, and C-10. These ran in a detached worktree under the temp folder, with `LOCALAPPDATA` and `--basetemp` isolated and one pytest at a time. That worktree and its temp folders are removed. The real `%LOCALAPPDATA%\s19_app` was not created (the folder that exists predates this session), and the clipboard was not touched.
- **Mutants** are applied by exact text replace, then the run, then a byte-exact restore with sha256 printed (`REVERTED byte-exact` in every transcript).

## Ruling → change → evidence

| Ruling | Change | Evidence (state) |
|---|---|---|
| **C-1** (CR-1) | `_StampObserver._push._on_layout` now makes its own `query_one_optional("#result_summary")` and height check. It no longer calls the arm's `_summary_laid_out`. `_summary_laid_out`'s docstring says so. | `e5c-c1-observer-own-reading.txt` (executed, LAN). **M-C1** (the shared predicate fires one layout pass late): head form GREEN 3/3, which is the gap; C-1 form **RED 3/3** (all-bad 0.690 vs 0.339 s, cap 0.685 vs 0.402 s, scene 0.645 vs 0.375 s); unmutated C-1 form GREEN 3/3. Finding: the natural predicate mutants are **equivalent** on this panel (textual 8.2.8). Dropping the height check, `return True`, and waiting for the scrollbar all leave both stamps on the same publish, because the first layout publish already has the summary laid out (probe: 3 publishes per panel, summary 5-6 rows high and all rows mounted at the first). They are GREEN in both forms and are recorded in the same file. |
| **C-2** (CR-4) | `_spy_project_file_checks` takes an optional `raw` list and records `os.path.normcase(str(path))`, so `..` is kept. Arm 3 asserts `raw == [normcase(str(fold_dir / "x.json"))]`. | `e5c-c2-m9-lan-and-windows.txt` (executed). Windows: M-9 against the head form of arm 3 is GREEN (it survives); against the C-2 form it is **RED** (`…\r\missing\..\x.json`). LAN: M-9 RED, and unmutated GREEN. The Windows unmutated run is in `e5c-c7-c8-rollback-mutants.txt`. GATHER.12/3's Result follows: verified on win32 and on linux. |
| **C-3** (CR-5) | The R-PROJ-002.14 s19/hex/mac arms now keep `lines` and assert `lines.count(SYNC_REFUSAL) == 1` and `lines[-1] == f"Loaded other.{kind}"` before `exists is False`. | `e5c-c3-c8-sync-mutants-lan.txt` (executed, LAN). **M-C3** (the load never posts the sync): head form GREEN 4/4, which is the gap; C-3 form **RED** on s19/hex/mac. M-3 and M-4 are still RED. |
| **C-4** (CR-6, CR-7) | `gather_project_artifacts`'s Data Flow gains one bullet. It says each distinct name text is checked once (R-PROJ-GATHER.12) on the lexically folded join, never `resolve()`. The reasons: `resolve()` raises on a link loop, which must fall to the library (R-PROJ-GATHER.13), and it walks every component. The R-TST-110 node's docstring now reads "at the install stamp, never at the click". | Docstring only; covered by the final lanes. |
| **C-5** | For `save-project`, `test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second` asserts `outcomes[0] == "Project saved + manifest verified"`. GATHER.12/1 stays `partial` with the audit's reason. | C-10 runs and the final serial lane (executed). |
| **C-6** | none (runs only) | `e5c-c6-m6-m7ci-final-file-lan.txt` (executed, LAN, final file). **M-7 with `CI=1`**: RED by the equality, `sec6_5 appended` 0.826 s recorded vs 0.482 s stamped, and the 2 s bound did not trip. **M-6**: RED on all 3 parameters by the equality (0.942/0.339, 0.796/0.399, 0.785/0.265 s). R-TST-112's open item in the audit is closed. |
| **C-7** | New case R-PROJ-ROLLBACK.2/2 and node `test_r_proj_rollback_2_a_failed_save_keeps_a_patches_folder_that_existed_before`. Helpers `_link_loop_at` / `_remove_link` make a junction on Windows and a self-symlink elsewhere, so the node also runs on Linux. New mutant **M-12**: `home_preexisted` forced False. | `e5c-c7-c8-rollback-mutants.txt` (executed). GREEN on Windows and LAN. M-12 RED on both platforms (`(False, False, None)`: `patches/` removed). M-10 and M-11 are RED too. |
| **C-8** | Three black-box nodes through keys. (a) `test_r_proj_rollback_9_by_keys_save_project_with_a_link_loop_swapped_in_at_a_composition_name`: `ctrl+s`, `tab` `tab` `space` in `#assign_batch`, `alt+s`. The dialog lists only regular files (`_assignment_candidate_files`), so the loop is swapped in while the dialog is open; that is an injected precondition. (b) `test_r_proj_002_12_by_keys_a_load_over_unsaved_work_into_a_deleted_project_folder`: `ctrl+l`, typed path, `enter`, the replace question, `y`. (c) `test_r_proj_002_13_by_keys_an_a2l_typed_into_the_load_dialog_into_a_deleted_project_folder`: `ctrl+l`, typed `.a2l`, `enter`. It reuses the attach helper through a new `by_keys=False` keyword, and the delete is injected as in the handler node. Each node asserts the exact refusal count, the exact last line and that no folder exists. | `e5c-c3-c8-sync-mutants-lan.txt` and `e5c-c7-c8-rollback-mutants.txt` (executed). (a) GREEN on Windows and LAN; M-10 and M-11 RED on both. (b) GREEN on LAN; M-3 RED. (c) GREEN on LAN; M-4 RED. No case needed `partial` for lack of a key route. (a) reaches the loop only by the swap, as its docstring says. |
| **C-9** (CR-3) | The verifier prints `GAP <label>: … us` for each pair. | `e5c-c9-stamp-gaps-lan.txt` (executed, LAN). Idle runs 4-6: panel +30.9 to +52.4 us, append -2.8 to -3.9 us. Runs 1-2, under another agent's 8-worker load: up to +79.7 us. Run 3, under load, stopped at the arm's own 1 s bound (`sec6_5 appended` 1.0009 s) and is not counted. Every gap is under 0.5 ms, so the tolerance **stays 1 ms** and no E3 amendment is needed. |
| **C-10** | none (runs only) | `e5c-c10-save-project-windows.txt` (executed, Windows): `save-project` at 0.525, 0.582 and 0.515 s, so 5/5 with the 2 on record (0.694, 0.561). All are under 0.8 s, with margins of 30.6-48.5 %. M-10 and M-11 with the ROLLBACK.9/1 junction node: **RED** on Windows (`e5c-c7-c8-rollback-mutants.txt`). Both were `not-run` before. |
| **C-11** | `02-test-cases.md`: the audit's change table is applied. GATHER.12/2 → full. The GATHER.12/1 and 001.13/1 partial reasons are rewritten. GATHER.12/3 → full after C-2. The F4 clause is added to R-TST-111/2 and /3. Every Result is per platform (`verified (win32, …)` / `verified (linux, …)`, `n/a` for the junction cases on linux, `not_run` with its reason). 4 cases are added (ROLLBACK.2/2, ROLLBACK.9/2, 002.12/7, 002.13/3), plus M-12, M-C1 and M-C3 in the negative-control table, and the Count note. `E1-slice.md` §4 gains an E5 paragraph: the R-TST-049 main-ref dependency, the observer's own reading, the 1 ms result and R-TST-008. | For `04-validation.md` (later): `test_r_tst_049` failed on the LAN clone only because the clone's local `main` ref was stale; the orchestrator fixed it (the clone's `main` now follows `origin/main`). It passed in both final lane-1 runs here. |

## Backlog (`.dev-flow/BACKLOG-CODE.md`, CRLF, batch-101 style)

- **CR-2:** the existing `test_tc_b97_64_burst…` row is extended. It now names the 9 sibling dwell-then-press nodes, and its closing condition is widened.
- **E5S-1:** to be folded into "the existing S-3 row". A grep showed that **S-3 had never been pasted** into `BACKLOG-CODE.md`; it lived only in `inc-3/E1-rulings.md` §5. The S-3 row is appended with E5S-1 folded in.
- **E5S-2** and **CR-8:** new rows.
- **OR-4 / D-4:** a new row. D-4 had not been pasted either, so its E1 text is folded in, with a pointer to the Inc 2 R1-P1 row.
- **Not done, for the orchestrator:** E1-rulings §5's S-4 and S-5 rows are still not in `BACKLOG-CODE.md`. No ruling here routes them.

## Final runs

| Run | Platform | Result | Transcript |
|---|---|---|---|
| Lane 1 (`-n 8 -m "not serial_timing"`), 4 touched test files + `test_suite_hygiene.py` + `test_id_registry.py` | LAN Linux | first run, with the host at load 16 (this agent's law-guard run and another agent's 8-worker lane): `2 failed, 316 passed, 10 skipped, 1 xfailed`. The 2 failures are `test_tc_b100_19_save_back_becomes_the_active_variant[A]` and `test_tc_b100_71_emit_records_a_base_outside_the_project`: the count-bounded `_wait_for` timed out ("the project save"). Both are pre-existing, untouched by Inc 3, in the class of the Inc 2 backlog row for count-bounded pause loops, and both pass alone (`2 passed`). Re-run on the idle host (the counted run): `318 passed, 10 skipped, 1 xfailed`, 0 failed, `test_r_tst_049` included | `e5c-final-lane1-lan.txt` |
| Serial lane (`-m serial_timing`), same 6 files | LAN Linux, idle | `23 passed, 1 skipped`; QC-TM `43 bounds, 0 under 20 % margin` | `e5c-final-serial-lan.txt` |
| Law guards (CLAUDE.md): `test_engine_unchanged.py`, `test_tui_directionb.py` (incl. `test_tc031_*`), `test_requirements_canon.py` | LAN Linux | `196 passed` | `e5c-law-guards-lan.txt` |
| Junction arms + GATHER.12/13 + rollback nodes | Windows | `6 passed` | `e5c-c7-c8-rollback-mutants.txt` |
| C-10 `save-project` ×3 | Windows | 3/3 passed, 0.515-0.582 s | `e5c-c10-save-project-windows.txt` |

**Case count and coverage:** 30 cases (26 + 4), 30 covered, 0 `gap`. 27 are full and 3 partial (R-PROJ-001.13/1, R-PROJ-GATHER.12/1, and R-TST-110/1's call-site half). Every case is verified on at least one platform:

- **win32 `not_run`:** R-PROJ-002.12/7 and 002.13/3 (operator rule: these are not Windows-only arms).
- **linux `n/a`:** the 3 Windows junction cases.
- **Run on Windows before C-3:** R-PROJ-002.14/1-4. Their Windows Result names the head form; the C-3 form ran on Linux.

**Mutants:** 11 from the E5 table plus 3 new (M-12, M-C1, M-C3), **14 killed, 0 survived**.

- M-10 and M-11 are now killed on Windows (the junction node) and on Linux (through the new symlink nodes).
- M-9 is now killed on Windows too.
- The test-file count is 3 equivalent mutants for C-1, recorded and not counted.
- **Source files changed by this pass:** 1 (`project_gather_service.py`, docstring only). `app.py` is unchanged; the Inc 3 total is still 2.

## What I could not do, or did differently

- **C-1:** the mutant that proves the RED is test-level and contrived (a call counter in the helper). The natural predicate edits CR-1 names cannot move the stamp on this Textual version (see the equivalents above). The C-1 change still removes the shared logic.
- **C-8 (a):** this is a black-box route with an injected swap. No real user flow puts a link loop into the Save dialog's list.
- **Windows runs of the new by-keys load nodes, the C-3 form and the C-1 observer form:** not run (operator rule). The win32 Results of R-TST-111/112 name E4's head-form runs.
- **Kill of my over-broad law-guard run:** the auto-mode classifier refused it, so the run completed instead (196 tests, all passed). Nothing of another agent's was touched.
- The LAN host was shared with another agent's lanes during part of this pass. Every timing verdict counted here comes from an idle-host run, and the loaded runs are labelled.
