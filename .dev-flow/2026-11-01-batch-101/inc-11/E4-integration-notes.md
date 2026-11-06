# Inc 11 — E4 integration notes

Stage E4 (integration) of the design-first flow. Integrator model: opus. All runs on the LAN Linux host (Python 3.11.18, Textual 8.2.8, pytest-xdist 3.8.0), own detached worktree `<HOME>/work/s19_i11` at `origin/main` f9f3cb09 (identical to b7b77c4 in `s19_app/` and `tests/`; only `.dev-flow/`, `.gitignore` and the archived `prototypes/` differ) with `git diff b7b77c4` of branch `b101-inc11` applied. Nothing was run on Windows. Transcripts: `evidence/inc-11/int-*.txt` (home and account names redacted to `<HOME>` / `<USER>` / `<CONDA>`).

## Verdict

**GREEN.** Every new and re-pinned test passes; all 77 cases of `02-test-cases.md` pass; the importer group, the app / directionb / snapshot group, the law guards and the serial lane are GREEN. The only failures left are the OR-3 freeze guards:

1. the engine freeze guards that compare `rules.py` / `a2l.py` with `main` (OR-3, by design until the merge): TC-027 `test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main`, TC-B94-18's freeze arm, and the two `test_tui_directionb.py::test_tc031_*` nodes (the second guard `CLAUDE.md` names; same cause, see OR-3 below);
Also seen once in a valid run: `test_b100_a2l_progress.py::test_tc_b100_52_project_install_step_is_painted_before_the_install[case_06]` in the 28-file importer group under `-n 6` (int-08, a Textual `WaitForScreenTimeout` on a loaded shared host); the third branch run of the same group is GREEN (int-15, 490 passed) and the test passes alone and in its own file on both trees. See *Environment failure* below.

Code fixes: **none**. The three implementer units match the design; no source line was changed at E4.

## Runs (counts as printed by pytest)

| Transcript | Set | Result |
|---|---|---|
| `int-01-new-and-repinned` | 3 new files, re-pinned files, `test_segment_split_window.py`, `test_engine_unchanged.py` (`-n 6`) | 5 failed, 236 passed — superseded by int-02 / int-07 |
| `int-02-fix-round-1` | AT-I11-3, AT-I11-4, `test_tui_issues_triage_b94.py`, `test_id_registry.py` after the fixes (`-n 4`) | 1 failed (TC-B94-18 freeze arm, OR-3), 16 passed |
| `int-03-importers` | 28 files importing `validation.rules` / `issues_view` / `a2l` | **INVALID** (stray re-sync during the run, see below); 1 failed, 489 passed, 17 skipped, 2 xfailed |
| `int-04-law-guards` | `test_id_registry.py`, `test_suite_hygiene.py`, `test_requirements_canon.py`, `test_engine_unchanged.py` (serial) | 2 failed (TC-607 count, TC-027), 86 passed, 1 deselected — TC-607 fixed, re-run in int-07 |
| `int-05-app-directionb-snapshot` | `test_tui_app.py`, `test_tui_directionb.py`, `test_tui_snapshot.py` | treated as invalid (started within a minute of the stray re-sync); 2 failed (TC-031), 245 passed, 29 skipped, 1 xfailed |
| `int-06-serial-lane` | `-m serial_timing` over the whole GREEN set (serial) | **30 passed**, 1114 deselected |
| `int-07-new-repinned-guards-final` | 3 new files, re-pinned files, `test_segment_split_window.py`, `test_engine_unchanged.py`, `test_id_registry.py`, `test_suite_hygiene.py`, `test_requirements_canon.py` (`-n 6`) | **2 failed (TC-027, TC-B94-18 freeze arm — OR-3), 326 passed** |
| `int-08-importers-rerun` | the 28 importer files (`-n 6`) | **1 failed (tc_b100_52[case_06], environment), 489 passed, 17 skipped, 2 xfailed** |
| `int-09-app-directionb-snapshot-rerun` | `test_tui_app.py`, `test_tui_directionb.py`, `test_tui_snapshot.py` (`-n 6`) | **2 failed (TC-031 ×2 — OR-3), 245 passed, 29 skipped, 1 xfailed** |
| `int-10-b100-52-branch` / `int-11-b100-52-base` | tc_b100_52 alone, branch / pristine base (serial) | 2 passed (case_06 42.1 s) / 2 passed (case_06 48.3 s) |
| `int-12-importers-on-base` | the 28 importer files on pristine `origin/main` (`-n 6`) | 490 passed, 17 skipped, 2 xfailed |
| `int-13-a2l-progress-branch-n6` / `int-14-a2l-progress-base-n6` | `test_b100_a2l_progress.py` (`-n 6`) | 10 passed / 10 passed |
| `int-15-importers-third` | the 28 importer files, third branch run (`-n 6`) | **490 passed, 17 skipped, 2 xfailed** |

Node counts of the new files: `test_b101_a2l_blocks_and_segments.py` 152, `test_b101_issues_severity_view.py` 11, `test_b101_inc11_acceptance.py` 6; `test_tui_issues_triage_b94.py` 3. Skips are pre-existing environment arms (Windows-only junction / share-mode arms, `ruff` absent, `examples/software_a.a2l` / `check_test.a2l` top-level smoke files absent, `case_08_release_demo` without image, and the `test_tui_snapshot.py` module skip "pytest-textual-snapshot not installed").

Runs int-07 … int-15 print a tree fingerprint (sha256 of `git diff` plus untracked files) at start and end; it is identical (`f2c0ee954a895b80`) in every branch run, so no run of that set saw a tree change.

### Stray re-sync (orchestrator notice)

Another agent ran this integrator's scratchpad helper `sync.sh` twice (about 17:56 and 18:10 host time), which did `git reset --hard` + `git clean` in `<HOME>/work/s19_i11` and re-applied the same diff. 17:56: no run of mine was in progress (int-01 ended 17:55:18, int-04 17:52:29; int-02 started after my own re-sync). 18:10: int-03 (18:03:57 → 18:11:21) was running and is **invalid**; int-05 started 18:11:21, within the notice's "about", and is treated as invalid too. Both were re-run as int-08 and int-09 after a fresh re-sync, with the fingerprint check added. int-06 (18:17) is after both events. The helpers now carry an `i11int_` prefix.

## Failures and causes

| Failure (first run) | Cause | Class | Fix |
|---|---|---|---|
| `test_tui_issues_triage_b94.py::test_tc_b94_19_panel_reclassification_matrix`, `::test_at_b94_14_fixture_triage_through_surface` — `NoMatches: .issue-code-chip` | test sync: the waits counted `IssueRow`s, which `query` sees one frame before their `compose` children (the chip) exist; under load the chip read hit that frame | test asserts too early (not a design statement) | helper `_rows_composed(panel, n)`: n rows mounted **and** each holds its chip; the three waits use it. No assertion changed |
| `test_b101_inc11_acceptance.py::test_at_i11_4_split_join_lists_four_demo_segments` — table body stays the manual hint | the case's route "`t` twice" is not the product's: `t` onto the manual tab focuses its localities box (`segment_split_view.action_cycle_tab`, keyboard-first, outside the slice), so the second `t` is typed into the box | design contradicts code → seam ruling **SR-1** | the test presses `t`, Tab, `t` (the user's route out of the box) and opens the window through the palette (OR-8) |
| `test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` — 253 ≠ 250 | three new test modules, no support module | count bump owed by the increment | `EXPECTED_SCANNED_TEST_FILES` 250 → 253, MEASURED by the guard, docstring line added |
| TC-027, TC-B94-18 freeze arm, TC-031 ×2 | `rules.py` and `a2l.py` differ from `main` by plan | OR-3 | none (GREEN after the merge) |
| tc_b100_52[case_06] in the importer group | see below | environment | none |

### Environment failure: tc_b100_52[case_06]

`WaitForScreenTimeout` in `settle_workers`' `pilot.pause()` after the case_06 project (37 MB A2L, 220 040 tags) installed: the main thread did not drain its messages within Textual's 30 s while five other xdist workers ran heavy TUI tests on an 8-core host shared with the Inc 4 integration (load average 10–17 during int-03/int-08). Evidence that it is not an Inc 11 regression:

- alone: branch 42.1 s, base 48.3 s, both pass (int-10 / int-11); its own file under `-n 6`: 10/10 on both trees (int-13 / int-14);
- the branch does **less** work on case_06: a probe of `parse_a2l_file` + `validate_a2l_structure` gives parse 10.8 s vs 11.0 s, 0 issues vs 11 005 `A2L_UNRECOGNIZED_BLOCK` WARNINGs on the base (the IF_DATA exemption), 0 MEMORY_SEGMENTs on both, regions `unknown` on both — the Issues view renders 0 rows instead of 11 005 (ad-hoc probe on both trees, output not kept as a transcript);
- the same group: base 490 passed (int-12); branch failed once in a valid run (int-08, load 10–17) and passed in the third run (int-15, 490 passed, load about 7).

→ E5 item: run tc_b100_52 in the full battery; if it fails there, it is the shared-host timing class (the test's `settle_workers` does not ride out `WaitForScreenTimeout`, unlike the acceptance file's own `_press` / `wait_until`).

## Orchestrator rulings (E4)

- **OR-5 — R-A2L-121 indent.** The graph's two spaces (D-6) are binding; the requirement does not state the indent, so `test_r_a2l_121_index_note_once_above_header` keeps the stripped-line compare. The product emits `  x: point index (axis points unavailable)` (two spaces, `a2l.py:render_curve_description`). Kept, noted.
- **OR-6 — AT-I11-5's first CURVE.** Verified on GREEN: the first CURVE row of the demo, reached by PgDn, has no axis values; its description holds the note line once and the row suffix 0 times (AT-I11-5 passes in int-01 and int-07). Assumption true, case unchanged.
- **OR-7 — 262 / 285.** The GREEN run gives the E1 model numbers exactly: clean demo `total=262 | errors=0 | warnings=262 | info=0 | filter=all | page 1/7 rows 1-40/262`; faulty demo `total=285 | errors=8 | warnings=277 | info=0 | filter=all | page 1/8 rows 1-40/285`, page 1 `✗ ERRORS  (8)` then `⚠ WARNINGS  (277)`; Warnings filter `page 1/7 rows 1-40/277` (AT-I11-1/2/3 pass). No model or product deviation.
- **OR-8 — user routes.** AT-I11-3: a real pointer click (`pilot.click("#issues_filter_warning")`) reaches the button and works → used, case `full`. AT-I11-4: the command palette route (`ctrl+k`, type `join`, Enter runs the first match "Split / Join / Export") works → used, case `full`; the source tab is then cycled by keys (SR-1). AT-I11-5 still places the cursor with `DataTable.move_cursor` (not in OR-8's scope) → case `partial`.

## Seam rulings

- **SR-1 — Split / Join source tab route.** E1's AT-I11-4 input "`t` twice (ranges → manual → a2l)" contradicts the shipped window: on the manual tab `t` is text for the localities box. The smallest fix is in the test (the code is outside the slice and behaves as its own design states): `t`, Tab, `t`. The requirement under test (R-SEG-SRC.6, `a2l(4)` and the four rows) is unchanged.
- **SR-2 — composed-row wait.** The re-pinned triage tests wait for composed rows, not mounted rows (test sync; the assertions are byte-identical).
- **OR-3 scope.** OR-3 names TC-027 and TC-B94-18; `test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main` and `::test_tc031_engine_modules_have_no_name_only_diff_vs_main` are the same freeze (the second guard `CLAUDE.md` names) and fail for the same reason. Recorded under OR-3, not fixed.

## Clean-up

The remote worktrees `<HOME>/work/s19_i11` and `<HOME>/work/s19_i11_base` (pristine base for the comparison runs), the helper scripts and the pytest temp dirs were removed after the last run; `<HOME>/work/s19_app` and the other agents' worktrees were not touched.

## Snapshot baselines

`pytest-textual-snapshot` is not installed on the LAN host (`pip list`: no such package; `test_tui_snapshot.py` skips). The six `a2l-*` baselines were not re-recorded: **snapshot re-record owed at E5 / batch end with the CI-matching env**. Never on Windows.

## Items for E5

1. TC-027, TC-B94-18 freeze arm, TC-031 ×2 must be GREEN on the merged tree before the push (OR-3).
2. Re-record the six `a2l-*` snapshot baselines in the CI-matching env and review the diff (Region `flash`, CURVE index line, Issues severity).
3. tc_b100_52[case_06] under the full battery (environment class above).
4. R-A2L-036.7/1 ("Split / Join lists no row" half), R-SEG-SRC.6/2 (white-box name read) and AT-I11-5 (`move_cursor`) stay `partial`.
5. The tester's G1 corpus walker (R-VAL-032.2/3) is independent of the engine; E5 reviews it as an oracle.
6. Mutation check of the new tests was not run at E4.
