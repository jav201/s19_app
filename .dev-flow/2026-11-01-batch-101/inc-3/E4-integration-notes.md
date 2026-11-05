# Inc 3 -- E4 integration notes

Batch 2026-11-01-batch-101, increment 3. Integrator: Opus. Tree: branch `b101-inc3` on main `9f9f6af`; E4 work committed as found in `b2b3c05` ("implementation and independent tests (Sonnet)"); the integration edits below are in the next commit. Host: Windows, Python 3.11.15, textual 8.2.8, no xdist (every run is serial in one process). Evidence states: `executed` for the runs below; nothing here is `approved`.

## Verdict

**GREEN** on Windows, with one recorded intermittent outside Inc 3's rows: the serial lane failed once (int-03) on the pre-existing `sec6_5 load` bound inside the verifier's scene, and passed on the second run (int-06); the verifier passed 3/3 alone (int-05). Every Inc 3 row passed in every run. No product code was changed at integration; the implementer's code matches the design (`project_gather_service.py` composition limb; the two sync functions lose their `mkdir`). Integration changed test code only (stamp placement, an id lookup, requirement ids in docstrings, one marker and its census registration) and records. Linux (LAN host) and CI lanes are not run here (E5).

## Runs (transcripts in `evidence/inc-3/`, redacted)

| Transcript | Selection | Result |
|---|---|---|
| `int-01-verifier-diag.txt` | R-TST-111/112 verifier, 3 node runs, `abs_tol=0.001`, with a temporary uncommitted print of arm minus observer | 3/3 runs: 3 passed each; differences 29.8-52.4 us (panel), -2.7 to -5.3 us (append) |
| `int-02-touched-lane1.txt` | the 4 touched files, `-m "not serial_timing"` | 248 passed, 1 xfailed (pre-existing), 23 deselected, 0 skipped |
| `int-03-serial-lane.txt` | serial lane alone, `-m serial_timing`, over every file of the GREEN set plus `test_b97_flow_execution.py` | 52 passed, **1 failed**: `test_r_tst_111_112_...[scene]` stopped at the scene's own `sec6_5 load` bound (1.001 s / 1.000 s), before its equality asserts; failure 4 below. TC-B97-64 burst passed in the lane; `save-project` 0.694 s (30.6 %) |
| `int-04a-guards.txt` | `test_suite_hygiene.py`, `test_id_registry.py`, `test_engine_unchanged.py`, `test_tui_directionb.py` (law guards incl. `tc031`), not serial | 261 passed, 1 deselected |
| `int-04b-importers.txt` | project_gather_service importers part 1 (`test_b100_document`, `_load_question`, `_project_homes`, `_reuse`), not serial | 328 passed, 23 deselected |
| `int-04c-importers.txt` | part 2 (`test_b100_save_dialog`, `_save_guards`, `_save_image`), not serial | 315 passed, 5 deselected |
| `int-04d-importers.txt` | part 3 (`test_b97_chips_help`, `test_b99_staging`, `test_copy_into_workarea_content_dedup`, `test_open_folder_chips`), not serial | 125 passed |
| `int-05-verifier-3of3.txt` | R-TST-111/112 verifier on the final tree, 3 node runs | 3/3 runs, 3 passed each (`sec6_5 load` 0.861, 0.710, 0.859 s) |
| `int-06-serial-lane-rerun.txt` | serial lane alone, second run, same selection as int-03 | 53 passed; `sec6_5 load` 0.950 s (folder-ceiling arm) and 0.917 s (verifier scene); `save-project` 0.561 s (43.9 %) |
| `int-00-first-attempts.txt` | the first lane-1 runs (int-02 before the docstring edits: 248 passed, 1 xfailed; one combined guard+importer run that hit the 2400 s cap with 3 failures, cause below) | superseded |

`tests/test_id_registry.py` passed with no count change (12 passed in int-04a): no registry count needed updating.

## Failures found and their causes

1. **Engine-frozen guards RED (3 nodes: `test_tc027_engine_modules_unchanged_vs_main`, `test_tc031_engine_modules_have_no_diff_vs_main`, `..._no_name_only_diff_vs_main`).** Cause: integration's own step 1. The first E4 commit force-added `s19_app/` and `tests/`, which pulled 168 ignored `__pycache__/*.pyc` files into it, 8 of them under `s19_app/validation/`. Fix: the unpushed commit was redone without any `.pyc` (`b2b3c05`, same message, 12 files); the guards pass (int-04a). Not a product or test defect.
2. **R-TST-002 marker guard RED after OR-5's marker.** `serial_timing on a test that is not a timing arm: tests/test_b97_flow_execution.py::test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one`. The census sees only ordering asserts over clock intervals; a press burst against a dwell has none. See seam ruling S-2.
3. **Trace check TEST gaps (3) and SLICE gap (1)** (`trace_check.py --req inc-3/01-requirements.md --base 9f9f6af --src s19_app/tui/app.py s19_app/tui/services/project_gather_service.py`): R-PROJ-001.13, R-PROJ-ROLLBACK.2 and R-TST-112 were named by no test file (the node names fold `9_2` and `111_112` into one token); `project_gather_service.py` was named by no requirement file. Fix: S-3. After it: 1 gap, EVID (`04-validation.md`, owed at E5).

4. **int-03: `test_r_tst_111_112_arm_values_equal_the_product_stamps[scene]` failed at `sec6_5 load` 1.001 s / 1.000 s.** The scene the verifier replays carries the folder-ceiling arm's own load bound (`_assert_sec6_5_bounded`), which is not an Inc 3 row and which Inc 3's code does not touch (the project load path does not run the gather or the sync). The same bound already failed on Windows before Inc 3 (1.103 s, `evidence/inc-2/int-win-arms-a.txt`); this integration measured it at 0.686-1.001 s across 7 readings (int-01, int-03, int-05, int-06), and the tester saw 0.971 s. Not fixed here (no bound is raised; OR-4 routes it to E5). Consequence for E5: the verifier's `[scene]` parameter inherits this flake, so a red `[scene]` must be read for which assert stopped it.

No test asserted something the design does not say, and no product code deviated from the design.

## Orchestrator rulings applied

- **OR-1 (verifier tolerance).** Source of the 0.4-0.6 ms found and removed; **1 ms kept** (E3 A-1 unchanged, no amendment). The two paint callbacks run in one `Signal.publish`, observer first. Each called `_summary_laid_out`, a `screen.query("#result_summary")` that walks the whole panel (about 1 000 problem rows, about 0.5 ms), and took its stamp after it; so one full walk sat between the observer's stamp and the arm's. Fix (test only): `_summary_laid_out` uses `screen.query_one_optional("#result_summary")` (an id lookup that stops at the first match and returns `None` when absent, so F3's "never raise before mount" still holds), and every paired stamp is taken first in its callback or wrapper (N-3): the arm's and the observer's layout callbacks, the scene's `_capture` and the observer's `_status`. Measured after the fix: 29.8-52.4 us panel, 2.7-5.3 us append, 3/3 runs (int-01), about 20x under 1 ms. M-6 + M-7 applied to the final test file (panel clock and append clock stopped when the wait notices) still turn it RED: all-bad 0.7760 vs 0.2388 s, cap 0.8248 vs 0.3005 s, scene's own 1 s bound trips first at 1.073 s (run in the integrator's scratch, not kept as a transcript; the tester's `red-01-tester-base.txt` holds the base-side mutant runs).
- **OR-2 (GATHER.12 counter seams).** Confirmed in code: the product's project-folder check is `in_project.is_file()` on a `Path` (`project_gather_service.py`, composition limb, `in_project = Path(os.path.normpath(resolved_project / name))`). The spy on `Path.is_file` counts it; the spy was not extended. The library check (`common_candidate.is_file()`) is outside the project prefix and not counted, as the case says.
- **OR-3 (`#result_body .result-problem`).** Accepted: the graph's intent is the panel's problem-row count at the stamp equal to the arm's final `rows`, and both sides use the same selector. Recorded in the graph node `_watch_panel_paint` and `E1-slice.md` row 5.
- **OR-4 (`sec6_5 load` margin).** Outside Inc 3's rows. Seen again here: `LOW 10.7 % 0.893 s / 1.000 s sec6_5 load` in run 2 of int-01, and over the bound once (1.001 s, int-03; failure 4). For E5's LAN run, beside D-4.
- **OR-5 (TC-B97-64 burst arm into the serial lane).** `@pytest.mark.serial_timing` added to `tests/test_b97_flow_execution.py::test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one`, nothing else in that test. Recorded as an Inc 3 addition against Inc 2's R-TST-002 (every timing arm runs in the serial lane). The hygiene suite needed S-2 to stay GREEN; R-TST-049 (wrap drift) passes: the function differs from the base only by the marker. The census press-burst form stays in the backlog.

## Seam rulings (integrator)

- **S-1 [OR-1, F3].** `_summary_laid_out` moves from `query` plus a length check to `query_one_optional`. F3 asked for "`query` with a length check, not `query_one`"; its reason (the signal can publish before the summary is mounted, and `query_one` raises) is kept by `query_one_optional`, which returns `None`. Records updated: graph node `_watch_panel_paint`, `E1-slice.md` row 5.
- **S-2 [OR-5 vs R-TST-002].** The ruling said "marker only", and the marker guard refuses a mark the census cannot see. Smallest fix that keeps both: the node is listed by hand in `tests/support/suite_census.py::SAMPLED_TIMING_ARMS` (the guard's set of arms the census cannot see; its comment now names the press-burst kind and the backlog) and the hygiene pin `_SAMPLED_PIN` names it too. Alternative rejected: drop the marker (leaves the CI flake of run 42037470050 in the parallel lane).
- **S-3 [trace rule].** Requirement ids written into test docstrings so the trace check finds them: `test_r_tst_111_112_...` (R-TST-111 and R-TST-112), `test_r_proj_rollback_9_2_...` (R-PROJ-ROLLBACK.9 and R-PROJ-ROLLBACK.2), and one sentence in the existing `test_tc_b100_20_...` docstring (the `save-project` parameter verifies R-PROJ-001.13). That node was "unchanged" in `E1-slice.md` row 12; the change is docstring only, no assert, marker or wrap moves (R-TST-049 passes). `01-requirements.md` gains one line under R1-P1 naming `s19_app/tui/services/project_gather_service.py`.
- **S-4 [N-3 (c)].** The observer's `installed` is now the last install return before the paint (was the first), as N-3 asks.

## Record edits (E3 round 2 addenda)

- N-1: `E1-rulings.md` E1-D8, the false sentence replaced with the reviewer's text.
- N-2: graph I-1 lists the fourth input (a name `resolve()` rejects with `ValueError`, such as an embedded NUL). No test owed.
- N-3: applied in the test file (OR-1, S-4) and written into the graph node.
- Cosmetic: the blank line splitting the graph's interface table removed. `codewire_lint`: `nodes=15 entities=4 edges=0 findings=0 not read=0`.

## Counts

- Source files changed by the increment: 2 (`project_gather_service.py`, `app.py`).
- Test files changed: 4 touched by the tester, plus at integration `tests/test_b97_flow_execution.py` (marker), `tests/support/suite_census.py` and `tests/test_suite_hygiene.py` (S-2).
- Cases: 26; Result column filled from these runs (Windows only): 25 `verified`, 1 `not_run` (R-PROJ-001.13/1: 2 of 5 runs here, both inside the 0.8 s target).

## Left for E5

- LAN Linux runs: R-PROJ-GATHER.13/2 is the deterministic catch there (junction cases skip); R-PROJ-GATHER.12/3 discriminates on POSIX only.
- R-PROJ-001.13's 0.8 s target (QC-TM >= 20 %, 5/5 Windows and 5/5 LAN), serial lane alone.
- R-TST-111/112 verifier 3/3 on the LAN host and in the CI serial lane.
- Mutants M-1 to M-4, M-9 to M-11 (source copies).
- OR-4 `sec6_5 load` margin (it went over the bound once here, failure 4) and D-4 `sec6_5 appended` margin, base vs head on the LAN host.
- The census press-burst form (backlog); TC-B97-64 burst now runs in the serial lane, CI to confirm.
- `04-validation.md` (trace EVID gap).
