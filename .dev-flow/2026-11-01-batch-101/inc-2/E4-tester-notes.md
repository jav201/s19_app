# Inc 2 — E4 independent tester notes (test hygiene guard host)

Owner file: `tests/test_suite_hygiene.py` (new; the only file the tester
writes). Design sources only: `01-requirements.md` (48 rows), `02-test-cases.md`
(81 cases), `codewire/graph-inc2.md` (I-1 .. I-9), `E3-rulings.md` (round 1/2
rulings + E4 addenda). No in-progress implementation file was read to decide
what to test; base-tree facts were read from `git show 84d4507:...`.

Rule for full/partial (per the review skill): a test is **full** only when the
product itself produces what the test asserts. Guard-text assembly from census
results lives in the guard host (this file is the guard host per O-1/E3A-9),
so a planted-case test is full when the product census decides detection and
the asserted text is the design-pinned string; the static workflow/conventions
checks are partial where the case itself declares the full verification to be
a CI run log or gate transcript.

## Test → case mapping (54 nodes over the 81 cases)

| Test node | Case(s) | Mark | Why |
|---|---|---|---|
| `test_r_tst_001_serial_timing_marker_is_registered` | 001/1 | full | `pytest --markers` output of the tree under test must hold the exact registration line. |
| `test_r_tst_002_every_timing_arm_carries_serial_timing` | 002/1, 005/5 | 002 full; 005/5 partial | Real-tree guard: census arms ∪ `SAMPLED_TIMING_ARMS` (pinned to I-4) minus the marked set (own decorators, `pytestmark` refused per E3A-16) must be empty; the 31 slice arms must be found. 005/5 is partial: the superset is checked on the one tree the suite runs on; the case also asks for the `b3bf42e` tree, which a suite test cannot reach (E5 can re-run it there). |
| `test_r_tst_002_2_parallel_lane_collection_prints_no_qc_tm_text` | E3S-1 addendum (new guard case, no case row) | full | A `--collect-only -q -m "not serial_timing"` subprocess run on the tree prints no `QC-TM` text and no unknown-marker warning. |
| `test_r_tst_003_an_unmarked_timing_arm_is_named` | 003/1 | full | Planted unmarked arm; guard text `timing arm without serial_timing: <file>::<test>` from the census key. |
| `test_r_tst_004_a_marked_non_arm_is_named` | 004/1 | full | Planted marked non-arm; reverse guard text. |
| `test_r_tst_005_detector_finds_each_timing_arm_form[form1..form7]` | 005/1, /2, /3, /4, /6, /7, /8 | full | The seven planted forms of the graph examples (interval in test; same-module helper; nested return; `timing_bound` operand; hook-recorded stamp list; `report_margin` wrap with interval from a planted support module; `import time as` alias). |
| `test_r_tst_006_detector_ignores_intervals_no_assert_reads` | 006/1, /2, /3 | full | Real-tree negatives: 0 arms in `tests/test_sync_evidence.py`; the print-only ceiling test and the `_reopen` unpack test absent; the hostile arm present. |
| `test_r_tst_007_conventions_hold_each_test_rule[R-TST-007/030/047/048/052/060]` | 007/1, 030/1, 047/1, 048/1, 052/1, 060/1 | full | Verbatim sentences; 007 also checks both lane commands in order inside the new section and the LAN host naming. |
| `test_r_tst_010_pull_request_runs_two_lanes` | 010/1 | partial (static) | Text-parsed steps whose `if:` holds `pull_request` run exactly the two pinned commands in order. Full = first PR run log (owed). Also carries the E3S-6 ratchet: no `run:` line holds `${{ github.event.`/`${{ github.head_ref`, and `on:` lists no `pull_request_target`/`workflow_run`. |
| `test_r_tst_011_push_runs_two_lanes` | 011/1 | partial (static) | Same for `push`. |
| `test_r_tst_012_serial_lane_runs_after_a_red_lane` | 012/1 | partial (static) | Both lane-2 `if:` conditions hold `!cancelled()` beside the event test, in the E3A-13/E3S-5 form `github.event_name == '<event>' && !cancelled() && steps.install.outcome == 'success'`. First red run showing the serial step as run = CI evidence (owed). |
| `test_r_tst_013_014_ci_checks_out_full_history` | 013/1 | full (static fact) | `fetch-depth: 0` on the single `tui-ci` checkout; `snapshot` job still present; `persist-credentials: false` on both checkouts (E3S-3). 014/1's full verification is the PR run log (owed). |
| `test_r_tst_015_016_017_ci_time_limits` | 015/1, 016/1, 017/1 | 015/016 full (static facts), 017 partial | Lane-1 `timeout-minutes` 180 (push) / 120 (PR); lane-2 45 / 30; job 240; install step `id: install`; the N-3 budget arithmetic 3+180+45 ≤ 240 and 3+120+30 ≤ 240. A real lane-1 stop showing lane 2 as run = CI evidence (owed). |
| `test_r_tst_018_ci_installs_pinned_xdist` | 018/1 | partial (static) | The install step holds `python -m pip install "pytest-xdist==3.8.0"`. 018/2's worker header = PR run log (owed). |
| `test_r_tst_020_shared_wait_is_bounded_by_the_wall_clock` | 020/1 | full | Fake pilot, never-true predicate, `timeout=0.5`: `AssertionError("never")` after ≥ 0.5 s and < 1.5 s (bound through `report_margin`, since this guard test is itself a timing arm and is marked `serial_timing`); plus the graph's fast-return example (< 0.4 s with a 60 s bound). |
| `test_r_tst_020_021_shared_helpers_delegate_to_the_one_wait` | 020/2, 021/2 | full | `shared_wait_bodies` over the tree: 0 `range(...)` pause loops in each of the 7 functions; 9 `wait_until` failure arguments in total (2 in `dismiss_load_result_panel`, 2 in `save_case01_project`). |
| `test_r_tst_021_shared_wait_yields_between_checks` | 021/1 | full | Counting predicate, `timeout=1.0`: ≤ 21 checks. |
| `test_r_tst_022_settled_pauses_before_its_first_check` | 022/1 | full | Predicate true at once records ≥ 1 pause before its first evaluation. Co-condition (documented, for base-RED): the keyword-only `timeout` must exist on `settled` — R-TST-020's bounded wait is what this row's pause-first helper serves; without it the pause-first order is the old unbounded count loop. |
| `test_r_tst_023_shared_wait_signatures_are_kept` | 023/1 | full | `inspect.signature` of the 7 functions against the pinned positional names/order/defaults plus the keyword-only `timeout` (I-7). |
| `test_r_tst_024_shared_wait_failure_texts[W1..W6]` | 024/1 .. /6 | full | Real helpers, fake pilot/app, exact texts; W5 asserts no `escape` pressed, W6 asserts exactly one. |
| `test_r_tst_024_shared_wait_failure_texts[W7..W9]` | 024/7 .. /9 | partial (static) | Failure arguments of `save_case01_project` / `append_variant` via `shared_wait_bodies` (f-string sources carry `{item}` / `{name}` / `{source.name}` / `{statuses}`). The waits run inside a whole app, so the case itself marks these static. |
| `test_r_tst_025_load_project_clock_stops_at_the_install_callback` | 025/1 | full | case_01 project "P", 3 fresh apps, recorder on `app._install_prepared_project`; returned interval equals stamp − start within 0.001 s; also asserts the wrapper is restored (E3A-12). |
| `test_r_tst_031_032_post_press_and_dwell_arms_keep_their_forms` | 031/1, 031/2, 032/1 | partial (static) | Static forms: the quit-confirm arm holds the save worker at `Hold(..., "place_into_workarea")` via `held_save_scene`; the parse arm spies `step_busy`; the dwell arm patches `_fx_clock`. Co-condition (documented, for base-RED): the census must not flag the three nodes as arms — they keep no wall-clock bound and stay in the parallel lane per the design. The 3/3 parallel-lane runs on the LAN host are owed to the gate. |
| `test_r_tst_040_report_margin_returns_the_bound` | 040/2 | full | `report_margin("x", 0.5, b) is b`; with the E3A-11/E3S-1 fresh-pending fixture the drain is also checked (`qc_tm_drain` → 1 record `("qc_tm", "x|0.500|1.000|50.0")`, pending empty at teardown). |
| `test_r_tst_040_041_every_upper_timing_bound_is_reported` | 040/1, 040/3, 040/4, 041/1, 041/2 | full | Real tree: 0 unreported sites and none of the five not-a-bound sites (E3A-3); planted marked arm with 4 raw bounds (float, int, `timing_bound(1.0) * 2`, module constant) → 4 sites with exact file:line and the guard text `timing bound without report_margin: <file>:<line>`. 040/1's "37 reported bounds at the base set" and 040/4's base-tree list (`:841/:978/:1350`) are measurable only on `b3bf42e`; a suite test sees the head tree, where the expected set is empty — E5 can re-run the census on the base tree for the 37-count. |
| `test_r_tst_042_margin_report_is_a_test_property` | 042/1 | full | Inner `runpytest_subprocess` run (E3S-1): planted arm reports `p|0.850|1.000|15.0`; a planted `pytest_runtest_logreport` probe shows the property on the call report **and** the teardown report; the junit XML carries exactly one `qc_tm` property. |
| `test_r_tst_043_045_qc_tm_section_rows_and_count` | 043/1, 045/1 | full | Three planted reports (40.0/15.0/25.0): heading `QC-TM timing margins`, rows ascending with the exact format, `LOW ` prefix on 15.0, count line `QC-TM: 3 bounds, 1 under 20 % margin`. |
| `test_r_tst_043_2_teardown_error_report_gives_one_row` | 043/2 | full | Planted arm whose fixture teardown raises: the section shows exactly one row for the node and `QC-TM: 1 bounds, 1 under 20 % margin` (E3A-1: call-phase reports only). |
| `test_r_tst_044_low_margin_prefix` | 044/1, 044/2 | full | Margin 15.0 row begins `LOW `; margin 20.0 (0.8/1.0, the E3A-10 1-decimal case) carries no prefix. |
| `test_r_tst_046_over_bound_arm_still_reports` | 046/1 | full | Planted failing arm (`assert 1.2 < report_margin("o", 1.2, 1.0)`) fails and the section still holds `LOW -20.0%  1.200 s / 1.000 s  o  <nodeid>`. |
| `test_r_tst_050_status_log_keeps_every_painted_line` | 050/1, 051/1 | full | `StatusLog.since(mark)` returns the 6 painted lines in order while `app.log_lines` holds 4 (unchanged behaviour, asserted because the case names it); carries the real-tree newest-line ratchet pass state (051/1): no file above its baseline, guard text pinned. |
| `test_r_tst_051_newest_line_waits_do_not_grow` | 051/2, /3, /4 | full | Planted newest-line wait in a new file (`1 > baseline 0`), in a copy of a baselined file (`n+1 > baseline n`), and through the support-module reader `last_status` (E3A-6), each with the exact guard text. |
| `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` | E3S-2 addendum (no case row; attached to the batch evidence/CI-record group) | partial | Greps the batch `evidence/` tree for user-profile paths, non-runner posix home paths and LAN addresses (`/home/runner/` allowed). Partial because the exact pattern set of the security report is not in the tester brief; generic patterns are used. Fails if the increment's evidence folder is absent from the checkout. |
| `test_r_tst_080_report_goldens_hold_no_tool_version` | 080/1 | full | Bytes scan of every file under `tests/goldens/`: 0 matches of `Tool version: [0-9]`; each of the 7 goldens holds `Tool version: <TOOL-VERSION>`. |
| `test_r_tst_081_golden_takes_the_package_version` | 081/2 | full | With `s19_app.version.__version__` patched to `9.9.9`, `canonical_report_bytes` replaces the token and leaves no `<TOOL-VERSION>`. (081/1 is the 7 golden nodes themselves, owned by G5.) |
| `test_r_tst_082_wrong_version_still_differs` | 082/1 | full | A produced `Tool version: 0.0.0` is untouched, the golden side canonicalizes to the patched package version, and the two differ. (082/2 is the E5 mutant run per producer.) |

## Owed (not pytest nodes)

- R-TST-008/1, 009/1 — the two-lane release gate on the LAN Linux host, twice; `evidence/inc-2/gate-*.txt` (D-15: no pytest node).
- R-TST-014/1 — the 6 history arms' `-rs` skip summary of Inc 2's own PR run.
- R-TST-018/2 — the PR run's lane-1 header (`xdist-3.8.0`, ≥ 2 workers).
- R-TST-023/2 — the `git diff b3bf42e -- tests/` call-site census (E5 transcript).
- R-TST-031/1, 031/2, 032/1 — the 3/3 parallel-lane runs of the three arms on the LAN host (static parts covered above).
- R-TST-070/1, 071/1, 072/1 — recorded in `evidence/ci/41372953464.txt` (E3 round 1; 071's condition did not occur).
- R-TST-090/1, 091/1 — lane/job times of Inc 2's PR run and the first post-merge push run.
- R-TST-081/1 — the 7 golden nodes themselves (G5 files); R-TST-082/2 — the E5 mutant transcripts.
- R-TST-005/5's base-tree half and R-TST-040/1's 37-count / 040/4's base list — census re-run on `b3bf42e` at E5 (a suite test can only see its own tree).
- E3A-7 registry: re-measure TC-607 (241 scanned) and run `tests/test_id_registry.py` + `tests/test_batch91_registry_hygiene.py` at integration.

## RED on base (main 84d4507)

Temporary detached worktree of `84d4507` under the session temp area, only
`tests/test_suite_hygiene.py` copied in, run there with the pinned env
(`PYTHONPATH=.`, `--basetemp` under the temp area, s19env interpreter,
timeout 1800; `s19_app.__file__` printed first). Result: **48 failed, 6
errors — every one of the 54 nodes red in 24.4 s.** Transcript (home paths
replaced by `<HOME>`): `../evidence/inc-2/red-01-tester-base.txt`. The
temporary worktree was removed afterwards.

Failure reasons, all behavioural:
- `ImportError: cannot import name 'suite_census'` — the census module is
  what R-TST-002/005/006/040/041/051 (and the 020/021/031-032/050/051
  helpers) create; behavioural for those rows.
- `ImportError: cannot import name 'wait_until'` / `report_margin` /
  `qc_tm_drain` — the helpers R-TST-020/021/040/042-046 create inside the
  existing `tests/support/timing.py`.
- `TypeError: ... unexpected keyword argument 'timeout'` — the shared waits
  of R-TST-020/022/024 accept no wall-clock bound on base.
- `AssertionError: returned interval 0.612764 s is not the install-return
  stamp minus the start (0.135097 s)` — R-TST-025's base behaviour (clock
  stops when the poll notices), the designed negative.
- Marker line, conventions sentences, workflow lanes/timeouts/install line,
  checkout `fetch-depth: 0`, golden version pins, unsubstituted
  `<TOOL-VERSION>` — each absent on base.
- 6 errors: the `pytester` fixture (base conftest has no
  `pytest_plugins = ["pytester"]`, E3A-8) for 042-046, and the fresh-pending
  fixture for 040/2 (`_QC_TM_PENDING` does not exist on base).
- `test_r_tst_070_2_...` fails because the increment's evidence folder is
  absent from the base checkout — the gate's contract is that the batch
  evidence folders exist and hold no secrets.

Tests whose own assertions are base-held behaviours and whose base-RED comes
from the imports/co-conditions named above: 020 (own import), 021, 022
(TypeError via the co-condition), 023, 024 W1-W6 (TypeError), 031/032
(census co-condition), 050 (ratchet co-condition). All other tests fail on
their own assertions.

## Could not express / deviations (all documented, none resolved by reading
the implementation)

1. `unreported_upper_bounds` signature: the graph pins
   `(tests_root, arms)`, the case text says `unreported_upper_bounds(tests/)`.
   The guard calls it with one argument and falls back to two (with the
   census arms) on `TypeError`. Same tolerance is not needed elsewhere.
2. `shared_wait_bodies` output shape (`dict[str, tuple]`) is not pinned past
   "range-loop count + failure argument per wait_until call": the guard
   reads the int and the list positionally from the tuple and matches
   functions by the key's tail after `::`.
3. Census key format (file path prefix) is normalized by the guard to
   repo-relative `tests/...` form before comparison with the pinned node ids
   and baselines; planted-file guard texts use the census key as returned.
4. R-TST-022 and R-TST-050 carry the small co-conditions described above so
   that every test is red on base; both co-conditions are design-backed
   (I-1/I-7 keyword-only `timeout`; the QC-OR ratchet of R-TST-051 on the
   same tree and guard host).
5. The inner-run conftest imports the two hooks from `tests.support.timing`
   per E3A-8, with a fallback to `tests.conftest` (the graph's node module
   field says `tests/conftest.py`); either approved location is accepted,
   neither silently.
6. R-TST-012/017 lane-2 conditions are asserted in the E3A-13/E3S-5 form
   (event test `&& !cancelled() && steps.install.outcome == 'success'`),
   which is stricter than the case text's "holds `!cancelled()` beside its
   event test".
7. E3S-2's exact security-report pattern is not available to the tester;
   generic patterns are used (noted partial).
8. E3A-12's empty-stamp `AssertionError` text has no case row and no way to
   trigger it through the public helper; only the wrapper-restore half is
   asserted (inside 025).

## `02-test-cases.md` tests-column updates

All rows keep the E1 node proposals, which the implementation matches.
Changed cells: R-TST-043/2 → `test_r_tst_043_2_teardown_error_report_gives_one_row`
(was the shared 043/045 node); R-TST-051/1 →
`test_r_tst_050_status_log_keeps_every_painted_line` (the real-tree ratchet
pass state is asserted there). Rows whose full verification is a gate/CI/E5
artifact keep their "no pytest node" wording. Nothing committed by the
tester.
