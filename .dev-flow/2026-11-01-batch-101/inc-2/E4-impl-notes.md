# Inc 2 — E4 implementation notes (batch-101, test hygiene)

Swarm of 2 parallel E4 implementers with disjoint file ownership, per the approved
design (`01-requirements.md`, `E1-slice.md`, `codewire/graph-inc2.md`,
`E3-rulings.md` round 1 + round 2 + E4 addenda). Nothing committed.

## Files changed

### Group A (infrastructure, census, CI, docs)
- `pyproject.toml` — `serial_timing` marker line (R-TST-001 text verbatim).
- `.github/workflows/tui-ci.yml` — job `tui-ci` `timeout-minutes: 240`; both
  checkouts `fetch-depth: 0` + `persist-credentials: false` (E3S-3, incl. the
  `snapshot` job); install step `id: install` + `python -m pip install
  "pytest-xdist==3.8.0"`; PR lane 1 `pytest -v -rs -n auto --dist loadfile
  -m "not slow and not serial_timing"` (120 min) + PR lane 2 `pytest -q -rs
  -m "serial_timing and not slow"` (30 min); push lane 1 `pytest -v -rs -n auto
  --dist loadfile -m "not serial_timing"` (180 min) + push lane 2 `pytest -q -rs
  -m serial_timing` (45 min); lane-2 conditions
  `github.event_name == '<event>' && !cancelled() && steps.install.outcome == 'success'`
  (E3A-13/E3S-5).
- `docs/engineering-rules.md` — new final section "Test timing, waits and
  oracles (batch-101 Inc 2)": the gate commands (`pytest -n 8 -m "not
  serial_timing"` then `pytest -m serial_timing` on the LAN Linux host) and the
  five rule sentences verbatim from the graph (R-TST-030/047/048/052/060).
- `tests/support/timing.py` — `WAIT_TIMEOUT_S = 60.0`, `POLL_S = 0.05`,
  `MARGIN_FINDING_PCT = 20.0`; `wait_until` (I-1, `failure: str | Callable[[], str]`,
  callable invoked only on raise); `report_margin` (I-2, returns the bound
  object unchanged, `ValueError` on `|` or <0x20 chars in the label per E3S-7);
  `qc_tm_drain`; `qc_tm_summary_lines` (rsplit("|", 3), ascending, `LOW ` on
  margin < 20.0 decided on the 1-decimal value per E3A-10); the two pytest
  hooks defined here per E3A-8 (`pytest_runtest_makereport` hookwrapper drains
  `item.user_properties` before its yield on every phase per E3A-11;
  `pytest_terminal_summary` reads call-phase reports only, skips error entries,
  silent when empty). `timing_bound`/`CI_TIMING_FACTOR` untouched.
- `tests/support/suite_census.py` — NEW. Pure-AST census (never imports scanned
  code); no AT-/TC- tokens. `SAMPLED_TIMING_ARMS` (I-4), pinned
  `NEWEST_LINE_BASELINE` (I-6), `timing_arms`, `unreported_upper_bounds`,
  `newest_line_waits`, `shared_wait_bodies`.
- `tests/conftest.py` — `pytest_plugins = ["pytester"]` (E3A-8) and the import
  of the two hooks from `tests.support.timing`; `TOOL_VERSION_TOKEN =
  b"<TOOL-VERSION>"`; `canonical_report_bytes` gains one final step replacing
  the token with `s19_app.version.__version__` read at call time (R-TST-081/082;
  a wrong version in a produced report is untouched).

### Group B (shared waits, timing arms, goldens)
- `tests/b97_probes.py` — `settled`: body → `wait_until(..., pause_first=True)`,
  text W3 `f"did not settle: {description}"`; `attempts=60` kept (no longer
  bounds; docstring says so).
- `tests/support/b100_load_dialog.py` — `wait_for`: body → `wait_until`,
  text W2 `f"timed out waiting for {description}"` (predicate checked first);
  E3A-17 docstring; `attempts=400` kept; `wait_for_dialog`/`wait_for_dialog_closed`
  unchanged.
- `tests/support/b100_projects.py` — `wait_for` (W1, same shape as W2);
  `read_load_result_panel` (W4 "the Load-result panel was not painted");
  `dismiss_load_result_panel` (W5 "the Load-result panel did not open", W6 "the
  Load-result panel did not close on esc"); `save_case01_project` (W7 f"the
  load of {item} did not land", W8 f"Save project {name} did not land");
  `append_variant` (W9 as a `lambda:` so the statuses are read at raise time,
  F-2); all keep their positional signatures with keyword-only `timeout=60.0`
  added (I-7). `load_project` (R-TST-025 + E3A-12): wraps
  `app._install_prepared_project` on the instance with a recorder stamping
  `perf_counter()` into a one-item list; saves and restores the previous
  attribute in `finally` (never `del`); `elapsed = stamp - start`; empty stamp
  list → `AssertionError(f"the project install callback of {name} was not
  reached")`; the wait predicate and the 6 pauses unchanged.
- 12 timing-arm files — 32 `@pytest.mark.serial_timing` decorators (placed
  directly above a `parametrize` where one exists, below `@pytest.mark.slow`
  where that exists) and 37 `report_margin` wraps keeping the operator, the
  assert message and `timing_bound(...)` inside the bound argument (CI scaling
  kept). `test_b100_busy.py::test_at_b100_17_...` decorated only (sampled arm).
  Not-bounds left untouched (project-check row asserts, save-dialog count
  chains, lower half of the q-delay chain).
- 7 golden files — `1.0.0rc1` → `<TOOL-VERSION>` only: batch35 at054b .html
  (`<li>` form) and .md, batch35 at055b .md, batch64 addendum-below-bound.md,
  batch74 producer-bound, batch76 document-bound, batch99 at288 .bin.
- `tests/test_report_service.py` — `test_at288_report_hex_sections_identical_
  after_move`: compare through `canonical_report_bytes(pinned)`; capture branch
  writes `emitted` with the version replaced by the token.
- `tests/test_report_addendum_bound.py` — exactly one line: `_golden_documents`
  decodes `canonical_report_bytes(_GOLDEN.read_bytes())`.

## Census numbers (implemented census, base tree b3bf42e via git archive)

- `timing_arms`: **31 arms** (the exact E1-slice §3 list).
- `unreported_upper_bounds`: **37 sites** on the base tree; **0** on the head
  tree (all bounds wrapped). Negative controls hold: project-check row asserts,
  save-dialog count chains, the `:2335` lower half are not bounds; the three
  list-appended bounds (`:841`, `:978`, `:1350`) are.
- `newest_line_waits` on the base tree — **86 sites in 15 files**, identical on
  the head tree; pinned verbatim as `NEWEST_LINE_BASELINE`:

| file | sites |
|---|---:|
| tests/test_b100_active_variant.py | 7 |
| tests/test_b100_focus.py | 12 |
| tests/test_b100_project_check.py | 1 |
| tests/test_b100_reuse.py | 1 |
| tests/test_b100_save_dialog.py | 1 |
| tests/test_b100_save_guards.py | 3 |
| tests/test_b100_save_image.py | 13 |
| tests/test_b100_session_reset.py | 3 |
| tests/test_b100_workers.py | 2 |
| tests/test_b99_a2l_encode.py | 1 |
| tests/test_b99_editor_image.py | 13 |
| tests/test_b99_export.py | 10 |
| tests/test_b99_load_project.py | 4 |
| tests/test_b99_s0.py | 5 |
| tests/test_b99_staging.py | 10 |

- `shared_wait_bodies` (head tree): 0 range loops in all 7 functions; 9
  `wait_until` calls (dismiss 2, save_case01 2, others 1); W7/W8/W9 failure
  texts as designed (W9 inside the lambda).
- Timing helper checks vs the graph examples: raise between 0.5–1.5 s at
  timeout 0.5; ≤21 checks in 1 s; `pause_first` ≥ 1 pause; quick-true < 0.4 s;
  callable failure text shows state at the timeout; drain format
  `p|0.850|1.000|15.0`; summary rows match the `LOW 15.0% / 25.0 / 40.0`
  example; canonicalizer examples of R-TST-081/082 pass.

## Deviations

1. `tests/goldens/batch64/addendum-below-bound.md` holds **6** version lines,
   not 7 (lines 14, 100, 337, 2267, 2348, 3429); the E1 note's "7" counted one
   line too many. All 6 replaced.
2. Unpinned `report_margin` labels were chosen in the pinned examples' style
   (`"<AT/TC id> <detail>"`, parametrized value interpolated where one exists):
   AT120, TC149, TC138, AT111, AT101, TC-B100-28, f"TC-B100-30 classifier
   {case}", f"TC-B100-24 {key}", "TC-B100-24 assignments", "TC-B100-61 all-bad
   load"/"all-bad painted", "TC-B100-61 checks a/b/d/e" (the four sec6_5
   each-name bounds), "TC-B100-61 R2-2 read", "TC-B100-61 sec7 serialize",
   "TC-B100-61 cap load"/"cap painted", "TC-B100-31 junction cycle",
   f"TC-B100-31 {arm}", "TC-B100-65 case06 paint"/"keystroke paint"/"4MiB
   paint", "TC-B100-05 merge", "TC-006 large image", "MAC view cache",
   "end-to-end load pipeline", f"stress load {load_order}".
3. `pytest_runtest_makereport` drains on every phase (E3A-11's "drains every
   phase" option) rather than call-phase only; call-phase-only reading in
   `pytest_terminal_summary` keeps rows from doubling.
4. On the current head tree `timing_arms` reports 32 (31 + the guard file's own
   planted marked arm); the guard's set arithmetic is unaffected.
5. The census resolves scanned paths relative to its CWD; base-tree numbers were
   measured by archiving `b3bf42e` to a Windows-visible temp dir and running the
   implemented census there (a POSIX `/tmp` path is invisible to the native
   interpreter and silently yields an empty census — measurement note, not a
   code defect).

## Verification runs

Environment: `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1
PYTHONIOENCODING=utf-8 PYTHONPATH=. LOCALAPPDATA=<temp>/s19i2/la`,
interpreter from the project venv, `--basetemp <temp>/s19i2/bt`, each run under
`timeout 1800`. Scope: the 12 touched arm files + the 7 golden test files
(19 files). Transcripts: `../evidence/inc-2/impl-1-full.txt`,
`impl-2-serial-timing.txt`, `impl-3-not-serial-collect.txt` (home paths
redacted as `<HOME>`).

(pending — see below)
