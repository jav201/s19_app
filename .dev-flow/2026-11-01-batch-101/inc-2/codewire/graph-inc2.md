# Code-Wire graph — Inc 2 (test hygiene, timing arms and CI), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`), corrected after E3 round 1 (`../E3-rulings.md`; changed lines carry the finding id in brackets). Graph only: no stub, mark or declaration in any tree. Base `b3bf42e`. Requirements `../01-requirements.md` (R-TST-001 … 071), slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (`<HOME>/Github/code-wire/docs/Notation-Grammar.md`), as in `2026-10-26-batch-100/inc-12b/codewire/`.

How to read it:
- One file holds the baseline and the prototype. Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **new**. Context nodes (unchanged) are here because a changed node calls them or wraps them.
- Example sources are the test-case ids of `02-test-cases.md` (`R-TST-020/1`); `B` = a probe of the base tree run at E1 (AST census from the session scratchpad, read-only on `tests/`). Every example states the Inc 2 target unless it says "holds on base".
- "Fake pilot" = a test double with `async pause(delay=None)` that returns at once and counts its calls. "Planted" = source written under `tmp_path` by the test.
- Requirements whose subject is configuration, a document or a run transcript (R-TST-001, 007 … 014, 030, 047, 048, 052, 060, 070, 071) have no function: their examples are the note blocks under the matching entity.

Groups for E4 (file ownership) and the interfaces they share — pinned here, changed only by an orchestrator ruling:

| Group | Files | Owns nodes |
|---|---|---|
| G1 infrastructure | `tests/support/timing.py`, `tests/support/suite_census.py` (new), `tests/conftest.py`, `tests/test_suite_hygiene.py` (new file) | `wait_until`, `report_margin`, `qc_tm_drain`, `qc_tm_summary_lines`, `timing_arms`, `unreported_upper_bounds`, `newest_line_waits`, `shared_wait_bodies`, the 2 hooks |
| G2 shared waits | `tests/b97_probes.py`, `tests/support/b100_load_dialog.py`, `tests/support/b100_projects.py` | `settled`, the two `wait_for`, `read_load_result_panel`, `dismiss_load_result_panel`, `save_case01_project`, `append_variant`, `load_project` |
| G3 timing arms | the 12 arm files of `E1-slice.md` §3 | the 32 decorators and 37 wraps (4 representative arm nodes below) |
| G4 config and docs | `pyproject.toml`, `.github/workflows/tui-ci.yml`, `docs/engineering-rules.md` | entities only |
| G5 version goldens [US-TST-5] | `tests/conftest.py` (`canonical_report_bytes` only; G1 owns the hooks in the same file — one writer, G1, applies both), the 7 goldens, `tests/test_report_service.py`, `tests/test_report_addendum_bound.py` (after the rebase, with the orchestrator's go) | `canonical_report_bytes`, `test_at288_report_hex_sections_identical_after_move`, `_golden_documents` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-1 the yielding wait | `async def wait_until(pilot, predicate: Callable[[], bool], failure: str \| Callable[[], str], *, timeout: float = WAIT_TIMEOUT_S, pause_first: bool = False) -> None` (a callable `failure` is called only when it raises; proposed by F-2, for E3 to confirm); `WAIT_TIMEOUT_S = 60.0`, `POLL_S = 0.05` in `tests/support/timing.py` | G1 → G2 |
| I-2 the margin reporter | `def report_margin(label: str, measured: float, bound: float) -> float` (returns `bound` itself); `MARGIN_FINDING_PCT = 20.0` | G1 → G3 |
| I-3 the marker | name `serial_timing`; registered line of R-TST-001 | G4 → G1 (guard), G3 (decorators) |
| I-4 the sampled-arm list | `SAMPLED_TIMING_ARMS: frozenset[str] = {"tests/test_b100_busy.py::test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys"}` in `suite_census.py` | G1 → G3 |
| I-5 the property | key `qc_tm`, value `<label>\|<measured:.3f>\|<bound:.3f>\|<margin:.1f>`, appended to `item.user_properties` before the call report is built [E3A-1], so the call report, the teardown report and junit (written from the teardown report) carry it | G1 (drain) → G1 (summary, call reports only), junit, Inc 1's TC-record generator (reads junit; ignores unknown properties) |
| I-9 CI parallel lane [R2] | `python -m pip install "pytest-xdist==3.8.0"` in the `tui-ci` install step; lane 1 `-n auto --dist loadfile`; lane 2 serial | G4 → CI |
| I-8 the tool-version token | `TOOL_VERSION_TOKEN = b"<TOOL-VERSION>"` in `tests/conftest.py`; `canonical_report_bytes` replaces it with `s19_app.version.__version__` | G5 → the 7 golden tests |
| I-6 the newest-line baseline | `NEWEST_LINE_BASELINE: dict[str, int]` pinned from the census on `b3bf42e` (E1 probe: 87 sites in 18 files; the exact dict is produced by the E4 detector on the base tree, not typed by hand) | G1 only |
| I-7 shared-wait signatures | each of the 7 keeps its `b3bf42e` positional parameters; `timeout: float` is added keyword-only | G2 → 159 direct call sites (unchanged) |

Order inside E4: G1 first defines I-1 and I-2 (G2 and G3 import them); G4 any time; G3's guard run needs G1's census.

## Nodes

wait_until
req: R-TST-020, R-TST-021, R-TST-022, R-TST-024
in: Pilot pilot; (Callable) ->bool predicate; str failure; float timeout = 60.0; bool pause_first = False
out: None
func: new. `deadline = time.monotonic() + timeout`; if `pause_first`, `await pilot.pause()` once; then loop: `predicate()` true → return; `time.monotonic() > deadline` → `raise AssertionError(failure() if callable(failure) else failure)`; else `await asyncio.sleep(POLL_S)` then `await pilot.pause()`. The `_wait_yielding` shape of fix round 2 R-1 with the failure text supplied by the caller.
module: tests/support/timing.py
examples: (R-TST-020/1) fake pilot, predicate `lambda: False`, failure "never", timeout `0.5` → raises `AssertionError("never")` after ≥ `0.5` s and < `1.5` s
examples: (R-TST-021/1) fake pilot, a predicate that counts its calls and returns False, timeout `1.0` → raises; the count is ≤ `21` (base `b100_projects.wait_for` with `attempts=10000` and a fake pilot: thousands of calls in 1 s, B)
examples: (R-TST-022/1) fake pilot, `pause_first=True`, predicate true at once that records `pilot.pauses` at its first call → returns None; the recorded value is ≥ `1`
examples: (R-TST-020/1b) predicate that turns true after 0.2 s, timeout `60.0` → returns None in < `0.4` s (no wait for the deadline)
examples: (R-TST-024/9) failure `lambda: f"seen: {seen}"` where the predicate appends to `seen` at each check, timeout `0.2` → raises `AssertionError` whose text lists the values appended up to the timeout, not "seen: []"

report_margin
req: R-TST-040, R-TST-042, R-TST-046
in: str label; float measured; float bound
out: float bound
func: new. Computes `margin = (bound - measured) / bound * 100`; appends `(label, measured, bound, margin)` to the module's pending list `_QC_TM_PENDING`; returns the `bound` object unchanged. Never asserts, never raises on a large `measured`.
module: tests/support/timing.py
modify: [Data: timing._QC_TM_PENDING] (append)
examples: (R-TST-040/2) label "x", measured `0.5`, `b = timing_bound(1.0)` → returns `b` (`is`); pending gets ("x", `0.5`, `1.0`, `50.0`)
examples: (R-TST-042/1) label "p", measured `0.85`, bound `1.0` → returns `1.0`; pending gets margin `15.0`
examples: (R-TST-046/1) label "o", measured `1.2`, bound `1.0` → returns `1.0`; pending gets margin `-20.0` (the caller's `assert 1.2 < 1.0` then fails; the record exists first)

qc_tm_drain
req: R-TST-042, R-TST-046
in: list[tuple] user_properties
out: int drained
func: new. [E3A-1] Called with `item.user_properties`, before the call report is built. Moves every pending record into `user_properties` as `("qc_tm", "<label>|<measured:.3f>|<bound:.3f>|<margin:.1f>")`, clears the pending list, returns how many it moved. Each report built after it copies `item.user_properties`, so the call and teardown reports both carry the records.
module: tests/support/timing.py
modify: [Data: timing._QC_TM_PENDING] (clear); user_properties (append)
examples: (R-TST-042/1) pending [("p", `0.85`, `1.0`, `15.0`)], `item.user_properties` [] → drained `1`; `item.user_properties` [("qc_tm", "p|0.850|1.000|15.0")]; pending []
examples: (R-TST-046/1) pending [("o", `1.2`, `1.0`, `-20.0`)] after a failed call → drained `1`; value "o|1.200|1.000|-20.0"; its section row reads "LOW -20.0%  1.200 s / 1.000 s  o  <nodeid>" [E3A-10]

qc_tm_summary_lines
req: R-TST-043, R-TST-044, R-TST-045
in: list[tuple[str, str]] reports
out: list[str] lines
func: new, pure. `reports` = (nodeid, `qc_tm` value) pairs from the call-phase reports of the session [E3A-1]. Empty → []. Else: `QC-TM timing margins` heading line, one row per pair `<margin>%  <measured> s / <bound> s  <label>  <nodeid>` sorted by margin ascending, prefixed `LOW ` when margin < `20.0`, then `QC-TM: <n> bounds, <k> under 20 % margin`.
module: tests/support/timing.py
examples: (R-TST-043/1) reports [("t::a", "a|0.600|1.000|40.0"), ("t::b", "b|0.850|1.000|15.0"), ("t::c", "c|0.750|1.000|25.0")] → lines[1] "LOW 15.0%  0.850 s / 1.000 s  b  t::b", lines[2] "25.0%  0.750 s / 1.000 s  c  t::c", lines[3] "40.0%  0.600 s / 1.000 s  a  t::a"
examples: (R-TST-045/1) the same reports → last line "QC-TM: 3 bounds, 1 under 20 % margin"
examples: (R-TST-044/2) reports [("t::d", "d|0.800|1.000|20.0")] → row "20.0%  0.800 s / 1.000 s  d  t::d" (no `LOW `)
examples: (R-TST-043/1b) reports [] → `[]` (no section in a session with no timing arm, e.g. the parallel lane)

timing_bound
req: R-TST-040
in: float seconds
out: float bound
func: unchanged. `seconds` locally, `seconds * 2` when env `CI` is truthy. Now usually read through `report_margin(label, took, timing_bound(1.0))`.
module: tests/support/timing.py
examples: (B) seconds `1.0`, env CI unset → `1.0`; env CI "true" → `2.0` (holds on base)

timing_arms
req: R-TST-002, R-TST-005, R-TST-006
in: Path tests_root
out: dict[str, int] arms
func: new, pure AST census. [E3A-2, E3A-16] For each `test_*.py` under `tests_root`, each top-level `test_*` function and each `test_*` method of a `Test*` class: resolves the clock names of the module (`time.perf_counter` and friends under any alias: `import time as _time`, `from time import perf_counter`); marks **clock stamps** (names, subscripts, attributes, list items bound to a clock call or `.append`ed from one); marks **intervals** — any subtraction with a clock call or stamp on either side (`painted_at[0] - started`, `stamp - start`), names or subscripts bound to one **by tuple position or dict key** (including the matching position of a value returned by a same-module, nested or support function that returns one), items of a list `.append`ed an interval, and either branch of a conditional expression that is one [N-1]. Clock imports are resolved at module and function level [N-1]. Reports the test when an ordering assert reached from it (body, nested defs, same-module functions it calls, transitively) has an operand that is an interval, or is or contains a `timing_bound(…)` or `report_margin(…)` call. Returns `"<file>::<test>"` → line of the first such assert. The sampled list I-4 is added by the guard. The guard reads the **marked set** from the tests' own decorators (`pytest.mark.serial_timing`) and refuses a module- or class-level `pytestmark` that carries `serial_timing`.
module: tests/support/suite_census.py
examples: (R-TST-005/1) planted `def test_a(): start = time.perf_counter(); f(); elapsed = time.perf_counter() - start; assert elapsed < 2.0` → arms has "…::test_a"
examples: (R-TST-005/2) planted `def _check(s): assert s["read"] < timing_bound(1.0)` and `def test_b(): _check(scene())` → arms has "…::test_b"
examples: (R-TST-005/3) planted nested `_s` returning `msgs, time.perf_counter() - start`, `msgs, elapsed = run_app(base, _s)`, `assert elapsed < 5.0` → arms has "…::test_c"
examples: (R-TST-005/6) planted hook-recorded stamps: `stamps = []`; a wrapper does `stamps.append(time.perf_counter())`; `took = stamps[0] - start`; `assert took < 1.0` → the test reported [E3A-2]
examples: (R-TST-005/7) planted `elapsed = other_module.measure()`; `assert elapsed < report_margin("l", elapsed, timing_bound(1.0))` → the test reported (form (d)) [E3A-2]
examples: (R-TST-005/8) planted `import time as _time`; `assert _time.perf_counter() - t < 2.0` → the test reported [E3A-16]; a function-local `import time` (as in `load_project`) resolves the same way [N-1]
examples: (R-TST-005/5) the head tree after the 37 wraps → the same `31` arms; "tests/test_b100_active_variant.py::test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second" found by the stamp form (`painted_at[0] - started`) and by form (d); the 3 hostile params of TC-B100-30 found by form (d) [E3A-2]
examples: (R-TST-005/5, B) the `b3bf42e` tree → `31` arms, among them "tests/test_b100_project_check.py::test_tc_b100_61_sec6_5_deep_entries_need_one_check_each_parent" (through `_assert_sec6_5_bounded`) and "tests/test_b100_project_homes.py::test_tc_b100_31_junction_cycle_ends" (through the nested `_scenario`)
examples: (R-TST-006/1, B) `tests/test_sync_evidence.py` (18 tests with `time.time() - N` file times) → `0` arms; (R-TST-006/2) `test_tc_b100_31_copy_ceiling_2000_files` (prints its interval) → absent; (R-TST-006/3) `test_tc_b100_30_reopen_lists_the_recorded_document` (unpacks `_reopen`'s 8-tuple, reads positions 0–4 only; position 5 is the interval) → absent [E3A-3]
examples: (R-TST-003/1) planted module, `def test_x()` with `assert time.perf_counter() - t < 1.0` and no mark → arms has "<file>::test_x"; the guard (arms ∪ I-4 minus the marked set) fails with "timing arm without serial_timing: <file>::test_x"
examples: (R-TST-004/1) planted module, `@pytest.mark.serial_timing` on `def test_y(): assert 1 + 1 == 2` → arms lacks "<file>::test_y"; the guard (marked set minus arms ∪ I-4) fails with "serial_timing on a test that is not a timing arm: <file>::test_y"

unreported_upper_bounds
req: R-TST-040, R-TST-041
in: Path tests_root; dict[str, int] arms
out: list[str] sites
func: new, pure AST census over the arms and the same-module functions they reach. [E3A-3] An **upper timing bound** is the bound side of `interval < b` / `interval <= b` / `b > interval` / the upper half of `a <= interval <= b`, where the interval side is an interval of `timing_arms`' rule — a direct subtraction, a stamp difference, a name or subscript tainted by **tuple position or dict key**, an item of a list `.append`ed an interval, or a branch of a conditional expression that is one [N-1] (a name unpacked from a count position, a key never assigned an interval, a call such as `len(…)` are not intervals). `b` may be any expression: there is no type rule. Returns `"<file>:<line>"` for each upper bound whose `b` is not a `report_margin(…)` call.
module: tests/support/suite_census.py
examples: (R-TST-040/1) the Inc 2 head tree → `[]`; on the `b3bf42e` tree (B) → `37` sites, among them "tests/test_b100_active_variant.py:738" and "tests/test_b100_save_dialog.py:2335" (the `<= 0.5` half only)
examples: (R-TST-041/1) planted marked arm with `assert elapsed < 1.0` at line `7` → ["<file>:7"]; the guard text "timing bound without report_margin: <file>:7"
examples: (R-TST-040/4, B) `tests/test_b100_project_check.py:841` `timing[0] < timing_bound(1.0)` (`:820` `timing.append(time.perf_counter() - app._load_started_at)`), `:978` `scene["load"] < …` (`:965` `"load": timing[0] if timing else None`) and `:1350` → in the list (3 of the 37) [N-1]
examples: (R-TST-041/2) planted `assert elapsed < 2` (int), `assert elapsed < timing_bound(1.0) * 2`, `assert elapsed < LIMIT` with `LIMIT = 1` → 3 sites [E3A-3]
examples: (R-TST-040/3, B) `tests/test_b100_project_check.py:843` `rows <= LOAD_PANEL_ROW_BOUND` (`timing, painted, rows = asyncio.run(_drive())`: position 2 is a count), `:981` `scene["rows"] <= LOAD_PANEL_ROW_BOUND` (key `rows` never assigned an interval), `tests/test_b100_save_dialog.py:2331` `1 <= len(out["burst_calls"]) <= 3`, `:3493` `1 <= count <= 3` (`count, final = _run(...)`: position 0 is a count), the lower half `0.1 <=` of `:2335` → not in the list [E3A-3]

newest_line_waits
req: R-TST-051
in: Path tests_root
out: dict[str, int] counts
func: new, pure AST census. [E3A-6] Per module, resolves **newest-line readers** (a local function, or a name imported from a support module, whose body holds `#log_line_4` or returns `….log_lines[-1]`, e.g. `b97_probes.last_status`) and **all-line readers** (one that builds `#log_line_{…}` with an f-string or returns every `log_lines` item, e.g. `painted_log` in `tests/test_b100_workers.py`). Counts, per file, each call whose callee name holds `wait`, `settle`, `until` or `poll` and which has a lambda argument that holds `#log_line_4`, reads `….log_lines[-1]`, calls a newest-line reader, or indexes `[-1]` on a call of an all-line reader. Files with 0 are left out.
module: tests/support/suite_census.py
examples: (R-TST-051/1, B) the `b3bf42e` tree → the counts E4's implemented census gives; `NEWEST_LINE_BASELINE` is generated by that census on the base tree, never copied from a probe (E3 probes: 89 in 18 files; the round-2 reviewer: 83 in 15) [R2]; e.g. "tests/test_b100_workers.py" now counts the `painted_log(app)[-1]` waits (`:3014`, `:3172`); e.g. "tests/test_b100_focus.py" counts the `'A2L loaded:' in _status_text(app)` waits
examples: (R-TST-051/2) a planted copy of a baselined file with one more `_wait_for(pilot, lambda: "x" in _status_text(app), "x")` → its count = baseline + `1`; the guard text "newest-line wait added in <file>: <n+1> > baseline <n>; collect the painted lines with StatusLog.since(mark)"
examples: (R-TST-051/3) a planted new file with one such wait → {"<file>": `1`}; text "… <file>: 1 > baseline 0; …"
examples: (R-TST-051/4) a planted copy of a baselined file that imports `last_status` from `tests.b97_probes` and adds `settled(pilot, lambda: "x" in last_status(app), "x")` → count = baseline + `1`; guard fails with the R-TST-051 text [E3A-6]

shared_wait_bodies
req: R-TST-020, R-TST-021, R-TST-024
in: Path tests_root
out: dict[str, tuple] shapes
func: new, pure AST census of the 7 shared functions (Definitions). Per function: the number of `for … in range(…)` loops whose body awaits `pilot.pause`, and the `failure` argument of each `wait_until` call (constant or f-string source).
module: tests/support/suite_census.py
examples: (R-TST-020/2) head tree → every function has `0` range loops; `dismiss_load_result_panel` has 2 `wait_until` calls, `save_case01_project` 2, the others 1 (9 in all)
examples: (R-TST-024/7) head tree → `save_case01_project`'s first failure is the f-string "the load of {item} did not land"; (R-TST-024/8) its second "Save project {name} did not land"; (R-TST-024/9) `append_variant`'s "the variant append of {source.name} did not land: {statuses}"
examples: (B) the `b3bf42e` tree → `b100_projects.wait_for` has `1` range loop and `0` `wait_until` calls

pytest_runtest_makereport
req: R-TST-042, R-TST-046
in: Item item; CallInfo call
out: None
func: new hookwrapper in the root test conftest. [E3A-1] **Before** its `yield`, when `call.when == "call"` (passed or failed): `qc_tm_drain(item.user_properties)`; then `yield`. The call report (built after the drain) and the teardown report copy `item.user_properties`, so both carry `qc_tm`, and the junit writer — which writes properties from the teardown report — writes it once. Setup and teardown phases drain nothing (E3A-11's per-phase clearing is an E4 addendum).
module: tests/conftest.py
modify: [Data: Item.user_properties] (append)
examples: (R-TST-042/1) planted test calling `report_margin("p", 0.85, 1.0)` in an inner `pytester` run → its call report and its teardown report each hold ("qc_tm", "p|0.850|1.000|15.0"); the junit XML holds, once, `<property name="qc_tm" value="p|0.850|1.000|15.0"/>`
examples: (R-TST-046/1) planted failing arm → the failed call report still holds its `qc_tm` property

pytest_terminal_summary
req: R-TST-043, R-TST-044, R-TST-045
in: TerminalReporter terminalreporter; int exitstatus; Config config
out: None
func: new hook. [E3A-1] Gathers (nodeid, value) from the reports in `terminalreporter.stats` whose `when == "call"` (passed or failed) and whose user_properties hold `qc_tm` — a teardown error report in `stats["error"]` carries the same property and is skipped, so no row is doubled — so it also works when reports arrive from xdist workers — and writes `qc_tm_summary_lines(...)` as a section; writes nothing when the list is empty.
module: tests/conftest.py
examples: (R-TST-043/1) inner run of 3 planted arms with margins 40.0, 15.0, 25.0 → output holds "QC-TM timing margins", then rows in order 15.0, 25.0, 40.0, the first starting "LOW ", and "QC-TM: 3 bounds, 1 under 20 % margin"
examples: (R-TST-043/1b) a session with no timing arm → no "QC-TM" text in the output
examples: (R-TST-043/2) inner run, one planted arm reporting 15.0 whose teardown raises → exactly `1` QC-TM row for it [E3A-1]

settled
req: R-TST-020, R-TST-021, R-TST-022, R-TST-023, R-TST-024
in: Pilot pilot; (Callable) ->bool predicate; str description; int attempts = 60; float timeout = 60.0
out: None
func: changed. was: `for _ in range(attempts): await pilot.pause(); if predicate(): return` then `raise AssertionError(f"did not settle: {description}")` — bounded by a count of bare pauses / now: `await wait_until(pilot, predicate, f"did not settle: {description}", timeout=timeout, pause_first=True)`; `attempts` is kept for the 45 call sites and no longer bounds (docstring says so).
module: tests/b97_probes.py
examples: (R-TST-024/3) fake pilot, predicate `lambda: False`, description "row 2 back", timeout `0.2` → `AssertionError("did not settle: row 2 back")`
examples: (R-TST-022/1) predicate true at once → returns None after ≥ `1` pause (base: also pause first, holds on base)
examples: (R-TST-023/1) `inspect.signature(settled)` → positional (pilot, predicate, description, attempts=`60`), keyword-only timeout

b100_load_dialog.wait_for
req: R-TST-020, R-TST-021, R-TST-023, R-TST-024
in: Pilot pilot; (Callable) ->bool predicate; str description; int attempts = 400; float timeout = 60.0
out: None
func: changed. was: check, then bare `pilot.pause()`, `attempts` times; `timed out waiting for <description>` / now: `await wait_until(pilot, predicate, f"timed out waiting for {description}", timeout=timeout)` (check first, as before). `wait_for_dialog` and `wait_for_dialog_closed` keep passing `attempts`, unchanged.
module: tests/support/b100_load_dialog.py
examples: (R-TST-024/2) fake pilot, `lambda: False`, "the Load dialog", timeout `0.2` → `AssertionError("timed out waiting for the Load dialog")`
examples: (R-TST-020/2) AST → `0` range loops, `1` `wait_until` call (base: `1` range loop, B)

wait_for
req: R-TST-020, R-TST-021, R-TST-023, R-TST-024
in: Pilot pilot; (Callable) ->bool predicate; str description; int attempts = 400; float timeout = 60.0
out: None
func: changed. was: the same count loop as `b100_load_dialog.wait_for` / now: `await wait_until(pilot, predicate, f"timed out waiting for {description}", timeout=timeout)`. Reached also through `load_image`, `load_project`, `save_project` (unchanged callers).
module: tests/support/b100_projects.py
examples: (R-TST-024/1) fake pilot, `lambda: False`, "the thing", timeout `0.2` → `AssertionError("timed out waiting for the thing")`
examples: (R-TST-021/1) through `wait_until`: never-true predicate, timeout `1.0` → ≤ `21` checks

read_load_result_panel
req: R-TST-020, R-TST-021, R-TST-023, R-TST-024
in: Pilot pilot; App app; int attempts = 200; float timeout = 60.0
out: str text
func: changed. was: `range(attempts)` loop until `#result_summary` has a height, then returns `load_result_panel_text(app)` / now: `await wait_until(pilot, <summary laid out>, "the Load-result panel was not painted", timeout=timeout)`, then returns `load_result_panel_text(app)` (unchanged).
module: tests/support/b100_projects.py
examples: (R-TST-024/4) fake app whose screen query for "#result_summary" is always empty, timeout `0.2` → `AssertionError("the Load-result panel was not painted")`

dismiss_load_result_panel
req: R-TST-020, R-TST-021, R-TST-023, R-TST-024
in: Pilot pilot; App app; int attempts = 200; float timeout = 60.0
out: None
func: changed. was: a `range(attempts)` loop for the close button, an `assert` "did not open", `escape`, a second `range(attempts)` loop, `raise` "did not close on esc" / now: `wait_until(pilot, <close button present>, "the Load-result panel did not open", timeout=timeout)`, `await pilot.press("escape")`, `wait_until(pilot, <close button gone>, "the Load-result panel did not close on esc", timeout=timeout)`.
module: tests/support/b100_projects.py
examples: (R-TST-024/5) fake app with no `LOAD_RESULT_CLOSE` match, timeout `0.2` → `AssertionError("the Load-result panel did not open")`; no `escape` pressed
examples: (R-TST-024/6) fake app whose close button stays after `escape`, timeout `0.2` → `AssertionError("the Load-result panel did not close on esc")`; `escape` pressed `1` time

save_case01_project
req: R-TST-020, R-TST-021, R-TST-024
in: Path base; str name = "P"; tuple files = CASE01 files
out: Path project_dir
func: changed (2 waits only). was: two `for _ in range(400)` loops with `else: raise AssertionError(...)` / now: each load waits with `wait_until(pilot, done, f"the load of {item} did not land")` and the save with `wait_until(pilot, lambda: app.current_project == name, f"Save project {name} did not land")`; the `settle_workers` calls and everything else unchanged.
module: tests/support/b100_projects.py
examples: (R-TST-024/7) AST → failure f-string "the load of {item} did not land"; (R-TST-024/8) → "Save project {name} did not land"
examples: (B) `build_p04_case(tmp, "clean")` → the folder `P` with `project.json`, `firmware.s19`, `firmware.mac`, `firmware.a2l` (holds on base; the 54 calls keep their outcome)

append_variant
req: R-TST-020, R-TST-021, R-TST-024
in: Path base; Path source; str name = "P"
out: None
func: changed (1 wait). was: `for _ in range(400)` until a status line holds "manifest verified", then `raise AssertionError(f"the variant append of {source.name} did not land: {statuses}")` / now: `await wait_until(pilot, lambda: any("manifest verified" in line for line in statuses), lambda: f"the variant append of {source.name} did not land: {statuses}")` — the text is built when `wait_until` raises, so it shows the statuses painted up to the timeout (Findings F-2; needs I-1's `failure` to accept a callable).
module: tests/support/b100_projects.py
examples: (R-TST-024/9) AST → the failure names "the variant append of {source.name} did not land: {statuses}" with the statuses painted up to the timeout

load_project
req: R-TST-025
in: Pilot pilot; App app; str name = "P"
out: float elapsed
func: changed (the clock end only). was: `start = perf_counter()`; `app._handle_load_project(name)`; `await wait_for(... current_project == name and current_file is not None ...)`; `elapsed = perf_counter() - start` — stops when the poll notices / now: before the request, wraps `app._install_prepared_project` on the instance with a recorder that calls the real method and then stamps `perf_counter()` into a one-item list; the wait stays (its predicate unchanged); `elapsed = stamp - start`; the wrapper is removed in a `finally`. `settle_workers` and the 6 pauses after it unchanged.
module: tests/support/b100_projects.py
modify: [Outside: S19TuiApp._install_prepared_project] (wrapped on the instance for one call)
examples: (R-TST-025/1) case_01 project "P", 3 fresh apps → each returned elapsed equals (install-return stamp − start) within `0.001` s
examples: (B) base: elapsed exceeds the install return by the time until the next poll check (up to one bare-pause cycle; up to `0.05` s once `wait_for` polls through `wait_until`) — the reason for the change

S19TuiApp._install_prepared_project
req: R-TST-025
in: PreparedProjectLoad prepared
out: None
func: unchanged (product, `s19_app/tui/app.py:13659`). "The one install callback (S-g)": sets `current_project`, `current_project_dir`, installs the image and MAC, paints the announcement, ends the busy run. Reached through `call_after_refresh(self._install_prepared_project, prepared)` (`:13657`), an attribute lookup on the instance at call time — so an instance attribute set by the test is the one called.
module: s19_app/tui/app.py
examples: (B) case_01 project "P" loaded through `_handle_load_project("P")` → after it returns, `app.current_project` = "P" and `app.current_file` is not `None` (holds on base)

StatusLog.since
req: R-TST-050
in: int mark
out: list[str] messages
func: unchanged (verified). `StatusLog(app)` wraps `app.set_status` on the instance, records every message in full, then paints it; `since(mark)` returns `messages[mark:]`. The QC-OR oracle helper: no cap, unlike the app's own `log_lines` (`deque(maxlen=4)`, `app.py:2776`).
module: tests/support/b100_projects.py
examples: (R-TST-050/1) `mark = len(log.messages)`; 6 calls `app.set_status("line 1")` … `("line 6")` → since(mark) = ["line 1", "line 2", "line 3", "line 4", "line 5", "line 6"]; `list(app.log_lines)` has `4` items (holds on base)

_assert_sec6_5_bounded
req: R-TST-040
in: dict scene
out: None
func: changed (4 wraps). was: `assert scene["read"] < timing_bound(1.0), timings` and the same for "load", "painted", "appended" / now: each bound side is `report_margin("sec6_5 <key>", scene[<key>], timing_bound(1.0))`; the two row asserts unchanged. Shared by 4 arms; each report carries the calling test's node id (the drain runs in that test's call phase).
module: tests/test_b100_project_check.py
examples: (R-TST-040/1) scene {"read": `0.135`, "load": `0.340`, "painted": `0.810`, "appended": `1.088`, …} → 4 reports, margins `86.5`, `66.0`, `19.0`, `-8.8`; the last assert fails as on base (values from the Windows battery log, `full-shard*.log`)

test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second
req: R-TST-002, R-TST-040
in: Path tmp_path; str writer
out: None
func: changed (decorator + 1 wrap). Gains `@pytest.mark.serial_timing` above its `parametrize`; `assert took < timing_bound(1.0), took` becomes `assert took < report_margin(f"TC-B100-20 {writer}", took, timing_bound(1.0)), took`. Its clock already stops at the `set_status` hook (fix round 2 R-1): the QC-TM exemplar. Name, params and the rest unchanged.
module: tests/test_b100_active_variant.py
examples: (R-TST-002/1) `-m serial_timing --collect-only` → the 5 params collected; `-m "not serial_timing"` → none of them
examples: (R-TST-043/1) serial lane, writer "save-project", took `0.82` s locally → row "18.0%  0.820 s / 1.000 s  TC-B100-20 save-project  tests/test_b100_active_variant.py::…[save-project]" prefixed `LOW ` (R1-P1's thin margin becomes a visible gate finding)

test_tc_b100_30_hostile_document_is_one_not_readable_under_one_second
req: R-TST-002, R-TST-025, R-TST-040
in: Path tmp_path; str case
out: None
func: changed (decorator + 1 wrap). Gains `serial_timing`; `assert elapsed < timing_bound(1.0), …` becomes `assert elapsed < report_margin(f"TC-B100-30 {case}", elapsed, timing_bound(1.0)), …`. `elapsed` comes from `load_project` through `_reopen`, so it now ends at the install callback (R-TST-025).
module: tests/test_b100_document.py
examples: (R-TST-008/1) release gate: the 3 params pass in the serial lane (batch-100: 3/3 failed under `-n 8`)

test_tc_b100_65_recompute_is_a_150ms_debounce
req: R-TST-002, R-TST-040
in: Path tmp_path
out: None
func: changed (decorator + 2 wraps). `assert out["final_after"] <= 0.3, out` → `<= report_margin("TC-B100-65 final paint", out["final_after"], 0.3)`; `assert 0.1 <= out["q_delay"] <= 0.5, out` → `0.1 <= out["q_delay"] <= report_margin("TC-B100-65 q delay", out["q_delay"], 0.5)` (the lower half stays a literal); `1 <= len(out["burst_calls"]) <= 3` unchanged (a count).
module: tests/test_b100_save_dialog.py
examples: (R-TST-040/1) head tree → `unreported_upper_bounds` lists none of this test's lines; base (B) lists ":2333" and ":2335"

test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys
req: R-TST-002, R-TST-008
in: Path tmp_path
out: None
func: changed (decorator only). A sampled timing arm (I-4): it counts spinner glyphs and elapsed texts sampled every 0.05 s during an about 2.4 s parse, so it has no bound to wrap; it gains `@pytest.mark.serial_timing`.
module: tests/test_b100_busy.py
examples: (R-TST-002/1) node id in `SAMPLED_TIMING_ARMS` and marked → guard passes; mark removed → "timing arm without serial_timing: tests/test_b100_busy.py::test_at_b100_17_worker_load_of_an_8_mib_s19_by_keys"
examples: (R-TST-008/1) release gate: passes in the serial lane (batch-100: failed under `-n 8`)

canonical_report_bytes
req: R-TST-081, R-TST-082
in: bytes raw; Path? run_root = None
out: bytes canonical
func: changed (one step added). was: CRLF → LF; run-root spellings → `<RUN-ROOT>`; separators normalized inside run-root spans; host-path residue check / now: the same, plus every `<TOOL-VERSION>` (I-8) replaced by `s19_app.version.__version__` encoded UTF-8, read at call time. Produced reports hold no token, so only golden bytes change. A wrong version in a produced report is not touched, so it still differs (R-TST-082).
module: tests/conftest.py
examples: (R-TST-081/2) raw `b"- Tool version: <TOOL-VERSION>\n"` with `s19_app.version.__version__` patched to "9.9.9" → `b"- Tool version: 9.9.9\n"`
examples: (R-TST-082/1) raw `b"- Tool version: 0.0.0\n"` (a produced report), package version "1.0.0rc1" → unchanged `b"- Tool version: 0.0.0\n"`, which differs from the golden's canonical `b"- Tool version: 1.0.0rc1\n"`
examples: (B) raw `b"a\r\nb"` → `b"a\nb"` (holds on base)

test_at288_report_hex_sections_identical_after_move
req: R-TST-081
in: Path tmp_path
out: None
func: changed (the pinned compare and its capture branch). was: `assert emitted == pinned` on raw bytes; when the capture is missing, writes `emitted` / now: `assert emitted == canonical_report_bytes(pinned)`; the capture branch writes `emitted` with the package version replaced by `<TOOL-VERSION>`. Name and the rest unchanged.
module: tests/test_report_service.py
examples: (R-TST-081/1) golden `tests/goldens/batch99/at288-pre-move-report.bin` holding `Tool version: <TOOL-VERSION>`, package version "1.0.0rc1" → passes

_golden_documents
req: R-TST-081
in:
out: dict[str, bytes] documents
func: changed (one line, Inc 1's file, after the rebase and with the orchestrator's go). was: decodes `_GOLDEN.read_bytes().replace(b"\r\n", b"\n")` / now: decodes `canonical_report_bytes(_GOLDEN.read_bytes())` (same CRLF undo, plus the version token). The shape split is unchanged.
module: tests/test_report_addendum_bound.py
examples: (R-TST-081/1) `tests/goldens/batch64/addendum-below-bound.md` with the token → each document holds `Tool version: 1.0.0rc1`; `test_at196_below_bound_report_is_byte_identical_to_the_inc1_golden` passes

## Entities

[Data: timing._QC_TM_PENDING]
in: list[tuple[str, float, float, float]]
desc: module-level list in `tests/support/timing.py`; per process (each xdist worker has its own); filled by `report_margin` during a test's call phase, emptied by `qc_tm_drain` in that test's report hook
sequence:
  armCall: report_margin → report_margin → pytest_runtest_makereport wins (drain)
  nextTest: pytest_runtest_makereport (drains nothing when the test reported nothing)

[Data: TestReport.user_properties]
in: list[tuple[str, str]]
desc: pytest's per-report properties; serialized from xdist workers to the controller and written to junit `<properties>`; key `qc_tm` (I-5)

[Outside: S19TuiApp._install_prepared_project]
desc: the product's install callback, wrapped on the instance by `load_project` for one load; the product file is not changed

[I/O: pyproject markers]
desc: `[tool.pytest.ini_options] markers` in `pyproject.toml` (`:111-114`); gains the `serial_timing` line (I-3)

### Examples — pyproject markers (R-TST-001)
- (R-TST-001/1) `pytest --markers` → a line "@pytest.mark.serial_timing: serial_timing: a wall-clock timing arm; run apart and serially (-m serial_timing)". Base (B): only `slow` and `snapshot` lines.

[I/O: tui-ci workflow]
desc: `.github/workflows/tui-ci.yml`, job `tui-ci` (the `snapshot` job is unchanged)
sequence:
  pull_request: checkout (fetch-depth 0) → install (+ pytest-xdist 3.8.0) → lane 1 `pytest -v -rs -n auto --dist loadfile -m "not slow and not serial_timing"` (120 min) → lane 2 `pytest -q -rs -m "serial_timing and not slow"` (30 min; runs when lane 1 is red: `!cancelled()`)
  push: checkout (fetch-depth 0) → install (+ pytest-xdist 3.8.0) → lane 1 `pytest -v -rs -n auto --dist loadfile -m "not serial_timing"` (180 min) → lane 2 `pytest -q -rs -m serial_timing` (45 min; `!cancelled()`); the job stops at 240 min

### Examples — tui-ci workflow (R-TST-010 … 018, 090, 091)
- (R-TST-010/1) PR steps after install → 2 `run:` lines exactly `pytest -v -rs -n auto --dist loadfile -m "not slow and not serial_timing"`, then `pytest -q -rs -m "serial_timing and not slow"`. Base (B): 1 step `pytest -q -m "not slow"` (`:45`).
- (R-TST-011/1) push steps → `pytest -v -rs -n auto --dist loadfile -m "not serial_timing"`, then `pytest -q -rs -m serial_timing`. Base: `pytest -q` (`:49`). With `-v` every node's outcome line is printed as it runs, so a lane stopped at its limit still names the failures before the stop [E3A-4].
- (R-TST-012/1) each lane-2 step's `if:` → "github.event_name == 'pull_request' && !cancelled()" and "github.event_name == 'push' && !cancelled()"; on a run where lane 1 has 1 failure, lane 2 shows `completed` and the job `failure`.
- (R-TST-013/1) the `tui-ci` checkout → `with: fetch-depth: 0`. Base: no `with:` (`:28`).
- (R-TST-014/1) Inc 2's own pull-request run, lane-1 `-rs` summary [E3A-4] → no line "git or commit b514b07 unavailable", "… 9c7beaf unavailable", "… 09e44de unavailable"; the 6 history arms passed.
- (R-TST-015/1) lane-1 steps → `timeout-minutes: 180` (push), `120` (PR). (R-TST-016/1) job `tui-ci` → `timeout-minutes: 240`. Base: neither. [R2]
- (R-TST-018/1) install step → `python -m pip install "pytest-xdist==3.8.0"`; (R-TST-018/2) Inc 2's PR run, lane-1 header → `plugins: … xdist-3.8.0 …` and `created: 4/4 workers` on a 4-vCPU `ubuntu-latest` runner [R2].
- (R-TST-090/1) Inc 2's PR run → record: lane 1 ≈ 60–90 min expected, lane 2 and job times, beside run 41372953464's serial `tui-ci` `4 h 53 min`. (R-TST-091/1) first push run after the merge → lane 1 + lane 2 ≤ `150` min.
- (R-TST-017/1) lane 1 stopped at 180 min (push; the step fails, it is not cancelled) → lane 2 runs under `!cancelled()` with its 45 min; 3 + 180 + 45 = 228 ≤ 240, so the job ends `failure` before its limit [N-3].

[I/O: test conventions]
desc: `docs/engineering-rules.md`; one new section "Test timing, waits and oracles (batch-101 Inc 2)" holding the gate commands and the five rules, each sentence verbatim from its requirement

### Examples — test conventions (R-TST-007, 030, 047, 048, 052, 060)
- (R-TST-007/1) the section holds `pytest -n 8 -m "not serial_timing"` before `pytest -m serial_timing`, and names the LAN Linux host.
- (R-TST-030/1) holds "An arm that checks the state a key press leaves while a real worker runs holds the worker at a forced slow step or records the state at the product hook; it never samples after the press."
- (R-TST-047/1) holds "A timing arm stops its clock at a stamp the product emits (a commit handler, a painted line, an install callback), never when a poll notices."
- (R-TST-048/1) holds "A margin under 20 % in the serial lane's QC-TM section is a gate finding; the finding gives the base tree's time beside it."
- (R-TST-052/1) holds "A test that waits on a painted outcome collects the lines painted since its trigger (StatusLog.since(mark)) and asserts the one it needs; it never waits on the newest line alone."
- (R-TST-060/1) holds "When an increment changes the order or the source of an observable, its gate greps tests/ for every node that asserts that observable and runs them, whatever module they sit in."
- Base (B): none of the six sentences; QC-BC exists only in the batch PLAN's Conventions.

[I/O: report goldens with a version]
desc: the 7 golden files of the Definitions; each holds `Tool version: <TOOL-VERSION>` in place of the version (I-8)

### Examples — report goldens (R-TST-080)
- (R-TST-080/1) head tree → 0 files under `tests/goldens/` match `Tool version: [0-9]`; the 7 hold `Tool version: <TOOL-VERSION>`. Base (B): 7 hold `Tool version: 0.1.0` (the main hotfix: `1.0.0rc1`).

[I/O: release gate transcripts]
desc: the two lanes on the LAN Linux host at Inc 2's merge tree, twice; evidence under `.dev-flow/2026-11-01-batch-101/evidence/inc-2/`

### Examples — release gate and CI record (R-TST-008, 009, 031, 032, 070, 071, 072)
- (R-TST-008/1) run 1 and run 2: lane 1 `-n 8 -m "not serial_timing"` reports 0 of the 32 timing arms (deselected); lane 2 `-m serial_timing` collects the 32 (more with params) and 0 fail. Batch-100 (B): one lane, 13 of them failed.
- (R-TST-009/1) lane 1 + lane 2 ≤ `75` min (batch-100's single lane: `62.6` min, `linux-gate-f72eef1-summary.txt`).
- (R-TST-031/1, /2; R-TST-032/1) lane 1, 3 runs: `test_at_b100_18_quit_confirm_half_slow_save_as_leaves_no_partial_folder`, `test_at_b100_17_parse_half_case06_a2l_by_keys`, `test_tc_b97_64_a_new_set_run_restarts_the_dwell` pass 3/3 each (they stay in lane 1: no wall-clock bound).
- (R-TST-070/1) run 41372953464's `tui-ci` job completed with FAILED lines {the 5 known failures} (the census reads only that job [E3A-5]) → record: 5 lines `known`, 0 `new`; any other FAILED node → `new` + the increment it is routed to (13 timing arms → Inc 2 itself, closed by the marker).
- (R-TST-071/1) run ends `cancelled` at step "Run full test suite (pushes)" → record states it and owes the check to the first push after Inc 2's merge.
- (R-TST-072/1) the run's `snapshot` job, `success` at 2026-11-02T01:33:53Z → record: "snapshot: success" and the 29 density cells of LLR-173.2m, each with its result [E3A-5].

## Findings

finding F-1 the two `wait_for` nodes share a name
anchor: tests/support/b100_projects.py:598, tests/support/b100_load_dialog.py:72
seen: Code-Wire marks must be unique by name; both helpers are called `wait_for`. The graph names the second `b100_load_dialog.wait_for`, which the extractor would read as a class method.
effect: a throwaway-worktree extractor run must take the two modules separately (`--path` per module) or rename the mark only in the throwaway copy.
decision: names in the source stay (D-14); E3 notes the extractor procedure.

finding F-2 a failure text that shows state at the timeout
anchor: tests/support/b100_projects.py:394-398 (`append_variant`)
seen: the base text `the variant append of {source.name} did not land: {statuses}` shows the statuses at the moment it raises. An f-string passed to `wait_until` as `failure` is evaluated at the call, when `statuses` is still empty, so the text would lose the lines it exists to show.
effect: R-TST-024/9 would pass on the template while the message loses its evidence.
decision: proposed for E3 — `wait_until` accepts `failure: str | Callable[[], str]`; a callable is called only when it raises. `append_variant` passes `lambda: f"…: {statuses}"`. The other 8 waits pass plain strings. (Alternative: `append_variant` catches the `AssertionError` and re-raises with the statuses — more code, two texts.)

finding F-3 timing arms outside the parallel lane lose concurrent coverage
anchor: the 32 arms
seen: marked arms never run beside other tests; a product change that makes them slow only under contention is not seen.
effect: none on correctness — their bounds state single-run times (QC-TM: "alone time").
decision: accepted; the serial lane is where their requirement's number holds.

finding F-4 CI wall time
anchor: CI runs 41290452101 (202 min), 41338318239 (230 min); 41372953464 at 4 h 14 min at E1
seen: the push lane ran serially for 4 h 53 min on run 41372953464 (17 595 s, `../../evidence/ci/41372953464.txt`) against GitHub's 6 h job limit; pushes queue full runs with no `concurrency` group.
effect: before E3, a run that hit the limit gave no FAILED set. Now `-v` on lane 1 (R-TST-011) names every outcome as it runs, the timeouts of R-TST-015 … 017 leave room for lane 2, and lane 1 runs in parallel (R-TST-018).
decision: operator decision on O-2 (E3 round 2): YES — pytest-xdist 3.8.0 in CI, lane 1 `-n auto --dist loadfile`; CI time measured by R-TST-090 (PR run) and R-TST-091 (first post-merge push) [N-2].

finding F-5 E3 round 1 corrections
anchor: ../E3-architect.md, ../E3-security.md, ../E3-rulings.md
seen: architect FAIL (E3A-1 … 7 blocking), security PASS-WITH-NOTES
decision: E3A-1 … 7 corrected in this graph and the E1 records; E3A-8 … 18 and E3S-1 … 7 are E4 addenda in ../E3-rulings.md; the version-agnostic goldens (US-TST-5) join as group G5
