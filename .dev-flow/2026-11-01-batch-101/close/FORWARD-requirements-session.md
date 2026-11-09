# FORWARD — batch-101 canon changes, for the requirements session

Worktree records only; do not commit. Every id below exists verbatim in the cited
record. Kind: **new** = a new canon row · **changed** = a canon row whose wording is
replaced in batch-101 · **withdrawn** = a canon row that leaves the canon · **brought in**
= an existing canon row brought into scope with its text unchanged.

For **changed** rows the Note column gives the canon text before (from
`docs/requirements/review/S<n>-ears-strict.md`) where that file holds it.

---

## S0 — process rows and documents

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-DOC-CANON.1 | new | The system shall keep its requirements in one file, `REQUIREMENTS.md`, at the root of its repository. | Inc 1 | inc-1/01-requirements.md | canon swap (US-101.1) |
| R-DOC-CANON.2 | new | The system shall give each requirement in `REQUIREMENTS.md` one table row with an id, a form and a sentence. | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.3 | new | The system shall write each requirement sentence in `REQUIREMENTS.md` in the form its row names, with the opening words of that form (CTX-CANON). | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.4 | new | The system shall write each requirement sentence in `REQUIREMENTS.md` with the obligation word of CTX-CANON exactly once. | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.5 | new | The system shall give each requirement row in `REQUIREMENTS.md` an id that no other row in the file uses. | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.6 | new | The system shall group the requirement rows of `REQUIREMENTS.md` under the modules S0 … S17, in that order. | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.7 | new | The system shall keep the requirements file that `REQUIREMENTS.md` replaced, byte for byte as committed at e273181, in `docs/requirements/history/`. | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.8 | new | The system shall cite in the absorbing cell of each line of S0's table (S0.2) only ids of rows that exist in `REQUIREMENTS.md`. | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.9 | new | The system shall keep, for each module, the decisions behind its rows in `docs/requirements/review/`. | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.10 | new | The system shall name in `docs/requirements/review/` only tests that are defined under `tests/`. | Inc 1 | inc-1/01-requirements.md | |
| R-DOC-CANON.11 | new | The system shall write each requirement sentence in `REQUIREMENTS.md` as one sentence. | Inc 1 | inc-1/01-requirements.md | |
| R-TST-001 | new | The test suite shall register the pytest marker `serial_timing` with the description `a wall-clock timing arm; run apart and serially (-m serial_timing)`. | Inc 2 | inc-2/01-requirements.md | process row (Inc 2's family) |
| R-TST-002 | new | The test suite shall carry the `serial_timing` marker on every timing arm. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-003 | new | If a timing arm does not carry the `serial_timing` marker, then the test suite shall fail its marker guard with the text `timing arm without serial_timing: <file>::<test>`. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-004 | new | If a test that is not a timing arm carries the `serial_timing` marker, then the test suite shall fail its marker guard with the text `serial_timing on a test that is not a timing arm: <file>::<test>`. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-005 | new | The test suite shall treat as a timing arm each test that matches a static form of *Timing arm* (Definitions). | Inc 2 | inc-2/01-requirements.md | |
| R-TST-006 | new | The test suite shall not treat as a timing arm a test whose clock interval no ordering assert reads. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-007 | new | The test conventions shall give the release gate as the parallel lane `pytest -n 8 -m "not serial_timing"` followed by the serial lane `pytest -m serial_timing`, both on the LAN Linux host. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-008 | new | When the release gate runs on the LAN Linux host at Inc 2's merge tree, the test suite shall report 0 failed timing arms over the two lanes. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-009 | new | When the release gate runs on the LAN Linux host, the test suite shall finish both lanes within 75 min of wall time in total. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-010 | new | When a pull request runs the CI workflow, the CI workflow shall run `pytest -v -rs -n auto -m "not slow and not serial_timing"` and then `pytest -q -rs -m "serial_timing and not slow"`. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-011 | new | When a push runs the CI workflow, the CI workflow shall run `pytest -v -rs -n auto -m "not serial_timing"` and then `pytest -q -rs -m serial_timing`. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-012 | new | If the first lane of a CI run fails, then the CI workflow shall still run the serial lane and mark the job failed. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-013 | new | The CI workflow shall check out the repository with its full history in the `tui-ci` job. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-014 | new | When the CI workflow runs, the test suite shall run the 6 history arms without skipping them. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-015 | new | The CI workflow shall stop lane 1 at its time limit: 180 minutes on a push, 120 minutes on a pull request. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-016 | new | The CI workflow shall stop the `tui-ci` job after 240 minutes. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-017 | new | If lane 1 of a push run reaches its time limit, then the CI workflow shall still run lane 2. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-018 | new | The CI workflow shall install pytest-xdist 3.8.0 in the `tui-ci` job. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-020 | new | Each shared wait helper shall bound its wait by the wall clock, 60 s by default. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-021 | new | Each shared wait helper shall yield the event loop for at least 0.05 s between two checks of its predicate. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-022 | new | The `settled` shared wait shall let the app process one pause before its first check of the predicate. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-023 | new | Each shared wait helper shall accept every call it accepted at `b3bf42e`, with the same parameter names, order and defaults for the positional parameters. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-024 | new | If a shared wait's condition does not hold within its bound, then the shared wait helper shall raise `AssertionError` with its text from table W. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-025 | new | When the shared project-load helper measures a project load, the test suite shall stop the clock when the app's project install callback returns. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-030 | new | The test conventions shall state the post-press rule: `An arm that checks the state a key press leaves while a real worker runs holds the worker at a forced slow step or records the state at the product hook; it never samples after the press.` | Inc 2 | inc-2/01-requirements.md | |
| R-TST-031 | new | The test suite shall verify the quit-confirm half of AT-B100-18 with the save worker held at a forced slow step, and the parse half of AT-B100-17 from the states recorded at the progress hook. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-032 | new | The test suite shall verify that a new set run restarts the confirm dwell with an injected dwell clock, independent of host speed. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-040 | new | The test suite shall pass each upper timing bound of a timing arm through the margin reporter, which returns the bound unchanged. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-041 | new | If an upper timing bound of a timing arm is not a margin-reporter call, then the test suite shall fail its margin guard with the text `timing bound without report_margin: <file>:<line>`. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-042 | new | When a timing arm reports a margin, the test suite shall attach the margin report to that test's item as the property `qc_tm`, so that its call report, its teardown report and the junit XML carry it. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-043 | new | When a test session that recorded at least one margin report ends, the test suite shall print a section titled `QC-TM timing margins` with one row per margin report of a call-phase test report, `<margin>%  <measured> s / <bound> s  <label>  <nodeid>`, in ascending margin order. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-044 | new | If a reported margin is below 20 %, then the test suite shall begin that row of the QC-TM section with `LOW `. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-045 | new | When the test suite prints the QC-TM section, the test suite shall end it with the line `QC-TM: <n> bounds, <k> under 20 % margin`. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-046 | new | If a timing arm's measured interval exceeds its bound, then the test suite shall record its margin report, with a negative margin, before the arm's assertion fails. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-047 | new | The test conventions shall state the clock rule: `A timing arm stops its clock at a stamp the product emits (a commit handler, a painted line, an install callback), never when a poll notices.` | Inc 2 | inc-2/01-requirements.md | |
| R-TST-048 | new | The test conventions shall state the margin rule: `A margin under 20 % in the serial lane's QC-TM section is a gate finding; the finding gives the base tree's time beside it.` | Inc 2 | inc-2/01-requirements.md | |
| R-TST-049 | new | If a function that a change wraps as a timing arm (a `serial_timing` marker or a `report_margin` call added against the merge-base with main) differs from its base version by anything other than that marker and the `report_margin(label, measured, bound)` wraps, then the test suite shall fail its wrap guard with the text `wrapped timing arm changed beyond marker and report_margin: <file>::<function>`. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-050 | new | The test suite shall give status oracles every status line the app paints after a mark, in paint order and without a cap. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-051 | new | If a test file holds more newest-line waits than its newest-line baseline (0 for a file absent from it), then the test suite shall fail its oracle guard with the text `newest-line wait added in <file>: <count> > baseline <n>; collect the painted lines with StatusLog.since(mark)`. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-052 | new | The test conventions shall state the oracle rule: `A test that waits on a painted outcome collects the lines painted since its trigger (StatusLog.since(mark)) and asserts the one it needs; it never waits on the newest line alone.` | Inc 2 | inc-2/01-requirements.md | |
| R-TST-060 | new | The test conventions shall state the census rule: `When an increment changes the order or the source of an observable, its gate greps tests/ for every node that asserts that observable and runs them, whatever module they sit in.` | Inc 2 | inc-2/01-requirements.md | |
| R-TST-070 | new | When CI run 41372953464 on `f72eef1` completes, the batch's CI record shall list each FAILED node of that run's `tui-ci` job, marked `known` when it is one of the known failures and otherwise `new` with the increment it is routed to. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-071 | new | If CI run 41372953464 ends cancelled or timed out, then the batch's CI record shall state the conclusion and the last step reached, and owe the confirmation to the first push run after Inc 2's merge. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-072 | new | When CI run 41372953464 has a concluded `snapshot` job, the batch's CI record shall state that job's conclusion and the result of each of the 29 density cells of LLR-173.2m. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-080 | new | The test suite shall hold the tool-version token, and no tool version, wherever a report golden records the tool version. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-081 | new | When a report golden test compares a report with its golden, the test suite shall put the package's version, as `s19_app.version` gives it at run time, in place of the tool-version token. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-082 | new | If a report prints a tool version other than the package's version, then the report golden test shall fail. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-090 | new | When Inc 2's own pull-request CI run completes, the batch's CI record shall give the wall time of each lane and of the job beside the serial baseline of run 41372953464 (`tui-ci` 4 h 53 min, 17 595 s). | Inc 2 | inc-2/01-requirements.md | |
| R-TST-091 | new | When the first push CI run after Inc 2's merge completes, the CI workflow shall have run lane 1 and lane 2 of the `tui-ci` job within 150 minutes in total. | Inc 2 | inc-2/01-requirements.md | |
| R-TST-110 | new | When a panel arm measures the paint of the Load-result panel, the test suite shall start the clock at the install stamp. | Inc 3 | inc-3/01-requirements.md | process row |
| R-TST-111 | new | When a panel arm measures the paint of the Load-result panel, the test suite shall stop the clock at the panel paint stamp. | Inc 3 | inc-3/01-requirements.md | |
| R-TST-112 | new | When an append arm measures the variant append, the test suite shall stop the clock at the outcome-line stamp. | Inc 3 | inc-3/01-requirements.md | |
| R-TST-113 | new | The test suite shall hold 1 second as the bound of every panel-paint and variant-append interval of the panel arms and the append arms. | Inc 3 | inc-3/01-requirements.md | |
| R-TST-150 | new | When the TC-331 arm requests the load of a change file, the test suite shall read the state of Edit JSON only after the change document's source path names that file. | Inc 15 | inc-15/01-requirements.md | verifies R-TUI-053.5 |
| R-TST-151 | new | When the TC-331 arm presses Parse pasted, the test suite shall read the state of Edit JSON only after the change document has no source path. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-152 | new | When the TC-B94-27 arm presses Bind with the ref lane A already reads, the test suite shall read lane A's bindings only after the panel has handled that press. | Inc 15 | inc-15/01-requirements.md | verifies R-FX-LANE.7/.8/.10 |
| R-TST-153 | new | When the TC-B94-27 arm presses Bind with `variant_b.hex` on lane A, the test suite shall read both lanes' bindings, lane B's box and lane B's painted cards only after the panel has handled that press. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-154 | new | If the app has not handled the press within the shared wait's bound, then the test suite shall fail the arm with the text `did not settle: <description>`, the description from table D. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-155 | new | The test suite shall make each wait of R-TST-150 … R-TST-153, R-TST-159 … R-TST-162 and R-TST-164 (D9) through the shared wait. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-156 | new | When the TC-331, TC-B94-27, AT-030c and TC-051 save-back nodes run 20 times serially on the Windows host at the Inc 15 tree, the test suite shall report 0 failures. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-157 | new | When the TC-331, TC-B94-27, AT-030c and TC-051 save-back nodes run on the LAN Linux host at the Inc 15 tree, the test suite shall report 0 failures in 3 serial runs and in the release gate's parallel lane. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-158 | new | The test conventions shall state the handled-press rule: `A new or changed arm that checks the state a press, a value it sets or a posted action leaves waits through a shared wait for a sign that the app handled it, also when it asserts that nothing changed; it never reads after fixed pauses alone.` | Inc 15 | inc-15/01-requirements.md | |
| R-TST-159 | new | When the AT-030c arm sets the change-file dropdown to `dropped.json`, the test suite shall read the change document's entries only after the change document's source path names `dropped.json`. | Inc 15 | inc-15/01-requirements.md | verifies R-PATCH-DOC-DROPDOWN-001.1/.3 |
| R-TST-160 | new | When the TC-051 arm requests an apply, the test suite shall act on the save-back prompt only after the prompt is shown. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-161 | new | When the TC-051 arm presses Don't save, the test suite shall read the prompt, the saved path and the work area only after the save-back prompt is hidden again. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-162 | new | When the TC-051 arm presses Write file with a typed name, the test suite shall read the saved path and the work-area files only after the save-back prompt is hidden again. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-163 | new | The test suite shall place each wait of R-TST-150 … R-TST-153, R-TST-159 … R-TST-162 and R-TST-164 (D9) as the statement that directly follows its table-D trigger. | Inc 15 | inc-15/01-requirements.md | |
| R-TST-164 | new | When the TC-B94-27 arm imports the template `base` a second time, the test suite shall read lane B's bindings and lane B's box only after the panel's lane names read `["base", "base_2"]` and lane B's box `#fx_in_1_0` is mounted with a non-empty screen region. | Inc 15 | inc-15/01-requirements.md | |
| R-DOC-SECURITY.1 | new | The system shall include a `SECURITY.md` that gives a private path to report a vulnerability. | Inc 14 | inc-14/01-requirements.md | proposed S0.4 |
| R-DOC-SECURITY.2 | new | The system shall state in its `SECURITY.md` which versions receive security fixes. | Inc 14 | inc-14/01-requirements.md | proposed S0.4 |
| R-DOC-RELNOTE.1 | new | The system shall state in the release notes of 1.0.0 that a CRC config with `reverse` true starts the CRC register at `init` as written. | Inc 14 | inc-14/01-requirements.md | proposed S0.5 |
| R-DOC-RELNOTE.2 | new | The system shall state in the release notes of 1.0.0 how to keep the CRC value that an earlier version gave for a config with `reverse` true. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.3 | new | The system shall state in the release notes of 1.0.0 that the before/after report is titled `Before/after report` and names the loaded A2L and MAC. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.4 | new | The system shall state in the release notes of 1.0.0 that a later flow block reads this run's copy of an external step's output. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.5 | new | The system shall state in the release notes of 1.0.0 that the Markdown file of a diff report writes a backslash before each Markdown character of a name. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.6 | new | The system shall state in the release notes of 1.0.0 that a diff report file holds every hex window whole. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.7 | new | The system shall state in the release notes of 1.0.0 that a load into a project whose folder was deleted outside the app no longer re-creates that folder. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.8 | new | The system shall state in the release notes of 1.0.0 that a confirmed external step whose relative log or output path climbs above the project folder stops the flow. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.9 | new | The system shall state in the release notes of 1.0.0 that a confirmed external step reads a relative output path under the project folder. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.10 | new | The system shall state in the release notes of 1.0.0 that the flow and chain-set reports name the external step's copy that a PATCH block read in place of its ref. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.11 | new | The system shall state in the release notes of 1.0.0 the reasons a CRC config is refused with. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.12 | new | The system shall state in the release notes of 1.0.0 that a failed write of a diff or before/after report leaves no partial report file and no Markdown file without its HTML file. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.13 | new | The system shall state in the release notes of 1.0.0 that a diff or before/after report writes a control or direction-override character of a name as a visible replacement character. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-RELNOTE.14 | new | The system shall state in the release notes of 1.0.0 that an interrupted write of a diff or before/after report can leave a `.part` file that is safe to delete. | Inc 14 | inc-14/01-requirements.md | |
| R-DOC-GUIDE.1 | new | The system shall describe in its user guide no behaviour that the system does not provide. | Inc 14 | inc-14/01-requirements.md | proposed S0.6; Inc 12 adds passages /13, /14 |
| R-DOC-GUIDE.2 | new | The system shall mark each row of the user guide's findings table that 1.0.0 fixes with `fixed in 1.0.0`. | Inc 14 | inc-14/01-requirements.md | Inc 12 extends the pinned set by named supersession (F-33, F-34, F-35, F-51) |
| R-DOC-REF.1 | new | The system shall name in its repository documents only repository paths that exist, except on a line that carries a removal mark. | Inc 16 | inc-16/01-requirements.md | CTX-DOCHYG (S0) |
| R-DOC-REF.2 | new | The system shall link in its Markdown repository documents only to files and folders that exist. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-REF.3 | new | The system shall name a retired-folder path in no tracked text file, except on an exempt line. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-REF.4 | new | The system shall name the retired fast-dev-flow workflow in a tracked text file only on a line that carries a removal mark, except on an exempt line. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-REF.5 | new | The system shall present `s19tool` in its repository documents only in an s19tool shape. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-REF.6 | new | The system shall name CDFX in its repository documents only on a line that carries a removal mark. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.1 | new | The system shall list in `CLAUDE.md` exactly the console scripts that `pyproject.toml` declares. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.2 | new | The system shall show each command-line example of the CLI in `CLAUDE.md` in the form `python -m s19_app.cli <command> <file>`. | Inc 16 | inc-16/01-requirements.md | form corrected at E4 integration (I-1) |
| R-DOC-DEV.3 | new | The system shall state in `CLAUDE.md` the branches and the two test lanes that `.github/workflows/tui-ci.yml` runs. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.4 | new | The system shall name the hex renderer `s19_app/render/hexview.py` in `CLAUDE.md`, `PROJECT_RULES.md` and `docs/engineering-rules.md`. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.5 | new | The system shall state no size in lines of a source module in `CLAUDE.md`. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.6 | new | The system shall cite source code in `CLAUDE.md` without a line number. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.7 | new | The system shall cite in `docs/engineering-rules.md` no personal memory file as a source. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.8 | new | The system shall restate the runtime dependencies and the test markers that `pyproject.toml` declares where its developer documents state them. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.9 | new | The system shall link in `docs/README.md` each entry of CTX-DOCINDEX. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.10 | new | The system shall state in `docs/README.md` no branch, commit, test tally or batch list as the project's state. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.11 | new | The system shall name in `docs/overview.md` each window of CTX-README by its rail label. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.12 | new | The system shall state the number of rail windows as twelve in `docs/overview.md` and `docs/architecture.md`. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.13 | new | The system shall state no count of tests in `docs/overview.md` and `docs/architecture.md`. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.14 | new | The system shall state in `docs/overview.md` that the Operations modal lists `extract` and `split_by_segment` without running them. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-DEV.15 | new | The system shall list in `examples/case_00_public/MANIFEST.md` each example case folder of `examples/`. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCH.1 | new | The system shall declare in the module table of `docs/architecture.md` a module prefix for each Python folder. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCH.2 | new | The system shall declare in the module table of `docs/architecture.md` no module prefix that matches no tracked file. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCH.3 | new | The system shall hold in `docs/architecture.md` no amendment note and no per-batch declaration of batches 88 … 100. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCH.4 | new | The system shall declare in §10 of `docs/architecture.md` each sub-module of CTX-SUBMOD with exactly the facts of CTX-SUBMOD. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCH.5 | new | The system shall list the contracts of CTX-IFACE in one Interfaces table in §11 of `docs/architecture.md`. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCH.6 | new | The system shall state in `docs/architecture.md` that an increment changes at most 4 source files. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCHIVE.1 | new | The system shall hold each finished note of CTX-ARCHIVE only at its archive path. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCHIVE.2 | new | The system shall keep, in the architecture archive of CTX-ARCHIVE, each line that this increment removes from §10 and §11 of `docs/architecture.md` and from its amendment notes. | Inc 16 | inc-16/01-requirements.md | |
| R-DOC-ARCHIVE.3 | new | The system shall hold none of the files of CTX-REMOVED. | Inc 16 | inc-16/01-requirements.md | CODE-CHANGES D13-17 |
| R-DOC-ARCHIVE.4 | new | The system shall hold no local identity in the files of the archive folder. | Inc 16 | inc-16/01-requirements.md | |

S0 count: **128 rows** (128 new, 0 changed, 0 withdrawn, 0 brought in).

---

## S1

No new, changed, withdrawn or brought-in rows in batch-101.

S1 count: **0 rows**.

---

## S2 — A2L

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-A2L-048 | new | When the system writes bytes into the loaded image in place, the system shall show in the tag table each tag's raw and physical values read from the written bytes. | Inc 10b | inc-10b/01-requirements.md | moved from Inc 10, id unchanged |
| R-A2L-049 | new | When the system writes bytes into the loaded image in place, the system shall keep the tag table's first shown row. | Inc 10b | inc-10b/01-requirements.md | moved from Inc 10; threshold amended by E3 A10-04 |
| R-A2L-105 | new | When the system writes bytes into the loaded image in place, the system shall keep the tag table's highlighted row. | Inc 10b | inc-10b/01-requirements.md | |
| R-A2L-106 | new | When the system writes bytes into the loaded image in place, the system shall keep the tags the tag table lists. | Inc 10b | inc-10b/01-requirements.md | |
| R-A2L-036.7 | new | If a MEMORY_SEGMENT block has no record words, then the system shall give the segment no name. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-036.8 | new | When the system reads a MEMORY_SEGMENT block that has a base, the system shall take as the segment's program type the last program-type word before its base. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-036.9 | new | When the system reads a MEMORY_SEGMENT block that has a base, the system shall take as the segment's memory type the last memory-type word before its base. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-036.10 | new | If no record word before a segment's base is a program-type word, then the system shall give the segment no program type. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-036.11 | new | If no record word before a segment's base is a memory-type word, then the system shall give the segment no memory type. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-036.12 | new | If a MEMORY_SEGMENT block has no base, then the system shall give the segment no program type and no memory type. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-036.13 | new | If the sum of a MEMORY_SEGMENT block's address word and the record word after it, both Numbers, exceeds 2^32 (0x100000000), then the system shall give the segment no base and no size. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-120 | new | If a point of a CURVE's point table has no axis value, then the system shall show the point's index, counted from 0, as its x. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-121 | new | If a CURVE's point table holds at least one point and no point has an axis value, then the system shall show the line `x: point index (axis points unavailable)` once, directly above the table header. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-122 | new | If a CURVE's point table holds at least one point and no point has an axis value, then the system shall show each point-table row without a note. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-123 | new | If some, but not all, points of a CURVE's point table have an axis value, then the system shall end each point-table row whose point has no axis value with `   (index (axis points unavailable))`. | Inc 11 | inc-11/01-requirements.md | |
| R-A2L-036.1 | changed | When the system reads a MEMORY_SEGMENT block, the system shall take its first record word as the segment's name. | Inc 11 | inc-11/01-requirements.md | was: "…the first word after `/begin MEMORY_SEGMENT` as the segment's name." |
| R-A2L-036.2 | changed | When the system reads a MEMORY_SEGMENT block whose address word is a Number of at least 0, whose record word after the address word is a Number above 0, and whose two Numbers sum to at most 2^32 (0x100000000), the system shall take the address word's value as the segment's base. | Inc 11 | inc-11/01-requirements.md | was: "…take as its record line the first line that splits into at least five words, a quoted text counting as one word." |
| R-A2L-036.3 | changed | When the system reads a MEMORY_SEGMENT block that has a base, the system shall take as the segment's size the value of the record word after its address word. | Inc 11 | inc-11/01-requirements.md | was: "…take its fourth word as the segment's base and its fifth word as the segment's size." |
| R-A2L-036.4 | changed | If a MEMORY_SEGMENT block has no address word, or its address word is not a Number of at least 0, or the record word after its address word is not a Number above 0, or the two Numbers sum to more than 2^32 (0x100000000, R-A2L-036.13), then the system shall give the segment no base and no size. | Inc 11 | inc-11/01-requirements.md | was: "If the base word of a MEMORY_SEGMENT record line is not a number, then the system shall give the segment no base and no size." |
| R-A2L-036.6 | changed | When the record word after a segment's size is a Number, the system shall take it as the segment's offset. | Inc 11 | inc-11/01-requirements.md | was: "When a MEMORY_SEGMENT record line has a sixth word that is a number, the system shall take it as the segment's offset." |
| R-A2L-036.5 | withdrawn | — | Inc 11 | inc-11/01-requirements.md | split absorbed by R-A2L-036.2/.4 (E1-rulings C-2). Canon was: "If the size word of a MEMORY_SEGMENT record line is not a number, then the system shall give the segment no size." |

S2 count: **21 rows** (15 new, 5 changed, 1 withdrawn, 0 brought in).

---

## S3 — validation, Issues screen, legend

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-VAL-032.2 | new | The system shall raise no `A2L_UNRECOGNIZED_BLOCK` issue for an A2L section whose name is an ASAM block name. | Inc 11 | inc-11/01-requirements.md | |
| R-VAL-032.3 | new | The system shall raise no `A2L_UNRECOGNIZED_BLOCK` issue for an A2L section inside an IF_DATA block. | Inc 11 | inc-11/01-requirements.md | |
| R-TUI-042b.5 | new | The system shall order the filtered list by severity rank, keeping the order of the issue list among issues of the same severity. | Inc 11 | inc-11/01-requirements.md | [OR-2] — depends on an orchestrator ruling; if declined, withdrawn and its cases dropped |
| R-TUI-042b.6 | new | The system shall show no text between a group header and the group's first issue row. | Inc 11 | inc-11/01-requirements.md | |
| R-VAL-032.1 | changed | If an A2L section's name is not an ASAM block name and the section is not inside an IF_DATA block, then the system shall raise the WARNING issue `A2L_UNRECOGNIZED_BLOCK` with the section's line number and the message `Unrecognized A2L block '<NAME>'.` | Inc 11 | inc-11/01-requirements.md | was: "If an A2L section's name is not a block name of ASAM MCD-2 MC, then the system shall raise the WARNING issue `A2L_UNRECOGNIZED_BLOCK` with the section's line number and the message `Unrecognized A2L block '<NAME>'.`" |
| R-VAL-032 | withdrawn | — | Inc 11 | inc-11/01-requirements.md | split into R-VAL-032.1, .2, .3 (E1-rulings C-1) |

S3 count: **6 rows** (4 new, 1 changed, 1 withdrawn, 0 brought in).

---

## S4 — hex view & Memory Map

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-TUI-018.4 | new | When the main, A2L or MAC hex view jumps to a target row that is its first view row, the system shall show the target row as the first row of the view. | Inc 10a | inc-10/01-requirements.md | |
| R-TUI-004.7 | new | When the system writes bytes into the loaded image in place, the system shall show the written bytes in the main, A2L and MAC hex views. | Inc 10b | inc-10b/01-requirements.md | |
| R-TUI-004.8 | new | When the system shows the written bytes of R-TUI-004.7, the system shall keep each hex view's shown window. | Inc 10b | inc-10b/01-requirements.md | threshold changed at E5 QA-4 |
| R-TUI-004.9 | new | When the system shows the written bytes of R-TUI-004.7, the system shall keep each hex view's `> ` marker. | Inc 10b | inc-10b/01-requirements.md | |
| R-TUI-018.1 | changed | When the main, A2L or MAC hex view jumps to a target row other than its first view row, the system shall show the target row as the second row of the view. | Inc 10a | inc-10/01-requirements.md | was: "When a hex view jumps to a target, the system shall show the target row second from the top." |
| R-TUI-018.2 | changed | When the main, A2L or MAC hex view jumps to a target, the system shall scroll the view to its first line and its left edge. | Inc 10a | inc-10/01-requirements.md | was: "When a hex view jumps to a target, the system shall scroll the view back to its left edge." |
| R-TUI-040.4 | changed | If the address is in the image, then the system shall show its target row as R-TUI-018.1 and R-TUI-018.4 place it. | Inc 10a | inc-10/01-requirements.md | was: "If the address is in the image, then the system shall show its target row second from the top of the hex view." |
| R-TUI-062.10.1 | changed | The system shall name in the Memory Map's key line only keys that the Memory Map handles. | Inc 14 | inc-14/01-requirements.md | split of R-TUI-062.10 (E7); .10.2 inspector subtitle and .10.3 row glyphs are recorded in E1-rulings.md §2 |
| R-TUI-062.10 | withdrawn | — | Inc 14 | inc-14/01-requirements.md | split into .10.1, .10.2, .10.3. Canon was: "The system shall name in the Memory Map's key line, inspector subtitle and row glyphs only keys that the Memory Map handles." |
| R-TUI-007.9 | brought in | When the operator loads a file, the system shall show the first hex page. | Inc 10a | inc-10/01-requirements.md | canon row used, text unchanged (E4-R1) |

S4 count: **10 rows** (4 new, 4 changed, 1 withdrawn, 1 brought in).

---

## S5 — workspace & loaded files

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-WS-LOADED.18 | new | When the system unloads files, the system shall show its unload status of R-WS-LOADED.13 as the file status. | Inc 10a | inc-10/01-requirements.md | |
| R-WS-LOADED.19 | new | While no S19 or HEX image is loaded, the system shall write no S19 or HEX file at the top level of a project the operator saves. | Inc 10a | inc-10/01-requirements.md | changed at E5 RR-1/RR-2 (widened to "no S19 or HEX image is loaded", narrowed to top-level files); withdraws ruling D-5 |
| R-WS-LOADED.20 | new | While a MAC file is loaded, no S19 or HEX image is loaded and no project is open, the system shall title the load question `Replace <MAC file name>?`. | Inc 10a | inc-10/01-requirements.md | |

S5 count: **3 rows** (3 new, 0 changed, 0 withdrawn, 0 brought in). Canon rows used text-unchanged (not forwarded): R-WS-LOADED.13, .14, .16, R-TUI-012L.8 — note R-WS-LOADED.16's threshold drops "the Issues Report" (QA-7).

---

## S6 — shell, focus, keys, status

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-SHELL-STATUS.7 | new | The system shall show the file status without characters of the Unicode categories Cc, Cf, Zl and Zp. | Inc 10a | inc-10/01-requirements.md | |
| R-SHELL-KEYS.3 | new | The system shall give every action at least one reach. | Inc 12 | inc-12/01-requirements.md | |
| R-SHELL-FOCUS.3 | changed | When a load completes, a load is cancelled or an unload ends while the focus behind any dialog is on a widget that is hidden, has no size, sits in a hidden window or is removed, the system shall put the focus on the shown window's focus target. | Inc 10a | inc-10/01-requirements.md | was: "When a load completes or is cancelled while the focus behind any dialog is on a widget that is hidden, has no size, or sits in a hidden window, the system shall put the focus on the shown window's focus target." |
| R-SHELL-FOCUS.4 | changed | When a load completes, a load is cancelled or an unload ends while the focus is on a shown widget of the shown window or on a frame widget the operator chose, the system shall keep the focus there. | Inc 10a | inc-10/01-requirements.md | was: "When a load completes or is cancelled while the focus is on a shown widget of the shown window or on a frame widget, the system shall keep the focus there." |

S6 count: **4 rows** (2 new, 2 changed, 0 withdrawn, 0 brought in).

---

## S7 — help & dialogs

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-WHELP.18 | new | The system shall state in the Reports help section that Generate new report writes one Markdown file, `<time>-report.md`, into the project's `reports\` folder. | Inc 14 | inc-14/01-requirements.md | |
| R-WHELP.19 | new | The system shall state in the Reports help section that the Declared regions box starts with the regions saved with the open project and keeps the lines of the last Generate. | Inc 14 | inc-14/01-requirements.md | |
| R-WHELP.20 | new | The system shall state in the A2L Explorer help section that `/` puts the cursor in the search box of the A2L Explorer's hex pane. | Inc 14 | inc-14/01-requirements.md | |
| R-WHELP.21 | new | The system shall state in the Split / Join / Export help section that the window exports parts of the loaded image. | Inc 14 | inc-14/01-requirements.md | |
| R-WHELP.22 | new | The system shall state in the Split / Join / Export help section that split writes `‹stem›_‹segment›.‹ext›` per range and join writes one `‹stem›_joined.‹ext›`. | Inc 14 | inc-14/01-requirements.md | |
| R-WHELP.23 | new | The system shall state in the Checks help section that the list groups the entries by outcome: failed, then uncheckable, then passed. | Inc 14 | inc-14/01-requirements.md | |
| R-WHELP.24 | new | The system shall state in the CRC Designer help section that coverage computes its CRCs over the ranges typed in Ranges. | Inc 14 | inc-14/01-requirements.md | |
| R-WHELP.25 | new | The system shall state in the Flow Builder help section that the CRC template field names the CRC config file a CRC block reads. | Inc 14 | inc-14/01-requirements.md | |
| R-WHELP.26 | new | The system shall state in the Flow Builder help section that a CRC block refuses a template the CRC Designer saves. | Inc 14 | inc-14/01-requirements.md | |
| R-DLG.14 | new | The system shall give every dialog at least one opener. | Inc 12 | inc-12/01-requirements.md | |
| R-DLG.15 | new | When the operator presses Escape while a dropdown list of a dialog is open, the system shall close only that dropdown list. | Inc 12 | inc-12/01-requirements.md | |
| R-DLG.2 | changed | When the operator presses Escape in a dialog while none of its dropdown lists is open, the system shall do what the dialog's Cancel or Close button does. | Inc 12 | inc-12/01-requirements.md | was: "When the operator presses Escape in a dialog, the system shall do what the dialog's Cancel or Close button does." Recorded `Partly` after Inc 12 (E3A-06) |

S7 count: **12 rows** (11 new, 1 changed, 0 withdrawn, 0 brought in).

---

## S8 — change documents & symbols

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-CHG-SYM.11 | new | When the system reads a document to run it on a variant, the system shall use the project's A2L file as the declared A2L. | Inc 4 | inc-4/01-requirements.md | |
| R-CHG-SYM.12 | new | If the project has no A2L file when the system reads a document to run it on a variant, then the system shall read the document with no declared A2L. | Inc 4 | inc-4/01-requirements.md | |
| R-CHG-SYM.13 | new | When the system reads a document of at most 1 000 symbol entries against a declared A2L of at most 220 040 tags, the system shall finish the read within 1.0 seconds. | Inc 4 | inc-4/01-requirements.md | |
| R-CHG-SYM.9 | changed | When the system makes a session read while an A2L is loaded, the system shall use that A2L as the declared A2L. | Inc 4 | inc-4/01-requirements.md | was: "When the operator loads or pastes a change document while an A2L is loaded, the system shall use that A2L as the declared A2L." |
| R-CHG-SYM.10 | changed | If no A2L is loaded when the system makes a session read, then the system shall read the document with no declared A2L. | Inc 4 | inc-4/01-requirements.md | was: "If no A2L is loaded when the operator loads or pastes a change document, then the system shall read the document with no declared A2L." |

S8 count: **5 rows** (3 new, 2 changed, 0 withdrawn, 0 brought in).

---

## S9 — Check Editor

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-CHKED-041.1 | new | When the operator picks a spec, the system shall replace the field set with one field per entry of the spec. | Inc 5 | inc-5/01-requirements.md | split of R-CHKED-041 |
| R-CHKED-041.2 | new | When the operator picks a spec, the system shall include the named parameter of each entry that has one, in entry order. | Inc 5 | inc-5/01-requirements.md | |
| R-CHKED-041.3 | new | If an entry of a picked spec has no named parameter, then the system shall load it as a memory row with no label. | Inc 5 | inc-5/01-requirements.md | |
| R-CHKED-054 | new | When the system writes a spec, the system shall keep the field set unchanged. | Inc 5 | inc-5/01-requirements.md | |
| R-CHKED-055 | new | If the loaded A2L no longer lists a parameter included in this session when the operator returns to the Check Editor, then the system shall drop that parameter from the field set. | Inc 5 | inc-5/01-requirements.md | scoped at E3 |
| R-CHKED-056 | new | If the loaded A2L no longer lists a parameter loaded from a spec when the operator returns to the Check Editor, then the system shall replace that parameter in the field set with a memory row with no label that has the address, byte count and expected bytes of its spec entry. | Inc 5 | inc-5/01-requirements.md | |
| R-CHKED-057 | new | When the system makes an in-place write to the loaded image, the system shall clear the Check Editor's validation results. | Inc 5 | inc-5/01-requirements.md | added at E5 C-10 |
| R-CHKED-032 | changed | When a spec is written, the system shall show the status `Check Editor: wrote <listed name> (<n> fields, kind=check).`, where `<listed name>` is the written file's value in the Spec list: `checks/<name>` with a project open, `<name>` without one. | Inc 6 | inc-6/01-requirements.md | was: "When a spec is written, the system shall show the status `Check Editor: wrote <name> (<n> fields, kind=check).`" |
| R-CHKED-040 | changed | When the operator opens the Check Editor, writes a spec, or a project load or a Save project completes, the system shall fill the Spec dropdown with the spec list. | Inc 6 | inc-6/01-requirements.md | was: "When the operator opens the Check Editor or writes a spec, the system shall fill the Spec dropdown with the spec list." |
| R-CHKED-041 | withdrawn | — | Inc 5 | inc-5/01-requirements.md | split into R-CHKED-041.1, .2, .3. Canon was: "When the operator picks a spec, the system shall replace the included parameters and the memory rows with one memory row per entry of the spec." |

S9 count: **10 rows** (7 new, 2 changed, 1 withdrawn, 0 brought in). Canon rows with text unchanged but scope changed by amended definitions (not forwarded as text): R-CHKED-010, R-CHKED-025, R-CHKED-026, R-CHKED-027.

---

## S10 — Patch Editor

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-TUI-058.9 | new | If a per-entry Edit JSON confirm records the R-CHG-SYM.2 finding, then the system shall show the status `Patch Editor: the entry names an A2L symbol and no A2L is loaded - load the A2L, then edit the entry again.` | Inc 4 | inc-4/01-requirements.md | |
| R-TUI-049.3.1 | new | When the document is replaced by a load, a project load, a paste, undo or redo, or an image load completes, the system shall hide the before/after control. | Inc 6 | inc-6/01-requirements.md | split of R-TUI-049.3 |
| R-TUI-049.3.2 | new | When the document is replaced by a load, a project load, a paste, undo or redo, or an image load completes, the system shall hide the save-back prompt. | Inc 6 | inc-6/01-requirements.md | |
| R-PATCH-DOC-DROPDOWN-001.1 | changed | When the Patch Editor is opened, a Save or a Refresh ends, or a project load or a Save project completes, the system shall fill the File dropdown with the change list. | Inc 6 | inc-6/01-requirements.md | was: "When the Patch Editor is opened, or a Save or a Refresh ends, the system shall fill the File dropdown with the change list." |
| R-PATCH-DOC-DROPDOWN-001.2 | changed | If the change list is empty, then the system shall show the dropdown with its prompt `Change files in patches/` and no option. | Inc 6 | inc-6/01-requirements.md | was: "If the change home holds no change document, then the system shall show the dropdown with its prompt `Change files in patches/` and no option." |
| R-PATCH-DOC-DROPDOWN-001.4 | changed | If the picked file is a link, lies under a linked folder, or lies outside its folder, then the system shall refuse it with the status `Patch Editor: change file '<name>' is outside the patches folder — not loaded.` | Inc 6 | inc-6/01-requirements.md | was: "If the picked file is a link or lies outside its folder, then the system shall refuse it with the status `Patch Editor: change file '<name>' is outside the patches folder — not loaded.`" |
| R-TUI-049.3 | withdrawn | — | Inc 6 | inc-6/01-requirements.md | split into R-TUI-049.3.1, .3.2. Canon was: "When the document is replaced by a load, a paste, undo or redo, the system shall hide the before/after control and the save-back prompt." |

S10 count: **7 rows** (3 new, 3 changed, 1 withdrawn, 0 brought in).

---

## S11 — project & workspace

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-PROJ-001.13 | new | When the operator confirms Save project into the open project at the T2 composition, the system shall show the status `Project saved + manifest verified` within 1 second of the confirm. | Inc 3 | inc-3/01-requirements.md | |
| R-PROJ-GATHER.12 | new | When the system gathers composition documents, the system shall check each distinct composition document name against the project folder once. | Inc 3 | inc-3/01-requirements.md | |
| R-PROJ-GATHER.13 | new | If the project folder holds a link loop at a composition document's name, then the system shall look that name up in the common patches library by its last part. | Inc 3 | inc-3/01-requirements.md | |
| R-PROJ-002.14 | new | If the open project's folder no longer exists when the system adds an S19, Intel HEX, MAC or A2L file to it, then the system shall create no folder at that folder's path. | Inc 3 | inc-3/01-requirements.md | CODE-CHANGES D11-72 |

S11 count: **4 rows** (4 new, 0 changed, 0 withdrawn, 0 brought in). Canon rows verified text-unchanged (not forwarded): R-PROJ-002.12, R-PROJ-002.13, R-PROJ-ROLLBACK.9, R-PROJ-ROLLBACK.2.

---

## S12

No new, changed, withdrawn or brought-in rows in batch-101.

S12 count: **0 rows**.

---

## S13 — CRC designer, config, engine

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-CRC-ENGINE-002.2 | new | The system shall give in the CRC operation, for each polynomial, init, final XOR and reverse, the CRC that the CRC Designer gives for width 32, that polynomial, init and final XOR as xorout, and refin and refout equal to reverse. | Inc 8 | inc-8/01-requirements.md | |
| R-CRC-CONFIG-001.16 | new | If the config text is a JSON object of the Designer template shape, then the system shall give the reason `CRC config is structurally invalid: a CRC Designer template is not a CRC config - it has no regions or groups`. | Inc 8 | inc-8/01-requirements.md | |
| R-CRC-CONFIG-001.17 | new | If the config text nests too deep, then the system shall give the reason `CRC config is not valid JSON: nesting too deep`. | Inc 8 | inc-8/01-requirements.md | |
| R-CRC-DESIGNER-001.2.1 | new | When the operator changes a toggle or a dropdown of the CRC Designer, the system shall recompute every result surface of CTX-DESIGNER. | Inc 13 | inc-13/01-requirements.md | split of R-CRC-DESIGNER-001.2 |
| R-CRC-DESIGNER-001.2.2 | new | When the quiet time has passed since the last pending change, the system shall recompute every result surface of CTX-DESIGNER. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-DESIGNER-007.1 | new | When the operator makes an edit burst, the system shall recompute every result surface once. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-DESIGNER-007.2 | new | When the operator loads a template, the system shall recompute every result surface once. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-DESIGNER-007.3 | new | When the operator picks a preset, the system shall recompute every result surface once. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-PREVIEW-002.1 | new | When the loaded image changes while the CRC Designer is displayed, the system shall recompute every result surface of CTX-DESIGNER. | Inc 13 | inc-13/01-requirements.md | Inc 5 amends the definition (in-place writes) |
| R-CRC-PREVIEW-002.2 | new | When the operator changes Join gaps from concat to fill in the F-23 CRC scene, the system shall show the recomputed coverage window within 3 seconds. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-PREVIEW-002.3 | new | When the operator loads the F-23 template in the F-23 CRC scene, the system shall show the recomputed coverage window within 3 seconds. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-PREVIEW-002.4 | new | When the quiet time has passed since the operator's last edit of Ranges in the F-23 CRC scene, the system shall show the recomputed coverage window within 3 seconds. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-PREVIEW-002.5 | new | When the CRC Designer becomes displayed while its coverage is stale, the system shall recompute every result surface of CTX-DESIGNER. | Inc 13 | inc-13/01-requirements.md | Inc 5 amends the definition (in-place writes) |
| R-CRC-PREVIEW-001.11 | new | If the coverage size exceeds the coverage cap, then the system shall show `Cannot preview: coverage exceeds 16777216 bytes` in the coverage preview and the coverage window. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-PREVIEW-001.12 | new | If the Ranges are not in ascending address order, then the system shall draw line 1 of the coverage window with at most 48 glyphs per range or gap. | Inc 13 | inc-13/01-requirements.md | |
| R-CRC-DESIGNER-001.2 | withdrawn | — | Inc 13 | inc-13/01-requirements.md | split into R-CRC-DESIGNER-001.2.1, .2.2. Canon was: "When the operator changes a field of the CRC Designer, the system shall recompute every result surface of CTX-DESIGNER." |

S13 count: **16 rows** (15 new, 0 changed, 1 withdrawn, 0 brought in). Canon rows verified text-unchanged (not forwarded): R-CRC-ENGINE-001.1, R-CRC-CONFIG-001.10, .11, R-CRC-DESIGNER-001.1, R-CRC-PREVIEW-001.1 … 001.8.

---

## S14 — reports

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-BEFORE-AFTER-REPORT-001.32 | new | The system shall write `# Before/after report` as the first line of the before/after report's Markdown file. | Inc 7 | inc-7/01-requirements.md | |
| R-BEFORE-AFTER-REPORT-001.33 | new | The system shall write `<title>Before/after report</title>` in the head of the before/after report's HTML file. | Inc 7 | inc-7/01-requirements.md | |
| R-BEFORE-AFTER-REPORT-001.34 | new | The system shall write `<h1>Before/after report</h1>` as the first heading of the before/after report's HTML file. | Inc 7 | inc-7/01-requirements.md | |
| R-BEFORE-AFTER-REPORT-001.35 | new | When the system writes the before/after report, the system shall compute both images' artifact lines against the loaded A2L and the loaded MAC. | Inc 7 | inc-7/01-requirements.md | |
| R-BEFORE-AFTER-REPORT-001.36 | new | If no project is open when a save-back succeeds, then the system shall show no before/after offer. | Inc 6 | inc-6/01-requirements.md | the "does not" half of .1 (rule E2) |
| R-CMP-004.9.1 | new | The system shall write each label field and each refusal message into the Markdown file of a diff report as report-safe text (S12 CTX-RPT-TEXT) with its field limit. | Inc 7 | inc-7/01-requirements.md | split of R-CMP-004.9 |
| R-CMP-004.9.2 | new | The system shall write each path field into the Markdown file of a diff report as path text (S12 CTX-RPT-TEXT). | Inc 7 | inc-7/01-requirements.md | |
| R-CMP-004.14 | new | The system shall write every row of each hex window, from the window's first address to its end, into each diff report file. | Inc 7 | inc-7/01-requirements.md | |
| R-CMP-004.15 | new | The system shall write each label field, path field and refusal message into the HTML file of a diff report as visible text, HTML-escaped. | Inc 7 | inc-7/01-requirements.md | |
| R-CMP-005.16 | new | If writing a diff report file fails, then the system shall leave no file under that file's name, and no temporary file, in the destination folder. | Inc 7 | inc-7/01-requirements.md | |
| R-CMP-005.17 | new | If writing the HTML file of a diff report fails or is refused after its Markdown file was written, then the system shall remove that Markdown file. | Inc 7 | inc-7/01-requirements.md | |
| R-BEFORE-AFTER-REPORT-001.21 | changed | The system shall write the provenance and linkage values in both files as visible text. | Inc 7 | inc-7/01-requirements.md | was: "The system shall remove control characters from the provenance and linkage values in both files." |
| R-DIFF-CHK.1 | changed | When the A2B Diff is shown, or a project load or a Save project completes, the system shall fill the check-spec list with the spec list. | Inc 6 | inc-6/01-requirements.md | was: "When the A2B Diff is shown, the system shall list in the check-spec list the `.json` files of the folder where the Check Editor saves check specs, by name, links left out." |
| R-DIFF-CHK.3 | changed | If the spec list is empty, then the system shall leave out the check row. | Inc 6 | inc-6/01-requirements.md | was: "If the check-spec folder holds no `.json` file, then the system shall leave out the check row." |
| R-DIFF-CHK.5 | changed | If the picked file is a link, lies under a linked folder, or lies outside its folder, then the system shall show the status `Check spec: '<name>' is outside the patches folder — not loaded.` | Inc 6 | inc-6/01-requirements.md | was: "If the picked file is a link or lies outside the check-spec folder, then the system shall show the status `Check spec: '<name>' is outside the patches folder — not loaded.`" |
| R-CMP-004.9 | withdrawn | — | Inc 7 | inc-7/01-requirements.md | split into R-CMP-004.9.1, .9.2. Canon was: "The system shall write image labels, paths and symbol names into the Markdown file as inert text." |
| R-BEFORE-AFTER-REPORT-001.11 | brought in | If no project is open, then the system shall refuse the report with the reason `No active project - the before/after report needs a project reports/ destination; use the manual A<->B Diff report (key 7) with an explicit destination instead.` | Inc 7 | inc-7/01-requirements.md | canon row brought into scope at E3 [F-E3-1] |

S14 count: **17 rows** (11 new, 4 changed, 1 withdrawn, 1 brought in).

---

## S15 — Flow Builder, CRC block, external steps

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-FLOW-CRC.9 | new | If the CRC config file is larger than the read limit of CTX-CRCCONFIG, then the system shall stop the flow with the summary `config malformed` and the cause `crc config invalid: CRC config file is <n> bytes, over the 268435456-byte read cap — the file was not read`. | Inc 8 | inc-8/01-requirements.md | |
| R-FLOW-EXT.9 | new | When a confirmed external step has copied its output, the system shall read that copy in place of the file named by each project ref of a later block of the same run that names `<project folder>/<output file name>`. | Inc 8 | inc-8/01-requirements.md | |
| R-FLOW-EXT.10 | new | When a PATCH block reads an external step's copy in place of its change document ref or of its effective A2L ref, the system shall give the copy's file name in place of that ref in each report that lists the block's changes. | Inc 8 | inc-8/01-requirements.md | |
| R-FLOW-EXT.11 | new | When a confirmed external step copies an output whose content differs from the file under the output file name, the system shall leave that file's name and content unchanged. | Inc 8 | inc-8/01-requirements.md | |
| R-FLOW-EXT.12 | new | When a block reads an external step's copy in place of a ref, the system shall end that block's summary with the read suffix, once for each such ref in the order the block reads its refs, placed before the final token `unresolved` when the summary ends with that token. | Inc 8 | inc-8/01-requirements.md | |
| R-FLOW-EXT.13 | new | When a LOAD block of a chain reads an external step's copy in place of its image ref, the system shall write that input's line of the chain-set report's Input provenance as `- Chain <name> input <j>: <ref> [bound] path=` + the copy's path in a code span + the read suffix. | Inc 8 | inc-8/01-requirements.md | |
| R-FLOW-EXT.14 | new | If a confirmed step's relative log path or relative output path climbs above the open project folder, then the system shall stop the flow with the summary `external step refused` and the cause `<log or output> '<path as given>' climbs above the project folder - give an absolute path for a file outside the project`. | Inc 8 | inc-8/01-requirements.md | |
| R-FLOW-CHAIN.19 | new | When a lane's confirm re-run ends, the system shall write a chain-set report of that lane alone into `<project>/reports/`. | Inc 9 | inc-9/01-requirements.md | |
| R-FLOW-CHAIN.20 | new | When a lane's confirm re-run ends, the system shall record the line `- **Mode:** confirm re-run` in that run's chain-set report. | Inc 9 | inc-9/01-requirements.md | |
| R-FLOW-FILE.12 | new | When the operator saves a flow under a file stem of at most 64 characters, the system shall write that file stem as the flow file's `name`. | Inc 9 | inc-9/01-requirements.md | |
| R-FLOW-FILE.13 | new | If the file stem of a flow being saved is longer than 64 characters, then the system shall write the first 64 characters of the file stem as the flow file's `name`. | Inc 9 | inc-9/01-requirements.md | |
| R-FLOW-FILE.14 | new | If a link in the flows home has the name of a flow file that the save would write, then the system shall write no byte through that link. | Inc 9 | inc-9/01-requirements.md | |
| R-FLOW-SET.8 | new | If a link in the flowsets home has the name of a chain-set file that the save would write, then the system shall write no byte through that link. | Inc 9 | inc-9/01-requirements.md | |
| R-FLOW-SET.9 | new | When the operator saves a chain set under a file stem of at most 64 characters, the system shall write that file stem as the chain-set file's `name`. | Inc 9 | inc-9/01-requirements.md | |
| R-FLOW-SET.10 | new | If the file stem of a chain set being saved is longer than 64 characters, then the system shall write the first 64 characters of the file stem as the chain-set file's `name`. | Inc 9 | inc-9/01-requirements.md | |
| R-TUI-059.25 | new | The system shall show every widget with an id of the Flow Builder in at least one state of the Flow Builder. | Inc 12b | inc-12b/01-requirements.md | moved from Inc 12 at E3, id unchanged |
| R-FLOW-CRC.1 | changed | When a CRC block runs, the system shall compute its CRCs as S13.2 computes them, from the CRC config file the block names, read as S13 CTX-CRCCONFIG, over the working image as it stands after the blocks before it. | Inc 8 | inc-8/01-requirements.md | was: "When a CRC block runs, the system shall compute its CRCs as S13.2 computes them, from a template read as S13 CTX-CRCCONFIG, over the working image as it stands after the blocks before it." |
| R-FLOW-CRC.3 | changed | If the CRC config file is refused or does not exist, then the system shall stop the flow with the summary `config unresolved` and the cause `crc config not found or not inside the project`. | Inc 8 | inc-8/01-requirements.md | was: "If the CRC template is refused or does not exist, then the system shall stop the flow with the summary `config unresolved` and the cause `crc config not found or not inside the project`." |
| R-FLOW-CRC.4 | changed | If the CRC config file is not a valid CRC config, then the system shall stop the flow with the summary `config malformed` and the cause `crc config invalid: <first three errors, separated by "; ">`. | Inc 8 | inc-8/01-requirements.md | was: "If the CRC template is invalid, then the system shall stop the flow with the summary `config malformed` and the cause `crc config invalid: <first three errors, separated by "; ">`." |
| R-FLOW-FILE.11 | changed | If the flows home passes through a link or resolves to a folder outside the work area, then the system shall save no flow file. | Inc 9 | inc-9/01-requirements.md | was: "If the flows home resolves to a folder outside the work area, then the system shall save no flow file." |
| R-FLOW-SET.7 | changed | If the flowsets home passes through a link or resolves to a folder outside the work area, then the system shall save no chain-set file. | Inc 9 | inc-9/01-requirements.md | was: "If the flowsets home resolves to a folder outside the work area, then the system shall save no chain-set file." |

S15 count: **21 rows** (16 new, 5 changed, 0 withdrawn, 0 brought in).

---

## S16 — Flow Execution & chain sets

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-FB-SAVE.8 | new | If a flow is not saved because its flows home passes through a link or resolves outside the work area (S15 R-FLOW-FILE.11), then the system shall show the status `Flow not saved - the project's flows folder is a link or is outside the work area.` | Inc 9 | inc-9/01-requirements.md | |
| R-FX-SET.15 | new | If a chain set is not saved because its flowsets home passes through a link or resolves outside the work area (S15 R-FLOW-SET.7), then the system shall show the status `Chain set not saved - the project's flowsets folder is a link or is outside the work area.` | Inc 9 | inc-9/01-requirements.md | |
| R-FX-SCR.4 | new | The system shall show every widget with an id of Flow Execution in at least one state of Flow Execution. | Inc 12b | inc-12b/01-requirements.md | moved from Inc 12 at E3, id unchanged |
| R-FB-RUN.8 | withdrawn | — | Inc 9 | inc-9/01-requirements.md | proposed row, withdrawn by orchestrator ruling D-2 = no; kept by id. Proposed text: "When the operator presses Clear, the system shall name the flow `flow`." |

S16 count: **4 rows** (3 new, 0 changed, 1 withdrawn, 0 brought in).

---

## S17 — Split / Join / Export

| Id | Kind | Final text in batch-101 (verbatim) | Increment | Source record | Note |
|---|---|---|---|---|---|
| R-SEG-OPEN.7 | new | While the window is hidden, the system shall run no action of the window's keys. | Inc 10a | inc-10/01-requirements.md | |
| R-SEG-PREV.20 | new | When the operator presses `g` in the F-23 Split/Join scene, the system shall show the updated preview within 2.5 seconds. | Inc 13 | inc-13/01-requirements.md | |
| R-SEG-PREV.21 | new | When the system writes bytes into the loaded image in place while the window is displayed, the system shall show the preview band, the stats line and the state line of the written bytes. | Inc 10b | inc-10b/01-requirements.md | moved from Inc 10, id unchanged |
| R-SEG-PREV.22 | new | When the system shows the preview of written bytes (R-SEG-PREV.21), the system shall keep the focus where it is. | Inc 10b | inc-10b/01-requirements.md | moved from Inc 10, id unchanged |
| R-SEG-EXP.15 | new | When the system writes bytes into the loaded image in place, the system shall disarm the confirm. | Inc 10b | inc-10b/01-requirements.md | |

S17 count: **5 rows** (5 new, 0 changed, 0 withdrawn, 0 brought in). Canon rows verified text-unchanged (not forwarded): R-SEG-PREV.2, R-SEG-PREV.7.

---

## CODE-CHANGES items done or partly done in batch-101

| Id | Increment | Evidence |
|---|---|---|
| D11-72 | Inc 3 | done — R-PROJ-002.14; "CODE-CHANGES D11-72 → done at this increment's merge" (inc-3/01-requirements.md) |
| D8-22 | Inc 4 | done — R-CHG-SYM.9 amended / R-CHG-SYM.10 (inc-4/01-requirements.md) |
| D9-7 | Inc 4 | done — headless entry point `run_checks_for_project` deleted; "CODE-CHANGES D9-7 is marked done at integration" (inc-4/01-requirements.md) |
| D9-11 | Inc 5 | done — R-CHKED-026 (expected bytes of a field loaded from a spec are the spec's bytes) |
| D9-12 | Inc 5 | done — R-CHKED-054, R-CHKED-055 (included parameters survive a Write / a return) |
| D14-14 | Inc 6 | done — the before/after offer half (R-BEFORE-AFTER-REPORT-001.36); text half ruled O-3 into Inc 7 (R-BEFORE-AFTER-REPORT-001.11) |
| D10-25 | Inc 6 | done — R-PATCH-DOC-DROPDOWN-001.1, .2 (the File dropdown lists the change home) |
| D9-15 | Inc 6 | done — R-CHKED-040 (the Spec dropdown fills with the spec list) |
| D9-10 | Inc 6 | done — co-located in Inc 6's patch/check-home work (inc-6/01-requirements.md header) |
| D10-30 | Inc 6 | done — R-TUI-049.3 split into .3.1, .3.2 (hide before/after control and save-back prompt) |
| D14-17 | Inc 6 | done — R-DIFF-CHK.1, .3, .5 (A2B Diff check-spec list) |
| D14-15 (= F-42) | Inc 7 | done — R-BEFORE-AFTER-REPORT-001.32 … .35, .24 |
| D14-10 | Inc 7 | done — R-CMP-004.9 split into .9.1 / .9.2; R-CMP-004.15 |
| D14-14 text half | Inc 7 | done — R-BEFORE-AFTER-REPORT-001.11 (ruling O-3) |
| D13-23 (= F-28) | Inc 8 | done — R-CRC-CONFIG-001.16, .17; R-FLOW-CRC.1, .3, .4 |
| D15-17 (= F-49) | Inc 8 | done — R-FLOW-EXT.9 … .14 |
| D13-20 | Inc 8 | done — R-CRC-ENGINE-002.2 (CRC model with reverse; release note R-DOC-RELNOTE.1/.2) |
| D15-18 | Inc 9 | done — R-FLOW-FILE.11, .14; R-FLOW-SET.7, .8; R-FB-SAVE.8; R-FX-SET.15 |
| D4-2, D4-6 | Inc 10a | done — R-TUI-018.1 … .4, R-TUI-040.4, .8, .11, .12 |
| D5-17, D5-19, D5-27 | Inc 10a | done — R-WS-LOADED.13, .14, .16, .18 … .20 |
| D6-21 | Inc 10a | done — R-SHELL-FOCUS.2 … .5 |
| D17-38 | Inc 10a | done — R-SHELL-FOCUS.2 … .5, R-SEG-OPEN.6, .7 |
| D3-12 (= F-02) | Inc 11 | done — R-VAL-032.1, .2, .3 |
| D7-10 | Inc 12 | done — R-DLG.14, R-SHELL-KEYS.3 |
| D6-12 (first half) | Inc 12 | partly — R-CHKED-058; "`_toggle_settings_menu` still open" (increment-012.md) |
| D9-8 | Inc 12 | done — R-DLG.2 (Reports dialog Escape) |
| D3-7 | Inc 12 | done (decision D-2) — removal of `_jump_to_validation_issue` / `_jump_to_validation_issue_object` / `_format_validation_issue_line`, traced through R-SHELL-KEYS.3 |
| D7-20 | Inc 12 | done for Reports — R-DLG.2 (recorded `Partly` after Inc 12; the other 7 dialogs stay BL-I12-5) |
| D16-6 | Inc 12b | done — R-TUI-059.25, R-FX-SCR.4 |
| D3-19 | Inc 14 | partly — the Memory Map key/field line done (R-TUI-062.10.1, R-LEGEND-011); the A2L, MAC and Issues legend rows stay out (D-10) |
| D7-26 (= F-37) | Inc 14 | done — R-WHELP.12 … .14, .20 … .24 |
| D0-9, D0-10, D0-11 (= F-38) | Inc 14 | done — R-DOC-README.2, .3, .4 |
| D13-17 | Inc 16 | done — R-DOC-ARCHIVE.3 removes `s19_app/tui/operations/requirements/REQ-crc.md` |

---

## Context terms (CTX-…) added or changed

| Term | Module | Change | Increment |
|---|---|---|---|
| CTX-CANON (forms, opening words, obligation word, one sentence) | S0 | added | Inc 1 |
| CTX-CHGDOC — session read, loaded A2L, the project's A2L file, the R-CHG-SYM.2 finding, case 08 | S8 | added (proposed) | Inc 4 |
| CTX-DESIGNER — *loaded image changes* amended: a Patch Editor apply, a save-back or a Save project commit that writes the image is an image change; Inc 13's "not an image change here" sentence withdrawn; *stale coverage* / *pending change* cover the in-place writes | S13 | changed | Inc 5 |
| CTX-CHECK-EDITOR — field set; field loaded from a spec; field included in this session; still lists (new at E3); declared field (amended); in-place write (new at E5); validation results (new at E5); named parameter of a spec entry | S9 | added / amended | Inc 5 |
| CTX-CHECK-EDITOR / S10.2 — change list, check home, spec list, current run (amended); linked folder (new) | S9/S10 | amended / added | Inc 6 |
| CTX-BEFOREAFTER — `title` term; CTX-DIFFREPORT — `label field`, `path field`, `refusal message`, `visible text`, `header`, `file write` (`<name>.<16 random hex digits>.part`) | S14 | added / changed | Inc 7 |
| CTX-CRCCONFIG — required field, number field, `<name>`, `<value>` (clipped), designer template shape, template rule text, nesting too deep | S13 | added | Inc 8 |
| CTX-CRC — KAT message, bit-symmetric init | S13 | added | Inc 8 |
| CTX-FLOW — output file name, the copy, names, in place of, run, read suffix, climbs above | S15 | added | Inc 8 |
| CTX-CHAIN — confirm re-run; CTX-FLOWREPORT — Mode values (changed); CTX-FLOWFILE — file stem, link, passes through a link, exists, status texts | S15 | added / changed | Inc 9 |
| CTX-HEX — jump, second row, view rows, first view row, next hex page (amended), last page shown; CTX-SHELL — file status (amended), focus target (amended); *in-place write* scope widened to S2/S17 | S4/S6 | added / amended | Inc 10a |
| CTX-A2L — first shown row (new); CTX-HEX — shown window (new); *in-place write* scope widened to S4 | S2/S4 | added | Inc 10b |
| CTX-A2L-BLOCKS (62 ASAM block names); CTX-ISSUE — section name, inside an IF_DATA block, severity rank; CTX-A2L — record words, number, address word, program-type word, memory-type word, program type / memory type, axis value, point-table rows | S2/S3 | added | Inc 11 |
| CTX-DIALOG — opener, dropdown list, dialogs today (changed); CTX-KEYS — action, reach, reached function; CTX-SHELL — shown widget, state of a window | S6/S7 | added / changed | Inc 12 |
| CTX-SHELL — shown widget, state of a window (identical text) | S6 | added | Inc 12b |
| CTX-DESIGNER — result surface, recompute, text field, toggle or dropdown, loaded image changes, displayed, stale coverage, pending change, quiet time (150 ms), edit burst, ascending address order, coverage size, coverage cap (16 MiB), demo image, F-23 CRC scene, F-23 template, F-23 Split/Join scene, base reference | S13 | added | Inc 13 |
| CTX-HELP — markdown mark (proposed, D-4), reference (proposed, D-7); CTX-LEGEND — map sheet changed (Legend copy I14, D-6); CTX-README — 26 keys; proposed S0 subsections: S0.4 security policy, S0.5 release notes, S0.6 user guide | S3/S7/S0 | added / changed | Inc 14 |
| CTX-DOCHYG (repository document, tracked text file, repository path, exists, removal mark, retired folder, retired-folder path, exempt line, s19tool shape, module table, Python folder, archive folder, guard probe, local identity); CTX-DOCINDEX; CTX-ARCHIVE; CTX-REMOVED; CTX-SUBMOD; CTX-IFACE | S0 | added | Inc 16 |

---

## Open items already promised to the requirements session

Collected from the batch's records (`03-increments/increment-0NN.md` "Canon ids to forward" sections, `E4-rulings.md`, `E4-integration-notes.md`, and the handoffs).

| Item | Increment | Source record |
|---|---|---|
| `S17-ears-strict.md` / CODE-CHANGES D17-27 still describe the old state-line order; Inc 13 made it conflict-first (R-SEG-PREV.7 / .8, finding E4-F1, fixed at E5 C-1). The review file and D17-27 need the record update. | Inc 13 | HANDOFF-2026-11-06.md; increment-013.md |
| R-DOC-DEV.2 correction: the CLI example form is `python -m s19_app.cli <command> <file>` (not `<file> <command>`), corrected at E4 integration I-1. | Inc 16 | E4-integration-notes.md I-1; HANDOFF-2026-11-06b.md |
| R-SHELL-FOCUS.4's frame-widget arm: "the operator chose" added (E4-R3). | Inc 10a | increment-010.md; inc-10/01-requirements.md |
| CTX-SHELL focus target of the A2L Explorer: tag table after a load / unload, `window_help_a2l` after a switch (E4-R4); and of the MAC View: record table after a load / unload, `mac_page_prev_button` after a switch (E4-R6). | Inc 10a | increment-010.md |
| R-WS-LOADED.19 widened to "when no S19 or HEX image is loaded" and narrowed to top-level files (E5 RR-1, RR-2). | Inc 10a | increment-010.md |
| R-TUI-007.9 brought in unchanged (E4-R1). | Inc 10a | increment-010.md |
| R-WS-LOADED.16's threshold drops "the Issues Report" (QA-7). | Inc 10a | increment-010.md |
| R-DLG.2 (changed; adds "while none of its dropdown lists is open", D-8) — recorded `Partly` after Inc 12 (E3A-06). | Inc 12 | increment-012.md |
| R-DLG.14, R-DLG.15, R-SHELL-KEYS.3, R-CHKED-058 (4 new) — into `REQUIREMENTS.md` at the batch-end requirements session. | Inc 12 | increment-012.md |
| R-TUI-004.8's threshold amended at E5 QA-4 (the scroll reads (10, 40) for main, (0, 40) for the A2L and MAC views). | Inc 10b | increment-010b.md |
| The S9 / CODE-CHANGES D9-7 wording reworded without the dead test name (`S9-ears-strict.md` R-CHK-001 note, `CODE-CHANGES.md` D9-7 `done`) — forwarded 2026-11-05 for confirmation. | Inc 4 | increment-004.md |
| QC-TM figure QC-TM-10b-1 (case_06, 220 040 tags: 0.35 s of 1 s) forwarded with the measurement record. | Inc 10b | increment-010b.md |
| New/changed canon ids of Incs 5, 6, 9, 10a, 10b, 15, 16 (each `01-requirements.md`) — still to send. | — | HANDOFF-2026-11-06b.md |

---

## Totals

| Module | New | Changed | Withdrawn | Brought in | Total |
|---|---|---|---|---|---|
| S0 | 128 | 0 | 0 | 0 | 128 |
| S1 | 0 | 0 | 0 | 0 | 0 |
| S2 | 15 | 5 | 1 | 0 | 21 |
| S3 | 4 | 1 | 1 | 0 | 6 |
| S4 | 4 | 4 | 1 | 1 | 10 |
| S5 | 3 | 0 | 0 | 0 | 3 |
| S6 | 2 | 2 | 0 | 0 | 4 |
| S7 | 11 | 1 | 0 | 0 | 12 |
| S8 | 3 | 2 | 0 | 0 | 5 |
| S9 | 7 | 2 | 1 | 0 | 10 |
| S10 | 3 | 3 | 1 | 0 | 7 |
| S11 | 4 | 0 | 0 | 0 | 4 |
| S12 | 0 | 0 | 0 | 0 | 0 |
| S13 | 15 | 0 | 1 | 0 | 16 |
| S14 | 11 | 4 | 1 | 1 | 17 |
| S15 | 16 | 5 | 0 | 0 | 21 |
| S16 | 3 | 0 | 1 | 0 | 4 |
| S17 | 5 | 0 | 0 | 0 | 5 |
| **Total** | **234** | **29** | **8** | **2** | **273** |

DONE forward — 234 new, 29 changed, 8 withdrawn, 2 brought in; 273 rows total.
