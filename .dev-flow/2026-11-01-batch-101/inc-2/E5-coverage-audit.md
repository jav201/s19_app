# Inc 2: E5 independent coverage audit of the test-case records

**Auditor:** an independent QA reviewer. It wrote neither the cases nor the tests. It changed only the tests-mark, coverage and result cells of `02-test-cases.md` and wrote this file. It committed nothing.

**Tree:** worktree `b101-inc2` at `ab879c8`.

**Mode:** validation. Every result below comes from transcripts recorded by the E4 integration step (`evidence/inc-2/`) or from the batch CI record (`evidence/ci/41372953464.txt`). The auditor ran no test. Where the auditor judged code without a run, the text says `inspection`.

## Verdict

- **Before → after:** 58 → 54 `verified`. 75 `gap` → 9 `gap`, because the E1 coverage value had never been refreshed. 72 → 66 `full`.
- **Changed by judgment: 14 of 81 cases (17.3 %).** These are mark, result or coverage changes beyond the stale-`gap` refresh. The s19 pilot comparison is 24 %.
- **Changed in any cell value: 69 of 81 (85.2 %).** One more case, 032/1, got an annotation only.
- **Four real defects.** Seven `verified` results went back to `not_run`:
  - The R-TST-041 failure text is printed by no guard route (F-1).
  - The R-TST-051 planted-copy cases never run the guard route, and they assert text the test built itself (F-2).
  - R-TST-040/3 was marked verified on a check that the head tree empties (F-4).
  - The `snapshot` job's checkout changed against the record (F-3).
- **Three static-only cases became full:** 010/1, 011/1 and 018/1. Their expected results are the static workflow text, and the tests assert it exactly.

## Rule applied

The rule comes from `dev-flow-v3-beta` SKILL.md, E4:

- A test verifies a case only if it asserts the case's expected result.
- A test is `full` only when the product produces what the test asserts. Here the product is the suite machinery: `tests/support/timing.py`, `tests/support/suite_census.py`, the conftest hooks, the guard host `tests/test_suite_hygiene.py` (ruling O-1), the workflow and `pyproject.toml`.
- These make a test `partial`: text echoed by the test itself, a stand-in, a fixture that already shows the result, or an entry point no product route calls.

Coverage values:

| Value | Meaning |
|---|---|
| `covered` | The named tests together assert the whole expected result, and at least one of them is full. |
| `partial` | Only part of the expected result is asserted. |
| `gap` | No test or evidence asserts any part of it. |
| `conflict` | The record and the shipped product disagree. |
| `not-testable` | The case cannot be tested (its condition did not occur). |

How cases are counted:

- **Result `verified`** requires `covered` plus a passing transcript from `ab879c8` or a direct ancestor.
- **Mark totals:** a case counts `full` when any entry of its tests cell is marked full, including evidence artifacts. Otherwise it counts `partial`.

## Evidence basis (checked)

- **Windows, the audited tree:** `int-win-final2.txt` records branch `b101-inc2` at 86c8aa6 plus the corrective edits, which were committed as `ab879c8`. It shows `pytest --markers` printing the S-1 line, and **54/54 `tests/test_suite_hygiene.py` nodes passed** (79 with the Inc 1 guards). Every hygiene case's Windows result rests on this run.
- **Linux, a direct ancestor:** `int-linux-plain-lane1.txt` and `int-linux-plain-lane2.txt` ran at 86c8aa6. `int-linux-lane1.txt` and `int-linux-lane2.txt` ran on the branch working tree just before the 86c8aa6 commit. In all of them, no failure header names a hygiene node.
  - The corrective commit `ab879c8` changes only the marker text, the two lane-1 commands and their pins in the test (`git diff 86c8aa6 ab879c8`). So the Linux results apply to every hygiene case except 001/1, 010/1 and 011/1, whose cells already name Windows only.
- **Goldens (R-TST-081/1):**
  - `int-win-goldens.txt` shows 204 passed and 1 failed. The failure is `test_at_056e_a2b`, a known failure that is not one of the 7 golden nodes.
  - Both Linux lane-1 runs show the same single known failure among the golden files.
  - The golden files are unchanged since then.
- **CI record (R-TST-070/1, 072/1):** `evidence/ci/41372953464.txt` was committed in `bab6e22`, an ancestor. It holds 5 FAILED lines copied verbatim, each classified `known`, with 0 new. It also holds `snapshot  success` and `29 snapshots passed.`
- **Who executed the runs:** the E4 integration step, on the Windows host and the LAN Linux host. The auditor consumed the transcripts and ran nothing.

## Findings for the orchestrator (not fixed here: the auditor edits no test or code)

| # | Severity | Finding | Cases | Route |
|---|---|---|---|---|
| F-1 | HIGH | R-TST-041 requires the margin guard to fail with `timing bound without report_margin: <file>:<line>`. No guard route prints that text. The real-tree guard fails with `raw upper timing bounds: <sites>` (`tests/test_suite_hygiene.py:1182-1184`), `suite_census.py` holds no guard text, and the planted part of the test builds the required string itself and checks it against a regex of itself. | 041/1, 041/2 | Tester: make the real-tree guard emit one `timing bound without report_margin: <file>:<line>` line per site through one shared function, and assert that function's output on the planted file. |
| F-2 | MAJOR | R-TST-051's planted cases assert census counts only. The baselined-file copy is written under another file name (`test_baselined_copy.py`), so the guard route `count > baseline.get(file, 0)` would compare it with baseline 0, not `n`. The expected `> baseline <n>` text is formatted by the test from the picked file's baseline. 051/3 compares the template with its own expansion. 051/4 asserts no text at all. | 051/2, 051/3, 051/4 | Tester: put the guard route in one function used by both the real-tree pass and the planted cases. Plant the copy under the baselined file's relative path inside a temporary tests root, and assert the function's exact output. |
| F-3 | MAJOR | `snapshot` job checkout: the Inc 2 diff adds `fetch-depth: 0` there too. No ruling covers it (E3S-3 rules `persist-credentials: false` only), and case 013/1 and `codewire/graph-inc2.md:339` say the `snapshot` job is unchanged. The test checks only that the job exists. | 013/1 | Orchestrator: either rule the extra `fetch-depth: 0` and correct the records, or remove it. Then the tester asserts the `snapshot` checkout's exact `with:` block. |
| F-4 | MAJOR | R-TST-040's base-tree halves are not asserted anywhere. 040/3 was marked `verified` on head, where `sites == set()` leaves the `_NOT_UPPER_BOUND_SITES` loop nothing to check. Its negative half still holds, because counts and lower bounds stay raw on head. No test plants the list-append or conditional form of 040/4 (N-1). | 040/1, 040/3, 040/4 | E5 census run on `b3bf42e`: the 37 sites, :841/:978/:1350, and none of the 5 not-a-bound sites. Tester: a planted `timing.append(time.perf_counter() - t0)` / `x = timing[0] if timing else None` / `assert x < 1.0` arm. |
| F-5 | MINOR | The 032/1 static check `"_fx_clock" in dwell_body` is met by the arm's docstring (line 1764). It cannot fail if the `monkeypatch.setattr(fs, "_fx_clock", ...)` line is removed. | 032/1 | Tester: assert the `setattr(fs, "_fx_clock"` call form in the body, not the bare name. |
| F-6 | MINOR | Record defect, corrected here: the tests cells of 051/2 to 051/4 said "same test", which pointed at `test_r_tst_050` after the tester moved 051/1 there. They now name `test_r_tst_051_newest_line_waits_do_not_grow`. | 051/2-4 | Done. |
| O-1 | note | 006/3: `test_r_tst_006` names one `_reopen` test. The other unmarked `_reopen` tests are held through `test_r_tst_002`'s two-way marker guard: an unmarked test reported as an arm would fail it. The mark stays full. | 006/3 | None. |
| O-2 | note | 014/1 keeps `gap`. The partial test named there checks the precondition (`fetch-depth: 0`), not the expected result (0 `unavailable` skip lines, 6 passed). | 014/1 | Inc 2 PR run log. |

## Totals

| Measure | Before | After |
|---|---:|---:|
| Tests mark `full` / `partial` | 72 / 9 | 66 / 15 |
| Coverage `covered` | 2 | 56 |
| Coverage `partial` | 3 | 14 |
| Coverage `gap` | 75 | 9 |
| Coverage `conflict` | 0 | 1 |
| Coverage `not-testable` | 1 | 1 |
| Result `verified` | 58 | 54 |
| Result `failed` | 0 | 0 |
| Result `not_run` | 23 | 27 |

- **Cases changed in any of the three cell values:** 69 of 81 (**85.2 %**). Of these, 55 are only the refresh of the never-updated E1 `gap`: 49 → `covered` and 6 → `partial`.
- **Cases changed by judgment** (mark, result, or a coverage value other than the stale-`gap` refresh): 14 of 81 (**17.3 %**):
  - Marks: 010/1, 011/1, 018/1, 013/1, 040/1, 040/3, 040/4, 041/1, 041/2, 051/2, 051/3, 051/4.
  - Coverage only: 031/1, 031/2.
- **Annotation only:** 032/1, with no value change.
- **Results:**
  - `verified` → `not_run` (7): 013/1, 040/3, 041/1, 041/2, 051/2, 051/3, 051/4.
  - `not_run` → `verified` (3): 010/1, 011/1, 018/1.

## Changed cases: judgment changes (15 rows: 14 value changes and 1 annotation)

| Case | Tests mark | Coverage | Result | Reason |
|---|---|---|---|---|
| R-TST-010/1 | partial -> **full** | gap -> **covered** | not_run -> **verified** | The expected result is the static step list (2 steps, in order, exact `run:` text). The test reads the shipped workflow and asserts exactly that list, so it is full, by the same standard the record already uses for 013/1, 015/1 and 016/1. The first PR run log is still CI evidence for the batch, but it is not this case's expected result. Backed by `int-win-final2.txt` (tree at ab879c8, 54/54). |
| R-TST-011/1 | partial -> **full** | gap -> **covered** | not_run -> **verified** | Same reasoning as 010/1 for the push steps. Backed by `int-win-final2.txt`. |
| R-TST-013/1 | full -> **partial** | gap -> **conflict** | verified -> **not_run** | The test asserts `fetch-depth: 0` 1/1 on `tui-ci`, but it checks only that the `snapshot` job exists, not "the `snapshot` job unchanged". The shipped workflow also contradicts that clause: the diff against main `e266395` adds `fetch-depth: 0` to the `snapshot` checkout, which no ruling covers (E3S-3 rules only `persist-credentials: false`; `codewire/graph-inc2.md:339` says the `snapshot` job is unchanged). That makes the coverage a record/product conflict. Found by inspection, with no transcript of a failure, so the result is `not_run`. |
| R-TST-018/1 | partial -> **full** | gap -> **covered** | not_run -> **verified** | The expected result is only the install line, and the test asserts it in the shipped workflow. The run-time header (`xdist-3.8.0`, n >= 2 workers) is case 018/2, which stays a gap. The test and the install line are unchanged since 86c8aa6, so the Windows run (`int-win-final2.txt`) and the Linux run (`int-linux-plain-lane1.txt` at 86c8aa6) both back it. |
| R-TST-031/1 | full | partial -> **covered** | not_run | The static test asserts the pinned form exactly, inside the function body (`Hold(monkeypatch, app_module, "place_into_workarea"`, absent from the docstring). The arm node itself is the full test for "3/3 passed". Together they assert the whole expected result, so the coverage is covered. The result stays `not_run`: 1 of 3 parallel-lane runs is on record. |
| R-TST-031/2 | full | partial -> **covered** | not_run | Same as 031/1. The body both reads (`= app.step_busy`) and reassigns (`app.step_busy = `) the hook, and neither string is in the docstring. |
| R-TST-032/1 | full | partial | not_run | Annotation only, no value change. The static check `"_fx_clock" in dwell_body` is met by the docstring alone (line 1764 names `_fx_clock`), so it cannot fail if the `monkeypatch.setattr(fs, "_fx_clock", ...)` line is removed. The mark and coverage stay partial, and the result note no longer says the static part is verified. |
| R-TST-040/1 | full -> **partial** | gap -> **partial** | not_run | The expected result has two parts: 0 unreported on head, and 37 reported bounds at the `b3bf42e` set. No test counts reported bounds (the test calls only `unreported_upper_bounds`), so the mark is partial. The result stays `not_run`. |
| R-TST-040/4 | full -> **partial** | gap | not_run | Neither half is asserted. The planted arm in the test has 4 plain raw bounds and no `timing.append(...)` or `x = timing[0] if timing else None` form. No base-tree list (:841/:978/:1350) is checked. On head those 3 sites are wrapped, so the head-tree pass cannot fail on a lost list-append taint. The mark is partial, the coverage stays gap, and the result note no longer claims a verified head-tree part. |
| R-TST-040/3 | full -> **partial** | gap -> **partial** | verified -> **not_run** | On head every upper bound is wrapped, so `sites == set()` passes. The loop that follows over `_NOT_UPPER_BOUND_SITES` can never fail, because the set is already empty (it also uses `b3bf42e` line numbers). The negative half still has teeth: counts and lower bounds stay raw on head, so a census that took one of them for an upper bound would fail `sites == set()`. The positive half (the 37 sites on `b3bf42e`) is not asserted. So the mark is partial, the coverage partial, and the result `verified` -> `not_run`. |
| R-TST-041/1 | full -> **partial** | gap -> **partial** | verified -> **not_run** | The census gives file and line, and the test asserts that part. The failure text `timing bound without report_margin: <file>:<line>` is built by the test itself (`guard_lines = [f"..." for site in planted_sites]`) and then regex-matched against itself. No guard route prints it: the real-tree guard fails with `raw upper timing bounds: ...` (`tests/test_suite_hygiene.py:1182-1184`), and the census has no guard text. This is echoed text, so partial. The result goes from `verified` to `not_run`, and it is a product finding (F-1). |
| R-TST-041/2 | full -> **partial** | gap -> **partial** | verified -> **not_run** | Same as 041/1. The 3 sites (int, scaled `timing_bound`, module constant) are detected with file and line, but the required text is the test's own. |
| R-TST-051/2 | full -> **partial** | gap -> **partial** | verified -> **not_run** | The count n+1 comes from the census. The guard decision and the text do not: the planted copy is written as `test_baselined_copy.py`, a file name absent from `NEWEST_LINE_BASELINE`, so the guard route (`count > baseline.get(file, 0)` in `test_r_tst_050`) would compare it with 0. The test builds the `> baseline <n>` text from the picked file's baseline by hand, then compares the template with its own expansion. Partial. The result goes from `verified` to `not_run`. The tests cell said "same test", which after the tester moved 051/1 to `test_r_tst_050` pointed at the wrong node; it now names `test_r_tst_051_newest_line_waits_do_not_grow`. |
| R-TST-051/3 | full -> **partial** | gap -> **partial** | verified -> **not_run** | The census count 1 is real. The asserted text is `_NEWEST_GUARD_TEXT.format(...)` compared with an f-string of the same words, a tautology that never runs the guard route on the planted file. Partial. The result goes from `verified` to `not_run`. The test name in the tests cell is also corrected (see 051/2). |
| R-TST-051/4 | full -> **partial** | gap -> **partial** | verified -> **not_run** | The test asserts the count n+1 only. The case expects the exact failure text, and no text is asserted. Partial. The result goes from `verified` to `not_run`. The test name in the tests cell is also corrected. |

## Changed cases: refresh of the never-updated E1 coverage (55 rows)

In every row below, the tests mark and the result value are unchanged. Only the coverage moves from the E1 `gap` to the value the existing test supports.

| Case | Tests mark | Coverage | Result | Reason |
|---|---|---|---|---|
| R-TST-001/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-002/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-003/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-004/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-005/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-005/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-005/3 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-005/4 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-005/5 | partial | gap -> **partial** | not_run | The E1 value (`gap`) was never updated. The test exists and its partial mark is right (the case itself declares the run-time half owed), so the coverage is partial. The result stays `not_run`. |
| R-TST-005/6 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-005/7 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-005/8 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-006/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-006/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-006/3 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-007/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-012/1 | partial | gap -> **partial** | not_run | The E1 value (`gap`) was never updated. The test exists and its partial mark is right (the case itself declares the run-time half owed), so the coverage is partial. The result stays `not_run`. |
| R-TST-015/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-016/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-017/1 | partial | gap -> **partial** | not_run | The E1 value (`gap`) was never updated. The test exists and its partial mark is right (the case itself declares the run-time half owed), so the coverage is partial. The result stays `not_run`. |
| R-TST-020/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-020/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-021/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-021/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-022/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-023/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-024/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-024/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-024/3 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-024/4 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-024/5 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-024/6 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-024/7 | partial | gap -> **partial** | not_run | The E1 value (`gap`) was never updated. The test exists and its partial mark is right (the case itself declares the run-time half owed), so the coverage is partial. The result stays `not_run`. |
| R-TST-024/8 | partial | gap -> **partial** | not_run | The E1 value (`gap`) was never updated. The test exists and its partial mark is right (the case itself declares the run-time half owed), so the coverage is partial. The result stays `not_run`. |
| R-TST-024/9 | partial | gap -> **partial** | not_run | The E1 value (`gap`) was never updated. The test exists and its partial mark is right (the case itself declares the run-time half owed), so the coverage is partial. The result stays `not_run`. |
| R-TST-025/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-030/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-040/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-042/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-043/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-043/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-044/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-044/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-045/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-046/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-047/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-048/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-050/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-051/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-052/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-060/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-080/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-081/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-081/2 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |
| R-TST-082/1 | full | gap -> **covered** | verified | The E1 value (`gap`) was never updated after E4 wrote the test. The named test asserts the expected result exactly and its mark is right, so the coverage is covered. The result is unchanged and backed (see Evidence basis). |

## Re-audit (57d19f4)

**Scope.** The cases the E5 corrective pass touched, plus every case whose test changed between `ab879c8` and `57d19f4`. The changed tests were found by an AST diff of `tests/test_suite_hygiene.py` (12 changed and 13 added top-level definitions) and by the product diffs: `suite_census.py`, the workflow, `test_report_service.py`, `test_b100_project_check.py`, and a docstring in `conftest.py`. The new case 049/1 is added. The rules are unchanged from the first audit.

**Evidence basis.**
- **Windows, the audited tree:** `int-win-e5c.txt` (branch at `ab879c8` + the E5 corrective edits, committed as `57d19f4`). 65/65 hygiene nodes passed with no skips, so the git-dependent nodes 013-snapshot, 040_1 and 049 ran.
- **Linux:** the 86c8aa6 runs still count only for cases whose test did not change. In the changed-test rows they are dropped and the cell names Windows only.
- **Other transcripts:**
  - `e5c-red-before.txt`: 3 failed on `ab879c8`, each for the defect its fix targets.
  - `mut-r2-040_4.txt`: M-040/4 killed by `040_4` and `040_1`.
  - `mut-r2-017.txt`: M-017 killed by the row's own node.
  - `e5c-f11-capture.txt`: the at288 capture branch on 57d19f4.
- **Who executed the runs:** the E5 corrective step. The auditor ran nothing.

### Value changes (11 existing cases, plus 1 added)

| Case | Tests mark | Coverage | Result | Reason |
|---|---|---|---|---|
| R-TST-013/1 | partial -> **full** | conflict -> **covered** | not_run -> **verified** | F9/F-3 removed `fetch-depth: 0` from the `snapshot` checkout. The new `test_r_tst_013_snapshot_job_changes_only_persist_credentials` asserts that the `with:` block is exactly `persist-credentials: false` and that the job equals its merge-base version apart from that E3S-3 setting. That is the record's "unchanged", read with the ruled exception. |
| R-TST-032/1 | partial (unchanged) | partial -> **covered** | not_run | The static check now reads the `setattr(..., "_fx_clock", ...)` call through the AST, so the docstring no longer satisfies it (mutant in `e5c-mutation-checks.txt`). Together with the arm node (full, 3 runs) the whole expected result is asserted. The 3/3 runs are still owed. |
| R-TST-040/1 | partial -> **full** | partial -> **covered** | not_run -> **verified** | `test_r_tst_040_1_base_tree_reports_its_37_bounds` extracts `tests/` of `b3bf42e` and asserts 37 guard sites. The head-tree node asserts 0 lines. |
| R-TST-040/3 | partial -> **full** | partial -> **covered** | not_run -> **verified** | The same base-tree node asserts that none of :843, :981, :2331, :3493 appears and that :2335 appears exactly once. The new planted node asserts the exact guard lines for the tuple and dict positions and for a lower bound. |
| R-TST-040/4 | partial -> **full** | gap -> **covered** | not_run -> **verified** | The base-tree node asserts :841, :978 and :1350. The new planted node plants the case's exact input (`timing.append(...)`, `x = timing[0] if timing else None`, `assert x < 1.0`) and asserts both that the arm is detected and that its bound is named. M-040/4 is killed by both. |
| R-TST-041/1 | partial -> **full** | partial -> **covered** | not_run -> **verified** | F-1 fixed: `_margin_guard_lines` is now the one function both the real-tree guard and the planted node use. The planted node asserts its 4 exact lines `timing bound without report_margin: tests/test_raw_bounds_planted.py:<12..15>`. |
| R-TST-041/2 | partial -> **full** | partial -> **covered** | not_run -> **verified** | The same node: lines 13-15 are the int, scaled `timing_bound` and module-constant sites. |
| R-TST-051/2 | partial -> **full** | partial -> **covered** | not_run -> **verified** | F-2 fixed: `_newest_guard_lines` is shared with the real-tree guard. The copy is planted under `tests/test_b100_reuse.py` (n = 1), and the exact `2 > baseline 1` text is asserted. An unchanged copy gives no line. |
| R-TST-051/3 | partial -> **full** | partial -> **covered** | not_run -> **verified** | The same function: the exact `1 > baseline 0` text for a new file. |
| R-TST-051/4 | partial -> **full** | partial -> **covered** | not_run -> **verified** | The same function: the exact text through the support-module reader `last_status`. |
| R-TST-005/7 | full -> **partial** | covered -> **partial** | verified -> **not_run** | F7 rewrote form 6. It now plants `elapsed = await projects.load_project(pilot, app, "P"); assert elapsed < 1.0`, an interval returned by a real support module with a raw bound. The case input is still a `report_margin` wrap over an interval from a planted support module, so the test no longer asserts this case's input. The new form is the stronger check (F7: the wrap alone made the old form an arm). The real wrapped arms stay detected through `test_r_tst_002` (005/5's check). **Fix needed (MINOR, R-1):** the orchestrator either corrects case 005/7's input to the F7 form or adds a planted wrap form back. |
| R-TST-049/1 (new) | **full** (real tree) + **partial** (planted) | **partial** | **not_run** | The row was added from `E5-corrective-notes.md` §4, with preconditions and the planted inputs named. The real-tree node asserts 0 lines on the Inc 2 tree (full). The planted node asserts the detection decision 2/2 (`["test_a"]` and `[]`), but it compares function names: the required text `wrapped timing arm changed beyond marker and report_margin: <file>::<function>` is formatted only inside the real-tree route. This is the same pattern F-1 and F-2 fixed. The exact text does appear, produced by the guard route, in `e5c-red-before.txt` (the real F1 drift on `ab879c8`), but no standing test asserts it. **Fix needed (MINOR, R-2):** move the line format into a `_wrap_guard_lines(...)` function shared by both nodes, and assert its exact output in the planted node. |

### Backing-only updates (values unchanged)

| Case | Reason |
|---|---|
| 005/1, 005/2, 005/3, 005/4, 005/6, 005/8 | `test_r_tst_005` changed (the form-6 branch was removed), so the result now cites Windows `int-win-e5c.txt` only. |
| 010/1, 011/1 | The tests changed (E5S-2 injection ratchet). The lane assertions are unchanged and still exact. Windows only, `int-win-e5c.txt`. |
| 015/1, 016/1 | The test changed (F5: the sums now come from parsed values; the job limit is matched exactly). Windows only. |
| 017/1 | Stays partial / not_run: the CI time-limit stop is still owed. The static part is now asserted in the row's own node, and M-017 is killed by it (`mut-r2-017.txt`). |
| 031/1, 031/2 | The test changed elsewhere in its body; these two assertions are identical. The static part is verified Windows at 57d19f4, and 3/3 runs are still owed. |
| 050/1, 051/1 | `test_r_tst_050` changed: it now uses the shared guard function, with the baseline regenerated by the fixed census. Windows only. |
| 081/1 | `test_at288_report_hex_sections_identical_after_move` changed, but only in its capture branch (F11). That branch is not taken while the golden exists, and `test_r_tst_080` holds that the golden exists. **This is a judgment call against the literal rule:** the other 6 golden nodes are unchanged and keep their Windows + Linux runs, and at288 ran on 57d19f4 through the F11 harness (`e5c-f11-capture.txt`). The harness executes the whole test body and asserts the same canonical byte equality against the committed golden. A plain re-run of the 7 golden nodes on 57d19f4 would remove the judgment call. |

**Unchanged on re-check:** 040/2 (its test is unchanged; the new unsafe-label node adds E3S-7 coverage but is not this case's expected result), 012/1 and 018/1 (unchanged tests; the workflow diff touches only the header and the `snapshot` checkout). F-6 was already done.

### Totals after the re-audit

| Measure | After first audit (81) | After re-audit (82) |
|---|---:|---:|
| Tests mark `full` / `partial` | 66 / 15 | 75 / 7 |
| Coverage `covered` | 56 | 65 |
| Coverage `partial` | 14 | 8 |
| Coverage `gap` | 9 | 8 |
| Coverage `conflict` | 1 | 0 |
| Coverage `not-testable` | 1 | 1 |
| Result `verified` | 54 | 62 |
| Result `failed` | 0 | 0 |
| Result `not_run` | 27 | 20 |

- **Existing cases with a changed value:** 11 of 81 (**13.6 %**): 10 resolved, and 1 (005/7) newly lost.
- **Added:** 1 (049/1).
- **Backing or annotation updates only:** 16 cases.
- **Record edit outside the cells:** the `Count:` line now reads 82 cases over 49 requirements, because the 049/1 row was added.

### Open from the re-audit

| # | Severity | Item | Route |
|---|---|---|---|
| R-1 | MINOR | 005/7: the case input no longer matches form 6. | Orchestrator: correct the case input, or add a planted wrap form back. |
| R-2 | MINOR | 049/1: the guard text is not asserted by a standing test. | Tester: a shared `_wrap_guard_lines` function, with its exact output asserted in the planted node. |
| R-3 | note | 081/1 rests on the F11 harness for at288 instead of a plain node run. | A re-run of the 7 golden nodes on 57d19f4. |
| — | carried | Still owed: the gate, CI and E5 evidence rows (008, 009, 014, 018/2, 023/2, 082/2, 090, 091) and the 3/3 lane runs of 031/1, 031/2 and 032/1. | Unchanged. |
