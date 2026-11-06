# Inc 15 — E5 coverage audit of the test-case marks

**Mode: validation.** The auditor is the qa-reviewer agent, which wrote neither `02-test-cases.md` nor the tests. Scope: the 26 cases of `02-test-cases.md` (R-TST-150 … 163). They were checked against the tests at head `b0b429e` and against the transcripts `../evidence/inc-15/int-NN.txt`, `evidence-e1/` and `evidence-e3/`. The result words are the record's own: `verified` / `failed` / `not_run`.

**Verdict: 23 of 26 cases hold as `full` / `covered` / `verified`. Two cases are `partial`: R-TST-153/1 and R-TST-155/1. One case, R-TST-157/1, is not verified as written, because its parallel-lane half was not run. No case is `failed` or `conflict`.**

## Basis

- **Who ran it.** The E4 integration step (orchestrator session, Opus) ran every cited run, as `E4-integration-notes.md` and `steps.log` record. This audit read those transcripts and ran no test. It used only text tools: `git diff`, `sha256sum`, and `trace_check.py --req inc-15/01-requirements.md --base c2cba35 --src s19_app`, which reported 2 US, 14 requirements and 1 gap (EVID: no `04-validation.md`).
- **Commit and platform.**
  - Windows, int-70 … 89: each header prints `commit under test = 77f4553`, `git HEAD here = 77f4553…`, and `s19_app.__file__` in the worktree.
  - LAN Linux: the tree is `c2cba35` plus a patch with sha256 `fdde60cc…`. Recomputed here, `git diff c2cba35 77f4553 -- tests docs | sha256sum` gives `fdde60cc014b8107…`, a match. Outside `.dev-flow/`, the only paths that differ between `c2cba35` and `77f4553` are the patch's 4 files.
  - `b0b429e` differs from `77f4553` only under `.dev-flow/`.
  - So both platforms' results hold for the head's tests.
- **Record state.** `02-test-cases.md` is still at E1: every case reads `(full)` / `gap` / `not_run`, because E4 did not update it. Every case below therefore changes its Coverage and Result marks. The last column flags where the audit differs from a plain update to `covered` / `verified`.

## Cases

Record marks on every row: Tests `full`, Coverage `gap`, Result `not_run`. Evidence: L = LAN Linux, W = Windows host.

| Case | Tests | Coverage | Result | Evidence | Audit change, why |
|---|---|---|---|---|---|
| 150/1 | full | covered | verified | L int-03…05 (12/12 node runs); W int-70…89 (20/20) | — (D1 raises if the load never lands; `file_disabled is True` asserted) |
| 150/2 | full | covered | verified | L int-06…08 GREEN, hold `patch_action[*] 1.5s` installed; int-09, 10 base RED at the load step | — |
| 151/1 | full | covered | verified | L int-03…05; W int-70…89 | — (D1 left `source_path` = `f.json`, so D2 cannot hold early) |
| 151/2 | full | covered | verified | L int-11…13 GREEN (no `NoMatches`); int-14, 15 base RED at the paste step | — |
| 152/1 | full | covered | verified | L int-03…05; W int-70…89 | — kept. The expected `{}` equals the state before the trigger, the rule's "fixture already shows the result". It stays full because D3's recorder proves the bind step returned, and int-44 shows the read fails when the no-op writes. `lane_bindings` returns `dict(lane.bindings)`, the record itself. |
| 152/2 | full | covered | verified | L int-44 RED `rebinding to the same ref wrote a record: {0: 'base.s19'}`; int-45 base passes the no-op, RED at `after_a` | — |
| 153/1 | **partial** | **partial** | verified | L int-03…05; W int-70…89 | **full → partial.** The paint half ("lane B paint holds `base.s19`, not `variant_b.hex`") is read through `FlowExecutionPanel.lane_paint_plain(1)` (`s19_app/tui/flow_screens.py:4102`). That seam is called by no product route and rebuilds the text from state (`_effective_ref`), not from the painted widgets. The bindings half and the box half (`#fx_in_1_0` value) are full. **Ruling needed:** accept partial (a TC-B94-27 assertion older than Inc 15; the timing goal holds because the seam is read after D4), or assert on the rendered lane. |
| 153/2 | full | covered | verified | L int-16…18 GREEN; int-19, 20 base RED `assert {} == {0: 'variant_b.hex'}` | — |
| 154/1 | full | covered | verified | L int-65 GREEN; controls int-60 (f-string → RED at D3), int-61 (text changed → RED at D5) | — **text fix:** Expected says "verbatim and in order". The guard keys each site on its own trigger and checks no order between sites, and R-TST-154 asks for no order. Drop "and in order"; if it stays, the mark is partial. |
| 154/2 | full | covered | verified | L int-50…57: each RED with its own `did not settle: <Dn text>` | — (the probe only forces the predicate and a 3 s bound; the text comes from the real `settled` → `wait_until`) |
| 155/1 | **partial** | **partial** | verified | L int-65; int-62 (range loop → RED), int-63 (local `settled` → RED), int-64 (pre-fix guard GREEN) | **full → partial.** R-TST-155's threshold is "0 module-local wait helpers added to the four arms". The case narrows that to `_settled`, and the guard counts only `_settled` calls. The b94 module's own wait helper `_wait_for` (`tests/test_tui_flow_execution_b94.py:131`, a range-counted pause loop) is never checked, so a `_wait_for` call added to TC-B94-27 passes the guard. **Fix:** widen Expected to the requirement's words, forbid `_wait_for` calls in the guard and add one copy control that turns it RED. Otherwise rule it. |
| 156/1 | full | covered | verified | W int-70…89: 20 runs, 80/80 node runs, `77f4553`. Headers show `NO_COLOR` unset and LOCALAPPDATA, APPDATA, TEMP, TMP in scratch; USERPROFILE and HOME are set by `probes/i15int-win.sh`. | — |
| 157/1 | full | covered | **not_run** (as written) | Serial half: L int-03…05, 12/12. Parallel half: **not run**; int-01 is `-n 6` over the 3 changed files, not the lane `pytest -n 8 -m "not serial_timing"` | not_run kept. **Split:** 157/1 (serial) → `verified`; new 157/2 (parallel lane) → `covered` / `not_run` until the E5 gate run. E4 notes §3 says the same. |
| 158/1 | full | covered | verified | L int-65 `[R-TST-158]` PASSED; control int-66 RED `R-TST-158 sentence missing or edited` | — The placement, checked at review, holds: rule 7, "Seven rules". The Origin sits inline at the end of the rule, while R-TST-158 asks for "its own Origin line"; the review decides whether that is enough. |
| 159/1 | full | covered | verified | L int-03…05; W int-70…89 | — |
| 159/2 | full | covered | verified | L int-21…23 GREEN; int-24, 25 base RED `… got -0x1` | — |
| 160/1 | full | covered | verified | L int-03…05; W int-70…89 | — kept. The "shown" sign is the `hidden` class, which the handled-Apply Definition names. The handler writes it itself (`show_save_prompt`), so it is not a class standing in for a painted style. |
| 160/2 | full | covered | verified | L int-26…28 GREEN; int-29, 30 base RED `AttributeError … 'saved_path'` | — |
| 161/1 | full | covered | verified | L int-03…05; W int-70…89 | — kept. The state before the trigger already equals the expected result (`saved_path` `None`, 0 `.s19`). D7's sign and int-46 show the read is not vacuous. |
| 161/2 | full | covered | verified | L int-31…33 GREEN; int-34, 35 base RED at `prompt_hidden_after_decline` | — |
| 161/3 | full | covered | verified | L int-46 RED at `declined_saved_path is None` (`img-patched.s19` written); int-47 base RED earlier | — |
| 162/1 | full | covered | verified | L int-03…05; W int-70…89 | — kept (the reserved-name read gets the same reasoning; int-48) |
| 162/2 | full | covered | verified | L int-36…38 GREEN; int-39, 40 base RED at `traversal_path is not None` | — |
| 162/3 | full | covered | verified | L int-48 RED `a Windows reserved device name must be refused` (`CON.s19` written); int-49 base RED earlier | — |
| 163/1 | full | covered | verified | L int-65; int-58 (D1 removed → RED) | — **Inspection only** for the clause "a missing function or helper fails, never skips": every lookup ends in `assert` or `raise AssertionError` and there is no skip, but no run removes a helper. One copy control (`_confirm_with` renamed → RED) closes it. |
| 163/2 | full | covered | verified | L int-59 RED, naming `test_tc331… › _drive` and the trigger `panel.request_action('load_doc')` | — |

## Thresholds and negative controls per requirement

| Req | Threshold exercised | Negative control: cited RED |
|---|---|---|
| 150 | yes: D1 static (int-65); hold 3/3 (int-06…08) | (a) int-09, 10; (b) int-41 |
| 151 | yes: int-65; paste-only hold 3/3 (int-11…13) | (a) int-14, 15; (b) int-42 |
| 152 | yes: D3 on count 1 (int-65); `{}` (int-03…05, int-70…89) | int-44 RED; int-45 shows the base form's vacuous pass |
| 153 | yes: hold 3/3 (int-16…18); values as above | (a) int-19, 20; (b) int-43 RED on lane B |
| 154 | yes: static 8/8 (int-65); behavioural 8/8 texts (int-50…57) | int-60, int-61 |
| 155 | **partly**: shared wait 8/8 and 0 range loops yes; "0 module-local wait helpers" checked only for `_settled`, not `_wait_for` | int-62 (also int-63 RED, int-64 pre-fix GREEN) |
| 156 | yes: 80/80 node runs, W, `77f4553` | base TC-331 5 of 16 at `c2cba35` (`evidence-e1/win/run-04`, `05-1`, `05-3`, `06-1`, `06-3`); see O2 |
| 157 | **partly**: serial 12/12 yes; parallel lane **not run** | int-50…57 |
| 158 | yes: sentence (int-65); placement read here | int-66 |
| 159 | yes: hold 3/3 (int-21…23) | int-24, 25 |
| 160 | yes: hold 3/3 (int-26…28); 4 calls per arm run | int-29, 30 |
| 161 | yes: hold 3/3 (int-31…33) | (a) int-34, 35; (b) int-46, 47 |
| 162 | yes: hold 3/3 (int-36…38) | (a) int-39, 40; (b) int-48, 49 (Linux only) |
| 163 | 8/8 positions yes (int-65); no-skip clause by inspection only | int-59 (also int-58) |

## Proposed changes to `02-test-cases.md` (not applied here)

1. **R-TST-153/1:** Tests `full` → `partial`, Coverage `gap` → `partial`, Result → `verified`. The paint read goes through the `lane_paint_plain` seam. Needs a ruling or a rendered-lane assertion.
2. **R-TST-155/1:** Tests `full` → `partial`, Coverage `gap` → `partial`, Result → `verified`. Widen Expected to "0 module-local wait helpers (`_settled`, `_wait_for`)", then extend the guard and add one RED control, or rule it.
3. **R-TST-157/1:** Coverage `gap` → `covered`. Result stays `not_run` as written. Split it into /1 serial (`verified`, int-03…05) and a new /2 parallel lane (`not_run`, owed by the E5 gate).
4. **R-TST-154/1:** text only. Drop "and in order" from Expected.
5. **R-TST-163/1:** add one copy control (helper renamed → RED), or record that inspection accepts the no-skip clause.
6. **The other 21 cases:** Coverage `gap` → `covered`, Result `not_run` → `verified`, with the evidence above. Tests stays `full`.

## Totals

- **Cases:** 26 (13 normal, 13 robustness) over 14 requirements.
- **Audit marks as written:**

  | Mark | Count |
  |---|---|
  | Tests `full` | 24 |
  | Tests `partial` | 2 |
  | Coverage `covered` | 24 |
  | Coverage `partial` | 2 |
  | Coverage `gap` | 0 |
  | Result `verified` | 25 |
  | Result `not_run` | 1 |
  | Result `failed` | 0 |

  After the split (27 cases): 26 `verified`, 1 `not_run` (157/2).
- **Cases with a mark changed against the record:** 26 of 26 (100 %), because the record was never moved past E1.
- **Cases where the audit departs from a plain update:** 3 of 26 (11.5 %). Two are new findings (153/1 and 155/1, `full` → `partial`). The third, 157/1, has a run E4 had already flagged as owed.
- **Other notes:** text corrections in 154/1, 155/1 and 157/1; an inspection-only clause in 163/1.

## Observations outside the marks

- **O1 (code review).** TC-B94-27 is an arm Inc 15 changed, but it still reads `before_b`, `field_b` and `dirty_before_noop` after the Import presses with only fixed pauses: `_import_stem` ends in two `pilot.pause()`, then one more follows. Rule 7 (R-TST-158) forbids that in a changed arm, and the 8-site guard does not see it (scope ruling E3 F3). A late import fails loudly (`KeyError` / `NoMatches`), not vacuously. Decide between the D-6 backlog and a wait. Separately, `dirty_before_noop` is collected and never asserted; that predates Inc 15.
- **O2.** R-TST-156's base RED comes from E1 Windows transcripts. Their headers print `s19_app.__file__` but not the commit; `c2cba35` is stated in `E1-rulings.md` §2. Those runs used 2 nodes, and 2 of the 5 failures were under CPU load (`run-06`), so they are not "the same run" as the threshold. The 3 unloaded failures (`run-04`, `run-05-1`, `run-05-3`) still meet "≥ 1".
- **O3.** The D-3 cell of `E1-rulings.md` §4 still says "beside rule 2", as E3 and E4 already noted.

## Evidence checklist

| Item | Status | Evidence |
|---|---|---|
| Mode declared | ✓ | `validation`, at the top |
| Executor named for each result | ✓ | E4 integration step (orchestrator); this audit ran no test |
| Every case has a result word | ✓ | 25 `verified`, 1 `not_run` |
| Expected results are explicit | ✓ | 154/1 and 155/1 text fixes proposed |
| Negative controls carry a cited RED | ✓ | all 14 requirements; the gaps in 155 and 157 are named |
| No unfilled placeholders | ✓ | — |
| No real PII or secrets | ✓ | repository-relative paths only |
| Layer B | n/a | tests-only increment, 0 files under `s19_app/` changed (`git diff --name-only c2cba35 77f4553`) |

## Re-audit

**Mode: validation.** This is a re-audit of the changed items only, after rulings `E5-rulings.md` C-1 … C-10 and the corrective pass (`E5-corrective-notes.md`). The auditor is the qa-reviewer agent. The E5 corrective agent (Opus) executed every cited `e5c-NN` run: LAN Linux e5c-01 … 27 and Windows e5c-31 … 50. **This re-audit ran no test and imported nothing from `s19_app`.** It used only `git diff`, `sha256sum`, `grep` and reads of the transcripts, the tests and the installed Textual source.

**Verdict: 6 of the 7 re-checked cases hold as marked: 153/1, 153/3, 154/1, 155/1, 157/1 and 163/1. One case is over-marked. R-TST-157/2's Coverage should read `partial`, because its run is the lane's flags over 3 test files, not the release gate's lane. One trace is wrong. D9 is not covered by R-TST-153's text, so 153/3 needs its own requirement row. C-1 is correct: the other 21 rows carry the audited marks.**

### Commit identity

- Head `2af73ef` differs from `5edcb3f` only under `.dev-flow/` (`git diff --name-only 5edcb3f 2af73ef`).
- On LAN Linux, `git diff --binary c2cba35 5edcb3f -- tests docs | sha256sum` gives `15df472e7925f3a2…`. That matches the header of every `e5c-01 … 27` transcript.
- Windows e5c-31 … 50: all 20 headers read `git HEAD here = 5edcb3f92e17…` and place `s19_app.__file__` in the worktree. Each run has its own scratch `LOCALAPPDATA`, `APPDATA`, `TEMP` and `TMP`, and each shows `NO_COLOR set = False`. All 20 report `1 passed` with `rc=0`.
- Since `77f4553`, only `tests/test_suite_hygiene.py` and `tests/test_tui_flow_execution_b94.py` changed (`git diff --name-only 77f4553 5edcb3f -- tests s19_app docs`). So the `int-NN` results for the patch-editor arms still hold.

### Re-checked cases

| Case | Marks in the record | Re-audit | Basis |
|---|---|---|---|
| 153/1 | full / covered / verified | **holds** | The paint read now comes off the compositor through `painted_rows` (`b94.py:548-552`), so C-6 is met. GREEN in e5c-03 … 05 (3/3) and W e5c-31 … 50 (20/20). See note R1. |
| 153/3 | full / covered / verified | **marks hold; trace does not** | The hold is installed: e5c-07 … 09 end with `hold installed = fx_import[*] 1.5s` and are GREEN 3/3. The form at `5054743` fails at the "before" read, `KeyError: 'base_2'` (`e5c-10:110-121`, e5c-11). D9's sign is not vacuous: Textual 8.2.8 `Region.__bool__` returns `width * height > 0` (`textual/geometry.py:467-470`). For the trace, see below. |
| 154/1 | full / covered / verified | **holds** | "and in order" is gone. Static check: e5c-06 GREEN; e5c-24 (D9 removed) RED. The f-string and changed-text controls int-60 and int-61 ran on the `77f4553` guard. They still apply by inspection, not by a re-run: `_settled_description` (`hygiene.py:2244`) is unchanged, and it runs before the new predicate assert. |
| 155/1 | full / covered / verified | **holds** | The ban loops over `_settled` and `_wait_for` (`hygiene.py:2384`). e5c-22 is RED, naming `_wait_for`, and e5c-26 shows the pre-fix guard GREEN on the same edit. The predicate pins come from C-2: e5c-20 and e5c-21 are RED, and e5c-25 is the pre-fix guard GREEN. Expected now matches what the guard checks. See note R2. |
| 157/1 | full / covered / verified | **holds** | Serial runs: e5c-03 … 05 give 12/12 at `5edcb3f`, and int-03 … 05 give 12/12 at `77f4553`. |
| 157/2 | full / **covered** / verified | **Coverage → `partial`** | e5c-01 ran `-n 8 -m "not serial_timing"` over the 3 changed files: 129 passed. e5c-02 deselects 129 and keeps 1, the hygiene arm, which places the four nodes among the 129. The case's Objective and R-TST-157 both name the release gate's parallel lane, which is the whole suite. The case itself says that lane is still owed by the merge verification. So the result is `verified` for what ran and `partial` for the lane. The alternative is to reword the Objective to "the lane's flags over the three changed files" and record R-TST-157's lane clause as owed. |
| 163/1 | full / covered / verified | **holds** | e5c-23 (`_confirm_with` renamed) gives `nested _confirm_with missing`, 1 failed, 0 skipped under `-rs`. The missing-function half is covered by inspection only: `_arm_function` raises AssertionError (`hygiene.py:2207-2220`). The last-occurrence key (`max`, `:2359`) is safe because D1 … D8 have unique triggers. |

### Is D9 traced correctly to R-TST-153?

**No.** R-TST-153's requirement sentence did not change at E5. Its trigger is still "presses Bind with `variant_b.hex` on lane A", and its response is "read … only after the panel has handled that press".

D9 has a different trigger, the second `await _import_stem(…)`. It guards reads that happen before any Bind, so that sentence cannot cover them.

The E5 edit added D9 only to R-TST-153's Threshold and Negative-control cells. A threshold measures the shall-sentence; it cannot add a trigger the sentence does not name, and strict EARS allows one trigger per row. The gap was already latent at E1, when the "before" read sat in this threshold, but D9 now makes it a named wait.

R-TST-155 and R-TST-163 reach D9 only through "each wait of R-TST-150 … R-TST-153". **Fix:**

1. Add a new row, R-TST-164 (E): "When the TC-B94-27 arm imports `base` a second time, the test suite shall read lane B's bindings and box only after the panel shows lanes `base` and `base_2`."
   - Threshold: D9, plus the `fx_import` hold 3/3.
   - Negative control: (c), moved from R-TST-153.
   - User story: US-TST-15.
2. Move 153/3 to R-TST-164/2.
3. Split the "before" read out of 153/1 into a new case, 164/1, which cites e5c-03 … 05 and W e5c-31 … 50.
4. Extend the ranges in R-TST-155 and R-TST-163 to include R-TST-164.

That gives 15 requirements and 29 cases.

### C-1 (the other marks)

The other 21 rows carry `full / covered / verified`, the values this audit set:

- 150/1, 150/2, 151/1, 151/2, 152/1, 152/2, 153/2, 154/2, 156/1, 158/1, 159/1, 159/2
- 160/1, 160/2, 161/1, 161/2, 161/3, 162/1, 162/2, 162/3, 163/2

The rows for the changed TC-B94-27 arm now cite runs at `5edcb3f`:

- 152/1: e5c-03 … 05 and W e5c-31 … 50
- 152/2: e5c-16
- 153/2: e5c-12 … 14 and e5c-15
- 154/2: e5c-17 … 19
- 156/1: W e5c-31 … 50

I checked every cited `e5c` transcript against `e5c-index-linux.txt` and `e5c-index-windows.txt`.

### Notes (no mark change)

- **R1. The negative paint assertion has no failing control of its own.**
  - The check is `"variant_b.hex" not in paint_b` (`b94.py:578`). Mutant m153b (e5c-15) fails earlier, at the record assert on `:573`, and it never repaints lane B: `_rebind` repaints only `lane_index` (`flow_screens.py:4421`). So this assertion has only ever passed.
  - The painted `base.s19` is lane B's input box `#fx_in_1_0`, the SOURCE card's box (`flow_screens.py:3533-3538`). The paint read and the box read therefore observe the same widget.
  - A cheap control would close this: in a copy, add a mutant that also repaints lane B, and drop the record and box asserts.
- **R2. D9's trigger calls `_wait_for` internally.** `_import_stem` calls `_wait_for` at `b94.py:153-154`, a pause loop counted with `range`. The ban sees only direct calls in the arm, so it does not see these. The helper predates Inc 15 and is not "added to the four arms", so R-TST-155 holds. A late picker fails loudly (`… did not mount`), and Windows passed 20/20. This belongs in the D-6 backlog row.

### Totals after the re-audit

- 28 cases. Tests `full`: 28.
- Coverage `covered`: 27, plus 1 `partial` (157/2).
- Result `verified`: 28.
- One trace defect: D9 and case 153/3 → R-TST-164.

### Evidence checklist

| Item | Status | Evidence |
|---|---|---|
| Mode declared | ✓ | `validation` |
| Executor named | ✓ | The E5 corrective agent ran e5c-01 … 50. This re-audit ran nothing. |
| Results trace to the commit under test | ✓ | Patch sha256 matches. The Windows HEAD is `5edcb3f`. `2af73ef` changes only `.dev-flow/`. |
| Every re-checked case has a result word | ✓ | 7 of 7 `verified`. 157/2 coverage is contested. |
| No real PII or secrets | ✓ | Repository-relative paths only. |
