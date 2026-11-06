# Inc 15 — E5 independent code review (batch-101, Windows-only failures, tests-only)

Reviewer role: code-reviewer (correctness, simplicity, reuse, conventions, test intent). This reviewer also carries the security lens, because the increment changes 0 product files. **No separate security-reviewer ran for this increment.** Read-only: the reviewer applied no fix and committed nothing.
Scope: `git diff c2cba35 HEAD -- tests docs` on branch `b101-inc15` at `b0b429e`. That is 4 files: `tests/test_tui_patch_editor_v2.py`, `tests/test_tui_flow_execution_b94.py`, `tests/test_suite_hygiene.py` and `docs/engineering-rules.md`. `git diff --stat c2cba35 HEAD -- s19_app` is empty. `git diff 77f4553 b0b429e -- tests docs s19_app` is empty, so the head adds evidence only after the integration commit.
Design read: `01-requirements.md` (Definitions, table D, R-TST-150 … 163), `02-test-cases.md`, `E1-slice.md`, `E1-rulings.md`, `E3-rulings.md`, `E4-impl-notes.md`, `E4-integration-notes.md`. Evidence read: `evidence-e1/`, `evidence-e3/`, `../evidence/inc-15/` (the int-NN transcripts, both indexes, the probes).

## Verdict

**PASS-WITH-NOTES.** The record's token is *OK to advance*, with notes. There is no BLOCKER, HIGH or MAJOR finding. The record has 1 MINOR (design-gap) and 4 NIT. None of them blocks.

## Findings

| Id | Tag | Severity | Where | Finding | Fix | State |
|---|---|---|---|---|---|---|
| F1 | design-gap | MINOR | `tests/test_suite_hygiene.py:2119-2350` (`_INC15_WAIT_SITES`, `test_r_tst_154_155_inc15_arms_wait_through_settled`) | The static guard pins each wait's position, description and count, but not its predicate. Reviewer probe on planted copies: (a) D6's predicate changed to `lambda: True` leaves the guard GREEN. (b) D7's predicate swapped to D6's sign, `not prompt.has_class("hidden")`, also leaves it GREEN. That sign holds at once, because D6 left the prompt shown. Either edit turns its arm back into a one-pause read with CI still green. In case (b), the decline no-op reads (`saved_path is None`, no `.s19`) become vacuous again, which is the defect US-TST-16 exists to stop. The predicates are shown necessary only by the E4 holds and mutants, which ran once and are not in CI. R-TST-154, 155 and 163 do not ask for a predicate check, so this is a gap in the design, not in the implementation. | Add a sixth column to `_INC15_WAIT_SITES` with `ast.unparse` of each site's predicate. In the site loop, assert `ast.unparse(following.value.value.args[1])` against it, the same way the description is checked. Any change to a predicate then has to edit the guard table, where review sees it. If this is not done, record it as a limit in the R-TST-163 scope note. | executed (reviewer AST probe; the guard was extracted and run on planted copies) |
| F2 | impl | NIT | `tests/test_suite_hygiene.py:2246-2266` (`_pause_loops`) | Only `for … in range(…)` loops are counted. A planted `while …: await pilot.pause()` passes (probe GREEN). This matches R-TST-155's wording, and the 8 sites are already pinned, so it is a limit, not a defect. | Optional: count `ast.While` bodies that call `pilot.pause()` too. | executed (probe) |
| F3 | impl | NIT | `tests/test_suite_hygiene.py:2300` | `from collections import Counter` is imported inside the test. The module keeps its imports at the top (`:31-40`). | Move it to the module imports. | executed (read) |
| F4 | impl | NIT | `E1-rulings.md:58` (the D-3 cell) | The cell still says "one sentence beside rule 2". The file and R-TST-158 place the sentence as rule 7. E3 round 2 and the integrator both saw this, and it was left as is. | Correct the cell at close: "rule 7, after rule 6". | executed (read) |
| F5 | design-gap | NIT | `tests/test_tui_patch_editor_v2.py:60` and `:3039` | The module now offers both the shared `settled` and the module-local `_settled`, which is attempts-counted and was left out of scope by Inc 2. Rule 7 says "a shared wait", and the two near-identical names invite the wrong pick in a future arm. The guard forbids `_settled` only in the four named arms. This predates Inc 15. | No change in this increment. Add "retire `_settled` onto `tests.b97_probes.settled`" to the D-6 backlog row. | executed (read) |

## Checks that passed (no finding)

- **Each wait follows its trigger and reads a product sign.** Every check below is a read on head. No wait can hold before its trigger is handled. — executed (read).
  - **D1:** `source_path.name == "f.json"`. A fresh document has no source path.
  - **D2:** `source_path is None`. D1 has just shown a file-backed document.
  - **D5:** `source_path.name == "dropped.json"`. A fresh document has no source path.
  - **D6:** `#patch_saveback_row` without `hidden`. The row is composed hidden, and each D7 / D8 wait leaves it hidden again.
  - **D7 / D8:** the row with `hidden`. D6 has just shown it.
  - **Same handler.** The document replacement and the Edit JSON guard writers run in one synchronous handler (`app.py:4733` → `_patch_editor_load` `:7127` → load tail `:7191`, plus `:4929`). The decision handler hides the row before its decline return and before its synchronous `save_patched` (`app.py:5002-5005`). A read after a wait therefore sees the handler's whole result.
  - **D3 / D4:** these read the test's recorder around `FlowExecutionPanel._rebind`, which E3 F5 ruled is the design: the no-op rebind emits no product sign. `_rebind` has exactly one caller (`flow_screens.py:4392`, `self._rebind`, an instance lookup), so the instance wrapper sees every Bind. The wrapper appends only after the real step returns, so a press that is dropped, raises or is held never counts. The no-op early return is inside `_rebind` (`:4417-4418`), so the no-op press still counts.
  - **Failure modes are loud.** A rename fails at install with `AttributeError`. A changed call path fails as `did not settle` within the 60 s bound. No failure mode is vacuous.
- **The recorder cannot make an arm pass vacuously.** The E4 pair int-44 / int-45 (same-ref mutant with the `fx_bind` hold) turns the fixed form RED at the no-op assertion. The base form passes that assertion and fails later, at `after_a`. The hold sits at class level on `on_button_pressed`, above the instance recorder (E3 F5). — executed (read of the transcripts and `probes/i15int_guard.py`).
- **The static guard is exact.** The reviewer ran the guard by itself: its functions were extracted by AST and run with nothing imported from `s19_app` or `tests`.
  - **Current tree:** GREEN, no false positives.
  - **Reviewer controls, beyond E4's int-58 … 63:** D6 in `_apply` replaced by one pause, D8 in `_confirm_with` replaced by one pause, and D7 replaced by one pause all go RED, each naming its helper or `_drive`. A description passed as a keyword goes RED (strict, accepted). A site called as `other.settled(...)` goes RED through the per-arm count.
  - **E4 controls:** removal, move-after-read, f-string, changed text, `range` loop and module-local `settled` are each RED. The pre-fix guard is GREEN (int-64).
  - **Limits:** the guard does not check predicates (F1) and does not count `while` loops (F2).
  - — executed (reviewer probe; transcripts int-58 … 64 read).
- **No node renamed and no expected value changed.** An AST comparison of base and head over the 3 test files found the same top-level test names, plus the one new hygiene test. The `assert` statements of every existing test are identical. The diff only swaps `pilot.pause()` for `settled(...)`, and adds the import, the recorder and docstring lines. The conventions parametrize list gains `R-TST-158`, which adds one node id and changes none. — executed (AST diff).
- **Rule 7 matches R-TST-158 exactly.** The sentence is the same in `docs/engineering-rules.md:205`, in `_CONVENTION_RULES["R-TST-158"]` (the concatenated literal) and in R-TST-158. The section reads "Seven rules", rule 7 follows rule 6, and it has its own Origin, citing Inc 15 and R-TST-158. No other file or test pins "Six rules". Control int-66 (rule 7 deleted) is RED. — executed (read; grep).
- **Table D matches.** The 8 descriptions and 8 triggers in `_INC15_WAIT_SITES` equal table D word for word, and the per-arm counts are 2 / 2 / 1 / 3. — executed (read).
- **Reuse and simplicity.** All 8 waits use the shared `tests.b97_probes.settled` → `wait_until` (pause first, a 60 s wall-clock bound, `did not settle: <description>`). The recorder is a 6-line local wrapper. The suite has no shared call-recorder utility, and local spies are the norm (for example `test_b100_document.py:151`, `test_b100_load_dialog.py:608`). `add_entry` correctly gets no wait (the TC-051 note in the records). No new file, no product file, no abstraction. — executed (read; grep).
- **Docstrings.** Each changed arm cites its R-TST ids, and the new guard test cites R-TST-154, 155 and 163. — executed (read).

## Security lens (carried here; no separate security reviewer)

- **Committed evidence is redacted.** Every added line of the 165 changed files was scanned. Patterns: home and drive paths, the account name, the operator's name, host names, `192.168.*` and other private ranges, kernel and `uname` strings, mail addresses. Result: 0 hits. The remaining tokens are only the placeholders `<HOME>` (231 times), plus `<USER>`, `<HOST>` and `<LAN-LAPTOP>` (2 each, in the records that explain the redaction). Beyond those: scratch paths under `/tmp/`, the interpreter path `/data/miniconda3/envs/s19ci` (no user or host in it), and pytest's `platform linux` / `platform win32` (no kernel string). A job id appears under `<HOME>`, which identifies nobody. — executed (grep).
- **The Windows runs were isolated.** Each header of int-70 … 89 prints `LOCALAPPDATA`, `APPDATA`, `TEMP` and `TMP` in that run's own scratch folder. `probes/i15int-win.sh` also points `USERPROFILE` and `HOME` there and sets `--basetemp` there. `NO_COLOR` is unset. The runner aborts unless `s19_app.__file__` is in the worktree. Only the 4 named nodes ran. The E1 Windows runs follow the same rules (`evidence-e1/probes/i15-run.sh`). — executed (read).
- **The clipboard was never written.** The guard replaces `write_os_clipboard`, the 3 writers and `_WRITE_STRATEGIES`. The only OS write path, `_mirror_and_write_os_clipboard` (`os_clipboard_input.py:769`), looks up `write_os_clipboard` when it is called, so the guard covers it. None of the four arms calls a copy or cut action. All 20 Windows runs passed with the raising guard installed. — executed (read).
- **The tests do not write outside tmp.** Every arm builds the app with `base_dir=tmp_path`. The traversal and absolute names are asserted to stay inside the work area; those assertions are unchanged. In the reserved-name mutant, `CON.s19` was written under `/tmp/i15int/runs/int-48/bt/…/workarea` (int-48), inside basetemp. All mutants and holds ran in rsync copies under `/tmp`, never in the worktree. The probes are loaded from outside the tree with `-p` and change no file. — executed (read of the transcripts and probes).
- No product code, dependency, network call or secret is touched. — executed (diff read).

## Owed elsewhere (not this lane)

- **R-TST-157's parallel half.** E4 ran the 3 changed files with `-n 6` (int-01: 129 passed, every non-serial node of those files). The release gate's whole-suite `pytest -n 8 -m "not serial_timing"` plus the serial lane is E5's gate run (qa-reviewer). State: `planned`.
- **The test-case results.** `02-test-cases.md` still reads `gap` / `not_run` in every row, and `04-validation.md` is absent. Both are E5 validation's. State: `planned`.

## Evidence checklist

- [x] **Diff read in full:** `git diff c2cba35 HEAD -- tests docs` (4 files, +329 / -10). That covers `test_suite_hygiene.py:105-113, 635-638, 2108-2350`, `test_tui_flow_execution_b94.py:30, 481-538`, `test_tui_patch_editor_v2.py:60, 529-616, 1570-1622, 3527-3586` and `engineering-rules.md:196, 205`.
- [x] **Correctness pass:** every wait's pre-state and handler path checked against `app.py:4733-4934, 4990-5005, 7054-7191` and `flow_screens.py:4380-4425`. No finding.
- [x] **Simplicity pass:** no premature abstraction. F3 is style only.
- [x] **Reuse:** the shared `settled` everywhere, and local spies by convention. F5 is a pre-existing naming hazard.
- [x] **Tests reviewed for intent:** the no-op arms are made non-vacuous (int-44 / 45, int-46 / 47, int-48 / 49 read). The guard's predicate gap is F1.
- [x] **Verdict explicit:** PASS-WITH-NOTES. No HIGH is open, so none needs applied-and-verified evidence.

## Independent review cell (packet §4b)

`code-reviewer` · PASS-WITH-NOTES (OK to advance, with notes) · no HIGH raised, so none to resolve. F1 (MINOR, design-gap) is recommended: pin each wait's predicate in the guard table. F2–F5 are NIT. Security lens carried by this reviewer (tests-only, 0 product files); no separate security-reviewer ran.
