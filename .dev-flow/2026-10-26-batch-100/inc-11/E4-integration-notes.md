# Inc 11 — E4 integration notes (the Save project dialog)

Stage E4, integration step. Inputs read: `E4-dialog-notes.md` (G-A), `E4-app-notes.md` (G-B), `E4-tester-notes.md`, `codewire/interfaces-11.md`, `codewire/proto-11-app.md`, `codewire/proto-11-dialog.md` (S6 / S9 / K21), `E3-rulings.md` (rounds 1–3), `E3-security.md` (S11-04), `E1-requirements-draft.md` (LLR-175.1, .1c, .1p, .4b). Worktree `<HOME>/Github/s19_app-b100-inc11` on `1747479` plus the uncommitted Inc 11 change. Evidence states use the seven words only.

## Result

The tree is GREEN on the targeted runs. See §Final pass counts. One source change was made (SR-11-1, in `app.py`). Seven test-side fixes were made: five in `tests/test_b100_save_dialog.py` (F-2 to F-5, F-8), one at two drive sites in `tests/test_b99_staging.py` (F-6, F-7), and the census bound in `tests/test_id_registry.py` (F-9). None of them weakens an oracle.

## Failures met

The first diagnostic run was split over 4 parallel shards for the new file plus 1 run for the re-pins (scratch transcripts, not kept as evidence). It found 7 failures. Each is judged against the graph and the requirements.

| # | Node | Cause | Who is wrong | Fix |
|---|---|---|---|---|
| F-1 | `SD::test_tc_b100_47_strasse_open_strasse_eszett_present_is_a_clash` | Typed `straße` with `strasse` open painted `strasse — updates the open project`, not `merges into an existing project`. Probe `evidence/inc-11/int-probe-strasse.py.txt` → `int-probe-strasse.out.txt`: `DIRECT 'strasse' None open project`. The G10 loop sees `strasse` (the open project, file identity) first in the sorted listing. It rebinds `cleaned` to `strasse` (LED .52(a)) before it reaches the exact folder `straße`. | **Graph** (inconsistent). The G10 step text ("only then `cleaned = item.name`") contradicts the graph's own example B11-82 ("Typed `straße` (its exact name) → `merges into an existing project`"). The code follows the step text. The test follows the example. LLR-175.1 says the painted folder is the sanitised name, with LED .52(a) as the only rebind. | **Code, smallest fix, seam ruling SR-11-1.** The rebind is deferred until after the loop. It applies only when no folder holds the exact typed (sanitised) name: `exact_folder` / `open_spelling` (`app.py:10460`–`:10504`). Every other case is unchanged: `ab` typed with `Ab` open still rebinds, because NTFS lists only `Ab`. `strasse` typed is still the S11-01 clash. |
| F-2 | `SD::test_tc_b100_65_save_before_the_preview_is_shown_repaints` (S11-04, fakes) | `confirm` received the painted plan, not `None`, and the dialog dismissed. Probe `evidence/inc-11/int-probe-shown.py.txt` → `int-probe-shown.out.txt`: event order `['post', 'paint', 'mark', ('save', True)]`. The `alt+s` posted to the app inside the first `preview` call is processed AFTER the screen's refresh, so `_mark_shown` has already run. | **Test** (the stimulus does not produce the precondition). The code is exactly the graph (proto-11-dialog S9 step 1, S6 step 1). In Textual 8.2.8, a key queued on the app during the freeze did not run before the next frame in this probe, contrary to E3-security S11-04's reading. | The fake now queues the Save on the dialog itself: `post_on_first=lambda: screen.call_next(screen.action_save)`. That runs after the current message and before the refresh, so the oracle (`confirm(name, None)`, 0 dismisses, `the summary changed`, a second `alt+s` saves) is unchanged. **Negative control executed:** the mutant `painted = self._plan` (M-20) → `1 failed in 3.64s` with `('fresh1', SavePlan(...))` (`evidence/inc-11/int-mut-M20.txt`). Source restored from a byte copy; CRLF re-checked. See seam ruling SR-11-2. |
| F-3 | `SD::test_at_b100_16_save_dialog_open_folder_clash_empty_escape[size1]` | `out["folder"] == 's — new folder'`. After typing `a b`, the wait token `new folder` was already present in the stale paint for `s`, so the wait returned before the debounce. It passed at `size0` by timing. | **Test** (race on a stale paint). | Wait with the test's own predicate `_where_line_for_text(..., "ab", "new folder")`, then settle. The oracle is unchanged. |
| F-4 | `SD::test_tc_b100_47_disguised_clash_names_both_and_exact_name_merges` | The `AB` arm read the `a b` refusal: the CLASH tokens were already painted. | **Test** (same race). | The wait also requires `'AB'` (the typed name quoted). The oracle is unchanged. |
| F-5 | `SD::test_tc_b100_47_name_cap_64_65_300` | The 64 arm timed out on `new folder`. Its work area under the mandated short `--basetemp` (about 170 characters) plus 1 + 64 + 53 exceeds `_SAVE_FULL_PATH_LIMIT` 259, so G9 `path too long` fires first. The 64 arm needs a work area of at most 141 characters, which no temp root under the scratchpad gives. (The tester never ran it GREEN; RED-01 timed out for another reason.) | **Test** (environment assumption). The code is right: G9 is a separate rule, LLR-175.1e. | The test lifts `_SAVE_FULL_PATH_LIMIT` to 10 000 with `monkeypatch`, and the docstring says why. LLR-175.1e keeps its own test, `test_tc_b100_47_path_limit_met_and_exceeded`, which is GREEN. |
| F-6 | `tests/test_b99_staging.py::test_tc_b99_ux_c10_save_project_filename_renders_literally` | `NoMatches '#project_name'`. The drive calls `app.action_save_project()` and waits only until the screen type is on the stack, before compose. | **Test** (re-pin race). | Both drives now wait for `is_save_dialog(app.screen) and app.screen.query("#project_name")`. |
| F-7 | `tests/test_b99_staging.py::test_tc_b99_ux_c10_placement_error_path_renders_literally` | Same as F-6. | **Test.** | Same as F-6. |

After the fixes, all 7 nodes plus the AT size0 arm were re-run together: `8 passed in 79.91s` (`evidence/inc-11/int-refail-diagnostic.txt`, diagnostic). The evidence runs below are separate complete runs.

The first complete evidence run of the new file then failed once. It is kept as `evidence/inc-11/green-01-new-run1-failed.txt` (`1 failed, 153 passed in 1422.97s`) and is reported as **failed**, not passed:

| # | Node | Cause | Who is wrong | Fix |
|---|---|---|---|---|
| F-8 | `SD::test_tc_b100_65_save_executes_the_painted_plan[files]` | `prepared.plan is painted_plan` was false, with equal content. In the `files` scenario the prefilled name `P` equals the typed name `P`. `_scenario_paint` read `screen.plan` while the initial paint for the prefill still satisfied the wait tokens. The debounce for the retyped `P` then repainted an equal plan as a new object, and that object was the one confirmed and committed. In the diagnostic shard the same node passed, by timing. | **Test** (race on a stale paint of identical text). The code is right: the commit received exactly the plan last painted (`payload.plan is prepared.plan`). | `_scenario_paint` waits for the recompute (`sd.wait_recompute`) after typing, before it reads the painted plan. This applies to every caller (TC-B100-65 rows / executed plan, AT-B100-21). The identity oracle is unchanged. |

The re-run `green-01-new.txt` is a second complete run of all 154 ids.

The first complete guards run also failed once. It is kept as `evidence/inc-11/guards-01-run1-failed.txt` (`1 failed, 248 passed, 4 skipped in 1282.70s`) and is reported as **failed**:

| # | Node | Cause | Who is wrong | Fix |
|---|---|---|---|---|
| F-9 | `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` | `the guard scanned 233 test modules, not the declared 231`. The tester added two test modules: `tests/test_b100_save_dialog.py` and `tests/support/b100_save_dialog.py`. | **Test** (the declared bound was not bumped; legitimate growth, as in Inc 7, 8a, 9b and 10). | `EXPECTED_SCANNED_TEST_FILES` 231 → 233, with a history line naming the two files. |

The 4 skips in the guards run are `tests/test_b100_load_dialog.py:377` "the volume refuses this name (reported not run)" (MAX_PATH under the scratchpad temp root). They are `not-run`, never passed. The same 4 skips appear in Inc 9b's own evidence (`evidence/inc-9b/green-04-new-and-guards.txt`).

Noted, not changed: in `test_tc_b100_47_name_cap_64_65_300` the 300 arm can read the 65 arm's paint, because the two refusal texts are identical. The arm cannot fail wrongly, but it cannot tell the two paints apart. Route: `qa-reviewer`.

## Deviation dispositions

| Group | Deviation | Disposition |
|---|---|---|
| G-A 1 | `id="load_dialog"` census: 6 → 5 on this tree, not the graph's 8 → 7 | **Accept.** The −1 holds. R1-1 was not turned into a test (tester notes), so nothing to re-pin. |
| G-A 2 | `_collect_composition` docstring `Used by` updated | **Accept.** Docstring only; the graph's Callers table moves the caller. |
| G-A 3 | throwaway names `_text` / `row` instead of `_t` / `r` | **Accept.** Not behavioural. |
| G-B 1 | `PurePosixPath(entry.relative).name` for the graph's `c.relative.name` | **Accept.** `InventoryFile.relative` is a `str`. This is the only correct reading (B11-76). |
| G-B 2 | `_match_identical` imported bare, called as `_workspace._match_identical` | **Accept.** The graph's import line and A11-03 both hold. The unused bare import is harmless: there is no lint gate, and the TC-B100-59 census counts modules. |
| G-B 3 | S11-11 memo as the sentinel key `_DOCUMENT_UNREADABLE_KEY = Path("<unreadable-change-document>")` in the session's `digests` dict | **Accept, judged carefully. No collision, no leak.** (a) The key cannot equal a real key. The real keys are the absolute paths of the loaded image, MAC and A2L. The sentinel is a relative path holding `<` / `>`, which Windows forbids in a file name. (b) It cannot reach the plan. `session.digests` is read only through `_digest(path)` (`app.py:12065`), which looks up those three real paths. The mapping is never iterated, compared, serialised or passed to the planner (grep: one producer `_save_session_inputs`, one consumer `_plan_project_save`). (c) The memo lives exactly one dialog open: the router drops the session, and the next open builds a fresh dict. The lazy-inventory `replace(...)` shares the same dict object. Costs, declared: it writes into a `Mapping` held by a frozen dataclass, and its value `(0, 0)` is not a digest. A private set on the app would add a fourth per-open attribute, three more reset sites and a TC-B100-09 re-pin, for no observable gain. Not replaced. The orchestrator may overrule (see SR-11-3). |
| G-B 4 | `occupants` dict values (size, path) never read | **Accept.** Kept verbatim per the graph. `_match_identical` re-stats and re-hashes (S11-09), so only the keys matter. |
| G-B 5 | `_refused` neutral `image_step` when `session is None` | **Accept.** On the direct path the name rules run before the session (A11-09). Only `refusal`, `toast` and `plan` are read on a refused save. |

## Orchestrator rulings on the tester's ambiguities (bind; recorded here)

1. The B11-25 `[b]P` arm is re-pinned to `[b]a b` against `bab`, as the tester did. The threshold text is corrected at close. — `SD::test_tc_b100_65_names_are_painted_literally`: GREEN in green-01.
2. The emitted image row paints `firmware.s19 → firmware_1.s19 — new`. R2-05 paints a rename whenever `source.name != landing.name`, so the test is right. — G-B agrees: `_plan_project_save` gives the emitted row `source = loaded.path` and `landing = image_step.name`, and `_compose_save_preview` paints the arrow on `row.source.name != row.landing.name` (`app.py:10876`). `SD::test_tc_b100_65_summary_rows_equal_the_plan`: GREEN. G-B needed no fix.
3. LLR-175.5 follows B11-36: an emitted image is not digested. The text is corrected at close. — `_save_session_inputs` digests the image only when `not image_step.emit` (`app.py:10739`). `SD::test_tc_b100_65_session_decided_once_per_open_case06`: GREEN.
4. `_save_painted_preview` is a private app attribute. Accepted; TC-B100-09 classifies it. — `tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census`: GREEN.
5–7. Accepted as the tester wrote them.
- Inc 10's E5 corrective pass on `b100-inc10` was not ported here. It arrives by merge before Inc 11's E5.

## Seam rulings to confirm

- **SR-11-1 (graph inconsistent; code changed).** The LED .52(a) rebind to the open project's on-disk spelling applies only when no work-area folder holds the exact typed (sanitised) name. Typed `straße` with `strasse` open and `straße` present → target `straße`, kind `merges into an existing project` (B11-82). Typed `strasse` → the S11-01 clash, unchanged. Typed `ab` with `Ab` open → `Ab`, unchanged. Proposed text fix at close: proto-11-app G10's rebind sentence gains "unless a folder holds the exact typed name"; LLR-175.1 may gain the `straße` arm.
- **SR-11-2 (finding; no code change).** S11-04's premise did not reproduce in Textual 8.2.8. A key posted to the app during the first preview's freeze was processed after the refresh, so the dialog had already marked the preview shown (event order `post, paint, mark, save(shown=True)`). The `_shown` guard therefore works as defence in depth: it holds against a Save queued on the dialog before its refresh, as the corrected test proves. The orchestrator decides whether the guard stays (prefer removal) or the S11-04 text is narrowed. The test stimulus now uses `screen.call_next(screen.action_save)`.
- **SR-11-3 (deviation G-B 3 kept).** The S11-11 memo stays a sentinel key in the per-open `digests` dict. Confirm, or rule the private-set alternative. That alternative adds one app attribute, its three reset sites (`action_save_project`, the router), and a TC-B100-09 classification.

## Final pass counts

Each count is read from one complete run's own summary line. green-02 ran in parallel with guards run 1. green-01 (both runs) ran alone. No timing arm failed in any evidence run; F-8 is a stale-paint race, not a timing threshold. Every transcript prints `s19_app.__file__` = `<HOME>\Github\s19_app-b100-inc11\s19_app\__init__.py` at its top.

| Run | Transcript | Result | State |
|---|---|---|---|
| New tests (`tests/test_b100_save_dialog.py`, 154 ids) | `evidence/inc-11/green-01-new.txt` | `154 passed in 1472.86s` | executed (run 1, `green-01-new-run1-failed.txt`: `1 failed, 153 passed` — failed, F-8) |
| Re-pinned nodes (24 functions, 35 ids) | `evidence/inc-11/green-02-repinned.txt` | `35 passed in 580.43s` | executed |
| Guards (`test_id_registry.py`, `test_b99_staging.py`, `test_engine_unchanged.py`, `test_b100_load_question.py`, `test_b100_load_dialog.py`; 253 ids) | `evidence/inc-11/guards-01.txt` | `249 passed, 4 skipped in 1227.74s` | executed; the 4 skips `not-run` (MAX_PATH) (run 1, `guards-01-run1-failed.txt`: `1 failed, 248 passed, 4 skipped` — failed, F-9) |

Not run, by the operator override of 2026-10-31: whole touched modules, the full suite, the 56 + 1 direct `_handle_save_dialog` call lines (`not-run`, owed to the batch-end battery). Mutation: only M-20 was `executed` (killed); the other rows of `E4-mutant-candidates.md` are `planned`.

## Source sha256[:16] (post-integration)

| File | sha256[:16] |
|---|---|
| `s19_app/tui/app.py` | `d8f3b2b38327fbc3` |
| `s19_app/tui/screens.py` | `3d1d07526bcafd5a` |
| `s19_app/tui/styles.tcss` | `038fd8dbc034373e` |
| `s19_app/tui/services/project_gather_service.py` | `e11a5e75d7346183` |

Source files touched by this step: 1 (`app.py`), within the 4-file set. Test files touched: `tests/test_b100_save_dialog.py`, `tests/test_b99_staging.py`, `tests/test_id_registry.py`. Line endings: all four sources stay CRLF with 0 bare LF (checked by byte count).

## Orchestrator rulings on the seam rulings (E4 close)

| Id | Ruling |
|---|---|
| SR-11-1 | **Accept.** The LED .52(a) rebind applies only when no folder holds the exact typed name. Text fix at close: proto-11-app G10 rebind sentence; add a `straße`-typed-with-`strasse`-open arm reference under LLR-175.1. |
| SR-11-2 | **Keep the `_shown` guard** (it defends a save queued on the dialog itself; M-20 kills it). Narrow the S11-04 text at close to "a save queued on the dialog before the first paint is marked shown". |
| SR-11-3 | **Keep the sentinel key**, declared as a deviation (cannot collide, never iterated). Open to the E5 reviewers; a reviewer finding with a concrete failure overrides this. |
| name_cap 300 arm | Route to the E5 corrective pass: make the 300 arm wait on a paint change it can tell apart (or assert the field value cap). |
