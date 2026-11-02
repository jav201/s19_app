# Inc 9b — E4 integration notes

Integration step of batch-100 Inc 9b (the unified Load dialog). Inputs: `E4-dialog-notes.md` (G-A), `E4-app-notes.md` (G-B), `E4-tester-notes.md`, `codewire/interfaces-9b.md`, both prototypes, `E3-rulings.md` (rounds 1–3; the Round 3 addenda bind) and `E1-requirements-draft.md`.

Run environment: `<HOME>/anaconda3/envs/s19env/python.exe` (Python 3.11.15, textual 8.2.8), `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. LOCALAPPDATA=<scratch int9b/lad>`. Every transcript prints `s19_app.__file__` (the worktree) in its header and, in its footer, whether the real `%LOCALAPPDATA%\s19_app` exists (it does not, in every run).

Scope of runs (operator override 2026-10-31): the new test file, the re-pinned nodes and the guards only. The whole touched modules and the full suite are `not-run` here; they belong to the batch-end battery.

## 1 · Failures met, cause and fix

Trial runs (scratch, not evidence): `try-01-new.txt` (new file: 1 failed, 132 passed), `try-02-repinned.txt` (re-pinned set: 5 failed, 123 passed), a guard trial (1 failed, 13 passed).

| # | Failure | Cause (who disagrees with the graph) | Fix |
|---|---|---|---|
| F1 | `test_tc_b100_64_preview_line_never_wraps`: the 300-character preview line painted 7 rows, not 1. | **Graph (mechanism).** C4 puts `text-wrap: nowrap; text-overflow: ellipsis` on `#load_preview`, the `VerticalScroll`. In Textual 8.2.8 neither property is inherited (they are not in the inherited rule set), so the body `Static` kept wrapping. The graph's K9 probe measured the rule on `#load_list`, where the rule sits on the widget that renders the text. | `styles.tcss`: a new rule `#load_preview Static { text-wrap: nowrap; text-overflow: ellipsis; }` with a one-line reason. The `#load_preview` rule stays as the graph wrote it. Seam ruling SR-1. |
| F2 | `tests/test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound`: 230 scanned, 228 declared. | **Test (bound not bumped).** The tester added `tests/test_b100_load_dialog.py` and `tests/support/b100_load_dialog.py`; the guard's own message prescribes the bump in the same change. | `EXPECTED_SCANNED_TEST_FILES` 228 → 230 with the measured-not-incremented note. |
| F3 | Three TC-B100-61 timing arms (`files_at_the_cap_all_missing_are_bounded`, `sec6_5_distinct_folders_stop_at_the_folder_ceiling`, `sec6_5_junction_loop_costs_one_failure`): `painted` 1.02–1.32 s against the 1 s bound. | **Test (re-pin moved the clock).** On the base, the project pick's dismiss callback ran the load inside the `#project_ok` click, so the clock (`pressed`, taken after the click) started after the load. The graph's one router defers every load with `call_after_refresh` (LLR-173.1e, B07), so the load now runs after the click and fell inside the paint window. Measured on the base tree with the base test file: `painted` 0.00 s / 0.937 s / 0.001 s, `load` 0.20 / 0.46 / 0.10 s; on 9b `load` + paint add up to the same total. The code agrees with the graph. | `tests/test_b100_project_check.py`: each timed `_handle_load_project` wrapper stamps `app._load_returned_at`; the paint clock starts at `max(pressed, _load_returned_at)` (`_paint_clock_start`). The load keeps its own 1 s bound. This restores the base meaning of the bound and is now stricter than the base for the files-at-cap arm (the base measured 0.00 s there; 9b now measures the real paint, 0.76 s). |
| F4 | `tests/test_b99_load_project.py::test_at_b99_13_project_and_file_pickers_load_by_name` (empty-boundary scene): `#load_reason` not found after `enter` — the dialog had closed and loaded. | **Test against H-1 / LLR-173.2b.** With 0 projects the dialog highlights the first loadable row (interfaces H-1, B05 arm 3). The scene had just loaded `a.s19`, so the Work area section holds `a.s19`, which was highlighted, and `enter` loaded it. The `nothing selected` arm the re-pin expected needs no loadable row. | The scene now asserts the H-1 fallback (`highlighted_prompt == "a.s19"`), moves to the empty path field with `shift+tab`, and presses `enter` → `nothing selected` (LLR-173.2h); the dialog stays; `escape`; the file stays loaded. LLR-173.2i stays covered by `test_tc_b100_41_no_loadable_row_highlighted_is_explained`. |
| F5 | `tests/test_tui_directionb.py::test_ac7_workspace_load_project_button`: flaky, 3 of 6 runs RED (`pushed` False), and in the batch run a teardown `NoMatches: '#load_list'` from `LoadDialog.on_mount`. | **Test (one pause).** One `pilot.pause()` after `button.press()` did not always deliver the `Pressed` message; the app then shut down while the dialog was mid-mount, so `on_mount` ran on a screen whose children were never composed. Alone, and in a 5-pause debug drive, the dialog is on top with its list focus at the first pause. No user path reaches the mid-mount shutdown. | A bounded wait (≤ 200 pauses) for the dialog with its `#load_list` focus. 6 of 6 GREEN after the fix. |

No failure was caused by the code disagreeing with the graph.

## 2 · Implementer deviation dispositions

| Deviation | Disposition |
|---|---|
| G-A: none declared. Transcription notes 1 (typed `query_one(..., Input)`) and 2 (three-pass `_initial_index`). | Accepted. Same widget and the same H-1 rule; the H-1 arms pass (`test_tc_b100_41_list_opens_on_the_open_project`, `…_falls_back_to_the_first_project`, and the AT-B99-13 fallback assert). |
| G-B 1: `validate_project_files` stays imported. | Accepted (orchestrator ruling). Seven call sites outside the 9b slice still use it; the graph's "leaves the import" line is corrected at close, and the sweep is Inc 12a (A9b-R3-3). |
| G-B 2: `_list_project_files` returns a 3-tuple. | Accepted. A9b-R3-4 binds over the node header. |
| G-B 3: the S9b-2 gate sits before `_reset_project_session()`. | Accepted. B99 / A9b-R3-5 require the session unchanged on the refusal; the graph line "before any manifest read" is satisfied as well. |
| G-B 4: the A2L "not readable" log carries the reason word, not the exception class. | Accepted. Log-only; no painted string changed (A9b-R3-2 strings verbatim). |
| G-B 5: a non-`FileNotFoundError` `OSError` on the preview's `project.json` lstat paints `could not be read`. | Accepted. Same outcome as `_handle_load_project`'s gate and the preview's outer catch; R3-1 (an absent file is not a refusal) holds. |
| Undeclared: `_folder_holds_project` lists the whole folder through `_list_project_files`; R3-4 says it "stops at the first data, MAC or A2L entry … but does not list the whole folder". | **Kept as written; seam ruling SR-2.** The graph node (step 2) and the examples B19, B22 (spy on `_list_project_files`), B23 and A9b-R2-4 / R2-N4 (inject into the named scan helper) all require the call to go through `_list_project_files`; an early-stop scan of its own would bypass those injections. The verdict is identical (True / False / None); the cost is one full metadata scan of a folder with no regular `project.json`. |

## 3 · Orchestrator rulings on the tester's ambiguities (binding, recorded)

1. LLR-173.1g is injected through `_list_project_files`, as B96 does; the threshold text is corrected at close.
2. LLR-173.4i "full recorded path" means the preview's content text, not the clipped painted strip. S9b-8 governs painting; the text is corrected at close. (With F1 fixed, the painted line is now one row with an ellipsis; `test_tc_b100_43_recent_preview_shows_the_store_facts_only` reads the content text and passes.)
3. B14 is as the tester wrote it: the arms start from a stale input and from the P-16 shape, because a visible Find input keeps its focus (pinned by `test_tc_b100_12_visible_find_input_keeps_its_focus`).
4–8. Accepted as the tester wrote them.
9. `_COLLIDING_PATH` in `tests/test_loadfilescreen_input.py` is pre-existing (batch-29). Left as is; backlog item to replace it with `username_subject`.

## 4 · Seam rulings to confirm

- **SR-1 (F1, styles.tcss).** The graph's C4 nowrap on `#load_preview` does not reach the body `Static` (no inheritance in Textual 8.2.8). Added `#load_preview Static { text-wrap: nowrap; text-overflow: ellipsis; }`. Confirm, and correct C4 / S8-9 / C4-5 in the prototype at close.
- **SR-2 (`_folder_holds_project`).** R3-4's "does not list the whole folder" conflicts with the graph node and with the R2-N4 injection examples (B19, B22, B23). Kept the graph's call through `_list_project_files`. Confirm, or rule the early-stop scan (which would need the B19 / B23 injections moved to `os.scandir`).
- **SR-3 (F3, test clock).** TC-B100-61's paint bound starts when the timed load returns (the base meaning). Confirm that the bound is "the panel paints under 1 s after the load", not "click to panel under 1 s" (the latter is RED at 1.02–1.32 s on 9b and was never measured on the base).
- **SR-4 (F4, AT-B99-13 empty boundary).** With 0 projects, the highlight falls back to a work-area row (H-1), so the scene proves "nothing selected" through the empty path field (LLR-173.2h), not through "no loadable row" (LLR-173.2i). Confirm.
- **SR-5 (observation, no change).** `LoadDialog.on_mount` raises `NoMatches` if the app shuts down between the push and the compose (seen only in F5's test teardown). No user path reaches it; no guard added (decision rule: no handling for scenarios that cannot happen). Confirm.
- **SR-7 (SEC6-5 timing margin).** The TC-B100-61 SEC6-5 arms run at 0.8–1.03 s against a 1 s bound on this host, on the base and on 9b (§5). One `green-02` run failed at 1.033 s; three reruns passed. No 9b code path is inside the `appended` clock, and the paint clock now excludes the load (SR-3). Decide whether the batch-end battery runs these arms on a quiet host, or whether the bound or `timing_bound`'s factor is revisited (outside 9b).
- **SR-6 (observation).** Five test files show as modified in `git status` with an empty content diff (`test_b99_a2l_encode.py`, `test_b99_bytes_field.py`, `test_b99_corpus.py`, `test_b99_editor_image.py`, `test_b99_s0.py`): line-ending stat noise from the tester's copy. They hold no re-pin; leave them out of the commit or let git normalise them.

## 5 · Final pass counts

| Transcript | Scope | Result | State |
|---|---|---|---|
| `evidence/inc-9b/green-01-new.txt` | `tests/test_b100_load_dialog.py` (every test) | **133 passed**, 0 failed, 0 skipped (9 min 23 s) | `executed` |
| `evidence/inc-9b/green-02-repinned.txt` | the re-pinned nodes plus the 6 new functions in `test_b100_recents.py` / `test_b100_focus.py` (128 items; node list = every test function whose body, or a same-file helper it reaches, changed in the tester's diff) | **127 passed, 1 failed**, 0 skipped (19 min 44 s). The failure: `test_tc_b100_61_sec6_5_distinct_folders_stop_at_the_folder_ceiling`, `painted` 1.033 s against 1.0 s (timing). | `failed` (1 timing arm) |
| `evidence/inc-9b/green-02b-timing-rerun.txt` | that one node, 3 separate runs with `-s` | **3 of 3 passed**: `painted` 0.864 / 0.932 / 0.001 s, `appended` 0.834 / 0.807 / 0.834 s | `executed` |
| `evidence/inc-9b/guards-01.txt` | `tests/test_id_registry.py`, `tests/test_b99_staging.py`, `tests/test_engine_unchanged.py` (the frozen-engine guard) | **45 passed**, 0 failed, 0 skipped | `executed` |

**The SEC6-5 timing arm is flaky near its bound on this host, on the base as well.** Four base runs of the base test file measured `painted` 0.613 / 0.001 / 0.001 / 0.801 s and `appended` 0.798 / 0.752 / 0.970 / 0.786 s (the tester's base tree; the temporary copy of the base test was removed). Four 9b runs measured `painted` 0.891 / 0.000 / 0.766 / 0.001 s and `appended` 0.920 / 1.034 / 0.874 / 0.997 s. The `appended` arm calls `load_from_path` directly, so no dialog code is inside that clock. During `green-02` another agent's pytest process (not started by this step, `--basetemp` under the same scratch root) was running on the host. Seam ruling SR-7.

Platform notes: Windows host, so the junction and store-write arms ran; 0 skips in every transcript. The real `%LOCALAPPDATA%\s19_app` does not exist after any run (each footer).

## 6 · Source files (sha256[:16], integrated tree)

| File | sha256[:16] | Edited at E4 |
|---|---|---|
| `s19_app/tui/screens.py` | `a7d9ed25e09de3ef` | no |
| `s19_app/tui/styles.tcss` | `5093edc072e03091` | yes (SR-1) |
| `s19_app/tui/__init__.py` | `0a5baebdb9fa71d2` | no |
| `s19_app/tui/app.py` | `ae3d1cd924c42a2a` | no |

Test files edited at E4: `tests/test_id_registry.py` (F2), `tests/test_b100_project_check.py` (F3), `tests/test_b99_load_project.py` (F4), `tests/test_tui_directionb.py` (F5).

Mutant table input: `E4-mutant-candidates.md` (96 rows; 11 predicted survivors named at its end).

## Orchestrator rulings on the seam items (2026-10-31)

- **SR-1 confirmed.** The nowrap/ellipsis rule sits on `#load_preview Static`. C4, S8-9 and C4-5 are corrected at close.
- **SR-2 confirmed.** `_folder_holds_project` goes through `_list_project_files`; the result is the same. R3-4's early stop was a cost note, not a behaviour. The cost (one listing per project folder at each dialog open) is declared in the packet's risks.
- **SR-3 confirmed.** TC-B100-61's paint bound means "the panel paints under 1 s after the load returns". The load keeps its own 1 s bound.
- **SR-4 confirmed.**
- **SR-5 accepted, with no guard.** Only a test teardown reaches it.
- **SR-6.** The five line-ending-only files stay out of the commit.
- **SR-7 declared.** The SEC6-5 arms sit at 0.8–1.03 s against 1 s on this host, base included, and the overrun happened under concurrent load. They go to the batch-end battery on a quiet host; the bound is not changed in 9b. The green-02 run stays recorded as 127 passed / 1 failed, and green-02b as 3 of 3.
