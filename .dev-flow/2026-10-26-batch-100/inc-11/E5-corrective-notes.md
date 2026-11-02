# Inc 11 — E5 corrective notes (the Save project dialog)

Stage E5, the one corrective pass. Inputs: `03-increments/review-increment-020.md` (CR F1–F3), `03-increments/security-increment-020.md` (SE5-11-1, SE5-11-2), the reviewers' probes (`scratchpad/rev11-code/probe_stale_inventory.py`, `scratchpad/rev11-security/probe_midload*.py`), `E5-rulings.md`, and the orchestrator's mutation rows (`evidence/inc-11/mutation-summary.md`, 18 survivors). Tree `<HOME>/Github/s19_app-b100-inc11`, branch `b100-inc11` at `051f586` plus this pass (not committed). Evidence states use the seven words only.

## Result

Every row marked `corrective` and every MUT11 row is done. Source files touched: 2 of the 4 allowed (`app.py`, `screens.py`); `styles.tcss` and `project_gather_service.py` are unchanged. Test files touched: `tests/test_b100_save_dialog.py`, `tests/test_loadfilescreen_input.py`.

| Run | Transcript | Result | State |
|---|---|---|---|
| RED on 051f586 (`scratchpad/base11c`, test files copied in) | `evidence/inc-11/red-03-corrective.txt` | `4 failed, 3 passed in 49.60s` (the 4 expected RED; the 3 passes are the name_cap and the two at042b ids, see below) + the name_cap mutant run `2 failed in 25.25s` | executed |
| GREEN, corrective arms | `evidence/inc-11/green-03-corrective.txt` | `7 passed in 48.12s` | executed |
| Targeted `test_b100_save_dialog.py` nodes + census node + at042b + guards (`test_id_registry.py`, `test_b99_staging.py`, `test_engine_unchanged.py`) | `evidence/inc-11/green-04-new-and-guards.txt` | `112 passed, 2 skipped in 700.36s`; the 2 skips re-run with a shorter basetemp: `2 passed in 19.12s` | executed (the 2 skips first `not-run`: basetemp 4 characters too deep for the 180-character padded work area; then executed, passed) |
| Full `tests/test_b100_save_dialog.py`, once | `evidence/inc-11/green-06-full-new-file.txt` | `157 passed in 1554.79s` | executed, on the intermediate state (before MUT11-M-47 and the MUT11 arms; see its header) |
| MUT11 kills on the scratch copy | `evidence/inc-11/mut-kill-03-corrective.txt` | 7 of 7 KILLED, each source restored and sha-verified | executed |
| GREEN on the final source | `evidence/inc-11/green-05-final.txt` | `68 passed in 537.46s` | executed |

Every transcript prints `s19_app.__file__` (worktree: `<HOME>\Github\s19_app-b100-inc11\s19_app\__init__.py`; RED: `...\scratchpad\base11c\s19_app\__init__.py`; kills: `...\scratchpad\corr11\mutcap\s19_app\__init__.py`). Env on every run: `env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. LOCALAPPDATA=<scratchpad>/corr11/la`, `--basetemp` under `<scratchpad>/corr11/`. No timing arm failed in any run. No pytest of mine is left running. `base11c` was restored to its clean state (`git status` empty).

Not run, by the operator override: whole touched modules (`test_loadfilescreen_input.py`, `test_address_census.py`), the full suite (`not-run`, owed to the batch-end battery).

## Per id

| Id | What changed | Where (final line numbers) | Arm | RED → GREEN |
|---|---|---|---|---|
| SE5-11-1 | `_SaveSession` gains `image_generation` (the app's `_image_generation` when the session is built). `_current_save_session` rebuilds a session whose generation is out of date; `_prepare_project_save` drops a stale passed session and rebuilds it after the name rules; the router reuses `confirmed` only while its session generation is current. No new refusal text: the dialog's next confirm repaints `the summary changed` with the fresh image decision. | `app.py:1833` (field), `:10799` (captured in `_save_session_inputs`, passed at the 3 construction sites), `:10860` (`_current_save_session`), `:10402` (`_prepare_project_save`), `:10337` (router) | new `SD::test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session[same_ranges]`, `[other_ranges]` | RED: same_ranges `derived_from` base `firmware.s19`; other_ranges `KeyError: 2147549184` out of the commit. GREEN: same_ranges the written image is `other.s19` + the entry, base `other.s19`, `active_variant` names it, memory equals it; other_ranges the app runs and `other.s19` is saved as an unchanged copy (`derived_from` none, `active_variant` `other`), which is what a dialog opened after the load plans. |
| CR11-F1 | `_plan_project_save` uses its `inventory` argument only in the walk branch (`walked = inventory if inventory is not None else inventory_project_tree(source_dir)`, passed as `inventory=walked`); `_prepare_project_save` passes `session.inventory` only when `save_as_source is not None`. | `app.py:12140`, `:12153`–`:12159`, `:12307`; `:10702` | new `SD::test_tc_b100_65_vanished_source_after_a_save_as_preview_copies_nothing` | RED: `folder reports/ (3 files) — new` painted for `R`. GREEN: the vanished folder `P` is painted, 0 `folder` rows, Save closes the dialog, the app runs, no `R/reports`, the moved folder unchanged. |
| CR11-F2 | The 19 requirement-tagged comments the move deleted are back above the statements they explain, text unchanged (the empty-name one then widened by MUT11-M-47): router `LLR-171.3 / LLR-171.3a`; in `_prepare_project_save` `HLR-164`, the empty-name line, `LLR-164.1`, `LLR-164.2 (Q-2)`, `F8`, `SEC2-1`, `LED .52(a)` (at the `open_spelling` capture), the exact-name merge note, `LLR-155.4`, `LED .50 / SEC-1`, `LLR-164.2 / HLR-164(f) / LLR-171.4g`, `LLR-171.1 / S3-6`, `LLR-171.1n (F1)`, `HLR-167 / LLR-167.1 / LLR-167.6` + `LLR-164.4`, `LLR-168.4 / LLR-167.6 (F3)`, `LLR-171.1h`, `LLR-164.2 / pre-ruling 7`, `LLR-171.1e / R7`. | `app.py:10314`, `:10426`–`:10734` | none (comment only) | no RED owed (comment-only fix). Check: `git diff main -- s19_app/tui/app.py` shows no removed requirement comment except the `LED .52(a)` one, which is present at its new indentation. |
| CR11-F3 | `_SaveSession.digests` annotated `dict[Path, Tuple[str, int]]` (docstring says why); the planner's `digests` parameter and `session_digests` local too (that is where the write happens — one step past the ruling's "the field", declared); a two-line comment at the sentinel write. | `app.py:1831`, `:12018`, `:12248` | none | no RED owed (annotation + comment). |
| CI9b-1 | `LoadDialog.on_mount`: the `IfExp` selector becomes two literal `query_one` calls in an if/else. | `screens.py:406`–`:409` | `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` | RED: `screens.py:407 other:IfExp`. GREEN. |
| CI9b-2 | Re-pin of `test_at042b` to SEC9b-1 ruling B: injection stays at `_STRATEGIES`; `[over_field_limit]` (CAP + 5 000 000 → capped read 65 536 > 4096 → `''`), `[fits_field_limit]` (4096 characters inserted whole). Docstring cites SEC9b-1 / batch-100 Inc 9b. | `tests/test_loadfilescreen_input.py:662` | both ids | re-pin: no RED owed. Both ids pass on 051f586 too (the field limit came with Inc 9b), which is expected. |
| SR-11-name-cap | Before each over-cap arm the test sets `bbb` and waits for `bbb — new folder`, then sets the long name and waits for the refusal; the field value (65 / 300 characters) is asserted. | `tests/test_b100_save_dialog.py:928` | `SD::test_tc_b100_47_name_cap_64_65_300` | The base source is correct, so the arm passes on 051f586. RED shown by a mutant on the scratch copy (cap `PROJECT_NAME_MAX_CHARS < len(cleaned) < 100`: 65 refused, 300 not): the new arm fails waiting for the refusal (the 300 name paints `new folder`). The pre-corrective arm also failed in that run, by timing (it read after the debounce); it is not guaranteed to. |
| SE5-11-2 | not touched (BACKLOG-CODE, Inc 12a sweep). | — | — | — |

## MUT11 rows (orchestrator, from the mutation summary)

Each kill: the mutant string from `scratchpad/mut11-work/specs-*.json` applied to `scratchpad/corr11/mutcap` (the final worktree source), the arm run, the file restored and its sha256 compared (`restored=True` for all 7). GREEN of each arm on the final worktree source: `green-05-final.txt`.

| Id | Arm | Kill evidence |
|---|---|---|
| MUT11-M-09 (live gate dropped) | new `SD::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute` — the dialog's first preview deferred 500 ms (a late first frame, stood in for by a test subclass that replaces `on_mount`), the field changed before it → 1 preview call, made live. | KILLED: `(['early', 'early'], [False, True])` |
| MUT11-M-14 (`_shown` not reset in `_paint`) | new `SD::test_tc_b100_65_a_save_queued_before_a_repaint_is_shown_repaints` — `one` shown, `two` repainted with a Save queued before its frame → `confirm("two", None)`, 0 dismisses, `the summary changed`; second `alt+s` dismisses `two`. | KILLED: confirm got `('two', SavePlan(...))` |
| MUT11-M-42 (router keeps `_save_session`) | new `SD::test_tc_b100_65_dialog_save_as_leaves_no_session_for_the_next_direct_save` — save as `Q` through the dialog, then patch, then direct save `R`. | KILLED: `_save_session` still set after the dialog save |
| MUT11-M-45 (typed-name clause dropped) | new `SD::test_tc_b100_65_confirm_is_not_reused_for_another_typed_name` (B11-14) — confirm `A`, payload `B` with the same plan object → `B` saved, no `A`. | KILLED: `(a_made, b_saved) = (True, False)` |
| MUT11-M-68 (emitted image digested) | strengthened `SD::test_tc_b100_65_session_decided_once_per_open_case06` — the emitted image's `_file_digest` count at open and after the keystrokes is `[0, 0]`. | KILLED: `[1, 1]` |
| MUT11-M-74 (refused preview keeps rows) | strengthened `SD::test_tc_b100_47_target_with_two_mac_files_refused_in_the_dialog` — the refusal's plan has ≥ 1 row and 0 rows are painted. | KILLED, by an exception (`'SavePlanRow' object has no attribute 'translate'`: the mutant hands plan rows to `Text`), before the rows assertion is reached |
| MUT11-M-96 (free-name walk without `normcase`) | new `SD::test_tc_b100_65_document_free_name_walk_folds_case` — `P` holds `patches/Changes.json` (other bytes) and the document `notes/changes.json`; save as `Q` → row and plan `patches/changes_1.json — new`, `Q/patches` holds both files with their bytes. | KILLED: painted `document patches/changes.json — new` |
| MUT11-M-47 (blank-name guard) | **Removed** (prefer removal). For `""` and whitespace, `sanitize_project_name` strips and returns `None`, and `if not cleaned:` gives the same text `Project NOT saved: name is empty — type a project name.` The guard is deleted and the comment above `if not cleaned:` now says it covers a blank name. One difference, harmless: a blank name's refused `_PreparedSave.cleaned` is now `None`, not `""` (as for a name with no usable character before); no refusal path reads it. `app.py:10430`–`:10433`. Covered by `test_tc_b100_49_empty_save_keeps_the_dialog_and_says_why` (6 ids), `test_tc_b100_47_no_usable_character_painted_live`, the refusal arms (green-05). | — |

Accepted as equivalent by the orchestrator (no work): M-01, M-02, M-05, M-29, M-31, M-44, M-55, M-87, M-88, M-92. Killed by runtime exception, standing as killed: M-11, M-21, M-52, M-66, M-70.

## Observations (not fixed; outside the rulings)

- **O-1, a source file that vanishes while the dialog is open.** In the CR11-F1 arm the loaded image lives in `P`, so renaming `P` also removes the image. The live session decided "source present" at the first preview and does not re-check, so the dialog paints `firmware.s19 unchanged copy`; the commit then fails (`[WinError 3] ... P\firmware.s19`), rolls back, closes the dialog and paints `Project NOT saved: could not save — ... check the folder.` The app keeps running and nothing is written. Before Inc 11, the missing-source check ran at dismiss time and gave the `source file missing` refusal. Route: the orchestrator (a per-confirm `exists()` re-check would restore it).
- **O-2, M-74 kill mode.** The two-MAC arm kills M-74 by an exception, not by its rows assertion, because the mutant puts `SavePlanRow` objects where strings go. A mutant that painted the rows as text would meet the new rows assertion.
- **O-3, the router fallback after a stale confirm (SE5-11-1).** When the session goes stale between confirm and dismiss (one `call_next` hop), the router prepares afresh and commits that plan, as the direct path does; the engineer did not see that plan. This follows the ruling ("reuses `confirmed` only while its generation is current").

## Source sha256[:16] (final)

| File | sha256[:16] | Line endings |
|---|---|---|
| `s19_app/tui/app.py` | `1a3ed1e9ed0976eb` | CRLF, 19 627 lines, 0 bare LF |
| `s19_app/tui/screens.py` | `dc988721ae7b6a87` | CRLF, 3 572 lines, 0 bare LF |
| `s19_app/tui/styles.tcss` | `038fd8dbc034373e` (unchanged) | CRLF |
| `s19_app/tui/services/project_gather_service.py` | `e11a5e75d7346183` (unchanged) | CRLF |

Intermediate app.py states and the runs on them: `6ffeffc796a61a82` (green-03, green-04), `01a04707c96420dd` (comment wording only; green-06), `1a3ed1e9ed0976eb` (MUT11-M-47 removal; green-05, kills).
