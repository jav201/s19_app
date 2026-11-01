# E5 rulings — batch-100 Inc 10 (increment 019), corrective pass

Source reports: `03-increments/review-increment-019.md` (CR10-01 … CR10-05) and `03-increments/security-increment-019.md` (SEC10-01, SEC10-02). SR-2 comes from `E4-integration-notes.md` §Orchestrator rulings. Rulings by the orchestrator, 2026-10-31. One corrective pass. Evidence for each row is in `E5-corrective-notes.md`.

| Id | Sev | Tag | Ruling | Done in |
|---|---|---|---|---|
| CR10-01 = SEC10-01 | MINOR | design-gap | Fix. Both reviewers found it independently. The attach-vs-image kind and the target name of a typed or recent `data` path come from the RESOLVED path that `resolve_input_path` returns (the one the classifier and `load_from_path` use), never from the typed text. When the typed suffix and the resolved suffix differ, fail closed: an image load, so the question asks. Add TC-B100-72 arms: (a) a relative `cal.mac` symlink to a `.s19` with D true → 1 question; (b) a plain `.mac` → 0 questions, the attach keeps D. Skip (a) with a reason where `os.symlink` raises. Prove each arm RED on the 1747479 source before the fix. | Corrective pass: `app.py` `_load_path_from_user_input` (data arm + Data Flow); new test `test_tc_b100_72_relative_mac_takes_its_kind_from_the_resolved_path[link\|plain]` |
| SR-2 (E4) | — | test-gap | Add the C60 test: the three S10-04 lines (`Variant not found`, `Variant file missing`, `No supported files in project`) paint the name through `painted_names`; a hostile name has no markup effect. Mutants M63, M64 and M70 must go RED. | Corrective pass: new test `test_tc_b100_45_refusal_lines_paint_names_literally`; M63, M64, M70 KILLED (`mut-c-M63/M64/M70.txt`) |
| CR10-02 | NIT | impl | Re-record GREEN on the merged tree: re-run `tests/test_b100_load_question.py`, the 5 re-pinned nodes and the guards as `green-03-merged.txt` (header: HEAD sha, `s19_app.__file__`). | Corrective pass: `evidence/inc-10/green-03-merged.txt` |
| CR10-03 | NIT | impl | Fix the `_dirty` comment and the `is_dirty` docstring: three outside readers (the dropdown guard is the third). | Corrective pass: `screens_directionb.py` `_dirty` comment, `is_dirty` docstring |
| CR10-04 | NIT | impl | Fix the `_confirm_then_load` docstring: the answer is `bool`, never `None`. | Corrective pass: `app.py` `_confirm_then_load` Data Flow |
| CR10-05 | NIT | impl | Move the `test_id_registry.py` bump line into the docstring history, as 8b did. | Corrective pass: `tests/test_id_registry.py` |
| SEC10-02 | NIT | design-gap | Backlog only: widen the S10-04 backlog row to `load_selected_file`'s / `_handle_load_error`'s `Load failed: {exc}` lines (Inc 12a sweep). No code change. | Backlog (Inc 12a sweep). Widened row text in `E5-corrective-notes.md` §SEC10-02. No code change. |

## Mutant survivors

Mutation run (on 1747479): 83 mutants, 69 killed, 14 survived, 0 invalid (`evidence/inc-10/mutation-summary.md`). Orchestrator rulings 2026-10-31, then re-run one by one on a scratch copy of the corrected tree (`<scratch>/c10/mutc`, never the worktree). Transcripts: `evidence/inc-10/mut-c-<id>.txt`. Details: `E5-corrective-notes.md` §Arms added for the mutation rulings.

| Mutant | What it breaks | Ruling | Arm | Final |
|---|---|---|---|---|
| M08 | adds a screen-level `enter` → `answer(True)` | equivalent | none: the focused button's own `enter` binding wins, and `AUTO_FOCUS` keeps a button focused (read; no-focus state not reachable by keys, not probed) | EQUIVALENT (survives all 25 TC-B100-45 nodes) |
| M14 | swaps the button order | equivalent (ruled) → **not equivalent** | none needed: `test_tc_b100_45_one_modal_with_replace_and_cancel` asserts the order; the original run used the wrong killer | KILLED |
| M15 | box id `confirm_box` → `load_dialog` | wrong target | `modal_builds_from_its_parameters` reads `#confirm_box > *` | KILLED |
| M16 | drops `event.stop()` | gap → arm | `click_answers_with_the_clicked_button` observes the app's `on_button_pressed` | KILLED |
| M29 | drops the dropdown cancel line | gap → arm | `change_file_dropdown_keeps_the_guard`: 1 cancel line per cancel | KILLED |
| M30 | drops the dropdown accept load | gap → arm | same test, accept arm | KILLED |
| M32 | defers the clean `go` | may stay a gap → arm (cheap) | `go_runs_at_once_when_clean_and_after_the_question_on_replace` | KILLED |
| M33 | runs `go` inside the answer callback | gap → arm | same test | KILLED |
| M50 | raw project name in the title | weak test | `names_paint_literally`: project name holds U+202E | KILLED |
| M63 | raw id in `Variant not found` | C60 test | `refusal_lines_paint_names_literally` | KILLED |
| M64 | raw name in `Variant file missing` | C60 test | same | KILLED |
| M70 | raw name in `No supported files` | C60 test | same | KILLED |
| M71 | `_declared_regions` written before the reset | gap → arm | `project_load_adopts_declared_regions_after_the_reset` | KILLED |
| M79 | `exists()` moved into `go` | may stay a gap → arm (cheap) | `workarea_file_takes_its_kind_from_its_suffix`: a missing pick asks 0 | KILLED (the C39 race itself stays a declared design note) |
| M75r / M75s / M76r / M77r | M75–M77 re-derived on the line CR10-01 rewrote | re-derivation (their original text no longer exists) | existing TC-B100-72 / TC-B100-44 nodes | KILLED ×4 |
| MC1 / MC2 | CR10-01 over-correction / the 1747479 rule | corrective-pass mutants | `relative_mac_takes_its_kind_from_the_resolved_path[plain]` / `[link]` | KILLED ×2 |

**Final kill count: 82 of 83 Inc 10 mutants killed, 1 equivalent (M08), 0 surviving.** Corrective-pass mutants: 2 of 2 killed.
