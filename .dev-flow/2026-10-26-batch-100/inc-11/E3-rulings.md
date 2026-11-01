# Inc 11 — E3 round 1 orchestrator rulings

Inputs:
- `E3-architect.md`: FAIL, 6 MAJOR · 6 MINOR · 5 NIT.
- `E3-security.md`: PASS-WITH-NOTES, 1 MAJOR · 5 MINOR · 3 NIT.

Rule: prefer removing a feature to guarding it. The orchestrator authorises `interfaces-11.md` edits where a row says "interfaces".

| Id | Ruling | Design effect |
|---|---|---|
| S11-01 | **Accept (fix a bug that exists on main).** "This is the open project" is decided by file identity (`os.path.samefile(target, current_project_dir)`, with an `OSError` meaning "not the same"), in G10 and in `_plan_project_save`'s target-kind test. Any other case-folded match falls into the existing disguised-clash refusal. New unwanted LLR: if the typed name case-folds to an existing folder that is not the open project's folder, then the save is refused as a disguised clash. Arms: `strasse` open with `straße` present → refused, 0 files written, `straße/project.json` unchanged. | G-B G10, `_plan_project_save`; draft |
| A11-01 | **Accept.** `emitted_record` is computed once per open, as a `_SaveSession` field. Add a 4 MiB emitting-image arm to LLR-175.5a. | G-B; interfaces (`_SaveSession`); draft |
| A11-02 | **Accept.** The two G18 free-space refusals pass `plan=None`. | G-B |
| A11-03 | **Accept.** The document arm of the Q10 fix calls `workspace._match_identical`, with the copied files as its listing. The top-level arm is dropped (Q-5 narrowed to the document row only, by the prefer-removal rule), and the top-level prediction gap goes to backlog. `test_e4_r11_a3r2_5` is NOT re-pinned. Re-pin `test_tc_b100_57_export_holds_no_byte_identity_rule` so it also catches attribute calls (`x._hash_file`). | G-B `project_gather_service`; interfaces Q-5; census |
| A11-04 | **Accept.** LLR-175.4a gains the p11b U3 and gb-plans S7 arms, which are RED on base. | draft |
| A11-05 | **Accept.** Paint one row from `manifest_keep_reason(prepared.existing)` naming `project.json.previous-<UTC>` when the commit will back the manifest up. | G-B preview; G-A row |
| A11-06 | **Declare.** HLR-175a and LLR-175.4a state that the active CRC template and the batch/assignment documents are copied outside the plan. The AT-B100-21 oracle excludes them. | draft |
| A11-07 | **Accept.** P-4 refuses on `validate_project_files`' "more than one MAC/A2L" error inside the preparation. | G-B |
| A11-08 | **Accept.** `confirm` compares the plan and `active_variant` (P-4) together. A change in either repaints `the summary changed`. | G-B |
| A11-09 / S11-06 | **Accept.** On the direct path, the name rules run before the session is computed. Opening and cancelling the dialog rewrites nothing (no `document.issues` write). The inventory is computed lazily, only when the target is a save-as. The payload sha256 is cached per image generation. | G-B; interfaces Q-4 |
| A11-11 | **Accept.** Re-pin `test_tc_b99_ux_c10_save_project_filename_renders_literally` (Q-6: no toast on the dialog path). The tester re-takes the census on the 9b+10 tree. | census |
| A11-12 | **Accept.** A renamed landing is painted `fw.s19 → fw_2.s19` (source name → landing name). | G-A row format; G-B row data |
| A11-13 | **Accept.** Rewrite G-A S5, its examples, and interfaces S-g/S-h to the debounce ruling and Q-3: blank text reaches `confirm("")`. | G-A; interfaces |
| S11-02 | **Accept.** The missing-source `Path.exists()` check moves inside the `try`. | G-B |
| S11-03 | **Accept.** The P-5 `try` wraps `sorted(...)`. The test stubs `os.listdir`. | G-B; example |
| S11-04 | **Accept.** A Save that arrives before the painted preview has been refreshed counts as out of date (`the summary changed`). | G-A `action_save`; example |
| S11-05 | **Accept.** The document digest leaves the session and is recomputed in each preparation (the document is ≤ 1 MiB). | G-B; interfaces |
| NITs | **Accept all:**<br>- A11-10: correct the "logs nothing" text;<br>- A11-14 / S11-07: P-4 moves inside the `try`, and `next()` gets a default;<br>- A11-15: B11-35 traces to a requirement or is removed, and B11-12's scrub claim is completed;<br>- A11-16: paint the vanished-source and dropped-document lines;<br>- A11-17: an existing folder that is not a project gets its own row wording, matching what the commit does;<br>- S11-08: the prefilled name goes through `painted_names` for display only, and the field keeps the raw name;<br>- S11-09: `_predict_in_copy` is gone (A11-03), so this is moot. | text, G-A, G-B |

Afterwards, update the decomposition lines, the TC rows and the draft ledger entry for every id added, changed or retired, naming the ids one by one.

## Round 2 rulings

Inputs:
- `E3-architect.md` §Round 2: FAIL. The 6 round-1 MAJOR are closed; 3 new MAJOR, 4 MINOR, 1 NIT.
- `E3-security.md` §Round 2: PASS-WITH-NOTES. S11-01 … S11-05 are closed; 1 MINOR, 2 NIT.

| Id | Ruling | Design effect |
|---|---|---|
| R2-01 | **Accept.** `confirm` memoises the fresh preview without the extra "the summary changed" line. A second Save press with nothing changed goes through, as B11-59 expects. | G-B `_confirm_project_save`; B11-59 |
| R2-02 / S11-10 | **Accept.** The lazy inventory fill writes `self._save_session` only when `session is self._save_session`, i.e. the dialog's own live session. Add a B11-15 arm: save-as, then patch, then a direct save, must plan from a fresh session and write the patched image. | G-B; B11-15 |
| R2-03 | **Accept.** LLR-175.1p's statement gains the two clauses from LLR-175.1c: the typed name differs from the folder name, and the folder is a project. The design (G10) is unchanged. | draft |
| R2-04 | **Declare.** `rederive_for_save` refreshes `document.issues` (change_service.py, outside the cap). That is a recomputation of derived state, not a user-visible write. Narrow A11-09's text to "opening and cancelling writes no file and no project state". | draft / text |
| R2-05 | **Accept.** A row is painted as renamed only when `source.name != landing.name`. B11-48 and B11-76 are updated to the arrow format. | G-B; examples |
| R2-07 | **Accept.** When no identical copy is found, the document arm's free-name walk is the same `_free_name` rule the commit uses. Name it in the node, and fix the census test's file in E1-scope to `tests/test_b100_reuse.py`. | G-B; scope |
| R2-08 | **Accept.** Fix the `_UNSET` comment (it means "no save-as source given; derive it"). A11-17's kind word keys on "folder holds no project" (`_folder_holds_project` false), not on `existing is None`. | text; G-B |
| A11-13 (rest) | **Accept.** Remove every throttle statement from proto-11-dialog.md (:99, :354 SC-1, :375 D-GA11-6, :394, :20-21 K8/K9, which become "probe history, superseded by the debounce ruling") and mark the `import time` recommendation (:442-444) rejected. | G-A text |
| S11-11 | **Accept.** An unreadable change document logs one warning per dialog open, not per recompute. | G-B |
| S11-12 | **Ruling.** The name `Input` holds the raw prefilled name. A Textual `Input` does not interpret markup, and its value is what the save uses. Only labels and `Static` text elsewhere go through `painted_names`. Remove the "display through `painted_names`" sentence. | G-A text |

## Round 3 — E3 closed; addenda for E4

Inputs: `E3-architect.md` §Round 3 PASS-WITH-NOTES (0 MAJOR); `E3-security.md` §Round 2 PASS-WITH-NOTES (0 MAJOR). E3 is closed. These rows bind the implementers (I) and the tester (T) and override any graph line they contradict.

| Id | Addendum | Who |
|---|---|---|
| R3-01 | In the lazy-inventory fill, capture `live = session is self._save_session` BEFORE `dataclasses.replace(...)`, and write `self._save_session` back only when `live` is true. B11-38 then holds: 1 walk per open. | I (G-B), T |
| R3-02 | There is no `_free_name` symbol. The document arm's free-name walk is `_placed_name_candidates` with `normcase`, as the node already says. | I |
| R2-08 follow-up | The "folder holds no project" test calls the post-9b `_folder_holds_project` (link-safe, no-follow scan). Do not inline `(project_dir/"project.json").is_file()`, which follows links. | I (G-B) |
| Base tree | Inc 11's E4 builds on main after 9b and 10 are merged, or on the `b100-inc10` branch once it is integrated. Every post-9b and post-10 symbol in the graph (`_folder_holds_project`, `_list_project_files`, the `check_action` tuple, `PatchEditorPanel.is_dirty`) exists there. | — |
