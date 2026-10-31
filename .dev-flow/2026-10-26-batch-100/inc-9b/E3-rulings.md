# Inc 9b — E3 round 1 orchestrator rulings

Inputs:
- `E3-architect.md`: FAIL, 0 HIGH · 6 MAJOR · 6 MINOR · 4 NIT.
- `E3-security.md`: PASS-WITH-NOTES, 0 HIGH · 2 MAJOR · 6 MINOR · 1 NIT.

Rule: prefer removing a feature to guarding it. Every row below is applied by one design-fix pass with targeted edits. Round 2 re-checks only the MAJOR rows.

| Id | Ruling | Design effect |
|---|---|---|
| A9b-01 | **Accept.** The dialog's `alt+l` binding becomes `priority=True`. | G-A BINDINGS. New example: the posted `events.Key("alt+l", character="l")` with the focus on `#load_path` → load runs, 0 characters typed. Test-note row for the tester. |
| A9b-02 | **Accept.** `_close` returns at once when `_dismissed` is set (its first line). | G-A `_close` node. New example: two Enter presses → 1 dismiss, 0 exceptions. |
| A9b-03 | **Accept.** On a `None` result the router calls `_rehome_focus_after_load()`. | G-B `_handle_load_dialog`; rewrite B14. Examples: focus on `search_input`, `ctrl+l`, `escape` → focus on the declared target. |
| A9b-04 | **Accept.** The preview is synchronous for every kind, so remove the generation/deliver machinery. The interface becomes `preview: Callable[[LoadChoice], list[PreviewLine]]`. Delete `show_preview`'s generation argument and its stale check, seams S-e, P-1 and P-3, and the examples that depend on them. Retire LLR-173.6i and the in-flight arm of LLR-173.2k (a "Retired" entry with a reason, as for LLR-171.2e). | `interfaces-9b.md` (the orchestrator authorises this edit), both prototypes, the draft, the scope. |
| A9b-05 / S9b-6 | **Accept: reverse ruling B-2.** `_load_from_item`'s A2L branch stays as in 9a, including `copy_into_workarea` (an identical-file reuse, which keeps the 256 MB cap and the link re-check). The 0-copy rule (LLR-173.1b) covers the data arm only. Remove the 0-copy spy from the A2L arm. | G-B G1 node, B10, the callers table, LLR-173.1b text. The 9a TC-B100-34 A2L arm is kept. |
| A9b-09 | **Moot** after A9b-05: no second copy of the A2L admission rule exists. | — |
| A9b-10 | **Accept.** Remove LLR-173.2m everywhere: Decomposition, VS-PA-4, §B, TC-B100-41 row, §D.3, §E, E1-scope. Add one line to E1-scope §"Routed": "VS-PA-4 labels → Inc 12a (Q8)". | draft, scope |
| S9b-1 | **Accept.** The guard reads the whole stack: `any(isinstance(s, LoadDialog) for s in self.screen_stack)`. | G-B `check_action` node. New example: `ctrl+p` over the dialog, then `ctrl+s` → 0 Save pushes. B90 gains that arm. |
| S9b-2 | **Accept.** Run the existing lstat regular-file check on `project.json` before any manifest read, in both the preview and `_handle_load_project`: if the file is not a regular file, show `could not be read` and do not open it. `_folder_holds_project` uses one `os.scandir` with `follow_symlinks=False` and stops at the first data or A2L entry. The preview's file-list check uses `lstat`/`is_file(follow_symlinks=False)` only. | G-B preview, `_handle_load_project`, `_folder_holds_project`; the Q2 table in E1-scope gets the corrected rows. New examples: a FIFO or link named `project.json` → refusal line, 0 opens. |
| S9b-3 | **Accept: remove LLR-173.6e** (the sub-folders line). | draft, G-B preview, examples |
| S9b-4 | **Accept.** `#load_path` gets an Input `restrict=` that rejects C0 control characters (U+0000–U+001F) and U+007F. | G-A compose. Example: a pasted NUL → not inserted. |
| S9b-5 | **Accept.** `A2L loaded: <name>` (G1, B10) and `Project not found: {name}` paint the name through `painted_names`. The load-tail `Loaded {path.name}` lines go to backlog (Inc 12a sweep). | G-B; backlog note in E1-scope §Routed |
| S9b-7 | **Accept.** The verdict returns a data or A2L kind only after the lstat walk shows a regular file. A folder named `x.s19` takes the `not found` / `check the path` token row. | G-B verdict node and an example |
| S9b-8 | **Accept.** `#load_preview` lines are nowrap with an ellipsis. | G-A CSS + the render node. Example: a 300-character name → 1 line. |
| A9b-06 | **Accept.** The redirect sets `_source = "path"` immediately. Escape is handled before Enter (the escape binding, or an `on_key` check of `escape` first). | G-A S4 and the on_key nodes; examples for `C`+Enter and Escape+Enter type-ahead. |
| A9b-07 | **Accept: remove the typed-file preview arm and `on_input_changed`.** While the path field has the focus, the preview shows no lines. Retire the typed-file arm of LLR-173.6b. | draft, G-A |
| A9b-08 | **Accept.** Retire LLR-173.1d (bare `Path` input) and re-pin its 3 test calls to `LoadChoice("path", …)`. | draft, scope test notes |
| A9b-11, S9b-9 | **Accept.** Fix the stale texts: `#load_dialog` → `#load_box` in VS-PA-3 and the interfaces; LLR-173.2e "planned" → executed; LLR-173.2j ListView → OptionList; remove "the preview never blocks" from HLR-173's rationale and R2-03; complete the Q2 table. | text only |
| A9b-12 | **Accept.** Leave the C1 marker comment in `styles.tcss` as it is (`_modal_css_block()` searches for it). Add a constraint line in G-A. | G-A |
| NITs | **Accept all four.** Remove the stale "timer"; add `RECENT_PROBLEM_*` to the imports; one recent-label format, the G-B one, in both fixtures; the B78 `cannot load:` line either traces to a requirement or is removed (prefer removal). | text |

After this pass, list every requirement id whose block changed, and give the ledger draft one entry naming each id one by one.

## Round 2 rulings

Inputs:
- `E3-architect.md` §Round 2: FAIL; the 6 round-1 MAJOR are closed; 1 new MAJOR, 4 MINOR and 1 NIT row.
- `E3-security.md` §Round 2: PASS-WITH-NOTES; S9b-1 and S9b-2 are closed; 3 MINOR and 3 NIT.

| Id | Ruling | Design effect |
|---|---|---|
| A9b-R2-1 | **Accept.** Delete G-B step (2) (the bare-`Path` arm) and example B12. The router input type is `Optional[LoadChoice]`. Remove the LLR-173.1d trace from proto-9b-dialog.md SA-4 and from :575. | proto-9b-app.md, proto-9b-dialog.md |
| A9b-R2-2 | **Accept.** S4 step 4 calls `_schedule_preview(None)`, so the preview clears when a printable key moves the source to the path field. | G-A S4; one example |
| A9b-R2-3 / R2-N1 | **Accept.** The preview shows no `●` mark when the scan finds more than one MAC or more than one A2L. Restore B78 without the painted `cannot load:` line. | G-B preview; B78 |
| R2-N2 | **Accept.** Add one helper (name it in the graph) that lists a project's files without following links. The preview and the install at Enter both use it, so the marks equal what installs. New requirement LLR-173.4n: "If a file in a project folder is a link, then the system shall neither list nor install it." Threshold: 1 linked `.s19` beside 1 regular `.s19` gives 1 row, 1 mark and 1 install, with 0 opens of the link target. Negative control: a helper that follows links gives 2 rows → RED. | draft (new LLR, TC row, ledger), G-B helper node, examples |
| R2-N3 | **Accept.** The scan counts MAC files, so a folder holding only a MAC file stays a project, as before. Restore B22. | G-B `_folder_holds_project`; B22 |
| A9b-R2-4 / R2-N4 | **Accept.** B73, B19 and B23 inject into the named scan helper (R2-N2), not into `validate_project_files`. | examples |
| R2-N5 | **Accept.** A `project.json` that is not a regular file paints `could not be read` in the preview as well. | G-B preview; B98 |
| S9b-7 (R2) | **Accept.** Rewrite B97 to the two real results: `project` when the folder is listed, `not a project` when it is not. Drop the `not found` sentence. | B97 |
| A9b-R2-5 | **Declare.** A queued `escape` then `alt+l` loads instead of closing. Add this to the design risks; no code change. | G-A risks |
| A9b-R2-6 | **Accept all of the text fixes.** For A9b-09, reverse "moot": lift the A2L admission rule (`app.py` around :11752-11790) into one helper, used by both the preview and the install. Add the early `_dismissed` return in `action_load`. | text; G-B helper node |
| R2-N3b | **Declare** the race between the regular-file check and the open as an accepted risk. | risks |

## Round 3 — E3 closed; addenda for E4

Inputs:
- `E3-architect.md` §Round 3: PASS-WITH-NOTES, 0 MAJOR.
- `E3-security.md` §Round 3: PASS-WITH-NOTES, 0 MAJOR.

E3 is closed. The rows below bind the E4 implementers (I) and the tester (T) as addenda. They take precedence over any graph line they contradict.

| Id | Addendum | Who |
|---|---|---|
| R3-1 (sec) | An absent `project.json` keeps today's behaviour: it is not a refusal, and the existing "no project.json" path applies. When the regular-file check refuses a `project.json`, every preview mark is `False`. | I (G-B), T |
| R3-2 (sec) | B97 has two cases. A listed folder named `ab.s19`: the dialog closes and the project loads. An unlisted folder: `not a project`, 0 dismisses, 0 loads. | I, T |
| R3-3 (sec) | LLR-173.4n's link arm needs a file symlink. Where `os.symlink` raises (Windows without Developer Mode), the arm is skipped with that reason, the way the junction arms are. | T |
| R3-4 (sec) | `_folder_holds_project` stops at the first data, MAC or A2L entry. It uses the same no-follow test as `_list_project_files`, but does not list the whole folder. | I (G-B) |
| A9b-R3-1 | Re-pin the TC-B100-38 arm "route: validate_project_files" (`tests/test_b100_recents.py`) so it patches `_list_project_files`. E1-scope's note is corrected at close. | T |
| A9b-R3-2 | `_list_project_files` and `_a2l_admission` return the 9a reason strings verbatim: `is a link or junction`, `is too large to open`, `could not be read` (pinned in `tests/test_b100_project_homes.py`). | I (G-B) |
| A9b-R3-3 | LLR-173.4n is narrowed to the Load dialog's preview and the project load (draft edited by the orchestrator). The variant-list rebuild after a save or a file activation still goes through `validate_project_files`; that goes to backlog (Inc 12a sweep). | — |
| A9b-R3-4 | `_list_project_files` also returns the 9a "more than one MAC / A2L" error string, so the rule lives in one place; both callers use it. | I (G-B) |
| A9b-R3-5 | B78's oracle: a status line with the refusal, no Load-result panel, the session unchanged. | T |
