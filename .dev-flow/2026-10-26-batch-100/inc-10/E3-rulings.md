# Inc 10 — E3 round 1 orchestrator rulings

Inputs:
- `E3-architect.md`: PASS-WITH-NOTES, 1 MAJOR · 7 MINOR · 3 NIT.
- `E3-security.md`: PASS-WITH-NOTES, 2 MAJOR · 2 MINOR.

The 3 MAJOR are fixed in the design before E4. Rule: remove a feature rather than guard it.

| Id | Ruling | Design effect |
|---|---|---|
| A10-01 | **Accept: remove the dead `None` arm.** Delete G-B `_route_load_project` step (1) and example C32. The parameter becomes `name: str`. | G-B |
| S10-01 | **Accept (fix).** In `_handle_load_project`, compute `a2l_context` and the all-`None` install check before `_reset_project_session()`; both are reads. A refusal after `y` then keeps the work. Add this arm to LLR-174.3c: an A2L-only project with an unreadable A2L → the refusal line, and the session (file, entries, dirty) unchanged. Add an example that reproduces the probe `probe_sec_refuse`. | G-B node + example; draft LLR-174.3c threshold |
| S10-02 | **Accept (fix, the guard the button already has).** In the app handler for `ChangeFileSelected` (the `#patch_doc_file_select` pick), read `panel.is_dirty`; when it is True, push the existing `LoadGuardScreen` exactly as the Load button does, and do not load. Add LLR-174.2t (unwanted): "If the engineer picks a change file in the Patch Editor's dropdown while the panel holds unsaved entries, then the system shall show the Patch Editor's load guard before replacing them." Threshold: dirty + pick → 1 `LoadGuardScreen`, entries unchanged; clean + pick → 0 guards, loads. Negative control: remove the check → entries replaced → RED. The goal text "every load route" stands. | G-B node + examples; draft |
| S10-03 | **Declare.** A load worker that is already running installs without a check. 12b closes this (its ruling Q3 refuses Patch Editor changes while a session-writing action runs). Add it to the risks and route it to 12b. | risks |
| S10-04 | **Accept.** In the two functions Inc 10 edits (`_handle_load_project` and `_handle_select_variant`), the names in the `No supported files` line and the two variant lines go through `painted_names`. The `File not found` line in `load_from_path` goes to backlog (Inc 12a sweep). | G-B |
| A10-02 | **Accept: remove the catch** in `_load_would_lose`, remove example C15, and remove the "not mounted counts as not dirty" sentence in S-e. | G-B, interfaces S-e |
| A10-03 | **Accept.** Add LLR-174.2s (unwanted): "If a second answer reaches the question after the first, then the system shall ignore it." It traces to Q5-1 … Q5-3. | draft |
| A10-04 | **Accept.** LLR-174.2b's threshold becomes 1 of 1, covered by Q1-2. | draft |
| A10-05 | **Accept.** Reword HLR-174 and HLR-174a to trigger on the unsaved flags (D, W, F). The "would lose" wording goes. No code change. | draft |
| A10-06 | **Accept.** Narrow LLR-174.2g to non-priority keys. Add a note that `ctrl+q` and the palette Quit belong to Inc 12's quit question. | draft |
| A10-07 | **Accept.** Apply P-GA10-1 everywhere: interfaces S-a (line 43) says `rich.text.Text`; G-A Q2 builds `Text(...)` labels; delete node I1 (the `textual.content` import); fix G-B's S-a seam row. | interfaces, G-A, G-B |
| A10-08 | **Accept.** Put P-1's stripped-path MAC test into the interfaces Q-4 text. Put P-2's census rule into the draft LLR-174.4 threshold, without the `on_mount` exemption. | interfaces, draft |
| E2 owed | Apply the draft text owed by E2-rulings P-3 (the undo boundary; new LLR-174.3d) and P-GA10-2 (LLR-174.2r's negative controls; "fully visible", body included). | draft |
| A10-09 … A10-11 | **Accept the text fixes.** SB-2: the callback runs after the pop. LLR-174.3c / C30: cite `_list_project_files`. Census line numbers: cite the 9b worktree lines (AT-B100-03 at `:775`). | text |

Afterwards, update the decomposition lines, the TC rows and the draft ledger entry for every id added or changed, naming the ids one by one.

## Round 2 — E3 closed; addenda for E4

Inputs:
- `E3-architect.md` §Round 2: PASS-WITH-NOTES, 0 MAJOR / 0 MINOR / 3 NIT.
- `E3-security.md` §Round 2: PASS, 2 NIT.

E3 is closed. The rows below bind the implementers (I) and the tester (T), and take precedence over any graph line they contradict.

| Id | Addendum | Who |
|---|---|---|
| S10-05 | Move `problems = check_project_files(...)` before the reset with the other reads, or hold the unreadable-A2L problem in a local until after it. The moved arm must never reference a name created after the reset. | I (G-B) |
| S10-06 | C58 asserts "D unchanged". Or add an Apply to its setup, then assert D is still `True`. | T |
| A10-R2-1 | Delete "A `None` name returns first" from interfaces-10.md:62. Text fix, already done. | — |
| A10-R2-2 | R-GA10-3 is closed: its node I1 is retired. | — |
| A10-R2-3 | In the cancel arm of the dropdown guard, reset `#patch_doc_file_select` to `Select.NULL`, so picking the same file again fires. Add an example arm. | I (G-B), T |

**Sequencing.** E4 builds on the integrated 9b tree. The worktree `b100-inc10` branches from `b100-inc9b` once 9b's integration is GREEN and committed on its branch. Any 9b E5 correction reaches Inc 10 by a merge of `b100-inc9b`, or of main after 9b closes, before Inc 10's E5.
