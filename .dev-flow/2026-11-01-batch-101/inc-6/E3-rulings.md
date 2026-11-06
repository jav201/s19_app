# Inc 6 — E3 rulings (orchestrator, 2026-11-06)

Round 1: `E3-architect.md` **FAIL** (4 MAJOR, 11 MINOR); `E3-security.md` **PASS-WITH-NOTES** (2 MAJOR, 4 MINOR, 1 LOW). Rulings under the operator's standing commission:

| Finding | Ruling | Why |
|---|---|---|
| E3A-01 | Accept: hide the control and the prompt in `_patch_editor_load` (a document replaced), not in the shared load tail that Save project also runs. | Save project replaces no document. |
| E3A-02 | Accept: call `update_checks_view()` beside the reset (#8) in #7 and #10, so a displayed Checks screen repaints after `ctrl+l` / `p`; add a case with the Checks screen displayed during the load. | R-CHKS-004/-009 hold while the screen is visible, not only on reopen. |
| E3A-03 | Accept: an in-place write ends the current run. Implement by extending Inc 5's in-place-write hook (`_note_image_bytes_written`, merged before Inc 6's E4) to call a `ChangeService` method that ends the run — one seam for every consequence of an in-place write. A MAC load also ends the run. Amend the S9 *current run* note; add cases (apply of a check document; MAC load). | The probe shows a stale `1 passed` after an apply; Inc 5 already clears Check Editor verdicts at the same seam. |
| E3A-04 | Accept: the three lists refill after `current_project_dir` is set (project install; Save project create / save-as); add the trigger to the rows; cases. | A stale list picks the wrong project's file. |
| S-1 (MAJOR) = E3A-14 | Accept: an image load hides the save-back prompt (in `_apply_prepared_load`, #10); add "an image load" to R-TUI-049.3.1/.3.2; 2 cases. | Confirming after an image load writes the wrong image under the old name and can rewrite `project.json`. |
| S-2 (MAJOR) = E3A-05 | **Revise D-3.** With a project open, each of the three lists (Patch Editor dropdown, Check Editor, A2B Diff) shows the project's entries (`patches/<n>`, `checks/<n>`) and then the common library's entries as `library/<n>`; picking a library entry opens it; every Write lands in the project home. The typed-path workaround is no longer needed. | Hiding the library in a project would make specs written before the project unreachable from two editors — a lost function. Listing with a prefix is the same visible form D-3 already admits. |
| S-3 = E3A-06 (MINOR) | Accept: the pick guard uses the same reparse-point walk as the Write guard; name Inc 9 (D15-18) as an interface. | One rule for pick and write. |
| S-4 (MINOR) | Accept: the guard returns the unresolved `folder / name`. | The Save project classifier compares unresolved text. |
| S-5 (MINOR) | Accept: the unsaved-changes popup re-runs the guard in `_answer` before loading. | Closes the check-then-use gap. |
| S-6 (MINOR) | Accept: the three link-refusal rows state D-6's linked-folder condition. | Completeness. |
| S-7 (LOW) | Backlog (bidi in names; same row as Inc 5 SEC5-5). | Pre-existing; outside the slice. |
| E3A-07 … E3A-13, E3A-15 (MINOR) | Fold each as a targeted edit: hidden-class asserts → `partial` unless the painted state is read; rule-7 waits planned in every case; the /7 negative arm rebuilt or the case ruled `not-testable` with its reason; .36/1 status sign and -009/1 expected value fixed; E4 updates the guide/help/DOSSIER text the change makes stale (text only); "patches folder" refusal texts named; R-DIFF-CHK.3 empty row; the overlap list gains the 2 functions; no re-mount on every action; US-PE-LIFE-1 narrowed to what the rows cover. | Minors fold without another round where they are one-line edits. |

Correction: one design-correction agent, targeted edits only. Round 2: the architect re-checks E3A-01 … E3A-04 and the revised D-3; the security reviewer re-checks S-1 and S-2.
