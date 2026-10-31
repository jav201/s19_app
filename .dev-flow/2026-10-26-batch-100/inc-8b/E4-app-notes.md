# Inc 8b — E4 notes, G1 (`s19_app/tui/app.py`)

Implementer notes for the approved design `codewire/proto-8b-app.md` (with `interfaces-8b.md` and `E3-rulings.md` R1–R16). Only `s19_app/tui/app.py` was edited. Each item says what the code does where it is not a word-for-word reading of the graph, and why.

## Deviations (closest correct behaviour)

D-1 (R15, step 12b mismatch line). `_copy_project_subfolders` decides a carried-row mismatch with `_plan_row_mismatch(row, placed)` as the graph says, but paints its own line: "Project NOT saved: the plan named <landing name> (<action>) but the file landed at <landed name> (<action>) — save again.", each name through `painted_names`. Reason: R15 requires `painted_names`, and `painted_names` clips each name to 120 characters; a full temp-folder path would be clipped before the file name, so the line could lose "fw_2.s19". A top-level copy's landing is in the project folder itself, so the name is the project-relative path. The full paths go to the log (`%r`).

D-2 (row 8, "and K more" line). The graph's func text gives the line as `and K more files copied but not recorded`; the example (LLR-171.7a) asks for 12 rows → `10` lines holding "copied but not recorded" and `1` line holding "and 2 more". With the func wording the count would be 11. The code paints "and K more files not recorded in project.json", so both the token row's `and K more` and the example's count of 10 hold.

D-3 (LLR-171.2g problem next step). `ProjectFileProblem.step` accepts only the `STEP_*` marks of `variant_execution_service.DOCUMENT_NEXT_STEP` (not a G1 file, not a G2 file). The A2L problem therefore carries the R5 next step in its reason ("a link or junction — replace the A2L file, then Load again"); the load composer still appends the `not readable` kind's own step ("replace the file, or Save project to drop it"). The tokens the requirement names (`not readable`, `link or junction` / `too large to open`, `replace the A2L file, then Load again`) are all painted; the second next step is redundant text. A clean fix is one `STEP_*` mark in `variant_execution_service.py` — outside this increment's files; for E5 to rule.

D-4 (row 7 wording). The token table's full line starts "Links or junctions not copied:"; every example (LLR-171.1c, LLR-171.7a) asks for a line *holding* the token `links or junctions not copied`, which is case-sensitive. The code paints "Save as: links or junctions not copied: <names> — copy those files into the project if it needs them." so the token appears verbatim.

D-5 (AT-B100-10, "the Loaded panel names firmware.a2l") — NOT met, out of this file. Step (7) attaches the A2L as the graph says (`current_a2l_path` = `W/P/firmware.a2l`, `current_a2l_data`, `update_a2l_view()` → 3 tags, `_refresh_loaded_panel()`). But `LoadedArtifactsPanel._slot_state` (`screens_directionb.py`) reads the A2L slot only from `LoadedFile.a2l_path`; with no image there is no `LoadedFile`, so the slot paints "(none)" — the same as a standalone A2L load with no image at `ebe6d0c`. Making the panel name the A2L needs a change in `screens_directionb.py` (the slot reading the app's A2L when no file is loaded) or a design change; neither is in this increment's file set. The load announcement does name the A2L (`a2l_name=current_a2l_path.name`). For E5 / the orchestrator to rule.

## Implementation choices inside the graph (no behaviour change)

C-1. `_copy_project_subfolders` keeps a per-call set of the folder levels it has already checked and created, so the guard + `mkdir` run once per new level instead of once per file. Each NEW level is still checked by `_guarded_destination(level.parent, workarea)` before its `mkdir` (S3-5 b), and every file still goes through `place_into_workarea` with its destination unresolved. A `FileExistsError` folder is not added to `created_dirs` (this save did not create it).

C-2. `_plan_project_save` skips the inventory walk when the image step already refused (a blocked re-derive): the plan refuses with that refusal first in any case (A3-13), so the walk could not change the outcome.

C-3. Token row 9 and every load refusal paint the project name through `painted_names` and then `safe_text(...).plain`.

C-4. The `exempt` link rule is applied to both arms (same path; same name + size + digest): a target MAC / A2L that `lstat` does not show as a regular, non-reparse file is never exempt ("a target file that is a link is never exempt"). An `OSError` on the `lstat` or the digest leaves the name out of `exempt` (the plan then refuses with the row 4 / 5 text).

C-5. The free-space `OSError` arm paints "Project NOT saved: could not save — the free space of the work area could not be read — check the folder." (the graph names the `could not save` / `check the folder` tokens, no full line).

C-6. The R9 rebind is inline in `_handle_save_dialog` (the node set stays at 7): `document.source_path.absolute().relative_to(P.absolute())` (textual, `..` kept), refused when the relative text has `..` or is absolute, accepted only when it equals an entry of `plan.copies` or the document row's landing relative to `Q.resolve()`; the new path is `Q` joined with that text.

## Measurements

Probes (throwaway, in the session scratchpad, through the shipped handler in a headless `run_test` app, Windows 11, Python 3.11.15):

- R12, 2 000-file save as (P = case_01 project + top-level `a.json` + 1 999 one-byte files under `reports`; `plan.copies` = 2 000): `_handle_save_dialog` wall time 14.02 s and 13.98 s (two quiet runs; 14.57 s while a test run shared the CPU). Q held 1 999 files under `reports` and `a.json`; status "Saved project to …". cProfile: ~93 % of the copy time is inside `place_into_workarea` (2 003 calls), the two per-file containment re-checks ~10 %, the plan (inventory walk included) 0.30 s. Matches F-9's 12–18 s estimate; the background copy stays with Inc 12a.
- R16, entry ceiling on a NESTED tree (10 001 empty folders, two levels under `reports`; 10 004 walked entries): refusal "Project NOT saved: 'P' has too many files to copy (over 10 000 entries) — move files out of the project, then save again." in 0.973 s handler wall time (bound 5 s; example bound 2 s), Q absent.
