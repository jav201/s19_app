# Inc 6 — E3 security review (design, code-free)

**Verdict: PASS-WITH-NOTES.** There is no BLOCKER and no HIGH finding. No designed Write can land outside the work area or the open project through a link or `..`. The Check Editor Write (#23) goes through `write_change_document` → `place_into_workarea` → `_guarded_destination`. That guard walks every reparse point on the unresolved path, and it runs before the `mkdir`. The claim is an `O_EXCL` claim of a free name with an `lstat` re-check, so nothing is overwritten and a hard link in the folder is harmless. There are two MAJOR findings. S-1: a save-back prompt left open across an image load writes a file the operator never reviewed, and makes it the project's active variant. S-2: in a project, existing specs drop out of two screens' lists and those screens have no other way to reach them. Five MINOR or LOW findings concern the new pick guard. This review clears design risk only. It is not merge authority.

## Scope reviewed

- `01-requirements.md`, `E1-rulings.md` (with the orchestrator rulings), `E1-slice.md`, `02-test-cases.md`, `codewire/graph-inc6.md`.
- Code read at `2c323ee` (= base `9bb0e3a` plus records):
  - `app.py`: the save-back handler (`:4943-5068`), the action handler (`:4733-4940`), the pick guard (`:7054-7125`), `_patch_editor_load` and its tail (`:7127-7198`), `_change_doc_save_home` (`:6856`), screen activation (`:9590-9606`), `_reset_project_session` (`:13412`), `list_projects`, `_apply_prepared_load`.
  - `change_service.py`: `load`, `save`, `save_patched` (`:2575-2618`), `rederive_for_save`, `adopt_rederived`, `_note_image` (`:1812-1814`), `run_checks`, `_document_signature`, `_check_glyphs`.
  - `changes/io.py`: `write_change_document`, `list_change_documents`.
  - `workspace.py`: `_guarded_destination` (`:754-798`), `place_into_workarea` (guard at `:1189`, `mkdir` at `:1200`).
  - `project_gather_service.py`: `classify_active_document` and `document_in_home` (`:273-351`), `scoped_home` and `scoped_home_target`.
  - `utils.py`: `safe_text`.
  - `b101-inc5`: `_note_image_bytes_written` and its three call sites.
- One probe on the LAN Linux host, with Textual 8.2.8. It used plain Textual and did not import `s19_app`. Its folder `/tmp/i6e3s` has been removed. It tested whether a hidden, focused button still takes Enter. It does not: hiding the button cleared focus, closing a modal did not give focus back to the hidden button, and the button counted 0 presses. So a hidden prompt cannot be pressed.

## Findings

| Id | Severity | Row / node | Finding | Proposed fix |
|---|---|---|---|---|
| S-1 | MAJOR | R-TUI-049.3.2; `_apply_prepared_load` (#10); out-of-scope item (a) | **An image load leaves the save-back prompt open.** This is the larger half of the D10-30 defect, and the records carry it to the backlog with no stated consequence. If the operator confirms after loading image 2, `save_patched` re-derives onto `current_file`, so it writes image 2 plus the document. The file gets image 1's suggested name (`<old variant>-patched.s19`). `record_save_entries` runs before `adopt_rederived` → `_note_image`, so the save is not told the entries were never applied to image 2, and the status shows no not-applied suffix. With a project open, the file becomes the active variant and `project.json` is rewritten. I read this in the code; I did not run it. | Add the hide (#9) to #10's `else` block, which the slice already touches. Add "an image load" to the conditions of R-TUI-049.3.1 and .3.2 (the same reasoning as D-5), with 2 cases. If it stays out of scope, write this consequence into the backlog row. |
| S-2 | MAJOR | R-CHKED-040, R-DIFF-CHK.1; D-3 | **Existing specs drop out of two lists inside a project.** At base, every Check Editor Write went to `workarea/patches/`, also with a project open (D9-15). With this change those specs are no longer listed in the Check Editor or the A2B Diff while the project is open. D-3's workaround, opening the file by typing its path, exists only in the Patch Editor. Neither of these two screens has a path input (`screens_directionb.py:7647-7663`, `:8258-8268`). The records do not admit this visible change. | Record the consequence and a path for the operator: copy the files into `<project>/checks/` (the 📂 chip opens that folder). Or list the common library read-only, for example as `library/<name>`. Add a case. |
| S-3 | MINOR | `_resolve_listed_file` (#16); D-6; Definitions, "Linked folder" | **The pick guard and the Write guard decide differently.** The pick guard resolves both paths and compares them; the Write guard walks reparse points. So the pick guard accepts:<ul><li>a link that stays inside the project, for example `proj/checks` → `proj/patches` (the S8-2 shape that Inc 9 / D15-18 owns);</li><li>without a project, a linked `workarea/patches` (the same as base).</li></ul> In both cases the Write refuses the same folder that a pick accepts. Neither interface table names Inc 9. | Guard with `_is_reparse_point` and `_path_traverses_reparse_point(folder / name, stop_at=workarea.parent)`, the rule the Write already applies. Widen "Linked folder" to any link. Name Inc 9 as an interface. |
| S-4 | MINOR | #16 return value; Save project | **The guard returns the resolved path, and the save classifier expects the unresolved one.** The returned path becomes `document.source_path`. `classify_active_document` and `document_in_home` compare unresolved text exactly (SEC8a-1, LED .50). If `base_dir` is spelled in a non-canonical form (on Windows: a `subst` drive, an 8.3 short name, or different letter case), a picked project file is classed `outside`. Save project then copies it, or reuses an identical copy, and skips the "unsaved edits" warning. | After the guard passes, return `folder / name` unresolved. Add a case asserting that a picked file is classed `in_home`. |
| S-5 | MINOR | `on_patch_editor_panel_change_file_selected` (#17) | **Time-of-check gap at the unsaved-changes popup.** The answer callback loads the `candidate` that was checked before the popup opened. A folder replaced by a link while the popup is open would be read through. This also happens at base. | Run #16 again inside `_answer`. |
| S-6 | MINOR | R-PATCH-DOC-DROPDOWN-001.4, R-CHKED-044, R-DIFF-CHK.5 | **Row text does not state what D-6 adds.** The rows stay marked "unchanged", but D-6 adds the refusal "under a linked folder or outside the project". "Lies outside its folder" does not clearly cover a file inside a linked folder, so the row cannot be verified against that case. | Add the condition to the row text, or to a context note. |
| S-7 | LOW | #12 / #15 labels | **File names from project folders keep bidi and format characters on screen.** `safe_text` strips C0/C1 control characters only. It keeps U+202A–U+202E, U+2066–U+2069 and U+200E/U+200F, and these now reach 3 lists. The refusal status is safe because `repr` escapes them. | Backlog: scrub these characters in `safe_text`. `utils.py` is outside the slice. |

## Checked, no finding

- **The before/after offer.** The `b` key and the control refuse after every replacement: `load`, `load_text`, undo, redo and the project reset all clear `last_summary`.
- **Displayed check verdicts.** The stamp (entries plus image generation) covers every path that writes bytes in place: an apply, a save-back and a Save project commit, Inc 5's census. An apply or a Save project emit under a check document is blocked (`_decide_project_image` returns `emit=False`; `rederive_for_save` marks every entry `blocked`), so the amended "current run" note holds. No other reader of `last_check_result` exists.
- **A linked project folder.** `list_projects` and `_project_folder_refusal` refuse one at load. The Write guard also catches one that appears after the load.
- **Where the Write root comes from (note).** `write_change_document` places files with a work-area root it reads from the destination path. The Patch Editor Save, already shipped, does the same. The save-back passes the root explicitly (SEC-4). It is acceptable here because the project folder is always `self.workarea/<name>`.

## Round 2

**Verdict: PASS-WITH-NOTES.** S-1 and S-2 are closed in the design at `64c24ac`. The revised D-3 opens no hole that can write outside the project home, overwrite a file, or read through a link. There are two new LOW notes (S-8, S-9). Each mitigation is `planned` until E4 runs its cases. This clears design risk only. It is not merge authority.

Scope: `E3-rulings.md`, `git show HEAD --stat` (the five records), and the base code they rely on: `ChangeService.save` / `save_patched`, `write_change_document` / `_safe_name` / `list_change_documents`, `place_into_workarea` (the `lstat` + `O_EXCL` claim, `_placed_name_candidates`), `_path_traverses_reparse_point`, `RESERVED_WORKAREA_HOMES`, `_apply_prepared_load`, `_apply_unload` / `_unload_primary`, the save-back handler, and the Save project document handling (`app.py:12650-12680`, `:13070-13100`). Read only; nothing imported `s19_app`.

### S-1 — closed (design)
- #10 hides the prompt and the control when `loaded.mem_map is not previous_map`. `previous_map` is taken before `current_file` is replaced. `current_file` is assigned in three places: `_apply_prepared_load`, `_apply_unload` and the project reset (#7 hides there). So every new image dict passes through the hide. A MAC attach keeps the dict and the bytes, so a confirm after it still writes the reviewed image under its own name.
- A primary unload leaves the prompt painted. A confirm after it writes nothing: `_unload_primary` gives `file_type="mac"`, which `save_patched` refuses (`CHG-HEX-SAVE-UNSUPPORTED`). An unload of all gives `current_file None`, which the handler refuses. In both cases `ok=False`, so neither `_activate_project_file` nor `_rewrite_project_manifest` runs. No finding.
- R-TUI-049.3.1 and .3.2 now name the image load. Cases /8 cover it (the oracle: not painted, and no `img-patched.s19`). The case runs with no project open. The project half of the consequence, the `project.json` rewrite, uses the same hide, so it needs no case of its own.

### S-2 — closed (design)
- The library appears as `library/<n>` in all three lists while a project is open (`_change_homes` #12, `_spec_homes` #32, the CTX *change list* / *spec list* amendments). It is reachable through #16 (cases R-PATCH-DOC-DROPDOWN-001.2/2, 001.3/3, R-CHKED-040/1, R-CHKED-042/1, R-DIFF-CHK.1/1, R-DIFF-CHK.8/1). No function is lost.

### Revised D-3 — no new hole
- **Where Write lands after a `library/<n>` pick.**
  - Patch Editor Save calls `service.save(base_dir, dest_dir=_change_doc_save_home())` with the default name `changes.json`. It never uses the source path, so it never writes the library file.
  - Check Editor Write writes to `_check_home()` with the bare Write as name (R-CHKED-042).
  - Save project copies a library document into the project as `outside` through `place_into_workarea`.
  - All three take the claim: an `lstat`, then `O_CREAT|O_EXCL` on the first free `<stem>_<N><suffix>`, with byte-identical reuse. A project file of the same name is never overwritten (R-CHKED-031/3).
- **A library entry as a link.** The listing skips symlinks (`is_symlink`). #16 walks the file, `workarea/patches`, and `workarea` (stopping at `.s19tool`, exclusive), and it also checks `.s19tool`. A junction directory named `x.json` is listed, because `glob` matches folders, but the pick is refused. A hard link is only read. Writes go to a new claim, never into an existing inode.
- **Prefix ambiguity.** `glob("*.json")` lists direct children only. No file name on Windows or Linux can hold `/`, so a file literally named `library/x` cannot exist. With a project open, the three prefixes are distinct and none starts another. The `""` home exists only without a project. A stale list fails closed: `patches/a.json` with no project holds a separator, and `w.json` in a project matches no prefix, so both are refused. A project cannot be named `patches`, because `RESERVED_WORKAREA_HOMES` is case-folded, so no project folder is the library. `current_project_dir` is set only at `:12683` and `:14090`, and both refill the lists (#35).

### S-3 … S-6 — landed as ruled
- S-3: #16 uses the Write guard's walk and stop point. "Linked folder" now covers any link (Definitions). Inc 9 is named in `E1-rulings.md` §6 and in the graph's interface table. Case 001.4/4.
- S-4: #16 returns the unresolved `folder / name`. Cases 001.3/1 and /4.
- S-5: `_answer` runs #16 again. Case 001.4/5.
- S-6: the rows 001.4, R-CHKED-044 and R-DIFF-CHK.5 state the linked-folder condition. S-7 is in the backlog as (d).

### New notes

| Id | Severity | Where | Finding | Proposed fix |
|---|---|---|---|---|
| S-8 | LOW | `E1-rulings.md` §5, D-6 row, first sentence | The row still says "the guard requires the resolved file inside the open project folder". An implementer who follows it refuses every `library/<n>` pick and brings S-2 back. The graph (#16: inside the resolved work area) is right. | Strike the clause or replace it with #16's rule. |
| S-9 | LOW | `_on_project_saved` (#37), `app.py:12663` | The "has unsaved edits" line fires only for `in_home`. If a library document is edited and Save project runs, the project records the library file as it is on disk and shows no line. The panel stays dirty. This happens at base for a typed path too; revised D-3 makes it one pick away. No data leaves the work area. | Backlog: extend the line to a copied `outside` document. |

Outside the security lens, for the architect: a Write collision names the new file `w.chk_1.json` (`_placed_name_candidates`). The name no longer ends `.chk.json`, so it is listed as ` PATCH`. This happens at base too.

### Evidence checklist
- ✓ Every finding has what, where, why and a fix (table above).
- ✓ Every finding has a severity.
- ✓ No secret values (none in scope).
- ✓ The verdict is explicit. There is no HIGH.
- n/a — no new tool or integration.
