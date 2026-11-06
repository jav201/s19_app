# Inc 6 — E1 rulings: scope, canon changes, decisions

Base `9bb0e3a`; Inc 5 (`b101-inc5`, `6256ef4`) read as the merge-first neighbour. Every claim below was read in the code at `9bb0e3a` or measured by the pilot (`evidence-e1/i6e1-pilot-transcript.txt`, LAN Linux host, `s19_app.__file__` = the throwaway worktree).

## 1. Scope

| Finding / item | Cause (code at `9bb0e3a`) | Pilot | In scope |
|---|---|---|---|
| F-05 = D14-14 | `on_patch_editor_panel_save_back_decision` (`app.py:5063-5068`) notifies on every successful save-back, with no project test, and the text ends `(action: before_after_report).` | 1 offer without a project; `b` → `.11` refusal (already says `key 7`) | yes |
| D10-30 | The control hides only in the `load_doc` and `parse_paste` arms (`app.py:4815`, `:4823`); the dropdown pick (`:7054`), the guarded accept (`:7200`), undo/redo (`:5268`, `:5296`) and the project reset (`:13412`) hide nothing; the save-back prompt hides only on its own buttons | control stays after a pick; prompt stays after a pick and after undo | yes |
| F-06 = D10-25 | `_scan_patch_change_files` (`app.py:6898`) lists `workarea/patches/` only; Save writes `<project>/patches/` or `checks/` (`_change_doc_save_home`, `:6856`) | Save → `proj/patches/changes.json`; dropdown 0 options | yes |
| D9-15 | Check Editor Write calls `write_change_document(document, base_dir, file_name)` with no destination (`app.py:7374`): always `workarea/patches/`; its Spec list (`:7255`) and pick guard (`:7464`) use the same common folder; the 📂 chip already opens `<project>/checks/` (`folder_open_service._family_homes`) | spec written to `patches/s1.chk.json` with `proj` open | yes |
| D14-17 | The A2B Diff list (`_compose_screen_diff` `:6779`, `_prefill_diff_check_files` `:6830`) and its pick guard (`on_ab_diff_panel_check_file_selected` `:7765`) use the same scan and folder | lists the common file | **yes, ruling D-1** |
| F-40 = D9-10 | `last_check_result` survives `load` / `load_text` / entry edits (`change_service.py:839-841`); nothing re-renders the Checks tab on a load, an image install (`app.py:18003-18045`) or the project reset (`:13531`, which rebinds the service); `update_checks_view` gates on `last_check_result is None` (`:16520`); the tab's subtitle comes from the row count (`screens_directionb.py:6929-6932`) | 2 stale rows, `2 checked`, `✓1 ✗1` after a document, an image and a project load; 0-entry run → `no run yet` | yes |
| F-47 | Only the `b` binding (`app.py:2719`) and the panel control reach `action_before_after_report` | not reproduced (0 refusals after start and project load; only `b` triggers) | **no product change** (§4) |

Out of scope, recorded: (a) an image load while a save-back prompt is open leaves the prompt (no canon row; backlog); (b) the before/after control without a project (ruling D-2); (c) the common library is not listed while a project is open (D-3).

## 2. Changes to canon rows (applied at integration)

| Row | Change | Reason |
|---|---|---|
| R-TUI-049.3 | split into **R-TUI-049.3.1** (hide the before/after control) and **R-TUI-049.3.2** (hide the save-back prompt); the condition gains "a project load" | E2: one object per row; D-5 |
| R-BEFORE-AFTER-REPORT-001.36 | **new**: `If no project is open when a save-back succeeds, then the system shall show no before/after offer.` | E2: the "only with a project" of .1 needs its "does not" row (D14-14) |

No other row text changes. The ids were checked absent from `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl`, `tests/`, the `.dev-flow/` of this worktree and of `b101-inc5`, and `s19w/review` on 2026-11-06.

## 3. Context notes amended (canon, applied at integration)

- **S10 CTX-PE-DOC, change list** — was: "Every *.json file of the change home that is not a link, sorted by name." / now: "Without an open project: every *.json file of workarea/patches/ that is not a link, named by its file name. With an open project: every such file of <project>/patches/ and of <project>/checks/, named patches/<file name> and checks/<file name>. Sorted by name." Reason: with a project the change home is two folders (by kind), and both hold a default `changes.json`; a bare name cannot say which one is meant (D-3).
- **S9 CTX-CHECK-TEXT, current run** — was: "… while the document's entries (type, address, bytes, in order) and the loaded image are the ones it ran over. Undo and redo end it." / now: "… while the document's entries (type, address, bytes, in order) are the ones it ran over and no image load or project load has happened since. Undo and redo end it." Reason: "the loaded image" did not say whether an apply or a new load ends the run; D9-10 rules "the stamp the ledger glyphs already use", which is the install counter (`app.py:18003`), not the image bytes. Effect: an apply alone does not end a run (in the Patch Editor an apply after a run needs a new document first, which ends it).

## 4. F-47

Not reproduced at `9bb0e3a`. The guide's driver (`guide_run.py`, outside the repo, DOSSIER §3) is not available, so the ch17/18 sequence could not be replayed. The pilot shows the action has exactly two triggers and fires on no startup or project-load path. The likely cause is a key the driver sent while no input had focus (a race in the driver), not product code. Per the P0 risk row: no product change; carry F-47 to the backlog with this evidence, and keep the guide driver in-repo for the next capture run.

## 5. Decisions (each needs the orchestrator; recommendation given)

| Id | Question | Recommendation |
|---|---|---|
| D-1 | Take D14-17 (A2B Diff check-spec list = check home) into Inc 6? | **Yes.** The three lists share one scan (`_scan_patch_change_files`); moving the check home without the A2B list makes a spec written in a project vanish from that list (R-CHKED-033, R-DIFF-CHK.1) — a regression this increment would cause. Same file, three small functions |
| D-2 | Gate the before/after **control** (R-TUI-049.1) on a project too? | **No, keep R-TUI-049.1.** Pressing it without a project gives the `.11` refusal, which names the manual path; hiding it is a further visible change; backlog row for the next UI round |
| D-3 | Option text of the Patch Editor dropdown with a project | **`patches/<name>` / `checks/<name>`** while a project is open; bare names without one (unchanged). Visible: the options gain their folder only in a project. The common library is not listed in a project (canon change home); a common file is loaded by the typed path |
| D-4 | F-47 | **Carry, no product change** (§4) |
| D-5 | Does a project load count as "the document is replaced" for R-TUI-049.3.x? | **Yes.** The project reset discards the document and the last apply (`_reset_project_session` rebinds `ChangeService`); a pending prompt would save the old apply into the new project |
| D-6 | A linked `patches/` or `checks/` folder in a project | List its names (plain text, as today) but refuse every pick and Write through it: the guard requires the resolved file inside the open project folder (R-PATCH-DOC-DROPDOWN-001.4, R-CHKED-044, R-DIFF-CHK.5); Write goes through the writer's placement checks (R-CHKED-034). No new row |

## 6. Interfaces with other increments

- **Inc 5** (merges first) edits `on_patch_editor_panel_action_requested` (after the `try`), `on_patch_editor_panel_save_back_decision` (after `save_patched`), `on_check_editor_panel_spec_file_selected` (the item dicts), `_on_project_saved`, `_check_items_to_document`, new `_note_image_bytes_written`, and `CheckEditorPanel` methods. Inc 6 touches the first three in other lines (the `parse_paste` arm and the handler's last lines; the notify at the end; the guard at the top) — graph §Interfaces.
- **Inc 15** (merged): tests wait on `document.source_path` and `#patch_saveback_row`'s `hidden` class for Load, paste, pick, Apply and the save-back buttons. Inc 6 does not move these observables.
- **Inc 4** (merged): the pick handlers keep `read_change_document(…, a2l_context=self.current_a2l_data)`.

## Orchestrator rulings on E1 decisions (2026-11-06)

Taken under the operator's standing commission (decide with a recorded reason).

- **D-1 → yes**, add D14-17: the A2B Diff check list follows the check home. Why: the three lists share one scan; without it a spec written in a project disappears from that list (same defect as F-06, same files).
- **D-2 → no**, keep R-TUI-049.1; gating the before/after control on a project is a backlog row. Why: not needed by any reproduced finding; it would change a visible control (UI rows are out of scope by the operator's P0 ruling).
- **D-3 → accept.** With a project open, the Patch Editor dropdown lists `patches/<n>` and `checks/<n>`; common-library files open by typed path. Why: this is the F-06 defect becoming correct (the pilot shows 0 options after a Save in a project); the prefixes are the minimum that tells two homes apart. Recorded as the one visible change the increment admits.
- **D-4 → yes**, F-47 goes to the backlog with the pilot evidence; no product change. Why: not reproduced (P0 risk rule: no change without a reproduced cause).
- **D-5 → yes**, a project load counts as replacing the document. Why: the stale save-back prompt and check rows after a project load are the same defect as after a file load (D10-30, F-40).
- **D-6 → yes**, a linked project folder's files are listed but every pick and Write through the link is refused, with the existing refusal text named in the row. Why: same path-safety rule as D15-18 (no write lands outside the work area through a junction); refusal is simpler than resolving the link.
- **Overlap with Inc 5:** Inc 5 merges first; Inc 6 rebases on main before E4 and re-checks the three shared functions' line ranges.
