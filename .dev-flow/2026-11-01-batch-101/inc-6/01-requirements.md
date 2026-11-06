# Inc 6 — Patch Editor document lifecycle: requirements (E1)

Batch 2026-11-01-batch-101, increment 6. Base `9bb0e3a` (main: Incs 1, 2, 3, 4, 7, 8, 11, 13, 14, 15, 16). Designed against main plus Inc 5 (`b101-inc5`, in flight; it merges first). Findings F-05, F-06, F-40, F-47 (`docs/user-guide/DOSSIER.md` §5); CODE-CHANGES D14-14, D10-25, D9-15, D9-10, D10-30, and D14-17 (co-located, ruling D-1 in `E1-rulings.md`).
Rulings, decisions and canon changes: `E1-rulings.md` (E3 round-1 corrections of `E3-rulings.md` folded in, 2026-11-06). Slice: `E1-slice.md` (source files `s19_app/tui/app.py`, `s19_app/tui/services/change_service.py`, `s19_app/tui/screens_directionb.py`, `s19_app/tui/window_help.py`). Cases: `02-test-cases.md`. Graph: `codewire/graph-inc6.md`. Pilot on `9bb0e3a`: `evidence-e1/i6e1-pilot-transcript.txt` (`P` below).

Form column: U = ubiquitous, E = event (`When`), S = state (`While`), N = unwanted (`If … then`). Row texts marked "unchanged" are the canon's; the increment changes the code (and, where stated, a context note). "Base" = what `9bb0e3a` does.

## User stories

### US-PE-LIFE-1 — no report offer I cannot use
As the operator, after a save-back with no project open, I want no "press b" notice, so that the app does not tell me to press a key whose report it then refuses (F-05; P: 1 offer shown, `b` refused). The persistent before/after control stays (D-2); pressing it gives the `.11` refusal, which names the manual path.

### US-PE-LIFE-2 — what I save in a project is in the lists
As the operator, with a project open, I want the Patch Editor file list to show the documents I saved into the project, and a check spec I write to land in the project's `checks/` and show in the Check Editor and A2B Diff lists, with the common library's files still listed after the project's (revised D-3), so that saving and finding use one folder and no earlier file is lost (F-06; P: `proj/patches/changes.json` written, dropdown empty; spec written to `patches/s1.chk.json` of the common folder).

### US-PE-LIFE-3 — the Checks views show the run I have now
As the operator, I want the Checks tab and the Checks screen to show a run only while its document is the one loaded and no load or in-place write of the image has happened since, so that a result never describes another document, image, image state or project (F-40; P: 2 stale rows after a document load, an image load and a project load; E3 probe: `1 passed` stays after an apply put the byte back).

### US-PE-LIFE-4 — a new document starts clean
As the operator, when the document is replaced or another image is loaded, I want the save-back prompt and the before/after control of the old apply gone, so that I cannot save or report the old apply under the new document or onto the new image (D10-30, S-1; P: both stay after a dropdown pick, the prompt after undo).

## Definitions

- **Fixture image** `img.s19`: one S1 record, 16 bytes `00 01 … 0F` at `0x8000`. **Image 2**: the same addresses, bytes `40 41 … 4F`.
- **Document C**: kind change, one bytes entry `0x00008003` = `AA`. **C2**: `0x00008005` = `BB`. **Check K**: kind check, entries `0x00008000` = `00` (pass) and `0x00008001` = `FF` (fail). **Check E**: kind check, no entry. **Check K1**: kind check, one entry `0x00008003` = `AA`. **Check W**: kind check, one entry `0x00008000` = `00`, stored as `workarea/patches/w.chk.json` (a common-library spec).
- **MAC file** `m.mac`: the one line `T=0x8000`.
- **Project `proj`**: folder `.s19tool/workarea/proj/` holding a variant `v.s19` (bytes `10 … 1F` at `0x8000`).
- **A load** (S10.2): Load, a dropdown pick, or the accept of the unsaved-changes popup.
- **An image load**: a file load (`ctrl+l`, a variant pick, a project's variant) that installs a new S19 or HEX image. A MAC load that keeps the loaded image is not an image load. **A MAC load**: a file load of a MAC file.
- **Linked folder**: a folder that is a symbolic link or, on Windows, a junction, at any level from the work area down to the file, also when it points inside the open project (the rule Write applies, S-3).
- Canon terms used as they are: change home, change list (amended, `E1-rulings.md` §3), check home, spec list (amended, §3), current run (amended, §3), before/after control, save-back prompt, offer.

## Requirements

### S14.9 — the before/after offer (US-PE-LIFE-1)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-BEFORE-AFTER-REPORT-001.1 | E | When a save-back succeeds with a project open, the system shall show the offer `Before/after report ready - press b to write it to the project reports directory.` **(unchanged)** | exactly 1 offer, text equal; 3/3 | offer text keeps ` (action: before_after_report)` → RED | US-PE-LIFE-1 | No: text ends `(action: before_after_report).` (P) |
| R-BEFORE-AFTER-REPORT-001.36 | N | If no project is open when a save-back succeeds, then the system shall show no before/after offer. **(new: the "does not" half of .1, rule E2)** | 0 notifications titled `Before/after report`; 3/3 | the offer not gated on a project → 1 offer → RED | US-PE-LIFE-1 | No: 1 offer (P) |
| R-BEFORE-AFTER-REPORT-001.11 | N | If no project is open, then the system shall refuse the report with the reason `No active project - the before/after report needs a project reports/ destination; use the manual A<->B Diff report (key 7) with an explicit destination instead.` **(unchanged)** | status `Before/after report refused: <reason>` exact; 0 files; 3/3 | reason says `(screen 7)` → RED | US-PE-LIFE-1 | Yes (P; tests `test_r_before_after_report_001_11_1/_2`) |

### S10.8 — what a replaced document leaves (US-PE-LIFE-4)

**R-TUI-049.3** — Withdrawn: split into R-TUI-049.3.1 and R-TUI-049.3.2 (rule E2: one object per row; the condition also names the project load, ruling D-5).

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TUI-049.3.1 | E | When the document is replaced by a load, a project load, a paste, undo or redo, or an image load completes, the system shall hide the before/after control. | `Before/after report available:` absent from the painted screen after each of the 8 alternatives; 8/8; still painted after a Save project (/9) | the hide left out of the load path → dropdown pick and guarded-load arms RED; left out of the install → image-load arm RED | US-PE-LIFE-4 | Partly: hidden after Load and paste only (P: stays after a dropdown pick) |
| R-TUI-049.3.2 | E | When the document is replaced by a load, a project load, a paste, undo or redo, or an image load completes, the system shall hide the save-back prompt. | `Save patched image as:` absent from the painted screen after each of the 8 alternatives; 8/8; still painted after a redo with no step (/7) and after a Save project (/9) | the undo path without the hide → undo arm RED; the install without the hide → image-load arm RED | US-PE-LIFE-4 | No: stays after every alternative (P: dropdown pick, undo; image load read in code, S-1: a confirm then writes image 2 under the old variant's name) |

### S10.2 — the File dropdown (US-PE-LIFE-2)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-PATCH-DOC-DROPDOWN-001.1 | E | When the Patch Editor is opened, a Save or a Refresh ends, or a project load or a Save project completes, the system shall fill the File dropdown with the change list. **(trigger amended: project load, Save project, E3A-04; "change list" amended)** | option values equal the change list exactly, in order; 6/6 cases | the scan of `workarea/patches/` only → project arms list 0 options → RED; no refill after the project install → the project-load arm keeps the old values → RED | US-PE-LIFE-2 | Partly: lists `workarea/patches/` also with a project (P: 0 options after a Save into `proj/patches/`); a project load or a Save project refills nothing (read in code, E3A-04) |
| R-PATCH-DOC-DROPDOWN-001.2 | N | If the change list is empty, then the system shall show the dropdown with its prompt `Change files in patches/` and no option. **(condition amended: was "the change home holds no change document"; revised D-3 lists the library in a project)** | prompt exact, 0 options when the list is empty; 1 option when only the library holds a file; 2/2 | emptiness decided on the project folders alone → the library-only arm shows no option → RED | US-PE-LIFE-2 | Yes without a project; with one, the library is not listed (D-3 at E1) |
| R-PATCH-DOC-DROPDOWN-001.3 | E | When the operator picks a file in the dropdown, the system shall load it as the document. **(unchanged)** | document source = the picked file of its folder, spelled as the work area is spelled; 4/4 | the pick resolved under `workarea/patches/` → `checks/k.chk.json` refused → RED; the resolved path returned → the alias arm loses its unsaved-edits line → RED | US-PE-LIFE-2 | Partly: only common-folder names exist; the source is the resolved path (S-4) |
| R-PATCH-DOC-DROPDOWN-001.4 | N | If the picked file is a link, lies under a linked folder, or lies outside its folder, then the system shall refuse it with the status `Patch Editor: change file '<name>' is outside the patches folder — not loaded.` **(condition amended: "lies under a linked folder", D-6, S-6)** | status exact, document unchanged; 5/5 | guard resolves and compares instead of walking the links → the inside-project link arm loads → RED; no re-check after the popup → the popup arm loads through the link → RED | US-PE-LIFE-2 | Yes for the common folder; a linked `workarea/patches/` loads (S-3); the popup accept loads the pre-checked path (S-5) |

### S9.4 and S14.6 — one check home (US-PE-LIFE-2)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-CHKED-031 | E | When the operator writes a spec, the system shall place it in the check home. **(unchanged)** | file at `<home>/<name>` and nowhere else, also after a library pick; 3/3 | Write without the check home → `workarea/patches/s1.chk.json` → RED | US-PE-LIFE-2 | Partly: always `workarea/patches/` (P) |
| R-CHKED-032 | E | When a spec is written, the system shall show the status `Check Editor: wrote <listed name> (<n> fields, kind=check).`, where `<listed name>` is the written file's value in the Spec list: `checks/<name>` with a project open, `<name>` without one. **(amended at E5, C-9 = SEC E5-2: was `Check Editor: wrote <name> (<n> fields, kind=check).`)** | status exact, also after a library pick and on a name collision (the claimed name); 4/4 | status names the bare file → project arm reads `wrote s1.chk.json` → RED (M44) | US-PE-LIFE-2 | Yes at base (one home, so the bare name is the listed value); with Inc 6's project home the bare name no longer says which home was written (SEC E5-2) |
| R-CHKED-034 | N | If the writer refuses a spec, then the system shall show the status `Check Editor: spec NOT written.` **(unchanged; new case: a linked check home)** | status exact; 0 files outside the project; 1/1 | destination not containment-checked → file written through the link → RED | US-PE-LIFE-2 | n/a at base (Write never used the project) |
| R-CHKED-040 | E | When the operator opens the Check Editor, writes a spec, or a project load or a Save project completes, the system shall fill the Spec dropdown with the spec list. **(trigger amended: project load, Save project, E3A-04; "spec list" amended)** | option values equal the spec list exactly, in order; 3/3 | the common-folder scan → project arm lists `w.chk.json` bare → RED; no refill after a Save project → RED | US-PE-LIFE-2 | Partly: common folder only; no refill on a project change |
| R-CHKED-042 | E | When the operator picks a spec, the system shall set the Write as input to the spec's name ending in `.chk.json`. **(unchanged)** | Write as input = the file name with no folder part; 1/1 | the listed value passed as the name → `library/w.chk.json` → RED | US-PE-LIFE-2 | Yes (values had no folder part) |
| R-CHKED-044 | N | If the picked file is a link, lies under a linked folder, or lies outside its folder, then the system shall refuse it with the status `Check Editor: file '<name>' is outside the patches folder — not loaded.` **(condition amended: "lies under a linked folder", D-6, S-6)** | status exact, collector unchanged; 2/2 | as R-PATCH-DOC-DROPDOWN-001.4 → RED | US-PE-LIFE-2 | Yes for the common folder |
| R-DIFF-CHK.1 | E | When the A2B Diff is shown, or a project load or a Save project completes, the system shall fill the check-spec list with the spec list. **(amended: trigger and object, revised D-3, E3A-04; the old text is in `E1-rulings.md` §2)** | option values after `(no check spec)` equal the spec list exactly, in order; 3/3 | the common-folder scan → RED; no refill after the project install → RED | US-PE-LIFE-2 | Partly: common folder only (D14-17) |
| R-DIFF-CHK.3 | N | If the spec list is empty, then the system shall leave out the check row. **(condition amended: was "the check-spec folder holds no `.json` file"; revised D-3)** | `Check spec:` absent from the painted A2B Diff; 1/1 | the row composed for an empty list → RED | US-PE-LIFE-2 | Yes at compose; a list emptied after the row exists keeps an empty row (backlog, E3A-11) |
| R-DIFF-CHK.5 | N | If the picked file is a link, lies under a linked folder, or lies outside its folder, then the system shall show the status `Check spec: '<name>' is outside the patches folder — not loaded.` **(condition amended: "lies under a linked folder", D-6, S-6; "the check-spec folder" → "its folder")** | status exact; 2/2 | guard rooted at the common folder → the project file refused → RED | US-PE-LIFE-2 | Yes for the common folder |
| R-DIFF-CHK.8 | E | When a check spec loads, the system shall show the status `Check spec '<name>' loaded — <n> declared field(s) will ride the report.` **(unchanged)** | status exact for a library pick in a project; 1/1 | library values resolved under the project → refused → RED | US-PE-LIFE-2 | n/a at base (the library was the only folder) |

### S9.2 and S9.3 — only a current run is shown (US-PE-LIFE-3)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-CHK-PE-008 | S | While the Checks tab is shown and a current run with n entries exists, the system shall show the inspector subtitle `<n> checked`. **(unchanged)** | `2 checked`, `0 checked`, and `2 checked` again after Add + Remove; 3/3 | subtitle from the row count → 0-entry arm `no run yet` → RED | US-PE-LIFE-3 | Partly: 0-entry run shows `no run yet` (P) |
| R-CHK-PE-009 | S | While the Checks tab is shown and no current run exists, the system shall show the inspector subtitle `no run yet`. **(unchanged)** | `no run yet` after each of 6 alternatives; 6/6 | no re-render at the load tail → doc-load arm `2 checked` → RED; the in-place-write hook without the run end → apply arm `1 checked` → RED | US-PE-LIFE-3 | No: `2 checked` stays (P: document, image, project load); `1 checked` stays after an apply (E3 probe) |
| R-CHK-PE-010 | S | While no current run exists, the system shall show `No check run yet: press Run checks.` as the Checks tab status. **(unchanged)** | status exact; 2/2 | as -009 → `Checks: 1 passed, 1 failed, 0 uncheckable` → RED | US-PE-LIFE-3 | No (P) |
| R-CHK-PE-011 | S | While no current run exists, the system shall show the patch strip with zero counts and an empty bar. **(unchanged)** | strip `✓0 ✗0 ◐0` / `░░░░░░░░`; 2/2 | `check_aggregates` not gated → `✓1 ✗1` → RED | US-PE-LIFE-3 | No (P) |
| R-CHK-PE-012 | S | While no current run exists, the system shall show no result row on the Checks tab. **(unchanged)** | 0 children in `#patch_checks_results`; 2/2 | as -009 → 2 rows → RED | US-PE-LIFE-3 | No (P) |
| R-CHK-PE-014 | S | While no current run exists, the system shall lead each ledger row's Kind cell with `·`. **(unchanged)** | Kind cell `·` after a save-back that ended a run; 1/1 | the in-place-write hook ends the run without repainting the ledger → `◐` stays → RED | US-PE-LIFE-3 | n/a at base (a save-back ended no run) |
| R-CHKS-001 | E | When the operator opens the Checks screen, the system shall show the current run. **(unchanged)** | grouped rows of the current run; no-run note after a document load; 2/2 | gate on `last_check_result is None` → stale groups → RED | US-PE-LIFE-3 | Partly: shows the last run (P) |
| R-CHKS-004 | N | If a file is loaded and no current run exists, then the system shall show the note `No check run yet — run checks from the Patch Editor.` in the grouped list. **(unchanged)** | note exact, also painted while the screen stays displayed; 2/2 | as -001 → RED; no Checks-screen repaint at the install → the displayed-screen arm keeps the groups → RED | US-PE-LIFE-3 | Partly: only when no run was ever made or after undo/redo; a displayed screen is not repainted (E3A-02) |
| R-CHKS-009 | S | While no current run exists, the system shall show the aggregate line with zero counts and an empty bar. **(unchanged)** | zero line exact, also while the screen stays displayed; 2/2 | aggregates not gated → `Pass 1 / Fail 1` → RED; no repaint at the project reset → displayed arm RED | US-PE-LIFE-3 | Partly (as -004) |

## Not a requirement here

- **F-47** (a before/after refusal "right after start"): not reproduced on `9bb0e3a` (P: 0 refusals after start and after a project load; of the keys `p / g tab enter space ctrl+z ] B b` only `b` reaches the action, 1 refusal). No row and no product change (P0 risk ruling); carried, `E1-rulings.md` §4.
- **E3 backlog** (no row here): bidi and format characters in listed names (S-7); the "patches folder" wording of the three refusal texts for a `checks/` or `library/` pick (E3A-10); an A2B check row left empty after its list empties (E3A-11); unloading the primary image ends no run. Each is recorded in `E1-rulings.md` §1.
