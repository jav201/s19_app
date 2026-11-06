# Inc 6 — Patch Editor document lifecycle: requirements (E1)

Batch 2026-11-01-batch-101, increment 6. Base `9bb0e3a` (main: Incs 1, 2, 3, 4, 7, 8, 11, 13, 14, 15, 16). Designed against main plus Inc 5 (`b101-inc5`, in flight; it merges first). Findings F-05, F-06, F-40, F-47 (`docs/user-guide/DOSSIER.md` §5); CODE-CHANGES D14-14, D10-25, D9-15, D9-10, D10-30, and D14-17 (co-located, ruling D-1 in `E1-rulings.md`).
Rulings, decisions and canon changes: `E1-rulings.md`. Slice: `E1-slice.md`. Cases: `02-test-cases.md`. Graph: `codewire/graph-inc6.md`. Pilot on `9bb0e3a`: `evidence-e1/i6e1-pilot-transcript.txt` (`P` below).

Form column: U = ubiquitous, E = event (`When`), S = state (`While`), N = unwanted (`If … then`). Row texts marked "unchanged" are the canon's; the increment changes the code (and, where stated, a context note). "Base" = what `9bb0e3a` does.

## User stories

### US-PE-LIFE-1 — no report offer I cannot use
As the operator, after a save-back with no project open, I want no "press b" offer, so that the app does not promise a report it then refuses (F-05; P: 1 offer shown, `b` refused).

### US-PE-LIFE-2 — what I save in a project is in the lists
As the operator, with a project open, I want the Patch Editor file list to show the documents I saved into the project, and a check spec I write to land in the project's `checks/` and show in the Check Editor and A2B Diff lists, so that saving and finding use one folder (F-06; P: `proj/patches/changes.json` written, dropdown empty; spec written to `patches/s1.chk.json` of the common folder).

### US-PE-LIFE-3 — the Checks views show the run I have now
As the operator, I want the Checks tab and the Checks screen to show a run only while its document and image are the ones loaded, so that a result never describes another document, image or project (F-40; P: 2 stale rows after a document load, an image load and a project load).

### US-PE-LIFE-4 — a new document starts clean
As the operator, when the document is replaced, I want the save-back prompt and the before/after control of the old document gone, so that I cannot save or report the old apply under the new document (D10-30; P: both stay after a dropdown pick, the prompt after undo).

## Definitions

- **Fixture image** `img.s19`: one S1 record, 16 bytes `00 01 … 0F` at `0x8000`. **Image 2**: the same addresses, bytes `40 41 … 4F`.
- **Document C**: kind change, one bytes entry `0x00008003` = `AA`. **C2**: `0x00008005` = `BB`. **Check K**: kind check, entries `0x00008000` = `00` (pass) and `0x00008001` = `FF` (fail). **Check E**: kind check, no entry.
- **Project `proj`**: folder `.s19tool/workarea/proj/` holding a variant `v.s19` (bytes `10 … 1F` at `0x8000`).
- **A load** (S10.2): Load, a dropdown pick, or the accept of the unsaved-changes popup.
- **Linked folder**: a folder that is a symbolic link (or, on Windows, a junction) to a folder outside the open project.
- Canon terms used as they are: change home, change list (amended, `E1-rulings.md` §3), check home, spec list, current run (amended, §3), before/after control, save-back prompt, offer.

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
| R-TUI-049.3.1 | E | When the document is replaced by a load, a project load, a paste, undo or redo, the system shall hide the before/after control. | `#patch_before_after_row` hidden after each of the 7 alternatives; 7/7 | the load tail without the hide → dropdown pick and guarded-load arms RED | US-PE-LIFE-4 | Partly: hidden after Load and paste only (P: stays after a dropdown pick) |
| R-TUI-049.3.2 | E | When the document is replaced by a load, a project load, a paste, undo or redo, the system shall hide the save-back prompt. | `#patch_saveback_row` hidden after each of the 7 alternatives; 7/7 | the undo path without the hide → undo arm RED | US-PE-LIFE-4 | No: stays after every alternative (P: dropdown pick, undo) |

### S10.2 — the File dropdown (US-PE-LIFE-2)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-PATCH-DOC-DROPDOWN-001.1 | E | When the Patch Editor is opened, or a Save or a Refresh ends, the system shall fill the File dropdown with the change list. **(unchanged; "change list" amended)** | option values equal the change list exactly, in order; 4/4 alternatives | the scan of `workarea/patches/` only → project arms list 0 options → RED | US-PE-LIFE-2 | Partly: lists `workarea/patches/` also with a project (P: 0 options after a Save into `proj/patches/`) |
| R-PATCH-DOC-DROPDOWN-001.3 | E | When the operator picks a file in the dropdown, the system shall load it as the document. **(unchanged)** | document source = the picked file of its folder; 2/2 | the pick resolved under `workarea/patches/` → `checks/k.chk.json` refused → RED | US-PE-LIFE-2 | Partly: only common-folder names exist |
| R-PATCH-DOC-DROPDOWN-001.4 | N | If the picked file is a link or lies outside its folder, then the system shall refuse it with the status `Patch Editor: change file '<name>' is outside the patches folder — not loaded.` **(unchanged)** | status exact, document unchanged; 3/3 | guard checks the home only, not the project → the linked-folder arm loads → RED | US-PE-LIFE-2 | Yes for the common folder |

### S9.4 and S14.6 — one check home (US-PE-LIFE-2)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-CHKED-031 | E | When the operator writes a spec, the system shall place it in the check home. **(unchanged)** | file at `<home>/<name>` and nowhere else; 2/2 | Write without the check home → `workarea/patches/s1.chk.json` → RED | US-PE-LIFE-2 | Partly: always `workarea/patches/` (P) |
| R-CHKED-034 | N | If the writer refuses a spec, then the system shall show the status `Check Editor: spec NOT written.` **(unchanged; new case: a linked check home)** | status exact; 0 files outside the project; 1/1 | destination not containment-checked → file written through the link → RED | US-PE-LIFE-2 | n/a at base (Write never used the project) |
| R-CHKED-040 | E | When the operator opens the Check Editor or writes a spec, the system shall fill the Spec dropdown with the spec list. **(unchanged)** | option values equal the check home's `*.json` names; 2/2 | the common-folder scan → project arm lists the common file → RED | US-PE-LIFE-2 | Partly: common folder only |
| R-CHKED-044 | N | If the picked file is a link or lies outside its folder, then the system shall refuse it with the status `Check Editor: file '<name>' is outside the patches folder — not loaded.` **(unchanged)** | status exact, collector unchanged; 2/2 | as R-PATCH-DOC-DROPDOWN-001.4 → RED | US-PE-LIFE-2 | Yes for the common folder |
| R-DIFF-CHK.1 | E | When the A2B Diff is shown, the system shall list in the check-spec list the `.json` files of the folder where the Check Editor saves check specs, by name, links left out. **(unchanged)** | option values equal the check home's names; 2/2 | the common-folder scan → RED | US-PE-LIFE-2 | Partly: common folder only (D14-17) |
| R-DIFF-CHK.5 | N | If the picked file is a link or lies outside the check-spec folder, then the system shall show the status `Check spec: '<name>' is outside the patches folder — not loaded.` **(unchanged)** | status exact; 1/1 | guard rooted at the common folder → the project file refused → RED | US-PE-LIFE-2 | Yes for the common folder |

### S9.2 and S9.3 — only a current run is shown (US-PE-LIFE-3)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-CHK-PE-008 | S | While the Checks tab is shown and a current run with n entries exists, the system shall show the inspector subtitle `<n> checked`. **(unchanged)** | `2 checked`, `0 checked`, and `2 checked` again after Add + Remove; 3/3 | subtitle from the row count → 0-entry arm `no run yet` → RED | US-PE-LIFE-3 | Partly: 0-entry run shows `no run yet` (P) |
| R-CHK-PE-009 | S | While the Checks tab is shown and no current run exists, the system shall show the inspector subtitle `no run yet`. **(unchanged)** | `no run yet` after each of 4 alternatives; 4/4 | no re-render at the load tail → doc-load arm `2 checked` → RED | US-PE-LIFE-3 | No: `2 checked` stays (P: document, image, project load) |
| R-CHK-PE-010 | S | While no current run exists, the system shall show `No check run yet: press Run checks.` as the Checks tab status. **(unchanged)** | status exact; 2/2 | as -009 → `Checks: 1 passed, 1 failed, 0 uncheckable` → RED | US-PE-LIFE-3 | No (P) |
| R-CHK-PE-011 | S | While no current run exists, the system shall show the patch strip with zero counts and an empty bar. **(unchanged)** | strip `✓0 ✗0 ◐0` / `░░░░░░░░`; 2/2 | `check_aggregates` not gated → `✓1 ✗1` → RED | US-PE-LIFE-3 | No (P) |
| R-CHK-PE-012 | S | While no current run exists, the system shall show no result row on the Checks tab. **(unchanged)** | 0 children in `#patch_checks_results`; 2/2 | as -009 → 2 rows → RED | US-PE-LIFE-3 | No (P) |
| R-CHKS-001 | E | When the operator opens the Checks screen, the system shall show the current run. **(unchanged)** | grouped rows of the current run; no-run note after a document load; 2/2 | gate on `last_check_result is None` → stale groups → RED | US-PE-LIFE-3 | Partly: shows the last run (P) |
| R-CHKS-004 | N | If a file is loaded and no current run exists, then the system shall show the note `No check run yet — run checks from the Patch Editor.` in the grouped list. **(unchanged)** | note exact; 1/1 | as -001 → RED | US-PE-LIFE-3 | Partly: only when no run was ever made or after undo/redo |
| R-CHKS-009 | S | While no current run exists, the system shall show the aggregate line with zero counts and an empty bar. **(unchanged)** | zero line exact; 1/1 | aggregates not gated → `Pass 1 / Fail 1` → RED | US-PE-LIFE-3 | Partly (as -004) |

## Not a requirement here

- **F-47** (a before/after refusal "right after start"): not reproduced on `9bb0e3a` (P: 0 refusals after start and after a project load; of the keys `p / g tab enter space ctrl+z ] B b` only `b` reaches the action, 1 refusal). No row and no product change (P0 risk ruling); carried, `E1-rulings.md` §4.
