# Inc 8b — shared interfaces (fixed by the orchestrator for E2)

Two E2 groups prototype against these: **G1** `app.py`, **G2** `project_gather_service.py` (+ `workspace.py` only if a helper is truly needed). An agent that needs a change writes it under "Proposed changes" in its own prototype file; E3 decides.

## project_gather_service.py (G2 owns)

- `inventory_project_tree(project_dir: Path) -> ProjectInventory` (NEW, filesystem walk with `lstat`, never follows a link): `ProjectInventory.folders: tuple[PlannedFolder, ...]` (one per top-level sub-folder, links-only folders included with 0 files), `ProjectInventory.skipped_links: tuple[str, ...]` (project-relative POSIX text of every directory link / junction / file symlink found, at any depth), `ProjectInventory.total_bytes: int` (regular files only, all depths, incl. top level).
- `PlannedFolder(name: str, file_count: int, skipped_links: tuple[str, ...])` — `name` is the top-level folder name; `file_count` recursive, regular files only; `skipped_links` the links found under that folder.
- `SavePlan` gains `folders: tuple[PlannedFolder, ...]` (save-as to a new folder only; empty for a merge, an open-project save and a save into itself — LLR-171.1g), `skipped_links: tuple[str, ...]`, `total_bytes: int` (every byte this save copies: top-level, emitted image, sub-folders — LLR-171.1i).
- `plan_project_save(...)` decides, before any folder exists: the single-MAC and single-A2L refusals (LED .63(b) / .66; the open project's own A2L exempt by same path, or same name and same bytes — LLR-167.6f), and the per-file cap refusal (a file over the placement cap, naming it — LLR-167.6g). These come back as the plan's `refusal` with its tokens.
- **One owner per landing (C5):** the document row (HLR-170) owns its landing; the sub-folder copy leaves that path out, so every landing has at most one plan row (LLR-167.6e).
- `GatherOutcome.unrecorded: tuple[str, ...]` — project-relative text of files copied that `project.json` cannot record (LLR-171.5, BACKLOG R2-1).

## app.py (G1 owns)

- Consumes the above. Owns: the free-space check against `SavePlan.total_bytes` before any folder is created (LLR-171.1e); the foreign-parent refusal before any folder is created (LLR-171.3); the sub-folder copy execution through the guarded placement (never descending into a link); the carry of the source's `batch`, `assignments`, `declared_regions`, `gathered`, `active_document` into the save-as target (LLR-171.1h); the listing and load folder check (not a link, resolves inside this work area — LLR-171.4c/.4e/.4f); the Save target link check (.4g); the A2L-only load attaching the project's own A2L in place (LLR-171.2, `current_a2l_path` = the project's file); the status lines (skipped links, unrecorded copies).
- One shared "is this folder a project here" check is used by listing, load and Save (G1 decides where it lives inside `app.py`).

## E3 pre-rulings (orchestrator, after the two E2 prototypes)

These amend the interfaces above; E3 reviews the design with them in place.

1. **One copy list (G1 R-1 = G2 PC-1).** `InventoryFile(relative: str, size: int)`; `PlannedFolder.files: tuple[InventoryFile, ...]` (`file_count == len(files)`); `SavePlan.copies: tuple[InventoryFile, ...]` — the flattened list after the landing-owner rule. G1 copies exactly `SavePlan.copies` and never walks P again.
2. **Totals (G1 R-3/P-4, G2 PC-3/DR-8).** `ProjectInventory.total_bytes` is dropped. `SavePlan.total_bytes` = the top-level planned file sizes (the emitted image, not the source image) + the sizes in `copies`. `ProjectInventory.root` added (the unresolved folder walked, PC-2).
3. **Landing conflict (G1 R-2, G2 DR-1).** The document's own source file is left out of the copy. A different P file sitting at the pasted document's landing is copied as is, and the pasted document's landing is predicted against the copy list (it takes the next free name, e.g. `changes_1.json`): no file is lost and every landing has one row.
4. **Cap at call time (G1 R-4, G2 PC-6/DR-9).** `plan_project_save(..., inventory: Optional[ProjectInventory] = None, size_cap: Optional[int] = None)`; `size_cap=None` reads `workspace.DEFAULT_COPY_SIZE_CAP_BYTES` at call time. `inventory=None` for merge, open-project and fresh-session saves (P-3).
5. **Own companion files (G1 P-2, G2 DR-6).** Planning computes no digests (Inc 5 rule), so G1 passes `exempt: frozenset[str]` — the target's MAC / A2L file names that are the open project's own (same path, or same name and same bytes). The MAC rule becomes the same as the A2L rule; the plan keeps the decision and the tokens.
6. **Unreadable folder (G2 DR-5).** `ProjectInventory.unreadable: tuple[str, ...]` — a sub-folder the walk could not read is named, never silently skipped; one status line names it (token row "could not be read" → "check the folder can be opened, then save again").
7. **`unrecorded` (G2 DR-7):** gather rows only; the active document keeps its own finding. LLR-171.5's example is corrected from "flow row" to a gathered file row in the design pass.
8. **Order (G2 DR-11/12, G1):** sub-folder copy before the gather; the MAC/A2L checks live only in the plan (the body's "more than one" validation error stays).
9. **Save-as records (G1 F-6 + Q7):** `derived_from` is carried too (project-relative, copied with its files) — LLR-171.1h gains it in the design pass. `batch` / `assignments`: the dialog's selection when non-empty, otherwise P's carried value; C-7 (an open-project save writing an empty selection over P's `batch`) goes to E3 to confirm or refute.
10. **Rejected / deferred:** PC-4 (top-level file links stay listed in `skipped_links`); PC-5 / DR-2 and R-7 → backlog; R-8 (LLR-171.2d "records no missing file") → E3 to specify.
11. **Token rows:** G1's 8 drafts + rows 9–11 and G2's texts for rows 4–6 go to E3 for confirmation; one wording per row.

## E3 round-1 rulings applied

Source: `../E3-rulings.md`; applied to `proto-8b-app.md`, `proto-8b-gather.md`, `01-requirements.md` (LED .78). A ruling wins over a pre-ruling above.

- **R1 (S3-1):** `plan_project_save` refuses a save as whose `copies` exceed 2 000 files or whose tree has a path over 32 components, before any folder; `inventory_project_tree` stops at the ceiling (`ProjectInventory.over_ceiling`); LLR-171.1j.
- **R2 (A3-1):** the copy runs right after `mkdir`, before the rows loop and the gather; pre-ruling 8 reads "before the first home placement and before the gather". R11: the top-level entries of `copies` run after the rows loop and before the variant rebuild and the gather.
- **R3 (A3-2):** `copies` also holds P's top-level regular files the save does not write itself (`ProjectInventory.top_level`, one "carried" plan row each), counted in `total_bytes`; LLR-171.1; not `project.json.previous-*` (R10).
- **R4 (A3-3):** for every target, `batch` / `assignments` = the dialog's selection when non-empty, else the carried value; the gather's `composition_names` come from the resolved `batch` plus the names in the resolved `assignments` (LLR-171.6, .6a; A3R2-3); LLR-171.6, .6a, .6b.
- **R5 (S3-3):** one `lstat` + cap guard on the project's A2L before `_load_a2l_data_with_cache`: refused before the reset for an A2L-only folder, left out with a `not readable` problem beside a data file; LLR-171.2f, .2g.
- **R6 (S3-4):** every painted name from P's tree goes through `painted_names` (G2: at most 10 names then `and K more`, each clipped to 120, control / bidi / zero-width removed); the copy returns row 11 in user terms; LLR-171.7, .7a, .7b.
- **R7 (S3-9):** `total_bytes` rounds each file up to a multiple of 4 096 and adds 65 536 for a new target; LLR-171.1i, .1e.
- **R8 (A3-5, S3-2):** `ProjectInventory.unreadable` (unlistable folders from `walk_tree_no_links(root, unreadable=…)`, entries `lstat` cannot read or classify, names ending in "." or " ") is a plan refusal before any folder; pre-ruling 6 is now a refusal, not a status line; LLR-171.1k.
- **R9 (A3-11):** a completed save as calls `_publish_flow_session_dir()` and rebinds a Patch Editor document whose file is inside P to its copy in Q; LLR-171.1l, .1m.
- **Accepted items, applied in the prototypes:** A3-4, A3-6, A3-7, A3-8, A3-9, A3-10, A3-12, A3-13, A3-14 (pre-ruling 2 now reads "the planned rows whose action is new + the copies"), A3-16; S3-5, S3-6 (`_plan_project_save(..., source_reason=…)`), S3-7, S3-8, S3-10. Pre-ruling 5's premise reads "no payload digests in the planner" (A3-17 wording). Backlog: A3-15, A3-17.

## E3 round-2 rulings applied

Source: `../E3-rulings.md` (R10, R11, R13 and "E3 round 2"), `../E3-architect.md` "Round 2" (A3R2-1 … A3R2-6) and `../E3-security.md` "Round 2" (S3R2-1 … S3R2-6); applied to `proto-8b-app.md`, `proto-8b-gather.md`, `01-requirements.md` (LED .79). A round-2 ruling wins over a round-1 ruling above.

- **R10 (F-7; A3R2-2, S3R2-2):** with a session MAC / A2L row every other MAC / A2L file of P stays out of `copies` (confirmed). `inventory_project_tree` leaves `project.json` and every `project.json.previous-*` name (compared with `normcase`) out of `ProjectInventory.top_level` and out of the file stop; the stop becomes more than `SAVE_AS_FILE_CEILING + 4` counted files (image, MAC, A2L, the document's own file). HLR-171 and LLR-171.1 name the backups as not copied.
- **R11 (F-8; A3R2-1, A3R2-5):** `_copy_project_subfolders` is called twice: with the sub-folder entries of `copies` right after `mkdir`, and with the top-level entries after the rows loop, before `self._report_filter_path = None` and the variant rebuild. The rows loop skips `row.role == "carried"`. Each top-level landing is checked against its carried row with `_plan_row_mismatch` (new keyword `carried` on `_copy_project_subfolders`). LLR-171.1's threshold and LLR-167.6's threshold say so.
- **R13 (S3R2-1):** `SAVE_AS_ENTRY_CEILING = 10 000` (read at call time) counts every walked entry (folders, links, unreadable entries and files); over it → `ProjectInventory.over_ceiling = "entries"` → the `too many files to copy (over 10 000 entries)` refusal before any folder. `walk_tree_no_links(root, unreadable=None, max_entries=None)`: with `max_entries` it stops reading a folder before sorting it and yields at most `max_entries + 1` entries; its other callers pass nothing. Logs keep at most the first 100 names plus the count. New arm in LLR-171.1j.
- **A3R2-3 / A3R2-4:** the gather list is the resolved `batch` plus the names in the resolved `assignments` (G1 step 13, G2 `gather_project_artifacts`, LLR-171.6b). LLR-171.6b's fixture also removes P's top-level `a.json` and asserts on the `composition_names` spy and `P/patches/a.json` reappearing.
- **A3R2-6:** LLR-167.6's threshold names the `carried` rows; §5.3 gains TC rows for LLR-171.1j–.1m, .2f, .2g, .6–.6b, .7–.7b.
- **S3R2-3:** the R5 guard sets the local `a2l_files = []` before `choose_install_set`, so the image install and the MAC load see no A2L; MAC arm with a 0-parse spy in LLR-171.2g.
- **S3R2-4:** `painted_names` removes Unicode categories Cc, Cf, Zl, Zp and replaces an unpaired surrogate (Cs) with U+FFFD; names reach the log as `%r`; LLR-171.7 wording.
- **S3R2-5:** the R9 rebind binds only to an entry of `plan.copies` or to the document row's landing, built from the plan entry; a `source_path` whose relative part has `..` or is absolute keeps its binding; LLR-171.1m arm.
- **S3R2-6:** an unlistable project folder is painted as `'P'`, never `.`; a name whose stem is a reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, `CONIN$`, `CONOUT$`) is `unreadable`; LLR-171.1k's definition of "cannot classify".
- **Interpretation recorded:** "stop `+4`" is read as "stop once MORE than `SAVE_AS_FILE_CEILING + 4` files are counted" (the 2 005th), the same form as round 1's "+6 = more than ceiling + 5"; a stop at exactly 2 004 could refuse a save whose copy list is exactly 2 000. Residual: R10's "every other MAC / A2L of P" is unbounded in number, so a P holding extra MAC / A2L files beside 2 000 copyable files can still reach the file stop early (a P with two MACs is already a load problem, LED .63 (b)).
