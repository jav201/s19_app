# Code-Wire prototype — Inc 8b, group G2 (`project_gather_service.py`)

Stage E2 of the design-first pipeline for Inc 8b. Graph only: no stub, mark or other change in `s19_app/` (`git diff --stat -- s19_app` stays empty). New functions and fields are nodes whose `func:` starts with "new"; a changed node's `func:` starts with "changed". The shared interfaces are those of `interfaces-8b.md`; where a node needs more than that file fixes, the node says "(proposed PC-n)" and the change is listed under "Proposed changes" for E3. G1 (`app.py`) prototypes in parallel; the seams are under "Design risks".

**`workspace.py`: one change (E3 r1, R8, A3-5).** `walk_tree_no_links` already never pushes a reparse point (so a junction cycle ends) and yields each link entry as a leaf; `inventory_project_tree` classifies each yielded entry itself with `os.lstat` + `_is_reparse_point`. R8 makes an unreadable sub-folder a plan refusal, so the walker gains one optional argument that reports the folders it could not list (DR-5); E3 r2 (R13, S3R2-1) adds a second optional argument, `max_entries`, that stops the walk before it sorts a folder past the entry ceiling; its other callers are unchanged. `workspace.py` becomes the third source file of Inc 8b (cap 4).

**E3 round 1 applied (design-correction pass).** The orchestrator's rulings R1–R9 and the accepted reviewer items of `../E3-rulings.md` (from `../E3-architect.md` A3-n and `../E3-security.md` S3-n) are applied below, on top of the pre-rulings 1–11 of `interfaces-8b.md`; each changed line names its ruling or item. New: the node `painted_names` (R6) and the inventory fields `top_level` (R3), `unreadable` (R8, pre-ruling 6) and `over_ceiling` (R1); `ProjectInventory.total_bytes` is dropped (pre-ruling 2).

**E3 round 2 applied (design-correction pass 2).** Rulings R10, R11 and R13 of `../E3-rulings.md` and the reviewer items A3R2-1 … A3R2-4 (`../E3-architect.md` "Round 2") and S3R2-1, S3R2-2, S3R2-4, S3R2-6 (`../E3-security.md` "Round 2") are applied below; each changed line names its ruling or item. R10: `project.json` and its `project.json.previous-*` backups are out of `top_level` and of the file stop (now more than `SAVE_AS_FILE_CEILING + 4`). R13: an entry ceiling `SAVE_AS_ENTRY_CEILING = 10 000`, read at call time, and `walk_tree_no_links(..., max_entries=)` that stops before it sorts a folder. R11: G1 executes the sub-folder entries of `copies` before its rows loop and the top-level entries after it. The node set is unchanged (12).

Example sources: the numeric thresholds of `01-requirements.md` (LLR-167.6, LLR-167.6a–g, LLR-171.1, .1a, .1b, .1d, .1g, .1i, LLR-171.5, after LED .76 / .77) and TC-B100-59 / TC-B100-31. Each example says "target (8b)" (asked for, not true at `ebe6d0c`) or "holds" (behaviour 8b keeps). Paths are project-relative POSIX text unless a line says otherwise.

**The reference tree** used by several examples (sizes in bytes): `P/firmware.s19` 4000, `P/firmware.a2l` 300, `P/project.json` 200, `P/patches/a.json` 10, `P/flows/f.json` 20, `P/flows/sub/g.json` 30, `P/flows/link` a directory junction to an outside folder holding a 10 MiB file. Save as Q with a pending patch: the emitted image is 5000 bytes. (E3 r1: the image sizes changed from 1000 / 1024 so that the source and the emitted image fall on different 4 KiB steps under R7's rounding, and the "source instead of emitted" mutant stays RED.) The session image is P's `firmware.s19` and the session A2L P's `firmware.a2l`, so R3 copies no top-level file of this tree.

**Counts (after E3 r1):** 12 nodes — 11 owned (6 functions: `inventory_project_tree` new, `_second_file_refusal` new, `painted_names` new (R6), `plan_project_save` changed, `gather_project_artifacts` changed, `walk_tree_no_links` changed (`workspace.py`, R8); 5 data nodes: `ProjectInventory` new, `PlannedFolder` new, `InventoryFile` new (pre-ruling 1), `SavePlan` changed, `GatherOutcome` changed) and 1 unchanged context node (`classify_active_document`). 80 example lines (57 at E2; 90 after E3 r2). 12 design risks, 6 proposed changes, each now with its E3 r1 decision.

## Nodes

InventoryFile
req: LLR-171.1, LLR-167.6a, LLR-167.6g, LLR-171.1i, LLR-171.1j
in: str relative; int size
out: InventoryFile file
func: new (pre-ruling 1), frozen dataclass. One regular file of the walked project that a save as may copy: at the top level (R3, `relative` is its bare name) or under a top-level sub-folder (`relative` its project-relative POSIX text, `flows/sub/g.json`); `size` its `os.lstat` size in bytes. The plan needs each file's size for the per-file cap (LLR-167.6g) and the total (LLR-171.1i), and G1 copies exactly `SavePlan.copies` (LLR-167.6: the handler executes exactly the plan); a count alone gives neither.
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-31, reference tree) `P/flows/sub/g.json` → relative "flows/sub/g.json", size `30` (target (8b))
examples: (TC-B100-31, R3) `P/a.json` of 12 bytes → relative "a.json", size `12` (target (8b))

PlannedFolder
req: LLR-167.6a, LLR-167.6b, LLR-171.1
in: str name; int file_count; tuple[str, ...] skipped_links; tuple[InventoryFile, ...] files = ()
out: PlannedFolder folder
func: new, frozen dataclass (interfaces-8b.md), with `files` (pre-ruling 1). One top-level sub-folder of the open project: `name` the folder name, `file_count` the recursive count of regular files the save-as copies under it, `skipped_links` the links found under it (project-relative), `files` those files. Invariant: `file_count == len(files)`. A folder holding only links, or nothing, is still a row with `file_count` 0 (ruling Q9).
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-59 Inc 8b arm, LLR-167.6a, reference tree) folder `flows` → name "flows", file_count `2`, skipped_links "flows/link", files "flows/f.json" and "flows/sub/g.json" (target (8b))
examples: (LLR-167.6a, ruling Q9) `P/checks` holding only the junction `checks/j` → name "checks", file_count `0`, skipped_links "checks/j" (target (8b))

ProjectInventory
req: LLR-171.1, LLR-171.1a, LLR-171.1b, LLR-171.1d, LLR-171.1j, LLR-171.1k, LLR-167.6a, LLR-167.6b
in: Path root; tuple[PlannedFolder, ...] folders; tuple[InventoryFile, ...] top_level; tuple[str, ...] skipped_links; tuple[str, ...] unreadable; Optional[str] over_ceiling = None
out: ProjectInventory inventory
func: new, frozen dataclass (interfaces-8b.md as amended by pre-rulings 2 and 6 and by R1, R3, R8). `root` (pre-ruling 2): the unresolved folder that was walked, so the planner can tell the document's own file from another file at the same landing (LLR-167.6e) and predict a home row against the source home (DR-1). `folders` sorted by name, one per top-level sub-folder. `top_level` (R3): every top-level regular file that is not a link, with its size, sorted by name, except `project.json` and its `project.json.previous-*` backups (R10, A3R2-2: names compared with `normcase`); the session's files are included and the planner leaves out what the save writes itself. `skipped_links` every link found, sorted, project-relative (top-level file links included, pre-ruling 10). `unreadable` (pre-ruling 6 widened by R8, S3-2): project-relative text of every sub-folder the walk could not list and every entry it could not classify, sorted. `over_ceiling` (R1, R13): `None`, or `"files"` / `"entries"` / `"depth"` when the walk stopped at a ceiling (then `folders`, `top_level` and `unreadable` are partial and the planner refuses). `total_bytes` is dropped (pre-ruling 2, PC-3).
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-31, reference tree) root `P` → folders "flows" and "patches" (2 rows), top_level "firmware.a2l" `300`, "firmware.s19" `4000` (`0` entries for "project.json", R10), skipped_links "flows/link", unreadable `0` entries, over_ceiling `None` (target (8b))

inventory_project_tree
req: LLR-171.1, LLR-171.1a, LLR-171.1b, LLR-171.1d, LLR-171.1j, LLR-171.1k, LLR-167.6a, LLR-167.6b
in: Path project_dir
out: ProjectInventory inventory
func: new. One link-free enumeration of the open project for a save as; writes nothing, hashes nothing, follows no link. `walk_tree_no_links(project_dir, unreadable=found, max_entries=SAVE_AS_ENTRY_CEILING)` yields every entry (never descending into a reparse point) and appends to `found` each folder it could not list (R8, A3-5: one walker, no second walk); when the project folder itself cannot be listed the walker reports it as "." and the plan paints it as the project's name (S3R2-6). Entry ceiling (R13, S3R2-1): every yielded entry counts (folders, links, unreadable entries and files); more than `SAVE_AS_ENTRY_CEILING` → the walk stops, `over_ceiling = "entries"`; the walker itself stops reading a folder before it sorts it once its running count passes `max_entries`, so it yields at most `SAVE_AS_ENTRY_CEILING + 1` entries. Each yielded entry is classified: a name ending in "." or " " (S3-2: Windows cannot open it by its normal path, and `lstat` may read a sibling's metadata), or a name whose stem (case-insensitive, before the first dot) is a reserved device name `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, `CONIN$` or `CONOUT$` (S3R2-6: an open could reach the device and block the main thread) → `unreadable`; `os.lstat` raising `OSError` → `unreadable`; a symbolic link or reparse point (`_is_reparse_point`) → its POSIX text joins `skipped_links` and, when it lies under a top-level sub-folder, that folder's `skipped_links`; a top-level directory link is a skipped link but not a folder row; a plain directory at the top level opens a folder row (0 files until a file is seen); a regular file (`stat.S_ISREG`) at the top level joins `top_level` (R3) unless its `normcase` name is `project.json` or starts with `project.json.previous-` (R10, A3R2-2, S3R2-2: neither added nor counted toward the file stop), under a top-level sub-folder that folder's `files`, each with its `st_size`; anything else (FIFO, device) → `unreadable` (R8: never silently left out). Ceilings (R1, S3-1; R13), read at call time from `SAVE_AS_FILE_CEILING = 2000`, `SAVE_AS_ENTRY_CEILING = 10000` and `SAVE_AS_DEPTH_CEILING = 32` (module constants, NEW): an entry whose relative path has more than 32 components → the walk stops, `over_ceiling = "depth"`; once more than `SAVE_AS_FILE_CEILING + 4` counted regular files are collected (more than the ceiling plus the at most 4 files the copy list leaves out after R10: the image, the MAC, the A2L and the document's own file; `project.json` and its backups are not counted) → the walk stops, `over_ceiling = "files"`; below that the planner counts the copy list exactly. The full `skipped_links` / `unreadable` lists go to the log as at most the first 100 names plus the count (S3R2-1). Order: folders by name, files and links by POSIX text, so two runs on one tree give equal inventories.
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-59 Inc 8b arm, LLR-167.6a/b, reference tree) project_dir `P` → folders "flows" file_count `2` and "patches" file_count `1`, skipped_links "flows/link" (1 entry) (target (8b))
examples: (LLR-171.1, nested sub-folder) P with `flows/`, `flowsets/`, `patches/`, `checks/`, `reports/`, `templates/`, `splits/` (one file each) and `reports/2026/r2.md` → `7` folders, "reports" file_count `2`, files of reports "reports/2026/r2.md" and "reports/r.md"; the 8 relative paths equal P's link-free listing (0 missing) (target (8b))
examples: (LLR-167.6a, ruling Q9) P whose `checks/` holds only the junction `checks/j` → folder "checks" file_count `0`, skipped_links "checks/j" (target (8b))
examples: (LLR-167.6a empty) P with only `firmware.s19` and `project.json` → folders `0` rows, top_level "firmware.s19" only (R10), skipped_links `0` entries (target (8b))
examples: (LLR-171.1, R10, S3R2-2) P with `project.json`, `project.json.previous-20261030T000000Z`, `Project.JSON.previous-20261029T000000Z` and `a.json` → top_level "a.json" only (target (8b)); a mutation without the exclusion → top_level holds the 2 backups → RED
examples: (LLR-171.1, R3) P with the top-level `a.json`, `notes.txt` and a file link `x.s19` → top_level holds "a.json" and "notes.txt", skipped_links "x.s19" (target (8b))
examples: (LLR-171.1j, R1, R10) P with `2005` counted regular files (`project.json` and its backups not counted) → over_ceiling "files", the walk stops at the 2005th; P with `2004` → over_ceiling `None`; P with `2004` counted files plus `project.json` and `6` backups → over_ceiling `None` (target (8b))
examples: (LLR-171.1j entries, R13, S3R2-1) P whose walk yields exactly `10000` entries (2 top-level files, the folder `reports` and `9997` empty folders under it) → over_ceiling `None`; `10001` entries with `0` regular files → over_ceiling "entries" (target (8b)); one folder of `50000` files → over_ceiling "entries", the walker yields at most `10001` entries (spy on the yield count) and sorts no folder of more than `10001` names; a mutation counting regular files only → the `10001`-folder arm gives `None` → RED
examples: (LLR-171.1k, S3R2-6) the project folder `P` itself cannot be listed → unreadable "." (painted as `'P'` by the plan); `P/NUL.txt` and `P/reports/com1.json` made through the "\\?\" form → unreadable "NUL.txt" and "reports/com1.json", reported as not run where the platform refuses to create the name (target (8b))
examples: (LLR-171.1j depth, R1) a file at `33` path components → over_ceiling "depth"; at `32` → `None` (target (8b))
examples: (LLR-171.1k, R8, A3-5) `P/reports/locked` cannot be listed → unreadable "reports/locked", folder "reports" still a row with its readable files (target (8b))
examples: (LLR-171.1k, S3-2) `P/flows/x.json.` (trailing dot) alone, and beside `P/flows/x.json` → unreadable "flows/x.json." in both; folder "flows" files hold "flows/x.json" in the second only (target (8b))
examples: (LLR-171.1a) top-level junction `P/linked` → an outside folder holding `secret.txt`, nested junction `P/reports/j` → the same → 0 files named "secret.txt" in any folder; skipped_links "linked" and "reports/j"; no folder row named "linked" (target (8b))
examples: (LLR-171.1a cycle) `P/flows/loop` a junction to `P` → returns in under `5` s; skipped_links "flows/loop"; folder "flows" counts only its regular files (target (8b))
examples: (LLR-171.1b) `P/patches/l.json` a file symbolic link to an outside file → skipped_links "patches/l.json"; folder "patches" files do not hold "patches/l.json"; reported as not run when the platform cannot create a file link (target (8b))
examples: (LLR-167.6b, the 3 links of LLR-171.1a/b) `linked`, `reports/j`, `patches/l.json` → skipped_links `3` entries, equal to the 3 paths LLR-171.1c names (target (8b))
examples: (LLR-171.1d, reference tree) the junction `flows/link` reaching a 10 MiB file → `0` InventoryFile entries under "flows/link", so no size behind it can reach the plan's total (pre-ruling 2: the inventory carries no total) (target (8b))
examples: (LLR-167.6, "computing a plan writes 0 bytes") any tree → `0` bytes written, `0` folders created, `0` payload digests (target (8b))
examples: (LLR-171.4c context, R18) `P/patches` itself a junction → skipped_links "patches", no folder row "patches", 0 files read through it (target (8b))

_second_file_refusal
req: LLR-167.6c, LLR-167.6d, LLR-167.6f
in: Path target; Sequence[Path] existing; PlannedFile planned; str kind_label; frozenset[str] exempt
out: Optional[str] refusal
func: new, private; called twice by `plan_project_save` (MAC with `existing` = the target's MAC data files, A2L with the target's A2L files, both from `validate_project_files(target)` when the target is a directory). Returns `None` when `existing` is empty, or when the name (`normcase`) of an existing file is in `exempt` (pre-ruling 5: G1 decides "the open project's own file" — the same path as text, or the same name with the same bytes and not a link, S3-8 — because that needs the target file's digest). `predict_placement` is no longer called here (A3-4). Otherwise the refusal text with its tokens (token rows 4 / 5, A3-7): "Project NOT saved: '{target.name}' already has a {kind_label} file ({existing name}) — choose another name.", the names through `painted_names` (R6). One rule for MAC and A2L (DR-6 decided: the MAC rule changes from name-only to this rule; LLR-167.6c's text follows). No digest is computed here.
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-59, LLR-167.6c) merge target `R` holding `a.mac`, planned MAC `b.mac`, exempt `0` names → refusal holds "already has a MAC file", "a.mac" and "choose another name" (target (8b))
examples: (TC-B100-59, LLR-167.6d) merge target `R` holding `a.a2l`, planned A2L `b.a2l`, exempt `0` names → refusal holds "already has an A2L file" (target (8b))
examples: (TC-B100-59, LLR-167.6f same path) target `P` holding `firmware.a2l`, planned A2L source `P/firmware.a2l`, exempt "firmware.a2l" → refusal `None` (target (8b); C3 at ebe6d0c refuses)
examples: (LLR-167.6f same name and bytes) target `R` holding `firmware.a2l` 300 bytes, planned A2L `X/firmware.a2l` with the same 300 bytes, exempt "firmware.a2l" (G1) → refusal `None` (target (8b))
examples: (LLR-167.6f negative control, same name and other bytes) target `R` holding `firmware.a2l`, planned `X/firmware.a2l` with other bytes, exempt `0` names → refusal holds "already has an A2L file" (target (8b); the name-only mutant saves → RED)
examples: (LLR-167.6c, DR-6) target `R` holding `a.mac`, planned `X/a.mac` with other bytes, exempt `0` names → refusal holds "already has a MAC file" (target (8b); at ebe6d0c the name-only rule saves it as a second MAC)
examples: (TC-B100-59, test_tc_b100_59_open_project_unchanged) target `P1` holding `firmware.mac`, planned MAC source `P1/firmware.mac`, exempt "firmware.mac" → refusal `None` (holds)
examples: (LLR-167.6c, a new target) target `Q` does not exist, existing `0` files → refusal `None` (holds)

painted_names
req: LLR-171.7, LLR-171.7a, LLR-171.1c, LLR-171.1k, LLR-171.5
in: Sequence[str] names; int limit = 10; int clip = 120
out: str text
func: new (R6, S3-4), pure. The one way a name taken from the open project's tree reaches painted text. Each name: every character whose `unicodedata.category` is `Cc`, `Cf`, `Zl` or `Zp` removed, and every unpaired surrogate (`Cs`) replaced by U+FFFD (S3R2-4, replacing round 1's fixed list; the SEC8a-4 fix: C0 / C1 controls, U+200B–U+200F, U+202A–U+202E, U+2066–U+2069 stay covered as examples, and U+061C, U+2028 / U+2029, U+FEFF, U+00AD and the tag characters are now covered too), then clipped to `clip` characters with the clip `_entry_mark` already uses (`variant_execution_service._clip`, ending in "…"). The first `limit` names are joined with ", "; when more are given, ", and K more" follows (K = the rest). Used by the plan's refusal texts (R8 unreadable list, cap file, MAC / A2L names) and by G1's status lines (rows 7, 8 and 11; row 8 calls it per line and G1 adds the `and K more` line). The list goes to the log, never to the status: at most the first 100 names plus the count (S3R2-1), each name logged as its `%r` form, so control and surrogate characters reach the log escaped and a strict handler cannot raise (S3R2-4).
module: s19_app/tui/services/project_gather_service.py
examples: (LLR-171.7a, R6) 25 names → `10` names and "and 15 more" (target (8b))
examples: (LLR-171.7a) 3 names → the 3 names, `0` "more" (target (8b))
examples: (LLR-171.7, R6) a name of 300 characters → `120` characters ending "…" (target (8b))
examples: (LLR-171.7, R6, SEC8a-4) "patches/" + U+202E + "osj.exe.json" → "patches/osj.exe.json"; a name holding U+200B and "\x1b" → both removed (target (8b))
examples: (LLR-171.7, S3R2-4) "a" + U+061C + "b" → "ab"; "c" + U+2028 + "d" → "cd"; "e" + U+DC80 + "f" → "e" + U+FFFD + "f", and the text encodes as UTF-8 with `0` raises (target (8b)); a mutation using round 1's fixed list → U+061C kept → RED
examples: (LLR-171.7a) `0` names → "" (target (8b))

plan_project_save
req: LLR-167.6, LLR-167.6a, LLR-167.6b, LLR-167.6c, LLR-167.6d, LLR-167.6e, LLR-167.6f, LLR-167.6g, LLR-171.1, LLR-171.1g, LLR-171.1i, LLR-171.1d, LLR-171.1j, LLR-171.1k
in: Path target; str target_kind; Sequence[PlannedFile] files; str image; Sequence[str] manifest_keys; Optional[str] refusal = None; Optional[ProjectInventory] inventory = None; Optional[int] size_cap = None; frozenset[str] exempt = frozenset()
out: SavePlan plan
func: changed; still pure (writes nothing, hashes no payload). New keywords (keyword-only, pre-rulings 4 and 5): `inventory` (G1 passes it for a save as with an open project), `size_cap` (`None` → `workspace.DEFAULT_COPY_SIZE_CAP_BYTES` read at call time, so a test lowers the one constant) and `exempt` (the target's MAC / A2L names that are the open project's own, decided by G1). Refusal precedence (A3-13), each a row-less plan: (1) a passed `refusal` (G1's row 9, else the re-derive refusal) (holds). (2) R1 walk stop: `inventory.over_ceiling` "files" → "Project NOT saved: '{P}' has too many files to copy (over 2 000) — move files out of the project, then save again."; "entries" (R13, S3R2-1) → "Project NOT saved: '{P}' has too many files to copy (over 10 000 entries) — move files out of the project, then save again."; "depth" → "… has folders nested too deep (over 32 levels) — …" (LLR-171.1j). (3) R8: `inventory.unreadable` non-empty → "Project NOT saved: {painted_names(unreadable)} could not be read — check that they can be opened, then save again." (LLR-171.1k, pre-ruling 6); the entry "." (the project folder itself) is painted as `'{P}'`, the project's name (S3R2-6). (4) The copy list, only when `target_kind` is "new" and `inventory` is given, else `folders`, `skipped_links` and `copies` are empty (LLR-171.1g): (4a) top-level copies (R3): `inventory.top_level` (`project.json` and its `.previous-*` backups are already absent from it, R10), minus every name equal (`normcase`) to the landing name of a top-level row (image, MAC, A2L), minus every top-level MAC file when a MAC row is planned and every top-level A2L file when an A2L row is planned (Q holds one of each, LED .63 (b) / .66; finding F-7 of the G1 prototype); (4b) sub-folder copies: every folder's `files`, minus the document's own file (a document row whose source text is `root / relative`, normcase equal, owns that landing; the file leaves its folder's `files` and count, pre-ruling 3, C5); `copies` = (4a) then (4b), in POSIX order. (5) R1 count: `len(copies) > SAVE_AS_FILE_CEILING` → the "too many files to copy" refusal of (2). (6) MAC then A2L: `_second_file_refusal(..., exempt=exempt)` on the planned file of role "mac" / "a2l", when there is one (LED .66, .63 (b)). (7) Per-file cap: the first planned file, then the first copy, with size > cap → token row 6b for a planned (session) file, "Project NOT saved: {name} is too large to copy (over {limit}) — a project cannot hold files over {limit}.", and row 6a for a copy, "Project NOT saved: {relative} is too large to copy (over {limit}) — move it out of the project folder, then save again." ({limit} in MiB, or in bytes under 1 MiB; A3-7), checked for every planned file whatever its action, because `place_into_workarea` checks the cap before its reuse decision. Then the rows (8): as at 8a, plus one row per top-level copy (role "carried", action "new", landing `target / name`, R3; LLR-167.6's "one row per top-level file"); for a save as with an inventory, a row with a home (the document row) that does not own a sub-folder file is predicted against `inventory.root / home`, the folder the sub-folder copy mirrors into Q before the rows loop runs (R2); the top-level rows (image, MAC, A2L) are predicted against the empty top level of `target`, and each "carried" row's landing is the one G1 places after its rows loop (R11, A3R2-1), and its landing is spelled in the resolved form `Path(target).resolve() / home / predicted.name`, the form `_plan_row_mismatch` compares against `PlacementResult.path` (A3-9, DR-1). (9) `total_bytes` (A3-14 rule, R7 rounding) = Σ round_up_4k(size) over the planned rows whose action is "new" and over every copy, + `65536` for `project.json` and the folders when `target_kind` is "new"; round_up_4k rounds up to a multiple of 4 096 (0 stays 0). A refused plan has 0 rows, 0 folders, 0 links, 0 copies, total 0.
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-59 Inc 8b arm, LLR-167.6a/b/LLR-171.1i, reference tree) target `Q` "new", files [image `firmware.s19` 5000 emitted, a2l `firmware.a2l` 300], inventory of P → folders "flows" `2` and "patches" `1`, skipped_links "flows/link", copies `3` ("flows/f.json", "flows/sub/g.json", "patches/a.json"; `0` top-level copies), rows image "new", a2l "new", manifest "new", total_bytes `90112` (8192 + 4096 + 3 × 4096 + 65536) (target (8b))
examples: (LLR-171.1i negative control, R7) the same plan → total_bytes is not `86016` (the source image rounded, 4096, in place of 8192), not `77824` (sub-folders and margin only), not `70896` (no rounding) and not `24576` (no margin) (target (8b))
examples: (LLR-171.1i rounding, R7) copies of `0`, `1`, `4096` and `4097` bytes → `0`, `4096`, `4096` and `8192` counted (target (8b))
examples: (LLR-171.1d) the same plan → total_bytes `90112`, the 10 MiB behind `flows/link` not counted; G1 with free space simulated at 90112 saves (target (8b))
examples: (LLR-171.1, R3, R10) P holding "a.json" 12, "firmware.s19" 4000, "firmware.a2l" 300, "project.json" 200 and "project.json.previous-20261030T000000Z" 180, so inventory top_level "a.json", "firmware.s19", "firmware.a2l"; session image row "firmware.s19", a2l row "firmware.a2l" → copies hold "a.json" only (`1` top-level copy), `1` row role "carried" action "new" (target (8b))
examples: (LLR-171.1j, R10, A3R2-2) P with `2000` copyable files plus `project.json` and `6` backups → over_ceiling `None`, copies `2000`, refusal `None` (target (8b))
examples: (LLR-171.1j entries, R13) inventory with over_ceiling "entries" → refusal holds "too many files to copy" and "over 10 000 entries", rows `0`, copies `0` (target (8b))
examples: (LLR-171.1k, S3R2-6) inventory unreadable "." for the project `P` → refusal holds "'P' could not be read", `0` refusals holding ". could not be read" (target (8b))
examples: (LLR-171.1, R3, F-7) inventory top_level "old.mac" and a planned MAC row "new.mac" → copies hold no ".mac" file; no MAC row (session without a MAC) → copies hold "old.mac" (target (8b))
examples: (LLR-171.1j, R1) inventory with over_ceiling "files" → refusal holds "too many files to copy" and "over 2 000", rows `0`, copies `0`; copies of `2000` → refusal `None`; `2001` → refused (target (8b))
examples: (LLR-171.1j depth, R1) inventory with over_ceiling "depth" → refusal holds "nested too deep", rows `0` (target (8b))
examples: (LLR-171.1k, R8) inventory unreadable "reports/locked" → refusal holds "reports/locked", "could not be read" and "check that they can be opened, then save again", rows `0`; `12` unreadable entries → `10` named and "and 2 more" (target (8b))
examples: (A3-13, precedence) a passed refusal and unreadable entries → the passed refusal; over_ceiling and unreadable entries → the R1 refusal; unreadable entries and a MAC clash → the R8 refusal (target (8b))
examples: (LLR-167.6a ruling Q9) inventory with `checks/` holding only `checks/j` → folder "checks" file_count `0` with skipped_links "checks/j" (target (8b))
examples: (LLR-167.6a empty) inventory with 0 sub-folders → folders `0`, skipped_links `0` (target (8b))
examples: (LLR-171.1 trigger) target `Q` "new", inventory `None` (a fresh session, no open project) → folders `0`, skipped_links `0` (holds the 8a rows)
examples: (TC-B100-31, LLR-171.1g merge) target `R` "merge", inventory of P given → folders `0`, skipped_links `0`, copies `0`, total_bytes counts only the "new" top-level rows, rounded, with no margin (target (8b))
examples: (LLR-171.1g into itself) target `P` "open project", inventory of P given → folders `0`, copies `0`; image and a2l rows "keep", total_bytes `0` (target (8b))
examples: (TC-B100-59, LLR-167.6c) target `R` "merge" holding `a.mac`, files with mac `b.mac`, exempt `0` names → refusal holds "already has a MAC file" and "choose another name", rows `0`, folders `0`, total_bytes `0` (target (8b))
examples: (TC-B100-59, LLR-167.6d) target `R` "merge" holding `a.a2l`, files with a2l `b.a2l` → refusal holds "already has an A2L file", rows `0` (target (8b))
examples: (AT-B100-10, LLR-167.6f) the A2L-only project `P` (firmware.a2l, project.json) open, saved into itself, files [a2l source `P/firmware.a2l`], exempt "firmware.a2l" → refusal `None`, the a2l row action "keep", landing ends "P/firmware.a2l"; a second plan after that save → refusal `None`, "keep" again (0 `_1` landings) (target (8b))
examples: (TC-B100-59, LLR-167.6g, row 6a) size_cap `1024`, inventory holding `splits/big.bin` 1025 bytes → refusal holds "splits/big.bin", "too large to copy", "over 1024 bytes" and "move it out of the project folder, then save again", rows `0`, folders `0` (target (8b))
examples: (LLR-167.6g boundary) size_cap `1024`, `splits/big.bin` 1024 bytes → refusal `None`, folder "splits" file_count `1` (target (8b); the `>=` mutant refuses → RED)
examples: (LLR-167.6g, shipped cap) size_cap `None` → cap `268435456` (256 MiB); `splits/big.bin` of 269484032 bytes (257 MiB) → refusal holds "splits/big.bin" and "over 256 MiB"; the test reaches this arm by lowering `workspace.DEFAULT_COPY_SIZE_CAP_BYTES` (or passing size_cap), never by writing 257 MiB (target (8b))
examples: (LLR-167.6g top-level, row 6b) size_cap `1024`, image `firmware.s19` planned at 1025 bytes → refusal holds "firmware.s19" and "a project cannot hold files over 1024 bytes" (target (8b))
examples: (LLR-167.6g, R3, row 6a) size_cap `1024`, a top-level copy `a.json` of 1025 bytes → refusal holds "a.json" and "move it out of the project folder, then save again" (target (8b))
examples: (TC-B100-59, LLR-167.6e, C5) P with `patches/boost.json`, the Patch Editor document file-backed at `P/patches/boost.json` (home "patches"), save as `Q` → exactly 1 row with a landing ending "Q/patches/boost.json", role "document", action "new"; folder "patches" file_count `0` and its files do not hold "patches/boost.json" (target (8b))
examples: (LLR-167.6e) every plan of this node → each landing path appears once among the rows (0 duplicates) (target (8b))
examples: (DR-1, other source, other bytes) document file-backed at `workarea/patches/boost.json` 50 bytes while `P/patches/boost.json` holds 40 other bytes, save as `Q` → folder "patches" file_count `1` (P's file copied), document row landing ends "Q/patches/boost_1.json" action "new" (target (8b))
examples: (DR-1, other source, same bytes) the outside document equal to `P/patches/boost.json` → folder "patches" file_count `1`, document row landing ends "Q/patches/boost.json" action "keep" (target (8b))
examples: (DR-1, pasted document, R2) a pasted document "changes.json" home "patches" while `P/patches/changes.json` holds other bytes, save as `Q` → document row landing ends "Q/patches/changes_1.json" action "new", and "patches/changes.json" is in copies; G1 copies the sub-folder entries before the rows loop (R2), so the pasted file lands at "changes_1.json" as planned (target (8b))
examples: (A3-9, landing form) W reached through a second spelling, save as `Q` → the document row landing equals `Path(target).resolve() / "patches" / "boost.json"` as text (normcase), the form PlacementResult.path has (target (8b))
examples: (TC-B100-59, test_tc_b100_59_refused_plan_writes_nothing) refusal "blocked" passed and a MAC clash present → plan.refusal "blocked" (the passed refusal first), rows `0` (holds)
examples: (TC-B100-59, test_tc_b100_59_fresh_folder) target `P1` "new", files [image `firmware.s19`], inventory `None` → rows image "new" and manifest "new", folders `0` (holds)
examples: (LLR-167.6, test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload) any plan above → `0` bytes written, `0` folders created, `0` payload digests (holds)

SavePlan
req: LLR-167.6, LLR-167.6a, LLR-167.6b, LLR-171.1, LLR-171.1g, LLR-171.1i
in: Path target; str target_kind; tuple[SavePlanRow, ...] rows; str image; tuple[str, ...] manifest_keys; Optional[str] refusal = None; tuple[PlannedFolder, ...] folders = (); tuple[str, ...] skipped_links = (); tuple[InventoryFile, ...] copies = (); int total_bytes = 0
out: SavePlan plan
func: changed, frozen dataclass. New fields (interfaces-8b.md with pre-rulings 1 and 2), each with a default so every 8a construction stays valid: `folders` (save as to a new folder only; empty for a merge, an open-project save, a save into itself and a refused plan), `skipped_links` (the inventory's links when `folders` is planned, else empty), `copies` (pre-ruling 1: the flattened copy list G1 executes, top-level copies first (R3), then sub-folder files, after the landing-owner rule; G1 executes the sub-folder entries before the rows loop and the top-level entries after it, R11), `total_bytes` (A3-14 / R7: the "new" rows and the copies, each rounded up to 4 KiB, plus 64 KiB for a new folder). `rows` stay the per-path rows (a top-level copy has its own "carried" row); a folder row is a count, never a per-path row, so a landing has at most one per-path row (LLR-167.6e).
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-59, reference tree) the save-as plan → folders `2`, skipped_links "flows/link", copies `3`, total_bytes `90112` (target (8b))
examples: (TC-B100-59, 8a constructions) `SavePlan(target, "new", (), "unchanged copy", ())` → folders `0`, skipped_links `0`, copies `0`, total_bytes `0` (holds)

gather_project_artifacts
req: LLR-171.5, LLR-138.1, LLR-170.2
in: Path project_dir; Sequence[str] composition_names = (); Path? active_document = None; str active_document_kind = "change"; Path? active_template = None; Path common_patches_dir; Path common_templates_dir; Path workarea_root
out: GatherOutcome outcome
func: changed in one place: a placed row (written or reused) whose project-relative text `_manifest_key_refusal` refuses is still left out of `gathered` (review F1, holds) and is now also appended to `outcome.unrecorded`, sorted, so the app paints one line per file (LLR-171.5; at most 10 lines then `and K more`, R6, G1). The active document is not added there: when its landing cannot be recorded it keeps its 8a `GATHER-DOCUMENT-NOT-RECORDED` finding, so one file never gets two lines (DR-7, pre-ruling 7). Everything else holds: the classifier, R11, R18, the composition limb resolving against `project_dir` first (which, after G1's copies ran — the sub-folder entries right after `mkdir`, R2, the top-level entries after the rows loop, R11 — finds P's snapshot in Q and copies nothing — DR-11). Its `composition_names` input is unchanged; G1 now feeds it the resolved `batch` plus the names in the resolved `assignments` (each the dialog's selection when non-empty, else the carried value; R4, A3R2-3, LLR-171.6, .6a, .6b), as `app.py:9932-9936` builds it from the payload today (LLR-138.1 kept).
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-31, LLR-171.5) composition_names "con.json", the common library holding `con.json` (or another name `project.json` refuses where the platform cannot create that one) → the file is copied, outcome.gathered has no "patches/con.json", outcome.unrecorded "patches/con.json", 0 raises (target (8b); base R2-1: copied with 0 lines)
examples: (LLR-171.5 none) composition_names "boost.json" → outcome.unrecorded `0` entries, gathered "patches/boost.json" (target (8b))
examples: (LLR-171.5, a reused row) a second save with `Q/patches/con.json` already identical → outcome.written `0` files, outcome.unrecorded "patches/con.json" (target (8b))
examples: (DR-11, save as after the copy) `Q/patches/x.json` placed by the sub-folder copy, composition_names "patches/x.json" → 0 copies from the common library, outcome.written `0` files (target (8b))
examples: (TC-B100-23 / R11, 8a) active_document `P/patches/boost.json` with project_dir `P` → outcome.active_document "patches/boost.json", 0 files written (holds)

GatherOutcome
req: LLR-171.5
in: dict[str, list[str]] gathered; list[ValidationIssue] issues; list[Path] written; list[Path] created_homes; str? active_document = None; tuple[str, ...] unrecorded = ()
out: GatherOutcome outcome
func: changed, dataclass. New field `unrecorded: tuple[str, ...]` (interfaces-8b.md): project-relative text of every gathered file placed in the project that `project.json` cannot record, sorted; the active document excluded (it has its own finding). Default empty, so every existing construction stays valid.
module: s19_app/tui/services/project_gather_service.py
examples: (LLR-171.5) the gather with `con.json` → unrecorded "patches/con.json" (target (8b))
examples: (LLR-171.5 none) `GatherOutcome()` → unrecorded `0` entries (holds for every existing caller)

classify_active_document
req: LLR-167.6, LLR-170.2
in: Path project_dir; Path source; str home
out: tuple(str kind, str? name)
func: unchanged (Inc 8a, E3 R11 and R18). Context: in a save as, `project_dir` is Q, so a document anywhere in P is classified `outside` (not inside Q) and its row exists; a `P/patches` junction makes it `missing` (no row), which matches the inventory skipping `patches`. A document deeper than its home in P (`P/patches/sub/x.json`) is `outside` for Q and lands flat as `Q/patches/x.json` (DR-2).
module: s19_app/tui/services/project_gather_service.py
examples: (C5, save as) project_dir `Q`, source `P/patches/boost.json`, home "patches" → kind "outside", name "boost.json" (holds)
examples: (R18, save as) `P/patches` a junction, source `P/patches/boost.json` → kind "missing", name `None` (holds)

walk_tree_no_links
req: LLR-171.1a, LLR-171.1j, LLR-171.1k
in: Path root; Optional[list[Path]] unreadable = None; Optional[int] max_entries = None
out: Iterator[Path] entries
func: changed (`workspace.py`; R8, A3-5; R13, S3R2-1). Yields every entry below `root` as a relative path, depth-first, names sorted; a reparse point is yielded but never pushed, so a junction cycle ends. A folder whose `os.scandir` raises `OSError` is still skipped, and NEW: when `unreadable` is given, its relative path is appended to that list first (DR-5; `root` itself is reported as "."). NEW (R13): when `max_entries` is given, the walker keeps a running count of the entries it has read from `os.scandir`; once that count passes `max_entries` it stops reading the current folder BEFORE sorting it (today `sorted(os.scandir(...))`, `workspace.py:300`), yields what it has read in sorted order, up to `max_entries + 1` entries in all, and ends, so one huge folder is never sorted whole. Its other callers pass neither argument and keep today's behaviour (`workspace.py:288-291`: the save-as inventory and its unit test).
module: s19_app/tui/workspace.py
examples: (LLR-171.1a cycle) `P/flows/loop` → `P`: the walk yields "flows/loop" once and ends (holds by reading the code; the inventory arm proves it)
examples: (LLR-171.1k, R8) `P/reports/locked` cannot be listed, unreadable given → the list holds "reports/locked", the walk goes on with the other folders (target (8b))
examples: (holds) the same tree, unreadable not given → "reports/locked" skipped with no record, as at ebe6d0c
examples: (LLR-171.1j entries, R13, S3R2-1) one folder of `50000` empty files, max_entries `10000` → `10001` entries yielded, then the walk ends; `sorted` never receives more than `10001` names (spy) (target (8b))
examples: (LLR-171.1j entries) a tree of `10000` entries, max_entries `10000` → `10000` entries yielded, the same as with max_entries not given (target (8b))
examples: (holds) max_entries not given → every entry yielded, as at ebe6d0c

## Findings

### Design risks. DR-1 to DR-12. Seams with G1 are marked "seam".

finding DR-1 Document landing claimed by another file of the copied tree (seam)
anchor: plan_project_save step (6); interfaces-8b.md "one owner per landing"
seen: interfaces-8b.md says the document row owns its landing and the sub-folder copy leaves that path out. Read literally (by landing text), a document from the common library named `boost.json` would drop P's own `patches/boost.json` (other bytes) from Q, so LLR-171.1's "100 % of the expected set" fails for that file. If the copy keeps P's file and the plan predicts the document against the still-empty Q, the gather lands it as `boost_1.json` and `_plan_row_mismatch` aborts the save.
cause: the document row is predicted against Q before the copy has filled Q's home.
effect: either data loss in Q or an aborted save on a common workflow (gather once, edit the library copy, save as).
decision: the copy leaves out only the document's own file (same source text). Every other home row of a save as is predicted against `inventory.root / home`, the folder the copy mirrors into Q, so "keep" / "_1" come out as the gather will place them. Needs G1 to run the sub-folder copy before the gather (DR-11). Residual: a link in `P/patches` named like the document occupies the name in P but not in Q, so the prediction and the landing differ; the row check then aborts (fail loud). Simpler alternative for E3: refuse the plan when a home row lands on a copied path of another source. E3 r1: decided by pre-ruling 3 (this form, A3-9 confirmed, landing in resolved form) and R2 (G1 copies right after `mkdir`, before the rows loop, so the pasted document's `_1` is real too).

finding DR-2 A document deeper than its home in P is copied twice into Q
anchor: classify_active_document (unchanged, 8a)
seen: `P/patches/sub/x.json` is `inside_elsewhere` for a save into P (not recorded), but `outside` for a save as Q, so the gather copies it flat to `Q/patches/x.json` and records it, while the tree copy also puts it at `Q/patches/sub/x.json`.
cause: the 8a classifier decides "inside" against the target; a save as has a source project too.
effect: one extra file and an `active_document` that a save into P would not record. No loss (DR-1's prediction keeps P's own `patches/x.json`).
decision: left as 8a behaviour in this prototype. Option for E3: for a save as, classify against `inventory.root` (PC-5). E3 r1: backlog (pre-ruling 10).

finding DR-3 The free-space total leaves out project.json
anchor: plan_project_save step (7); LLR-171.1i
seen: the manifest's bytes are known only after serialization, which runs after the plan.
cause: `total_bytes` is computed at plan time.
effect: with free space exactly T, the real save also needs the manifest's few hundred bytes; the tests simulate free space, so they pass.
decision: E3 accepts or names a margin; LLR-171.1i's T as written (A2L + emitted image + S) matches this design. E3 r1: decided by R7 (S3-9) — each file rounded up to 4 KiB, plus 64 KiB for `project.json` and the folders of a new target (plan_project_save step 9).

finding DR-4 The tree can change between the plan and the copy (seam)
anchor: inventory_project_tree; G1's copy loop
seen: the inventory is taken at plan time. A file that grows past the cap makes `place_into_workarea` raise; a file removed makes the copy fail; a file added is not copied.
cause: a plan is a snapshot.
effect: the first two abort and roll back (fail loud, LED .53); the third is a silent omission of a file that did not exist when the plan was painted.
decision: G1 states what a vanished planned file does (abort with rollback is the existing rule). No change here. E3 r1: G1's copy re-checks the source after each placement (S3-5) and returns row 11 in user terms for any copy failure (R6).

finding DR-5 An unreadable sub-folder is omitted silently
anchor: walk_tree_no_links (`except OSError: continue`); inventory_project_tree
seen: a folder whose `os.scandir` raises yields nothing, and an entry whose `lstat` raises is left out.
cause: the walker swallows the error and does not report which folder it skipped.
effect: LLR-171.1's "0 missing" can be false with no line telling the user.
decision: open for E3. Fixing it needs the walker to report skipped folders (`workspace.py`, the only change found there) and a plan refusal or a status clause. Not in the prototype. E3 r1: decided by R8 (A3-5, S3-2) — a plan refusal before any folder; the walker reports unreadable folders through its new optional argument, and the inventory adds unclassifiable entries (applied in `walk_tree_no_links`, `inventory_project_tree`, `plan_project_save`).

finding DR-6 The MAC rule changes from "same name" to "same path, or same name and same bytes"
anchor: _second_file_refusal; app.py `_handle_save_dialog` MAC check at `ebe6d0c`
seen: at `ebe6d0c` a session MAC with the same name as the target's MAC is exempt whatever its bytes; the placement then lands it as `_1`, a second MAC, and the next load reports "more than one MAC file".
cause: LLR-167.6c says "not one of the target's data files"; one rule for MAC and A2L (LLR-167.6f) reads that literally.
effect: a same-name, other-bytes MAC into a merge target is refused now; no test asserts the old text or this arm (searched `tests/`).
decision: one rule for both files. E3 confirms or keeps the name rule for the MAC. E3 r1: confirmed by pre-ruling 5 and A3-4 (G1 passes `exempt`; LLR-167.6c's text now says "not the same path, and not the same name with the same bytes").

finding DR-7 One line per unrecorded file (seam)
anchor: gather_project_artifacts; GatherOutcome.unrecorded
seen: the active document whose landing cannot be recorded already gets `GATHER-DOCUMENT-NOT-RECORDED`; LLR-171.5's example says "a gathered flow row", but the gather has no flow limb (flows are copied by G1's tree copy, which writes nothing into `project.json`).
cause: two sources of "copied but not recorded".
effect: without a rule, one file could get two lines, or a flow file could be expected in `unrecorded` and never appear.
decision: `unrecorded` holds gather rows only and excludes the active document. E3 corrects LLR-171.5's example ("a gathered row", not "a gathered flow row"). G1 paints one line per `unrecorded` entry. E3 r1: decided by pre-ruling 7; LLR-171.5 corrected (A3-4); G1 caps the lines at 10 plus `and K more` (R6).

finding DR-8 ProjectInventory.total_bytes has no reader
anchor: interfaces-8b.md `ProjectInventory.total_bytes` (incl. top level)
seen: `SavePlan.total_bytes` must count the emitted image, not P's source image, and must not count P's `project.json` (LLR-171.1i negative control); the inventory's total counts both.
cause: the plan's total is built from the planned files and the sub-folder files instead.
effect: a field nobody reads; a later reader adding it to the plan total would double-count.
decision: kept as fixed in this prototype; PC-3 proposes to drop it. E3 r1: dropped (pre-ruling 2); `ProjectInventory` no longer has the field.

finding DR-9 The per-file cap is read in two places
anchor: plan_project_save `size_cap`; place_into_workarea `max_size_bytes = DEFAULT_COPY_SIZE_CAP_BYTES`
seen: the plan reads the module constant at call time; the placement's default was bound when `workspace.py` was imported.
cause: Python binds a default at definition time.
effect: a test that lowers the constant changes the plan only. LLR-167.6g's arms still hold (cap + 1 refused by the plan; exactly the cap passes both), but no test can show that the two agree. In production both are 256 MiB.
decision: accepted; recorded so no one reads a lowered-cap test as proof of the placement's cap.

finding DR-10 Inc 8a / Inc 5 rules this design must keep
anchor: LLR-167.6 threshold; E3 R11, R18; LED .45
seen: (a) "0 payload digests": the new code adds `predict_placement` calls that hash only an existing file of equal size, as 8a already does; (b) "no import of change_service / changes": the new imports are `validate_project_files`, `walk_tree_no_links`, `_is_reparse_point` and the `workspace` module (for the cap), all siblings; (c) R11 one classifier and R18 unresolved source: unchanged; (d) LED .45 manifest keys stay an input.
cause: —
effect: the E4 tester re-runs `test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload` and the 8a document arms unchanged.
decision: none needed; listed for E3.

finding DR-11 The sub-folder copy must run before the gather (seam)
anchor: G1 `_handle_save_dialog`; gather_project_artifacts composition limb
seen: the gather resolves a composition name against `project_dir` first, then the common library by bare name. If the gather runs first in a save as, `patches/x.json` named by P's carried `batch` is taken from the common library (maybe other bytes) and P's snapshot then lands as `x_1.json`, so Q's `batch` names the wrong bytes.
cause: Q is empty until the copy runs.
effect: wrong content behind a carried record, and DR-1's prediction would not match.
decision: G1 orders mkdir → top-level placements → sub-folder copy (the plan's files only) → gather → manifest. Each copy lands at `target / relative` or the row check aborts. E3 r1: superseded by R2 (A3-1). E3 r2 (R11, A3R2-1): mkdir → sub-folder copies → the rows loop (top-level placements and the pasted document; "carried" rows skipped) → top-level copies (R11) → gather → manifest.

finding DR-12 Which rows G1 must stop checking in the save body (seam)
anchor: app.py `_handle_save_dialog` after `mkdir` (MAC and A2L checks at `ebe6d0c`)
seen: the plan now refuses the second MAC / A2L before `mkdir`; the body checks would refuse again, and the body's A2L check still refuses the open project's own A2L (C3).
cause: the decision moved.
effect: if the body checks stay, LLR-167.6f fails on the second save into itself.
decision: G1 removes both body checks. The body's `validate_project_files` error ("more than one MAC file" already in the target) stays in the body: a target that already holds two is not a refusal this design moves.

### Proposed changes to interfaces-8b.md. PC-1 to PC-6. E3 decides each.

finding PC-1 Per-file list in PlannedFolder
anchor: PlannedFolder, InventoryFile
seen: the plan must refuse a file over the cap by name and sum the sizes; G1 must copy exactly the plan's files.
cause: `PlannedFolder(name, file_count, skipped_links)` carries a count only.
effect: without it, G1 re-walks (a second listing that can differ from the painted plan) and the cap needs a second size source.
decision: add `InventoryFile(relative: str, size: int)` and `PlannedFolder.files: tuple[InventoryFile, ...] = ()` with `file_count == len(files)`. E3 r1: decided by pre-ruling 1, plus `SavePlan.copies`.

finding PC-2 The walked root in ProjectInventory
anchor: ProjectInventory.root
seen: the planner must tell the document's own file from another file at the same landing (DR-1) and predict home rows against the source home.
cause: the inventory holds only relative paths.
effect: without it, `plan_project_save` needs a separate `source_dir` keyword that can disagree with the inventory.
decision: add `ProjectInventory.root: Path` (unresolved). E3 r1: decided by pre-ruling 2.

finding PC-3 Drop ProjectInventory.total_bytes
anchor: DR-8
seen: no reader; misleading next to `SavePlan.total_bytes`.
cause: the plan total is built from the planned files.
effect: one less number to keep true.
decision: drop it (rule: not used, deleted). If E3 keeps it, keep the fixed meaning (all regular files, top level included). E3 r1: dropped (pre-ruling 2).

finding PC-4 Top-level file links out of skipped_links
anchor: inventory_project_tree; interfaces-8b.md "every directory link / junction / file symlink found, at any depth"
seen: the save-as enumeration of LLR-171.1 covers the sub-folders; top-level files reach Q through the plan's image, MAC and A2L rows. A top-level `firmware.s19` that is a link would be named "skipped" while the image row may copy its bytes.
cause: the fixed text lists file links at any depth.
effect: a misleading status clause, and a mismatch with LLR-171.1c ("links the enumeration skips").
decision: the prototype follows the fixed text. Proposal: list top-level directory links and every link under a sub-folder, not top-level file links. E3 r1: rejected (pre-ruling 10); with R3 a top-level file link is a file the copy skips, so listing it is now also true.

finding PC-5 Save-as classification against the source project
anchor: DR-2
seen: a document deeper than its home in P is recorded in Q but not in P.
cause: the classifier decides "inside" against the target.
effect: one extra file in Q.
decision: optional. Pass `inventory.root` to the classifier for a save as; `in_home` in P → the document row owns `home/name`, `inside_elsewhere` in P → no row (the tree copy carries it). Not applied here. E3 r1: backlog (pre-ruling 10).

finding PC-6 New keywords on plan_project_save
anchor: plan_project_save
seen: interfaces-8b.md says the planner decides the refusals and the sub-folders but names no new input.
cause: the planner needs the inventory and the cap.
effect: G1 calls `plan_project_save(..., inventory=inventory_project_tree(P))` for a save as with an open project and passes no `size_cap`.
decision: add `inventory: Optional[ProjectInventory] = None` and `size_cap: Optional[int] = None` (keyword-only). E3 r1: decided by pre-ruling 4, plus `exempt: frozenset[str] = frozenset()` (pre-ruling 5).
