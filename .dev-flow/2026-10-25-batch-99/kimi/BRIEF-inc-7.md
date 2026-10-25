# Kimi brief — batch-99 Increment 7 · US-151 / HLR-162 · Load project and Workarea Files load by name

Read `BRIEF-COMMON.md` first. Its rules bind this increment.

## Requirement (grep in `.dev-flow/2026-10-25-batch-99/01-requirements.md`)
HLR-162, LLR-162.1, 162.2, 162.3; TC-B99-34, 35, 36; AT-B99-13. Design: `design/design-proposal-b99.md` §4 B99-I9; map row B99-I9 in `docs/architecture.md`. Context: batch-97 Inc-9 fixed `LoadProjectScreen` (it stores the project name on the item). See `tests/test_b97_load_project_dialog.py` for its idiom, and reuse it.

## SOURCE files (max 2)
`s19_app/tui/app.py`, `s19_app/tui/workspace.py`.

## What to build
1. `RESERVED_WORKAREA_HOMES` (a tuple constant in `workspace.py`): `temp`, `patches`, `templates`, `logs`, `crc`, `flows`, `flowsets`, `splits`, `reports`. Grep the code for every folder created directly under the work area. If you find one more, add it and say so in the packet.
2. `list_projects` omits every name in the tuple.
3. `refresh_files` lists the regular files of the folder that file loads copy into (the temp load folder, see `load_from_path` / `copy_into_workarea` callers), never the `.staging` subfolder. It stores each file name on its `ListItem`, the same way as the Inc-9 dialog fix.
4. `_load_from_item` reads the stored name and resolves it against that same folder, never `str(Label)`.

## Tests — `tests/test_b99_load_project.py`
- **TC-B99-34:** picking `a.s19` and `a b.s19` (a name with a space) loads that file.
- **TC-B99-35:** with folders `P1`, `P2` and every reserved home present, the project list holds `P1` and `P2` only. The test imports the tuple.
- **TC-B99-36:** after one file load, the Workarea Files list holds that file, and picking it loads it. With no file loaded, the list is empty.
- **AT-B99-13** (pilot, real keys and clicks), with projects `P1`, `P2` and a `patches` folder:
  1. The dialog lists `P1` and `P2` only.
  2. Three pick paths each load `P2`, and the status names `P2`: (a) keyboard highlight + click `#project_ok`; (b) click the item + `#project_ok`; (c) keyboard highlight + focus `#project_ok` + `enter`.
  3. After a file load, the Workarea Files list shows that file, and picking it loads it.
  4. Empty boundary: with no project, pressing Load loads nothing, and the current file stays loaded.
- Mutations: restore `str(label_widget)` in `_load_from_item` (TC-34 / AT RED); `!= WORKAREA_TEMP` only (TC-35 RED); list the work-area root (TC-36 RED). Revert each one.

## Out of scope
Enter-to-load on the list itself (D10) and any dialog redesign: those belong to the Load+projects batch.

## Reverse census
`grep -rln "list_projects\|refresh_files\|_load_from_item\|files_list\|project_list" tests/`. Re-pin only what HLR-162 changes.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-007.md`, REQ-ID `HLR-162`.
