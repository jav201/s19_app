# HANDOFF — batch-99 Increment 7 (HLR-162 · Load project and Workarea Files load by name)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc7` (branch `b99-inc7`, base `f1ba70c`). Nothing committed — all changes are in the working tree for the orchestrator.

## What was built
- `s19_app/tui/workspace.py`: new tuple constant `RESERVED_WORKAREA_HOMES` (`temp`, `patches`, `templates`, `logs`, `crc`, `flows`, `flowsets`, `splits`, `reports`) with a doc comment (LLR-162.2). Writer census: only `temp`/`patches` are created directly under the work area (`ensure_workarea`, `workspace.py:85-86`); the other seven are `.s19tool/` homes or per-project homes — no extra home found, the LLR's closed set stands.
- `s19_app/tui/app.py`:
  - import the tuple;
  - `list_projects` omits every tuple name (was `!= WORKAREA_TEMP` only — P-20);
  - `refresh_files` lists regular files of `workarea/temp` (the load folder, CW-U-3), never the root / `.staging`, and stores `entry.data = name` on each `ListItem` (the codebase's stored-payload idiom);
  - `_load_from_item` reads `item.data`, resolves against `workarea/temp`, never `str(Label)` (P-19 / CW-U-1).
- Both files remain pure CRLF (re-measured: 13619 / 862 CRLF, 0 LF-only).

## Tests — `tests/test_b99_load_project.py` (new, 4 nodes, CRLF)
- `test_tc_b99_34_pick_loads_the_picked_file_name` — pilot; `a.s19` and boundary `a b.s19`; dialog load then list pick; the fresh load is observed as the painted `Loaded <name>` line being pushed into `#log_line_3`.
- `test_tc_b99_35_reserved_homes_are_not_projects` — unit; imports the tuple; P1+P2+all nine homes → `['P1','P2']`; reserved-only → `[]`.
- `test_tc_b99_36_workarea_files_reads_the_load_folder` — pilot; empty list at fresh mount; after one load the list holds exactly that file (no `.staging`); picking it loads it.
- `test_at_b99_13_project_and_file_pickers_load_by_name` — black-box AT: dialog lists `P1`,`P2` only (with `patches` present); three pick paths (keyboard highlight + `#project_ok`; click item + `#project_ok`; keyboard highlight + focus `#project_ok` + `enter`) each load P2 with the status naming it; file pick after load; empty boundary (no project → `No saved projects found.`, current file stays loaded — driven via the shipped `#ws_load_project_button` because the Segment Split window binds `p` after a load; recorded in the packet §5).

## Verification (all transcripts in `.dev-flow/2026-10-25-batch-99/evidence/inc-7/`)
- Import proof: `python -c "import s19_app; print(s19_app.__file__)"` → worktree path.
- RED baseline on the unmodified tree: all 4 nodes FAILED on their exact oracles (`red-initial.txt`): TC-34/36 `[] == ['a.s19'/'one.s19']`, TC-35 `ImportError`, AT `['P1','P2','patches']`.
- GREEN: 4/4 nodes (per-node transcripts), 23 address census, 13 id-registry (`EXPECTED_SCANNED_TEST_FILES` 209 → 210, bumped with comment), joint run 27 passed.
- Mutations (each KILLED, reverted by SHA-256 to `0979a4bb…` app.py, no mutant left): LLR-162.1 restore `str(Label)` → TC-34/36+AT RED; LLR-162.2 `!= WORKAREA_TEMP` only → TC-35+AT RED; LLR-162.3 root listing → TC-36/34+AT RED.
- Reverse census: 8 files, 7 per-symbol probes, 0 re-pins. Regression run: 390 passed, 1 xfailed, 1 failed — the failure (`test_at_b78_32_app_bindings_block_is_untouched`) is pre-existing, red at `evidence/baseline-pytest-a293213.txt`.
- Note: first TC-34 RED run and the first census run caught two test-side defects (a `tmp_path` collision and `pilot.click(<Call>/<Await>)` sites the tree-guard rejects); both fixed and every affected transcript re-run on the final tree.

## Packet
`.dev-flow/2026-10-25-batch-99/03-increments/increment-007.md` — filled §1–§7, §4b `pending — orchestrator`; all 13 evidence hashes in the packet match the stored bytes and `SHA256SUMS.txt` in the evidence folder.

## Open questions
- None against the brief. Enter-to-load on the list (D10) and dialog redesign remain out of scope per the brief (Load+projects batch).

__KIMI_UNIT_DONE__
Files changed: s19_app/tui/workspace.py, s19_app/tui/app.py (2 SOURCE); tests/test_b99_load_project.py (new), tests/test_id_registry.py (count bump).
Tests added: 4 nodes — TC-B99-34, TC-B99-35, TC-B99-36, AT-B99-13.
RED/GREEN: baseline RED 4/4; GREEN 4/4 nodes + 23 census + 13 registry + joint 27; regression 390 passed / 1 pre-existing failure.
Mutations: 3 (LLR-162.1 str(Label), LLR-162.2 temp-only filter, LLR-162.3 root listing) — all KILLED, all reverted by SHA-256.
Open questions: none; awaiting the orchestrator's independent review (§4b pending).
