# Inc 9a — orchestrator rulings on E1 questions and E2-baseline candidates

Under the batch's standing authorization (autonomous; stop only on HIGH or an operator decision). The E1 text already follows Q1–Q9 as recommended, so no E1 re-apply pass.

| Id | Ruling | Why |
|---|---|---|
| Q1 / C1 | Record after the copy into `temp/` (LLR-172.1a/.1d), in `load_from_path` / `load_a2l_from_path`, on the calling thread. A file that copies and then fails to parse is still recorded. | One record point, no worker-thread write; the engineer did pick that source, and the parse failure is reported by the load itself. |
| Q2 | A command-line startup load of an outside file is recorded (same route). | No special case. |
| Q3 / C3 | A typed project path goes through `_route_load_project` (the Load-result panel opens). | The typed and the picked route must not differ. |
| Q4 | No work-area lookup for a bare name at 9a; tests type the absolute path. | 9b's list picks by name. |
| Q5 | A failed store write: 1 log warning, 0 status lines. | The store is a convenience; the load's status stays the user's signal. |
| Q6 | Unreadable store problem word: `could not be read`. | Existing token (8b F7). |
| Q7 | No new token rows. | Every refusal reuses a pair. |
| Q8 | AT-B100-12 stays one AT under HLR-172 and HLR-172a. | One chain. |
| Q9 | A typed empty folder → `not a project` (§1.3); `list_projects` unchanged at 9a; 9b LLR-173.4 decides its rows. | §1.3 is the definition; the list is 9b's surface. |
| C2 | No `resolve()` before the link check on a typed path (LLR-172.5d). | Resolving first would load a junction's target. |
| C4 | The typed route uses §1.3's project definition in one app-side helper; unifying `list_projects` / `_project_folder_refusal` / the typed check is 9b (with LLR-173.4). Routed to BACKLOG-CODE at close. | Two-file cap; the list is 9b. |
| C5 | Row label = `safe_text(name)`; `item.data` keeps the on-disk name; the pick reads `item.data`. | A safe label differs from the name. |
| C6 | `recent_kind` maps suffixes with the loader's own extension sets (`workspace.py` sets near line 107–110), so `.srec`/`.ihex`/… get the kind the loader gives them; any other suffix → not recorded. | One suffix table. |
| C7 | `.a2l.json` rows in the Workarea Files list: not 9a (the lister keeps today's file set, LLR-172.4 is about one lister). Routed to BACKLOG-CODE at close (9b list surface). | Scope. |
| C8 | Nothing in the test suite or the tools may write the real per-user store: an autouse fixture in `tests/conftest.py` points `LOCALAPPDATA` at `tmp_path`; `tools/e13/run.py` and `capture_readme_media.py` set `LOCALAPPDATA` to their scratch folder. Tests and tools are not source files (cap unchanged). | A test run must not touch the engineer's store. |
