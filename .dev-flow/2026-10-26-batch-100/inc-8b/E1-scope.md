# E1 — Inc 8b requirements scope and E2 slice

Stage E1 of the design-first pipeline (`design-first-increment` skill) for Inc 8b (PLAN.md roadmap row 8b: M-3, M-6, M-5, D5–D7, O-4). Source: `01-requirements.md` after the E1 edits (LED-2026-10-26-batch-100.76) and the orchestrator's rulings on the E1 open questions (LED-2026-10-26-batch-100.77). Line numbers are those of the edited file. Inputs from the parallel Code-Wire baseline (`codewire/baseline-notes.md`, items C1–C6 and caller 1) are folded in as LED .76 and .77 state.

**Counts.**
- **Before:** 6 requirements in scope (HLR-171; LLR-171.1, .2, .3, .4; the Inc 8b arm of LLR-167.6), holding about 20 "shall"/behaviour clauses.
- **After E1 and the rulings:** 37 single-"shall" requirements in 8b scope, 3 HLRs and 34 LLRs.
  - 3 LLRs were already met at Inc 1 (LLR-171.4, .4a, .4b).
  - 31 LLRs are owed new at 8b.
- **Outside the count:** LLR-171.4d is withdrawn into .4c (ruling Q6). LLR-171.4i and .4j (SEC-5) stay written but are routed out of 8b (ruling Q1). LLR-167.6 keeps its multi-increment statement; only its 8b arm moved to LLR-167.6a–g.

**Per EARS form (37 in scope):** event (E) 12 · state (S) 4 · ubiquitous (U) 7 · unwanted (UW) 14 · optional 0.

## 1 · Scope list

| Id (line) | Statement (short) | EARS | Threshold (pass) | Negative control |
|---|---|---|---|---|
| HLR-171 (497) | When Save project saves the open project into a new project folder, the new project holds every regular sub-folder file not reached through a link | E | `p06` C: 0 missing, 0 differing; 3 links → 0 files through them | base `1d677ba` P-9 → AT-B100-09 RED |
| HLR-171a (514) | When a folder with one A2L and no data file is loaded, open the project with its A2L attached | E | `p04` 10: opens, 3 A2L tags, 0 `No supported files`, the A2L is the project's own file | base P-12 → AT-B100-10 RED |
| HLR-171b (531) | Treat a folder as a project only when it is not a link/junction and resolves inside this work area | U | junction → 0 listed, 0 loads, 0 bytes outside (8 writers); foreign parent → refused | S-02 probe → AT-B100-11 RED |
| LLR-167.6a (902) | When planning a save as, one row per top-level sub-folder with its recursive copy count; a links-only sub-folder → a 0-file row | E | 7 rows, counts = written (0 diffs); links-only → 1 row, 0 files; none → 0 rows | no sub-folder rows; 0-file sub-folder omitted |
| LLR-167.6b (912) | When planning a save as, list each skipped link | E | 3 entries = LLR-171.1c's 3 paths; links-only sub-folder's junction listed against its row | links dropped from the plan |
| LLR-167.6c (922) | If the target holds a MAC and the session's MAC is not one of its data files, refuse in the plan | UW | plan refusal, 0 rows, 0 `mkdir` calls (spy), 0 rollbacks | base: refusal after `mkdir` (1 call) |
| LLR-167.6d (932) | If the target holds an A2L and the session holds an A2L other than it, refuse in the plan | UW | same as .6c | base: after `mkdir`; body-only check |
| LLR-167.6e (942) | At most one plan row per landing path | U | document in a copied sub-folder → 1 row, action = tree | both own the landing → 2 rows |
| LLR-167.6f (952) | When the target's A2L is the session's A2L (same path, or same name and bytes), plan without the A2L refusal | E | A2L-only project saved into itself twice → 2 saves, 0 refusals, 0 `_1` copies; same name, other bytes → refused | base C3: second save refused; name-only exemption |
| LLR-167.6g (962) | If a file to copy exceeds the per-file cap, put a refusal naming it into the plan | UW | cap + 1 → refusal naming `splits/big.bin`, 0 rows, 0 `mkdir`; exactly the cap → saved | base: raises after `mkdir` (1 call); `>=` |
| LLR-171.1 (1152) | Copy each regular sub-folder file, at every depth, to the same relative path in the new folder | E | 100 % of the expected set, 0 differing SHA-256; no sub-folder / no open project → 0 | P-9 RED; first-level-only copy |
| LLR-171.1a (1162) | While enumerating for save as, never descend into a directory link/junction | S | 2 junctions → 0 outside files; cycle → done < 5 s | S-03 `os.walk` probe; no reparse re-check (Py 3.11) |
| LLR-171.1b (1172) | While enumerating for save as, never copy a file symlink | S | 0 files at `Q/patches/l.json`; "not run" if no link can be made | follow file links |
| LLR-171.1c (1182) | When a link is skipped, name its relative path in the status | E | 3 of 3 named (whole `set_status` message) | silent skip → 0 of 3 |
| LLR-171.1d (1192) | Exclude bytes behind a link from the save-as total | U | free space = T → saved | plain walk (R2-06) → refused |
| LLR-171.1e (1202) | If total > free space, refuse with `not enough free space` before creating the folder | UW | T − 1 → 1 line with tokens, 0 folders, 0 bytes; T → saved | check after `mkdir`; `>=` |
| LLR-171.1f (1212) | Save as never modifies, adds or removes a file of the open project | U | P's (path, SHA-256) set: 0 changed/added/removed | move instead of copy |
| LLR-171.1g (1222) | While the target is an existing project folder, never copy the open project's sub-folders | S | merge into R → 0 P sub-folder files beyond the gather's rows, 0 sub-folder rows; into itself → 0 copies | copy run for a merge → `R/flows/f1.json` |
| LLR-171.1h (1232) | When saving as, write the open project's `batch`, `assignments`, `declared_regions`, `gathered`, `active_document` (relative) into the new `project.json` | E | 5 of 5 equal, named files present, `gathered` = P's + this save's, `files` scope unchanged, Load Q → 0 `missing` | fresh manifest → `batch` empty; absolute paths → refused |
| LLR-171.1i (1242) | Count every byte the save as writes (top-level, emitted image, sub-folders) in the total | U | T includes A2L + emitted image + S; T − 1 → refused, T → saved | sub-folders only; source image instead of emitted |
| LLR-171.2 (1252) | When an A2L-only folder is loaded, attach the project's own A2L in place | E | 3 tags, Loaded panel names it, A2L path = `workarea/P/firmware.a2l`, 0 files in `workarea/temp`, 0 refusals | P-12 RED; `load_a2l_from_path` → temp copy or self-refusal |
| LLR-171.2a (1262) | … remove the previously loaded data file | E | `current_file` None, 0 images | skip the reset |
| LLR-171.2b (1272) | … make that folder the open project | E | open project `P`, unresolved `workarea/P` | project not set |
| LLR-171.2c (1282) | While an A2L-only project is open, a loaded data file is recorded in `project.json` | S | 1 variant, `active_variant` = `firmware` | variant set left `None` |
| LLR-171.2d (1292) | If `project.json` and no data/A2L file, refuse with `no data or A2L file` | UW | 1 line with both tokens, 0 resets | paints `No supported files` |
| LLR-171.2e (1302) | If no `project.json` and no data/A2L file, refuse with `no project.json` | UW | 1 line, 0 resets | reaches the `no data or A2L file` branch |
| LLR-171.3 (1312) | If the parent does not resolve to this work area, refuse before creating any folder | UW | 3 foreign parents → `Project NOT saved`, 0 `mkdir` calls (spy) | base `ebe6d0c` refuses after `mkdir` (C2); `is_relative_to` |
| LLR-171.3a (1322) | When the parent is this work area under another spelling, save there | E | 3 of 3 saved and listed once | text comparison |
| LLR-171.4 (1332) | Inside = resolved path equals or lies below the resolved root (Inc 1, met) | U | 5 of 5 predicate arms | S-02 probe |
| LLR-171.4a (1342) | If a placement destination is outside, refuse it (Inc 1, met) | UW | 2 refusals, 0 bytes | S-02 probe |
| LLR-171.4b (1352) | If the `project.json` destination is outside, refuse the write (Inc 1, met) | UW | 0 bytes outside | `_check_destination_contained PASSED` |
| LLR-171.4c (1362) | If a work-area folder is a link/junction, leave it out of the list (absorbs .4d) | UW | `evil`, `alias`, outside junction → 0 rows; normal → 1 | no link check → `alias` listed |
| LLR-171.4e (1377) | If a project to load is a link/junction, refuse the load (picked arm) | UW | `evil`, `alias` → 0 loads, 0 resets, 1 line each | no link check → `alias` loads |
| LLR-171.4f (1387) | If a project to load resolves outside, refuse the load (picked arm) | UW | `..` name → 0 loads | no containment check → `..` loads |
| LLR-171.4g (1397) | If the Save target is a link/junction, refuse with `link or junction` before resolving | UW | new and merge → 2 lines, 0 folders, 0 bytes outside | resolve before the check |
| LLR-171.4h (1407) | 8 named writers write 0 bytes outside this work area | U | 16 of 16 junction arms 0 bytes; 8 of 8 normal arms inside | containment removed from `place_into_workarea` |
| LLR-171.5 (1437) | If a copied file's path cannot be recorded in `project.json`, paint 1 line naming it (R2-1) | UW | device stem → saved, 1 line, 0 raises; none → 0 lines | base: 0 lines (code read); drop the line |

Out of the 8b count: LLR-171.4d (1372, withdrawn into .4c), LLR-171.4i (1417) and LLR-171.4j (1427) (SEC-5, routed to the LED .50 backlog item).

| AT / TC | Owner | 8b share |
|---|---|---|
| AT-B100-09 (HLR-171) | US-161 | written at 8b: save-as → Q folder → flow list |
| AT-B100-10 (HLR-171a) | US-161 | written at 8b: A2L-only Save → Load (with LLR-167.6f, a second save into itself is not refused) |
| AT-B100-11 (HLR-171b) | US-161 | written at 8b: listing and Save refusal |
| TC-B100-31 | LLR-171.1, .1a–.1i, LLR-171.5 | full |
| TC-B100-32 | LLR-171.2, .2a–.2e | full |
| TC-B100-33 | LLR-171.3, .3a | full |
| TC-B100-62 | LLR-171.4c, .4e–.4h | 8b arms; the Inc 1 arms (.4, .4a, .4b) stay green |
| TC-B100-59 | LLR-167.6a–g | 8b arms |

29148 check: every requirement above is singular (one "shall", checked by script), states a numeric threshold and a negative control, and names functions only in its trace. Declared exceptions: LLR-171.1b depends on the platform allowing a file symlink (a test that cannot create one counts as not run, never as passed); LLR-171.5's base control is a code read, not an executed run; LLR-167.6g lowers the per-file cap in the test (the shipped cap is 256 MiB).

## 2 · Items routed to 8b and where they went

| Item | Where |
|---|---|
| LED .63 (b) / LED .66: MAC and A2L refusals before the folder exists | LLR-167.6c, .6d (plan-time, `mkdir` spy) + .6f (own-A2L exemption). A new target folder cannot hold either file, so the arms use merge or open-project targets. |
| SEC-5: flow and flowset writers outside the placement | LLR-171.4i, .4j written, then routed OUT of 8b (ruling Q1), with the chain-set, report and report-filter writers (Code-Wire C1). |
| LED .23 B-06: TC-B100-59's sub-folders arm at 8b (the brief cited it as LED .19) | LLR-167.6a–g. |
| BACKLOG-CODE R2-1 | LLR-171.5. |
| Code-Wire C2 (LLR-171.3's control stale) | LLR-171.3 re-based on `ebe6d0c` with a `mkdir` spy. Once the parent must be this work area, the name-clash scan (which reads `self.workarea`) reads the right folder by construction. |
| Code-Wire C3, C4, C5, C6 | LLR-167.6f, LLR-171.2, LLR-167.6e, LLR-167.6g. |
| Code-Wire caller 3 (Execute on an A2L-only project) | out of 8b (ruling Q11): backlog; E3 checks only that Execute does not crash. |
| Stale citations (`workspace.py:172`, `app.py:8519-8524`, `screens.py:144-176`) | removed; cited by symbol. |

## 3 · Slice for E2

Names come from the requirements, the code at `ebe6d0c` and the Code-Wire baseline (5 changed nodes there). **(guess)** marks a node the requirements imply but do not name; such a node may end up inline in its caller. Sources: `app.py` and `project_gather_service.py`; `workspace.py` only if a helper is truly needed (ruling Q1). `flow_persistence_service.py` is out.

### `app.py` — 5 changed + up to 6 new

| # | Node | What changes | Requirement |
|---|---|---|---|
| 1 | `S19TuiApp._handle_save_dialog` | refuses the parent before any `mkdir` unless it resolves to this work area (spelling-tolerant); runs the sub-folder copy for a new folder only (copies through `place_into_workarea` with `workarea_root=self.workarea`); refuses on free space before `mkdir`; the status names skipped links and unrecordable copies; the MAC, A2L and cap checks leave the body (plan-time); writes the carried records for a save as | 171.1, .1c, .1e, .1f, .1g, .1h, 171.3, .3a, 171.4g (kept), 171.5, 167.6c/d/f/g |
| 2 | `S19TuiApp._plan_project_save` | builds the save-as inventory, the sub-folder `PlannedFile`s (top-level, recursive count, 0-file rows) and the skipped links; the total over every written byte; the MAC/A2L refusal with the own-A2L exemption; the per-file cap refusal; one owner per landing; no sub-folder rows for an existing target | 167.6a–g, 171.1d, .1g, .1i |
| 3 | `S19TuiApp._manifest_carry` | used for a save as too: the source project's 5 records, made relative to the new project (today it carries for an in-project rewrite, a merge and an open-project save) | 171.1h |
| 4 | `S19TuiApp.list_projects` | drops a link/junction child | 171.4c |
| 5 | `S19TuiApp._handle_load_project` | refuses a link/junction or outside folder before any reset; the A2L-only branch attaches the project's own A2L in place, resets, sets the project and the variant set for a later append; the two refusal tokens | 171.4e, .4f, 171.2, .2a–.2e |
| N1 | `_save_as_inventory` (guess) | one link-free enumeration → (files, skipped links, sub-folder byte total) | 171.1a, .1b, .1d |
| N2 | `_copy_project_subfolders` (guess) | the copy of the planned sub-folder files, recording placements for the rollback | 171.1 |
| N3 | `_free_space_refusal` (guess) | total vs `shutil.disk_usage(workarea).free` | 171.1e, .1i |
| N4 | `_project_folder_refusal` (guess) | one check shared by the listing and the load: link check before `resolve()`, then `contained_in_workarea` (the load only, after Q6) | 171.4c, .4e, .4f |
| N5 | `_open_a2l_only_project` (guess) | the A2L-only branch of the load (in place, the `_load_a2l_data_with_cache` payload; not `load_a2l_from_path`) | 171.2–.2c |
| N6 | `_single_file_refusal` (guess) | the MAC/A2L condition with the same-path / same-name-and-bytes exemption, as a plan input | 167.6c, .6d, .6f |

### `project_gather_service.py` — 2 changed functions + 3 data nodes

| # | Node | What changes | Requirement |
|---|---|---|---|
| 6 | `plan_project_save` | sub-folder rows with counts (0-file rows kept), skipped links, 1 row per landing (dedup or a declared owner), the cap refusal passed as `refusal` | 167.6a, .6b, .6e, .6g |
| 7 | `gather_project_artifacts` | reports each row it copied but left out of `gathered` | 171.5 |
| D1 | `SavePlan` | + skipped links (guess: a field) | 167.6b |
| D2 | `PlannedFile` / `SavePlanRow` | + a sub-folder role and count (guess) | 167.6a |
| D3 | `GatherOutcome` | + the unrecorded copies (guess: a field) | 171.5 |

### `workspace.py` — 0 firm, 1 guess

`walk_tree_no_links` yields link entries as leaves without saying which are links; N1 can re-check each leaf with `_is_reparse_point`. Change it only if E2 needs the walker to classify (guess). `contained_in_workarea`, `_is_reparse_point`, `place_into_workarea`, `DEFAULT_COPY_SIZE_CAP_BYTES`, `validate_project_files`, `build_variant_set` are unchanged context.

**Node count:**
- **Firm: 10.** `app.py` 5 functions; `project_gather_service.py` 2 functions + 3 data nodes.
- **With the guesses: up to 17** (+6 `app.py`, +1 `workspace.py`).
- That is above ~8, so E2 runs by file group:
  - G1 `app.py` (5–11).
  - G2 `project_gather_service.py`, plus `workspace.py` if the walker changes (5–6).
- **Source files:** 2–3, within the cap of 4.

**Seams to fix before E2 (shared interfaces):**
- the shape of the plan's sub-folder row (top-level, recursive count, 0-file rows) and the skipped-links field (G1 ↔ G2);
- the owner of a landing that both the document row and the sub-folder copy claim (C5);
- the unrecorded-copy field on `GatherOutcome` (G1 ↔ G2);
- the cap refusal: computed in `app.py` and passed as the plan's `refusal`, or computed in `plan_project_save` from the sizes.

## 4 · Orchestrator rulings (LED .77) and the Q5 placeholder list

| Q | Ruling | Applied in |
|---|---|---|
| Q1 | SEC-5 and the non-placing writers are out of 8b (LED .50 backlog item / BACKLOG-CODE) | LLR-171.4i, .4j marked "Not in Inc 8b"; HLR-171b; §5.3 |
| Q2 | a save into an existing project copies no sub-folder | LLR-171.1g (new) |
| Q3 | the A2L refusal exempts the open project's own A2L (same path, or same name and bytes) | LLR-167.6d narrowed; LLR-167.6f (new) |
| Q4 | an A2L-only project attaches its own A2L in place; the session's A2L path is the project's file | LLR-171.2, HLR-171a |
| Q5 | token rows: E2 drafts, E3 confirms | placeholder list below |
| Q6 | drop LLR-171.4d, its arm into .4c | LLR-171.4d withdrawn |
| Q7 | save as carries `batch`, `assignments`, `declared_regions`, `gathered`, `active_document` (relative); `files` keeps its scope | LLR-171.1h (new) |
| Q8 | the free-space total counts every byte written (top-level, emitted image, sub-folders) | LLR-171.1i (new); .1d, .1e refer to it |
| Q9 | one row per top-level sub-folder with its recursive count; a links-only sub-folder → a 0-file row with its skipped links | LLR-167.6a, .6b |
| Q10 | a file over the per-file cap is refused in the plan, naming it, before any folder exists | LLR-167.6g (new) |
| Q11 | Execute on an A2L-only project is out of 8b (backlog); E3 checks only that it does not crash | no requirement |

**Q5 placeholder list: token rows for E2 to draft and E3 to confirm** (reason token / next-step token; none is in the §3 token table today):
1. Save parent not this work area (LLR-171.3).
2. Project load refused: the folder is a link or junction (LLR-171.4e).
3. Project load refused: the folder resolves outside this work area (LLR-171.4f).
4. Second MAC file in the target (LLR-167.6c); today's text is `Project already has a MAC file.`
5. Second A2L file in the target (LLR-167.6d); today's text is `Project already has an A2L file.`
6. A file over the per-file cap (LLR-167.6g), naming the file.
7. The skipped-link clause of the Save project status (LLR-171.1c).
8. The copied-but-not-recorded line (LLR-171.5).

## 5 · Observations

- LLR-167.6 keeps its multi-increment compound statement (Inc 5/7/8a); only its 8b arm was split out. Rewriting the whole statement is outside 8b.
- LLR-171.4h is one property (0 bytes outside) over 8 named writers. Its "shall" is singular, and it is verified by 16 + 8 arms.
- The typed project load named in the old LLR-171.4 has no code path at `ebe6d0c`; the typed arm is LLR-172.5 at Inc 9a.
- The ATs (AT-B100-09/10/11) are tests, not requirements. Their text is unchanged, and each now hangs on its own HLR.
- With Q1 out, a junction *sub-folder* (`P/flows` → outside) in a normal project is still written through by the flow and flowset writers until the LED .50 backlog item lands. The save-as copy never descends into one (LLR-171.1a).
