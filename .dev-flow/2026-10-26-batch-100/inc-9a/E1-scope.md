# E1 — Inc 9a requirements scope and E2 slice

Stage E1 of the design-first pipeline (`design-first-increment` skill) for Inc 9a (PLAN.md roadmap row 9a: "recent-sources store, shared work-area lister, project path routing", finding L-2; sources `workspace.py`, `app.py`). Source: `01-requirements.md` after the E1 edits (LED-2026-10-26-batch-100.82). Line numbers are those of the edited file; code lines are at `4fef292`. Premises in scope: P-15, P-24, S-01, S-06, S-07, S-12, S-16.

**Counts.**
- **Before:** 7 requirements in scope (HLR-172; LLR-172.1 … LLR-172.6), holding about 22 "shall"/behaviour clauses (HLR-172 alone had 6 "shall"s).
- **After E1:** 40 single-"shall" requirements, 3 HLRs and 37 LLRs, all owed new at 9a.
- **Outside the count:** LLR-171.4e and LLR-171.4f (Inc 8b) changed only their typed-arm pointer.

**Per EARS form (40 in scope):** event (E) 10 · state (S) 0 · ubiquitous (U) 8 · unwanted (UW) 22 · optional 0.

**Base probe.** `evidence/inc-9a/e1-probe-4fef292.md`, executed on `4fef292` in this worktree (s19env):
- typed `<workarea>/ab` → `['Unsupported file type: ']`; `<workarea>/ab/project.json` → `['Unsupported file type: .json']`; `<workarea>/temp` and `<workarea>/temp/../ab` → `['Unsupported file type: ']` (P-15 still TRUE);
- `_handle_load_project('temp')` → `Loaded project 'temp' …`, `current_project = temp` (S-01 still open at the load seam);
- the `[bold]x.s19` Workarea Files row → `Content('x.s19', spans=[Span(0, 5, style='bold')])` (P-24 still TRUE).

## 1 · Scope list

| Id (line) | Statement (short) | EARS | Threshold (pass) | Negative control |
|---|---|---|---|---|
| HLR-172 (569) | When Load copies an outside data/A2L file into the work area, record its path in the per-user store | E | 25 sources → 20 entries newest first; 0 store files under base; hostile set → 0 raises, 0 refused returned | code read: 0 `LOCALAPPDATA` hits → AT-B100-12 RED |
| HLR-172a (587) | When the typed path names a project folder here or its `project.json`, load that project | E | 2 loads of `ab`; `temp`, `TEMP`, `patches` → 0 loads, 0 files | probe: `Unsupported file type: ` → RED |
| HLR-172b (605) | Show each Workarea Files name as on disk, no markup, no control character | U | 4 hostile names → 4 literal rows, 0 spans, 0 control chars | probe: bold span → AT-B100-13 RED |
| LLR-172.1 (1668) | Store at `%LOCALAPPDATA%\s19_app\recent_sources.json` | U | 1 file there, 0 under base; real store digest unchanged | code read; `.s19tool` and `APPDATA` mutants |
| LLR-172.1a (1678) | Put the resolved path and kind first | E | 1 entry schema v1; 4 kinds newest first; `.SREC` → `s19` | base 0 entries; work-copy path; append-last |
| LLR-172.1b (1688) | One entry per resolved path, moved first | E | same file → 1; case spelling → 1; A,B,A → A first | no dedup; old position; case-sensitive |
| LLR-172.1c (1698) | At most 20 entries, oldest dropped | U | 20 → 20; 21st → 20, source 1 gone; 25 → 20 | cap 21 / none; drop newest |
| LLR-172.1d (1708) | If Load fails before its copy, store unchanged | UW | 4 failure arms → digest unchanged | record before copy |
| LLR-172.1e (1718) | If the source is inside the work area, not recorded | UW | 3 arms → 0 entries | no inside check |
| LLR-172.1f (1728) | If `LOCALAPPDATA` unset/empty/relative, no store file | UW | 3 arms → 0 files, load completes, 0 raises | relative used; `home()` fallback |
| LLR-172.1g (1738) | If the store folder is a link/junction, no write | UW | 0 files in the junction target | no reparse check |
| LLR-172.1h (1748) | Unique staging name, one-step replace | U | 100 writes → 100 names, 100 `os.replace`, 0 left; a read after each parses v1, 0 partial (corrected at close, R15) | fixed name; in-place write |
| LLR-172.1i (1758) | If the store write fails, the load completes, store as it was | UW | 2 injected × 2 kinds → 4 of 4 installed, 0 raises, digest same | `OSError` let out |
| LLR-172.1j (1768) | Record writes back only entries the read accepts | E | 2 ok + 3 refused → 3, 0 refused; broken store → 1 | raw carry-forward |
| LLR-172.2 (1778) | Read returns accepted entries in order, at most 20 | E | 1 000 → first 20; 5 among refused → 5 in order | no cap; sorted |
| LLR-172.2a (1788) | If > 65 536 bytes, no entries, `too large` | UW | 65 536 parsed; 65 537 → 0 + `too large`; 1 read ≤ 65 537 | no cap; `>=`; stat + full read |
| LLR-172.2b (1798) | If not a v1 object with `sources` list, no entries | UW | 5 shapes → 0, 0 raises | no shape check; any version |
| LLR-172.2c (1808) | If unreadable, no entries, `could not be read` | UW | 2 arms → 0 + problem | no catch; problem `None` |
| LLR-172.2d (1818) | If missing or no usable variable, no entries, no problem | UW | 2 arms → (0, `None`), 0 created | problem set; raises |
| LLR-172.2e (1828) | If not drive-rooted, drop | UW | 6 forms → 0; `C:\x\a.s19` kept | S-07 probe (UNC absolute) |
| LLR-172.2f (1838) | If a component is a device name, drop | UW | 3 → 0; `console` kept | last component only |
| LLR-172.2g (1848) | If a control character, drop | UW | 4 → 0 | NUL only (S-06) |
| LLR-172.2h (1858) | If kind ≠ suffix's kind, drop | UW | 5 → 0; `A.SREC` kept | no kind/suffix compare |
| LLR-172.2i (1868) | If not an object with string `path` and `kind`, drop | UW | 4 malformed → 0, 2 kept, 0 raises | no type check |
| LLR-172.2j (1878) | Every store read returns without raising | U | hostile set + 200 random → 0 raises | no decode guard |
| LLR-172.3 (1888) | Never copy a store entry into a file under the base folder | U | marker arm 1 (log incl.) → 0; arm 2 (log excl.) → 0 | manifest carries recents → 3 (base passes, declared) |
| LLR-172.4 (1898) | One function enumerates the temp folder | U | census → 1, in `workspace.py`, 0 in `app.py` | base: `app.py:7313` → RED; second enumeration |
| LLR-172.4a (1908) | Refresh shows one row per regular file, sorted | E | 3 rows sorted, 0 diffs; `.staging`, `sub/` → 0; empty → 0 | recursive; unsorted |
| LLR-172.4b (1918) | If a temp entry is a link, not listed | UW | file link → 0 rows ("not run" if no link can be made) | base `is_file()` follows the link |
| LLR-172.4c (1928) | If temp missing/unlistable, empty list | UW | 2 arms → 0 rows, 0 raises | no catch (base passes arm 1, declared) |
| LLR-172.5 (1938) | When the typed path names a project folder here, load it | E | 3 spellings → 3 loads of `ab` | probe → RED |
| LLR-172.5a (1948) | When the typed path names its `project.json`, load it | E | 2 loads; `ab/flows/project.json` → `not a project` | probe → RED |
| LLR-172.5b (1958) | If a typed folder inside is not a project, `not a project` | UW | 6 arms (3 reserved, empty, sub-folder, work area) → 0 loads, 1 line each | probe; S-01 probe |
| LLR-172.5c (1968) | If a typed folder (or its `project.json`) is outside, `outside the work area` | UW | 4 arms → 0 loads, 1 line each | code read; load-any-manifest mutant |
| LLR-172.5d (1978) | If a typed folder path passes a link/junction, `link or junction` | UW | 3 arms → 0 loads, 0 resets | code read; resolve-first mutant |
| LLR-172.5e (1988) | If no/unsupported suffix, `not a supported file` | UW | 3 arms → 0 loads, 0 copies | code read |
| LLR-172.5f (1998) | If the typed path does not exist, `not found` + `check the path` | UW | 2 arms → 0 loads | code read (no `check the path`) |
| LLR-172.5g (2008) | If a project load names a folder the project list does not list, refuse (S-01) | UW | 6 names → 0 loads, 0 resets, 0 writes; `AB` → 1 load (corrected at close, R15) | probe: `temp` loads → RED |
| LLR-172.6 (2018) | Paint Workarea Files names with no markup, no control chars | U | 4 rows literal, 0 spans | probe → RED |
| LLR-172.6a (2028) | A picked row loads the exact on-disk name | E | 2 of 2 names loaded | painted-name mutant (base passes, declared) |

| AT / TC | Owner | 9a share |
|---|---|---|
| AT-B100-12 | HLR-172 (store half), HLR-172a (typed half) | written at 9a: outside load → per-user store → typed `ab` path → project loaded |
| AT-B100-13 | HLR-172b | written at 9a |
| TC-B100-34 | LLR-172.1, LLR-172.1a … LLR-172.1j | full |
| TC-B100-35 | LLR-172.2, LLR-172.2a … LLR-172.2j | full |
| TC-B100-36 | LLR-172.3 | full |
| TC-B100-37 | LLR-172.4, LLR-172.4a, LLR-172.4b, LLR-172.4c | 9a; the dialog's files section is 9b (LLR-173.4) |
| TC-B100-38 | LLR-172.5, LLR-172.5a … LLR-172.5h (corrected at close, R15) | 9a (status line); `#load_reason` is 9b (LLR-173.5) |
| TC-B100-39 | LLR-172.6, LLR-172.6a | full |

29148 check: every requirement above is singular (one "shall", checked by script), states a numeric threshold and a negative control, and names functions only in its trace. Declared exceptions:
- LLR-172.4b depends on the platform allowing a file symbolic link (a test that cannot create one counts as not run, never passed).
- LLR-172.3, LLR-172.4c and LLR-172.6a hold on `4fef292`; each RED is a mutation.
- LLR-172.1, LLR-172.5c … LLR-172.5f base controls are code reads, not executed runs.

## 2 · Defects fixed in place

| Defect | Where |
|---|---|
| HLR-172 compound (6 "shall"s, 3 behaviours, 2 ATs) | split into HLR-172, HLR-172a, HLR-172b |
| "loads successfully" (HLR) vs "after a successful copy" (LLR-172.1) | copy kept (Q1) |
| LLR-172.3's threshold infeasible: the log under `.s19tool/logs/` records the load's own source path | two marker arms (store entries never loaded, log included; loaded path, log excluded) |
| LLR-172.4's census passed on base (1 enumeration already) | arm "in `workspace.py`, 0 in `app.py`"; base `app.py:7313` → RED |
| LLR-171.4e pointed to LLR-172.5 for a typed link arm that LLR-172.5 did not state | LLR-172.5d |
| LLR-173.5 points to LLR-172.5 for a missing typed path that LLR-172.5 did not state | LLR-172.5f (LLR-173.5's text left for 9b E1, §5) |
| Undefined: kind mapping, de-dup case/position, empty or relative `LOCALAPPDATA`, store write failure, record over a broken store, unreadable / missing store outcome, unlistable temp, picked row vs scrubbed label | LLR-172.1a, .1b, .1f, .1i, .1j, .2c, .2d, .4c, .6a |
| Stale citations `app.py:6543`, `:6559`, `:8658`, `:8710`, `:8789` | by symbol; `app.py:7313`, `:7316` where a line is load-bearing; P-24 gains its `4fef292` lines |
| "2 concurrent writers → a valid file" cannot fail deterministically | LLR-172.1h measured by distinct staging names |

## 3 · Slice for E2

Names come from the requirements and the code at `4fef292`. **(guess)** marks a node the requirements imply but do not name; it may end up inline. Sources: `workspace.py`, `app.py` (§5.5 row 9a: 2 files). Tests: `tests/test_b100_recents.py` (new), `tests/conftest.py` (the autouse `LOCALAPPDATA` fixture and the real-store guard).

### `workspace.py` — 0 changed + 4 new (+2 guesses)

| # | Node | What | Requirement |
|---|---|---|---|
| N1 | `recent_store_path() -> Optional[Path]` | `%LOCALAPPDATA%\s19_app\recent_sources.json`; `None` when the variable is unset, empty or not drive-rooted | 172.1, .1f, .2d |
| N2 | `record_recent_source(path) -> bool` | sanitised read (N3) + new entry first, de-dup by `normcase(resolve())`, cap 20, link check on the folder, `mkstemp` + `os.replace`, never raises | 172.1a, .1b, .1c, .1g, .1h, .1i, .1j |
| N3 | `read_recent_sources() -> RecentSources` + `RecentSources(entries, problem)` | bounded read, shape check, entry checks, never raises | 172.2 … .2j |
| N4 | `list_workarea_files(workarea) -> list[Path]` | regular, non-link direct children of `temp/`, sorted; missing/unlistable → `[]` | 172.4, .4a, .4b, .4c |
| G1 | `recent_kind(path) -> Optional[str]` (guess) | the suffix → kind map, shared by N2 and N3 | 172.1a, .2h |
| G2 | `_recent_entry_ok(entry) -> bool` (guess) | the five entry checks | 172.2e … .2i |

Unchanged context: `_is_reparse_point` (`:207`), `contained_in_workarea` (`:618`), `is_windows_device_name` (`:1833`), `resolve_input_path` (`:2020`), `RESERVED_WORKAREA_HOMES` (`:43`), the extension sets (`:107-110`), `WORKAREA_TEMP` (`:23`), `WORKAREA_STAGING_DIRNAME` (`:27`).

### `app.py` — 5 changed (+1 guess)

| # | Node (line at `4fef292`) | What changes | Requirement |
|---|---|---|---|
| 1 | `S19TuiApp.refresh_files` (7300) | rows from `list_workarea_files`; label `safe_text(name)`; `item.data` keeps the on-disk name | 172.4, .4a, .4c, .6, .6a |
| 2 | `S19TuiApp.load_from_path` (12767) | after `copy_into_workarea` succeeds, `record_recent_source(normalized)` when the source is outside the work area | 172.1a, .1d, .1e, .1i |
| 3 | `S19TuiApp.load_a2l_from_path` (12846) | same, after its copy | 172.1a, .1d, .1e, .1i |
| 4 | `S19TuiApp._load_path_from_user_input` (12715) | typed routing: lexical normalisation, work-area match under any case spelling, link check before any resolve (`_project_folder_refusal`), project folder / `project.json` → project load (Q3); the five token pairs | 172.5 … .5f |
| 5 | `S19TuiApp._handle_load_project` (11670) | refuses a name the project list does not list, after `_project_folder_refusal` (corrected at close, R15) | 172.5g |
| G3 | `_typed_project_target(path)` (guess) | typed path → (project name, or a refusal reason) | 172.5 … .5d |

Callers checked:
- `_load_path_from_user_input` ← `_handle_load_dialog` (12731, via `call_after_refresh`), `on_mount` (7189, the startup `load_path` at 7226).
- `load_from_path` ← `_load_path_from_user_input` (12726), `_handle_select_variant` (7553; call at 7606: a project variant, inside the work area → not recorded).
- `load_a2l_from_path` ← `_load_path_from_user_input` (12724), `_load_from_item` (13081; call at 13089: a work copy, inside → not recorded).
- `refresh_files` ← `on_mount` (7193), `action_refresh_files` (7322), `_handle_save_dialog` (9442; call at 10596), `load_from_path` (12834), `load_a2l_from_path` (12890).
- `_handle_load_project` ← `_route_load_project` (7444; call at 7473) and 20 test files (§5.4 reverse census).

Unchanged context: `list_projects` (12057), `_project_folder_refusal` (12116), `_route_load_project` (7444), `_load_from_item` (13081). No test pins `Unsupported file type` or `File not found:` (`grep -rn` over `tests/` → 0 hits), so the new token lines re-pin nothing.

**Node count:**
- **Firm: 9.** `workspace.py` 4 new functions (+1 data type); `app.py` 5 changed functions.
- **With the guesses: up to 12.**
- That is above ~8, so E2 runs by file group:
  - G1 `workspace.py` (4–6 nodes).
  - G2 `app.py` (5–6 nodes).
- **Source files:** 2, within the cap of 4.

**Seams to fix before E2 (G1 ↔ G2):**
- `record_recent_source`'s inputs: the resolved source path only, or path plus kind (kind from G1 inside the workspace).
- `recent_store_path()` returning `None` versus raising when the variable is unusable (the requirements need `None` + no write).
- `list_workarea_files` returns `Path`s or names (row `data` is the name).
- who owns the "inside the work area" test for recording (the caller in `app.py`, with `contained_in_workarea`, or `record_recent_source` given the work area).

## 4 · Open questions for the orchestrator

The requirement text follows each recommendation; a different ruling changes the named ids.

- **Q1 — when is a source recorded?** The old HLR said "loads successfully"; LLR-172.1 said "after a successful copy". **Recommendation: after the copy into `temp/`** (as written in LLR-172.1a / .1d). It keeps the record in `load_from_path` and `load_a2l_from_path`, so the source path does not need to travel to the worker's install. A file that copies and then fails to parse is recorded; picking it again at 9b fails again with the parse error. The alternative (record on install) adds `_start_load_worker` and `_apply_prepared_load` to the slice.
- **Q2 — the startup path.** `S19TuiApp(load_path=…)` runs `_load_path_from_user_input` from `on_mount` (7226), so a command-line load of an outside file is recorded too. **Recommendation: yes, record it** (same route, no special case).
- **Q3 — the typed project load route.** **Recommendation: route through `_route_load_project`**, so a typed project load opens the Load-result panel as a picked one does (LLR-178.3). AT-B100-12 then closes the panel (`LOAD_RESULT_CLOSE`). The alternative, a bare `_handle_load_project`, makes the two routes differ.
- **Q4 — a bare relative name (`ab`).** `resolve_input_path` tries the process folder, the base folder and the repo root, never the work area. **Recommendation: no work-area lookup at 9a;** the AT types the absolute work-area path. 9b's list is the way to pick a project by name.
- **Q5 — a failed store write.** **Recommendation: 1 log warning, 0 status lines** (LLR-172.1i). The store is a convenience; the load's own status stays.
- **Q6 — the unreadable-store problem word.** **Recommendation: `could not be read`** (LLR-172.2c), the token the 8b E5 F7 rows already use, so 9b can paint it in the recents section.
- **Q7 — tokens.** **Recommendation: no new §3 row.** Every 9a refusal reuses a pair: `not found` / `not a supported file` + `check the path`; `not a project` + `pick a project in the list` (typed reserved homes and the project-load refusal); `outside the work area` + `copy the folder into the work area`; `link or junction` + `pick a project in the list`. Two rows now name the 9a ids.
- **Q8 — AT-B100-12 under two HLRs.** It is one output-then-consume chain (load → store → typed path). **Recommendation: keep one AT under HLR-172 (store half) and HLR-172a (typed half); mint no new AT id.**
- **Q9 — an empty folder.** §1.3 says a project holds a `project.json`, a data file or an A2L. `list_projects` (12057) lists any plain folder, an empty one included. **Recommendation: a typed empty folder gives `not a project`** (LLR-172.5b, as the old LLR-172.5 threshold said); `list_projects` stays unchanged at 9a, and 9b's LLR-173.4 decides its rows.

## 5 · Observations

- LLR-173.5 (9b) still says "the matching tokens (LLR-172.5)"; its tokens are now LLR-172.5b … LLR-172.5f. 9b's E1 should repoint it.
- §6.3's privacy bullet cites `app.py:10820-10825` for the paths the log holds (a `1d677ba` line); at `4fef292` `load_from_path` logs the source at `copy_started` (12808). Out of 9a scope; left as written.
- The FLOW block `load_source_to_load_dialog` keeps the parent ids as owners (as 8b did); V22 reports the split ids as never-owner notices, not blocks.
- In 9a a typed refusal paints a status line: the current Load dialog has already closed. Keeping the dialog open with `#load_reason` is 9b (LLR-173.5).
- `screens.py:712` (the Load project list) still builds `Label(name)` with markup on. That is LLR-173.3, at 9b.
