# Design proposal — s19_app — Batch 2026-10-26-batch-100

> Authored between P2 and PDR, against the contract approved at P2 (`9469b81`), with the PDR conditions applied as LED-2026-10-26-batch-100.24 to .34. It is staged here; its canonical home is the vault (`artifact_homes.design_pdr`), published by `/dev-flow-sync`.

| Field | Value |
|---|---|
| Id | `PDR-2026-10-26-batch-100` |
| Requirements covered | HLR-163 to HLR-178 with their 74 LLRs (US-153 to US-168), as of LED-2026-10-26-batch-100.34 |
| Modules touched (from `docs/ARCHITECTURE.md` §10 batch-100 declarations) | workspace (`tui/workspace.py`); services (`change_service.py`, `manifest_writer.py`, `variant_execution_service.py`, `project_gather_service.py`); screens (`app.py`, `screens.py`, `screens_directionb.py`, `styles.tcss`); split/join (`segment_split_view.py`); tests (`tests/test_b100_*.py`, `tests/support/b100_*.py`). No frozen-engine file (§7 of the map) is touched |
| Triggers that fired | A2 · A3 · B1 · B4 · C6 · C8 · D1 · E1 · E2 |
| Author / reviewers | orchestrator-delegated author · `architect` · `qa-reviewer` · `ux-reviewer` (D1 fired) · `security-reviewer` (family C fired) |

## 1 · Objective and scope

A project restores what the session held, or the load names what it could not restore. One Load dialog offers what is already loaded and opens projects, no unsaved work is replaced without a question, and long actions show real progress. The scope is the approved contract: PH-1, PH-2, PH-4, PH-5, M-1..M-7, L-2..L-4, G-005, CW-U-2/5/12/13, the reserved and device names, N5 and the P-E panel, with every prototype slot filled by the operator's verdict.

**Out of scope:**
- the three writers that bypass the manifest writer (A-01): reported as `not recorded`, routed to `BACKLOG-CODE.md`;
- the two older device-name lists (B-12): in the backlog;
- flow runs and the A2L tag-table build, which stay on the main thread;
- no new module and no boundary move (A1 not fired).

## 2 · Modules and boundaries

| Module | What it owns here | What it exposes | What it must NOT reach into |
|---|---|---|---|
| workspace `workspace.py` | the one placement (`find_identical`, `place_into_workarea`, `predict_placement`), this-work-area containment, the name rules (`PROJECT_NAME_MAX_CHARS`, `is_windows_device_name`), the per-user recent store, the work-area lister | `PlacementResult`; `copy_into_workarea` (unchanged `Path` return); `contained_in_workarea`; `recent_store_path`, `record_recent_source`, `read_recent_sources`; `list_workarea_files` | the app's session state |
| services `change_service.py` | the `save_patched` split; the unsaved-state record; the `image_differs_from_source` fast path | `rederive_for_save`, `emit_and_verify`, `save_patched` (their composition), `mark_saved`, `differs_from_last_saved` | the screens; the manifest |
| services `manifest_writer.py` | the envelope (`files`, `active_document`, `derived_from`); `check_project_files`; private staging; the verify drift domain; containment of the seam | `serialize_manifest`, `write_project_manifest`, `verify_written_manifest`, `check_project_files`, `file_record` | image parsers (A-05: `not readable` comes from the app) |
| services `variant_execution_service.py` | the reader's caps, the manifest-keys path mode, `compose_load_announcement` | `read_project_manifest`, `ProjectManifest` (+ `gathered`, `files`, `active_document`, `derived_from`) | the screens |
| services `project_gather_service.py` | the pure save plan; placing the gathered documents; save-as sub-folders | `plan_project_save` → `SavePlan` (frozen); `gather_project_artifacts` | `change_service` / `changes` (no new import edge; the digests are passed in) |
| screens `app.py` | every handler and seam: Save project, Load project, the reset, the focus targets, the one load seam, `choose_install_set`, the busy seam, the workers | painted text and the status log | service internals beyond their public results |
| screens `screens.py`, `styles.tcss` | the Load dialog (`pa_C` ids), the confirm modal (`pb_A`), the Save dialog (`pc_B`), the Load-result panel (`pe_B`) | `LoadChoice`; `SaveProjectScreen.plan` (read-only, immutable) | placement and listing functions (the Save dialog paints the plan only) |
| screens `screens_directionb.py` | a public read-only reader of the Patch Editor panel's dirty flag | that reader | nothing else changes |
| split/join `segment_split_view.py` | the export's status word from `PlacementResult` | export results | its own byte-identity rule (removed) |

Boundaries respected as declared in `docs/ARCHITECTURE.md` §10 and §11: ✓. No module is created and no boundary moves. The new import edges are `app → workspace` names that already exist; `project_gather_service` gains none.

## 3 · Diagrams

**Save project, one call (Inc 5, extended at 7, 8a, 8b, 11, 12):**

```
dialog open ──► first frame painted ──► worker: image digest + copied-file digests (once)
name typed ──(150 ms debounce)──► plan_project_save(names, digests, …) ──► SavePlan (frozen) ──► #save_summary
alt+s ──► refusal?  ──yes──► tokens painted, 0 files
        │ no
        ▼
main thread: rederive_for_save(copy) ──► data differs from source?  (pre-check true = start at once; never "copy" alone)
        │ yes: apply re-derived image to the view in place         │ no: byte copy of the source
        ▼                                                          ▼
worker: emit_and_verify → save_patched_image → copy_into_workarea → place_into_workarea (containment, staging, reuse/_N)
        │ each landed PlacementResult == planned row?  no → error naming both paths
        ▼
MAC / A2L / document / sub-folders → place_into_workarea      manifest seam → write_project_manifest (contained_in_workarea, private staging)
        ▼
mark_saved (service + Patch Editor panel); derived_from recorded (Inc 7); status: N entries, K applied by this save
```

**Every image-replacing route through one seam (Inc 10):**

```
Load dialog (LoadChoice) ─┐
Workarea Files pick ──────┤
v / panel v (variant) ────┼──► _confirm_then_load(kind, go)
project load (dialog) ────┘        │ worker running?  → `busy` refusal
                                   │ 24-cell guard: image replace asks iff D; attach never; project iff D|F|W
                                   ▼
                          question (pb_A, focus on No) ──n/esc──► unchanged
                                   │ y
                                   ▼
                          _reset_project_session (project only) → install
```

**Load project result (Inc 6 and 7):**

```
read_project_manifest (caps, manifest-keys mode) ─► check_project_files ─► install via choose_install_set
        │                                                 │                     │ not readable from the result
        ▼                                                 ▼                     ▼
compose_load_announcement ◄── one problem per file by precedence ◄─────────────┘
        ├─► status log: "<variant> opened (k of n) · N problems · details: p"
        ├─► end_busy final lines: outcome → project + file → file state
        └─► Load-result panel (focus on the list; Close (esc); v → variant selector)
```

## 4 · Interfaces that change — and which ones FREEZE

The map rows are in `docs/ARCHITECTURE.md` §11 (B100-I1..I22). Where a row and the contract differ, the contract's form is frozen and the architect updates the row at PDR (ARCH C-1..C-3, listed in §9).

| Interface | After | Consumers (measured) | LLR | **Frozen** |
|---|---|---|---|---|
| B100-I1 envelope | + `files`, `active_document`, `derived_from` (additive, `_reject_unsafe_entry`); verify drift domain includes all three | the seam; `test_manifest_writer.py` pins `:99`, `:216`, `:481` | 169.1, 169.3, 170.1, 168.4 | before Inc 7 (`files`, `derived_from`), Inc 8a (`active_document`) |
| B100-I2 reader | + `gathered`, `files`, `active_document`, `derived_from`; 1 MiB; 1 000 per array, `assignments` 1 000 in total and 1 000 keys | `_handle_load_project`, the verify re-read, `plan_variant_executions` | 168.1, 169.4, 170.1 | before Inc 6 (`gathered`), Inc 7, Inc 8a |
| B100-I3 `check_project_files` | manifest and disk problems; never parses images | `_handle_load_project`, the Load-dialog preview | 169.5, 169.9 | before Inc 7 |
| B100-I4 reset seam | S1–S13 + the 11 probe names; rebind of the service | `_handle_load_project` | 165.1, 165.3 | before Inc 3 |
| B100-I5 `image_differs_from_source` | a fast path into the data comparison only; never decides copy | `_handle_save_dialog` | 167.1 | before Inc 5 |
| B100-I6 reuse rule | in `find_identical`; `copy_into_workarea` = `place_into_workarea(...).path` | 15 call sites in 7 files (unchanged) | 163.1 | before Inc 1 |
| B100-I7 manifest seam | every writer carries every key it does not own, project-relative | Save project, save-back, the variant append, the MAC/A2L syncs | 168.2, 168.3 | before Inc 6 |
| B100-I8 Load dialog result | `LoadChoice(kind, value)`; `pa_C` ids; `p` opens it; `LoadProjectScreen` retires | the router; `test_tui_app.py:1254`, `:1288` (`Path` kept) | 173.1, 173.2 | before Inc 9b |
| B100-I9 recent store | `%LOCALAPPDATA%\s19_app\recent_sources.json`; `RecentSources(entries, problem)` | `load_from_path`, `load_a2l_from_path`, the dialog | 172.1, 172.2 | before Inc 9a |
| B100-I10 `SaveProjectPayload.parent_folder` | must resolve to this work area | `_handle_save_dialog` | 171.3 | before Inc 8b |
| B100-I11 name rules | 64; the path limit; device names raw + sanitised; reserved case-folded | the handler, `list_projects`, the summary | 164.1, 164.3 | before Inc 2 |
| B100-I12 busy seam | `begin_busy(key, label, steps)` / `step_busy(key, text, done, total)` / `end_busy(key, outcome, final_lines)`; one owner of `#status_text` | the 24 `set_progress` sites | 176.1, 176.2 | before Inc 12a |
| B100-I13 placement | `find_identical`, `place_into_workarea → PlacementResult` | every placement | 163.1 | before Inc 1 |
| B100-I14 containment | `contained_in_workarea`, inside the placement and the manifest seam | all writers; `list_projects`; `_handle_load_project` | 171.4 | before Inc 1 |
| B100-I15 `save_patched` split | `rederive_for_save(copy) -> (map, summary)`, `emit_and_verify(map, ranges, …)` (contract form, ARCH C-1) | Save project, the save-back, the Inc 12 worker | 167.7 | before Inc 5 |
| B100-I16 `derived_from` | name, SHA-256 and byte count, computed at the write (contract form, ARCH C-3) | the panel, the composer, the rewrites | 168.4 | before Inc 7 |
| B100-I17 save plan | `plan_project_save → SavePlan` (frozen); rows at plan granularity | the handler, the Save dialog, AT-B100-21 | 167.6, 175.4 | before Inc 5 |
| B100-I18 unsaved predicate | `mark_saved`, `differs_from_last_saved` | the guard, the summary's pending line | 167.5 | before Inc 5 |
| B100-I19 `_session_snapshot` | the normalised projection | TC-B100-09, TC-B100-53 | 165.2 | before Inc 3 |
| B100-I20 one load seam | `_confirm_then_load(kind, go)` | the four routes | 174.4 | before Inc 10 |
| B100-I21 manifest-keys mode | the tightened path mode, reader and writer only | `read_project_manifest`, `_reject_unsafe_entry`; flow callers keep the default | 169.8 | before Inc 7 |
| B100-I22 `predict_placement` | `(digest_or_bytes, size, destination, name)` (contract form, ARCH C-2) | the save plan | 163.7 | before Inc 1 |

No fork, so no lane freeze; each row freezes at the point named, and changing one afterwards is trigger A3.

## 5 · Proposed test cases

Every TC and AT is specified in `01-requirements.md` §3–§4 with its threshold and Negative control. This section groups them by increment and names, for each, the mutation that turns it RED, declared at authoring time. Test files are `tests/test_b100_<topic>.py` (one per HLR, named in each LLR's Executed verification), with the helpers below. Each mutation is applied in the increment's own worktree and restored, with the file's hash checked, before the next gate (C-40).

**Enablers (design enablers for Phase 3 and validation):**
- **E1** `tests/support/b100_links.py` (NEW): `make_junction(link, target)` (a Windows junction, or a directory symlink elsewhere) and `make_file_link`. Used for the junction arms of LLR-163.1, 171.1 and 171.4, and for AT-B100-11.
- **E2** hostile names, created on disk at test time: `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19`, `a\x9bb.s19`, and the folder `[b]P`. Each exists on NTFS and paints a span with markup on (QA-02, S-13 probes).
- **E3** the two distinct `firmware.s19` sources: `examples/case_01_basic_valid`, `examples/case_02_gaps_and_patch_targets`.
- **E4** `tests/support/b100_projects.py` (NEW): builders for P1 (S19 + MAC + A2L), P2 (`prg.s19`), the `p02` A/B save-backs, the `p04` cases 2/5/6/7/9/10, a legacy project, a hand-copied variant, `p06` A/C, and a project holding the case_06 A2L.
- **E5** `LOCALAPPDATA` pointed at `tmp_path` by `monkeypatch`.
- **E6** the large-A2L fixture `examples/case_06_large_nested_a2l/firmware.a2l` (37 742 888 bytes, P-33): the slow black-box action for AT-B100-17/18 and the digest budget of LLR-175.4. No monkeypatch in an AT node.
- **E7** a check document (the TC-700 pattern, `kind: check`, one entry).
- **E8** `tests/support/b100_manifests.py` (NEW): 1 001-entry arrays, 75 × 1 000 `assignments`, a 1 MiB + 1 byte file, the hostile key set.
- **E9** `tests/support/b100_recents.py` (NEW): 1 000 distinct `C:\NNN.s19` entries, an exactly-65 536-byte file, the hostile entry set.
- **E10** an AT size helper: every UI AT runs at `(118, 54)` and `(220, 60)` with `notifications=True`.
- **E11** `tests/support/independent_reader.py` (batch-99): the image-byte oracle.
- **E12** the Kimi brief common file: `PYTHONPATH=<worktree>`, an `s19_app.__file__` probe, `NO_COLOR` unset.
- **E13** a real-terminal capture script, kept outside `prototypes/` (C-UX-5): it opens Windows Terminal in truecolor with `NO_COLOR` unset, captures the app at 118×54, 220×60 and 99×54, and closes every window it opened. The Phase-4 inspection reads its PNGs.

**Per-increment SOURCE file sets** (ARQ §8 / §8.1, every conditional decided at PDR):

| Inc | SOURCE files | Count |
|---|---|---|
| 1 | `workspace.py`, `segment_split_view.py`, `app.py` | 3 |
| 2 | `app.py`, `workspace.py` | 2 |
| 3 | `app.py` | 1 |
| 4 | `app.py` | 1 |
| 5 | `app.py`, `services/change_service.py`, `services/project_gather_service.py` | 3 |
| 6 | `app.py`, `services/variant_execution_service.py`, `screens.py`, `styles.tcss` | 4 ⚠ at cap |
| 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` | 3 |
| 8a | `app.py`, `services/manifest_writer.py`, `services/variant_execution_service.py`, `services/project_gather_service.py` | 4 ⚠ at cap |
| 8b | `app.py`, `services/project_gather_service.py`, `workspace.py` | 3 |
| 9a | `workspace.py`, `app.py` | 2 |
| 9b | `screens.py`, `app.py`, `styles.tcss` | 3 |
| 10 | `screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py` | 4 ⚠ at cap |
| 11 | `screens.py`, `app.py`, `styles.tcss` | 3 |
| 12a + 12b | `app.py`, `styles.tcss`, `s19_app/tui/a2l.py` (named frozen-engine crossing, LLR-176.4) | 3 |

### 5.1 Inc 1 — one placement function, reuse, containment

**SOURCE files (3):** `workspace.py`, `segment_split_view.py`, `app.py` (paths under `s19_app/tui/`).

**Findings:** M-1, G-005. **Hard order:** first; Inc 6 relies on its reuse rule.
- **Design characteristics.**
  - `find_identical` lists the destination once. It filters `<name>` and `<stem>_<digits><suffix>` (case-folded on Windows) and checks size before reading bytes. Links, reparse points and 0-byte files are never reused.
  - `place_into_workarea` owns the whole placement: the source and destination reparse checks, `contained_in_workarea(destination, workarea)`, the 256 MiB cap, private staging, then reuse or the `O_EXCL` claim of the lowest free `_<N>`, then `os.replace`. It returns `PlacementResult(path, reused)`.
  - `copy_into_workarea` becomes the one line `return place_into_workarea(...).path`.
  - `predict_placement(digest_or_bytes, size, destination, name)` runs the same candidate walk and free-name walk with no staging and no claim.
  - The export takes its `reused` / `wrote` word from the `PlacementResult` it got back.
  - `_sync_loaded_file_to_project` names the existing variant when `reused` is true.
- **Interfaces:** freezes B100-I6 (as amended), B100-I13, B100-I14 and B100-I22 before this increment; consumes B99-I2.
- **Enablers:** E1 (`tests/support/b100_links.py`, junctions); E3 (two `firmware.s19` sources: `examples/case_01_basic_valid`, `examples/case_02_gaps_and_patch_targets`).
- **Re-pins in this increment:** `test_tc018_existing_name_is_dedup_suffixed`, `test_at031b_two_saves_are_distinct_no_clobber` and `test_tc_b99_31_changed_bytes_take_the_next_free_name`. Each is named old → new in the packet's reverse census.

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-163.1 One placement function holds every guard and decides reuse | TC-B100-01 | Inc 1 | executed on `1d677ba` (`ui_load_dialogs_probe` S7): `copy case_02 again -> firmware_2.s19` → RED. Mutation at Phase 3: restrict the comparison to the bare name → RED; move the size cap back into the wrapper only → the direct … |
| LLR-163.2 Size before bytes | TC-B100-02 | Inc 1 | a mutation removing the size check → 5 reads → RED. |
| LLR-163.3 G-005: the re-pinned expectations of TC-018 and AT-031b | re-pinned nodes: test_tc018_existing_name_is_dedup_suffixed, test_at031b_two_saves_are_distinct_no_clobber | Inc 1 | executed on `1d677ba` (P-7): the old single-arm expectations → `FF`. Mutation at Phase 3: disable the reuse → the identical arm of both → RED. |
| LLR-163.4 The one ripple re-pin | re-pinned node: test_tc_b99_31_changed_bytes_take_the_next_free_name; unchanged: test_tc_b99_31_bin_pair_placed_under_one_suffix (C-QA-8) | Inc 1 | a mutation disabling the reuse → the re-pinned arm sees `t_isle_2.s19` → RED. |
| LLR-163.5 No "added" status for a reused variant | TC-B100-03 | Inc 1 | a mutation always emitting the added-variant status → RED. |
| LLR-163.6 The export reports reuse from the placement it performed | TC-B100-57 | Inc 1 | a mutation restoring the requested-name-only check in the export → the `_1` arm reports `wrote` → RED. |
| LLR-163.7 `predict_placement` uses the placement code itself | TC-B100-68 | Inc 1 | a mutation giving the prediction its own free-name walk that skips directories → the directory arm predicts `firmware_1.s19` → RED. |
| LLR-171.4 Containment means this work area, checked inside the placement (S-02) | TC-B100-62 | Inc 1 (guard) / 7 (seam) / 8b (listing, load) | executed (S-02 probe): `_check_destination_contained PASSED (no raise)` and `copy_into_workarea WROTE …\other\.s19tool\workarea\target\src.s19` at `1d677ba` → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-01 | HLR-163 | executed on `1d677ba` (P-6): `firmware_2.s19 310 a9e114d56077` beside an identical `firmware_1` → AT-B100-01 is RED today. |

### 5.2 Inc 2 — Save project name guards

**SOURCE files (2):** `app.py`, `workspace.py` (paths under `s19_app/tui/`).

**Findings:** M-4 (Q-2), M-7 (Q-1), reserved and device names, L-3. **Hard order:** before Inc 11, whose summary uses these rules.
- **Design characteristics.**
  - One name check in `_handle_save_dialog` runs before any `mkdir`, in this order: the empty name; `is_windows_device_name` (NEW, `workspace.py`) on the raw and the sanitised name and on every component; the reserved homes, case-folded; the 64-character cap; the full-path limit (`len(workarea) + 1 + len(name) + 53 ≤ 259`); the disguised clash; and the link/junction target check before `resolve()`.
  - From the folder's creation on, the body runs under one `OSError` handler that calls `_remove_created_project_dir`.
  - An exact-name save into an existing project that is not open still adds a variant (LLR-005.1); its full merge carry arrives at Inc 8a.
  - `list_projects` filters reserved homes case-folded.
- **Interfaces:** freezes B100-I11 (as amended); consumes B100-I13.
- **Enablers:** a work-area base padded to length L = 150, for the path-limit arms.

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-164.1 Reserved homes and device names, compared case-folded | TC-B100-04 | Inc 2 | executed on `1d677ba` (P-14): `Splits` saved and listed → RED; (S-04) `CON` saved → RED; a mutation checking only the sanitised name → `con.txt` saved as `contxt` → RED. |
| LLR-164.2 Q-2: clash, merge and the open project | TC-B100-05 | Inc 2 (merge carry 8a) | executed on `1d677ba` (P-10): `'a b' -> project='ab'` saved silently → RED; a mutation passing the session's `batch` in the merge → the carried-key arm RED. |
| LLR-164.3 Name cap, path limit and `OSError` | TC-B100-06 | Inc 2 | executed on `1d677ba` (P-13): `RAISED FileNotFoundError` → RED. |
| LLR-164.4 A refused or failed save leaves no folder it created | TC-B100-07 | Inc 2 | a mutation deleting one removal call → the census names that exit → RED; S-05's executed probe (a 262-character path) → `FileNotFoundError` escapes and the folder stays → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-02 | HLR-164 | executed on `1d677ba` (P-14): `dialog Save 'reports' -> … Saved project` → AT-B100-02 is RED today. |

### 5.3 Inc 3 — a project load starts clean

**SOURCE files (1):** `app.py` (paths under `s19_app/tui/`).

**Finding:** PH-2. **Hard order:** before Inc 8a and Inc 10, which sit around the reset.
- **Design characteristics.**
  - `_reset_project_session()` is called once in `_handle_load_project`, after validation and before the first install. It resets rows S1–S13 of the ARQ inventory plus the 11 probe names, and rebinds a new `ChangeService` with the image generation re-pushed.
  - `_apply_unload("all" | "a2l")` clears `current_a2l_data`.
  - `_session_snapshot()` returns the normalised projection of every name the class's source assigns, derived by a census at test time, minus the declared exclusions.
- **Interfaces:** freezes B100-I4 and B100-I19.
- **Enablers:** E4 (projects P1 = case_01 S19 + MAC + A2L, and P2 = `prg.s19`; the `p03` scenario).

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-165.1 One reset seam, before the first install | TC-B100-08 | Inc 3 | a mutation moving the call after `load_selected_file` → the MAC merge sees the old file → RED. |
| LLR-165.2 The session snapshot, derived from the live app (C-31) | TC-B100-09 | Inc 3 | a code mutation dropping one reset line (`current_a2l_path`) → 1 differing name → RED; a set mutation dropping one census name without an exclusion → the classification arm RED; QA's probe without the stat-key normaliser → cold … |
| LLR-165.3 The change service is rebound | TC-B100-10 | Inc 3 | a mutation keeping the old object → 1 leaked entry → RED. |
| LLR-165.4 Unload clears the parsed A2L | TC-B100-11 | Inc 3 | today's code (P-25, no clearing writer) → the tags survive → RED (repro planned at Phase 3). |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-03 | HLR-165 | executed on `1d677ba` (P-2): `P2 files after re-save: ['firmware.a2l', 'firmware.mac', 'prg.s19', 'project.json']` → AT-B100-03 is RED today. |

### 5.4 Inc 4 — focus after a load

**SOURCE files (1):** `app.py` (paths under `s19_app/tui/`).

**Finding:** CW-U-2.
- **Design characteristics.**
  - A per-window focus-target table lives in `app.py`. It is derived from the window registry and asserted against it, and it never names an `Input` or `TextArea`.
  - `_step_finalize` and the A2L load tail re-home the focus when the focused widget has region area 0, sits in a window that is not displayed, or is a text input.
  - The modal-close arms come later: the panel at Inc 6, the dialog at Inc 9b, the question at Inc 10 (ARQ §8.1).
- **Interfaces:** none frozen.
- **Enablers:** none new.

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-166.1 The load tails and the modal closes put the focus on the window's target | TC-B100-12 | Inc 4 (closes 6, 9b, 10) | executed on `1d677ba` (P-16): `focused region area: 0` → RED. |
| LLR-166.2 The A2L load tail re-homes the focus | TC-B100-13 | Inc 4 | a mutation removing the re-home from the A2L tail → area 0 → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-04 | HLR-166 | executed on `1d677ba` (P-16): `focused region area: 0`, `` `p` -> Screen `` → AT-B100-04 is RED today. |

### 5.5 Inc 5 — Save project: the split, the emit decision, the plan

**SOURCE files (3):** `app.py`, `services/change_service.py`, `services/project_gather_service.py` (paths under `s19_app/tui/`).

**Findings:** PH-1, D1, R-PC. **Hard order:** before Inc 10 and Inc 11, which use the unsaved predicate and the plan.
- **Design characteristics.**
  - **The `save_patched` split:**
    - `rederive_for_save(copy)` restores the journal on a copy and applies the current **change** document onto it, never touching the session map;
    - `emit_and_verify(map, ranges, …)` places through `save_patched_image` → `copy_into_workarea` and verifies;
    - `save_patched` is their composition plus the in-place view update, so B99-I7 is unchanged.
  - **The emit decision:** re-derive onto a copy, then compare data. The `image_differs_from_source` pre-check only starts that comparison early and never decides copy. A check document never counts and is gathered into `checks/`.
  - **The saved-state record:** `mark_saved` / `differs_from_last_saved` are recorded at load, save-back and Save project. Save project also calls the panel's `mark_saved`.
  - **The save plan:** `plan_project_save(...) -> SavePlan`, a frozen dataclass with rows at plan granularity, landing names from `predict_placement` and action words. It is fed the image digest and the copied-file digests the app computed once per open, so `project_gather_service` gains no `changes` import. `_handle_save_dialog` executes the plan, and checks each landed `PlacementResult` against its row (a mismatch is an error naming both paths).
- **Interfaces:** freezes B100-I5 (as a fast path only), B100-I15, B100-I17 and B100-I18; consumes B100-I13 and B100-I22.
- **Enablers:** E7 (a check document, the TC-700 pattern); E11 (`tests/support/independent_reader.py`, from batch-99).

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-167.1 The emit decision is made on data | TC-B100-14 | Inc 5 | the round-2 rule (emit when the document holds any entry) → the check-document arm emits and is refused (P-37), and the same-byte arm emits a byte-different file (P-38) → RED. |
| LLR-167.2 Save project emits through the split or copies the source | TC-B100-15 | Inc 5 | executed on `1d677ba` (P-1): `== in-memory patched image? False` → RED; a mutation deciding emit-or-copy on `differs_from_last_saved` → the save-back-then-Save arm copies the unpatched source → RED (A-08). |
| LLR-167.3 The status names the entries the image carries | TC-B100-16 | Inc 5 | a mutation dropping the suffix → 0 counts → RED. |
| LLR-167.4 A blocked re-derive refuses the whole save | TC-B100-17 | Inc 5 | a mutation ignoring `ok=False` → a manifest is written → RED. |
| LLR-167.5 The unsaved predicate and the saved-state record | TC-B100-58 | Inc 5 | a mutation calling `mark_saved` on the save-back path only → the Save project arm stays True → RED. |
| LLR-167.6 One save plan, painted and executed (R-PC) | TC-B100-59 | Inc 5 (rows 7, 8a, 8b) | a mutation where the handler places a file the plan did not name → 1 tree row without a plan row → RED. |
| LLR-167.7 `save_patched` split into re-derive and emit-and-verify | TC-B100-69 | Inc 5 | a mutation where `rederive_for_save` writes the session map → the 0-writes arm RED. |
| LLR-167.8 Save project clears the Patch Editor's dirty flag | TC-B100-70 | Inc 5 | a mutation skipping the panel's `mark_saved` → the load asks → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-05 | HLR-167 | executed on `1d677ba` (P-1): `project firmware.s19 == in-memory patched image? False` → AT-B100-05 is RED today. |

### 5.6 Inc 6 — save-back active variant, manifest carry, the Load-result panel

**SOURCE files (4):** `app.py`, `services/variant_execution_service.py`, `screens.py`, `styles.tcss` (paths under `s19_app/tui/`).

**Findings:** PH-4, D2, O-1, P-E (panel). **Hard order:** after Inc 1; before Inc 7.
- **Design characteristics.**
  - The reader parses `gathered`.
  - The save-back sets the active variant in the session and in `project.json`.
  - The variant append and the MAC and A2L syncs place through `place_into_workarea`, then rewrite through `_write_and_verify_manifest`, carrying every key they do not own, converted from the reader's absolute paths back to project-relative POSIX strings.
  - `compose_load_announcement` (pure, `variant_execution_service.py`).
  - The Load-result panel (`screens.py`) on the `pe_B` ids:
    - the focus starts on the problem list;
    - `#result_ok` is labelled "Close (esc)";
    - `escape` dismisses it from anywhere, and `enter` only on the button;
    - `v` runs `select_variant`.
  - The panel's "patched" line against `derived_from` arrives at Inc 7.
- **Interfaces:** freezes B100-I2 (`gathered`) and B100-I7; consumes B100-I13.
- **Enablers:** E4 (`p02` A/B projects with the default and the `_1` save-back names).
- **⚠ Exactly 4 SOURCE files** (`app.py`, `variant_execution_service.py`, `screens.py`, `styles.tcss`). It cannot be cut: the panel is a new screen with its own layout rules, which live in `styles.tcss` by the project's convention; the composer belongs to the manifest reader's module; and the writers and the push sit in `app.py`. Moving the panel to Inc 7 would make Inc 7 five files.

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-168.1 The reader parses `gathered` | TC-B100-18 | Inc 6 | a mutation ignoring the key → the rewrite drops `gathered` → RED in TC-B100-20. |
| LLR-168.2 The save-back becomes the active variant | TC-B100-19 | Inc 6 | executed on `1d677ba` (P-3): `active_variant 'firmware'` → RED. |
| LLR-168.3 Every in-project writer rewrites the manifest, carrying every key it does not own | TC-B100-20 | Inc 6 | a mutation removing the seam call from the variant append → `active_variant` stale → RED; a mutation passing the reader's absolute `batch` → `serialize_manifest` refuses and no manifest is written (A-03 probe) → RED. |
| LLR-178.1 The announcement composer | TC-B100-55 | Inc 6 | a mutation reporting "recorded active" for the fallback case → RED; a mutation comparing with the first variant by name → the `firmware-patched.s19` arm compares the image with itself (P-39) → RED. |
| LLR-178.2 The summary line and the final `#status_text` | TC-B100-56 | Inc 6 | a mutation painting with markup on → 1 span → RED. |
| LLR-178.3 The Load-result panel, reachable by keyboard | TC-B100-67 | Inc 6 | a mutation starting the focus on `#result_ok` → the immediate `enter` closes the panel unread → RED; a mutation truncating the list at 10 rows → 20 missing → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-06 | HLR-168 | executed on `1d677ba` (P-3): `RELOAD -> file=firmware.s19 … image_is_patched=False` → AT-B100-06 is RED today; A-03's executed carry probe (`serialize_manifest` refuses the reader's absolute `batch`) → AT-B100-20 RED for a carry … |
| AT-B100-20 | HLR-168 | executed on `1d677ba` (P-3): `RELOAD -> file=firmware.s19 … image_is_patched=False` → AT-B100-06 is RED today; A-03's executed carry probe (`serialize_manifest` refuses the reader's absolute `batch`) → AT-B100-20 RED for a carry … |
| AT-B100-19 | HLR-178 | executed on `1d677ba` (P-3): the reload status is `Loaded project 'P' -> firmware.s19`, with no panel, no count and no reason → AT-B100-19 RED today; P-39: a composer comparing with the first variant by name says "identical" for … |

### 5.7 Inc 7 — digests, problems, caps, `derived_from`

**SOURCE files (3):** `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` (paths under `s19_app/tui/`).

**Findings:** PH-5, L-4, D3, O-2, O-11, UX-26.
- **Design characteristics.**
  - `files` (size + streamed SHA-256) is computed by the seam from disk, over the top-level data and A2L files.
  - The reader enforces the caps: 1 MiB; 1 000 entries in each array; `assignments` 1 000 in total and 1 000 keys.
  - The manifest-keys mode of `_resolve_manifest_entry` is used by the reader and `_reject_unsafe_entry` only; both flow callers stay on the default mode.
  - `check_project_files` reports manifest and disk problems. `_handle_load_project` adds `not readable` from the install result and keeps one problem per file by precedence.
  - Private manifest staging; `_check_destination_contained` calls `contained_in_workarea` (SEC PDR-C1).
  - `derived_from` (name, SHA-256, byte count, computed at the write) is written by the save-back and by Save project's emit, emitted in the B100-I1 envelope, verified, and carried.
  - `choose_install_set` (a pure module-level function in `app.py`) holds the fallback rule.
- **Interfaces:** freezes B100-I1, B100-I2 (`files`, `derived_from`), B100-I3, B100-I16 and B100-I21.
- **Enablers:**
  - E4: the `p04` cases 2/5/6/7/9, a legacy project, and a hand-copied variant;
  - E8 (`tests/support/b100_manifests.py`): 1 001-entry arrays, 75 × 1 000 `assignments`, a 1 MiB + 1 file, hostile keys.

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-168.4 `derived_from` records what a patched variant derives from | TC-B100-71 | Inc 7 | a mutation dropping the key from the carry → after a variant append the panel loses the "patched" line → RED. |
| LLR-169.1 The `files` envelope | TC-B100-21 | Inc 7 | a mutation emitting an empty `files` key → the byte-identity arm → RED. |
| LLR-169.2 The seam computes `files` from disk, over the O-2 scope | TC-B100-22 | Inc 7 | a mutation walking sub-folders → `flows/f1.json` recorded → RED; a mutation keyed on `.s19` only → `prg.srec` missing → RED. |
| LLR-169.3 Verify covers the new keys | TC-B100-23 | Inc 7 | a mutation leaving `files` out of the domain → 0 mismatches → RED. |
| LLR-169.4 The reader treats `project.json` as untrusted (C6) | TC-B100-24 | Inc 7 | a mutation accepting a `bool` size → 0 issues on that arm → RED; P-40: an uncapped `batch` of 75 677 entries takes 14.92 s → RED for the timing arm. |
| LLR-169.5 `check_project_files`: manifest and disk problems | TC-B100-25 | Inc 7 | executed on `1d677ba` (P-4): `notices=[]` for cases 2 and 7 → RED; a mutation dropping the `not recorded` kind → the hand-copied arm → RED. |
| LLR-169.6 Load opens the valid files and writes one summary line | TC-B100-26 | Inc 7 | executed on `1d677ba` (P-5): `activating the first variant` then `-> firmware.mac` → RED. |
| LLR-169.7 The manifest is staged privately | TC-B100-27 | Inc 7 | executed on `1d677ba` by the QA race probe: `ok=3 cross-content=12 failed-writes=60` → RED; the source predicate → 1 hit at `:509` → RED. |
| LLR-169.8 A manifest-key mode refuses drive-relative, stream and device names (S-09) | TC-B100-60 | Inc 7 | executed (S-09): `'C:x.s19' -> …\workarea\P\x.s19 0` at `1d677ba` → RED; P-41: the same tightening applied to every caller → `test_tc_b97_20_hostile_refs_render_literally` RED, so the mode is required. |
| LLR-169.9 The load result adds `not readable`, one problem per file wins, worded for the user | TC-B100-61 | Inc 7 | a mutation keeping every kind per file → case 6 gives 2 problems → RED; a mutation painting the issue code → 1 `MANIFEST-` code painted → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-07 | HLR-169 | executed on `1d677ba` (P-4): `[2 image edited on disk] … notices=[]` → AT-B100-07 is RED today. |

### 5.8 Inc 8a — the change document travels with the project

**SOURCE files (4):** `app.py`, `services/manifest_writer.py`, `services/variant_execution_service.py`, `services/project_gather_service.py` (paths under `s19_app/tui/`).

**Findings:** M-2, D4, Q-5. **Hard order:** after Inc 3 and Inc 7.
- **Design characteristics.**
  - `active_document` is recorded in the envelope, and the reader enforces the `patches/` / `checks/` prefix and the `.json` suffix.
  - The app writes a pasted document through `write_change_document` as `patches/changes.json` (M-1 rule); the gather only places files and names the landed path in `GatherOutcome`.
  - Load reopens the document after the A2L is attached.
  - The merge carry of LLR-164.2(b) and the plan's document and merge rows are extended here.
- **Interfaces:** freezes B100-I1 (`active_document`) and B100-I2 (`active_document`).
- **Enablers:** E4 (`p06` A, with a gathered document); the `p01` pasted-entry session.
- **⚠ Exactly 4 SOURCE files** (`app.py`, `manifest_writer.py`, `variant_execution_service.py`, `project_gather_service.py`). It cannot be cut: the writer, the reader and the gather each own one side of `active_document`, and `app.py` owns the reopen. ARQ §8 records no slack here: any further file needs a re-cut.

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-170.1 The `active_document` key | TC-B100-28 | Inc 8a | a mutation skipping the prefix rule → `firmware.s19` accepted → RED. |
| LLR-170.2 The app writes a pasted document; the gather places | TC-B100-29 | Inc 8a | executed on `1d677ba` (P-8): nothing under `patches/` for a pasted document → RED. |
| LLR-170.3 Load reopens the document after the A2L | TC-B100-30 | Inc 8a | executed on `1d677ba` (P-8): `editor doc = None` → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-08 | HLR-170 | executed on `1d677ba` (P-8): `after Load: editor doc = None entries = 0` → AT-B100-08 is RED today. |

### 5.9 Inc 8b — save-as, A2L-only, this work area

**SOURCE files (3):** `app.py`, `services/project_gather_service.py`, `workspace.py` (paths under `s19_app/tui/`).

**Findings:** M-3 (D5), M-6 (D6), M-5 (D7, handler), S-02 (listing and load).
- **Design characteristics.**
  - Save-as uses one link-pruned walk for both the file list and the total, refuses a copy larger than the free space (`not enough free space`), and copies through `place_into_workarea`.
  - An A2L-only project opens with `_variant_set = build_variant_set(name, [])`; a folder with neither a data file nor an A2L paints `no data or A2L file` (UX-22).
  - A parent folder is refused unless it is this work area.
  - `list_projects` and `_handle_load_project` require `contained_in_workarea` and refuse a reparse-point project folder.
  - The 8-writer junction arm runs here; the manifest seam's own check landed at Inc 7.
- **Interfaces:** consumes B100-I14 (frozen at Inc 1) and B100-I10.
- **Enablers:** E1 (junctions at the top level and nested, a file symlink); E4 (`p06` C, `p04` 10).

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-171.1 Save as copies every sub-folder, never through a link | TC-B100-31 | Inc 8b | executed on `1d677ba` (P-9): Q lacks the sub-folders → RED; S-03's executed probe: `os.walk(P)` lists `flows\secret.txt` through a junction → RED; security R2-06's probe: a plain walk descends a junction → the total arm RED. |
| LLR-171.2 An A2L-only project opens | TC-B100-32 | Inc 8b | executed on `1d677ba` (P-12): `No supported files in project: P` → RED; a mutation leaving `_variant_set` as `None` → the rewrite arm writes nothing → RED. |
| LLR-171.3 Only this work area is a parent | TC-B100-33 | Inc 8b | executed on `1d677ba` (P-11): the other work area accepted, not listed → RED. |
| LLR-171.4 Containment means this work area, checked inside the placement (S-02) | TC-B100-62 | Inc 1 (guard) / 7 (seam) / 8b (listing, load) | executed (S-02 probe): `_check_destination_contained PASSED (no raise)` and `copy_into_workarea WROTE …\other\.s19tool\workarea\target\src.s19` at `1d677ba` → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-09 | HLR-171 | executed on `1d677ba`: P-9 → AT-B100-09 RED; P-12 → AT-B100-10 RED; S-02's executed probe (a junction folder is listed and written through) → AT-B100-11 RED. |
| AT-B100-10 | HLR-171 | executed on `1d677ba`: P-9 → AT-B100-09 RED; P-12 → AT-B100-10 RED; S-02's executed probe (a junction folder is listed and written through) → AT-B100-11 RED. |
| AT-B100-11 | HLR-171 | executed on `1d677ba`: P-9 → AT-B100-09 RED; P-12 → AT-B100-10 RED; S-02's executed probe (a junction folder is listed and written through) → AT-B100-11 RED. |

### 5.10 Inc 9a — recent store, lister, typed paths

**SOURCE files (2):** `workspace.py`, `app.py` (paths under `s19_app/tui/`).

**Findings:** the Load request's data half, L-2.
- **Design characteristics.**
  - `recent_store_path()` returns `%LOCALAPPDATA%\s19_app\recent_sources.json` (disabled when `LOCALAPPDATA` is unset).
  - `record_recent_source` writes with `mkstemp` staging + `os.replace`; `read_recent_sources` reads `read(65 536 + 1)` into `RecentSources(entries, problem)`.
  - One `list_workarea_files` lister.
  - The typed-path router (projects of this work area only; reserved homes never load).
  - `refresh_files` paints names through `safe_text`.
- **Interfaces:** freezes B100-I9.
- **Enablers:**
  - E5: `LOCALAPPDATA` pointed at `tmp_path` by `monkeypatch`;
  - E2: names that exist on disk and paint a span with markup on — `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19`, and `a\x9bb.s19`;
  - E9 (`tests/support/b100_recents.py`): 1 000 distinct entries, an exactly-65 536-byte file, and the hostile entry set.

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-172.1 The recent-sources store is written per user | TC-B100-34 | Inc 9a | a mutation dropping the de-duplication → 2 entries → RED; a mutation writing to `<base>/.s19tool/` (round-2 location) → the base-folder arm RED. |
| LLR-172.2 The store is read as untrusted input (C6) | TC-B100-35 | Inc 9a | a mutation removing the size cap → the 65 537-byte arm returns entries → RED; S-07's executed probe: `\\host\share\x.s19 … is_absolute = True` → RED for an absolute-only filter. |
| LLR-172.3 Recent paths stay out of projects, reports and every work area | TC-B100-36 | Inc 9a | a mutation adding the recents to the manifest → 1 occurrence → RED. |
| LLR-172.4 One work-area lister | TC-B100-37 | Inc 9a | a mutation adding a second enumeration of `temp/` in `app.py` → the census counts 2 → RED. |
| LLR-172.5 A typed project path opens the project (L-2); reserved homes never do (S-01) | TC-B100-38 | Inc 9a | executed on `1d677ba` (P-15): `Unsupported file type: ` → RED; S-01's executed probe: `validate_project_files(workarea/temp)` accepts → RED. |
| LLR-172.6 The Workarea Files list renders names literally (C8) | TC-B100-39 | Inc 9a | today's markup-on `Label` paints 1 span for `[bold]x.s19` (QA-02 probe) → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-12 | HLR-172 | executed on `1d677ba` (P-15): `Load file 'ab' -> status=['Unsupported file type: ']` → AT-B100-12 RED today. AT-B100-13: with today's `Label(item.name)` (`app.py:6559`, markup on) `[bold]x.s19` paints 1 span (QA-02 probe) → RED. |
| AT-B100-13 | HLR-172 | executed on `1d677ba` (P-15): `Load file 'ab' -> status=['Unsupported file type: ']` → AT-B100-12 RED today. AT-B100-13: with today's `Label(item.name)` (`app.py:6559`, markup on) `[bold]x.s19` paints 1 span (QA-02 probe) → RED. |

### 5.11 Inc 9b — the Load dialog

**SOURCE files (3):** `screens.py`, `app.py`, `styles.tcss` (paths under `s19_app/tui/`).

**Findings:** the Load dialog (P-A C), D10, CW-U-12/13, C8.
- **Design characteristics.**
  - One two-pane modal on the `pa_C` ids, dismissing with `LoadChoice`.
  - Keys and focus:
    - the focus starts on `#load_path`;
    - `tab` goes path → list → preview → buttons;
    - a printable key typed in the list moves to the path field and types there;
    - `enter`, `alt+l` and `#load_ok` load the row or the typed path by last focus;
    - a click selects; `escape` closes.
  - The preview marks `●` through `choose_install_set` and reads a project's manifest on a cancellable worker.
  - Recent rows are never read before Enter. `#load_reason` paints the tokens.
  - `p` highlights the open project's row; `LoadProjectScreen` retires.
- **Interfaces:** freezes B100-I8.
- **Enablers:** E2 (the hostile `[b]P` folder); E3; the AT size helper E10 (`(118, 54)` and `(220, 60)`, `notifications=True`).

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-173.1 `LoadChoice` and one router | TC-B100-40 | Inc 9b | a mutation routing `workarea` through `load_from_path` → 1 new copy → RED. |
| LLR-173.2 Keys, focus order and the empty Load | TC-B100-41 | Inc 9b | executed on `1d677ba` (P-18, P-19) → RED; a mutation starting the focus on `#load_list` (`pa_C`'s start) → the open arm RED. |
| LLR-173.3 Every list renders names through `safe_text` (C8) | TC-B100-42 | Inc 9b | today's `Label(name)` paints 1 span for `[b]P` (QA-02 probe) → RED. |
| LLR-173.4 The dialog's sources, empty sections and recent rows | TC-B100-43 | Inc 9b | a mutation listing folders without `list_projects` → the reserved folder listed → RED; a mutation previewing a recent on highlight → 1 filesystem call → RED; a main-thread preview read → the 200 ms arm RED. |
| LLR-173.5 An invalid typed path is explained inside the dialog (UX-06) | TC-B100-63 | Inc 9b | a mutation dismissing with the path → the dialog closes → RED. |
| LLR-173.6 The preview marks the active set for every row kind, and the load installs it | TC-B100-64 | Inc 9b (function at 7) | a mutation computing the mark from the first variant by name → the save-back project's mark differs from the install → RED. |
| LLR-173.7 Painted text carries no internal decision id | TC-B100-66 | Inc 9b | the prototypes paint "Browse is gone (D7)" and "D10: click loads OFF" (UX-18 captures) → a surface copied from them → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-14 | HLR-173 | executed on `1d677ba` (P-18, P-19): `escape on LoadFileScreen -> screen: LoadFileScreen`; `Enter with a typed path -> current_file before/after: firmware_1.s19 / firmware_1.s19` → AT-B100-14 RED today. |

### 5.12 Inc 10 — one question on every route

**SOURCE files (4):** `screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py` (paths under `s19_app/tui/`).

**Findings:** CW-U-5 (P-B A), B-02. **Hard order:** after Inc 5.
- **Design characteristics.**
  - `_confirm_then_load(kind, go)` is the one seam for the router, the Workarea pick, `_handle_select_variant` and project loads. It runs the 24-cell guard (an image replace asks iff D; an attach never; a project load iff D or F or W).
  - The confirm modal on the `pb_A` ids: one short question, the focus on `#confirm_no`, `y` / `n` / `escape`.
  - `screens_directionb.py` gains a public read-only dirty-flag accessor.
- **Interfaces:** freezes B100-I20.
- **Enablers:** E4 (P1/P2); a dirty Flow Builder (an unsaved block added through the panel API).
- **⚠ Exactly 4 SOURCE files** (`screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py`). It cannot be cut: the W term (LLR-174.1) needs a public reader on the Patch Editor panel, whose flag is private (P-43); the modal needs `screens.py` and its layout rules; and the seam is `app.py` (ARCH C-5).

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-174.1 The trigger truth table | TC-B100-44 | Inc 10 | dropping D → 5 cells wrong, dropping F → 1, dropping W → 1 (executed); making an attach ask on D (the round-2 table) → 4 cells wrong → RED. |
| LLR-174.2 One short question, safe focus, keys | TC-B100-45 | Inc 10 | a mutation focusing `#confirm_yes` first → the immediate `enter` replaces → RED. |
| LLR-174.3 The question comes before the reset | TC-B100-46 | Inc 10 | a mutation resetting before asking → the cancelled session is empty → RED. |
| LLR-174.4 One load seam for every image-replacing route | TC-B100-72 | Inc 10 | executed on `1d677ba` (P-42): the Workarea pick and `v` replace the image with no question → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-15 | HLR-174 | executed on `1d677ba` (P-17): `Load file over patched image -> stack: ['Screen'] … image still patched? False` → AT-B100-15 RED today. |

### 5.13 Inc 11 — the Save project dialog

**SOURCE files (3):** `screens.py`, `app.py`, `styles.tcss` (paths under `s19_app/tui/`).

**Findings:** the M-4 summary, the D7 dialog half (P-C B).
- **Design characteristics.**
  - `SaveProjectScreen` on the `pc_B` ids. `#save_summary` is painted only from the frozen `SavePlan`, which is exposed read-only as `.plan`.
  - The first frame paints before any digest; the per-open digests run on a worker (rows show `computing…`), and an `alt+s` before they finish waits under the busy indicator.
  - The name-dependent rows are debounced at 150 ms. The summary scrolls with its buttons pinned.
  - No parent field and no Browse….
- **Interfaces:** consumes B100-I17 and B100-I11.
- **Enablers:** E4 (the 5 scenarios); the case_06 project, for the digest budget (UX C-2).

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-175.1 The dialog's lines follow the name rules | TC-B100-47 | Inc 11 | a mutation computing the lines without case-folding → `Reports` shows no line → RED. |
| LLR-175.2 No parent field | TC-B100-48 | Inc 11 | today's dialog (`screens.py:555`) → 1 Browse button → RED. |
| LLR-175.3 Keys and the empty Save | TC-B100-49 | Inc 11 | executed on `1d677ba` (P-18, P-19) → RED. |
| LLR-175.4 The summary is the save plan (R-PC) | TC-B100-65 | Inc 11 | a mutation dropping `keep` rows from the painter → 1 row missing in the merge scenario → RED; a mutation recomputing the plan with digests per keystroke → the 0-digests arm RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-16 | HLR-175 | executed on `1d677ba` (P-18, P-19): `escape on SaveProjectScreen -> screen: SaveProjectScreen`; `empty name Save click -> … new status: []` → AT-B100-16 RED today. AT-B100-21: a mutation where the handler places a file the plan … |
| AT-B100-21 | HLR-175 | executed on `1d677ba` (P-18, P-19): `escape on SaveProjectScreen -> screen: SaveProjectScreen`; `empty name Save click -> … new status: []` → AT-B100-16 RED today. AT-B100-21: a mutation where the handler places a file the plan … |

### 5.14 Inc 12a + 12b — real progress and workers (one unit)

**SOURCE files (3):** `app.py`, `styles.tcss`, `a2l.py` (paths under `s19_app/tui/`). `a2l.py` is a named crossing of the frozen engine layer (`docs/ARCHITECTURE.md` §7; C-UX-1 / C-QA-1, the operator's "Cruce con nombre"); the increment re-adds it to `tests/test_engine_unchanged.py::_ENGINE_PATHS`.

**Findings:** N5 (P-D A), O-7, R-PD. One unit.
- **Design characteristics.**
  - `begin_busy` / `step_busy` / `end_busy`: one owner of `#status_text`, the bar reset to 0 and cleared when idle, keeping its row so the log lines never move (C-UX-7), within-step progress from byte counts, one main-thread `set_interval`.
  - The keyed action table covers all 24 `set_progress` sites.
  - `a2l.py`'s parse entry point takes an optional `progress(bytes_consumed, total_bytes)` callback and parses exactly what it parses today; `step_busy` feeds the bar from it, so the bar rises at least twice during the case_06 parse (LLR-176.4, AT-B100-17).
  - Project load, Save project (emit, copy, hash and manifest from a copy, after the main-thread re-derive) and the A2L parse run under `@work(thread=True)`, installing through `call_from_thread`.
  - The refused set while a worker runs; quit asks through the Inc 10 confirm modal, which takes its question text and both button labels as parameters (C-UX-4 / ARCH-PDR-4), so `screens.py` is not touched.
  - The A2L tag-table build stays on the main thread, with its step painted first.
- **Interfaces:** freezes B100-I12.
- **Enablers:** E6 (the case_06 A2L and a project holding it, P-33); its worker share is measured above one timer tick at the first run and recorded.

| LLR | Proposed test | Written at | The mutation that turns it RED |
|---|---|---|---|
| LLR-176.1 The busy seam owns `#status_text` and moves the bar within steps | TC-B100-50 | Inc 12 | a mutation dropping `end_busy` on the exception path → 1 indicator left → RED; a mutation setting the bar from the step index only → the within-step arm RED. |
| LLR-176.2 Every progress caller maps to one action (C-31) | TC-B100-51 | Inc 12 | a mutation removing one action's failure-path end → the census names that action → RED. |
| LLR-176.3 Main-thread steps paint before they work | TC-B100-52 | Inc 12 | a mutation starting the work before the refresh → the callback reads the previous text → RED. |
| LLR-176.4 The A2L parser reports the bytes it has consumed (named crossing) | TC-B100-73 | Inc 12 | a mutation calling the callback only once at the end → fewer than 2 calls → RED; a mutation changing a parsed field when a callback is given → the equality arm RED. |
| LLR-177.1 Three actions on workers, installs on the main thread, everything else refused | TC-B100-53 | Inc 12 | today's synchronous load (`app.py:8510`) → 0 changes → RED; a mutation omitting `v` from the refused set → the image changes during the save → RED. |
| LLR-177.2 Worker failures keep the app running | TC-B100-54 | Inc 12 | a mutation letting the exception escape the worker → the app exits → RED. |

| AT | HLR | The mutation or executed RED that turns it RED |
|---|---|---|
| AT-B100-17 | HLR-176 | executed on `1d677ba` by the round's capture (UX-02): the screen did not repaint between the start and the end of the case_06 parse → AT-B100-17 RED today. |
| AT-B100-18 | HLR-177 | code-read on `1d677ba`: `_handle_load_project → load_selected_file` runs synchronously (`app.py:8510`, `:10731`), so the elapsed text cannot advance during it → AT-B100-18 RED today (executed at Phase 3). |


### 5.15 Design → requirement traceability

Every LLR, the increment where its test is written (extensions are in the contract's §5.3), and that increment's SOURCE files.

| LLR | HLR | Increment | SOURCE files of that increment |
|---|---|---|---|
| LLR-163.1 | HLR-163 | 1 | `workspace.py`, `segment_split_view.py`, `app.py` |
| LLR-163.2 | HLR-163 | 1 | `workspace.py`, `segment_split_view.py`, `app.py` |
| LLR-163.3 | HLR-163 | 1 | `workspace.py`, `segment_split_view.py`, `app.py` |
| LLR-163.4 | HLR-163 | 1 | `workspace.py`, `segment_split_view.py`, `app.py` |
| LLR-163.5 | HLR-163 | 1 | `workspace.py`, `segment_split_view.py`, `app.py` |
| LLR-163.6 | HLR-163 | 1 | `workspace.py`, `segment_split_view.py`, `app.py` |
| LLR-163.7 | HLR-163 | 1 | `workspace.py`, `segment_split_view.py`, `app.py` |
| LLR-164.1 | HLR-164 | 2 | `app.py`, `workspace.py` |
| LLR-164.2 | HLR-164 | 2 (merge carry 8a) | `app.py`, `workspace.py` |
| LLR-164.3 | HLR-164 | 2 | `app.py`, `workspace.py` |
| LLR-164.4 | HLR-164 | 2 | `app.py`, `workspace.py` |
| LLR-165.1 | HLR-165 | 3 | `app.py` |
| LLR-165.2 | HLR-165 | 3 | `app.py` |
| LLR-165.3 | HLR-165 | 3 | `app.py` |
| LLR-165.4 | HLR-165 | 3 | `app.py` |
| LLR-166.1 | HLR-166 | 4 (closes 6, 9b, 10) | `app.py` |
| LLR-166.2 | HLR-166 | 4 | `app.py` |
| LLR-167.1 | HLR-167 | 5 | `app.py`, `services/change_service.py`, `services/project_gather_service.py` |
| LLR-167.2 | HLR-167 | 5 | `app.py`, `services/change_service.py`, `services/project_gather_service.py` |
| LLR-167.3 | HLR-167 | 5 | `app.py`, `services/change_service.py`, `services/project_gather_service.py` |
| LLR-167.4 | HLR-167 | 5 | `app.py`, `services/change_service.py`, `services/project_gather_service.py` |
| LLR-167.5 | HLR-167 | 5 | `app.py`, `services/change_service.py`, `services/project_gather_service.py` |
| LLR-167.6 | HLR-167 | 5 (rows 7, 8a, 8b) | `app.py`, `services/change_service.py`, `services/project_gather_service.py` |
| LLR-167.7 | HLR-167 | 5 | `app.py`, `services/change_service.py`, `services/project_gather_service.py` |
| LLR-167.8 | HLR-167 | 5 | `app.py`, `services/change_service.py`, `services/project_gather_service.py` |
| LLR-168.1 | HLR-168 | 6 | `app.py`, `services/variant_execution_service.py`, `screens.py`, `styles.tcss` |
| LLR-168.2 | HLR-168 | 6 | `app.py`, `services/variant_execution_service.py`, `screens.py`, `styles.tcss` |
| LLR-168.3 | HLR-168 | 6 | `app.py`, `services/variant_execution_service.py`, `screens.py`, `styles.tcss` |
| LLR-168.4 | HLR-168 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.1 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.2 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.3 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.4 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.5 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.6 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.7 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.8 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-169.9 | HLR-169 | 7 | `services/manifest_writer.py`, `services/variant_execution_service.py`, `app.py` |
| LLR-170.1 | HLR-170 | 8a | `app.py`, `services/manifest_writer.py`, `services/variant_execution_service.py`, `services/project_gather_service.py` |
| LLR-170.2 | HLR-170 | 8a | `app.py`, `services/manifest_writer.py`, `services/variant_execution_service.py`, `services/project_gather_service.py` |
| LLR-170.3 | HLR-170 | 8a | `app.py`, `services/manifest_writer.py`, `services/variant_execution_service.py`, `services/project_gather_service.py` |
| LLR-171.1 | HLR-171 | 8b | `app.py`, `services/project_gather_service.py`, `workspace.py` |
| LLR-171.2 | HLR-171 | 8b | `app.py`, `services/project_gather_service.py`, `workspace.py` |
| LLR-171.3 | HLR-171 | 8b | `app.py`, `services/project_gather_service.py`, `workspace.py` |
| LLR-171.4 | HLR-171 | 1 (guard) / 7 (seam) / 8b (listing, load) | `workspace.py`, `segment_split_view.py`, `app.py` |
| LLR-172.1 | HLR-172 | 9a | `workspace.py`, `app.py` |
| LLR-172.2 | HLR-172 | 9a | `workspace.py`, `app.py` |
| LLR-172.3 | HLR-172 | 9a | `workspace.py`, `app.py` |
| LLR-172.4 | HLR-172 | 9a | `workspace.py`, `app.py` |
| LLR-172.5 | HLR-172 | 9a | `workspace.py`, `app.py` |
| LLR-172.6 | HLR-172 | 9a | `workspace.py`, `app.py` |
| LLR-173.1 | HLR-173 | 9b | `screens.py`, `app.py`, `styles.tcss` |
| LLR-173.2 | HLR-173 | 9b | `screens.py`, `app.py`, `styles.tcss` |
| LLR-173.3 | HLR-173 | 9b | `screens.py`, `app.py`, `styles.tcss` |
| LLR-173.4 | HLR-173 | 9b | `screens.py`, `app.py`, `styles.tcss` |
| LLR-173.5 | HLR-173 | 9b | `screens.py`, `app.py`, `styles.tcss` |
| LLR-173.6 | HLR-173 | 9b (function at 7) | `screens.py`, `app.py`, `styles.tcss` |
| LLR-173.7 | HLR-173 | 9b | `screens.py`, `app.py`, `styles.tcss` |
| LLR-174.1 | HLR-174 | 10 | `screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py` |
| LLR-174.2 | HLR-174 | 10 | `screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py` |
| LLR-174.3 | HLR-174 | 10 | `screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py` |
| LLR-174.4 | HLR-174 | 10 | `screens.py`, `app.py`, `styles.tcss`, `screens_directionb.py` |
| LLR-175.1 | HLR-175 | 11 | `screens.py`, `app.py`, `styles.tcss` |
| LLR-175.2 | HLR-175 | 11 | `screens.py`, `app.py`, `styles.tcss` |
| LLR-175.3 | HLR-175 | 11 | `screens.py`, `app.py`, `styles.tcss` |
| LLR-175.4 | HLR-175 | 11 | `screens.py`, `app.py`, `styles.tcss` |
| LLR-176.1 | HLR-176 | 12 | `app.py`, `styles.tcss` |
| LLR-176.2 | HLR-176 | 12 | `app.py`, `styles.tcss` |
| LLR-176.3 | HLR-176 | 12 | `app.py`, `styles.tcss` |
| LLR-177.1 | HLR-177 | 12 | `app.py`, `styles.tcss` |
| LLR-177.2 | HLR-177 | 12 | `app.py`, `styles.tcss` |
| LLR-178.1 | HLR-178 | 6 | `app.py`, `services/variant_execution_service.py`, `screens.py`, `styles.tcss` |
| LLR-178.2 | HLR-178 | 6 | `app.py`, `services/variant_execution_service.py`, `screens.py`, `styles.tcss` |
| LLR-178.3 | HLR-178 | 6 | `app.py`, `services/variant_execution_service.py`, `screens.py`, `styles.tcss` |

### 5.16 Whole-tree guards at every increment gate

These run at **every** gate, before the packet's verdict. Batch-99's lessons: guards skipped at increment gates surfaced at the close, and the record BLOCKs were unread until then.

| Guard | Command | Watch at |
|---|---|---|
| import census | `pytest tests/test_import_census.py` | every gate; Inc 5 must show no new `project_gather_service` → `changes` edge |
| snapshot cells | `pytest tests/test_tui_snapshot.py` | every gate; rebaselines named in the packet at Inc 6 (panel), 9b (dialog), 10 (question), 11 (Save dialog), 12 (status line) |
| id registry | `pytest tests/test_id_registry.py tests/test_batch91_registry_hygiene.py` | every gate (every increment adds `at_b100_NN` / `TC-B100-NN` nodes) |
| address census | `pytest tests/test_address_census.py` | every gate; widget ids change at 6, 9b, 10, 11 |
| freeze guards | `pytest tests/test_engine_unchanged.py` | every gate (no frozen-engine file may change) |
| full suite | `pytest -q` against the baseline captured at `1d677ba` before Inc 1 | every gate; no new failure |
| flow record | `python ~/.claude/skills/dev-flow/scripts/devflow-validate.py --brief .` | every gate, before `--decision` |

One command for the six guard files: `pytest tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py tests/test_batch91_registry_hygiene.py tests/test_address_census.py tests/test_engine_unchanged.py`. Each run sets `PYTHONPATH=<worktree>` and prints `s19_app.__file__` first (the `pip -e` trap).

## 6 · Risks and rejected alternatives

- **`app.py` in 14 of 15 increments.** Mitigation: sequential increments, one worktree each, merged in order (ARQ §9).
- **The Save dialog's digest budget is assumed.** The budget is 2 s on the CI host for the case_06 project, but it has not been measured. Mitigation: it is measured at Inc 11 and recorded in the packet; a miss is a packet finding, not a silent pass.
- **Re-pinned tests could hide a regression.** This covers G-005, `test_tc_b99_31_…`, the `#project_parent_path` nodes, the `#project_list` nodes and the status-line snapshots. Mitigation: each re-pin is named old → new → LLR in its packet's reverse census.
- **Threading (Inc 12).** Mitigation: installs happen only through `call_from_thread`, `_session_snapshot` compares a worker load with a main-thread load, and flow runs stay off the worker (I-7 untouched).
- **Windows placement locks.** Bounded retries already exist (batch-99 LLR-155.2); containment adds no new retry path.

| Alternative considered | Why it was rejected |
|---|---|
| Change `copy_into_workarea`'s return type | 15 call sites in 7 files; the wrapper keeps every caller covered by construction (R35) |
| `choose_install_set` in `variant_execution_service.py` | makes Inc 9b 4 files; both callers already sit in `app.py` (LED .34) |
| Digests computed on the main thread at dialog open | the same freeze class as UX-02 (UX C-2) |
| `image_differs_from_source` deciding copy | after a save-back it is false-for-source, so it could copy the unpatched source (A-08, PDR-QA-2) |
| A per-list cap on `assignments` only | 75 × 1 000 entries read in 14.80 s (SEC PDR-C2) |
| `%APPDATA%` for the recent store | it roams to a profile server (SEC PDR-C3, orchestrator ruling) |
| The panel in Inc 7 rather than Inc 6 | Inc 7 would be 5 files |
| A separate quit-question modal | it would add `screens.py` to Inc 12; the Inc 10 modal takes its text as a parameter |

## 7 · Forward-applicability table — **the section that makes this document honest**

| Output of this PDR | Named consumer downstream | Where the consumer will read it |
|---|---|---|
| design characteristics | the Phase-3 increments | §2–§3, and §5.1–§5.14 per increment, quoted in each Kimi brief (`kimi/BRIEF-inc-<N>.md`) |
| enablers (fixtures, data, scaffolding, env) | Phase 3 and validation | §5 enablers E1–E13, built in the first increment that names them; E12 in `kimi/BRIEF-COMMON.md` |
| proposed test cases | layers 0/A/B and the DDR | §5.1–§5.14 (mutations per LLR and per AT) and `01-requirements.md` §3–§4; each packet's RED counterfactual and mutation rows |
| design → requirement traceability | the matrix and the DDR | §5.15, and `06-docs/traceability-matrix.md` at P6 |
| whole-tree guard commands | every increment gate | §5.16, copied into each packet's gate run |
| PDR condition dispositions | the PDR verdict and the map update | §9, LED-2026-10-26-batch-100.24 to .34, and the seal's contract-text conditions in LED .35 to .48 |
| real-terminal look of every changed screen (C-UX-5) | the Phase-4 inspection | E13's PNGs at 118×54, 220×60 and 99×54, read against the prototype verdicts (P-A C, P-B A, P-C B, P-D A, P-E B) |

## 8 · Parallelisation plan *(only if the batch forks)*

Not applicable. The batch runs one lane, in sequence (ARQ §9; `01-requirements.md` §2.8).

## 9 · PDR conditions carried from P2 — disposition

| Condition | Disposition | Where | Owner · increment |
|---|---|---|---|
| UX-22 (C-3) | discharged: LLR-171.2 paints `no data or A2L file` / `load a file and Save project`; TC-B100-32 arm | LED .24 | Inc 8b |
| UX C-1 | discharged: `#result_ok` labelled "Close (esc)"; `escape` dismisses from anywhere, `enter` only on the focused button; TC-B100-67 presses `esc` | LED .25 | Inc 6 |
| UX C-2 | discharged: first frame before any digest; digests once per open on a worker; `computing…` rows; `alt+s` waits (superseded at the seal: an early `alt+s` closes the dialog, C-UX-3, LED .37); budget 2 s for the case_06 project (assumed, measured at Inc 11) | LED .26 | Inc 11 (plan inputs from Inc 5) |
| ARCH C-1 (B100-I15 names) | the contract form is frozen (`rederive_for_save`, `emit_and_verify(map, ranges, …)`); map row updated by the architect at PDR | §4 | architect · before Inc 5 |
| ARCH C-2 (B100-I22 signature) | the contract form is frozen (`predict_placement(digest_or_bytes, size, destination, name)`) | §4 | architect · before Inc 1 |
| ARCH C-3 (B100-I16 record) | the contract form is frozen (name, SHA-256, byte count; the "not in this project" wording) | §4 | architect · before Inc 7 |
| ARCH C-4 | discharged: LLR-174.4 names `_handle_load_project` | LED .27 | Inc 10 |
| ARCH C-5 | discharged: Inc 10 = 4 files, no bracket (§5.5 of the contract, §5 here) | LED .27 | Inc 10 |
| SEC PDR-C1 | discharged: `_check_destination_contained` calls `contained_in_workarea` (Inc 7); LLR-171.4's "by construction" sentence drops the seam; the 8th-writer arm at Inc 8b | LED .28 | Inc 7 (code), Inc 8b (arm) |
| SEC PDR-C2 | discharged: `assignments` capped at 1 000 in total and 1 000 keys; arm 75 × 1 000 → 1 issue, < 1 s | LED .29 | Inc 7 |
| SEC PDR-C3 | discharged by the orchestrator ruling: `%LOCALAPPDATA%\s19_app\recent_sources.json` | LED .30 | Inc 9a |
| PDR-QA-1 | discharged: `SaveProjectScreen.plan` is a frozen dataclass, read only after `alt+s` by key, compared by landing name and action on rows that are not cut | LED .31 | Inc 11 |
| PDR-QA-2 + B100-I5 | discharged by the orchestrator ruling: the pre-check is only a fast path into the data comparison and never decides copy; two TC-B100-14 arms | LED .32 | Inc 5 |
| `derived_from` in the B100-I1 envelope | discharged by the orchestrator ruling: emitted in the envelope and in the verify drift domain | LED .33 | Inc 7 |
| `choose_install_set`'s home | proposed and written: a pure module-level function in `app.py`, landed at Inc 7, reused at Inc 9b; Inc 7 = 3 files, Inc 9b = 3 files | LED .34 | Inc 7 |
