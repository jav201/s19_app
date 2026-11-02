# Increment 016 — Inc 8b · HLR-171 / HLR-171a / HLR-171b · LLR-171.1–171.7 · LLR-167.6a–g · save as copies the project, A2L-only projects, project-folder containment

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `008b` |
| Lane | `main` · 4 SOURCE files at the cap (`app.py`, `project_gather_service.py`, `workspace.py`, `screens_directionb.py`) plus a 5th (`variant_execution_service.py`) operator-approved for F2 on 2026-10-31 — 5 total |
| Requirement(s) | `HLR-171` · `HLR-171a` · `HLR-171b` · `LLR-171.1`–`LLR-171.7` (with suffixes `.1a`–`.1o`, `.2a`–`.2h`, `.3a`, `.4c`, `.4e`–`.4h`, `.5`, `.6`/`.6a`/`.6b`, `.7a`/`.7b`/`.7c`) · `LLR-167.6a`–`.6g` (the Inc 8b arms) · `LLR-164.2` (rollback, `LLR-171.7c`) |
| Acceptance | `AT-B100-09` (HLR-171) · `AT-B100-10` (HLR-171a) · `AT-B100-11` (HLR-171b) — all in `tests/test_b100_project_homes.py` — and the white-box `TC-B100-31` (`test_b100_project_homes.py`) · `TC-B100-32` · `TC-B100-33` · `TC-B100-59` (8b arms in `test_b100_save_image.py`) · `TC-B100-62` (8b arms) |
| Interfaces | consumes the Inc 1 placement seam (`place_into_workarea` with `workarea_root`, `_path_traverses_reparse_point`, `contained_in_workarea`), the Inc 5 plan seam (`plan_project_save`, `SavePlanRow`), the Inc 8a manifest seam (`_manifest_carry`, `read_project_manifest`, `_write_and_verify_manifest`); adds `walk_tree_no_links(unreadable=, max_entries=)` to `workspace.py`, `InventoryFile` / `PlannedFolder` / `ProjectInventory` / `inventory_project_tree` / `painted_names` to `project_gather_service.py`, `GatherOutcome.unrecorded` |
| Agent | design-first experiment (`inc-8b/`): E1 requirements · E2 Code-Wire prototype (graph only) · E3 code-free design review (architect 3 rounds, security 2 rounds) · E4 parallel build (3 implementers + tester) · E5 change validation (mutants on DeepSeek v4 Pro via pi, code + security review on Opus, one corrective pass). Models per stage in the step table below |
| Date | `2026-10-31` (E1 through the close all on 2026-10-31 UTC) |
| Base | `ebe6d0c` (Inc 8a final); tree uncommitted at the time of writing |
| Import proof | `<HOME>\Github\s19_app-b100-inc8b\s19_app\__init__.py` — printed in every transcript header (`# s19_app.__file__` / `s19_app.__file__ =`) |

---

## 1 · What changed

**The feature (HLR-171 / HLR-171a / HLR-171b).** Save as copies the whole open project into the new folder; an A2L-only folder loads as a project with its A2L attached; only folders inside this work area are listed, loaded or written.

- **HLR-171 — save as copies the whole project.** One link-free enumeration (`inventory_project_tree` → `walk_tree_no_links`) feeds the plan and the copy. Every regular file of P that the save does not write itself is copied at the top level and at every depth of its sub-folders, through `place_into_workarea` (LLR-171.1); top-level files (`a.json`, `other.s19`, `notes.txt`) are copied (R3), `project.json.previous-*` backups and P's other MAC / A2L files are not (R10). Links and junctions at any depth are skipped and never followed (LLR-171.1a / .1b) and named in the status within the 10-name limit (LLR-171.1c); their bytes stay out of the free-space total (LLR-171.1d); a total over the free space refuses before any folder exists (LLR-171.1e, rounded per R7); the open project is never modified (LLR-171.1f); a save into an existing project copies no sub-folder (LLR-171.1g); the new `project.json` carries `batch`, `assignments`, `declared_regions`, `gathered`, `active_document` and `derived_from` (LLR-171.1h, R10/SEC8b-3 refuse a linked `P/project.json`); the total counts every written byte (LLR-171.1i). Ceilings: over 2 000 files, a walk over 10 000 entries, or a path over 32 components refuse before any folder (LLR-171.1j, R1/R13/R16); an unreadable or unclassifiable entry refuses before any folder (LLR-171.1k, R8); after the save the Flow panels and a Patch Editor document follow Q (LLR-171.1l / .1m); if P's folder is gone the save still writes the session's files with one line naming the missing folder (LLR-171.1n, F1); the copy refuses when a folder above a copied file becomes a link (LLR-171.1o, SEC8b-2).
- **HLR-171a — an A2L-only project opens.** `_handle_load_project` attaches the project's own A2L in place (not `load_a2l_from_path`), clears the previous data file, sets the open project, and a later data-file load is recorded in `project.json` (LLR-171.2, .2a, .2b, .2c). `project.json` with no data/A2L file → `no data or A2L file`; no `project.json` and no file → `no project.json` (LLR-171.2d, .2e). A linked or over-cap A2L is refused before the reset in an A2L-only folder (LLR-171.2f) and left out with one `not readable` problem beside a data file (LLR-171.2g; painted next step `replace the A2L file, then Load again` through `STEP_REPLACE_A2L` — F2). The A2L unload of a session with no data file detaches the A2L (LLR-171.2h, F3).
- **HLR-171b — project-folder containment.** `list_projects`, Load and the Save target refuse a link/junction or a folder resolving outside this work area (LLR-171.4c / .4e / .4f / .4g); the Save parent must resolve to this work area, spelling-tolerant (LLR-171.3 / .3a); the 8-writer containment arm is LLR-171.4h (routed from the Inc 1 arms).
- **The plan (LLR-167.6a–g).** One row per top-level sub-folder with its recursive count, a links-only sub-folder → one 0-file row (167.6a); skipped links listed (167.6b); a second MAC / A2L refused in the plan before any `mkdir` (167.6c / .6d); at most one row per landing (167.6e); the open project's own A2L exempt (167.6f); a file over the per-file cap refused in the plan, naming it (167.6g). A save as with top-level copies → one `carried` row per copy, action `new`, equal to the written tree.
- **Painted names and the rollback.** Names from P's tree are scrubbed by Unicode category (Cc, Cf, Zl, Zp; surrogate → U+FFFD) and clipped to 120, at most 10 then `and K more` (LLR-171.7 / .7a, `PAINTED_NAME_LIMIT`); a failed copy paints `could not save` / `check the folder` with no exception text (LLR-171.7b); the rollback keeps a file under a now-link/junction folder or with a changed `(st_dev, st_ino)` and paints one line (LLR-171.7c, SEC8b-1). A copied file `project.json` cannot record → one line naming it (LLR-171.5; `Windows reserves that name` for a device stem, `the name is not one project.json records` otherwise — F4). `batch` / `assignments` are the dialog selection when non-empty, otherwise the carried value (LLR-171.6 / .6a / .6b, R4).

**Corrective pass 1 (E5, 11 items + F2; `inc-8b/E5-cp1-notes.md`).** F1 (`_save_as_source_for`, the missing-source save — LLR-171.1n), F2 (`STEP_REPLACE_A2L`, the 5th source — LLR-171.2g), F3 (`_apply_unload` A2L-only branch — LLR-171.2h), F4 (LLR-171.5 example to the CRC template + token row 8 reason), F5 (the repeating-mismatch step and the rebind to the gather's landing — LLR-171.1m), F6 (`PAINTED_NAME_LIMIT` one definition), F7 (a) (`"unreadable"` reason — LLR-171.4f) / F7 (b) (R-7 routed to the backlog), SEC8b-1 (`_PlacedFiles` + `_abort_save` — LLR-171.7c), SEC8b-2 (`_path_traverses_reparse_point` source check — LLR-171.1o), SEC8b-3 (`_manifest_is_link` carry — LLR-171.1h), M24 / M35 (the two E5 survivors re-killed with new nodes), M46 (recorded equivalent), and the CI timing factor (`tests/support/timing.py` `timing_bound(seconds)` ×2 when `CI` is truthy; `test_id_registry.py` 226 → 227; the requirement bounds stay at 1 s).

**Process decision carried from Inc 8a (operator ruling, LED .75).** Per increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. No reverse census and no full suite per increment; the full battery runs once at the batch end. This packet applies it: the reverse-census checklist row is marked not run, never met.

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | HLR-171 · HLR-171a · HLR-171b · LLR-171.1/.1a–.1o · LLR-171.2/.2a–.2h · LLR-171.3/.3a · LLR-171.4c/.4e–.4g · LLR-171.5 · LLR-171.6/.6a/.6b · LLR-171.7/.7a/.7b/.7c · LLR-167.6a–g | `_handle_save_dialog` (parent/target/source checks, free space, the two copy phases, R4 batch/assignments, save-as carry/`derived_from`, status lines, R9 rebind), `_plan_project_save` (target kind, token row 9, inventory, `exempt`, MAC/A2L/cap refusals, `source_dir=None`), `_handle_load_project` (folder check, R5 A2L guard, A2L-only branch, `_project_folder_refusal`), `list_projects`, `_copy_project_subfolders`, `_save_as_source_for`, `_PlacedFiles` + `_abort_save`, `_manifest_is_link`, `_manifest_carry`, `_apply_unload` A2L-only branch, `_publish_flow_session_dir`. Final sha256[:16] `87c7f9d74909138c` |
| `s19_app/tui/services/project_gather_service.py` | source | HLR-171 · LLR-171.1/.1j/.1k · LLR-171.5 · LLR-171.6b · LLR-171.7/.7a · LLR-167.6a–g | `painted_names` / `PAINTED_NAME_LIMIT`, `InventoryFile` / `PlannedFolder` / `ProjectInventory`, `inventory_project_tree`, `_second_file_refusal`, `_walk_refusal`, `_plan_copies`, `plan_project_save` (sub-folder rows with counts, 0-file rows, skipped links, carried rows, refusals), `GatherOutcome.unrecorded`, `gather_project_artifacts` (unrecorded copies). Final `524c3409037cae26` |
| `s19_app/tui/workspace.py` | source | HLR-171 · LLR-171.1a · LLR-171.1j (R13/R16) · LLR-171.1k · LLR-171.1o · LLR-171.7c | `walk_tree_no_links(unreadable=, max_entries=)` (entry ceiling stops before sorting, unreadable entries yielded), `_path_traverses_reparse_point` (reused by the copier and the rollback). Final `d9f361f3fb092ae2` (unchanged by cp1) |
| `s19_app/tui/screens_directionb.py` | source | HLR-171a · LLR-171.2h | `LoadedArtifactsPanel._slot_state` — the A2L slot names `current_a2l_path` (tag count from `current_a2l_data`) when no `LoadedFile` exists (ruling D-5). Final `e94f8e764f950b1a` (unchanged by cp1) |
| `s19_app/tui/services/variant_execution_service.py` | source | LLR-171.2g | `DOCUMENT_NEXT_STEP` gains `STEP_REPLACE_A2L` → `replace the A2L file, then Load again`; the 5th source, operator-approved for F2 on 2026-10-31. Final `8a38dde7fcd14211` |
| `tests/test_b100_project_homes.py` | test | HLR-171 · HLR-171a · HLR-171b · LLR-171.1 · LLR-171.2 · LLR-171.3 · LLR-171.4 · LLR-171.5 · LLR-171.6 · LLR-171.7 · LLR-167.6a–g · AT-B100-09 · AT-B100-10 · AT-B100-11 | NEW module (TC-B100-31/32/33/62 nodes, AT-B100-09/10/11, the E4-integration gap nodes, the cp1 nodes) |
| `tests/test_b100_save_image.py` | test | LLR-167.6a–g | TC-B100-59 Inc 8b arms; re-pins RP-1, RP-2 |
| `tests/test_b100_reuse.py` | test | LLR-171.1 | RP-5: placement census 8 → 9 (one guarded placement in `_copy_project_subfolders` names `workarea_root`) |
| `tests/support/b100_projects.py` | fixture | HLR-171/171a/171b | Inc 8b builders (save-as trees, links/junctions at depth, links-only folder, bulk files, nested empty folders, deep path, R7 total oracle); RP-3 (`_is_link` reparse attribute on 3.11) |
| `tests/support/timing.py` | test | HLR-171 | `timing_bound(seconds)` ×2 when `CI` is truthy (21 `< 1 s` asserts in 4 files) |
| `tests/test_id_registry.py` | config | HLR-171 | `EXPECTED_SCANNED_TEST_FILES` 225 → 226 (E4), 226 → 227 (cp1) |
| `tools/e13/run.py` · `tools/e13/capture_all.ps1` | test | LLR-171.2 · UX-26 | orchestrator-owned: scenario `pe-a2l-only` (open + closed) |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-171/171a/171b | E1 / E3 / E5 edits (LED .76–.80) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-171/171a/171b | LED .76 – .81 |
| `.dev-flow/BACKLOG-CODE.md` | doc | HLR-171 | items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/inc-8b/*` | doc | HLR-171 | the experiment records: `E1-scope.md`, `E3-rulings.md`, `E3-architect.md`, `E3-security.md`, `E4-*.md`, `E5-cp1-notes.md`, `E13-notes.md`, `steps.log`, `codewire/*` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-016.md` | doc | HLR-171 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-8b/*` | generated | HLR-171 | transcripts (evidence digest table at the end of §4) |

## 3 · How to test

```bash
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
# new and touched requirements (the 31-module set of green-01 / green-cp1):
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_project_homes.py tests/test_b100_save_image.py \
  tests/test_b100_save_guards.py tests/test_b100_document.py tests/test_b99_load_project.py tests/test_project_gather.py \
  tests/test_tui_workspace.py tests/test_tui_workspace_insight.py tests/test_tui_workspace_layout.py \
  tests/test_workspace_variants.py tests/test_tui_app.py tests/test_b100_reuse.py tests/test_b99_staging.py \
  tests/test_id_registry.py tests/test_b100_active_variant.py tests/test_b100_announce.py tests/test_b100_focus.py \
  tests/test_b100_project_check.py tests/test_b100_session_reset.py tests/test_b97_load_project_dialog.py \
  tests/test_b99_patch_truth.py tests/test_report_progress.py tests/test_tui_commandbar.py tests/test_tui_helpers.py \
  tests/test_tui_manifest_save.py tests/test_tui_patch_variant.py tests/test_tui_report_filter_surface.py \
  tests/test_tui_report_seam.py tests/test_tui_report_view.py tests/test_tui_variants.py tests/test_variant_execution.py
# guards:
python -m pytest -q -p no:cacheprovider tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py \
  tests/test_batch91_registry_hygiene.py tests/test_address_census.py tests/test_engine_unchanged.py
# reviewers' probes (unedited): evidence/inc-8b/review/test_r8b_probes.py, test_r8b_probes2.py, test_r8b_probes_r2.py
# security probes: evidence/inc-8b/security/*.py (common8b.py on PYTHONPATH)
# mutants: evidence/inc-8b/mutation-summary.md (85 rows) + cp1 MC01–MC15
# NOT run per increment (operator ruling): the reverse census and the full suite -> batch-end battery (§7)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-8b/`. **Final source hashes** (sha256[:16], printed in the header of every cp1 transcript): `app.py` `87c7f9d74909138c` · `project_gather_service.py` `524c3409037cae26` · `workspace.py` `d9f361f3fb092ae2` · `screens_directionb.py` `e94f8e764f950b1a` · `variant_execution_service.py` `8a38dde7fcd14211` (pre-cp1 hashes: `b75f9125c9eb12c1` · `7f1ecfefde90ee6b` · `d9f361f3fb092ae2` · `e94f8e764f950b1a`; the 5th file was `699c38bd2cce77cd` before F2; base `ebe6d0c`). Import proof in every header: the worktree's `s19_app\__init__.py`; `NO_COLOR` unset.

**Scope (operator ruling, carried from Inc 8a):** new and modified requirement tests, the modules that exercise the changed functions, and the guards. No reverse census, no full suite. The runs below are exactly that and no more.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | TC-B100-31 (LLR-171.1j/.1k, .1l/.1m, .1n/.1o/.7c, .7/.7a/.7b) · TC-B100-32 (LLR-171.2f/.2g, .2h) · TC-B100-33 (LLR-171.3/.3a) · TC-B100-59 (LLR-167.6a–g) · TC-B100-62 (LLR-171.4c/.4e–.4h) — `tests/test_b100_project_homes.py`, `tests/test_b100_save_image.py` | `executed` — E4 integration `green-01`: **1051 passed, 4 failed, 1 xfailed** (`green-01-new-and-touched.txt`, 56:01); the 4 failures: 1 timing under load re-run alone (`green-02`/`green-03`), 1 re-pinned (RP-5), 2 pre-existing at base (`test_at_b78_03`, `test_at_056e_a2b` — `base-01-two-failures.txt`). After cp1 on the final bytes: **1069 passed, 4 failed, 1 xfailed** (`cp1/green-cp1.txt`, 62:01) — 2 base-known + 2 timing under load, re-run alone: **2 passed** (`cp1/green-cp1-timing-alone.txt`, 8.71 s) |
| **B · black-box** `AT-NNN` <-> story | `core` · `full` | AT-B100-09 (save-as → Q → flow list), AT-B100-10 (A2L-only Save → Load), AT-B100-11 (listing and Save refusal) | `executed`: AT-B100-09/10/11 nodes in `green-01`; RED `red-01-vs-base.txt` 57 failed, 8 passed vs base |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| E4 tester's nodes vs base `ebe6d0c` (tester's 65 nodes, RED 57F/8P) | `red-01-vs-base.txt` | **57 failed, 8 passed, 63 deselected** (5:48, run on Python 3.12.7 in the base worktree). 52 behavioural failures + 5 import failures on new symbols; the 8 passes are boundaries/controls that hold at base. An earlier superseded run is `red-00-vs-base-superseded.txt` |
| cp1 arms on the pre-cp1 snapshot | `cp1/red-cp1.txt` | **13 failed, 4 passed, 70 deselected** of the first 17 selected, each on its own assertion; the 4 passes by design (the "present" negative control, the `con.json` end-to-end node — path already working, P-2 — and the M24 / M35 mutant-killing nodes). Appended after the operator's approval: the F2 node, **1 failed** (painted `replace the file, or Save project to drop it`) |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| the save-as copy tree | `red-01-vs-base.txt` fails on base: the sub-folder files, the links, the top-level files and the ceilings are all absent at base; each behavioural node has its own mutant |
| the free-space boundary | the total is computed independently by the security probe (90 112 = the sum, each size rounded to 4 KiB + 65 536); M15–M21 RED on the rounding and the margin |
| the entry ceiling before sorting | the new node spies on the walker module's `sorted` and the yield count (MC14 = M35 again: KILLED, no wall-clock bound) |
| the rollback identity / reparse checks | MC08 (both checks), MC09 (reparse), MC10 (identity) RED; MC10 re-run after its node's `is_file()` assertion was tightened |
| the painted next step | the probes assert the defect text, so a failure means the defect is gone (P-1 / P-3 / P-4 fail on the final bytes) |

### Mutation verdicts (C-40)

**E5 run on the copy tree `mut8b`** (`mutation-summary.md`; every transcript `mut-<id>.txt` ends `restored = True`): **85 rows total = 72 run in this pass + 13 skipped (already killed at E4 integration). 69 KILLED, 3 SURVIVED, 0 INVALID.**

| Verdict | Mutants | Disposition |
|---|---|---|
| KILLED | 69 | each failure line read for a behavioural assertion, not only the return code |
| SURVIVED, wrong target | M24 (LLR-171.1g: the behaviour is gated in two files, and the planner merge arm was masked by the fixture's own A2L clash) | re-killed in cp1: MC13 KILLED (a new planner node passes no file row) |
| SURVIVED, weak test | M35 (R16: removing the early stop still finishes under the 5 s wall-clock bound) | re-killed in cp1: MC14 KILLED (a `sorted` spy + yield count, no wall-clock bound) |
| SURVIVED, equivalent | M46 (LLR-171.2c: `_variant_set` left `None` on the A2L-only branch has no observable effect — the next data-file load rebuilds it from disk before `active_variant` is written) | kept as equivalent (`E5-cp1-notes.md`) |

**cp1 run on the final tree** (`mut-cp1-MC01.txt` … `mut-cp1-MC15.txt`, copy trees `cp8b-1/mutA|mutB|mutC`): **15 of 15 KILLED, 0 SURVIVED, 0 INVALID**, all `restored = True`. Mutants covered: F1 (MC01, MC02), F2 (MC15), F3 (MC03), F4 (MC04), F5 (MC05, MC06), F7(a) (MC07), SEC8b-1 (MC08, MC09, MC10), SEC8b-2 (MC11), SEC8b-3 (MC12), M24 again (MC13), M35 again (MC14).

**Not claimed:** the 72 E5 mutants ran on the pre-cp1 bytes; the 15 cp1 mutants cover what cp1 changed. The 72 were not re-run on the final tree (M24 / M35 were, as MC13 / MC14).

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| `project.json` (save as) | parsed with the stdlib `json`; `batch`, `assignments`, `declared_regions`, `gathered`, `active_document`, `derived_from` equal to the carried records as project-relative strings; a linked `P/project.json` carries nothing (SEC8b-3 arm) |
| the copied tree | Q's tree compared byte-for-byte against P's link-free listing (0 missing, 0 differing SHA-256); the security probe confirms 0 reparse points and 0 outside bytes in Q |
| the status line / panel | painted `#log_line_*` / `#result_body` / `#loaded_panel` renders; 0 issue codes, 0 class names, 0 `WinError` / `Refusing` / `errno`, 0 Cc/Cf/Zl/Zp/Cs characters |

### Guards and snapshot cells

| Run | Transcript | Result |
|---|---|---|
| guards on the integration bytes | `guards-01.txt` | **74 passed, 1 failed; 29 snapshots passed, 0 cells changed** (2:17). The failure was `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` on the tester's `query(projects.LOAD_RESULT_CLOSE)`; fixed, re-run `guards-02-after-selector-fix.txt`: **24 passed** |
| guards on the final bytes | `cp1/guards-cp1.txt` | **75 passed, 29 snapshots passed, 0 snapshot cells changed** (2:52) |
| the census sweep (`-k census`) | — | **not run** (operator ruling; batch-end battery) |

### Reviewers' probes on the cp1 tree

`cp1/probes-cp1.txt`: the reviewer probes **4 failed, 3 passed** — they assert the defect, so a failure means the defect is gone (P-1 D-3 now paints `replace the A2L file, then Load again`; P-2 passes, that path already worked; P-3 I-2 the A2L detaches with `Unloaded A2L.`; P-4 F1 both saves complete and the missing-folder line is painted; P-5 R-7 not reproduced). The security probes B3, B7, E1 run in the same transcript: B3 `R user files deleted by the rollback: []` with the `Not removed after the failed save` line; B7 both swaps refused `changed while saving`, Q absent; E1 `Q batch: []`, the outside value not carried, the link line names `project.json`.

### Security probes

`security/out_A.txt` (links at depth, hostile carry, rebind), `out_B.txt` (swaps B1/B2/B6, rollback B3, mid-copy fault B4, target-appearing B5), `out_B7.txt` (SEC8b-2 P-swap), `out_C_134.txt` / `out_C_256.txt` (ceilings, depth, cap, free space), `out_D_135.txt` (unreadable/reserved entries, list/load/Save target, TOCTOU after load), `out_D_2.txt` (foreign-parent spellings), `out_D_64.txt` (A2L guard, `painted_names`), `out_E.txt` (SEC8b-3 linked `project.json`). Full per-question results are in `security-increment-016.md`.

### E13 (C-UX-5) evidence

Orchestrator-owned captures, real Windows Terminal: scenario `pe-a2l-only` (open + closed) x 3 sizes (118x54, 220x60, 99x54) = **6 PNGs** in `evidence/inc-8b/e13/`, failures=0 (`E13-notes.md`). D-5 (AT-B100-10) renders at 220x60 (`A2L  firmware.a2l  3 tags`, `S19 (none)`, `MAC (none)`); at 118x54 and 99x54 the panel is in the compact two-row form and the A2L appears only in the status bar — OBS-8b-1..3 routed to the backlog.

### Experiment step table (from `inc-8b/steps.log`; UTC)

| Start | End | Step | Agents | Outcome |
|---|---|---|---|---|
| 2026-10-31 01:26:46 | 01:33:37 | E2-baseline | 1 x Opus | graph 23 nodes, extractor exit 0, 6 candidates C1–C6, 9 requirement notes |
| 01:26:46 | 01:38:14 | E1 | 1 x Opus | 6 requirements (~20 clauses) → 35 single-shall (event 10, state 3, ubiquitous 6, unwanted 16), LED .76, slice 9–16 nodes, 11 open questions |
| 01:39:19 | — | E1-rulings | orchestrator | Q1–Q11 decided |
| 01:39:49 | 01:44:37 | E1-apply | 1 x Opus | rulings applied (LED .77): 37 single-shall, slice 10 firm / 17 max, 2 groups |
| 01:45:24 | — | E2 start | orchestrator | interfaces-8b.md fixed; 2 x Opus G1 app, G2 gather |
| 01:45:51 | 01:57:32 | E2 | 2 x Opus parallel | G1 app 7 nodes / 79 ex, G2 gather 11 nodes / 57 ex; 25 design risks, 11 interface proposals; both found the missing copy list |
| 01:58:50 | — | E3-prerulings | orchestrator | 11 rulings; E3 r1 start |
| 01:58:55 | 02:10:42 | E3-r1 | 2 x Opus | architect FAIL (3 MAJOR incl. C-7 confirmed pre-existing; 14 MINOR/LOW), security FAIL (1 MAJOR copy unbounded; 3 MINOR 6 LOW) |
| 02:11:46 | — | E3-rulings | orchestrator | R1–R9; design pass 1 start |
| 02:11:50 | 02:34:51 | E3-fix1 | 1 x Opus | R1–R9 + accepted items; `workspace.py` becomes the 3rd source; app 117 ex, gather 80 ex; LED .78 |
| 02:35:57 | — | E3-r2 start | orchestrator | R10–R12 |
| 02:36:01 | 02:44:00 | E3-r2 | 2 x Opus | architect FAIL text-only (1 MAJOR R11 not written, 3 MINOR 2 LOW), security PASS-WITH-NOTES (3 MINOR 3 LOW) |
| 02:43:24 | — | E3-fix2 start | orchestrator | — |
| 02:43:28 | 02:53:37 | E3-fix2 | 1 x Opus | 12 items + R13 applied (LED .79); G1 127 ex, G2 90 ex |
| 02:54:14 | — | E3-r3 | orchestrator | architect verify A3R2 lines |
| 02:54:19 | 02:58:00 | E3-r3 | architect verify | PASS-WITH-NOTES (1 MINOR, 1 LOW) → PDR approved; R14–R16 addenda |
| 02:59:02 | — | E4 start | orchestrator | G1 app, G2 gather+workspace, tester |
| 02:59:00 | 03:34:00 | E4 | 3 x Opus parallel | G2 gather+workspace 15 min, G1 app 35 min (2 000-file save-as 14 s main thread; entry ceiling 0.97 s), tester 32 min (65 nodes, RED 57F/8P: 52 behavioural + 5 import; 75 mutant rows, 11 test gaps) |
| 03:35:42 | — | E4-integration start | orchestrator | rulings D-5 (`screens_directionb` 4th source), D-3 (composer step) |
| 03:35:47 | 04:47:46 | E4-integration | 1 x Opus | D-5, D-3, 5 re-pins, 13 gap nodes + 13 mutants killed; GREEN 1051 passed (2 base-known, 1 timing re-run ok, 1 re-pinned), guards 0 cells changed |
| 04:48:28 | — | E5 start | orchestrator | mutants DeepSeek v4 Pro via pi (copy `mut8b`); code + security review Opus |
| 04:49:11 | 05:27:12 | E5-mutants | 1 x DeepSeek v4 Pro (pi) | 72 run → 69 killed, 3 survived (1 equivalent, 1 weak test, 1 wrong target), 0 invalid; all restored; spot-check 4/4 valid |
| 04:49:00 | 05:04:00 | E5-reviews | 2 x Opus | code FAIL (1 MAJOR design-gap F1 absent source folder; 3 MINOR 3 LOW), security PASS-WITH-NOTES (1 MINOR rollback via junction, pre-existing since Inc 2; 2 LOW) |
| 05:27:59 | — | E5-cp1 start | orchestrator | F2 5th source pending operator |
| 05:56:04 | — | operator approval | orchestrator | 5th source file (`variant_execution_service.py`) approved for F2 |
| 05:28:04 | 07:01:22 | E5-cp1 | 1 x Opus | F1, F3–F7, SEC8b-1..3, M24/M35 + F2; RED 14F/4P by design, 15/15 mutants killed, GREEN 1069 passed (2 base-known, 2 timing re-run ok), guards 0 cells changed; LED .80 |
| 07:01:22 | — | E5 cp1 end | Opus | 11 items + F2; 15/15 MC killed; GREEN 1069p/4f; guards 0 cells; ~93 min vs 60 timebox |
| 07:05:50 | — | E13 | orchestrator, Opus | `pe-a2l-only` captured 6/6; OBS-8b-1..3 MINOR → backlog |
| 07:12:23 | — | close records start | DeepSeek v4 Pro via pi | — |

First step start to the last logged step: 01:26:46Z to 07:12:23Z = about 5 h 46 min wall. Raw facts for the operator's comparison (per `PLAN.md`): **E3 (design, no code) caught 4 MAJOR in round 1 (A3-1, A3-2, A3-3, S3-1) and 1 MAJOR in round 2 (A3R2-1), 0 in round 3; E5 (code) caught 1 MAJOR (F1, tagged design-gap) and 0 HIGH; 1 corrective pass; 0 full-census launches.** The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59); full SHA-256 of the staged blobs

The 16-hex prefixes below are the precomputed `digests-8b.md` table verbatim (the staged blobs equal the disk bytes on this checkout, so the full digests extend those prefixes).

| Artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-8b/` | SHA-256 |
|---|---|---|
| base-01-two-failures.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/base-01-two-failures.txt | a382e57a21d13d5080cb2eafe13a336fca7ffeddfdf800b099c81f3a33dd75b9 |
| green-01-new-and-touched.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/green-01-new-and-touched.txt | ca4e45d35c3e9decf44908955deecb3dc7d114d117daae9b03dfb28059ddce6c |
| green-02-repin-and-timing.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/green-02-repin-and-timing.txt | 21987074a778cd3ee49eaed5d3cb01d2971e3b8f17b8c3b4cfbaa3d0896705c4 |
| green-03-timing-alone-2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/green-03-timing-alone-2.txt | 8aaeab44789c7a0db25d88bef74042af3f0f648d337a005fe2350a5f34ada578 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/guards-01.txt | e8abbad9a89fbeba851629559541723ef8415f23ccf74661608ebb50798a2689 |
| guards-02-after-selector-fix.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/guards-02-after-selector-fix.txt | 13a5261d57ea57a9d997d5db5456e8705257c8690ce138524863e8132d54ed53 |
| mut-M01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M01.txt | 189d0ee38634a7bd048beaed66b65a7ab40e9db542786412ad847f0e7d1dfef6 |
| mut-M02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M02.txt | 8bcc57122a2043ab48773a6f599321eda3485215e78394fb8e5f7df9f46ccb29 |
| mut-M03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M03.txt | c80d4f07d452baf11e7c32da37aded7eec137e485c98c295e53d65d7b7340f41 |
| mut-M04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M04.txt | 5151a5a4b1a343fc56468d8813ed0d70775ac6fb1a675db3cac4f91040afec9c |
| mut-M05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M05.txt | 0cc1ca5bfe25f20d489aae5d1a8588dc3e4a03cd896bb87f1e4044fb9c2268b1 |
| mut-M06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M06.txt | 31a0369faa8d05eece36714393311ec8d58bd34d509502b209dcc6357e11426f |
| mut-M07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M07.txt | f8dc7060a10d7e13e2e1d641a867238f546b38a819e925ed5167b3d33ebfcb24 |
| mut-M08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M08.txt | 08cc9d3a3c6915cff6a52cbbf3a8d6a898f143c72d86dda82544e71ea68e8047 |
| mut-M09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M09.txt | b9976082fb700ce9ead86977c97858d27c13fc95d8c54419a35c158d2e68ef1e |
| mut-M10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M10.txt | 56140eeaefbf5aecc48d6e15981f362f040029dd95be0c70ef6eb63c4bcb7f5b |
| mut-M11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M11.txt | 73f10dc07b4e4c3f335f8c34f22b070941297d981ea88d0ed9c7d996a7ea8898 |
| mut-M12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M12.txt | 39b37486d740a873fa71589018aa3582e4c28823d86fcc5afbc7a383f896f94d |
| mut-M13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M13.txt | 4ec72b96b0dfa5d9b9155e8a2b4f921c2854adfa6e24894dbdf981ebc64b9685 |
| mut-M14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M14.txt | 8834a9218c10790327b24e2f1cddfc1894d7c7c81b729a18a354ea0e17b185ba |
| mut-M15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M15.txt | 72cb956c4bab2fe5d319059d3f315c2ad1a593d28ee58f943048c64ffb4ad753 |
| mut-M16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M16.txt | b9d85389e14f7818f84fe85f401b0e19065641704d76069bba0a6674e885d608 |
| mut-M17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M17.txt | 39bac4313fbd8e1dfe5c685cf043204e978628679081532c4bee3d2a30bc691b |
| mut-M18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M18.txt | 77547fa09123ffc15c3174b883d3ebafddc61adaf02582d0479a213354357f12 |
| mut-M19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M19.txt | 50ddd1a86e24ca5b4806d8af6a3e95ecf8920a0fa4a47110fbd2cb1851d67b5c |
| mut-M20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M20.txt | 33092cdbaa1d06907255dc93174a9bb82eaeaf40cef6c3aac94e7dec9eedf9a4 |
| mut-M21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M21.txt | 7c741fb57b178cc3afb6dbb6247b56d8d38909b15f69a40d738e1f3c97346409 |
| mut-M23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M23.txt | b0cf6a78c0c1503038ac30bcaf0a90c7438335220322f07e390da650d38d6255 |
| mut-M24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M24.txt | 3e8b2bc59254591dd315c3a9285a88a7fe89588a73d7486a713c0744561dce70 |
| mut-M25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M25.txt | a5e32c287c48ce5c5b201541d120890658e44568d2ff68bdd1c4bd40d40fefdf |
| mut-M26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M26.txt | 3dc912ab774ed01e1c96b7a7448197118b2fad55869a4d2a13940c509cb1608f |
| mut-M27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M27.txt | 39ac3d862ac30a39160e402687b89a6195c786f3f76186b0f73a5403d8fd5173 |
| mut-M28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M28.txt | 1ee6e0432ed20fa43b7131fe43b2b31676387f57ca760c5fb8ba45fb2a1af7ab |
| mut-M29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M29.txt | 6be127f2845fbd848930e94fb133e6b19b86834dbab927385d1c9ebd9a5574d7 |
| mut-M30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M30.txt | a5f6b4410bcbd028fac914ff1344ab4919fc26b66dc69d729b6027c57b297817 |
| mut-M31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M31.txt | 3a7c9005bf5c1be1ae0b7290a3f3e7eacd511cd0ee409d5e0b5430b66fcd1bfd |
| mut-M32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M32.txt | a0bdce09af6cd10452b23500a54e552670e5eed797fe7a691231363fe2e84b6a |
| mut-M33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M33.txt | ee8b72c7ef666c6aa645e48fbb7ce49e4c5414f333ca9243fe66f5942dd81794 |
| mut-M34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M34.txt | c7dc6ea1dca6b6418a67e070891ceed2f7440578bf5e6fc0c9fdd59b2e2c1cca |
| mut-M35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M35.txt | 7ef791e5e670b40ebd1bbb22798aecb26e293b131079e9dee77801df508f09cd |
| mut-M36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M36.txt | ca83a110d326a9294cf421422b9bfeb339dacf3e4ec78d0395f09214192bd9b9 |
| mut-M37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M37.txt | 7384f03e2b5781707df616d067fbfa2ea836180a37bc534667ebb098f884904f |
| mut-M38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M38.txt | db6eea5d6d4b42bed68e2c8c69a7743cf83f38c4b194fef512ceef837ed26393 |
| mut-M39.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M39.txt | 7f678d923f3dae8294ce43fdf6b951ce81baac8448793fc2f46f579259d5348c |
| mut-M40.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M40.txt | 9cea09eed859f78656a90f91b261a1edb48251b5460547d1bc39f2960c71848b |
| mut-M42.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M42.txt | e52628b8d5087fa1c4ba0b33662b2ff7dac79174f7b924440689f154add79aba |
| mut-M43.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M43.txt | e4624e1def7cbbbb37f31fab2f59013c1620e1fbc2b8eda536fedea81315960e |
| mut-M44.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M44.txt | 02c898a2fb1a14bc3150ba59da7395fc31eac9a64a5b2f7824268dd017a33040 |
| mut-M45.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M45.txt | 4c7e94e22b8cd4e7903dee799c2631384faa5ae08a8ea52a2c26b785d3166a25 |
| mut-M46.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M46.txt | 4a17e35d7b8f07320433dc375553ceec5cf80fc48f2966d8d7e7f06e3318d72e |
| mut-M47.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M47.txt | aef0ced6fb7672ffaaa829dc6747319f4979f142d2dbe5130cbd328d00122080 |
| mut-M48.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M48.txt | 391b10aa7edd1efe08c5a8138593401d9c2e2b7835333c231356e81bed8f1cac |
| mut-M49.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M49.txt | 2c9b45a28dbfbea349132ebd67f7642559f64731649e8ab0106843b4dd2f57b4 |
| mut-M50.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M50.txt | 30022e32e5d474ac4fe1344a7781bad2dd7af8301b3a59b8e7da871ff23fd337 |
| mut-M51.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M51.txt | 45861f340774278e8973895e69aaf85890c4ee969dbe5cc5cc852635714b0970 |
| mut-M52.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M52.txt | 35b09a36a4592af0e7a3d55f10fbda4256d971afc0bad61eed8c01ee5eaa09a6 |
| mut-M53.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M53.txt | 51fb8fa1b33cfeb5565f75f9e69725d9fcbe218f08376f232febb32e0ce68de8 |
| mut-M55.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M55.txt | 1a5a2383fc10921b942c2d5b979dc352faa22ec430a83c0bc35928e2c2f2f861 |
| mut-M56.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M56.txt | 19ded3930d42f13e2f9d4fb58a0ad7c98e28fc5c9d8595f3e82e84f244e98e50 |
| mut-M57.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M57.txt | 4dcc3ed7beb0c1c7feccd8fdf9c1fc54b3d6f45068353ab52614bb3e43539ef5 |
| mut-M58.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M58.txt | 58add7217469fc846042f5dcfe3a5df5ddcbff7cb089256aabd82e3dffa5acb3 |
| mut-M59.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M59.txt | 278be668a8285dbeab62d6b0b8c8494867143b04c084980ce6c0afc3c2648a23 |
| mut-M60.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M60.txt | be9b0ddee97780364898abfb9d313f066db96fdcacce49ad736b680910296946 |
| mut-M61.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M61.txt | 3c136ed9190b6448876f978fa101ca9a643b25bd9e3941decb07687422dc9454 |
| mut-M62.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M62.txt | 3445d691ae665d02282057a734953464822ceabdfb3af38e59bdd8d2fcd50a64 |
| mut-M63.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M63.txt | 61240e594951d183bbf9659560bd3051b7284edccb5224c7181ea12ff133856f |
| mut-M64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M64.txt | 7ae2a7855f34123b9761d473092d1bbebdb48cc58d4a32b0052aceecbb4dc65b |
| mut-M65.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M65.txt | ffcade33b8213f1232e226279b7c96db9d2d8508db6af1b3792586fecf9c74af |
| mut-M66.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M66.txt | e37261b9414020f92eb590f6dd586b4d4c5dd1ab0595b214e17042c345bb2f71 |
| mut-M67.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M67.txt | 7a2962dd7ba15b9c93b53a8844a10ab92b181755567efdccaa23522b89e06247 |
| mut-M68.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M68.txt | 0018a7ad875fc989d98f98125d509e5519d00dc9c70430b7cd2ca94b114ad319 |
| mut-M69.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M69.txt | 3eec714858411336d6766e8337abd96ef0a7edaf0addd23acbe771be301df72f |
| mut-M70.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M70.txt | e7b7b4a0887740255150bf3fc4dd02356dd528a7353aac4cc2fb69fd1e01632b |
| mut-M71.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M71.txt | 81123412f20818ea318a864f94357f7b89b78819f66076d9ce9032dca7cd293d |
| mut-M72.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M72.txt | a17d783af0be53c8ddf7f2206e1130f927fe17bd21ea5f00d503f767efe53986 |
| mut-M73.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M73.txt | ae7ed56d29d14623bf4a5db852c61a3b1af91c4e418482fd49db733df1eda83e |
| mut-M74.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M74.txt | e99dfb71b14b14dca9b27dea6619052be773bebd7394e5fc237d538ed54ab687 |
| mut-M77.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-M77.txt | 211af1fd0b23f8f31f7d4bb67b54b3fcdbd0f872670c8ac6f00659ecb8b80c02 |
| mut-cp1-MC01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC01.txt | 1d96548c8945a47014a218e566700bb5019c40bb3a1eeadad7942eec1730222f |
| mut-cp1-MC02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC02.txt | cfd8de3927066f1d5dee088037506810664f4d32b3808408edbc28ba9e839796 |
| mut-cp1-MC03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC03.txt | 60bf896d6bee1ab357fae4e1d78250bafbf2d7d2e9d808ed3c7525f03ce035d3 |
| mut-cp1-MC04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC04.txt | c18906eb9beb13696f8c475f3805f8cb33dd1b340d627660793720919a423f4d |
| mut-cp1-MC05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC05.txt | 56e8ef5a006c0344c01c7faf05b4c74ae2f3de54f21fd45a6171d2fbded821a8 |
| mut-cp1-MC06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC06.txt | be1c5cca833985b6049304308d62ac6aede8930322e9380aff481dae418133d0 |
| mut-cp1-MC07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC07.txt | d70ac3338cb20c81ac4881efd7c524103c71e0a5aba258c955f792c3a8be9427 |
| mut-cp1-MC08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC08.txt | 95426cdc51dd7d5ae4d2b627b5a0e2d154024e0856f813e197c1d0cac6ef4534 |
| mut-cp1-MC09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC09.txt | 762d2afdcc7d09a4ebae8c070720c38ffaf6bf53012659d864844d3827dbffdb |
| mut-cp1-MC10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC10.txt | ea540909b3deeee65d3b9b8aeac4d381bb546d3d41d214eb890a2ac98a90d680 |
| mut-cp1-MC11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC11.txt | ed7a7a95257a929e1b22e3bd0f2521c4dc3a7dcb6a3b10c98a2d4fcd7b18b5d8 |
| mut-cp1-MC12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC12.txt | 99afe88be060ea9096f5a4193a309f67d5e5ec92429605677d731f7c2fe06779 |
| mut-cp1-MC13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC13.txt | 9464680ac54c8223a4a34d17eee7e29962d066540bc74e4b84dd974d479845c4 |
| mut-cp1-MC14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC14.txt | f6bc24829f04c23bdef610f6321b4ff4b4e59809d9e9344700e362d0618fbd14 |
| mut-cp1-MC15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mut-cp1-MC15.txt | cadcf2104053c51f64825504e556d8f4d6eb0b8c09272e229e4018ee0c937547 |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/mutation-summary.md | fcf98ca7ca1408a7a586d00c92d1fd43aee272e8c9377776af86a238f2be10c5 |
| red-00-vs-base-superseded.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/red-00-vs-base-superseded.txt | 4cb45783925928ab6838ca89021792505ca7e92d42b1a22a7108c56da97ea3da |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/red-01-vs-base.txt | 62f3ca372a446e3cf2b4a538e435bed9b2b8620f4e89e570bb6480d58531bbee |
| green-cp1-timing-alone.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/cp1/green-cp1-timing-alone.txt | 230c7ac0d4faca059d45d6e8543b74d93a6c630836d52e7260ab96810a0e5c1d |
| green-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/cp1/green-cp1.txt | f5b526f160cbe95d284a3c2e7501d598dc4f41d97a4f898fcc29e946511961f0 |
| guards-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/cp1/guards-cp1.txt | 4985fbb2de2e2f8d30b90441b931884d68e7280310049b500f4abbb2415de7b5 |
| probes-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/cp1/probes-cp1.txt | bdde45963e8b26c134e53efdfc44452fd92e9b3e257f00c0ca04889c5276953c |
| red-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/cp1/red-cp1.txt | 3279f376b3c30f8ab53a02fc8de367c0a6a6837277a5e55923b1cdf3a9d17aa7 |
| pe-a2l-only-closed.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/e13/pe-a2l-only-closed.118x54.png | 22a25b12874b588b7eef29ff3039af281c94911e46642324dcd3d6af465301ce |
| pe-a2l-only-closed.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/e13/pe-a2l-only-closed.220x60.png | 043ac9bb89dfe52efab612546cc90892d21ffff3e4aff6de68850e89d0825ef1 |
| pe-a2l-only-closed.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/e13/pe-a2l-only-closed.99x54.png | 0ad48ab2fda097dffacb2b8b58b25dfc5eed838e5fa993ed3afd105a23e1bb95 |
| pe-a2l-only.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/e13/pe-a2l-only.118x54.png | fd349f77bca213ecf3d79ebed610d15b1ff2e4cfa8358f96e2ae13078a5942e5 |
| pe-a2l-only.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/e13/pe-a2l-only.220x60.png | b8d5c6c1d3d91b1a74e5a680e71fca24b6f1925c42450390ec568dba365cc6e9 |
| pe-a2l-only.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/e13/pe-a2l-only.99x54.png | 27a7876adbcbf38608f37e0fcac1a0edef27332ba495038995710a886146c208 |
| probes-out.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/review/probes-out.txt | f07c3facc2913c2dc53f2c67651e64d68e4f86d0ae797407d825afb427629996 |
| probes2-out.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/review/probes2-out.txt | 90b956de6a748be7e0416f20b28020c1e558c1176d14f4f888c5a818fdbeea54 |
| probes3-out.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/review/probes3-out.txt | 7d7ce782007d63bf7792e24a836e349432843a9901982a20f16d357432afcc99 |
| r2-P4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/review/r2-P4.txt | 85360cb337fe85502866d734bda0fabf80daf18468e3fed17b6456857ace2e5e |
| test_r8b_probes.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/review/test_r8b_probes.py | 09e0bbc5d6c067650d32d13a4959c8364a93f2559f153018c81bfbbd35a2da40 |
| test_r8b_probes2.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/review/test_r8b_probes2.py | f9154f50ac1ac78ddbfe7eb5fe1c1836647ddebca051d44f405b3661a9679eaa |
| test_r8b_probes_r2.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/review/test_r8b_probes_r2.py | ca3c587998b1f0b44b10319fc9bea46d0f718b6b216b35bb9f0f795465f5544b |
| common8b.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/common8b.py | be94fe09164e6f71ca39f7bda857efd3a2cad2f7b4e3d7dfb87dddb33c96f54f |
| out_A.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_A.txt | bc6d36409ec3b2b9dba3ccfbb0e2f927b65098c4f0792ef377a67566ae762631 |
| out_B.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_B.txt | 489f261c441beeb95db0ae46c80b82c0d7ff6013fe858eeb28ee19cbf15ad33c |
| out_B7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_B7.txt | 7f6881e98c9bc18a15c68729aee462229fdb52c47aa6ef132ee898fe0cc7be44 |
| out_C_134.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_C_134.txt | 452055e72c285b0f964a95522e8afec22e3d388bd54793d0624c4e8d5ad132c2 |
| out_C_256.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_C_256.txt | b56b5dbc148e4fb1eb7f7739b19e6c4e5718572e02ee014d617fc0d9317c3b9f |
| out_D_135.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_D_135.txt | 5a27621b6ae01ad5b95b850d6dcf3a196b787c4b66a3e5dcb9a23ad04d546c8d |
| out_D_2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_D_2.txt | d34f0382636896acb9228aa2394d54a7cdfa33596bc76d427dd629182f2383a5 |
| out_D_64.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_D_64.txt | 4ebbdebed6d3e329741dc68de4c3aa4068f8ad763bf90f40a30f32db722e9f96 |
| out_E.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/out_E.txt | e9379de1e0f99bff30b9fb66b50d97ea90244eea4a574da0f1748ed809d18940 |
| probe_a_copy.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/probe_a_copy.py | 7372c382e501270de6b822054305cce532ec0f1d18336e39b00481ad50dbf375 |
| probe_b7_projswap.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/probe_b7_projswap.py | b7a19f683138ce614e6d9c21acabba7616af680ac3ce10d6958b61ad765b1274 |
| probe_b_swaps.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/probe_b_swaps.py | 9da42c0e7e9e8ca7636a5632a7d78382a272aeb105eab1fd1e5cd4c55fad920f |
| probe_c_ceilings.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/probe_c_ceilings.py | aa000517a87803d83489a776fcdb79ec387c063a61eaedbf1ff0f6a01fb9d151 |
| probe_d_folders.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/probe_d_folders.py | 6b974ecc3eb4a303eb49734a79245e18841888b763e4ca7af6bd222e446fb8e3 |
| probe_e_manifest_link.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8b/security/probe_e_manifest_link.py | 2b53bcf01987b4d6d1bf9dd6ee0df5050c5046126b6d871a6cfaecdaa7215616 |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · **round 1 FAIL (`BLOCK — BLOCK-UNTIL: F1`)** · **round 2 PASS-WITH-NOTES**. Round 1: F1 MAJOR (design-gap) — once the open project's folder is gone, every new-target save is refused with a false next step (P-4); F2 (D-3, false step), F3 (I-2, the A2L unload), F4 (I-1, LLR-171.5's example + token row 8's "too long" reason), F5 (deterministic plan/landing mismatch), F6 (wording drift), F7 (a) (misleading `"outside"` text) / F7 (b) (R-7 routed). Round 2 (narrow re-review of cp1): **F1 discharged** — the fix read on the diff (`_save_as_source_for`, `app.py:12103-12115`) and P-4 re-run by the reviewer (`r2-P4.txt`); F2–F7a, SEC8b-1..3, M24/M35 and `timing_bound` hold; new R2-1 LOW (`os.path.lexists` swallows `PermissionError` as gone — token row 9 unreachable), R2-2 LOW (the source predicate is evaluated twice) — both to the backlog. 0 HIGH open. — `review-increment-016.md`, transcripts under `evidence/inc-8b/review/`. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR, 1 MINOR, 2 LOW) — SEC8b-1 (design-gap: the rollback unlinks resolved paths, a Q folder swapped for a junction mid-save deleted 6 of 7 files of another project), SEC8b-2 (impl: the copier's source check is anchored on a moving `source_dir`), SEC8b-3 (design-gap: a linked `project.json` named "not copied" yet carried); SEC8b-1..3 fixed in cp1 (MC08–MC12 KILLED) and verified by the cp1 probes B3/B7/E1, **not re-reviewed**. — `security-increment-016.md`, transcripts under `evidence/inc-8b/security/`. **Design reviews (E3, code-free):** `architect` (3 rounds: r1 FAIL, r2 FAIL text-only, r3 PASS-WITH-NOTES) and `security-reviewer` (2 rounds: r1 FAIL, r2 PASS-WITH-NOTES) -> PDR approved (`inc-8b/E3-architect.md`, `E3-security.md`). **Orchestrator (2026-10-31).** Final source hashes `app.py` `87c7f9d74909138c`, `project_gather_service.py` `524c3409037cae26`, `workspace.py` `d9f361f3fb092ae2`, `screens_directionb.py` `e94f8e764f950b1a`, `variant_execution_service.py` `8a38dde7fcd14211` (the 5th, operator-approved for F2). Scope ruling in force (operator, 2026-10-30, carried from Inc 8a): per increment, the new and modified requirement tests, the modules that exercise the changed functions and the guards only; the reverse census and the full suite run once at the batch end. Rulings applied: R1–R16 (`inc-8b/E3-rulings.md`), the E4 integration rulings D-3 / D-5, and the cp1 findings F1–F7 / SEC8b-1..3 (LED .80). |

---

## 5 · Risks

- **No reverse census or full suite was run for Inc 8b** (operator ruling): a test outside the 31 modules that lists a project folder after a save as now sees the copied tree. The batch-end full battery is the check (§7).
- **The security review ran on the pre-cp1 bytes.** cp1 changed `app.py`, the gather and `variant_execution_service.py` after it (F1–F7, SEC8b-1..3). Their arms and mutants ran on the final bytes; no reviewer re-read them. The code reviewer's round 2 did read the cp1 diff.
- **The 2 000-file save-as runs on the main thread** — 14.0 s quiet (E4) / 17.8 s shared-CPU, with no progress and no cancel; closing the app mid-copy leaves a partial Q without rollback. Accepted by R1 / R12; the background copy with progress and cancel is Inc 12a.
- **`os.path.lexists` folds any `OSError` into "gone"** (R2-1): a permission error on `lstat(W/P)` reads as "not found" and the save proceeds as if P were gone. Rare input; no data harm (P is never read, Q gets only the session files). The F7(a) save-as source arm (token row 9 "could not be read") is unreachable on that path.
- **The save-as source predicate is evaluated twice** (R2-2): if `W/P` vanishes between the handler's and the planner's calls, the save completes with 0 copies and no line. Millisecond race.
- **The `lstat` → `read_project_manifest` window in the carry** (`app.py:9718-9721`) is the usual TOCTOU class; handed off from the code reviewer to the security reviewer (not re-checked after cp1).
- **M46 is an accepted equivalent mutant** — `_variant_set` left `None` on the A2L-only branch has no observable effect (the next data-file load rebuilds it from disk before `active_variant` is written).
- **AT-B100-09/10/11 are black-box nodes** through keys and dialogs at 118 and 220; their limits are the panel-cell reads (RP-4) and the two compact-panel observations OBS-8b-1 / OBS-8b-2 (backlog).
- **POSIX and Python 3.12 were not run** for the 8b arms (the E4 RED run used Python 3.12.7 against the base tree; the GREEN and guards runs used Python 3.11.15); Windows junctions, symlinks and held files ran on Windows 11 / Python 3.11.15. The 8.3 short-name and `subst` arms ran here and were removed after.
- **Two known pre-existing failures** stay red at base and in every GREEN run: `tests/test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` and `tests/test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection` (`base-01-two-failures.txt`).

## 6 · Pending items / spec deviations

**Backlog added at the close** (`.dev-flow/BACKLOG-CODE.md`, each with its evidence path): R2-1 (save-as source `os.path.lexists` treats `PermissionError` as gone → false "was not found"; token row 9 unreachable), R2-2 (handler and planner compute the save-as source separately), the SEC8b-3 TOCTOU hand-off (`_manifest_is_link` then `read_project_manifest`), OBS-8b-1, OBS-8b-2, OBS-8b-3 (from `E13-notes.md`), R-7 (F7 b — already routed), the device-stem `batch` entry (F4 side note — already routed), the F5 plan-prediction remainder (already routed), A3-15 (Execute next step on an A2L-only project), A3-17 (a MAC appearing mid-save), and the background copy with progress and cancel (→ Inc 12a).

**Named gaps / observations.** M46 is an equivalent mutant (recorded, no fix). The 2 000-file save-as on the main thread is the R12 cost, accepted; the background copy is Inc 12a. LLR-171.4h (8 named writers, 16 + 8 junction arms) was not written at E4 (ruling 5); the Inc 1 arms stay. Q11 (Execute on an A2L-only project, crash check) was not written (A3-15 backlog). The `red-01-vs-base.txt` run used Python 3.12.7 (the shell's `python`), the GREEN/guards runs the s19env 3.11.15 interpreter — recorded, not a deviation.

**Finding → disposition (E3, code-free design review).**

| Finding | Severity | Disposition |
|---|---|---|
| A3-1 (pasted document placed before the sub-folder copy → clashing document aborts), A3-2 (carried `batch`/`assignments` name top-level files a save as does not copy), A3-3 (C-7 confirmed: Save project writes the empty selection over `batch`/`assignments`) | MAJOR | R2, R3, R4 (LED .78) |
| S3-1 (the save-as copy is unbounded: ~6 min for 20 000 files) | MAJOR | R1: LLR-171.1j ceilings (LED .78) |
| A3-4 … A3-17, S3-2 … S3-10 | MINOR / LOW | accepted as written or ruled (R5–R9; A3-15 / A3-17 to the backlog) |
| A3R2-1 (R11 not written; the rows loop also executes the carried rows) | MAJOR | R10/R11 written (LED .79) |
| A3R2-2 … A3R2-6, S3R2-1 … S3R2-6 | MINOR / LOW | R13 (entry ceiling), the accepted text edits; security minors verified at E5 |
| A3R3-1 (the total counts each top-level copy twice), A3R3-2 | MINOR / LOW | R14 (`total_bytes` leaves carried rows out of the row sum), R15 (`painted_names` in the step-12b line) |

**Finding → disposition (E5, code).**

| Finding | Severity / tag | Disposition |
|---|---|---|
| F1 absent open-project folder refuses every new-target save | MAJOR / design-gap | fixed in cp1 (`_save_as_source_for`); LLR-171.1n; MC01/MC02 KILLED; discharged in r2 |
| F2 (D-3) composer step false for the A2L row | MINOR / design-gap | fixed (`STEP_REPLACE_A2L`, 5th source, operator-approved); MC15 KILLED |
| F3 (I-2) A2L unload paints "Nothing to unload." | MINOR / impl | fixed (`_apply_unload`); MC03 KILLED |
| F4 (I-1) LLR-171.5 example unreachable; token row 8 "too long" reason has no rule | MINOR / design-gap | requirement re-worded to the CRC template; MC04 KILLED |
| F5 (a)/(b) deterministic plan/landing mismatch, false "save again" | LOW / design-gap | true step for the repeating mismatch; rebind to the gather's landing; MC05/MC06 KILLED; the plan-prediction remainder to the backlog |
| F6 wording drift + duplicated constant | LOW / impl | `PAINTED_NAME_LIMIT` one definition |
| F7 (a) permission error painted "outside"; (b) R-7 unruled | LOW / impl + design-gap | (a) `"unreadable"` reason, MC07 KILLED; (b) R-7 routed to the backlog |
| SEC8b-1 rollback deletes through a swapped folder | MINOR / design-gap | fixed (`_PlacedFiles` identity + reparse walk in `_abort_save`); LLR-171.7c; MC08/MC09/MC10 KILLED |
| SEC8b-2 copier source check anchored on a moving `source_dir` | LOW / impl | fixed (`_path_traverses_reparse_point(source, stop_at=workarea)`); LLR-171.1o; MC11 KILLED |
| SEC8b-3 linked `project.json` named "not copied" yet carried | LOW / design-gap | fixed (`_manifest_is_link`); LLR-171.1h arm; MC12 KILLED |
| M24 / M35 (E5 survivors) | — | re-killed in cp1 (MC13 / MC14) |
| R2-1, R2-2 (round 2) | LOW | backlog |
| M46 | — | equivalent, recorded (no code change) |

**Orchestrator rulings R1 – R16** are in `inc-8b/E3-rulings.md`: R1 file/depth ceilings before any folder · R2 sub-folder copy right after `mkdir` · R3 top-level files copied · R4 `batch`/`assignments` = dialog selection when non-empty · R5 one `lstat` + cap before the A2L load · R6 painted names (10 names, 120 chars, scrubbed) · R7 free space rounded (4 KiB + 64 KiB) · R8 unreadable/unclassifiable entry refuses · R9 the session follows Q · R10 every other MAC/A2L left out, `project.json.previous-*` not copied · R11 top-level copy after the rows loop · R12 the 2 000-file ceiling stays, background copy → Inc 12a · R13 the 10 000-entry ceiling · R14 `total_bytes` counts carried rows once · R15 the step-12b line through `painted_names` · R16 the nested fixture and the 5 s bound. E4 integration rulings: D-3 (the A2L problem's bare reason + composer step), D-5 (`screens_directionb` 4th source, the A2L slot).

**Re-pins (test::node — old -> new — requirement).** RP-1 `test_tc_b100_59_gather_service_imports_no_change_module` import set + `stat`, `unicodedata`, `..` (still 0 change-module imports) · RP-2 `test_tc_b100_69_*` SEC-4 junction save-back re-routed through a post-load swap (LLR-171.4e) · RP-3 `b100_projects._is_link` reparse attribute on 3.11 (the fixture followed junctions, so `free_space[T-1 refused]` counted 10 MiB behind the junction) · RP-4 AT-B100-10 reads the `#loaded_panel` `Static` cells (the container `render_line` paints only its background) · RP-5 `test_tc_b100_01_app_placements_name_the_workarea_root` 8 → 9 placement calls (the copier's one guarded placement). Removed: 0.

## 7 · Suggested next task

**Inc 9a of batch-100** with the `design-first-increment` pipeline (the typed project load arm LLR-172.5 and the T-11 placement-naming rule named in `BACKLOG-CODE.md` belong there). Carry into it: the batch-end full battery owed once (§7 of `increment-008.md`), unchanged.

**Batch-end full battery (owed once, when all increments are done — operator ruling 2026-10-30).**
1. the full reverse census / full suite on the final tree, every failure dispositioned against base;
2. the guards and the census sweep (`-k census`) on the final bytes;
3. the mutants of every increment re-run on the final tree where a later increment touched the same function (the 72 Inc 8b mutants ran on the pre-cp1 bytes; M24 / M35 re-ran as MC13 / MC14);
4. the CI run, comparing the FAILED set with the previous run and the known flake `test_tc_b97_64_a_new_set_run_restarts_the_dwell`;
5. a security re-read of the cp1 changes if the orchestrator wants SEC8b-1..3 re-reviewed rather than probe-verified.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4/4 at the cap (`app.py`, `project_gather_service.py`, `workspace.py`, `screens_directionb.py`) + a 5th (`variant_execution_service.py`) operator-approved for F2 on 2026-10-31 — §2 |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_project_homes.py` (NEW) + TC-B100-59 8b arms + `tests/support/b100_projects.py` builders + `tests/support/timing.py` — §2, §4 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `inventory_project_tree`, `painted_names`, `walk_tree_no_links(max_entries=)`, `_second_file_refusal`, `_plan_copies` |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01-vs-base.txt` (57 failed, 8 passed vs `ebe6d0c`); `cp1/red-cp1.txt` (13 failed + 4 passed, plus the F2 node 1 failed) |
| 5 | Reverse census declared | `core` · `full` | ⚠ | **not run per increment — operator ruling 2026-10-30, batch-end full battery** (§7). The 31 modules of `green-01` / `green-cp1` and the guards ran |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES r2 (r1 FAIL `BLOCK — BLOCK-UNTIL: F1`); the cp1 diff was read in round 2 |
| 7 | No file from another lane touched | all | ✓ | the 5 named sources + tests / fixtures / config / records; `tools/e13/` is the orchestrator's; `prototypes/` untouched |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `_ENGINE_PATHS` modules untouched (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`); `workspace.py` changes are additive (`walk_tree_no_links` params) |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript; the 72 E5 mutants are stated as run on the pre-cp1 bytes, the 15 cp1 mutants on the final tree |
| 10 | Load-bearing emptiness declared | all | ✓ | the M24 node passes no file row so the A2L clash cannot mask it; the M35 node spies `sorted` and the yield count; MC10 re-run after its node's `is_file()` assertion was tightened |
| 11 | Mutation verdicts declared — per arm | all | ✓ | 72 run: 69 KILLED, 3 SURVIVED (wrong target / weak test / equivalent), 13 skipped; cp1: 15 KILLED — §4 |
| 12 | Instrument RED-proof declared | all | ✓ | §4 Instrument RED-proof |
| 13 | Correction population declared | all | ✓ | writers of the save-as plan/emit: `_handle_save_dialog`, `_plan_project_save`, `_copy_project_subfolders`, the carry (`_manifest_carry` / `_manifest_is_link`), the rollback (`_abort_save`), the load (`_handle_load_project`, `_apply_unload`), the panel (`_slot_state`) |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b — `code-reviewer`, `security-reviewer`, E3 `architect` and `security-reviewer` |
| 16 | Evidence files declared | all | ✓ | §4 evidence digest table (precomputed, staged-blob sha256[:16]) covers `evidence/inc-8b/` |
