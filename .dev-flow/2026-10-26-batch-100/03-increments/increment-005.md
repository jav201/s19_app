# Increment 005 — HLR-167 / LLR-167.1–167.8 · `Save project saves the image you see (PH-1, D1, R-PC)`

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `005` |
| Lane | `main` · 4 SOURCE files (⚠ at cap, LED .56) |
| Requirement(s) | `HLR-167 · LLR-167.1 · LLR-167.2 · LLR-167.3 · LLR-167.4 · LLR-167.5 · LLR-167.6 · LLR-167.7 · LLR-167.8` · LED .45 (key list is an input) · LED .50 (every placement passes `workarea_root`) · LED .53 (the emit's placement joins the exact-created list) · LED .56 (SEC-4) · LED .61 (LLR-167.8 scope at Inc 5) |
| Acceptance | `AT-B100-05` · white-box `TC-B100-14 · -15 · -16 · -17 · -58 · -59 (Inc 5 rows) · -69 · -70` |
| Interfaces | freezes B100-I5 (fast path only), B100-I15, B100-I17, B100-I18; consumes B100-I13, B100-I22 |
| Agent | `software-dev` (replacing Kimi; briefs `kimi/BRIEF-COMMON.md`, `kimi/BRIEF-inc-5.md`) |
| Date | `2026-10-29` |
| Base | `main` `8d6056f` (Inc 1–4 + hotfix 3b merged) |
| Import proof | `C:\Users\jjgh8\Github\s19_app-b100-inc5\s19_app\__init__.py` — `.dev-flow/2026-10-26-batch-100/evidence/inc-5/import-proof.txt` |

---

## 1 · What changed

BLUF: Save project now saves the image the session shows. It re-derives the current **change** document onto a copy of the source image, compares the data with the source, and emits the patched image (32 bytes per line, the source's S0) only when the data differs; otherwise it byte-copies the source as before. A blocked document refuses the whole save before any folder exists. Every file the save writes is a row of one frozen save plan, and each landing is checked against its row.

**The `save_patched` split (B100-I15, LLR-167.7) — `change_service.py`.**
- `rederive_for_save(copy, *, ranges, session_map, mac_records, a2l_tags) -> (copy, summary)` restores the journal onto the copy (only when the journal is bound to `session_map`), runs the apply's collision refresh and applies the current document to the copy. The session map is never written.
- `emit_and_verify(image, ranges, dest_dir, filename, *, source_kind, bytes_per_line, s0_header, source_image_path, summary, workarea_root, on_placed) -> ChangeActionResult` emits through `save_patched_image`, stamps the summary and verifies.
- `adopt_rederived(mem_map, derived, summary=None)` is the in-place view update (re-journal the document spans, write the re-derived bytes at the old ∪ new journal addresses). `record_save_entries()` is the applied / not-applied split `save_back_status_suffix` renders.
- `save_patched` is now exactly `record_save_entries` → `rederive_for_save` → `adopt_rederived` → (blocked refusal | reuse rule) → `emit_and_verify`. The end state (map, journal, summary, `_applied_addresses`, file bytes) equals the pre-split one; TC-B100-69 proves the file bytes for 4 documents and the B99 editor-image module stays green.
- Additive parameters beyond the frozen form: `rederive_for_save` takes `ranges` (the apply needs them for containment) and `session_map` (to know whether the journal describes this image — without it a copy of a newly loaded image would get the previous image's source bytes). Declared in §6.

**The fast path and the saved-state record (B100-I5, B100-I18, LLR-167.1, LLR-167.5).**
- `image_differs_from_source(mem_map)`: true iff the journal is bound to this dict and a journaled address holds a non-source byte. O(journal), never iterates the map.
- `mark_saved(mem_map)` / `differs_from_last_saved(mem_map)`: the record holds the journaled addresses' bytes as last loaded or written. Writers: the install point (only when a NEW image dict is installed — a MAC/A2L attach keeps the live dict and must not hide an unsaved patch), a successful save-back, and a successful Save project (only when the session image equals what was written: an emit, or a copy of a session that does not differ from its source). It never decides emit or copy (A-08; mutant `167.2-decide-on-saved-state` proves the difference).
- `rederived_differs_from_source(mem_map, derived)`: the data comparison over the document's addressed spans (outside them the copy equals the source by construction).

**SEC-4 (LED .56) — `changes/apply.py`.** `save_patched_image` takes its staging root from `_guarded_destination(dest_dir, workarea_root)` instead of walking the resolved `dest_dir`, so a junctioned destination is refused before any `temp/` or `temp/.staging/` exists in another work area. It places through `place_into_workarea` and reports the `PlacementResult` through `on_placed` (LED .53). `render_patched_image(...)` returns the exact bytes the emit writes (the emitter text with the platform line ending a text-mode write produces); the emit now writes those bytes, so the plan can digest the image before anything is placed. The dead resolved-walk helper `_find_workarea_ancestor` is removed. The save-back passes `workarea_root=self.workarea`.

**The save plan (B100-I17, LLR-167.6) — `project_gather_service.py`.** `PlannedFile`, `SavePlanRow`, `SavePlan` (all frozen) and `plan_project_save(target, *, target_kind, files, image, manifest_keys, refusal)`: one row per top-level file with its landing name from `predict_placement` and its action (`new` / `keep`), plus the `project.json` row (`new` / `rewrite`), the image description, the manifest keys (an input, LED .45) or the refusal. The digests are inputs, so the service gains no `changes` / `change_service` import (only `predict_placement` from `..workspace`, an existing edge, and `os`).

**The handler — `app.py`.**
- `_decide_project_image()` (LLR-167.1): a check document never counts; with a change document the re-derive runs when the pre-check is true or the document holds entries; blocked entries refuse the save, naming them (`Project NOT saved: 1 blocked entry (0x8000007C) — fix them in the Patch Editor.`); otherwise emit iff the data differs. It writes nothing to the session map.
- `_plan_project_save()` builds the plan, computing the source / MAC / A2L digests and the emitted bytes' digest app-side.
- `_handle_save_dialog`: decide and plan BEFORE the folder is created; a refused plan returns with no folder. Inside the existing rollback try, it executes exactly the plan's file rows — the image row through `emit_and_verify` with the plan's landing name when emitting, otherwise `place_into_workarea` — and checks each landed `PlacementResult` against its row (`_plan_row_mismatch`; a mismatch names both paths and rolls back). An emit failure rolls back with `could not save — the patched image was not written: …`. On commit: `adopt_rederived` (the view equals what was saved), the verify line (`Saved + verified: firmware.s19 — 1 entry applied before this save (0x8000007C)`, through `save_back_status_suffix`), `ChangeService.mark_saved`, and the success line carries `— firmware.s19 + N change entries, K applied by this save` (LLR-167.3). The landed name becomes the active variant (existing variant rebuild).
- LLR-167.8 at Inc 5 (LED .61): Save project calls `ChangeService.mark_saved` only, NOT `PatchEditorPanel.mark_saved()` — Save project does not yet write the editor's document (Inc 8a), so clearing the panel's flag would hide unsaved document edits. The panel call and TC-B100-70's positive arm move to Inc 8a.

**Corrective pass 1 (`review-increment-005.md` BLOCK F1, F2; `security-increment-005.md` SEC-7).** The same 4 source files, no new dependency.
- **F1 / SEC-7 (`app.py`).** The emit's `on_placed` callback (`_emit_landed`) now appends the landed image to `placed_files` the moment it lands, so a verify re-read that raises `OSError` inside `emit_and_verify` rolls back the image and the folder this save created. The post-call loop is gone. A new `except Exception:` clause after the existing `except OSError` rolls back any other error raised after the folder's creation, then re-raises it (a defect is not swallowed). The AST census still sees exactly one post-creation `except OSError`.
- **F2 (`app.py`).** The decide and plan calls run inside `try … except OSError`, before the folder exists. An unreadable source paints `Project NOT saved: <name> could not be read: <reason>. Nothing written.` (the base copy refusal's shape) with the error notify, and returns; the app keeps running. `_file_digest` gives a read error that names no file (a byte-range lock fails the read, not the open) the digested path as its `filename`, so the refusal can name it.
- **F7 (`change_service.py`, `app.py`).** `save_entry_split()` (NEW, pure) returns the applied / not-applied split without storing it; `record_save_entries()` stores it. `_decide_project_image` now calls the pure split, so deciding writes no service state. The handler calls `record_save_entries()` immediately before `emit_and_verify`, whose `ok` message reads it; the precondition is written in `emit_and_verify`'s Data Flow.
- **F8 (`app.py`).** `_SAVE_MANIFEST_KEYS` is replaced by `_save_manifest_keys(declared_regions)`, which serializes an empty composition through `manifest_writer.serialize_manifest` and reads its keys. The writer is now the one source, and `manifest_writer.py` is unchanged (it is outside the 4 files). `gathered` is not in the plan's keys: the gather decides it after the plan and has no plan rows until Inc 7 / 8a (LED .63).
- **F9.** `SavePlan.row_for`, `PLAN_ACTION_REPLACE` and `PLAN_ACTION_MERGE` are removed (no caller; Inc 8a adds the two words with the rows that produce them). `_ProjectImageStep.summary` is typed `Optional[ChangeSummary]`. `save_patched_image` renders first, so the unsupported-source refusal is the one check that proves a payload exists; the production `assert payload is not None` is gone.
- **F6.** Data Flow and Dependencies are added to the 8 new public methods (plus `save_entry_split`), `render_patched_image`, `_decide_project_image` and `_plan_project_save`. `_surface_verify_result` names Save project in its `Used by`, and its Data Flow names `emit_and_verify` as the stamp's writer.
- **F10 skipped.** The 7 identical `_abort_save(...)` calls stay. The TC-B100-07 census (`test_b100_save_guards.py`) recognises an exit by a `self._abort_save(...)` attribute call in the same block; a local `_rollback()` closure is a plain name call, so folding would require the census to resolve a local alias. That weakens the direct check it makes today. No behaviour would change.

---

## 2 · Files modified

**The budget counts SOURCE files only.** 4 / 4 (⚠ at cap). It cannot be smaller: `apply.py` holds the emit's staging that SEC-4 fixes on the path this increment splits (LED .56); `change_service.py` owns the split and the record; `project_gather_service.py` owns the plan (B100-I17); `app.py` owns the handler.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | HLR-167 · LLR-167.1 · LLR-167.2 · LLR-167.3 · LLR-167.4 · LLR-167.5 · LLR-167.6 · LLR-167.8 (LED .61) · LLR-164.4 (fix 1: F1, F2) | `_ProjectImageStep`, `_file_digest`, `_plan_row_mismatch`, `_save_manifest_keys` (module level; fix 1 replaced `_SAVE_MANIFEST_KEYS`); fix 1: emit recorded in `on_placed`, non-`OSError` rollback clause, decide+plan read-error refusal; `_decide_project_image`, `_plan_project_save` (NEW methods); `_handle_save_dialog` decides + plans before the folder, executes the plan rows, commits the re-derived view, records the saved state, paints the entry clause; install point records the state for a new image dict; save-back passes `workarea_root` and records the state |
| `s19_app/tui/services/change_service.py` | source | LLR-167.1 · LLR-167.5 · LLR-167.7 | `image_differs_from_source`, `mark_saved`, `differs_from_last_saved`, `record_save_entries`, `rederive_for_save`, `rederived_differs_from_source`, `adopt_rederived`, `emit_and_verify` (NEW); fix 1: `save_entry_split` (NEW, pure), docstring sections; `save_patched` composed of them (+ `workarea_root`); `_saved_bytes` / `_saved_map` state |
| `s19_app/tui/services/project_gather_service.py` | source | LLR-167.6 | `PlannedFile`, `SavePlanRow`, `SavePlan`, `plan_project_save`, `PLAN_*` constants (NEW); fix 1: `row_for`, `PLAN_ACTION_REPLACE`, `PLAN_ACTION_MERGE` removed |
| `s19_app/tui/changes/apply.py` | source | LLR-167.7 (SEC-4, LED .56) | `render_patched_image` (NEW); `save_patched_image(…, workarea_root, on_placed)` stages under the guard's root and places via `place_into_workarea`; `_find_workarea_ancestor` removed; fix 1: render first, the production `assert` removed, docstring sections |
| `tests/test_b100_save_image.py` | test | HLR-167 · LLR-167.1 · LLR-167.2 · LLR-167.3 · LLR-167.4 · LLR-167.5 · LLR-167.6 · LLR-167.7 · LLR-167.8 · LLR-164.4 (fix 1) | NEW, 48 nodes (TC-B100-14 ×8, -15 ×8, -16 ×2, -17 ×5, -58 ×4, -59 ×8, -69 ×6, -70 ×2, F2 ×3, AT-B100-05 ×2); fix 1 added 9 nodes and the F8 key oracle inside `59_fresh_folder` |
| `tests/test_b99_staging.py` | test | LLR-167.2 · LLR-167.3 | re-pin of `test_at_b99_05_save_project_after_same_name_save_back` (see §4 reverse census) |
| `tests/test_id_registry.py` | config | HLR-167 | `EXPECTED_SCANNED_TEST_FILES` 218 → 219 |
| `tests/test_b100_reuse.py` | test | LLR-167.6 · LLR-167.7 (SEC-4) | re-pin of the TC-B100-01 app placement census (9 → 7 calls) + the 2 emit calls must name `workarea_root` |

| Count | Value |
|---|---|
| **SOURCE files** | **4 / 4** (declared at cap, LED .56) |
| Test / config files | 4 |
| Evidence | `.dev-flow/2026-10-26-batch-100/evidence/inc-5/` |

---

## 3 · How to test

```bash
# interpreter: C:/Users/jjgh8/anaconda3/envs/s19env/python.exe
export PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<this worktree>
unset NO_COLOR
python -m pytest -q -p no:cacheprovider tests/test_b100_save_image.py tests/test_b99_staging.py tests/test_b100_reuse.py tests/test_b99_editor_image.py tests/test_id_registry.py
# corrective pass 1 also: tests/test_b100_save_guards.py tests/test_changes_apply.py; the 6 guards; -k census tests
```

---

## 4 · Test results

**Superseded by corrective pass 1 (subsection below, final hashes there).** First-pass tree (read-only `sha256sum` at packet time, 16 chars): `app.py` `2f6b446594652dbc` · `change_service.py` `3623a42e6d1cd13e` · `apply.py` `9cb482d5e2876f00` · `project_gather_service.py` `a0dae1342b64bc14`. No source file changed after the mutation run; the reverse census, guards, `green-02` and `red-03` ran on this tree. `green-01` ran before the AT oracle reorder (test-only); `census-batch-a.txt` re-runs the whole module on the final tree.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` ↔ LLR | `core` · `full` | TC-B100-14 (8) · -15 (8) · -16 (2) · -17 (2) · -58 (3) · -59 (6, Inc 5 rows: fresh, open project, pending patch, refused, no-write planning, import census) · -69 (6, incl. 4 parametrized documents and the SEC-4 junction arm) · -70 (2) | 37 passed |
| **B · black-box** `AT-NNN` ↔ story | `core` · `full` | AT-B100-05 at (118×54) and (220×60), notifications on: Load file dialog → Patch Editor add + Apply by clicks → `ctrl+s` dialog → reopen in a fresh app through `p` | 2 passed |

GREEN: `.dev-flow/2026-10-26-batch-100/evidence/inc-5/green-01-save-image.txt` — the module + the AT-B99-05 re-pin + the registry module: **53 passed in 125.40s**. After that run the AT's oracle order was swapped (the P-1 data assertion now runs before the status assertion, so the base RED shows the declared negative control); the reverse-census batch A re-runs the whole module on the final tree (`census-batch-a.txt`).

Windows-only arms (PDR C-QA-6): 1 — `test_tc_b100_69_sec4_junction_save_back_stages_in_this_work_area` (skips off Windows with the named reason). It ran (passed) here.

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| Module + AT-B99-05 re-pin vs base `8d6056f` | `red-01-new-module-vs-base.txt` | **33 failed / 7 passed.** Behavioural failures (17): TC-15 ×5 (the project image lacks the patch: `assert [2147483772, …] == []`; HEX `[4100, 4101]`), TC-16 ×2 (no entry clause), TC-17 ×2 (the blocked/refused save wrote the project), TC-69 SEC-4 (`['T', 'T\\firmware.s19', 'temp', 'temp\\.staging']` — the executed SEC-4 probe shape), TC-70 refused arm (the blocked document saved), AT-B100-05 ×2, AT-B99-05 re-pin (`{4096: 17, 8192: 0}`), TC-59 import census (the module lacked `os` — a shape check, not a behavioural RED). **Missing-symbol failures (16), NOT a behavioural RED:** TC-14 ×8 (`image_differs_from_source` / `_decide_project_image`), TC-15 save-back arm, TC-58 ×3, TC-59 ×5, TC-69 rederive arm — their behavioural RED is carried by the mutants below. The 7 passes hold at base by design: TC-15 check-document and unchanged-document copies (base always copies), TC-69 ×4 pre-split byte equality (the equivalence evidence: base `save_patched` writes the same bytes the split writes) and TC-70 unwritten-document arm (base never clears the flag) |
| AT-B100-05 vs base (P-1, after the oracle reorder) | `red-02-at-b100-05-vs-base.txt` | 2 failed — `AssertionError: project firmware.s19 == in-memory patched image? False` at both sizes |
| SEC-4 probe (security-increment-001 Round 2) | inside `red-01` | the junction save-back created `temp` and `temp\.staging` in the other work area |

### Mutation verdicts (C-40) — each against the FULL new module, restored and hash-verified

Harness `.dev-flow/2026-10-26-batch-100/evidence/inc-5/mutation_harness.py` (position + operation; pre / mutant / restored SHA-256 and `RESTORE OK` in every transcript).

| Mutation | LLR | Transcript | Verdict — killing nodes |
|---|---|---|---|
| Round-2 rule (any document kind counts, emit whenever the document holds an entry) | 167.1 | `mut-167.1-round2-rule.txt` | KILLED 5: `14_same_bytes_copy` (P-38), `14_check_document_copies` (P-37: refused), `14_applied_then_undone_copies`, `15_check_document_only_copies`, `15_unchanged_document_copies` |
| The pre-check decides copy (false pre-check skips the comparison) | 167.1 | `mut-167.1-precheck-decides.txt` | KILLED 4: `14_unapplied_entry_emits`, `17_blocked_entry_refuses_the_whole_save`, `59_refused_plan_writes_nothing`, `70_refused_save_keeps_the_flag` |
| Emit-or-copy decided on `differs_from_last_saved` (A-08) | 167.2 | `mut-167.2-decide-on-saved-state.txt` | KILLED 4: `14_applied_then_undone_copies`, `14_unapplied_entry_emits`, `14_save_back_then_emit`, `15_save_back_then_save_project_keeps_the_patch` |
| The entry clause dropped from the success line | 167.3 | `mut-167.3-drop-suffix.txt` | KILLED 3: both TC-16 nodes, AT-B100-05 [220×60] (the 118 arm checks the verify line only — the success line is clipped there) |
| The blocked re-derive ignored | 167.4 | `mut-167.4-ignore-blocked.txt` | KILLED 3: `17_blocked_entry…`, `59_refused_plan…`, `70_refused_save…` |
| `mark_saved` on the save-back path only | 167.5 | `mut-167.5-saveback-only.txt` | KILLED 1: `58_save_project_records_the_saved_state` |
| The handler places a file the plan did not name | 167.6 | `mut-167.6-unplanned-file.txt` | KILLED 13 (every emitting save: the extra file makes the emit land off-plan → mismatch → rollback), incl. both AT sizes |
| `rederive_for_save` writes the session map | 167.7 | `mut-167.7-rederive-writes-session.txt` | KILLED 2: `69_rederive_writes_nothing…`, `14_deciding_writes_nothing` |
| INVERSE probe for LED .61: Save project clears the panel flag unconditionally | 167.8 | `mut-167.8-inverse-clears-flag.txt` | KILLED 1: `70_unwritten_document_keeps_the_flag` (the declared mutation "skip the panel's mark_saved" has no subject at Inc 5 — LED .61) |
| SEC-4: the staging root resolves `dest_dir` again | 167.7 (LED .56) | `mut-sec4-resolved-staging.txt` | KILLED 1: `69_sec4_junction…` |
| SEC-4 threading: `workarea_root` dropped from app.py's `emit_and_verify` call | 167.7 (LED .56) | `mut-sec4-app-root-dropped.txt` (runs the TC-B100-01 census node) | KILLED 1: `test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root` |

All 11 transcripts end `RESTORE OK`; the post-run SHA-256 of the three mutated files equals the pre-run value (`app.py` `2f6b4465…`, `change_service.py` `3623a42e…`, `apply.py` `9cb482d5…`).

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| the project image | parsed by `tests/support/independent_reader.py` (`read_s19` / `read_hex`), never the app's loader: 0 differing addresses vs source + document, S0 equal to the source's, data records ≤ 32 bytes (raw text parse) |
| copies (S19 / MAC / A2L) | raw byte equality with the example files |
| the save-back file (TC-69) | raw byte equality with the pre-split write path (`emit_s19_from_mem_map` + text-mode `write_text`) |
| the plan vs the tree | SHA-256 tree manifests before/after, by full path and action |
| the painted status | `#log_line_1..4` renders |

### Reverse census — trigger family B

| Probe | Command | Result |
|---|---|---|
| B1 brief grep + LED .60 lesson grep + fixture users + other changed symbols | `.dev-flow/2026-10-26-batch-100/evidence/inc-5/reverse-census-grep.txt` (4 greps, commands inside) | 47 test files (+ `tests/b97_fixtures.py`, whose users are in the list) |
| B1 re-validation | all 47 files run in full on the final tree, with the new module, in two batches | `census-batch-a.txt`: **2 failed, 856 passed** · `census-batch-b.txt`: **4 failed, 632 passed, 1 xfailed** — every failure dispositioned below |
| B3 snapshot cells | `tests/test_tui_snapshot.py` inside the guards | `guards.txt`: **75 passed, 29 snapshots passed** — no cell changed; `guards-census.txt`: **87 passed, 3856 deselected** |
| A3 frozen interfaces | B100-I5/I15/I17/I18 frozen here; I13/I22 consumed unchanged | `copy_into_workarea` untouched (15 call sites) |

**Census failures and their disposition** (the LED .60 lesson: each compared with base under the same load before being called anything):

| Node | Disposition | Evidence |
|---|---|---|
| `test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root` | **Re-pinned** (this increment changed the count): Save project's 3 placement calls became 1 loop call, so 9 → 7; the census now also requires the 2 emit calls (`save_patched`, `emit_and_verify`) to name `workarea_root` (SEC-4 threading) | GREEN `green-02-reuse-census-repin.txt` (38 passed); base RED `red-03-reuse-census-repin-vs-base.txt` (`assert 9 == 7`); mutant `mut-sec4-app-root-dropped.txt` (root dropped from `emit_and_verify` → 1 failed, RESTORE OK) |
| `test_tui_commandbar.py::test_at_b78_03…`, `test_tui_diff_screen.py::test_at_b78_32…`, `test_tui_report_filter_surface.py::test_at_056e_a2b…` | **Pre-existing at base**: 5/5 failures on base `8d6056f` and 5/5 on this tree (b78_03 and 056e are the Inc 3 packet's known pre-existing pair) | `preexisting-census-base-5runs.txt`, `preexisting-census-tree-5runs.txt` |
| `test_before_after_report.py::test_at_038b…` | **Flake under census load**: 0/5 failures on base and 0/5 on this tree in isolation; the test drives the decline path (no save, no Save project) with single pauses | same two transcripts |
| `test_tui_patch_editor_v2.py::test_tc345…` | **Flake at base**: alternating isolated runs fail 4/15 on base and 3/15 on this tree; parallel runs 1/10 base vs 4/10 tree (contention). The node loads a change document with a single pause after `request_action("load_doc")` and touches no code this increment changed | `tc345-base-15runs-alternating.txt`, `tc345-tree-15runs-alternating.txt`, `tc345-base-10runs.txt`, `tc345-tree-10runs.txt` |

**Re-pin recorded:** `tests/test_b99_staging.py::test_at_b99_05_save_project_after_same_name_save_back` — `_data(placed) == {0x1000: 0x11, 0x2000: 0x00}` (the project copied the unpatched work copy, P-1) → `== {0x1000: 0x11, 0x2000: 0xAA}` plus `"1 change entry" in` the success line — LLR-167.2 / LLR-167.3 (the contract's §5.4 row names exactly this re-pin). RED at base: `red-01` (`{4096: 17, 8192: 0}`).

### Signed-balance test ledger

Scanned files: `219 = 218 − 0 + 1` (`tests/test_b100_save_image.py`). Nodes in the new module: 39 = TC-14 8 + TC-15 8 + TC-16 2 + TC-17 2 + TC-58 3 + TC-59 6 + TC-69 6 + TC-70 2 + AT-B100-05 2. Corrective pass 1: `48 = 39 − 0 + 9` (TC-17 +3, TC-58 +1, TC-59 +2, F2 +3), plus one assertion added to `59_fresh_folder`; no file added, so still 219 scanned. Re-pinned: 2 (one in `test_b99_staging.py`, one in `test_b100_reuse.py`). Deleted: 0.

### Corrective pass 1 — `review-increment-005.md` (BLOCK F1, F2) and `security-increment-005.md` (SEC-7)

**The final tree after the pass.** Read-only `sha256sum`, 16 characters:

- `app.py` `8032dead73f7ee54`
- `apply.py` `6d00f17fcefb704c`
- `change_service.py` `95da58bf3bcc27cd`
- `project_gather_service.py` `11697d6c85efb9e2`
- `test_b100_save_image.py` `559768f390ded771`

These hashes are printed in the header of every `fix1-*` transcript; the mutant transcripts carry the full SHA-256 values. No source file changed after `fix1-green-02`. The pre-fix tree is the reviewed one (`2f6b4465…` / `9cb482d5…` / `3623a42e…` / `a0dae134…`). It was snapshotted before any edit, and the tests were written first.

**RED on the pre-fix sources, GREEN after.** RED is `fix1-red-01-new-arms-vs-prefix.txt` (the pre-fix sources with the new arms): **5 failed, 5 passed**. GREEN is `fix1-green-01-new-arms.txt`: **10 passed**.

| Finding | Test node (`tests/test_b100_save_image.py::`) | RED (pre-fix) | GREEN | Mutant |
|---|---|---|---|---|
| **F1 / SEC-7** (HIGH) | `test_tc_b100_17_verify_reread_failure_rolls_the_emit_back` | FAILED: `P1` exists holding `firmware.s19` (probe P1's shape) | passed | **MC KILLED** (4 nodes) |
| F1 (non-`OSError` half) | `test_tc_b100_17_non_os_error_after_the_emit_rolls_back_then_surfaces` | FAILED: `P1/firmware.s19` left behind | passed | **MX KILLED** (1) |
| **F2** (HIGH) | `test_f2_unreadable_source_refuses_and_the_app_keeps_running[image]` / `[a2l]` | FAILED ×2: `PermissionError: [Errno 13] Permission denied` escapes the app callback | passed ×2 | **MF2 KILLED** (3) |
| F2, probe P2b (the reviewer's reproduction) | `test_f2_byte_range_locked_image_refuses_and_the_app_keeps_running` (Windows: `msvcrt` byte-range lock; skips elsewhere with the named reason) | FAILED: `PermissionError` escapes | passed | MF2 |
| **F3** (MAJOR) | `test_tc_b100_59_landing_that_differs_from_its_row_rolls_back[emit]` / `[copy]` | passed (the check is correct; this arm exists to kill MB) | passed ×2 | **MB KILLED** (2) |
| **F4** (MAJOR) | `test_tc_b100_17_failed_manifest_write_adopts_nothing` | passed (the order is correct) | passed | **ME KILLED** (2) |
| **F5** (MINOR) | `test_tc_b100_58_mac_attach_keeps_an_unsaved_patch_unsaved` | passed (the guard is correct) | passed | **MG KILLED** (1) |
| **F8** (MINOR) | the key oracle added to `test_tc_b100_59_fresh_folder` (`tuple(project.json) == plan.manifest_keys`) | passed (the hand-copied list matched this case) | passed | **MK KILLED** (1) |

**What the arms assert:**
- **F1:** the status reads `Project NOT saved: could not save`, the `P1` folder does not exist, and the work-area tree equals the pre-save tree.
- **F2:** the status starts `Project NOT saved:` and contains `<file> could not be read` and `Nothing written.`. The app is running with `return_code` `None`, and no folder exists. In the `a2l` arm, the pending patch is still unsaved in memory.
- **F3:** a writer claims the planned landing between the plan and the placement. The refusal names `…\P1\firmware.s19 (new) but the file landed at …\P1\firmware_1.s19 (new)`. Only the other writer's `firmware.s19` remains, byte-identical, and no `project.json` exists.
- **F4:** the entry is unapplied, and the manifest write fails. The session map still holds the source bytes at `0x8000007C..7F`, and `last_summary` carries no `saved_path`.

**Mutation verdicts (C-40).** Harness: `fix1-mutation_harness.py`, which applies a byte-exact CRLF anchor (count 1), runs the FULL module of 48 nodes, then restores the file and verifies its SHA-256. All 7 transcripts end `RESTORE OK`. MB, MC, ME and MG are the code-reviewer's survivors, re-anchored on the corrected code. MX, MF2 and MK pin this pass's own decisions.

| Mutant | Transcript | Verdict: killing nodes |
|---|---|---|
| MB: the plan-row check silenced (`mismatch = None`) | `fix1-mut-MB-mismatch-silenced.txt` | KILLED 2: `59_landing_that_differs…[emit]`, `[copy]` |
| MC: the emitted image is never recorded for rollback | `fix1-mut-MC-emit-not-recorded.txt` | KILLED 4: `17_verify_reread_failure…`, `17_non_os_error…`, `17_failed_manifest_write…`, `59_landing_that_differs…[emit]` |
| ME: adopt before the project folder exists | `fix1-mut-ME-adopt-before-folder.txt` | KILLED 2: `17_failed_manifest_write_adopts_nothing`, `16_entry_added_after_the_apply` |
| MG: every install records the saved state | `fix1-mut-MG-install-always-marks.txt` | KILLED 1: `58_mac_attach_keeps_an_unsaved_patch_unsaved` |
| MX: no rollback on a non-`OSError` | `fix1-mut-MX-no-rollback-on-defect.txt` | KILLED 1: `17_non_os_error…` |
| MF2: a read error escapes the decide/plan block | `fix1-mut-MF2-read-error-escapes.txt` | KILLED 3: `f2_unreadable…[image]`, `[a2l]`, `f2_byte_range_locked…` |
| MK: the plan's keys drift from `project.json` | `fix1-mut-MK-manifest-keys-drift.txt` | KILLED 1: `59_fresh_folder` |

**Re-runs on the final tree:**

| Run | Transcript | Result |
|---|---|---|
| The 5 named modules: `test_b100_save_image.py`, `test_b99_staging.py`, `test_b100_reuse.py`, `test_b99_editor_image.py`, `test_id_registry.py` | `fix1-green-02-modules.txt` | **138 passed** (the reviewer's 129, plus 9 new nodes) |
| The handler's guard module and the engine module: `test_b100_save_guards.py` (incl. the TC-B100-07 abort census, which still finds exactly one post-creation `except OSError`) and `test_changes_apply.py` (the `save_patched_image` reorder) | `fix1-green-03-save-guards.txt` | **84 passed** |
| The 6 guards: `test_import_census`, `test_tui_snapshot`, `test_id_registry`, `test_batch91_registry_hygiene`, `test_address_census`, `test_engine_unchanged` | `fix1-guards.txt` | **75 passed, 29 snapshots passed**; no cell changed |
| `-k census tests`, first sample | `fix1-guards-census.txt` | **1 failed, 86 passed** (`test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent`: `checks_line` False after fixed `pilot.pause()` counts) |
| `-k census tests`, second sample | `fix1-guards-census-rerun.txt` | **87 passed** |
| `at058b`, isolated, 30 alternating runs per side | `fix1-at058b-base-vs-tree-30runs-alternating.txt` | **Base 1/30 failed, tree 1/30 failed**: a flake present at base. The node exercises the Patch Editor's Run checks wiring, which this pass does not touch |

`fix1-guards` counts 75 nodes, which matches the Inc 5 run. The `-k census` selection deselects more nodes now (3865, was 3856) because the test count grew.

### Corrective pass 2 — `review-increment-005.md` round 2 (R2-1 to R2-4)

Same 4 SOURCE files; only a docstring changed in them. No new dependency.

**The final tree after the pass.** Read-only `sha256sum`, 16 characters (these replace the pass-1 values above for `app.py` and the test module; the other three are unchanged):

- `app.py` `ecfe48ae4da0f24e` (full `ecfe48ae4da0f24ef7926f3b9ecf850af1a82e418bc5e2cbf64c0ad7bc2b113e`)
- `apply.py` `6d00f17fcefb704c`
- `change_service.py` `95da58bf3bcc27cd`
- `project_gather_service.py` `11697d6c85efb9e2`
- `test_b100_save_image.py` `2e28e20e8e683d59` (full `2e28e20e8e683d597483d45fe0f467e1fb5f9038668b064aaa6006e249ed12c8`)

- **R2-1 (MINOR), tests only; the app's line format is unchanged.** The success line `Saved project to {project_dir} … — {plan.image}` is cut at the terminal width by `set_status`, so a long project path clips the LLR-167.3 counts (moving the counts is routed to Inc 11; the orchestrator amends LED .64). The tests no longer read the capped log line for that clause:
  - `_save_session` takes an optional `statuses` list and wraps the app's `set_status` to collect the FULL message of every call. TC-B100-16 (both nodes) reads `statuses[-1]`; the verify-line check stays on `log_lines`.
  - AT-B100-05 keeps the painted check of the verify line (`1 entry applied before this save (0x8000007C)`). The 220-column painted check of the success clause is replaced by a check on the full captured `set_status` message at both sizes. The comment is updated.
  - RED at a deep temp path: `--basetemp` of 114 characters (`C:\Users\jjgh8\AppData\Local\Temp\b100deep\a…\b…`; the scratchpad path suggested in the brief is itself about 140 characters deep, which exceeds the Windows MAX_PATH limit for pytest's own folder creation, so a shorter deep folder was used) on the OLD tests (`fix2-red-01`): **3 failed, 1 passed** (TC-16 ×2 and AT-B100-05 at 220×60 fail; AT-B100-05 at 118×40 never checked the clause). GREEN on the NEW tests at the same basetemp (`fix2-green-01`): **4 passed**. GREEN on the NEW tests at the default basetemp (`fix2-green-02`): **4 passed**. The deep folder was deleted afterwards.
- **R2-2 (NIT), done.** The assert message in the F3 arm (the `Project NOT saved: the plan named` check) now uses `statuses`, not the undefined `lines`.
- **R2-3 (NIT), done.** The `_decide_project_image` docstring now says no image byte and no save record is written, and that the document's collision findings (`document.issues`) are refreshed by the re-derive. Docstring only.
- **R2-4, noted, no change.** `save_patched_image` renders the image before the filename sanitizer and the destination guard; the cost is negligible and it removes the `assert`.

**Whole module after the pass** (`fix2-green-03-module.txt`, default basetemp): **48 passed**.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-5/` | SHA-256 |
|---|---|---|
| census-batch-a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/census-batch-a.txt | 7fb48b31bd04f9f565ca3d4c0df51263fa93d139cbc5479748361a2a630f5030 |
| census-batch-b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/census-batch-b.txt | bc1c1e25074aa841da625b005b87d29a148a305f7b3ad1047a5def9d9ccdee21 |
| green-01-save-image.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/green-01-save-image.txt | 53f70fd5e7e2c7aa31142df03300a478b507caf832243298881e867451ecf1a6 |
| green-02-reuse-census-repin.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/green-02-reuse-census-repin.txt | bb8ed10799538909feb0f3dfba33a739588edd40ddd63497aaf382f2aaad5627 |
| guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/guards-census.txt | c29b69fc7e57104710696eb279aafa3b2c8b715688e427a0d99af85104e76472 |
| guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/guards.txt | 5e53dd8a0d308ef4e0e704cd1cb5fa3837cc13318a8934dadd7485f5979c132e |
| import-proof.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/import-proof.txt | 4143d04eb5d05cc89077ff3df00abbc8f690cd882b5f7039750a049a94172b8e |
| mut-167.1-precheck-decides.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.1-precheck-decides.txt | 8ae9dfac4b4b6090db324919ac805fc81afbabb61e4be9bda53e5c7af3805e8b |
| mut-167.1-round2-rule.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.1-round2-rule.txt | 5a87b29e4ccc8604fa8c500cc66c159bc2c2d6742512cbce23a43152e3a5f68b |
| mut-167.2-decide-on-saved-state.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.2-decide-on-saved-state.txt | 33299ce6fdd0a902ef6d2b3a2e24d03fdbd2d7bc20b34c093a55b82551c771a3 |
| mut-167.3-drop-suffix.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.3-drop-suffix.txt | c970c9323fb16114f2476f6c324e3fd2bc891fb5b6b8c84055e774ce8f928dd2 |
| mut-167.4-ignore-blocked.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.4-ignore-blocked.txt | ab2243a4ad2821aa22d1d331c28e3e2c9adfd373eb968650db57f4cd6f444659 |
| mut-167.5-saveback-only.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.5-saveback-only.txt | 884d44e61b56557a3f412107c74b932c0c0a0e9b6810f7668c25926018265cb5 |
| mut-167.6-unplanned-file.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.6-unplanned-file.txt | f86e70d26bf0c4c8b59b40dafc16908b96dee8930e0be5b3ad5ee9b004889b3f |
| mut-167.7-rederive-writes-session.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.7-rederive-writes-session.txt | f58d454129d14573ffc8f387d7c3973b762c8a191b1ada2caf59602e6affdafd |
| mut-167.8-inverse-clears-flag.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-167.8-inverse-clears-flag.txt | 48e03159dc97608d0de81de902be79c00bdbc02e4a2aac343309078f3a596a3c |
| mut-sec4-app-root-dropped.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-sec4-app-root-dropped.txt | 97436cc4ad53c1e6d40022446f835b6da27bd4debecbfb02e0d16481811f15c5 |
| mut-sec4-resolved-staging.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mut-sec4-resolved-staging.txt | 1c3a0bad9e203ec72328ba60ddccc718e1b925452663ed515dbb06ba7f2602f2 |
| mutation_harness.py | .dev-flow/2026-10-26-batch-100/evidence/inc-5/mutation_harness.py | 01358ee46d8eedc751d28a6b0b28c34f58b0c3944d4d61d8e33a09b858160b5f |
| preexisting-a2l-guard-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/preexisting-a2l-guard-base.txt | de996cedb4ab8459b701be9681079bb197bd58f785ca42cbbc8729ed5cd06d18 |
| preexisting-a2l-guard-probe.py | .dev-flow/2026-10-26-batch-100/evidence/inc-5/preexisting-a2l-guard-probe.py | fca08baba6aa0bb3e6e405fd1eedb0cc9340b7d84a719fedd35248098f81ea7c |
| preexisting-census-base-5runs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/preexisting-census-base-5runs.txt | 840fc5a4b6b66db6c91c143c28d600846579755d307bfccaae323a5ae717a2cb |
| preexisting-census-tree-5runs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/preexisting-census-tree-5runs.txt | b3fe573bbbc70b5f73f28191acf343c0423bfc70991f4f84d7b867536e01f5a2 |
| red-01-new-module-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/red-01-new-module-vs-base.txt | 2c3ab33fa77ba887944477d449145d395d0b75eb35fc837698e24b6eeef78654 |
| red-02-at-b100-05-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/red-02-at-b100-05-vs-base.txt | 0e6af84492b7cc196c393f3748c238e7071f3f9bd4a29b42f03d3130d69134da |
| red-03-reuse-census-repin-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/red-03-reuse-census-repin-vs-base.txt | 32f4b9f01ba00830c2350f787652dd5198583d6e5cf18f3c164af9403721398e |
| reverse-census-grep.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/reverse-census-grep.txt | 93b95b6da8c49a210af38da4352b5151bbd9f8f42a80e08412cb097fecb5db5d |
| tc345-base-10runs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/tc345-base-10runs.txt | 8bced175b33e63a767da8f0c86b502edbb5e51070a83fa049867dec5143189c9 |
| tc345-base-15runs-alternating.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/tc345-base-15runs-alternating.txt | 2b53d56c378221e0fac538043e79ae16aefb88b1bab2b470de692bfbdbeef324 |
| tc345-tree-10runs.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/tc345-tree-10runs.txt | fac41517ac2610454b3640f3be9f15b3370e1590c6b1a26ea78a9ff862064b97 |
| tc345-tree-15runs-alternating.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/tc345-tree-15runs-alternating.txt | 1c1b9906eee07527de54b5d51b9a2ca5ceb2134aad82ee93824817f54d6236e6 |
| fix1-at058b-base-vs-tree-30runs-alternating.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-at058b-base-vs-tree-30runs-alternating.txt | 024e3a1cf885401c7934f94b4a1dd55506fd671702e4d1bb7b7d5d87da0f9206 |
| fix1-green-01-new-arms.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-green-01-new-arms.txt | 3a42fb0cc83c2e4afaa0b7fdaf77fc3fd6af2e246f1794ffd67dd311c2034130 |
| fix1-green-02-modules.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-green-02-modules.txt | 2d723fe8fc5c7c88c3f62910578610733228e132efa7de833cca9ae38771d35d |
| fix1-green-03-save-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-green-03-save-guards.txt | 51a0d7f1c5aa5553fbe11cfae1dd7893377455e71e23d219eadc9bf2b63b6012 |
| fix1-guards-census-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-guards-census-rerun.txt | 854957f2e66a3a224e11254b0111c80a0639516efc42d64998f0f85c51179bf8 |
| fix1-guards-census.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-guards-census.txt | f047a87ba10c29dc934eb888c4124fa453b91c199528668234bf681d11eb997a |
| fix1-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-guards.txt | 49eaa03a549e8e144a7a06de68a529248a6482d5e714dd6b78c16db8ad11c2c6 |
| fix1-mut-MB-mismatch-silenced.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-mut-MB-mismatch-silenced.txt | dc62f328d6d4a7fddc4783d2e7cbd402c130013a2b0fdede5b4d83010151bd11 |
| fix1-mut-MC-emit-not-recorded.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-mut-MC-emit-not-recorded.txt | 70838b0f86f471c219ecce2c32d344293b0ae6e2fa87e2312c7158122dc64fa4 |
| fix1-mut-ME-adopt-before-folder.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-mut-ME-adopt-before-folder.txt | b0fec17432ccc510d5b882c7f4288d1550d821ab9a67e65fc6ff240ca61ed1ec |
| fix1-mut-MF2-read-error-escapes.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-mut-MF2-read-error-escapes.txt | d505bbb038cb40ad3f2f8eae6468883a4049f62b0ef1229702f4bad77cd3124d |
| fix1-mut-MG-install-always-marks.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-mut-MG-install-always-marks.txt | 7f7c48bd45b692e154d14c5e9dd4d4dae6973ca3d8c0e74e987b68fffb3c1de7 |
| fix1-mut-MK-manifest-keys-drift.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-mut-MK-manifest-keys-drift.txt | 9d9bfcc54a96a91c8f21b24acc1cbcf0059f7b41c35a5452468f545c58bb65e9 |
| fix1-mut-MX-no-rollback-on-defect.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-mut-MX-no-rollback-on-defect.txt | 3d5937695d0e5445d5c48133714f8deefd60f0c8bd1f3fda59f05b4c99f5b89f |
| fix1-mutation_harness.py | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-mutation_harness.py | 8be1bf7eadb82092dc313295cb59c33aa9e97b6ac2abb0cceee820ae1d76ba95 |
| fix1-red-01-new-arms-vs-prefix.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix1-red-01-new-arms-vs-prefix.txt | 7ef9e50e721db6839050fac21034ca5e326abcad67069b3f41e9ddf9a76c7d81 |
| fix2-green-01-deep-basetemp-new-tests.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix2-green-01-deep-basetemp-new-tests.txt | a60abac655a3c6bfa9f6d455324612af4ca1be91285761d425d6572e225080f6 |
| fix2-green-02-normal-basetemp-new-tests.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix2-green-02-normal-basetemp-new-tests.txt | 4e5df9108ef8a5016fe68c226e02225e7c44380d8054b533b0791b787333b5d8 |
| fix2-green-03-module.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix2-green-03-module.txt | 1ab6f61176957fffb172ccb9bb0e062d158c58b4bf6434062e4fcda4bf671dfe |
| fix2-red-01-deep-basetemp-old-tests.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/fix2-red-01-deep-basetemp-old-tests.txt | 5afceebd3c352a354b0acbca8c31a20b599b87f48aaafa6fa2c9739426795188 |
| sec/sec_inc5_probe.out (security-reviewer) | .dev-flow/2026-10-26-batch-100/evidence/inc-5/sec/sec_inc5_probe.out | e58209b60d300e03a90a09329bb83b8473d06644ba0a359e3fb220e620647a25 |
| sec/sec_inc5_probe.py (security-reviewer) | .dev-flow/2026-10-26-batch-100/evidence/inc-5/sec/sec_inc5_probe.py | c5ca9685d7888c8d924fce0afe6dbdb0a3da2dc759feca36eefe8f3c4abd3d65 |
| sec/sec_inc5_rerun_nodes.out (security-reviewer) | .dev-flow/2026-10-26-batch-100/evidence/inc-5/sec/sec_inc5_rerun_nodes.out | ab4b67e1b2ec8d66eeadc6a8c8d3089ab6845daefbfaaf9b7e8a682fcba69065 |
| orch-census-batch-a.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/orch-census-batch-a.txt | 2aad5ffe34650392b62cc1bcfd91f70690b9021bf7b8d19d3641f704527c08b7 |
| orch-census-batch-b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/orch-census-batch-b.txt | 191d24831b6c314f6d10b182a55fe7657616b19a2c7afb6b4208b46c21e53e1d |
| orch-census-batch-b-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/orch-census-batch-b-rerun.txt | 2be635a396103af60735adf8cde76f30a490e4e94c5c755b832ffc92ef39998f |
| orch-guards.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-5/orch-guards.txt | fa7ddb99757ee7c1fa2421d407c50d39eb78c7780a1e92c6df6e521c124f6553 |

| Field | Value |
|---|---|
| **Evidence files** | `58 artifact(s), each at the declared home, with the digest of its bytes on disk` |

---

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · PASS-WITH-NOTES after 2 rounds (r1 FAIL `BLOCK — BLOCK-UNTIL: F1, F2`: F1 HIGH the emitted image escaped the rollback, F2 HIGH an unreadable source crashed the app, F3/F4 MAJOR unpinned mismatch path and adopt ordering, F5–F10 MINOR/LOW; r2 PASS-WITH-NOTES: F1/F2 discharged on the reviewer's own re-run of probes P1, P2b and mutants MC, MF, MX, MR; F3–F9 closed, F10 withdrawn; R2-1 MINOR the LLR-167.3 clause clips with a long path, R2-2..R2-4 NIT) — `review-increment-005.md`. Corrective pass 2 made the TC-B100-16 nodes and AT-B100-05 read the full `set_status` message (RED at a deep basetemp, `fix2-red-01`), fixed R2-2/R2-3; the line format moves to Inc 11 (LED .64). `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · PASS-WITH-NOTES (`security-increment-005.md`): SEC-4 discharged by an executed junction probe (0 entries in the other work area); SEC-7 = F1, fixed; SEC-8 → Inc 11 and SEC-9 → LED .50 backlog (LED .65, .66). Rulings: B100-I15 re-frozen with `ranges`, `session_map`, `save_entry_split` (LED .62); partial save plan (LED .63). Orchestrator re-run on the final tree `ecfe48ae` (app.py): reverse census batch A 867 passed (`orch-census-batch-a`); batch B first run 9 failed / 627 passed (`orch-census-batch-b`) — 6 of them passed in isolation and in a full second run, which gave 3 failed / 633 passed, the 3 being the known main failures b78_03, b78_32, 056e (`orch-census-batch-b-rerun`); guards 75 passed + 29 snapshots, census sweep 87 passed (`orch-guards`). |

---

## 5 · Risks

- **Save-path data.** Every emit lands through the plan's predicted name and is checked against it; a divergence (a concurrent writer) rolls the save back naming both paths (fix 1: `59_landing_that_differs_from_its_row…` ×2, mutant MB). The rollback removes only what this save created (LED .53). The emit's placement joins that list inside `on_placed`, the moment it lands. Before fix 1 this claim was false: it joined only after `emit_and_verify` returned (review F1 / SEC-7). It is now pinned by `17_verify_reread_failure…` and mutant MC.
- **A defect after the folder exists** rolls the save back and then surfaces (the `except Exception` clause re-raises). Run as the dialog's callback, it still ends the Textual session, as any unhandled defect does; the work area is left as it was.
- **A failed save leaves the view unchanged.** The session map is adopted only after the manifest is on disk; deciding and planning write nothing to it (TC-14 trap map, mutant 167.7; fix 1: `17_failed_manifest_write_adopts_nothing`, mutant ME).
- **`record_save_entries` before the emit (F7).** On a save that then rolls back, `last_save_applied` / `last_save_not_applied` keep this save's split. Their only readers are the emit's `ok` message and `_surface_verify_result`, and both paths that reach them (save-back, Save project) record first. A stale pair is never painted.
- **Status clipping.** At 118 columns the success line's entry clause is clipped (the path is long); the verify line `Saved + verified: … — 1 entry applied before this save (…)` fits and names the entries. A UX observation for Inc 11 / the status design, not a defect of this LLR.
- **Copy while the view is patched.** With a check document as the current document (or an applied entry later undone), Save project copies the source while the view still shows applied bytes — exactly the contract's rule (a check document never counts; applied-then-undone → copy). The saved-state record is NOT written then, so `differs_from_last_saved` keeps reporting unsaved work (the Inc 10 question will ask).
- **The pre-split equivalence** is proven on file bytes and by the B99 editor-image module, not by running both implementations side by side; the base run of the same TC-69 arms passes (`red-01`), which shows the expected bytes are the pre-split ones.

## 6 · Pending items / spec deviations

- **Orchestrator rulings in force (main-checkout ledger, `01-requirements-ledger.md`):**
  - **LED .61:** LLR-167.8 at Inc 5 (below).
  - **LED .62:** B100-I15 is re-frozen with `ranges` and `session_map` and the public helpers listed below. Fix 1 adds one member, `ChangeService.save_entry_split()` (pure), which `record_save_entries()` now wraps. This resolves review F7: the decide step no longer writes service state. The coupling that remains is explicit and local: the handler calls `record_save_entries()` on the line before `emit_and_verify`, and `emit_and_verify`'s Data Flow states the precondition. **For the orchestrator: add `save_entry_split` to the B100-I15 freeze.**
  - **LED .63:** the save plan is partial until Inc 7, 8a and 8b. F8's `gathered` decision follows it: the plan's manifest keys exclude `gathered` until the gather has plan rows.
  - **LED .64:** LLR-167.3 counts on two status lines.
  - **LED .65:** SEC-8 is routed to Inc 11 and SEC-9 to the LED .50 backlog item; neither is fixed here. SEC-7 is code-review F1, fixed in corrective pass 1.
- **Corrective pass 1 — skipped or partial:** F10 is skipped (reason in §1: the abort census would lose its direct check). F8 cannot add a constant to `manifest_writer.py`, which is outside the 4 files; the writer is still the single source, because the plan reads its output.
- **LED .61 (LLR-167.8 at Inc 5).** Save project does not call `PatchEditorPanel.mark_saved()`: it does not write the editor's document until Inc 8a, so clearing the flag would hide unsaved edits. TC-B100-70 holds the refused arm and the "document not written → flag kept" arm (both trace to LLR-167.8 as scoped by LED .61); the positive arm and the panel call move to Inc 8a.
- **Additive signature deviation (B100-I15).** `rederive_for_save(copy, *, ranges, session_map, mac_records=None, a2l_tags=None)` — `ranges` and `session_map` are required keywords beyond the frozen `rederive_for_save(copy)` form (reasons in §1). `emit_and_verify` adds `summary`, `workarea_root`, `on_placed` in its `…`. New public helpers: `record_save_entries`, `rederived_differs_from_source`, `adopt_rederived` (service), `render_patched_image` (engine). Re-frozen by LED .62; fix 1 adds `save_entry_split` (above).
- **LLR-167.3 wording.** The counts come from the same applied / not-applied split `save_back_status_suffix` renders: the verify line carries the suffix text itself, and the success line carries `N change entries, K applied by this save` — the suffix text alone has no total and no "applied by this save" phrase, which the threshold requires.
- **Plan rows not yet in the plan (Inc 7 / 8a / 8b, per TC-B100-59's split):** the gathered documents and templates (sub-folder rows — the gather still runs after the plan rows and reports its own created list), `files`, the merge rows, `derived_from` (LLR-168.4, Inc 7). The MAC/A2L single-file refusals still run after the folder exists (unchanged, rolled back); Inc 11's dialog will need them in the plan.
- **Pre-existing defect (routed to the backlog by the orchestrator):** the single-A2L guard compares suffixes, so saving into an OPEN project that already holds its own A2L is refused (`Project already has an A2L file.`). Base evidence: `preexisting-a2l-guard-base.txt` (probe `preexisting-a2l-guard-probe.py`, base `8d6056f`). TC-B100-59's open-project arms therefore seed S19 + MAC.
- **"saved → undone" in TC-58** is exercised as undo followed by the apply that returns the image to source: an undo alone changes the document, not the image (the panel's dirty flag covers it).
- Re-pins: 2 (`test_b99_staging.py::test_at_b99_05…`, `test_b100_reuse.py::test_tc_b100_01_app_placements…`), each with its base RED and the requirement that changed it (§4).
- Pre-existing census failures at base (3) and flakes (2) are listed in §4 with their base comparisons; none is caused by this increment.

## 7 · Suggested next task

First, the code-reviewer re-reads corrective pass 1 on the diff and re-runs probes P1 and P2b and mutant MC (the BLOCK's discharge condition). The orchestrator adds `save_entry_split` to the B100-I15 freeze (LED .62). Then Increment 6 (the save-back's active variant, the manifest carry, the Load-result panel), which consumes the split and the saved-state record.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4/4, declared (LED .56) — §2 |
| 2 | Tests written in this same increment | all | ✓ | `tests/test_b100_save_image.py` (48 nodes after corrective pass 1) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | unit arms: TC-58 predicate sequence, TC-69 rederive + 4 documents, TC-59 planner + import census |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01`, `red-02`; fix 1: `fix1-red-01` (F1 ×2, F2 ×3 RED on the pre-fix sources) |
| 5 | Reverse census declared | `core` · `full` | ✓ | §4: 47 files, 6 failures dispositioned (1 re-pin, 3 pre-existing, 2 flakes — each with a base comparison) |
| 6 | `code-reviewer` passed | `core` · `full` | pending | §4b |
| 7 | No file from another lane touched | all | ✓ | the 4 named source files + 4 test/config files |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ⚠ | B100-I15 re-frozen (LED .62); fix 1 adds `save_entry_split`. §6 asks the orchestrator to add it to the freeze |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript |
| 10 | Load-bearing emptiness declared | all | ✓ | the TC-59 "0 digests" arm rests on a target with no same-size candidate (a same-size candidate is hashed by the placement's own rule — by design, B100-I22) |
| 11 | Mutation verdicts declared — per arm | all | ✓ | §4: 11 first-pass mutations plus 7 in fix 1 (MB, MC, ME, MG, MX, MF2, MK), all KILLED |
| 12 | Instrument RED-proof declared | all | ✓ | every oracle failed first: `red-01` / `red-02` / the mutants |
| 13 | Correction population declared | all | ✓ | the placement calls of `_handle_save_dialog` (3 sites: image, MAC, A2L) → one plan loop; `save_patched_image` callers (`save_patched`, `flow_execution_service`, and `variant_execution_service.py:797` per SEC-9), the last two keep `workarea_root=None` (LED .50 backlog item, LED .65); fix 1: the handler's 1 emit `on_placed` site and its 2 digest-reading steps (decide, plan) |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | pending | §4b |
| 16 | Evidence files declared | all | ✓ | §4 evidence table (50 rows) |
