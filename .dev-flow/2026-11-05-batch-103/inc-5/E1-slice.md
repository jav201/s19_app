# Inc 5 — E1 slice: concrete functions, files and requirement map

Date 2026-11-10; model Kimi. Base: current static worktree, read only; no commit id is claimed and no tests/probes/Git commands were run. Authority and rulings: `01-requirements.md`, `E1-rulings.md` D-1 … D-8 with the **E3 round-1 correction** to D-1/D-4/D-7. Names marked **new** are design proposals, not declarations added to product source.

## 1. Count and source boundary

| File | Planned change | Count |
|---|---|---:|
| `s19_app/tui/app.py` | 6 existing functions changed; 4 private functions new/extracted; defaulted `A2LAttachRequest.sync_project` field | 10 implementation nodes |
| `s19_app/tui/segment_split_view.py` | 1 new public `SplitJoinWindow.invalidate_a2l_selection()` | 1 implementation node |
| `s19_app/tui/a2l_parameter_picker.py` | **No change**: reuse `set_parameters(rows, signature)`; oracle only name/address/format/signature | 0 |
| Every other source file | Read-only context; no edit authorized | 0 |

**Totals after E3R1-Q8/Q9 closure:** **3 permitted source files; 2 planned to change; 6 changed functions + 5 new functions = 11 implementation nodes**. With 10 primary unchanged context nodes in §3, the graph is **21 nodes**, below the 40-node cap. No picker API change is proposed. No product or test file was edited in E1/E3R1.

## 2. Implementation map

| # | Function and current file:line | Planned change | Requirements |
|---:|---|---|---|
| 1 | `S19TuiApp._refresh_a2l_dependent_views` — **new**, proposed beside `update_a2l_view` at `s19_app/tui/app.py:21018` | The single UI-thread fan-out of D-1: reset mode before fresh `update_a2l_view`; clear/repaint A2L hex; close old description modal; Detail Card immediate + after-refresh clear; Check/Patch prefills with oracles limited to name/address/format/signature; MemoryMap; call #9 immediately before `watch_current_file`; Loaded. No worker calls or outcome text. | .001-.019, .023, .026, .027 |
| 2 | `S19TuiApp._confirm_project_a2l_replacement` — **new**, proposed beside `load_a2l_from_path` at `app.py:16606` | Compose/capture the exact question. No is inert. Yes has post-Yes busy boundary 1 in the accepted callback, then identity recheck, then calls #3 with `sync_project=False`; N3 is post-Yes boundary 2 immediately before worker creation. No pre-Yes case is assigned to .025. | .020-.025 |
| 3 | `S19TuiApp._start_a2l_load` — **new extraction** from `app.py:16650-16690` | Add keyword-only `sync_project: bool = True`; own normalized-source checks, second post-Yes busy boundary, busy-run creation and one `A2LAttachRequest(..., sync_project=sync_project)`/worker launch. No view mutation or duplicate install path. | .001, .014, .020-.026 |
| 4 | `S19TuiApp.load_a2l_from_path` — `app.py:16606-16690` | **Changed:** preserve initial busy-first ordering; replace only exactly-one-project-A2L refusal with #2; ordinary routes call #3 with default `sync_project=True`. Existing validation errors keep their order. | .001, .014, .020-.026 |
| 5 | `S19TuiApp._install_attached_a2l` — `app.py:16734-16779` | **Changed:** keep `_replace_current_a2l`, cache/log/current-file attachment and deferred outcome behind #1's detail barrier; call #1 once. Call `_sync_loaded_a2l_to_project()` only when `result.request.sync_project and self.current_project`, so confirmed replacements make no project write if the old A2L disappears after Yes. | .001, .006-.019, .023, .026, .027 |
| 6 | `S19TuiApp._apply_prepared_load` — `app.py:19125-19439` | **Changed, returns `bool`:** first operation is preflight for non-`None` prepared key against expected post pair `(current A2L + bool(loaded.a2l_data), current image + 1)`. Mismatch returns `False` before any cache/session/widget/outcome work and discards the whole prepared load with no fallback. Accepted loads return `True`; `publish_a2l=True` publishes through #1 before return, while `publish_a2l=False` leaves publication to #7. C6 never owns loose sync/`Loaded`. | .002, .003, .006-.019, .026-.028 |
| 7 | `S19TuiApp._install_prepared_project` — `app.py:15078-15151` | **Changed:** preflight keyed bundles before reset; call #6 directly with `publish_a2l=False` for image/MAC and abort on any `False` (no #1/result/success/fallback). Otherwise assign project identity, install final pair and call #1 exactly once before deferred outcome. No fan-out on transient reset and no #10 wrapper. | .003, .004, .006-.019, .026-.028 |
| 8 | `S19TuiApp._apply_unload` — `app.py:18101-18242` | **Changed:** after selected clear/cache resets, use #1 instead of separate A2L/MemoryMap/Loaded calls for all four kinds; #1 also invokes #9. Preserve unrelated focus/status behavior and order outcomes behind the detail barrier. | .005-.019, .026 |
| 9 | `SplitJoinWindow.invalidate_a2l_selection` — **new public**, beside `refresh_window` at `segment_split_view.py:1722` | Clear only `_sel["a2l"]`, set `_cursor["a2l"] = 0` and `_armed = False`. Preserve manual text/state, ranges/manual selections/cursors and other window state. Do not repaint; #1 calls it before `watch_current_file`. | .005, .016 |
| 10 | `S19TuiApp._complete_prepared_load` — **new**, between `_start_load_worker` and #6 at `app.py:19759` | UI wrapper with `prepared`, `path`, `load_started`, keyword-only `gen` and `sync_project`. On C6 `True`, preserve existing project sync + `Loaded <name>`; on `False`, do neither and close busy exactly `Load superseded — current state kept.` No duplicate preflight or fallback. | .002, .028 |
| 11 | `S19TuiApp._start_load_worker` — `app.py:19650-19770` | **Changed completion tail:** keep worker parse/precompute/cache handoff/step and error paths, but replace direct C6 + separate sync + unconditional `Loaded` with one `call_from_thread(#10, prepared, path, load_started, gen=gen, sync_project=sync_project)`. No direct C6 or widget install in the worker. | .002, .026, .028 |

## 3. Unchanged context and reuse points

These are concrete read/reuse dependencies, not new edit targets. The ten primary context nodes for E2 are items C1-C10; the remaining entries are supporting read-back seams.

| Id | Function and file:line | Static role | Rows |
|---|---|---|---|
| C1 | `S19TuiApp._replace_current_a2l` — `app.py:20853-20890` | Sole A2L path/data writer; monotonic A2L generation and cache invalidation. Keep unchanged. | .001-.006, .014, .027 |
| C2 | `S19TuiApp._compute_a2l_enriched_tags` — `app.py:20892-20939` | Existing `(A2L generation, image generation, memory size)` key and ordinary cache-miss computation. Keep unchanged; E3R1 does not use it as a fallback for a superseded prepared load. | .002, .006, .012-.015, .027 |
| C3 | `S19TuiApp.update_a2l_view` — `app.py:21018-21078` | Existing summary/table renderer; refreshes MAC before rows and clears absent A2L state. #1 resets mode before reuse. | .006-.011, .018, .019 |
| C4 | `S19TuiApp._prefill_check_editor` — `app.py:7885-7907` | Existing fresh measurable rows + signature; call while visible. Oracle only name/address/format/signature, never physical values. | .012, .014, .027 |
| C5 | `S19TuiApp._prefill_patch_editor` — `app.py:7909-7928` | Patch equivalent of C4; no document/history writes or physical-value oracle. | .013, .014, .027 |
| C6 | `S19TuiApp.update_memory_map` — `app.py:20223-20265` | Pushes current enriched tags, issues and image data to MemoryMap. | .004, .005, .015 |
| C7 | `S19TuiApp.watch_current_file` — `app.py:19089-19123` | Existing Split / Join `refresh_window` seam; #1 calls #9 first, then this even when `current_file` does not change. | .005, .016 |
| C8 | `S19TuiApp._refresh_loaded_panel` — `app.py:18244-18245` (body follows) | Existing current artifact slot renderer, including A2L-only fallback in the panel. | .004, .005, .017 |
| C9 | `S19TuiApp.update_mac_view` and `update_validation_issues_view` — `app.py:20600-20653`, `:17486-17560` | Recompute A2L-dependent statuses/issues while retaining records, MAC page and Issues filter. Reached through C3. | .018, .019 |
| C10 | `S19TuiApp._prepare_load_payload` — `app.py:19487-19648` | Existing worker precompute and generation fields stay unchanged; #6 now owns preflight/supersession before installation instead of the old late fallback guard. | .026, .028 |
| — | `A2LParameterPicker.set_parameters` — `a2l_parameter_picker.py:526-574` | Changed signature repopulates; equal non-`None` signature no-ops; `None` always repopulates. **Reuse unchanged; no API delta; oracles only name/address/format/signature.** | .012-.014, .027 |
| — | `CheckEditorPanel.set_a2l_parameters` — `screens_directionb.py:7285-7314`; `PatchEditorPanel.set_a2l_parameters` — `:5375-5391` | Existing delegations preserve spec-pick reconciliation/layout behavior. Read-only, outside edit boundary. | .012, .013 |
| — | `A2LDetailCard.show_tag` — `app.py:1572-1595`; hint constant — `:1248-1250` | Existing invalidation surface and exact placeholder. | .010 |
| — | `S19TuiApp.update_alt_hex_view` — `app.py:20463-20542`; highlight field initialized at `:3060` | Existing painter; clear only `_a2l_tag_hex_highlight`, then repaint. | .011 |
| — | `SplitJoinWindow._a2l_rows` / `refresh_window` — `segment_split_view.py:1603-1629`, `:1722-1749` | Current segment derivation and refresh stay unchanged; only new public #9 is added in this file. | .016 |
| — | `ConfirmQuestionScreen` — `screens.py:2229-2318` | Existing exact Yes/No ids, `y`, `n`, Escape and boolean result. Reuse without editing `screens.py`. | .020-.025 |
| — | `S19TuiApp._refuse_if_busy` — `app.py:22655-22677` | Existing visible canonical busy refusal. .024 initial request; .025 exactly two post-Yes boundaries: N2 accepted callback and N3 pre-worker. | .024, .025 |
| — | `S19TuiApp._sync_loaded_a2l_to_project` — `app.py:16146-16188` | Existing persistence helper unchanged; #5 calls it only when `request.sync_project` is true. Confirmed replacement passes `False`, preventing writes after external old-A2L disappearance. | .020-.023 boundary |
| — | `S19TuiApp._sync_loaded_file_to_project` — existing loose-load helper called formerly at `app.py:19763-19764` | Existing helper unchanged; #10 calls it only after C6 `True` and when `sync_project and self.current_project`, preserving sync+Loaded on success and forbidding both on supersession. | .002, .028 |

## 4. Route-to-slice matrix

| Product route | Install/clear owner | Fan-out owner | Required distinguishing cases |
|---|---|---|---|
| Direct A2L attach/reload | #4/#3 → #5 → C1 | #5 → #1 (+#9) | initial/different/same path, visible Check/Patch name/address/format/signature, filter state, project Yes/No, initial busy and two post-Yes boundaries, `sync_project=False` on confirmed replacement |
| Loose image load/reload with A2L | #11 worker → #10 → #6 preflight → C1 only on match | accepted #6 → #1 (+#9), then #10 sync+`Loaded`; rejected #6 → #10 exact superseded outcome | C6 `True` preserves sync+Loaded; C6 `False` gives no sync/Loaded and closes busy `Load superseded — current state kept.`; previous state kept, no fallback |
| Project image+A2L | #7 bundle preflights/reset/assign → #6(`publish_a2l=False`) direct | #7 after all accepted installs → #1 (+#9) | any C6 `False` aborts without #10; otherwise exactly one final coherent fan-out, Loaded/MAC/Issues preserved, no intermediate reset painted |
| Project A2L-only/empty | #7 no-image branch → C1 | #7 → #1 (+#9) | empty and image-bearing outgoing sessions; no `LoadedFile`; A2L generation > old, image generation equal |
| Unload `primary`/`mac`/`a2l`/`all` | #8 (C1 for A2L/all) | #8 → #1 (+#9) | all four kinds plus A2L-only unload; current empty/retained artifacts in every live view; Split A2L selection/cursor/arm invalidated, manual preserved |

## 5. Explicitly outside the slice and E3R1 closure notes

- **Historical results:** no rewrite of check verdicts, before/after reports, flow results, saved documents or undo/redo history; no new result artifact or historical-result requirement.
- **Other product modules:** no edit to `screens_directionb.py`, `screens.py`, parser/reader modules, services or styles. `segment_split_view.py` is permitted only for #9.
- **Adjacent increments:** no Inc 6 array/format/picker correctness work and no Inc 7 list parser, autocomplete or viewer-list feature work; picker oracles never include physical values.
- **Persistence:** no project-file deletion/overwrite, manifest change or rollback design for replacing an A2L on disk; Yes installs the session A2L only, with `sync_project=False` to prevent post-Yes external-disappearance writes. Loose file sync remains in #10 after accepted C6 only.
- **API churn:** no new picker method, argument, event or return type. If the existing picker seam proves insufficient, stop and reopen D-3 rather than expanding silently.
- **E3R1-Q8 closed:** #11 now calls #10, which consumes C6 `bool`; accepted preserves sync+Loaded, rejected skips both and ends with the exact superseded text. C7 still calls #6 directly and aborts on `False`.
- **E3R1-Q9 closed:** the orchestrator has updated R-A2L-REFRESH.028 to whole-prepared discard, previous state, no success and the exact superseded outcome. #6/#10/#7 implement those arms without stale-cache fallback. `01-requirements.md` was not edited in this closure.
- **Final count:** **11 implementation (6 changed + 5 new) + 10 context = 21 nodes; 3 permitted source files, 2 changed.**
