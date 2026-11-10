# Code-Wire graph — Inc 5 (every live view current after an A2L transition), batch-103

Stage E2 of `dev-flow-v3-beta`, corrected at **E3 round 1** on 2026-11-10, model Kimi. **Graph only:** no stub, extractor mark or declaration was added to any product tree. No application, test or probe was run; no GREEN or runtime result is claimed. Requirements `../01-requirements.md` (R-A2L-REFRESH.001 … .028), rulings `../E1-rulings.md` (D-1/D-4/D-7 as corrected), slice `../E1-slice.md`. Base references are the current static worktree lines used by E1. The extractor was not needed: the real entry/callback sites below were read directly. Notation follows Code-Wire v3.1.0 and the batch's Inc 4/Inc 12 graphs.

## 1. Delta, ownership and pinned interfaces

The delta is exactly **6 changed functions + 4 new/extracted functions in `app.py` + 1 new public function in `segment_split_view.py` = 11 implementation nodes**, plus **10 unchanged primary context nodes**. Estimated graph: **21 nodes**, below the 40-node cap. There are **3 permitted source files**, 2 planned to change; `a2l_parameter_picker.py` remains unchanged and there is no picker API change. E3R1-Q8/Q9 are closed by the wrapper and the orchestrator's updated .028.

| Group | Files | Owns |
|---|---|---|
| G1 app implementation | `s19_app/tui/app.py` | N1-N3/N5 and C4-C9 below; no new module, widget class or event bus |
| G2 Split / Join invalidation | `s19_app/tui/segment_split_view.py` | N4 `SplitJoinWindow.invalidate_a2l_selection`, the only new public method in this increment |
| G-T future independent tests | test paths are not allocated at E2 | the 56 graph examples expanded to the E1 numeric thresholds, product-route read-back, thread/order spies and negative controls; no test file written here |
| Read-only dependencies | `a2l_parameter_picker.py`, `screens_directionb.py`, `screens.py`, `a2l_describe.py` | existing picker/panel seams, modal and description modal; no edits |

### I-4 — A2L refresh contract (PINNED; change only by orchestrator ruling)

1. **Identity.** The existing pair `(_a2l_view_generation, _image_generation)` is the refresh identity. The existing enrichment key remains `(A2L generation, image generation, len(mem_map) if mem_map is not None else -1)`. There is no third generation and no path/object-identity substitute.
2. **Single state writer.** `_replace_current_a2l` remains the only writer of `current_a2l_path/current_a2l_data`. A direct attach or A2L-only project install increments A2L generation and leaves image generation unchanged. A project may increment A2L generation more than once (reset + install); **exactly +1 is not a contract**.
3. **Single publication and completion.** After a coherent install/clear, N1 runs once on the UI thread and all live consumers read the same post-install state. A project reset publishes nothing. For loose file loads, C9 calls N5 through `call_from_thread`; N5 calls C6, and only C6's `True` permits project sync and `Loaded <name>`. C6's `False` permits neither and N5 closes busy with the exact outcome `Load superseded — current state kept.` C7 continues to call C6 directly and aborts on `False`.
4. **Preflight freshness (E3R1/Q8/Q9 closed).** Before C6 performs **any** cache/session/widget/outcome work, a non-`None` `prepared.a2l_enriched_key` requires `actual == expected`, where `actual = (prepared.a2l_view_generation, prepared.a2l_image_generation)` and `expected = (current_a2l_generation + int(bool(prepared.loaded.a2l_data)), current_image_generation + 1)`. A mismatch marks the whole `PreparedLoad` **superseded**: C6 returns `False` immediately, with no partial installation, stale-cache fallback, UI recompute, widget work or C6 outcome. Only an exact match may install the prepared values. N5 supplies the sole loose-route superseded outcome; previous state is kept and no success is painted.
5. **Picker interface and oracle (unchanged API; E3R1-narrowed assertions).** Check/Patch receive `rows = [tag for tag in _a2l_enriched_tags if isinstance(tag.get("address"), int)]` through the existing app prefills and `set_parameters(rows, _a2l_enriched_key)`. Equal non-`None` keys retain the existing no-op; `None` always repopulates, including clear. Picker oracles assert **name, address, format (`Fmt · Unit`/normalized size-format tuple) and signature only**. They do not assert raw or physical values; those belong to the A2L Viewer, not the parameter-picker contract.
6. **Consumer contract.** Inc 6 consumes the same prefill/signature seam. Inc 7 may build an index once per observed A2L view generation and must discard an index/result older than the live generation. MemoryMap, Split / Join, MAC, Issues and Loaded consume current app state through existing seams; no second event bus. Every Split / Join A2L transition also invokes N4 before `watch_current_file`.
7. **Thread contract.** Workers copy/parse/precompute only. All N1/N4/N5 calls and widget mutations are UI-thread work. C9 reaches N5 through `call_from_thread`; existing deferred install callbacks remain the worker-to-UI boundary.
8. **Persistence boundary (E3R1).** Yes replaces only the session A2L. `A2LAttachRequest` gains `sync_project: bool = True` after `gen`, preserving existing positional construction. N3 has the same keyword-only default and passes it into the request. N2's confirmed replacement always calls N3 with `sync_project=False`; C5 calls `_sync_loaded_a2l_to_project()` only when `result.request.sync_project and self.current_project`. Thus, if the old project A2L disappears externally after Yes, no new project file/manifest is written. Loose file-load sync uses N5's separate `sync_project` argument and occurs only after C6 returns `True`.

### Internal interfaces pinned by this delta

```text
N1 S19TuiApp._refresh_a2l_dependent_views(self) -> None

N2 S19TuiApp._confirm_project_a2l_replacement(
    self, path: Path, normalized: Path, *, copy: bool,
    project_name: str, project_dir: Path, project_a2l: Path,
) -> None

N3 S19TuiApp._start_a2l_load(
    self, path: Path, normalized: Path, *, copy: bool,
    sync_project: bool = True,
) -> None

N4 SplitJoinWindow.invalidate_a2l_selection(self) -> None

N5 S19TuiApp._complete_prepared_load(
    self, prepared: PreparedLoad, path: Path, load_started: float,
    *, gen: int, sync_project: bool,
) -> None

C6 S19TuiApp._apply_prepared_load(
    self, prepared: PreparedLoad, path: Path, load_started: float,
    *, publish_a2l: bool = True,
) -> bool
```

- `path` is the original input used by the existing recent-source/fallback and message logic; `normalized` is the already-admitted source used for stat/copy/parse. N3 repeats the busy check and the existing post-guard source checks, then creates exactly one `A2LAttachRequest(..., sync_project=sync_project)` and starts exactly one worker.
- `publish_a2l=True` is the loose-file/default behavior: an accepted C6 calls N1 synchronously before returning `True`. `False` is used only by C7 while it installs a project's image/MAC; C7 publishes once after the final pair and after assigning the new project identity. **`True` means the prepared load was accepted for installation (with publication when requested); `False` means superseded preflight rejection.** C7 aborts on any `False`.
- N5 is the only loose-file completion wrapper. On `True`, it preserves the existing `sync_project and self.current_project → _sync_loaded_file_to_project()` behavior and then `end_busy("file_load", gen, f"Loaded {painted_names([path.name])}")`. On `False`, it skips both and calls only `end_busy("file_load", gen, "Load superseded — current state kept.")`.
- Project/A2L identity comparisons use `normcase(abspath(path))` on the lexical path, never `resolve()` and never object identity. The callback revalidates the captured project name, project directory and exactly-one-A2L listing before N3. N2 and N3 are separate post-Yes busy boundaries; no pre-Yes busy case is attributed to R-A2L-REFRESH.025.

## 2. Baseline and real callers (static read)

| Node | Current `file:line` | Real caller / baseline delta |
|---|---|---|
| C4 `load_a2l_from_path` | `app.py:16606-16690` | typed A2L route `:16382-16385`; workarea candidate `:17035`; direct tests/fixtures. Busy is checked first; exactly one project A2L currently returns at `:16644-16647`; post-guard body starts the worker |
| C5 `_install_attached_a2l` | `app.py:16734-16779` | `_on_a2l_attached` via `call_after_refresh` at `:16729-16732`; currently installs, calls `update_a2l_view`, labels/Loaded, then synchronous `end_busy` |
| C6 `_apply_prepared_load` | `app.py:19125-19439` | `_apply_loaded_file` at `:18845`; loose file loads through new N5; C7 image/MAC directly with `publish_a2l=False`. Returns acceptance `bool`; no caller may treat `False` as a minimal-load fallback |
| C7 `_install_prepared_project` | `app.py:15078-15151` | `_on_project_loaded` at `:15068-15076`; currently resets, installs no-image A2L before assigning `current_project`, then installs image and MAC separately |
| C8 `_apply_unload` | `app.py:18101-18242` | Loaded-panel message at `:18335`; Unload-all action at `:18362`; currently performs the renderer tail and writes unload status synchronously |
| C9 `_start_load_worker` | `app.py:19650-19770` | existing loose-load worker; currently calls C6 directly and unconditionally schedules sync/`Loaded`. Changed only in its completion tail to call N5 instead |
| N1 `_refresh_a2l_dependent_views` | new beside `update_a2l_view` (`app.py:21018`) | called by C5, C6 (when `publish_a2l=True`) and C7/C8 |
| N2 `_confirm_project_a2l_replacement` | new beside `load_a2l_from_path` | called only by C4's exactly-one-project-A2L arm |
| N3 `_start_a2l_load` | extracted from `app.py:16650-16690` | called by C4's ordinary arm (`sync_project=True`) and N2's accepted/revalidated arm (`False`) |
| N4 `invalidate_a2l_selection` | new public method beside `segment_split_view.py:1722` | called by N1 immediately before the existing `watch_current_file` seam |
| N5 `_complete_prepared_load` | new between C9 and C6 | C9's sole `call_from_thread` completion callback; consumes C6 `bool`, owns loose sync/`Loaded` versus exact superseded outcome |

No product caller is added to `a2l_parameter_picker.py`: N1 reaches its existing API through the existing app prefills and panel shims. `A2LAttachRequest` (`app.py:563-573`) gains only the defaulted field `sync_project: bool = True` after `gen`; existing positional/test construction remains valid, and N3 always passes the keyword explicitly.

## 3. Nodes

### N1 — `S19TuiApp._refresh_a2l_dependent_views`

req: R-A2L-REFRESH.001 … .019, .023, .026, .027  
in: none; reads only the coherent current session and mounted widgets  
out: `None`  
module: `s19_app/tui/app.py`  
modify: `[Data: A2L Viewer]`, `[Data: Check/Patch picker]`, `[Data: Memory Map]`, `[Data: Split / Join]`, `[Data: Loaded/MAC/Issues]` (refresh, never historical results)

func: **new.** The only A2L-transition view coordinator. UI-thread callers only. The order is pinned as follows; step 0 deliberately precedes the render so an old `inmem`/`invalid` predicate cannot filter the new payload.

0. Preserve by doing nothing to the filter input or field. Set `a2l_tags_filter_mode = "all"`. For the three existing buttons, set `variant="primary"` on `#a2l_filter_all` and `variant="default"` on `#a2l_filter_invalid` and `#a2l_filter_inmem`; this is the visible active mark and needs no CSS edit.
1. Call `update_a2l_view()`. It computes/accepts only the live enrichment, refreshes MAC and Issues before painting tag rows, applies the retained text/field with mode `all`, and renders summary or empty state.
2. Set `_a2l_tag_hex_highlight = None`; call `update_alt_hex_view()` with no focus/reset argument, so no old tag span survives and unrelated window state is not invented.
3. If the visible/top screen is a `CurveDescriptionScreen`, dismiss it with `None` (a buried screen is not a live view; unrelated modals are never popped). Immediately call `A2LDetailCard.show_tag(None)`. Register `call_after_refresh(card.show_tag, None)` as the **detail barrier**, so a `RowHighlighted` message queued by table repopulation is processed before the final invalidation. Do not auto-select a replacement tag.
4. Call `_prefill_check_editor()` and `_prefill_patch_editor()` using the already refreshed enrichment/key. Their existing missing-panel guards and panel shims are unchanged; no document load, dirty-flag change, undo/redo operation or historical check rerun occurs. Picker assertions are limited to names, addresses, format and signature; raw/physical values are not picker oracles.
5. Call `update_memory_map()`. Resolve `#screen_split_join` with the existing guarded-query idiom and call its public N4 `invalidate_a2l_selection()` before calling `watch_current_file()`; finish with `_refresh_loaded_panel()`. Both Split calls are required even when `current_file` is unchanged. N4 clears A2L selection/cursor and `_armed` while `watch_current_file` refreshes rows. Manual text/state is preserved. Existing project labels, focus restoration and unrelated load tails remain outside N1.
6. Return. The route's outcome is registered after N1, hence after the detail barrier. For C5/C7, `end_busy` is deferred with `call_after_refresh`; for C8 the two unload status writes keep their order through `call_after_refresh`. For the file worker, its existing `end_busy` is scheduled only after C6 returns, so an accepted load is also behind the barrier.

State preserved: exact filter text and selected field; primary image/MAC when the route does not replace them; MAC records/page (existing clamp); Issues severity filter; Split / Join manual text/state and ranges/manual selections; Patch document/dirty/undo/redo; historical check/flow/report outputs. State deliberately invalidated: A2L mode (to `all`), first A2L page, row selection, Detail Card, visible description modal, A2L-tag hex span and Split / Join A2L selection/cursor plus `_armed`.

examples: (I5-001-A/B through I5-019-A/B, I5-023-A/B, I5-026-A/B, I5-027-A/B in §6) each gives the pre-state, trigger and exact post-state; the B examples are mutants expected RED, not runs.

### N2 — `S19TuiApp._confirm_project_a2l_replacement`

req: R-A2L-REFRESH.020 … .025  
in: original `path`; admitted `normalized`; `copy`; captured `project_name`, `project_dir`, `project_a2l`  
out: `None`; pushes one existing `ConfirmQuestionScreen`  
module: `s19_app/tui/app.py`

func: **new.** Compose exactly title `Replace project A2L?`, body `Project '<project name>' already has A2L '<current file>'. Load '<new file>' instead?`, buttons `Yes (y)` and `No (n)`, with each name passed once through `painted_names`. Push the existing modal with a boolean callback. No copy, parse, busy run, worker or session mutation precedes the answer.

- `False` (No button, `n`, Escape): return with no status/outcome synthesis, no focus helper, no worker start/cancel and no state/project-file write. The modal's own dismissal restores its prior focus.
- `True`: defer the accepted callback with `call_after_refresh`. **Post-Yes boundary 1:** the accepted callback first calls `_refuse_if_busy()`; if true, stop. Re-read active project identity and `validate_project_files`. Existing unreadable/validation errors use their existing status text. If the captured project/A2L identity differs, start no worker and install nothing; the proposed visible refusal is `A2L NOT loaded: project or its A2L changed — load again.` Otherwise call N3 with the captured original/normalized paths, `copy`, and **`sync_project=False`**. N3 is **post-Yes boundary 2**, checking busy again immediately before busy-run/request/worker creation.

A same-path question compares path identity, not content; changed content at the same path remains a valid confirmed reload. Multiple A2Ls never reach this node. R-A2L-REFRESH.025 covers only those two post-Yes boundaries, not an action that began before Yes. `sync_project=False` remains attached to the request through worker completion, so C5 cannot write to the project if the old A2L disappears externally after confirmation.

examples: (I5-020-A exact different-path modal; I5-020-B old terminal refusal; I5-021-A Escape invariance; I5-021-B falsy-as-accept mutant; I5-022-A/B identity race; I5-023-A/B accepted install with sync disabled; I5-024-A/B initial busy; I5-025-A/B two post-Yes busy boundaries)

### N3 — `S19TuiApp._start_a2l_load`

req: R-A2L-REFRESH.001, .014, .020 … .026  
in: original `path`; admitted `normalized`; `copy`; `sync_project=True`  
out: `None`; starts one normal A2L worker on success  
module: `s19_app/tui/app.py`

func: **new extraction**, not a second loader. Recheck `_refuse_if_busy()` immediately before any busy-run/request/worker creation (the second post-Yes boundary), then execute the existing post-project-guard body: source stat/missing handling, large-file log, recent-source decision using original `path` versus `normalized`, `_busy_begin_action("a2l_load", normalized.name)`, one `A2LAttachRequest(source=normalized, copy=copy, …, gen=gen, sync_project=sync_project)`, existing `step_busy` for `copy=False`, and `_a2l_attach_worker(request)`. Existing `BaseException → _busy_fail` behavior remains. No widget or current-A2L mutation occurs here. Ordinary C4 calls use the default `True`; the N2 confirmed replacement always supplies `False`.

examples: (I5-001-A) one request leads to C5/N1 before outcome; (I5-014-A) equal source path does not short-circuit; (I5-020-A) zero requests before modal; (I5-022-A/B) identity failure gives zero requests; (I5-023-A) confirmed request carries `sync_project=False`; (I5-025-A) each post-Yes busy boundary gives zero additional requests; (I5-026-B) a UI call here/worker side is the negative control.

### C4 — `S19TuiApp.load_a2l_from_path`

req: R-A2L-REFRESH.001, .014, .020 … .026  
in: `path: Path`; `copy: bool = True` (public signature unchanged)  
out: `None`  
module: `s19_app/tui/app.py`

func: **changed.** was: busy → normalize/missing/suffix → project validation → terminal refusal for exactly one project A2L → source checks/recent/busy/worker. now: retain busy-first and all existing missing/suffix/project validation errors; for exactly one project A2L call N2 and return; every other admissible route delegates to N3 with original and normalized paths and the default `sync_project=True`. No direct worker body remains here and no project-file write is added.

examples: (I5-014-A loose same-path, I5-020-A project question, I5-021-A cancellation, I5-024-A initial busy, I5-026-A thread ownership; B arms pin refusal/short-circuit races)

### C5 — `S19TuiApp._install_attached_a2l`

req: R-A2L-REFRESH.001, .006 … .019, .023, .026, .027  
in: `result: A2LAttachResult`  
out: `None`; success outcome deferred behind N1's detail barrier  
module: `s19_app/tui/app.py`

func: **changed.** Keep recent-source recording, file refresh/cache store, `_replace_current_a2l`, parse log and `current_file.a2l_path/a2l_data` attachment in their current order. Remove the viewer-only `update_a2l_view` block and standalone Loaded refresh; call N1 once after current-file attachment. Keep `update_project_labels` and logging. Replace the project-sync condition with `if result.request.sync_project and self.current_project: self._sync_loaded_a2l_to_project()`; therefore a confirmed replacement (`False`) never writes a project file/manifest even if the old A2L vanished after Yes. Replace the direct successful `end_busy` with `call_after_refresh(self.end_busy, "a2l_load", gen, <existing safe text>)`; it is registered after N1's detail barrier. Failure and `BaseException → _busy_fail` arms are unchanged.

examples: (I5-001-A `refresh@ui` precedes `A2L loaded`; I5-006-A Alpha/Gamma replace Alpha/Beta; I5-010-A modal+settled-card invalidation; I5-012/013-A visible prefills; I5-015/016/017/018/019-A all dependent surfaces; I5-023-A `sync_project=False` skips project sync; I5-027-A generation values)

### C6 — `S19TuiApp._apply_prepared_load`

req: R-A2L-REFRESH.002, .003, .006 … .019, .026 … .028  
in: `prepared`; `path`; `load_started`; `publish_a2l=True`  
out: `bool`; `False` = superseded before installation, `True` = accepted (and published when requested)  
module: `s19_app/tui/app.py`

func: **changed.** **Preflight is the first operation**, before `_store_a2l_cache`, variant stamping, `current_file`, `_change_service`, generation changes, cache clears, widget calls, status/log outcome or deferred steps. If `prepared.a2l_enriched_key is not None`, compute `expected = (self._a2l_view_generation + (1 if prepared.loaded.a2l_data else 0), self._image_generation + 1)` and compare it with `(prepared.a2l_view_generation, prepared.a2l_image_generation)`. On mismatch, discard the whole prepared load as superseded and return `False` immediately. There is no stale-cache fallback, no UI recomputation and no partial prepared/minimal installation. The old late “discard enrichment but continue installing” guard is removed, not duplicated.

On a match (or no prepared key), keep the existing cache/state installation, `_image_generation` semantics, Patch/document invalidation and `_replace_current_a2l`; install the already accepted prepared enrichment/key/summary directly. Keep deferred sections/main-hex steps for responsiveness. Remove `_step_a2l` and A2L/MemoryMap/Loaded work from `_step_finalize`; at the end, if `publish_a2l` is true call N1 synchronously, then schedule the remaining sections/hex chain. If false, schedule no A2L fan-out; C7 owns the single final publication. Return `True` after the accepted work.

C6 never calls the loose-file sync or outcome helpers. N5 consumes its return; C7 consumes it directly and aborts on `False`. Synchronous publication for an accepted loose load still finishes before N5's sync/`Loaded` tail.

examples: (I5-002-A equal-size image replacement produces fresh membership before `Loaded`; I5-003-A `publish_a2l=False` prevents intermediate project paint and a `False` result aborts C7; I5-018/019-A current MAC/Issues; I5-026-A no worker paints; I5-028-A/B both stale dimensions reject the whole prepared load with no fallback)

### N5 — `S19TuiApp._complete_prepared_load`

req: R-A2L-REFRESH.002, .028  
in: `prepared`; `path`; `load_started`; keyword-only `gen: int`, `sync_project: bool`  
out: `None`; loose completion after C6 acceptance/supersession  
module: `s19_app/tui/app.py`

func: **new.** UI-thread wrapper between C9 and C6. Call `accepted = self._apply_prepared_load(prepared, path, load_started)` (default `publish_a2l=True`). If `accepted` is `False`, make no `_sync_loaded_file_to_project` call and no `Loaded` outcome; call exactly `self.end_busy("file_load", gen, "Load superseded — current state kept.")` and return. If `accepted` is `True`, preserve the existing behavior: when `sync_project and self.current_project`, call `_sync_loaded_file_to_project()`; then call `self.end_busy("file_load", gen, f"Loaded {painted_names([path.name])}")`. C6 has already completed N1 before either tail. N5 contains no preflight duplicate and no fallback.

examples: (I5-002-A) accepted load → N1, optional project sync, `Loaded img2.hex`; (I5-028-A) preflight `False` → 0 sync calls, 0 `Loaded`, busy outcome exactly `Load superseded — current state kept.` and previous state unchanged; (I5-028-B) sync or `Loaded` on `False` → RED.

### C9 — `S19TuiApp._start_load_worker`

req: R-A2L-REFRESH.002, .026, .028  
in: existing `path`, optional `a2l_files`, keyword-only `gen`, `sync_project=True` (signature unchanged)  
out: `None`; worker parse/precompute and one UI completion dispatch  
module: `s19_app/tui/app.py`

func: **changed only in its completion tail.** Keep worker parse, preparation, existing non-keyed minimal preparation for actual prepare exceptions, cache handoff, logging, `step_busy("file_load", gen, 3)` and error routing. Replace the direct `call_from_thread(self._apply_prepared_load, …)`, separate project sync and unconditional `Loaded` with one `call_from_thread(self._complete_prepared_load, prepared, path, load_started, gen=gen, sync_project=sync_project)`. C9 performs no widget/session installation itself and never calls C6 directly. Existing outer `BaseException → _busy_fail` remains for actual exceptions, not preflight supersession.

examples: (I5-026-A) C9 worker thread prepares only; N5/C6/N1 run on UI; (I5-028-A) C6 `False` reaches N5 and produces only the exact superseded outcome; (I5-028-B) leaving the old unconditional sync/`Loaded` tail after C6 → RED.

### C7 — `S19TuiApp._install_prepared_project`

req: R-A2L-REFRESH.003, .004, .006 … .019, .026 … .028  
in: `prepared: PreparedProjectLoad`  
out: `None`; aborts on any superseded C6; otherwise one final publication and deferred success outcome  
module: `s19_app/tui/app.py`

func: **changed.** Build the non-precomputed image/MAC bundles first. Before `_reset_project_session`, evaluate the same C6 preflight for every bundle with a key; any superseded bundle aborts before project/session/widget/outcome mutation. Today these bundles have `a2l_enriched_key=None`, so this guard is inert but pins the atomic route. Then keep reset/admission/cache/document/manifest behavior. The no-variant/no-MAC arm still calls `_replace_current_a2l(install.a2l, data)` but no longer paints before project assignment. Assign `current_project` and `current_project_dir`, refill document lists and set the variant as today.

For an image or MAC, call C6 directly with its bundle and `publish_a2l=False`; C6 repeats its own preflight. **If either call returns `False`, return immediately with no N1, result screen or successful outcome.** There is no fallback from a rejected bundle's caches. Since these UI calls do not yield, a key admitted by C7's preflight remains stable through C6.

After all accepted image/MAC installs and after the new project identity is assigned, call N1 exactly once for **every** project route: image+A2L, A2L-only, image/MAC without A2L, and empty project. Then keep `update_project_labels`, flow-session publication and result-screen behavior. Register successful `end_busy("project_load")` with `call_after_refresh` after N1's detail barrier. No N1 call occurs in `_reset_project_session` or in either accepted C6(`publish_a2l=False`) call.

examples: (I5-003-A exactly one final fan-out; I5-003-B any C6 `False` aborts without final publication/outcome; I5-004-A A2L-only has current project/A2L and no `LoadedFile`; I5-017-A Loaded names the new project; I5-027-A project A2L generation may advance twice while image generation stays equal; I5-028-A project supersession aborts before reset)

### C8 — `S19TuiApp._apply_unload`

req: R-A2L-REFRESH.005 … .019, .026  
in: `kind: Literal["primary", "mac", "a2l", "all"]` (existing string contract)  
out: `None`; common refresh before ordered unload outcome  
module: `s19_app/tui/app.py`

func: **changed.** Keep early no-op cases, `_unload_*`/snapshot installation, A2L clear through `_replace_current_a2l` for `a2l/all`, Patch `set_image_mem_map(None)` for primary/all, cache resets, sections and the three hex updates, project labels and empty-state handling. Replace separate `update_a2l_view`, `update_memory_map` and `_refresh_loaded_panel` with one N1 after those state changes. Register `set_file_status(f"Unloaded {label}.")` then `set_status(f"Unloaded {label}.")` through `call_after_refresh` after N1's detail barrier; keep the existing focus landing last. N1's N4 call clears Split A2L selection/cursor and `_armed` on every kind.

examples: (I5-005-A all four kinds + A2L-only; I5-009-A mode reset; I5-011-A old span gone; I5-013-A Patch empty but document retained; I5-016-A no-A2L note, A2L selection disarmed and manual preserved; I5-018/019-A retained MAC/Issues state)

### N4 — `SplitJoinWindow.invalidate_a2l_selection`

req: R-A2L-REFRESH.005, .016  
in: none  
out: `None`  
module: `s19_app/tui/segment_split_view.py`  
modify: `[Data: Split / Join A2L selection/cursor/arm]`

func: **new public method**, beside `refresh_window` (`segment_split_view.py:1722`). Execute exactly `self._sel["a2l"].clear()`, `self._cursor["a2l"] = 0`, `self._armed = False`, then return. Do not change `_a2l_rows_cache_src/_a2l_rows_cache` (N1's following `watch_current_file` refreshes them from current data), ranges/manual selections or cursors, `#sje_manual.text`, `_manual_dropped`, mode/gap/pad/format/destination/pattern or loaded-image state. It paints nothing itself; N1 calls it immediately before `watch_current_file`, so the old A2L selection is invalid before the refreshed rows are planned and no export remains armed for the old segments.

examples: (I5-016-A) A2L-A selected row 0/cursor 0 and armed, manual `0x4000-0x40ff`, A2L-B attach → A2L selection empty, cursor 0, `_armed=False`, RAM rows refreshed, manual and ranges/manual state unchanged; (I5-016-B) omit N4 while retaining only `watch_current_file` → selected index and armed export survive onto RAM.

## 4. Read-only context nodes (10)

| Id | Function `file:line` | Contract consumed, unchanged |
|---|---|---|
| C1 | `_replace_current_a2l` — `app.py:20853-20890` | sole current-A2L writer; increments `_a2l_view_generation`; invalidates enrichment/filter/row-key caches; no painting added |
| C2 | `_compute_a2l_enriched_tags` — `app.py:20892-20939` | existing generation+image+memory-size key; absent A2L gives empty rows/key `None`; UI recompute on miss |
| C3 | `update_a2l_view` — `app.py:21018-21078` | summary/table plus MAC/issues ordering; N1 sets mode before calling it |
| C4x | `_prefill_check_editor` — `app.py:7885-7907` | fresh measurable rows and current signature; no screen activation required by N1; oracle only name/address/format/signature |
| C5x | `_prefill_patch_editor` — `app.py:7909-7928` | Patch equivalent; no document/history refresh; no raw/physical-value oracle |
| C6x | `update_memory_map` — `app.py:20223-20265` | pushes current enriched tags/issues/image; no synthetic file for A2L-only |
| C7x | `watch_current_file` — `app.py:19089-19123` | existing Split / Join `refresh_window` call; N1 invokes N4 first, then this seam even when `current_file` identity is unchanged |
| C8x | `_refresh_loaded_panel` — `app.py:18244` | current artifact renderer; called after C7 assigns new project identity |
| C9x | `update_mac_view` / `update_validation_issues_view` — `app.py:20600`, `:17486` | recompute A2L relationships while retaining MAC records/page and Issues severity filter |
| C10 | `_prepare_load_payload` — `app.py:19487-19648` | unchanged worker preparation and generation fields; C6's new preflight owns acceptance/supersession before any install; no stale prepared value reaches N1 |

Supporting external seams, also unchanged: `A2LParameterPicker.set_parameters` (`a2l_parameter_picker.py:526-574`), both panel shims (`screens_directionb.py:5375-5391`, `:7285-7314`), `A2LDetailCard.show_tag` (`app.py:1572-1595`), `update_alt_hex_view` (`:20463-20542`), `SplitJoinWindow._a2l_rows/refresh_window` (`segment_split_view.py:1603-1629`, `:1722-1749`; N4 is the only new method in that file), `ConfirmQuestionScreen` (`screens.py:2229-2318`), `CurveDescriptionScreen` (`a2l_describe.py:31-97`), `_refuse_if_busy` (`app.py:22655-22677`) and `_sync_loaded_a2l_to_project` (`:16146-16188`, called by C5 only when `request.sync_project` is true).

## 5. Concrete fixtures and state sentinels

These are design inputs for E4, not files generated at E2.

- **A2L-A:** tags `Alpha@0x1000/2`, `Beta@0x1002/2`; segment `FLASH@0x1000+0x100`. **A2L-B:** `Alpha@0x1000/2`, `Gamma@0x2000/2`; segment `RAM@0x2000+0x100`. **A2L-A′:** A2L-A plus `Delta@0x1004/2` and `FLASH2@0x3000+0x80`, written at the same source path as A2L-A.
- **IMG-1:** S19, 16 bytes at `0x1000`, all `0x00`. **IMG-2:** Intel HEX, 16 bytes at `0x2000`, all `0xFF` (equal map size, different addresses/content). **MAC-1:** 150 records, including `Alpha@0x1000` and `Old@0x3000`; page size 100, current page 2.
- **P-IMG-A / P-IMG-B:** projects containing IMG-1+A2L-A and IMG-2+A2L-B respectively. **P-A2L:** A2L-A only, no image/MAC. **P-OLD:** active project `cal` containing exactly `old.a2l`.
- **View state:** filter input exactly `  Alpha  `, field `name`, mode initially `inmem` or `invalid`; Detail Card on Beta; A2L hex span `(0x1002, 2)`; description modal for Beta; Split A2L selection `{0}`, A2L cursor `0`, `_armed=True`, ranges/manual sentinels retained, manual text `0x4000-0x40ff`; Issues filter `warning`; Check spec `spec-a.json`; Patch document dirty with undo/redo depths `(2,1)`; historical sentinels `check-run-7` and `flow-report-9`.
- **Order oracle:** an event list records `N1:start`, each view mutation and its thread, `N1:detail-barrier-registered`, outcome. Views are read back visibly without manual refresh or screen re-entry. Spies supplement, never replace, painted/model assertions.

## 6. Row → nodes → concrete examples (56)

`A` is a positive or alternative example. `B` is the named negative control/mutant and its expected RED observation. These are graph examples, not `02-test-cases.md` allocations and not results.

| Row | Nodes | A — concrete input → expected output | B — negative control → RED observation |
|---|---|---|---|
| .001 | C4,N3,C5,N1 | **I5-001-A:** empty session, attach A2L-A → one worker; event order `N1 … detail-barrier … A2L loaded: a.a2l`; all mutations UI; no manual action. | **I5-001-B:** remove C5→N1 → Check/MemoryMap/Split remain empty at the success outcome. |
| .002 | C9,N5,C6,N1,C1,C2 | **I5-002-A:** A2L-A attached, IMG-1 then equal-size IMG-2 → C6 `True`, Alpha/Beta `in_memory` yes→no, N1 precedes N5's existing project sync and `Loaded img2.hex`. | **I5-002-B:** remove image generation from C2's key → equal-size reload reuses yes values; bypassing N5 drops the bool/outcome contract. |
| .003 | C7,C6,N1 | **I5-003-A:** P-IMG-A → P-IMG-B with image+MAC installs → each C6 returns `True` with `publish_a2l=False`, N1 exactly once after final pair/project identity, then outcome. | **I5-003-B:** any C6 returns `False` → C7 aborts with no N1/result/success outcome and no fallback; publishing in reset or after image before MAC also fails the coherent-pair oracle. |
| .004 | C7,N1,C6x,C8x | **I5-004-A:** empty → P-A2L → Alpha/Beta and A2L-A Loaded slot visible, `current_file is None`, pickers have two rows, Split has FLASH, Memory Map says no file. | **I5-004-B:** require a synthetic `LoadedFile` → phantom image appears and .027's unchanged image-generation assertion fails. |
| .005 | C8,N1,N4 | **I5-005-A:** from IMG-1+MAC-1+A2L-A run primary/mac/a2l/all independently, plus P-A2L `a2l` → each removed artifact disappears from every view; Split A2L selection/cursor/`_armed` clear while manual survives; retained artifacts/status are current before `Unloaded …`. | **I5-005-B:** retain the old renderer-only tail or omit N4 → Split FLASH/selection/arm and a visible picker still name or act on unloaded A2L-A. |
| .006 | N1,C2,C3 | **I5-006-A:** replace A2L-A with A2L-B → exact rows Alpha,Gamma; Beta absent; summary 2 tags and Gamma in-image under IMG-2; A2L unload gives 0 rows + `No A2L loaded.` | **I5-006-B:** reuse prior enrichment → Beta remains painted. |
| .007 | N1,C3 | **I5-007-A:** input `  Alpha  ` through attach/image/project/unload → byte-identical input, stripped matching gives Alpha only; no-match `Missing` gives `No A2L tags match 'Missing'.` | **I5-007-B:** clear the input during N1 → value becomes empty and Alpha+Gamma both paint. |
| .008 | N1,C3 | **I5-008-A:** choose field `address`, text `0x2000`, attach A2L-B → button remains `Field: address`, only Gamma; repeat project/unload preserving field. | **I5-008-B:** reset field with mode to `all` → name-field matching returns zero rows. |
| .009 | N1,C3 | **I5-009-A:** start `inmem`, attach A2L-B → model `all`, All `variant="primary"`, Invalid/In-Memory `default`, Alpha+Gamma shown (with empty text). Repeat from `invalid` and after unload. | **I5-009-B:** preserve `inmem` → only Gamma appears; reset model without variants → visible active state is wrong. |
| .010 | N1,C5/C6/C7/C8 | **I5-010-A:** Beta card+description open while A2L-B attach completes → top description dismissed, card immediately hint and still `Highlight a tag to inspect its fields.` after queued highlights/outcome. | **I5-010-B:** omit the after-refresh card barrier → queued row-0 highlight paints Alpha without operator input. |
| .011 | N1,C5/C6/C7/C8 | **I5-011-A:** old span `(0x1002,2)` then A2L-B attach → field `None`, repainted alt pane has no Beta span; current IMG bytes remain. | **I5-011-B:** clear field without `update_alt_hex_view` → old span remains painted. |
| .012 | N1,C4x,picker | **I5-012-A:** Check visible with spec-a, attach A2L-B → names Alpha/Gamma at `0x1000`/`0x2000`, format `u16`, fresh signature, no Beta and no screen re-entry; unload gives zero rows/signature `None`. No raw/physical assertion exists. | **I5-012-B:** prefill only in `action_show_screen` → old names/addresses/format/signature remain until re-entry; a physical-value assertion is out-of-oracle, not a substitute. |
| .013 | N1,C5x,picker | **I5-013-A:** Patch initially shows Alpha `0x1000`, `u16`, current signature; A2L unload → zero parameter rows, empty full-name line and signature `None`; dirty document/(2,1) history unchanged. No raw/physical assertion exists. | **I5-013-B:** refresh only Check or reload the Patch document → stale Gamma name/address/format/signature, or dirty/history sentinel changes. |
| .014 | C4,N3,C5,C1,N1 | **I5-014-A:** load A2L-A at path X `copy=False`, rewrite X to A2L-A′, load X again without clear → A2L generation increases; Delta/FLASH2 appear in Viewer/Split and pickers assert only Delta name, `0x1004`, `u16` and fresh signature. Repeat under project Yes. | **I5-014-B:** short-circuit equal path or path-only signature → Delta name/address/format and fresh signature are absent. |
| .015 | N1,C6x | **I5-015-A:** IMG-1 loaded, attach A2L-A → Memory Map's region names include Alpha,Beta and count `2 sym`; replacement B leaves no Beta; unload gives 0 with IMG-1 coverage intact. | **I5-015-B:** update only Viewer → panel's retained A2L list remains empty/old. |
| .016 | N1,N4,C7x | **I5-016-A:** Split visible with A2L selection `{0}`, cursor `0`, `_armed=True`, A2L-A→B → N4 gives selection `set()`, cursor `0`, `_armed=False`; RAM row `0x2000/+0x100` replaces FLASH; manual `0x4000-0x40ff` and ranges/manual sentinels unchanged; unload paints exact no-A2L note. | **I5-016-B:** omit N4 or `watch_current_file` → selection/cursor/arm survives onto RAM, or old FLASH remains because `current_file` identity did not change. |
| .017 | N1,C8x,C7 | **I5-017-A:** IMG-1+MAC-1, A2L-A→B → Loaded still IMG-1/MAC-1, A2L slot `b.a2l`, 2 tags; P-A2L shows project A2L with no phantom file. | **I5-017-B:** clear `current_file` as an A2L-refresh side effect → image/MAC slots vanish. |
| .018 | N1,C9x | **I5-018-A:** MAC-1 page 2, A2L-A→B → 150 identical records and page 2; Alpha matches, Old becomes `NOT_IN_A2L`, coverage recomputed; unload gives `NO_A2L`. | **I5-018-B:** reset `_mac_window_start=0` or retain old cache → page 1 or stale `A2LMatch`. |
| .019 | N1,C9x | **I5-019-A:** Issues filter `warning`; A2L-B removes A2L-A's old warning → old warning absent, filter still `warning`, counts/groups from fresh report; unload leaves non-A2L issues only. | **I5-019-B:** reset filter to `all` or clear report → unrelated ERROR appears or current issues disappear. |
| .020 | C4,N2 | **I5-020-A:** P-OLD `cal/old.a2l`, request `new.a2l` → one modal exactly `Replace project A2L?` / `Project 'cal' already has A2L 'old.a2l'. Load 'new.a2l' instead?` / Yes(y),No(n); zero workers/mutations before answer. Same-path X gets the analogous modal. | **I5-020-B:** keep `Project already has an A2L file.` or start copy/parse first → no compliant modal/ordering. |
| .021 | N2 | **I5-021-A:** open that modal, snapshot session/views/generations/project digest/workers, press Escape (repeat No button and `n`) → snapshots identical, zero new/cancelled workers, no outcome. | **I5-021-B:** treat falsy dismissal as True or eagerly parse → candidate installs or worker count changes. |
| .022 | N2,N3 | **I5-022-A:** while modal is open replace listed old.a2l with other.a2l, then Yes → zero new workers/install, current other.a2l retained, proposed changed-state refusal; unchanged identity proceeds. Project-name change arm likewise refuses. | **I5-022-B:** captured unconditional `go()` → new worker installs candidate over unconfirmed project state. |
| .023 | N2,N3,C5,N1 | **I5-023-A:** unchanged P-OLD, Yes for A2L-B → one normal worker with `request.sync_project=False`, current path/data B, N1 all views, then `A2L loaded: b.a2l`; if old.a2l disappears externally after Yes, C5 still performs session install but makes 0 project-sync calls/writes. | **I5-023-B:** modal callback assigns current A2L directly, N3 defaults the confirmed request to `True`, or C5 ignores the flag → worker/fan-out/order fails or an unconfirmed project write occurs. |
| .024 | C4,N3 | **I5-024-A:** while `Loading other.s19` runs, request project-A2L load → `busy: Loading other.s19 is running — wait for it to finish.`, zero modal/new workers/state delta; repeat for A2L/project/Save actions. | **I5-024-B:** inspect project before busy or open modal → wrong status and a queued second load. |
| .025 | N2,N3 | **I5-025-A:** two post-Yes arms: (1) Yes with no busy, Save project starts before N2's accepted callback → N2 shows the exact busy line and starts nothing; (2) N2 identity recheck passes, Save project starts before N3's pre-worker boundary → N3 shows the same line and starts nothing. Both preserve A2L/image/project/generations; no pre-Yes arm is used. | **I5-025-B:** remove N2's accepted-callback check → arm 1 starts a worker; remove N3's immediate pre-worker check → arm 2 starts a worker. Checking only the initial request or pre-Yes state does not cover either arm. |
| .026 | N3,C5,C9,N5,C6,C7,C8,N1,N4 | **I5-026-A:** instrument direct, file and project routes → C9 worker ids appear only in copy/parse/precompute; N5/C6/N1, every viewer/picker/map/Split/Loaded mutation and N4 invalidation run on the UI thread through the callback boundary. | **I5-026-B:** call `set_parameters`, `update_a2l_view`, `_complete_prepared_load` or `invalidate_a2l_selection` from a worker → thread-id assertion fails even if painted text looks right. |
| .027 | C1,C5,C7,C6,N1 | **I5-027-A:** before `(a=10,i=4)`, direct attach → `(11,4)`; same-path → `(12,4)`; empty→P-A2L may give `(a+2,4)`; image→P-A2L also image `4`; both picker keys carry fresh pair. | **I5-027-B:** require exactly one project A2L bump or increment/reset image generation on direct attach → valid project route fails or historical image invalidation changes. |
| .028 | C10,C9,N5,C6,C7 | **I5-028-A:** prepared rows/key/summary contain `STALE`; A2L-only and image-only mismatches each return `False` before cache/session/widget/C6 outcome, discarding the whole prepared load with previous state kept and no stale fallback/UI recompute. Loose: N5 makes 0 sync calls, paints 0 `Loaded` and closes busy exactly `Load superseded — current state kept.` Project: C7 aborts on `False` with no N1/result/success. | **I5-028-B:** late-only guard, minimal-load fallback, sync or `Loaded` on `False`, or C7 continuing after rejection → stale mutation/success; bypassing N5 with C9's old unconditional tail also gives the wrong outcome. |

## 7. Route and preservation matrix

| Route | State installation | Publication/outcome | Preservation oracle |
|---|---|---|---|
| Loose direct attach | C4→N3(`sync_project=True`)→worker→C5→C1 | C5→N1; deferred `end_busy` after detail barrier; C5 syncs only when the request flag is true | image/MAC/document/history unchanged; image generation unchanged |
| Project direct attach | C4→N2; Yes→N2 accepted busy/identity check→N3(`False`)→C5 | same session publication as loose; N3 performs the second post-Yes busy check; C5 never project-syncs | No/Escape is full no-op; changed identity/busy starts nothing; old A2L disappearing after Yes causes 0 project writes |
| Loose image load/reload | C9 worker→N5→C6 preflight/default `publish_a2l=True` | C6 `True`: N1 then N5 preserves sync+`Loaded`; C6 `False`: N5 makes no sync/`Loaded` and closes busy exactly `Load superseded — current state kept.` | previous state kept on supersession; no stale fallback; equal-size image cannot reuse stale membership |
| Project image+A2L(+MAC) | C7 bundle preflights before reset; C6(`publish_a2l=False`) directly for each image/MAC | any `False` aborts; otherwise C7 calls N1 once after final pair/project identity; deferred outcome | C7 never uses N5; no transient reset/image-only frame, no rejected-cache fallback; document/manifest/focus behavior remains with C7 |
| Project A2L-only/empty | C7 no-image C1 install; project identity assigned | C7 calls N1 once; deferred outcome | no synthetic `LoadedFile`; image generation unchanged for A2L-only; Loaded names new project |
| Unload primary/mac/a2l/all | C8 selected clear and cache reset | C8→N1 (including N4 before `watch_current_file`); ordered file/status lines after barrier; focus last | retained artifacts, Issues filter, MAC page (when applicable), Patch document and Split manual/ranges state intact; A2L selection/cursor/arm cleared |

## 8. Design decisions and E3R1 closure

E2-Q1 … Q5 and Q7 remain the synchronized design decisions. E3 round 1 closes Q6 and changes the freshness/persistence contracts as recorded in D-1/D-4/D-7. Q8/Q9 are now closed; no open caller or record alignment remains.

1. **E2-Q1 — file outcome race and duplicate project publication (carried).** Optional `publish_a2l` on C6 and one final C7 fan-out remain. The loose completion tail is now explicit: C9→N5→C6, with N5 consuming the return and C7 still calling C6 directly.
2. **E2-Q2 — all-before-render (carried).** N1 step 0 resets mode/variants before `update_a2l_view`; no second render.
3. **E2-Q3 — changed project/A2L message (carried).** `A2L NOT loaded: project or its A2L changed — load again.` remains the synchronized refusal for the N2 identity race.
4. **E2-Q4 — project identity before publication (carried).** All C7 publication stays after `current_project/current_project_dir` and final accepted image/MAC installation.
5. **E2-Q5 — queued row highlights (carried).** Immediate `show_tag(None)` plus the after-refresh detail barrier remains ahead of every accepted outcome.
6. **E2-Q6 — Split / Join selection (CLOSED by E3R1).** Public N4 clears A2L selection/cursor and `_armed`, preserves manual/ranges state and runs before `watch_current_file`.
7. **E2-Q7 — active-mode presentation (carried).** Textual `Button.variant`: `primary` for All and `default` for Invalid/In-Memory; no style-file edit.
8. **E3R1-Q8 — loose completion (CLOSED).** New N5 `_complete_prepared_load` consumes C6's `bool`. C6 `True` preserves project sync and `Loaded`; `False` skips both and ends busy exactly `Load superseded — current state kept.` C9 calls N5 through `call_from_thread`; no direct worker→C6 or unconditional `Loaded` path remains.
9. **E3R1-Q9 — whole-prepared supersession (CLOSED).** The orchestrator's updated R-A2L-REFRESH.028 is authoritative: whole-prepared discard, previous state kept, no success and exact superseded text. C6 supplies preflight/no-install, N5 supplies the loose exact outcome and C7 aborts directly on `False`; there is no stale-cache/UI fallback.

## 9. Counts and E3R1 closure boundary

- **11 implementation nodes:** **6 changed** (`load_a2l_from_path`, `_install_attached_a2l`, `_apply_prepared_load`, `_install_prepared_project`, `_apply_unload`, `_start_load_worker`) + **5 new** (`_refresh_a2l_dependent_views`, `_confirm_project_a2l_replacement`, `_start_a2l_load`, `_complete_prepared_load`, `SplitJoinWindow.invalidate_a2l_selection`).
- **10 unchanged primary context nodes**, **21 nodes total**; **3 permitted source files**, 2 planned to change, picker unchanged.
- **28/28 requirements** mapped to nodes and at least one concrete example; **56 examples** (`I5-001-A/B` … `I5-028-A/B`).
- **4 pinned interface groups:** I-4 identity/preflight/publication, internal N1-N5/C6 signatures (including `sync_project` and `bool`), unchanged picker seam, worker/outcome/thread boundary.
- **E2-Q6 and E3R1-Q8/Q9 closed.** No test case file, execution evidence or GREEN status is asserted.
