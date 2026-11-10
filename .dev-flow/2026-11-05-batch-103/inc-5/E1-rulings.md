# Inc 5 — E1 rulings: refresh contract, replacement question and boundaries

Date 2026-11-10; model Kimi. Authority: `../PLAN.md:60`, US-103-02 (`../PLAN.md:24`) and I-4 (`../PLAN.md:88`). Rows: `01-requirements.md`; implementation slice: `E1-slice.md`. These are E1 design rulings derived from the explicit commission; no operator approval, runtime probe or test result is claimed.

## 1. Static base confirmed, hypotheses kept separate

The current worktree was read only. No app was launched, no test/probe was run, and no Git command or mutation was used. Line references therefore describe the current static worktree, not a claimed commit.

Confirmed statically:

1. **Existing generation ownership is sufficient.** `_a2l_view_generation` is declared at `app.py:2975`, `_image_generation` at `:3117`, and `_replace_current_a2l` replaces path/data, increments A2L generation and invalidates enrichment/filter/row-key state at `:20853-20890`. `_compute_a2l_enriched_tags` keys on `(A2L generation, image generation, memory size)` at `:20921-20938`.
2. **The viewer is not the whole story.** Direct attach reaches `update_a2l_view`, project labels and Loaded at `:16744-16767`; it reaches neither Check/Patch prefill nor MemoryMap nor Split / Join. The file-load chain reaches A2L and MemoryMap at `:19397-19418`; unload reaches its renderer list at `:18228-18235`. There is no common fan-out.
3. **Check/Patch refresh is activation-driven.** `_prefill_check_editor` and `_prefill_patch_editor` are `:7885-7928`; activation calls them at `:10308` and `:10313`. Their delegation through `screens_directionb.py:5375-5391` and `:7285-7314` already reaches the same picker API.
4. **The picker API already fits.** `A2LParameterPicker.set_parameters(rows, signature)` returns `False` only for an equal non-`None` signature; otherwise it replaces rows, resets picker-local filter/page state and rebuilds (`a2l_parameter_picker.py:526-574`). No new API is justified by static evidence.
5. **Project replacement is refused today.** `load_a2l_from_path` checks busy first, then returns with `Project already has an A2L file.` when the active project lists one (`app.py:16606-16647`). The worker begins only later at `:16674-16687`.
6. **The existing modal and busy text are reusable.** `ConfirmQuestionScreen` already provides Yes/No ids, `y`, `n` and Escape (`screens.py:2229-2318`). `_refuse_if_busy` writes the canonical line through the status log (`app.py:22655-22677`; CTX-BUSY at `REQUIREMENTS.md:2128-2145`).
7. **Old prepared snapshots already have an oracle.** Apply accepts precomputed enrichment only when both generations match and otherwise leaves it for UI recomputation (`app.py:19321-19350`, `:19397-19410`).
8. **Dependent views expose existing seams.** MemoryMap consumes enriched tags in `update_memory_map` (`app.py:20223-20265`); Split / Join derives A2L rows in `segment_split_view.py:1603-1629` and refreshes through `app.py:19089-19123`; the Detail Card accepts `None` at `app.py:1572-1595`.

Hypotheses for E4, not asserted as base-runtime facts: the missing calls produce the visible stale views described by US-103-02; table repopulation may emit a highlight that must be overridden by explicit card invalidation; the final common ordering removes any transient mixed project pair. Every row's Base column labels its C/H basis.

## 2. Rulings

**E3 round-1 correction (2026-11-10, Kimi):** D-1, D-4 and D-7 below supersede their earlier forms. D-3 gains only an oracle restriction, D-6 names the two post-Yes boundaries precisely, and D-8 admits the single new Split / Join public method. **Q8/Q9 are closed:** N5 `_complete_prepared_load` plus changed C9 `_start_load_worker` own loose completion, and the orchestrator's updated .028 is authoritative. The graph is now **21 nodes: 11 implementation (6 changed + 5 new) + 10 context**, across 3 permitted source files (2 changed). No requirements/product/test file was edited in this closure.

### D-1 — One UI-thread fan-out after coherent state installation or clear (E3R1)

**Ruling:** add one app-owned common refresh and call it only on the UI thread after the final state of a transition is installed. Do not put rendering in `_replace_current_a2l`: project reset uses that seam for a transient clear, and rendering there would publish a half-reset session. Do not call the fan-out from a worker.

Order inside the fan-out:

1. reset viewer mode to `all` and its visible mode state, retaining filter text and field;
2. compute fresh enrichment and run `update_a2l_view` (which refreshes MAC and Issues before tag rendering);
3. clear `_a2l_tag_hex_highlight`, repaint the A2L hex pane, close an open `CurveDescriptionScreen` whose tag belongs to the invalidated generation, call `A2LDetailCard.show_tag(None)` immediately and register the after-refresh card barrier;
4. call `_prefill_check_editor` and `_prefill_patch_editor` while their panels are mounted, using the fresh enriched key;
5. call `update_memory_map`, then the new public `SplitJoinWindow.invalidate_a2l_selection()` immediately before `watch_current_file`, then `_refresh_loaded_panel`;
6. only then allow the transition's accepted success/unload outcome to be written behind the detail barrier.

`invalidate_a2l_selection()` clears `_sel["a2l"]`, sets `_cursor["a2l"] = 0` and `_armed = False`. It does not repaint or clear segment caches and preserves manual text/state, ranges/manual selections/cursors and unrelated window state. N1 owns the call; `watch_current_file` remains unchanged and refreshes the rows afterward.

The existing `update_project_labels`, focus restoration and unrelated load tails remain in their current owners. A panel not mounted is tolerated by the existing guarded prefill/refresh idiom. The fan-out is called once per published transition, not once for project reset plus once for final install. `segment_split_view.py` becomes the third permitted source file and the graph's ninth implementation node.

### D-2 — Viewer state: preserve text and field, reset only mode

**Ruling:** preserve the filter input's exact value and the selected filter field over every transition, including unload. Existing stripped/case-insensitive matching remains unchanged. Reset `a2l_tags_filter_mode` to `all` and synchronize the All/In-Memory/Invalid visual state after every transition. The existing first-page refresh remains; no requirement preserves the A2L table page or row selection. Detail Card and A2L-tag hex highlight are explicitly invalidated, not re-targeted by name or address.

### D-3 — Reuse `set_parameters(rows, signature)`; no picker API change; restricted oracle (E3R1)

**Ruling:** the common fan-out calls the existing app prefills, which call the existing panel shims and then `A2LParameterPicker.set_parameters(rows, self._a2l_enriched_key)`. The new A2L/image generation key distinguishes fresh state; equal non-`None` keys retain the R-B102-SEL-004 / R-B102-PE-005 no-op semantics. `a2l_parameter_picker.py` remains unchanged.

Picker examples and later test oracles assert **name, address, format (`Fmt · Unit` or normalized size-format tuple) and signature only**. They must not assert raw or physical values; those are Viewer concerns, not evidence of picker refresh. No document/dirty/history assertion is replaced by a value assertion.

Only concrete E2/E4 evidence that this seam cannot meet a row may reopen D-3. Such evidence must identify the missing behaviour and why a caller-side correction cannot supply it; an API change may not be introduced silently. `screens_directionb.py` is read-only context and is not in the edit boundary.

### D-4 — Project A2L: Yes/No question, guarded acceptance and sync ownership (E3R1)

**Ruling:** replace the terminal R-A2L-004.5 refusal for an active project with exactly one listed A2L by the exact question in R-A2L-REFRESH.020. Reuse `ConfirmQuestionScreen`; Yes is `True`, No/`n`/Escape are `False`.

At initial request, busy wins before project inspection or modal creation. The question captures candidate/`copy`/project/A2L identities. On Yes there are two distinct post-Yes boundaries: N2's accepted callback first rechecks busy and project/A2L identity; N3 rechecks busy immediately before busy-run/request/worker creation. R-A2L-REFRESH.025 covers exactly those two boundaries, not a session action that began before Yes. On No/cancel, mutate nothing and neither start nor cancel workers.

`A2LAttachRequest` gains defaulted `sync_project: bool = True` after `gen`, preserving existing construction. N3 has the same keyword-only default and passes it into the request. Ordinary C4 starts use `True`; N2's accepted replacement always uses **`False`**. C5 calls `_sync_loaded_a2l_to_project()` only when `result.request.sync_project and self.current_project`. Thus the confirmed replacement installs the session A2L but never writes a project file/manifest, including when the old A2L disappears externally after Yes.

“Replace” and “install” still mean replacing the **session's current A2L** through the normal worker/install route. This increment adds no deletion or overwriting of project files. The sync helper itself (`app.py:16146-16188`) remains unchanged; only C5's decision to call it is gated by the immutable request flag.

Multiple project A2Ls and other `validate_project_files` errors remain existing refusals, not a replacement question. At batch end, R-A2L-004.5 must be retired or narrowed so it no longer contradicts R-A2L-REFRESH.020; the canon is untouched now.

### D-5 — Generations: monotonic A2L identity, no project +1 equality, no gratuitous image bump

**Ruling:** reuse `_a2l_view_generation` and `_image_generation`; add no third generation. Every installed/cleared A2L state continues through `_replace_current_a2l`. Tests assert A2L generation strictly increases, never exactly `+1` on project routes because reset plus final install may legitimately increment it more than once. A direct attach or A2L-only project install leaves `_image_generation` unchanged. Image/file installs keep their existing image-generation semantics; this increment does not narrow or broaden them.

I-4 is therefore a reachability contract, not a numeric “one increment per user action” contract: the post-install generation pair reaches enrichment, both picker signatures and every live dependent view.

### D-6 — Busy at initial request and exactly two post-Yes boundaries (E3R1)

**Ruling:** use the exact CTX-BUSY line `busy: <label> is running — wait for it to finish.` at (a) initial request under .024, (b) N2's accepted callback under .025, and (c) N3's immediate pre-worker boundary under .025. No .025 example starts the competing action before Yes. A busy refusal opens no replacement dialog, starts no extra worker, mutates no session/view state and leaves progress status text under the existing busy owner. Removing either post-Yes check must turn its corresponding example RED.

### D-7 — Worker ownership and preflight supersession (E3R1)

**Ruling:** workers may copy, parse and precompute data only. All fan-out/selection-invalidation calls and widget mutations occur on the UI thread via the existing `call_from_thread` / deferred install routes.

C6's **first operation** is preflight whenever `prepared.a2l_enriched_key is not None`: `expected = (current_a2l_generation + int(bool(prepared.loaded.a2l_data)), current_image_generation + 1)`, compared with the prepared pair. On any mismatch, discard the whole `PreparedLoad` as superseded and return `False` before cache/session/generation/widget/outcome/deferred work. There is no minimal-load fallback, no stale-cache fallback and no UI recomputation from rejected values. The old late enrichment-only discard is removed. An accepted C6 returns `True`; `publish_a2l` controls only whether N1 runs in C6 or is left to C7.

C7 preflights keyed project bundles before reset and calls C6 with `publish_a2l=False` for image/MAC. Any `False` aborts the project route without N1, result screen, successful outcome or rejected-cache fallback. Otherwise C7 publishes exactly once after the final pair/project identity.

**Q8 closed — loose completion wrapper:** new N5 `_complete_prepared_load(prepared, path, load_started, *, gen, sync_project)` runs on the UI thread between C9 and C6. C9 `_start_load_worker` keeps parse/precompute but replaces direct C6 + separate sync + unconditional `Loaded` with one `call_from_thread(N5, …)`. N5 calls C6 with default publication. On `True`, it preserves `sync_project and self.current_project → _sync_loaded_file_to_project()` and then `Loaded <name>`; on `False`, it performs neither and closes busy exactly **`Load superseded — current state kept.`**. C6 never owns that loose tail, and C7 never uses N5: C7 still calls C6 directly and aborts on `False`. Previous state is kept and there is no success/fallback on supersession.

**Q9 closed — record aligned by the orchestrator:** R-A2L-REFRESH.028 now specifies whole-prepared discard, previous state kept, no success and the exact superseded outcome. C6 supplies preflight/no-install, N5 the loose exact outcome and C7 the direct project abort. `01-requirements.md` was not edited in this closure.

### D-8 — Historical results and adjacent features stay out (E3R1 exception)

**Ruling:** do not recompute, clear or rewrite historical check verdicts, before/after reports, flow results, saved documents or undo/redo history as part of A2L refresh. Existing image-generation invalidation remains intact. Also out: Inc 6 picker correctness/array/format work and all picker physical-value oracles; Inc 7 label-list/filter/autocomplete work; A2L parser/reader changes; Check/Patch panel internals; new project-file replacement semantics; and any new persistence format. Split / Join internals remain out **except** the single public `invalidate_a2l_selection()` ruled in D-1.

## 3. I-4 producer/consumer contract (E3R1)

**Producer (Inc 5):** after each coherent accepted install/clear, the UI thread publishes the current `(_a2l_view_generation, _image_generation)` pair through the existing enrichment key and runs the common fan-out before the outcome. Project reset is not a published intermediate generation. A keyed prepared load first proves its pair equals the expected post pair; otherwise the whole load is superseded before installation with `False`, never recomputed from stale caches. Loose loads complete through C9→N5→C6: `True` preserves sync+Loaded, `False` skips both and closes with `Load superseded — current state kept.` C7 calls C6 directly and aborts on rejection. `sync_project` is carried by the immutable attach request; confirmed replacement sets it `False` and C5 honors it.

**Consumers:**

- Inc 6 continues to obtain picker rows and signature through the existing prefill/`set_parameters` seam; it needs no refresh-specific picker API. Its refresh oracle is name/address/format/signature, never physical values.
- Inc 7 builds any label index once per observed A2L view generation, on the UI-side consumer lifecycle (its own worker ranking rules remain Inc 7's); it must drop an index/result whose generation is older than the current one.
- MemoryMap, Split / Join, MAC and Issues consume current app state through their existing seams, not a second event bus. Split / Join additionally receives N4 invalidation before `watch_current_file`, clearing A2L selection/cursor/`_armed` while manual/ranges state survives.

**Ownership invariant:** `_replace_current_a2l` remains the sole writer of current A2L path/data; the fan-out remains the sole A2L-transition view coordinator; N4 is the sole A2L-selection invalidator; N5 is the sole loose-file completion wrapper; C7 calls C6 directly without N5; workers never paint; C5 project sync is conditional on the request flag and loose sync on C6 `True`.

## 4. Canon and follow-up record

- Proposed at batch end: fold R-A2L-REFRESH.001 … .028 into the A2L Explorer/screen contract and retire or narrow R-A2L-004.5 as D-4 states. No canon/requirements file was edited at E1, E3R1 or this closure.
- No new ids outside `.001` … `.028` were allocated.
- E2/E3R1 gives 56 concrete examples for all 28 rows, including same-path without clear, A2L-only and image+A2L projects, all four unload kinds, visible Check/Patch name/address/format/signature, whole-prepared supersession and both post-Yes busy boundaries.
- **E3R1-Q8 closed:** N5 consumes C6 `bool`; C6 `True` preserves sync+Loaded, `False` skips both and produces the exact superseded text. C9 calls N5 through `call_from_thread`; C7 remains direct.
- **E3R1-Q9 closed:** the orchestrator's updated R-A2L-REFRESH.028 is authoritative for whole-prepared discard, previous state, no success and exact superseded text; no stale-cache fallback exists.
- E4 must use product routes and independent read-back; spies may establish thread/call ownership but may not replace visible assertions. No test files are authored in E1/E3R1.
- Corrected counts: **11 implementation (6 changed + 5 new) + 10 context = 21 nodes; 3 permitted source files, 2 changed; 56 graph examples; E2-Q6 and E3R1-Q8/Q9 closed.**
