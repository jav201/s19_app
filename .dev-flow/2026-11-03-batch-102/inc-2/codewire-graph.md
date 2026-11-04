# Code-Wire — Inc 2 — A2L load/reload refresh

Graph of the A2L viewer refresh slice. Requirements: `01-requirements.md`. Tests: `02-test-cases.md`.

## Nodes

S19TuiApp._replace_current_a2l
req: R-B102-A2L-001, R-B102-A2L-004, R-B102-A2L-005
in: S19TuiApp self; Path? a2l_path; dict? a2l_data
out: None
func: new single-writer seam for every `current_a2l_path` / `current_a2l_data` replacement or clear. Replaces the payload, bumps `_a2l_view_generation`, clears enrichment/filter caches and the row-key map, and leaves rendering to the existing caller.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_a2l_data] (replace); [Data: S19TuiApp._a2l_view_generation] (replace); [Data: S19TuiApp._a2l_enriched_tags] (clear); [Data: S19TuiApp._a2l_filtered_tags] (clear)
examples: (TC-B102-A2L-05) stale enriched list exists, generation `7`, new payload dict at a forced-identical `id` → None; generation is `8`; enriched/filtered lists are empty before `update_a2l_view`
examples: (TC-B102-A2L-06) payload `None` after an attached A2L → None; generation is `8`; viewer renders `No A2L loaded.`

S19TuiApp._compute_a2l_enriched_tags
req: R-B102-A2L-001, R-B102-A2L-002, R-B102-A2L-004
in: S19TuiApp self
out: list enriched
func: changed cache rule. Reuses enrichment only when `(a2l_view_generation, image_generation, mem_size)` equals the retained key; `id()` is never used. On a miss, calls `enrich_tags_and_render`, stores the result and resets the summary window. Including `_image_generation` makes an equal-size/different-content image reload recompute automatically.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._a2l_enriched_tags] (replace); [Data: S19TuiApp._a2l_enriched_key] (replace)
examples: (TC-B102-A2L-01) no cache, tags `Alpha`,`Beta`, mem size `16`, image generation `3` → enriched names include `Alpha` and `Beta`
examples: (TC-B102-A2L-02) image reload keeps mem size `16` but `_image_generation` moves `3` → `4` → enriched tags are recomputed for image 2
examples: (TC-B102-A2L-05) stale key `(7, 3, 16)`, current key `(8, 3, 16)` → enriched names come from the new payload, not the stale list

S19TuiApp._refresh_a2l_filtered_tags
req: R-B102-A2L-001, R-B102-A2L-003
in: S19TuiApp self; bool preserve_anchor
out: None
func: changed empty-filter message. Applies the active filter, resets or clamps the buffered page, and asks `update_a2l_tags_view` to render rows. When a non-empty filter matches nothing it passes `No A2L tags match '<filter>'.`; `update_a2l_tags_view` remains the one writer of the summary label.
module: s19_app/tui/app.py
examples: (TC-B102-A2L-03) filter `Alpha`, enriched `Alpha`,`Gamma` → None; rendered rows contain `Alpha` and not `Gamma`
examples: (TC-B102-A2L-04) filter `Missing`, enriched `Alpha`,`Gamma` → None; summary is `No A2L tags match 'Missing'.`

S19TuiApp.update_a2l_tags_view
req: R-B102-A2L-003, R-B102-A2L-005
in: S19TuiApp self; list[dict] tags; str empty_message = None
out: None
func: changed signature only: accepts an optional empty summary message so the generic `No A2L tags.` and filter-specific message share one final writer. Existing callers pass no message and keep the generic behaviour.
module: s19_app/tui/app.py
examples: (TC-B102-A2L-04) tags `[]`, empty_message `No A2L tags match 'Missing'.` → None; summary is exactly that text
examples: (TC-B102-A2L-06) tags `[]`, empty_message None with no A2L → None; generic empty behaviour paints zero rows

S19TuiApp.update_a2l_view
req: R-B102-A2L-001, R-B102-A2L-002, R-B102-A2L-005
in: S19TuiApp self
out: None
func: changed orchestration contract stays one call. With A2L present it computes enrichment, refreshes validation/MAC state, applies the persisted filter and renders summary + rows. With no A2L it clears all view state and paints `No A2L loaded.` plus zero rows.
module: s19_app/tui/app.py
examples: (TC-B102-A2L-02) a new image is applied with A2L attached → None; `update_a2l_view` runs and the row memory display reflects the new image before the load outcome
examples: (TC-B102-A2L-06) A2L is cleared through `_replace_current_a2l` → None; summary is `No A2L loaded.`; row-key map is empty

S19TuiApp._install_attached_a2l
req: R-B102-A2L-001, R-B102-A2L-003, R-B102-A2L-004
in: S19TuiApp self; A2LAttachResult result
out: None
func: changed install order. Replaces the A2L payload through `_replace_current_a2l`, calls `update_a2l_view()`, and only then paints labels/Loaded panel and the successful busy outcome. No separate user refresh is required.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_a2l_data] (replace); [Data: S19TuiApp._a2l_view_generation] (replace); [UI: A2L Viewer] (replace)
examples: (TC-B102-A2L-01) result payload has `Alpha`,`Beta` → None; table rows contain both before the outcome `A2L loaded: firmware.a2l`
examples: (TC-B102-A2L-03) result payload has `Alpha`,`Gamma`, filter persists as `Alpha` → None; table rows contain `Alpha` only

S19TuiApp._prepare_load_payload
req: R-B102-A2L-002, R-B102-A2L-006
in: S19TuiApp self; LoadedFile loaded; int a2l_view_generation; int image_generation
out: PreparedLoad prepared
func: changed. Precomputes A2L enrichment for the file-load worker and stores both generation snapshots plus the matching key `(a2l_view_generation, image_generation, len(mem_map))` in `PreparedLoad`. The function receives the predicted generations from `_start_load_worker`; it does not read mutable app generation counters off-thread.
module: s19_app/tui/app.py
modify: [Data: PreparedLoad.a2l_enriched_tags] (replace); [Data: PreparedLoad.a2l_enriched_key] (replace); [Data: PreparedLoad.a2l_view_generation] (replace); [Data: PreparedLoad.a2l_image_generation] (replace)
examples: (TC-B102-A2L-02) loaded A2L tags `Alpha`, snapshot generations `(7, 4)`, mem size `16` → prepared key `(7, 4, 16)`; enriched tags include `Alpha`
examples: (TC-B102-A2L-07) same payload but snapshot generations `(7, 4)` while apply-time generations are `(8, 4)` → prepared key stays `(7, 4, 16)` and is later discarded by `_apply_prepared_load`

S19TuiApp._apply_prepared_load
req: R-B102-A2L-002, R-B102-A2L-005, R-B102-A2L-006
in: S19TuiApp self; PreparedLoad prepared; Path path; float load_started
out: None
func: changed install. Bumps `_image_generation`, installs the loaded file, routes any loaded A2L through `_replace_current_a2l`, and installs the worker-precomputed A2L cache only when `prepared.a2l_view_generation == self._a2l_view_generation` and `prepared.a2l_image_generation == self._image_generation`; otherwise it leaves the caches cleared so `_compute_a2l_enriched_tags` recomputes on the UI thread.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._image_generation] (replace); [Data: S19TuiApp.current_a2l_data] (replace); [Data: S19TuiApp._a2l_enriched_tags] (replace); [Data: S19TuiApp._a2l_enriched_key] (replace)
examples: (TC-B102-A2L-02) prepared key `(7, 4, 16)` and apply generations `(7, 4)` → worker enrichment installs and `_step_a2l` renders it
examples: (TC-B102-A2L-07) prepared key `(7, 4, 16)` and apply generations `(8, 4)` → worker enrichment is discarded; final rows come from a fresh enrichment call

## Entities

[Data: S19TuiApp.current_a2l_data]
in: dict
desc: the parsed A2L payload attached to the session; it can be replaced by a distinct dict at a reused object address.

[Data: S19TuiApp._a2l_view_generation]
in: int
desc: explicit monotonically increasing attach generation bumped by `_replace_current_a2l`.

[Data: S19TuiApp._image_generation]
in: int
desc: existing monotonic image install generation; part of the enrichment-cache identity because enrichment depends on the memory map.

[Data: PreparedLoad]
in: LoadedFile + worker precomputed caches
desc: worker-to-main-thread bundle carrying A2L tags plus the generation snapshot that makes them applicable.

[Data: A2L Viewer]
in: list rows + str summary
desc: the visible A2L summary and tag table; one final writer per refresh.

## Edges

[Data: S19TuiApp.current_a2l_data] ──▶ S19TuiApp._compute_a2l_enriched_tags
[Data: S19TuiApp._a2l_view_generation] ──▶ S19TuiApp._compute_a2l_enriched_tags
[Data: S19TuiApp._image_generation] ──▶ S19TuiApp._compute_a2l_enriched_tags
S19TuiApp._replace_current_a2l ──▶ [Data: S19TuiApp._a2l_view_generation]
S19TuiApp._replace_current_a2l ──▶ [Data: S19TuiApp.current_a2l_data]
S19TuiApp._prepare_load_payload ──▶ [Data: PreparedLoad]
S19TuiApp._apply_prepared_load ──▶ S19TuiApp._replace_current_a2l
S19TuiApp.update_a2l_view ──▶ [Data: A2L Viewer]
S19TuiApp._install_attached_a2l ──▶ S19TuiApp._replace_current_a2l

## Findings

finding F-B102-A2L-1 object identity can collide across payload replacements
anchor: S19TuiApp._compute_a2l_enriched_tags
seen: cache key is `(id(self.current_a2l_data), mem_size)` at the current tree, and the file-load worker stores the same shape in `PreparedLoad`
cause: CPython may reuse a freed dict's address for the next payload, and an equal-size memory map leaves the key unchanged
effect: reload can paint the previous enriched/filtered tag set until another user action forces a render
decision: use `(a2l_view_generation, image_generation, mem_size)` and route every payload replacement through one generation-bumping seam

finding F-B102-A2L-2 a persisted filter can masquerade as a missing A2L load
anchor: S19TuiApp._refresh_a2l_filtered_tags
seen: `update_a2l_view` reapplies the input filter after attach
cause: the empty state always paints `No A2L tags.`, even when the A2L loaded and the active filter merely excluded every row
effect: the operator reads a successful load as stale data and tries manual refresh
decision: keep the filter but pass a filter-specific empty message to the single table-summary writer

finding F-B102-A2L-3 worker precompute can overwrite a fresher generation
anchor: S19TuiApp._apply_prepared_load
seen: `_prepare_load_payload` computes `a2l_enriched_key` off the main thread and `_apply_prepared_load` installs it later
cause: an A2L attach or another generation change can occur between worker prepare and main-thread apply; installing the old key resurrects stale data
effect: the precomputed cache can defeat the new generation rule at the last write
decision: carry generation snapshots in `PreparedLoad` and verify them at apply time; discard mismatched precomputes
