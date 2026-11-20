# Code-Wire delta — Inc 2 responsive direct A2L attach

Stage E2. E1 commit `85e68957`; product base `f44e8bc4`; Code-Wire commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05` (PLAN-pinned v3.2.0). This file is the only prototype. It contains deltas for A1–A4, P1, C1 and PA1, plus the data entities; it neither adds nor marks product code.

Inputs: `../01-requirements.md`, `../02-test-cases.md`, `../E1-slice.md`, `../E1-rulings.md`, `../../interfaces.md` (frozen), `baseline.md`, and the applicable batch-100/103 contracts they preserve. Baseline-only marks/extraction ran in a deleted throwaway clone: `../evidence-e2/baseline-extract/`; 6 marks, 6 nodes, 3 real calls, 0 findings and 0 parse failures. Its 55 name-based ambiguities are not call evidence; the explicit callback sequence below retains E1's direct reads. No example below is an executed functional, timing or recording result.

**Ownership and four-SOURCE boundary.** G-A owns A1–A4 and A5–A8 in `s19_app/tui/app/file_load.py`; G-P owns P1 in `s19_app/tui/a2l_parameter_picker.py`; G-C owns C1 in `s19_app/tui/screens_directionb/check_editor.py`; G-PA owns PA1 in `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py`. No fifth source file, parser edit, stylesheet, prefill-host edit or app-core edit is in this delta. G-A is the single requirement owner; the other groups own only their named consumer nodes.

**Frozen data-contract realization (I-ALP-2.1 and I-ALP-2.2).** All four classes are frozen dataclasses. Existing positional fields and defaults retain their order; new fields follow them. Every mapping is exposed through `MappingProxyType`; parsed A2L payloads, enriched row dictionaries and `Definition` objects are read-only by contract after hand-off, not recursively frozen.

| Contract | Fields and meaning |
|---|---|
| A5 `A2LAttachRequest` | Existing `source: Path`, `copy: bool`, `temp_dir: Path`, `workarea: Path`, `record_recent: bool`, `a2l_cache: A2LCacheEntry?`, `gen: int`, `sync_project: bool = True`; then `expected_a2l_generation: int? = None`, `expected_image_generation: int? = None`, `image_mem_map: Mapping[int, int]? = None`. Product requests always supply the expected pair. With an image, A1 captures an independent `dict` copy before worker launch and exposes only its read-only proxy. |
| A6 `A2LAttachResult` | Existing `request: A2LAttachRequest`, `path: Path`, `entry: A2LCacheEntry`, `parse_seconds: float`; then `preparation: A2LAttachSnapshot? = None`. Every successful product worker result supplies it; `None` is only the legacy direct-construction install arm. |
| A7 `A2LAttachSnapshot` | `expected_a2l_generation: int`, `expected_image_generation: int`, `enrichment_key: tuple[int, int, int]`, `enriched_tags: tuple[dict, ...]`, `summary_lines: tuple[str, ...]`, `picker_snapshots: Mapping[str, A2LPickerSnapshot]` with independent `check` and `patch` entries. |
| A8 `A2LPickerSnapshot` | `picker: str` restricted to `check` or `patch`; `signature: tuple[int, int, int]` equal to the full enrichment key; `a2l_source: dict`, the source object itself for identity comparison; `definitions: Mapping[str, Definition]`, that picker's own read-only bulk-describe result. |

The conductor's integrated I-ALP-2.2 pins the route-neutral A3 producer with five keyword-only inputs after `self`:

```text
FileLoadMixin._prepare_a2l_attach_snapshot(
    self, *, a2l_path: Path, a2l_data: dict,
    image_mem_map: Mapping[int, int] | None,
    expected_a2l_generation: int, expected_image_generation: int,
) -> A2LAttachSnapshot
```

For direct attach, A2 maps A5's expected pair into those explicit inputs, so A7's pair is equal by construction; Inc3 can reuse A3 without manufacturing an A5. A4 uses A7's recorded pair as the preflight authority. To preserve the existing cache attributes' list types without editing `app/core.py`, A4 makes one shallow `list` conversion of each A7 tag/summary tuple during installation, resets summary start to `0`, and installs A7's already read-only picker mapping without copying or merging it. Common refresh then reuses those installed lists. The A7/A8 names, preflight authority, shallow conversion, absent-mapping default and busy/outcome reading are ACCEPTED/INTEGRATED in the root interfaces; `../E2-report.md` records their dispositions.

**Population contract (I-ALP-2.3).** P1 gains keyword-only `prepared_definitions: Mapping[str, Definition]? = None` after `a2l_data`. An equal non-`None` signature returns `False` before reading either definition input. On a real population, a supplied mapping, including an empty mapping, becomes the read-only `definitions` without a describe; omitted input retains the existing `describe_definitions(names, a2l_data)` behavior. `definitions_source` remains the population's `a2l_data`.

C1 and PA1 first check `self.is_mounted`. An unmounted panel performs no `self.app` or accepted-mapping access and calls P1 with legacy `a2l_data=None` and omitted prepared definitions; it neither invalidates nor changes the accepted snapshot, whose identity survives until a later matching mount. Mounted adapters obtain the accepted mapping with `getattr(app, "_accepted_a2l_picker_snapshots", MappingProxyType({}))`, select only their own literal key, and require entry key, `a2l_source is current_a2l_data` and full-signature equality. A missing entry is omitted prepared input and preserves the existing route. Any present-but-mismatched mounted entry replaces the whole app mapping with an empty `MappingProxyType` on the UI thread before the existing fallback. Thus a matching empty map is consumed, a mismatch never reaches P1 as prepared data and a headless call leaves the hand-off available for mount.

**Concrete design fixtures.** OLD contains non-palindromic `OLD_SCALAR` (declared length `2`, `u16`) and `ARR12` (declared length `12`, `u16`), plus `AUX2` (length `2`, `u16`). NEW at the same path changes `ARR12` to declared length `8`, `f32`, and retains `AUX2`; no OLD cell is a valid NEW expectation. IMG1 is `{0x1000: 0x10, 0x1001: 0x20, 0x1002: 0x30}`, so its independently measured size is `3`. Timing values are required upper bounds or hold durations, never observed latencies.

## Nodes

FileLoadMixin._start_a2l_load
req: R-A2L-REFRESH.030, R-A2L-REFRESH.032, R-A2L-REFRESH.033, R-A2L-REFRESH.034
in: FileLoadMixin self; Path path; Path normalized; bool copy; bool sync_project = True
out: None
func: changed A1. Preserve admission, recents, busy and sync decisions. After beginning the existing busy run, capture current A2L+1 and unchanged image generations and an independent read-only copy of the current image map into A5, then start exactly one existing worker; copy remains keyword-only.
module: s19_app/tui/app/file_load.py
modify: [Data: A2L busy run] (append); [Data: A2L attach request] (replace)
examples: (R-A2L-REFRESH.030/1) empty session with A2L generation `0` and image generation `0` → request expects A2L generation `1`, image generation `0`, image mapping `None`; frozen request rejects writes
examples: (R-A2L-REFRESH.030/2) IMG1 with `0x1000: 0x10`, expected A2L generation `3` and unchanged image generation `7`; then source address 0x1000 changes to 0xFF → request retains `0x1000: 0x10`, map size `3`, and rejects mapping writes
examples: (R-A2L-REFRESH.033/6) `1000000` image bytes and keys `tab` then `shift+tab` queued immediately before request capture → both existing actions acknowledge before worker completion, each latency at most `1.0` s, and the worker receives an independent read-only copy
examples: (R-A2L-REFRESH.034/4) `1000000` image bytes during request capture → existing busy line remains visible, every visible progress gap is at most `1.0` s, and no timer freeze or bar regression occurs

FileLoadMixin._a2l_attach_worker
req: R-A2L-REFRESH.029, R-A2L-REFRESH.030, R-A2L-REFRESH.033, R-A2L-REFRESH.034, R-A2L-REFRESH.037, R-A2L-REFRESH.038
in: FileLoadMixin self; A2LAttachRequest request
out: None
func: changed A2. Inside the existing copy/parse Exception boundary, retain the selected path, parsed entry and parse timing, then call A3 after parsing with keyword-only a2l_path=path, a2l_data=entry[1], image_mem_map=request.image_mem_map, expected_a2l_generation=request.expected_a2l_generation and expected_image_generation=request.expected_image_generation. Construct one A6 from request, path, entry, parse_seconds and the returned A7 before dispatching the existing deferred install callback. Any preparation exception returns through the existing attach-failure callback; no result or partial snapshot is dispatched. Self is limited to existing logger, progress and thread-dispatch infrastructure.
module: s19_app/tui/app/file_load.py
modify: [I/O: workarea A2L copy] (replace); [Data: A2L attach result] (replace)
examples: (R-A2L-REFRESH.033/1) held real copy of `new.a2l` and keys `tab`, `shift+tab` → both acknowledgements occur before copy release and install, each at most `1.0` s, with attach progress ownership unchanged
examples: (R-A2L-REFRESH.033/2) held real parse after byte progress value `33` and keys `tab`, `shift+tab` → both acknowledgements occur before parse release, each at most `1.0` s, and every parse bar value remains within `33`–`66`
examples: (R-A2L-REFRESH.033/5) real `37742888`-byte case_06 attach with two existing navigation keys across post-parse/install/common-refresh windows → both acknowledgements are at most `1.0` s and terminal path, views and success describe NEW
examples: (R-A2L-REFRESH.034/3) real `37742888`-byte case_06 attach sampled until terminal outcome → every visible progress gap through common refresh is at most `1.0` s, existing labels and `33`–`66` parse bounds hold, and outcome follows the last in-progress frame
examples: (R-A2L-REFRESH.038/1) replacement enrichment raises ValueError `enrichment boom` → `File NOT loaded: 'new.a2l' could not be read — check that the file can be opened, then load again.`; current image and A2L-dependent generations/views stay exact, existing Workarea Files refresh runs and may list the new copy, with `0` installs, common refreshes, syncs or successes
examples: (R-A2L-REFRESH.038/2) real enrichment completes once, then render_a2l_view raises ValueError `summary boom` before describe → the same exact failure, describe count `0`, no install/common refresh/sync/success, and unchanged Workarea Files refresh/new-copy behavior
examples: (R-A2L-REFRESH.038/3) real enrichment and summary complete, then Check bulk describe raises ValueError `definitions boom` → the same exact failure, no partial NEW snapshot or Patch paint, `0` installs/common refreshes/syncs/successes, and the existing Workarea Files refresh may show the new copy

FileLoadMixin._prepare_a2l_attach_snapshot
req: R-A2L-REFRESH.029, R-A2L-REFRESH.030, R-A2L-REFRESH.033, R-A2L-REFRESH.034, R-A2L-REFRESH.036, R-A2L-REFRESH.037, R-A2L-REFRESH.038
in: FileLoadMixin self; Path a2l_path; dict a2l_data; Mapping[int, int]? image_mem_map; int expected_a2l_generation; int expected_image_generation
out: A2LAttachSnapshot preparation
func: new A3, route-neutral; all five inputs after self are keyword-only. On the worker, use a2l_path only as explicit parsed-source context and call the existing enrichment/summary service once with a2l_data and image_mem_map. Derive the enrichment key from the explicit expected pair and mem_size=-1 for None or len(image_mem_map), then derive measurable names using the existing address/name rules. Call describe_definitions independently once for Check and once for Patch over that same full name sequence; pack A7 and both A8 entries with a2l_source=a2l_data, signature=enrichment_key and read-only containers. Read no request, admission state, widget, mounted state, current session or live generation.
module: s19_app/tui/app/file_load.py
examples: (R-A2L-REFRESH.029/1) typed parsed NEW with `ARR12` length `12` and `u16` → one A7; enrichment `1`, summary `1`, Check describe `1`, Patch describe `1`, all off UI before install, and visible NEW cells are exact
examples: (R-A2L-REFRESH.029/2) existing workarea NEW with copy `False` → the same complete off-UI A7 before install, copy calls `0`, and no OLD cell survives
examples: (R-A2L-REFRESH.029/3) start-up load_path `new.a2l` → complete off-UI A7 before start-up install and outcome, with no component deferred to manual refresh
examples: (R-A2L-REFRESH.030/1) no-image parsed OLD at `old.a2l` with explicit expected pair `1`, `0` and image_mem_map `None` → one frozen A7 with enriched-tag tuple, summary tuple and read-only check/patch mapping; field, tuple and mapping writes all fail and worker UI/session reads are `0`
examples: (R-A2L-REFRESH.030/3) static census resolves worker/helper nodes `2` → forbidden widget/session reads `0`; one synthetic self.current_file read is detected once, while logger, progress-forwarder and thread-dispatch calls remain visible
examples: (R-A2L-REFRESH.033/3) real enrichment held off UI and keys `tab`, `shift+tab` → both acknowledgements occur during enrichment, each at most `1.0` s, before install or outcome
examples: (R-A2L-REFRESH.033/4) first real bulk describe held off UI and keys `tab`, `shift+tab` → both acknowledgements occur during definition preparation, each at most `1.0` s, and neither picker paints a partial generation
examples: (R-A2L-REFRESH.034/1) enrichment held off UI for `1.5` s → existing busy line stays visible, at least `2` spinner/elapsed changes occur, every measured gap is at most `1.0` s, and no outcome appears during the hold
examples: (R-A2L-REFRESH.034/2) bulk definitions held off UI for `1.5` s independently → existing busy line stays visible, at least `2` spinner/elapsed changes occur, every gap is at most `1.0` s, and no outcome appears during the hold
examples: (R-A2L-REFRESH.037/1) OLD measurable names `ARR12`, `AUX2` with lengths `12`, `2` and `u16` → one all-names Check describe and one independent all-names Patch describe, both off UI before population; each A8 contains both definitions and UI describes `0`
examples: (R-A2L-REFRESH.037/2) same-path NEW changes ARR12 to length `8` and `f32` → exactly one additional describe per picker for the new generation, distinct Check/Patch A8 entries, and no OLD `u16` definition or shared single-call shortcut

FileLoadMixin._install_attached_a2l
req: R-A2L-REFRESH.031, R-A2L-REFRESH.032, R-A2L-REFRESH.035, R-A2L-REFRESH.036, R-A2L-REFRESH.037
in: FileLoadMixin self; A2LAttachResult result
out: None
func: changed A4 on UI. For a product result, first compare A7's pair with current A2L+1 and unchanged current image before recents, files refresh, cache, session, dependent-view or project-sync mutation. A mismatch directly ends busy with the exact superseded text and returns. A match preserves existing install order, uses _replace_current_a2l, attaches the same parsed payload to the unchanged image, installs enrichment key/tags/summary with summary start 0 and _accepted_a2l_picker_snapshots, then runs exactly one existing common refresh and the existing outcome tail. Legacy A6 preparation None retains only the direct-construction compatibility path.
module: s19_app/tui/app/file_load.py
modify: [Data: Current A2L] (replace); [Data: A2L view caches] (replace); [Data: Accepted A2L picker snapshots] (replace); [Data: A2L busy run] (clear)
examples: (R-A2L-REFRESH.031/1) empty session generations `0`, `0` and matching OLD result → installed key has A2L generation `1`, image generation `0`, mem_size `-1`; OLD_SCALAR shows size `2` and `u16` coherently before refresh
examples: (R-A2L-REFRESH.031/2) A2L generation `1`, image generation `3`, IMG1 size `3` and matching OLD result → installed key is A2L generation `2`, image generation `3`, mem_size `3`; image identity and `0x1000: 0x10` remain and OLD cells match IMG1
examples: (R-A2L-REFRESH.031/3) IMG1 plus OLD at `same.a2l`, generations `2`, `3`, map size `3`; overwrite with NEW → installed key is A2L generation `3`, image generation `3`, mem_size `3`; source and snapshot show ARR12 length `8`, `f32`, image bytes stay unchanged and OLD `u16` does not survive
examples: (R-A2L-REFRESH.032/1) live generations A2L `5`, image `2`, but NEW A7 records A2L `5` instead of expected `6` → `Load superseded — current state kept.`; OLD/IMG1/MAC state and views stay exact, with `0` recent, cache, session, install, common-refresh, sync or success mutations
examples: (R-A2L-REFRESH.032/2) live generations A2L `5`, image `2`, but NEW A7 records image `1` instead of expected `2` → `Load superseded — current state kept.`; no NEW enrichment, picker definition or fallback recompute reaches a view, and every install-side effect count is `0`
examples: (R-A2L-REFRESH.035/1) first accepted `old.a2l` → exactly `install → common refresh(UI) → A2L loaded: old.a2l`, common-refresh count `1`, no manual refresh, and current OLD everywhere at outcome
examples: (R-A2L-REFRESH.035/2) accepted OLD→NEW replacement → exactly `install → common refresh(UI) → A2L loaded: new.a2l`, common-refresh count `1`, and neither an OLD value nor an intermediate empty state is painted at outcome
examples: (R-A2L-REFRESH.035/3) active one-A2L project, same-path OLD→NEW and modal answer Yes → one normal worker and one UI common refresh after complete NEW installation, before success; sync_project `False` and project bytes unchanged
examples: (R-A2L-REFRESH.036/1) OLD without image → worker enrichment construction `1`, worker summary construction `1`, UI constructions `0`; common refresh consumes the installed tags/summary and paints OLD size `2`, `u16` and no-image values
examples: (R-A2L-REFRESH.036/2) OLD over IMG1 → worker enrichment construction `1`, worker summary construction `1`, UI constructions `0`; the exact three-part key hits the installed caches and paints IMG1-backed OLD cells

A2LParameterPicker.set_parameters
req: R-A2L-REFRESH.037, R-PICKER-CORRECT.018, R-PICKER-CORRECT.019
in: A2LParameterPicker self; Sequence[dict] rows; object signature = None; Optional[dict] a2l_data = None (keyword-only); Optional[Mapping[str, Definition]] prepared_definitions = None (keyword-only)
out: bool repopulated
func: changed P1. Equal non-None signature returns False before consuming prepared input. Otherwise preserve row normalization, page, filter and pick behavior. A supplied read-only mapping, including empty, is installed as definitions with its a2l_data source and zero describes; omitted input preserves the existing one bulk direct describe. Definitions and definitions_source always describe the last real population.
module: s19_app/tui/a2l_parameter_picker.py
modify: [Data: Picker population] (replace)
examples: (R-A2L-REFRESH.037/1) matching Check and Patch populations receive their own prepared maps containing ARR12 length `12`, `u16` and AUX2 length `2`, `u16` → both return repopulated `True`, paint those exact cells and perform `0` UI describes
examples: (R-A2L-REFRESH.037/2) changed-signature NEW population with prepared ARR12 length `8`, `f32` → repopulated `True`, current cells show `8` and `f32`, additional UI describes `0`, and definitions_source is the identical NEW a2l_data object
examples: (R-A2L-REFRESH.037/3) after NEW, `20` real filter/page rebuilds plus one unchanged-signature request per picker → unchanged request returns `False` before prepared-map consumption; additional describes `0`, additional population describes `0`, each mounted page has at most `200` rows and current `f32` cells remain

CheckEditorPanel.set_a2l_parameters
req: R-A2L-REFRESH.037, R-A2L-REFRESH.012
in: CheckEditorPanel self; Sequence[dict] rows; object signature = None
out: None
func: changed C1 on UI. Before app access, an unmounted panel keeps legacy a2l_data None and omitted prepared definitions, reads or invalidates no accepted mapping and preserves its identity. A mounted adapter selects only the check A8 from the app's accepted read-only mapping. Pass its prepared definitions to P1 only when key, A2L-source identity and full signature match. On any present-entry mismatch, first replace the whole accepted mapping with an empty read-only mapping, then use the existing route describe. Preserve no-op, document, selection, demotion, layout and preview side effects.
module: s19_app/tui/screens_directionb/check_editor.py
modify: [Data: Accepted A2L picker snapshots] (replace); [Data: Check picker population] (replace)
examples: (R-A2L-REFRESH.037/1) matching accepted OLD check entry → Check consumes its own worker map and paints ARR12 length `12`, `u16` with `0` main describes
examples: (R-A2L-REFRESH.037/2) matching same-path NEW check entry → Check consumes only the new-generation map and paints ARR12 length `8`, `f32`, never OLD `u16`
examples: (R-A2L-REFRESH.037/3) unchanged Check signature → P1 returns `False`, filter/page/picks and definitions stay unchanged, and describes `0`
examples: (R-A2L-REFRESH.037/4) same-source signature mismatch from `(3, 4, 3)` to `(3, 5, 3)` and different-source project.a2l variant → each present mismatch invalidates the whole accepted mapping to read-only empty before existing-route describe; current `f32` paints, stale `u16` does not, and the matching-signature control still consumes the worker map
examples: (R-A2L-REFRESH.037/5) unmounted Check call with accepted mapping present → legacy a2l_data `None`, omitted prepared definitions, `0` app/mapping reads or invalidations, unchanged snapshot identity; later matching mount consumes the surviving worker map with `0` additional UI describes

A2lPickerMixin.set_a2l_parameters
req: R-A2L-REFRESH.037, R-A2L-REFRESH.013
in: A2lPickerMixin self; Sequence[dict] rows; object signature = None
out: None
func: changed PA1 on UI. Before app access, an unmounted panel keeps legacy a2l_data None and omitted prepared definitions, reads or invalidates no accepted mapping and preserves its identity. A mounted adapter selects only the patch A8 from the app's accepted read-only mapping. Pass its prepared definitions to P1 only on exact key, A2L-source identity and full-signature match. On any present-entry mismatch, replace the whole accepted mapping with an empty read-only mapping before the existing route describe. Preserve no-op, selection and layout invalidation side effects.
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
modify: [Data: Accepted A2L picker snapshots] (replace); [Data: Patch picker population] (replace)
examples: (R-A2L-REFRESH.037/1) matching accepted OLD patch entry → Patch consumes its distinct worker map and paints ARR12 length `12`, `u16` with `0` main describes
examples: (R-A2L-REFRESH.037/2) matching same-path NEW patch entry → Patch consumes the new-generation map and paints `8`, `f32`, never OLD `12`, `u16`
examples: (R-A2L-REFRESH.037/3) Patch filter/page rebuilds and unchanged signature → additional describes `0`, current NEW definitions, filter, page, highlight and picks remain according to existing contracts
examples: (R-A2L-REFRESH.037/4) same-source signature mismatch from `(3, 4, 3)` to `(3, 5, 3)` and different-source project.a2l variant → each present mismatch invalidates the whole accepted mapping to read-only empty before existing-route describe; current `f32` paints, stale `u16` does not, and the matching-signature control still consumes the worker map
examples: (R-A2L-REFRESH.037/5) unmounted Patch call with accepted mapping present → legacy a2l_data `None`, omitted prepared definitions, `0` app/mapping reads or invalidations, unchanged snapshot identity; later matching mount consumes the surviving worker map with `0` additional UI describes

## Entities

[Data: A2L busy run]
in: object
desc: Existing main-thread busy spinner, elapsed field, byte progress and outcome. Post-parse preparation leaves the completed parse-byte bar unchanged while spinner/elapsed continue. Progress transitions and the terminal outcome are not installation of an A2L result.
sequence:
  accepted: FileLoadMixin._start_a2l_load → FileLoadMixin._a2l_attach_worker → FileLoadMixin._prepare_a2l_attach_snapshot → FileLoadMixin._on_a2l_attached → FileLoadMixin._install_attached_a2l → ShellMixin.end_busy
  preparation_failure: FileLoadMixin._a2l_attach_worker → FileLoadMixin._prepare_a2l_attach_snapshot → FileLoadMixin._on_a2l_attach_failed

[I/O: workarea A2L copy]
in: Path
desc: Existing worker copy. A copy produced before stale preflight or preparation failure is not installed session state and is never project-synced by that rejected result. Preparation failure still routes through the existing Workarea Files refresh when copy=True and the new copy may appear in that list.
sequence:
  copy_then_accept: FileLoadMixin._a2l_attach_worker wins → FileLoadMixin._install_attached_a2l
  copy_then_reject: FileLoadMixin._a2l_attach_worker wins → FileLoadMixin._install_attached_a2l (preflight rejects)
  preparation_failure: FileLoadMixin._a2l_attach_worker wins → FileLoadMixin._on_a2l_attach_failed (existing Workarea Files refresh when copy=True; new copy may be listed)

[Data: Current A2L]
in: object
desc: Current path, parsed payload and A2L generation owned by _replace_current_a2l; preflight also reads the unchanged live image generation before this entity changes.
sequence:
  accepted: FileLoadMixin._install_attached_a2l (!) (preflight) → FileLoadMixin._install_attached_a2l wins (install) → A2lViewMixin._refresh_a2l_dependent_views (common refresh UI) → ShellMixin.end_busy (success outcome)
  stale_a2l: FileLoadMixin._install_attached_a2l (!) (preflight rejects) → ShellMixin.end_busy (superseded outcome)
  stale_image: FileLoadMixin._install_attached_a2l (!) (preflight rejects) → ShellMixin.end_busy (superseded outcome)

[Data: A2L view caches]
in: object
desc: Exact three-part enrichment key, enriched tags, summary lines and summary start. A4 installs all of them after current-A2L replacement and before common refresh; the unchanged cache consumer sees the key and performs no UI enrichment or summary construction.
sequence:
  accepted: FileLoadMixin._prepare_a2l_attach_snapshot → FileLoadMixin._install_attached_a2l wins → A2lViewMixin._refresh_a2l_dependent_views
  stale: FileLoadMixin._install_attached_a2l (preflight rejects without a cache write)

[Data: Picker population]
in: object
desc: Shared picker rows, read-only definitions, A2L source, signature, filter, page and picks. Equal non-None signature is a no-op before prepared-input consumption; a real population consumes one supplied map without describing.
sequence:
  direct_check: CheckEditorPanel.set_a2l_parameters → A2LParameterPicker.set_parameters wins
  direct_patch: A2lPickerMixin.set_a2l_parameters → A2LParameterPicker.set_parameters wins
  unchanged: A2LParameterPicker.set_parameters (returns False without population)
  filter_page: A2LParameterPicker.set_parameters (no call from rebuild-only actions)

[Data: Check picker population]
in: object
desc: Check adapter's embedded picker and existing document, selection, demotion, layout and preview behavior. Only a matching check snapshot supplies prepared definitions.
sequence:
  accepted: FileLoadMixin._install_attached_a2l → CheckEditorPanel.set_a2l_parameters → A2LParameterPicker.set_parameters wins
  mismatch: CheckEditorPanel.set_a2l_parameters (invalidate then existing fallback) → A2LParameterPicker.set_parameters wins

[Data: Patch picker population]
in: object
desc: Patch adapter's embedded picker and existing selection and layout behavior. Only a matching patch snapshot supplies prepared definitions.
sequence:
  accepted: FileLoadMixin._install_attached_a2l → A2lPickerMixin.set_a2l_parameters → A2LParameterPicker.set_parameters wins
  mismatch: A2lPickerMixin.set_a2l_parameters (invalidate then existing fallback) → A2LParameterPicker.set_parameters wins

[Data: A2L attach request]
in: A2LAttachRequest
desc: A5 immutable request with expected post-install pair and request-owned read-only image copy; the worker's only application input apart from existing logger/progress/thread infrastructure.

[Data: A2L attach result]
in: A2LAttachResult
desc: A6 immutable parse result. Product success always carries one complete A7; preparation None is limited to legacy direct construction and is never worker-isolation evidence.

[Data: A2L attach snapshot]
in: A2LAttachSnapshot
desc: A7 complete generation-bound worker hand-off of enrichment, summary and independent Check/Patch A8 entries. It is built before result dispatch and installed coherently or discarded whole.

[Data: A2L picker snapshot]
in: A2LPickerSnapshot
desc: A8 literal check or patch key, full enrichment signature, exact A2L source object and that picker's read-only bulk definitions. Parser and Definition payloads remain read-only after hand-off.

[Data: Accepted A2L picker snapshots]
in: Mapping[str, A2LPickerSnapshot]
desc: The app's _accepted_a2l_picker_snapshots, always a MappingProxyType when present. A4 replaces it before common refresh. Unmounted adapters read neither app nor this mapping and leave its identity intact for a later matching mount. Mounted adapters use an empty read-only default when absent; any present-entry generation/signature/source/key mismatch replaces the whole mapping with empty before fallback.
sequence:
  direct_check: FileLoadMixin._install_attached_a2l wins → CheckEditorPanel.set_a2l_parameters → A2LParameterPicker.set_parameters
  direct_patch: FileLoadMixin._install_attached_a2l wins → A2lPickerMixin.set_a2l_parameters → A2LParameterPicker.set_parameters
  check_mismatch: CheckEditorPanel.set_a2l_parameters (!) → CheckEditorPanel.set_a2l_parameters wins → A2LParameterPicker.set_parameters (existing fallback)
  patch_mismatch: A2lPickerMixin.set_a2l_parameters (!) → A2lPickerMixin.set_a2l_parameters wins → A2LParameterPicker.set_parameters (existing fallback)
  unmounted_check: CheckEditorPanel.set_a2l_parameters (legacy a2l_data None; no app/mapping read or write; snapshot survives)
  unmounted_patch: A2lPickerMixin.set_a2l_parameters (legacy a2l_data None; no app/mapping read or write; snapshot survives)

## Edges

FileLoadMixin._start_a2l_load ──▶ [Data: A2L attach request]
[Data: A2L attach request] ──▶ FileLoadMixin._a2l_attach_worker
FileLoadMixin._a2l_attach_worker ──▶ FileLoadMixin._prepare_a2l_attach_snapshot
FileLoadMixin._prepare_a2l_attach_snapshot ──▶ [Data: A2L attach snapshot]
[Data: A2L attach snapshot] ──▶ FileLoadMixin._install_attached_a2l
FileLoadMixin._a2l_attach_worker ──▶ [Data: A2L attach result]
[Data: A2L attach result] ──▶ FileLoadMixin._install_attached_a2l
[Data: Current A2L] ──▶ FileLoadMixin._install_attached_a2l
FileLoadMixin._install_attached_a2l ──▶ [Data: Current A2L]
FileLoadMixin._install_attached_a2l ──▶ [Data: A2L view caches]
[Data: A2L view caches] ──▶ A2lViewMixin._refresh_a2l_dependent_views
FileLoadMixin._install_attached_a2l ──▶ [Data: Accepted A2L picker snapshots]
[Data: Accepted A2L picker snapshots].check ──▶ CheckEditorPanel.set_a2l_parameters
[Data: Accepted A2L picker snapshots].patch ──▶ A2lPickerMixin.set_a2l_parameters
[Data: A2L picker snapshot].definitions ──▶ A2LParameterPicker.set_parameters
CheckEditorPanel.set_a2l_parameters ──▶ A2LParameterPicker.set_parameters
A2lPickerMixin.set_a2l_parameters ──▶ A2LParameterPicker.set_parameters
A2LParameterPicker.set_parameters ──▶ [Data: Picker population]
CheckEditorPanel.set_a2l_parameters ──▶ [Data: Check picker population]
A2lPickerMixin.set_a2l_parameters ──▶ [Data: Patch picker population]

## Findings

finding E2-1 cache container types use the integrated installation rule
anchor: FileLoadMixin._install_attached_a2l; I-ALP-2.3
seen: Static source reads show list-typed app caches, while the frozen hand-off requires tuples and the four-file slice excludes app/core.py.
cause: Direct tuple assignment would drift the existing cache attribute types; rebuilding enrichment would violate .036.
effect: The installation rule preserves cache types without recomputation or another source file.
decision: ACCEPTED/INTEGRATED. A4 performs one shallow list conversion per tag/summary tuple, resets summary start to 0, installs the picker mapping as-is and then reuses those caches.

finding E2-2 the accepted mapping uses the integrated absent-attribute default
anchor: CheckEditorPanel.set_a2l_parameters; A2lPickerMixin.set_a2l_parameters; I-ALP-2.3
seen: app/core.py is outside the counted slice, so no new initializer may be added there; non-direct routes can run before the first direct attach.
cause: First-use absence needs a read-only default that does not expand the source slice.
effect: The default avoids an unguarded attribute read and preserves the existing route when a key is absent.
decision: ACCEPTED/INTEGRATED. Both adapters read absence as empty MappingProxyType; A4 replaces the mapping and a present-entry mismatch empties it before fallback.

finding E2-3 A7 is the integrated preflight authority
anchor: FileLoadMixin._install_attached_a2l; A2LAttachSnapshot; I-ALP-2.4
seen: I-ALP-2.1 and I-ALP-2.2 carry the expected pair in both request and snapshot; integrated I-ALP-2.4 selects the snapshot pair for preflight.
cause: Direct A2 maps the request values into route-neutral A3, which returns the same pair in A7.
effect: .032 mutations and implementation have one explicit target and cannot confuse the two carriers.
decision: ACCEPTED/INTEGRATED. A4 preflights A7's pair and both .032 examples mutate that pair; preparation None remains legacy-only.

finding E2-4 busy progress and outcome are integrated control transitions
anchor: FileLoadMixin._on_a2l_attached; FileLoadMixin._install_attached_a2l; I-ALP-2.4
seen: The unchanged callback paints existing step 3 before A4 preflight; .032 requires previous-state preservation and an exact outcome while .034 requires continuous progress.
cause: Busy step/progress and terminal outcome control the existing run; they do not install A2L result data into dependent views.
effect: The accepted reading preserves progress/outcome without weakening preflight's ban on install-side mutation or expanding the counted slice.
decision: ACCEPTED/INTEGRATED. Preflight precedes recents, files, cache, session, project sync and dependent-view installation/refresh; busy progress and the mandated outcome remain control transitions.

finding E2-5 baseline extraction confirms static seams but not dynamic callbacks
anchor: evidence-e2/baseline-extract/diff-report.md
seen: Baseline-only extraction found 6 marks, 6 nodes, 3 real calls, 0 findings and 0 parse failures; it reported 55 name-based ambiguities and cannot see callbacks passed as values.
cause: Check/Patch homonyms and call_from_thread/call_after_refresh are outside precise name-based call resolution.
effect: The extraction alone cannot prove the worker-to-install order or distinguish the two adapters' callers.
decision: Retain E1's direct callback census and make the dynamic order explicit in entity sequences. No runtime defect or functional result is claimed.

finding E3-I2-01 unmounted adapters preserve legacy input and accepted snapshots
anchor: CheckEditorPanel.set_a2l_parameters; A2lPickerMixin.set_a2l_parameters; tests/test_b103_picker_editor.py
seen: The existing headless caller constructs an unmounted panel and calls set_a2l_parameters; eager app/mapping access would break its legacy a2l_data None behavior and could invalidate a snapshot before mount.
cause: Snapshot selection must be guarded by is_mounted before any self.app or mapping access.
effect: Unmounted Check and Patch calls retain omitted prepared input and a2l_data None, perform zero mapping reads/writes and preserve snapshot identity; a later matching mount reuses it.
decision: ACCEPTED/CORRECTED in both adapter nodes, their .037/5 examples and the accepted-mapping sequences; no SOURCE or describe-count change.

finding E3-I2-02 preparation failure retains Workarea Files refresh
anchor: FileLoadMixin._on_a2l_attach_failed; I/O workarea A2L copy
seen: The existing failure handler refreshes Workarea Files for a copying request and a new copy may consequently be listed.
cause: Preservation of every current view would incorrectly suppress an unrelated existing file-list obligation.
effect: Failure preserves the current image and A2L-dependent state/views while retaining the existing file-list refresh.
decision: ACCEPTED/CORRECTED in .038, its three examples and the workarea preparation_failure sequence; no common refresh, install, sync or success is added.

finding E3-I2-03 E3 alternative and collected-item counts
anchor: R-A2L-REFRESH.037; evidence-e2/validate_graph.py
seen: Adding one .037/5 alternative to each adapter adds two example links but no node, entity, edge or SOURCE file.
cause: The requirement ledger has 34 alternatives and 3 ATs, while the graph has 45 node-example links.
effect: Planned collected items total 37; graph structure remains 7 nodes, 12 entities, 20 edges and 4 SOURCE files.
decision: ACCEPTED/CORRECTED in E1/E2 validators and reports. Trace TEST granularity remains per requirement ID.
