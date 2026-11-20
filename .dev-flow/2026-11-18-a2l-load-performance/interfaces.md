# Shared interfaces — frozen for E2 lanes

E1 commit: `85e68957`. These contracts bind every graph lane. A lane proposes a correction in its own record; it never edits this file or changes a shared contract alone.

## I-ALP-1 — public definition model compatibility

`describe_definition(name, a2l_data)` and `describe_definitions(names, a2l_data)` keep their signatures and return shapes. `Definition.shared_with` remains an optional name computed by the same overlap, mask, homonym and file-order rules. The Inc1 occupancy implementation is private to `s19_app/tui/a2l_definition.py`; no later increment depends on a concrete private helper name beyond the counted E1 graph slice.

## I-ALP-2.1 — direct-attach request/result

`A2LAttachRequest` remains frozen and gains defaulted fields after `sync_project`:

- `expected_a2l_generation: int | None`;
- `expected_image_generation: int | None`;
- `image_mem_map`: `None` without an image, otherwise an independent read-only mapping captured before worker launch.

Product requests carry the expected pair. A read-only image mapping is request-owned; a live alias is not compliant.

`A2LAttachResult` gains defaulted `preparation=None`. Every successful product worker result carries an `A2LAttachSnapshot`; the `None` arm is only compatibility for legacy direct construction.

## I-ALP-2.2 — prepared A2L snapshot and route-neutral producer

`A2LAttachSnapshot` is frozen with these exact fields:

- `expected_a2l_generation: int`;
- `expected_image_generation: int`;
- `enrichment_key: tuple[int, int, int]`;
- `enriched_tags: tuple[dict, ...]`;
- `summary_lines: tuple[str, ...]`;
- `picker_snapshots: Mapping[str, A2LPickerSnapshot]`, with independent `check` and `patch` entries.

`A2LPickerSnapshot` is frozen with these exact fields:

- `picker: str`, restricted to `check` or `patch`;
- `signature: tuple[int, int, int]`, equal to the full enrichment key;
- `a2l_source: dict`, the source object itself for identity comparison;
- `definitions: Mapping[str, Definition]`, that picker's own read-only bulk-describe result.

The producer is one reusable method with explicit inputs and no admission/session/widget reads:

```text
FileLoadMixin._prepare_a2l_attach_snapshot(
    self,
    *,
    a2l_path: Path,
    a2l_data: dict,
    image_mem_map: Mapping[int, int] | None,
    expected_a2l_generation: int,
    expected_image_generation: int,
) -> A2LAttachSnapshot
```

Direct attach supplies its parsed path/data and request-owned image mapping. Inc3 supplies the parsed/loaded A2L source and the worker-owned image mapping at the applicable stage; A2L-only supplies `image_mem_map=None`. The producer computes the existing enrichment key, enrichment/summary and two independent picker bulk describes. Parser objects and definitions are read-only after hand-off.

## I-ALP-2.3 — picker consumption

The latest accepted mapping is exposed as `_accepted_a2l_picker_snapshots: Mapping[str, A2LPickerSnapshot]`, stored through `MappingProxyType` and installed before common refresh. Adapters read an absent attribute as `MappingProxyType({})`. A missing key retains the existing route; any present-entry key, generation, full-signature or source mismatch replaces the whole mapping with a read-only empty mapping before that fallback runs.

An unmounted Check/Patch panel preserves the legacy call with `a2l_data=None`: it neither reads `self.app` or the accepted mapping nor invalidates that mapping, so a matching later mount can still consume the snapshot. The existing headless caller remains a required E4 regression input.

`A2LParameterPicker.set_parameters` gains keyword-only `prepared_definitions: Mapping[str, Definition] | None = None` after `a2l_data`. Equal non-`None` signature returns before consuming it. A supplied map, including an empty map, is consumed without describing; omitted input preserves the existing direct-call behavior. `definitions` and `definitions_source` still describe the last real population.

Accepted installation converts each snapshot tag/summary tuple once with a shallow `list(...)` to preserve the existing app-cache attribute types, resets summary start to `0`, and installs the already read-only picker mapping without another copy or merge. It never rebuilds enrichment, summary or definitions on UI.

## I-ALP-2.4 — installation and generations

The snapshot's expected pair is the preflight authority; the producer derives the request and snapshot pairs from the same request values. Every accepted direct attach checks that pair against `(current_A2L + 1, unchanged_current_image)` before recents, cache, session, dependent-view installation or project-sync mutation. A mismatch discards the entire result with `Load superseded — current state kept.`.

The existing busy step/progress and required terminal outcome are control transitions, not installation of A2L result data. Enrichment/summary installation precedes the existing common refresh. The refresh and every widget mutation run on the UI thread exactly once before success. Preparation exceptions use the existing attach-failure route without partial installation or UI fallback.

## I-ALP-3 — prepared-load handoff

`PreparedLoad` appends `a2l_preparation: A2LAttachSnapshot | None = None` after its existing `a2l_cache` field. Deferred annotations and a `TYPE_CHECKING`-only `.file_load` import avoid the runtime `shared.py` ↔ `file_load.py` cycle. Existing positional constructors and non-prepared legacy test arms remain compatible, but those arms are never evidence of worker isolation.

`ProjectLoadRequest` appends `captured_a2l_generation: int | None = None` and `captured_image_generation: int | None = None` after `routed`; product requests populate both on UI. `PreparedProjectLoad` accepts `PreparedLoad | LoadedFile | None` for image/MAC, with `LoadedFile` confined to legacy direct construction, and appends `a2l_only: A2LAttachSnapshot | None = None`.

At project installation, P5 derives every required pair from the **current UI counters**, compares all stage expectations before reset, and rejects any mismatch before candidate/session/widget/project/publication mutation. L1 repeats each bundle's check immediately before that stage installs. If both legacy generation fields and snapshot fields are present, both legacy members are required and both representations must agree. A snapshot pair alone is complete; keyless generation-only stages perform preflight but do not replace the accepted picker mapping.

Project stage pairs are requirements-level contracts, not interchangeable implementation shortcuts: image+MAC+A2L uses image `(A+2,I+1)` and MAC-after-image `(A+3,I+2)`; project image+A2L without MAC uses `(A+2,I+1)`; A2L-only uses `(A+2,I)`. A2L-only remains P2/P5 and never synthesizes `PreparedLoad`, `LoadedFile` or an L1 call.

Generation movement caused by reinstalling unchanged content is distinct from content identity. R-A2L-REFRESH.047 requires changed content to publish under a newer generation and unchanged source bytes to remain unchanged; it does not forbid the existing writer/reset stages from incrementing a generation when an unchanged artifact is reinstalled.

Any correction returns to the conductor and is censused across every graph and requirement before editing.
