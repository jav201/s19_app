# Inc3 E2 — G-I3-F `file_load.py`

## Status and authority

Design delta for batch `2026-11-18-a2l-load-performance`, based on E1 commit `85e68957` and Code-Wire commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05` (v3.2.0). The source of the prototype is `codewire/graph-inc3-file-load.md`; this record is its human-readable coverage/findings summary.

The graph contains exactly the six F nodes allocated by `E1-slice.md`. No product, test, canon, PLAN, step, shared-interface or other-lane file was edited. No functional test, product route, timing arm, mark or extraction was run in this E2 lane. All examples below are planned requirement oracles, not observed outcomes.

**Integration status:** CW-I3-F-04 and CW-I3-F-05 are closed by the accepted root interfaces and corrected REFRESH.047. The graph is ready for integrated lint/E3; E4 still owns every functional, timing and mutation proof.

## Six-node delta

| Id | Node | Design responsibility |
|---|---|---|
| F1 | `FileLoadRequest` | New frozen data contract carrying the admitted path, explicit A2L paths, captured A2L path/data/cache, captured existing-file input, expected A2L/image generations, busy generation and sync flag. |
| F2 | `FileLoadMixin.load_from_path` | Preserve admission/copy/recents/busy behavior; capture F1 on UI after copy and before worker launch with `sync_project=True`. |
| F3 | `FileLoadMixin._load_workarea_file` | Preserve workarea refusal and in-place behavior; capture the same F1 contract on the admitted non-A2L `go` arm with no copy and `sync_project=False`. |
| F4 | `FileLoadMixin._parse_loaded_file` | Add keyword-only `context=None`; on the product arm consume only F1's explicit parse inputs and preserve parser/cache handoff without live session reads. |
| F5 | `FileLoadMixin._prepare_load_payload` | Add keyword-only `prepare_a2l=True`; replace direct enrichment with one Inc2 producer call when enabled, carry I-ALP-2 in `PreparedLoad`, and retain other derived-data preparation. |
| F6 | `FileLoadMixin._start_load_worker` | Add keyword-only `context=None` after `sync_project`; use F1 on product arms, remove the minimal-bundle preparation fallback and retain one UI completion dispatch. |

F4/F6 `None` arms and F5 omitted-generation defaults exist only for legacy synchronous/direct-test compatibility. They are not evidence of worker isolation, preparation parity or responsiveness.

## Explicit request contract

F1 fields are fixed after UI capture. Required fields are `path`, `a2l_path`, `a2l_data`, `a2l_cache`, `current_file`, `expected_a2l_generation`, `expected_image_generation` and `gen`; defaulted fields are `a2l_files=None` and `sync_project=True`. The graph spells out their types. Frozen assignment is not represented as recursive deep-copy: parsed A2L/LoadedFile payloads are read-only by contract after hand-off. The newly parsed image map used by F5 is worker-owned, not a live UI map alias.

Capture uses UI-observed counters `A` and `I` before worker launch:

- loose image with A2L: `(A+1, I+1)`;
- loose image without A2L: `(A, I+1)`;
- F2/F3 never defer that choice to the worker.

On the product arm, F6 uses `context.path`, `context.gen` and `context.sync_project`; the retained old parameters receive the same values only to preserve the callable signature. F6 calls F4 with `context=context` and no independent A2L route argument. F4 uses `context.a2l_files` first when supplied, otherwise `context.a2l_path`/`context.a2l_data`; it uses `context.a2l_cache` and `context.current_file` and ignores the legacy standalone A2L arguments on that arm. The old `current_project` log read also leaves the product worker arm rather than adding another live-session lookup.

F1 is private to this file/load design. It does not alter the frozen `A2LAttachRequest` or any picker API.

## I-ALP-2 reuse and generation flow

F5 is an adapter/consumer, not a second producer. When `loaded.a2l_data` exists and `prepare_a2l=True`, it calls the Inc2 `_prepare_a2l_attach_snapshot` producer exactly once with explicit A2L source/data, worker-owned image map and stage generations. It performs no direct `enrich_tags_and_render` or `describe_definitions` call of its own. The returned snapshot carries the exact enrichment key `(expected_A2L, expected_image, mem_size)`, immutable tag/summary tuples and independently described read-only `check` and `patch` maps.

When `prepare_a2l=False`, F5 performs no A2L production and returns a generation-only prepared bundle. This is the project image-after-reset stage before a MAC. A2L-only has no `LoadedFile` and must not be forced through F5: P4 calls the same Inc2 producer directly. Direct attach remains Inc2's route.

| Route/stage | Expected pair | Producer/publication obligation |
|---|---|---|
| Direct attach, external Inc2 | `(A+1,I)` | Inc2 producer once; Inc2 install publishes once. |
| Loose image+A2L, F2/F3→F6→F5 | `(A+1,I+1)` | F5 adapts to the producer once; F6 completion reaches L1, which publishes once. |
| Project image+MAC+A2L, image after reset | `(A+2,I+1)` | P4 calls F5 with `prepare_a2l=False`; no A2L snapshot and no intermediate publication. |
| Project image+MAC+A2L, MAC after image | `(A+3,I+2)` | P4 calls F5 once with `prepare_a2l=True`; P5 publishes only the final state. |
| Project image+A2L without MAC | `(A+2,I+1)` | P4 calls F5 once at the image stage; P5 publishes only the final state. |
| Project A2L-only | `(A+2,I)` | P4 calls the same producer directly once; no synthetic LoadedFile; P5 publishes once. |

A preparation exception propagates out of F5. F6 sends image-route failures to `_handle_load_error`; project failure handling stays in P4/P5. Neither route may construct a non-prepared candidate or retry enrichment/summary/definitions on UI. L1/P5 own actual stale rejection; F nodes preserve and deliver the generation-bound candidate without repairing it from live state.

## Concrete examples and coverage

The graph has at least one parsed Code-Wire `examples:` line for each assigned requirement. This table also accounts for every planned alternative in `02-test-cases.md`; “external” identifies the owner that must supply the route example/implementation outside this six-node graph.

| Example | Concrete design input → required observable | Location |
|---|---|---|
| EX-I3-039-A | Direct attach at `(A,I)=(8,4)` → one Inc2 producer call, frozen snapshot `(9,4)`, enrichment/summary/Check/Patch data and no widget work. | External Inc2 A3/A4; I-ALP-2 reference. |
| EX-I3-039-B | Loose image+A2L at `(8,4)`, map size `2` → F1/F5 snapshot `(9,5)`, key `(9,5,2)`, one producer call and zero direct enrichment/UI constructions. | F1, F2, F4, F5. |
| EX-I3-039-C | Project image+MAC+A2L at `(8,4)` → image bundle `(10,5)` with zero A2L production; MAC bundle `(11,6)` with the load's only producer call. | F5; external P4/P5/L1 route. |
| EX-I3-039-D | A2L-only project at `(8,4)` → direct producer snapshot `(10,4)`, key mem_size `-1`, one call and no synthetic image/LoadedFile. | External P4→Inc2 producer. |
| EX-I3-039-E | Project image+A2L without MAC at `(8,4)` → F5 snapshot `(10,5)`, one producer call and no MAC or duplicate UI preparation. | F5; external P4/P5/L1 route. |
| EX-I3-040-A | Three fresh serial image+case_06 runs (`37,742,888` bytes; fixture probe `220,040` tags) → independent request-to-outcome totals with four phases, median ≤45 s/every run <60 s, 50 ms timer ≤100 ms late, ≥3 ticks during a 0.20 s worker hold; a separate responsive 61 s hold must fail total. | F2, F5, F6. No timing result claimed. |
| EX-I3-043-A | Image producer raises `ValueError("PREPARE_CONTROL")` → existing image failure route, previous state/views/project hashes equal, zero installs/UI preparation/success. | F6. |
| EX-I3-043-B | P-PAIR producer raises the same error → exception escapes F5; no PreparedLoad, reset, candidate/widget/sync/success or UI fallback. | F5; external P4 failure route. |
| EX-I3-043-C | P-ONLY direct producer raises the same error → existing project failure route with previous state equal and no reset/A2L/cache/widget/success/UI fallback. | External P4→Inc2 producer. |
| EX-I3-044-A | First image with attached OLD A2L → final install `(9,5)` → exactly one common publication → successful outcome; zero pre-install publications. | F2, F6; external L1 publication. |
| EX-I3-044-B | Different-path NEW image replacement → exactly one final publication with NEW image/current A2L before outcome and no outgoing-image publication. | F6; external L1 publication. |
| EX-I3-044-C | Equal-size NEW image at the same path → NEW raw values/definitions installed before one publication/outcome; OLD values absent. | F4, F6; external L1 publication. |
| EX-I3-047-A | `image.s19` changes equal-size OLD→NEW at one path without clear → new request/parse, `NEW_IMAGE` published and image generation increases. A2L source bytes remain byte-identical and writer reinstallation permits D-3 final `(9,5)` from `(8,4)`; the former unchanged-A2L-generation assertion is withdrawn. | F1, F3, F4; conflict closed. |
| EX-I3-047-B | P-PAIR `same.a2l` changes OLD→NEW → producer receives NEW data and returns final MAC-stage `(11,6)`; NEW tags/definitions replace OLD, unchanged image bytes remain identical and image-stage reinstallation may move its generation. | F5; external P4/P5 route. |
| EX-I3-047-C | P-PAIR same-path image changes OLD→NEW → producer receives the new image map and final pair `(11,6)`; unchanged A2L bytes remain identical while reset/writer stages may move its generation, and no OLD image survives. | F5; external P4/P5 route; conflict closed. |
| EX-I3-047-D | P-ONLY `same.a2l` changes OLD→NEW → direct producer snapshot `(10,4)`, NEW tags/definitions and no image/MAC/current_file; OLD markers absent. | External P4/P5. |
| EX-I3-048-A | Loose candidate `(9,5)` after required becomes `(10,5)` → whole candidate rejected before cache/session/widget/sync/publication; exact `Load superseded — current state kept.`. | F1/F4/F6 preserve context; external L1 rejects. |
| EX-I3-048-B | Loose candidate `(9,5)` after required becomes `(9,6)` → same all-or-nothing rejection and exact superseded outcome; no stale image/enrichment installed. | F6; external L1 rejects. |
| EX-I3-048-C | P-PAIR MAC candidate `(10,6)` versus required `(11,6)` → candidate pair preserved for pre-reset rejection; zero reset/candidate/project/widget/publication calls. | F5; external P5 rejects. |
| EX-I3-048-D | P-PAIR MAC candidate `(11,5)` versus required `(11,6)` → whole-load pre-reset rejection and exact superseded outcome. | F5; external P5 rejects. |
| EX-I3-048-E | P-ONLY candidate `(9,4)` versus required `(10,4)` → rejection before reset/A2L/cache/view/project mutation or publication. | External P4/P5. |
| EX-I3-048-F | P-ONLY captured `(10,4)` after a controlled live-image change makes required `(10,5)` → reject before reset even though the candidate has no image; no success/fallback. | External P4/P5. |
| EX-I3-043-D | P-PAIR-NOMAC producer raises `PREPARE_CONTROL` → F5 propagates without a PreparedLoad; P4/P5 use existing failure with no reset/candidate/UI fallback or MAC. | F5 propagation; external P4/P5. |
| EX-I3-045-C | Empty → P-PAIR-NOMAC → F5 supplies one image-stage snapshot; P5 publishes final image+A2L once with no reset/stage publication or MAC. | F5; external P5 publication. |
| EX-I3-047-E | No-MAC same-path A2L OLD→NEW → F5 receives NEW content; unchanged image bytes remain identical while image reinstall may move its generation. | F5; external P4/P5. |
| EX-I3-047-F | No-MAC same-path image OLD→NEW → F5 receives NEW map; unchanged A2L bytes remain identical while reset/writer may move its generation. | F5; external P4/P5. |
| EX-I3-048-G | Keyless P-PAIR image bundle has stale A2L expectation and no enrichment key → F5 preserves the generation-only candidate; P5 rejects before reset and never calls L1. | F5; external P5 rejection. |
| EX-I3-048-H | Keyless P-PAIR image bundle has stale image expectation → same pre-reset rejection without requiring a key or calling L1. | F5; external P5 rejection. |
| EX-I3-048-I | Live A2L advances after P-PAIR capture but before P5 entry → F1 remains frozen; current-counter P5 preflight rejects before reset/L1. | F1; external P5 rejection. |
| EX-I3-048-J | Live image advances after P-PAIR capture but before P5 entry → same frozen F1/current-preflight rejection before reset/L1. | F1; external P5 rejection. |
| EX-I3-048-K | No-MAC image snapshot has stale A2L expectation → P5 rejects before reset; no MAC/L1/candidate publication. | F5 carrier; external P5 rejection. |
| EX-I3-048-L | No-MAC image snapshot has stale image expectation → same pre-reset rejection with previous project state intact. | F5 carrier; external P5 rejection. |

The normal example assertions have discriminating negatives from the ledger: bypassing the producer, adding direct enrichment, moving work to UI, restoring fallback, publishing early/twice, keying by path, using uniform project `+1`, or resetting before preflight each changes a named observable. No mutation was executed at E2.

## Findings and dispositions

| Finding | Evidence and design disposition | State |
|---|---|---|
| CW-I3-F-01 | Static E1-base reads in F4/F6 include current A2L path/data, current file, both counters and the `current_project` log field. F1 capture plus context-only F4/F6 removes these product-worker reads. This is not a runtime defect claim. | Closed in graph. |
| CW-I3-F-02 | Baseline F5 directly calls `enrich_tags_and_render` and cannot carry I-ALP-2 picker snapshots. F5 now delegates to the sole Inc2 producer and carries its snapshot. | Closed in graph. |
| CW-I3-F-03 | Baseline F6 constructs `PreparedLoad(loaded=loaded)` after preparation failure. F6 now uses the existing failure route with no candidate fallback. | Closed in graph. |
| CW-I3-F-04 | Root I-ALP-2.2 now pins the route-neutral keyword-only producer and I-ALP-3 pins the optional typed S1 handoff. F5 and L1 adopt them without a second producer or runtime import cycle. | **Closed by accepted root interfaces.** |
| CW-I3-F-05 | Corrected REFRESH.047/EX-I3-047-A now preserve unchanged A2L bytes while permitting writer reinstall and final `A+1,I+1`; project B/C preserve unchanged bytes while allowing stage-driven generation movement. NEW/OLD and all budgets remain intact. | **Closed by E1 D-6 and root I-ALP-3.** |

No baseline extractor drift finding exists to inherit (`baseline-extract/diff-report.md` records zero findings). Its 19 ambiguous name resolutions remain an extractor-resolution limitation, not runtime evidence. The required future extraction against a completed Inc2 tree was not available at this E1-commit lane and remains an integration obligation.

## Interface rulings — accepted in root

### P-F-01 — reusable Inc2 producer call

Root I-ALP-2.2 pins the route-neutral producer with five keyword-only inputs after `self`:

```text
_prepare_a2l_attach_snapshot(
    *,
    a2l_path: Path,
    a2l_data: dict,
    image_mem_map: Optional[Mapping[int, int]],
    expected_a2l_generation: int,
    expected_image_generation: int,
) -> A2LAttachSnapshot
```

The producer computes the existing key, enrichment/summary and two independent picker descriptions without reading app/session/widget state. Direct attach adapts its parsed result to the same call; F5 supplies `loaded.a2l_path`, `loaded.a2l_data`, `loaded.mem_map` and its explicit stage pair; P4 supplies the A2L-only inputs directly. No data shape or producer implementation is added in Inc3.

### P-F-02 — typed I-ALP-3 handoff

Root pins `PreparedLoad.a2l_preparation` as a defaulted optional `A2LAttachSnapshot`, appended after `a2l_cache`. A type-checking-only annotation/forward reference avoids the runtime `shared.py` ↔ `file_load.py` cycle. L1 installs the accepted snapshot's values and `_accepted_a2l_picker_snapshots` before common refresh; legacy `None` remains compatibility only. Existing enrichment fields are projections of the same snapshot rather than independently computed data.

### P-F-03 — REFRESH.047 reconciled

Applied ruling: retain the explicit D-3/I-ALP-3 generation matrix and distinguish unchanged source/content identity from generation changes caused by reinstallation. EX-I3-047-A asserts unchanged A2L source/content and final pair `(A+1,I+1)`; project reloads keep their stage-specific pairs. The requirements and ledger now carry that ruling, and no conflicting unchanged-A2L-generation assertion remains.

## Lint evidence

The corrected graph was re-linted at integration with direct Python, UTF-8 I/O and repository-relative paths. Exit `0`; verbatim stdout is `evidence-e2/integrated/file-load-lint.txt` and the full parse is `file-load-lint.json` beside it:

```text
not read=0 nodes=6 entities=5 edges=9
```

The JSON independently confirms six nodes named F1–F6, five findings and an empty `unread` array. The earlier deliberate one-node/one-unread-line instrument control remains in `evidence-e2/file-load/lint-red.txt`: exit `1`, `not read=1 nodes=1 entities=0 edges=0`; its temporary input was deleted. No hand-maintained hash table is retained for superseded lint bytes; the current evidence home is the integrated directory.

## Forward applicability and remaining work

- The conductor's root rulings for CW-I3-F-04/CW-I3-F-05 and P-F-01 through P-F-03 are consumed and closed; this lane changed no root rule.
- P/L/S lane owners consume the explicit stage pairs and snapshot handoff at integration; Inc2 retains producer ownership.
- The integrator must layer the completed Inc1/Inc2 graphs oldest first, run any marks/extraction only in a throwaway clone, delete that clone and rule every new finding.
- E3 reviews the reconciled graph and external callers. E4/E5 own all route, failure, publication, stale, same-path, performance, RED/GREEN and mutation execution; none is claimed here.
