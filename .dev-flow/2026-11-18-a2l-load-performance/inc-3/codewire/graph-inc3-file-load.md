# Inc3 G-I3-F — file_load prepared-load delta

E2 design at E1 commit `85e68957`; Code-Wire v3.2.0. This is a planned graph delta over `baseline.md`, not an execution report. Scope is exactly F1–F6 from `E1-slice.md`; product, tests and frozen interfaces are unchanged. Examples are requirement-derived oracles, not observed results.

## Nodes

FileLoadRequest
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.043, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: Path path; Optional[Path] a2l_path; Optional[dict] a2l_data; Optional[A2LCacheEntry] a2l_cache; Optional[LoadedFile] current_file; int expected_a2l_generation; int expected_image_generation; int gen; Optional[tuple[Path, ...]] a2l_files = None; bool sync_project = True
out: FileLoadRequest request
func: F1 frozen data node captures every artifact/cache/generation input on UI before worker launch; fields are fixed and captured payloads are read-only for the worker.
module: s19_app/tui/app/file_load.py
examples: (EX-I3-039-B) UI capture with A=`8`, I=`4`, attached A2L and busy generation `12` → request expected pair (`9`, `5`), gen `12` and sync_project `True`; field reassignment is refused
examples: (EX-I3-047-A) second admission of `image.s19` at one lexical path after equal-size OLD→NEW bytes → a new request with expected image generation `5`; unchanged A2L source bytes remain byte-identical while writer reinstallation permits final pair (`9`, `5`), and path equality does not reuse the old request
examples: (EX-I3-048-A) request captured as (`9`, `5`) before a competing A2L install → request remains (`9`, `5`) for downstream stale comparison and never refreshes itself from live counters
oracle: ../E1-slice.md F1 and ../E1-rulings.md D-3/D-6

FileLoadMixin.load_from_path
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.043, R-A2L-REFRESH.044, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: Path path
out: None
func: F2 preserves admission, copy, recents and busy behavior, then constructs F1 on UI with sync_project=True and starts the same worker with that explicit context.
module: s19_app/tui/app/file_load.py
examples: (EX-I3-039-B) admitted image with attached A2L at A=`8`, I=`4` → exactly `1` worker receives F1 with expected pair (`9`, `5`) and no live-session lookup is deferred to that worker
examples: (EX-I3-040-A) image request with attached case_06 A2L of `37742888` bytes → existing admission/copy precede F1 capture and worker launch; independent total measurement starts before admission and includes copy and parse
examples: (EX-I3-044-A) first image load with OLD A2L attached → one F1/worker dispatch and common-publication count `0` before final image/A2L installation
oracle: ../02-test-cases.md EX-I3-039-B, EX-I3-040-A and EX-I3-044-A

FileLoadMixin._load_workarea_file
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.043, R-A2L-REFRESH.044, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: str name
out: None
func: F3 preserves workarea admission/refusal and the in-place non-A2L go arm, then constructs F1 on UI with sync_project=False and no copy before starting the same worker contract.
module: s19_app/tui/app/file_load.py
examples: (EX-I3-047-A) admitted in-place `image.s19` with changed equal-size content → F1 has sync_project `False`, copy count `0` and one worker receives a fresh expected pair
examples: (EX-I3-039-B) workarea image with attached A2L → the same F1/F6 producer route is selected with exactly `1` eventual Inc2 producer call and no second enrichment pipeline
oracle: ../E1-slice.md F3 and ../02-test-cases.md EX-I3-047-A

FileLoadMixin._parse_loaded_file
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: Path path; Optional[list[Path]] a2l_files = None; Optional[list[A2LCacheEntry]] a2l_cache_out = None; Optional[FileLoadRequest] context = None
out: Optional[LoadedFile] result
func: F4 adds keyword-only context; the product arm uses context.a2l_files first, otherwise context path/data/cache/current-file inputs, ignores legacy standalone A2L arguments, reads no live session member including current_project, and preserves parser/cache handoff; None is legacy only.
module: s19_app/tui/app/file_load.py
examples: (EX-I3-039-B) context supplies attached A2L path/data/cache and the existing image → result merges the newly parsed image with that A2L while live current_a2l_path, current_a2l_data, current_file and current_project read count is `0`
examples: (EX-I3-047-A) equal-size NEW bytes replace OLD at `image.s19` without a clear → result contains `NEW_IMAGE`, not `OLD_IMAGE`; captured A2L cache remains an explicit parse input and path alone is not a cache key
examples: (EX-I3-048-A) live A2L state changes after F1 capture → result still uses the captured A2L input, leaving the later generation preflight to reject the whole candidate rather than mixing artifacts
oracle: ../E1-rulings.md D-3/D-6 and baseline premise P03

FileLoadMixin._prepare_load_payload
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: LoadedFile loaded; Optional[int] a2l_view_generation = None; Optional[int] image_generation = None; bool prepare_a2l = True
out: PreparedLoad result
func: F5 adds keyword-only prepare_a2l; with A2L and True it calls the Inc2 producer once using explicit source/data/map/stage generations and packs the returned I-ALP-2 snapshot with the other prepared data, never direct enrichment; False skips A2L production and omitted generations remain legacy synchronous behavior only.
module: s19_app/tui/app/file_load.py
examples: (EX-I3-039-B) loaded image+A2L, expected (`9`, `5`), mem_size `2` and prepare_a2l `True` → exactly `1` Inc2 producer call; result.a2l_preparation carries pair (`9`, `5`), key (`9`, `5`, `2`) and independent `check`/`patch` maps; direct enrichment calls `0`
examples: (EX-I3-039-C) image-after-reset stage at A=`8`, I=`4` with prepare_a2l `False` and expected (`10`, `5`) → producer calls `0`, no A2L snapshot and generation-only PreparedLoad retains (`10`, `5`)
examples: (EX-I3-039-C) MAC-after-image stage for the same load with prepare_a2l `True` and expected (`11`, `6`) → exactly `1` producer call and result snapshot pair (`11`, `6`); total A2L production for both stages is `1`
examples: (EX-I3-039-E) project image+A2L without MAC with expected (`10`, `5`) → exactly `1` producer call at the image stage and no MAC fabrication or duplicate UI preparation
examples: (EX-I3-040-A) parsed case_06 payload with `220040` tags and a `0.20` s producer gate → enrichment, summary, Check/Patch definitions and other payload preparation remain on the worker with UI construction count `0`
examples: (EX-I3-043-B) Inc2 producer raises ValueError(`PREPARE_CONTROL`) for P-PAIR → exception propagates with no PreparedLoad result, no candidate installation and no synchronous UI-preparation fallback
examples: (EX-I3-047-B) same-path `same.a2l` now yields `NEW_A2L` instead of `OLD_A2L` at captured A=`8`, I=`4` → producer receives NEW data, not a path identity, and the MAC-stage result carries (`11`, `6`); unchanged image bytes remain byte-identical while its reinstallation may move image generation
examples: (EX-I3-047-C) same-path project image now yields `NEW_IMAGE` instead of `OLD_IMAGE` → producer receives the new image map and current A2L data and returns the prepared MAC-stage pair (`11`, `6`); unchanged A2L bytes remain byte-identical while reset/writer stages may move A2L generation
examples: (EX-I3-048-C) MAC-stage candidate incorrectly carries (`10`, `6`) while required is (`11`, `6`) → result preserves the candidate pair for P5 pre-reset rejection; no generation is corrected by reading live state
examples: (EX-I3-048-D) MAC-stage candidate incorrectly carries (`11`, `5`) while required is (`11`, `6`) → result preserves that stale image expectation for whole-load rejection before reset
oracle: ../../interfaces.md I-ALP-2.2 and I-ALP-3; ../E1-rulings.md D-1/D-3/D-5

FileLoadMixin._start_load_worker
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.043, R-A2L-REFRESH.044, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: Path path; Optional[list[Path]] a2l_files = None; int gen; bool sync_project = True; Optional[FileLoadRequest] context = None
out: None
func: F6 adds keyword-only context after sync_project; product calls consume F1 rather than live artifacts/counters, run F4 then F5 off UI, route preparation failure to the existing failure handler with no minimal-bundle fallback, and dispatch one UI completion; None is legacy only.
module: s19_app/tui/app/file_load.py
examples: (EX-I3-040-A) `3` fresh serial case_06 image+A2L runs → request-to-outcome totals include admission/copy, parse, post-parse preparation and install/publication as `4` named phases; accept only median ≤`45` s and every run <`60` s, with `50` ms timer lateness ≤`100` ms and ≥`3` ticks during the `0.20` s worker hold; an independent `61` s hold fails total even if every tick passes
examples: (EX-I3-043-A) F5 raises ValueError(`PREPARE_CONTROL`) → one UI `_handle_load_error` dispatch, candidate installs `0`, UI preparation calls `0`, success outcomes `0`, and previous state/views/project hashes remain equal
examples: (EX-I3-044-A) first image with OLD A2L reaches expected (`9`, `5`) → ordered timeline final install → exactly `1` common publication → `Loaded image.s19`; pre-install publications `0`
examples: (EX-I3-044-B) different-path NEW image with attached A2L → exactly `1` final common publication with NEW image and current A2L before success; outgoing-image publications `0`
examples: (EX-I3-044-C) equal-size NEW image at the same path → `NEW_IMAGE` and its definitions are installed before exactly `1` final publication and success; `OLD_IMAGE` is absent
examples: (EX-I3-048-A) candidate pair (`9`, `5`) reaches completion after required becomes (`10`, `5`) → L1 rejects before candidate cache/session/widget/sync/publication mutation and outcome is exactly `Load superseded — current state kept.`
examples: (EX-I3-048-B) candidate pair (`9`, `5`) reaches completion after required becomes (`9`, `6`) → the whole candidate is rejected with the same exact superseded outcome and no stale image or enrichment is installed
oracle: ../02-test-cases.md EX-I3-040-A, EX-I3-043-A, EX-I3-044-A/B/C and EX-I3-048-A/B

## Entities

[Data: FileLoadRequest]
desc: F1 frozen UI-captured route context; product workers treat all referenced payloads as read-only and never resolve current session state themselves.

[Data: A2LAttachSnapshot]
desc: I-ALP-2.2 immutable generation-bound producer value with enrichment key, tag/summary tuples and independent read-only Check/Patch definition maps.

[Data: PreparedLoad]
desc: S1 handoff gains defaulted a2l_preparation carrying A2LAttachSnapshot; existing constructors remain compatible and legacy None is not product-worker evidence.

[Data: Session artifacts]
desc: current A2L path/data/cache, current file and both generation counters are read only during F2/F3 UI capture, never by the F1 product worker arm.

[I/O: case_06 A2L]
desc: committed 37742888-byte fixture whose E1 parser probe produced 220040 tags and zero parse errors; this fixture fact is not a load timing result.

## Edges

[Data: Session artifacts] ──▶ FileLoadMixin.load_from_path
when: UI capture after existing admission/copy and before worker launch

[Data: Session artifacts] ──▶ FileLoadMixin._load_workarea_file
when: UI capture in the admitted non-A2L go arm before worker launch

FileLoadMixin.load_from_path ──▶ [Data: FileLoadRequest]
FileLoadMixin._load_workarea_file ──▶ [Data: FileLoadRequest]
[Data: FileLoadRequest] ──▶ FileLoadMixin._start_load_worker
[Data: FileLoadRequest] ──▶ FileLoadMixin._parse_loaded_file
when: context is not None on the product worker arm

FileLoadMixin._prepare_load_payload ──▶ [Data: A2LAttachSnapshot]
when: prepare_a2l is True and loaded.a2l_data is present; the Inc2 producer creates the value

FileLoadMixin._prepare_load_payload ──▶ [Data: PreparedLoad]
FileLoadMixin._start_load_worker ──▶ [Data: PreparedLoad]
when: parsing and preparation both succeed; preparation failure has no PreparedLoad fallback

## Findings

finding CW-I3-F-01 worker reads live session at the E1 base
anchor: FileLoadMixin._parse_loaded_file; FileLoadMixin._start_load_worker
seen: static E1-base reads include current A2L path/data, current file, both generation counters and the current_project log field; this is a disk observation, not a functional test result
cause: the worker resolves request inputs at use time instead of receiving an explicit captured context
effect: a competing UI transition can mix artifacts or generations and worker isolation cannot be established from the old call contract
decision: F1 captures on UI; F4/F6 consume only F1 on product arms and legacy None arms are excluded from isolation evidence

finding CW-I3-F-02 direct enrichment bypasses the prepared interface
anchor: FileLoadMixin._prepare_load_payload
seen: the baseline calls enrich_tags_and_render directly and has no I-ALP-2 picker snapshots
cause: loose/project preparation predates the Inc2 generation-bound snapshot producer
effect: a second pipeline would duplicate enrichment/summary work and omit prepared Check/Patch definitions
decision: F5 calls the single Inc2 producer with explicit stage inputs and carries its snapshot in PreparedLoad; no new producer is designed in this lane

finding CW-I3-F-03 preparation failure currently creates a slow candidate
anchor: FileLoadMixin._start_load_worker
seen: the E1 base constructs PreparedLoad(loaded=loaded) after a preparation exception
cause: the old fallback moves derived-data construction into the UI installation path
effect: the candidate can install after failed preparation and violate REFRESH.043 and the responsiveness design
decision: F6 dispatches the existing failure route and never constructs or completes a candidate on that arm

finding CW-I3-F-04 reusable producer call and handoff type need explicit pinning
anchor: FileLoadMixin._prepare_load_payload; PreparedLoad
seen: root I-ALP-2.2 now pins the route-neutral keyword-only producer and I-ALP-3 pins PreparedLoad.a2l_preparation as optional A2LAttachSnapshot after a2l_cache with TYPE_CHECKING-only import
cause: direct-attach design owns the producer while Inc3 reuses it for parsed LoadedFile and project stages
effect: the formerly incompatible call/import choices are removed without changing A7/A8 or adding a second producer
decision: CLOSED — adopt the root producer and S1 carrier verbatim; P-F-01/P-F-02 are accepted and no interface edit is made by this lane

finding CW-I3-F-05 REFRESH.047 generation oracle conflicts with stage expectations
anchor: FileLoadRequest; FileLoadMixin._prepare_load_payload
seen: corrected REFRESH.047 and EX-I3-047-A now require NEW image content/generation, unchanged A2L bytes and final pair A+1,I+1; project B/C likewise preserve unchanged bytes while allowing stage-driven generation movement
cause: the former oracle treated unchanged content identity and reinstalled artifact generation as the same observable
effect: the loose-image contradiction and project B/C ambiguity are removed while NEW/OLD and the stage matrix remain binding
decision: CLOSED — E1 D-6 applies root I-ALP-3; changed bytes require newer generation, unchanged bytes remain identical and reinstall may increment generation
