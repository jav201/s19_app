# Inc3 integrated Code-Wire graph — image/project A2L load parity

E2 integration over E1 commit `85e68957`, using Code-Wire v3.2.0 and accepted root `../../interfaces.md`. Inputs are the corrected F, P and L+S graphs in that order. The graph preserves every node, example and finding; duplicate PreparedLoad/A2LAttachSnapshot entities are subsumed by their later root-accepted L+S definitions.

Coverage is 12 parsed function/data nodes plus S1's PreparedLoad entity = 13 implementation nodes across exactly four SOURCE modules: `s19_app/tui/app/file_load.py`, `project_load.py`, `loaded_state.py` and `shared.py`. All ten REFRESH.039–.048 requirements have concrete examples. No functional test, timing result, product mark or product extraction is claimed.

REFRESH.047 distinguishes changed content from reinstallation: changed bytes require a newer generation of each changed artifact, unchanged content/bytes remain byte-identical, and writer/reset/reinstall stages may move an unchanged artifact's generation. The old unchanged-A2L-generation assertion is withdrawn; NEW/OLD and all total/UI budgets remain binding.

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

ProjectLoadRequest
req: R-A2L-REFRESH.039, R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043, R-A2L-REFRESH.048
in: str name; Path project_dir; tuple[Path, ...] data_files; tuple[Path, ...] a2l_files; Optional[ProjectFileProblem] a2l_problem; Optional[A2LCacheEntry] a2l_cache; int gen; bool routed; Optional[int] captured_a2l_generation = None; Optional[int] captured_image_generation = None
out: ProjectLoadRequest request
func: P1 frozen UI-captured request retains every positional admission field and adds default-None captured generations; product requests always populate both and workers read no live counters
module: s19_app/tui/app/project_load.py
examples: (EX-I3-039-C) admitted P-PAIR with current A=`7` and I=`4` → frozen request captures `7` and `4` before worker launch
examples: (EX-I3-039-E) admitted P-PAIR-NOMAC with A=`7` and I=`4` → the same request contract captures both counters without a MAC-specific default
examples: (EX-I3-048-F) P-ONLY request captures I=`4`, then a test-controlled UI change advances live I to `5` → request remains frozen at `4` for the already-running worker
oracle: .dev-flow/2026-11-18-a2l-load-performance/inc-3/E1-slice.md, P1 and stage matrix

PreparedProjectLoad
req: R-A2L-REFRESH.039, R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043, R-A2L-REFRESH.045, R-A2L-REFRESH.046, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: ProjectLoadRequest request; Optional[str] refusal; ProjectVariantSet variant_set; Optional[ProjectManifest] manifest; tuple[ProjectFileProblem, ...] problems; Optional[A2LCacheEntry] a2l_cache; InstallSet install; PreparedLoad | LoadedFile | None image; tuple[VariantDescriptor, ...] unreadable; PreparedLoad | LoadedFile | None mac; Optional[RecordedDocumentState] document; Optional[A2LAttachSnapshot] a2l_only = None
out: PreparedProjectLoad prepared
func: P2 frozen worker handoff carries prepared image/MAC bundles or legacy LoadedFile test values, plus one optional A2L-only Inc2 snapshot, without changing existing field order
module: s19_app/tui/app/project_load.py
examples: (EX-I3-039-C) captured A=`7`, I=`4` → image bundle expects `9`, `5` with no A2L snapshot; MAC bundle expects `10`, `6` with the load's single A2L snapshot
examples: (EX-I3-039-E) captured A=`7`, I=`4` and no MAC → image bundle expects `9`, `5` and carries one A2L snapshot; mac is `None`
examples: (EX-I3-046-A) captured A=`0`, I=`0` for P-ONLY → image=`None`, mac=`None`, and a2l_only expects `2`, `0` without a synthetic LoadedFile
oracle: .dev-flow/2026-11-18-a2l-load-performance/interfaces.md, I-ALP-2.2 and I-ALP-3

ProjectLoadMixin._handle_load_project
req: R-A2L-REFRESH.039, R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: Optional[str] name; bool routed = False
out: None
func: P3 preserves cheap refusals, admission and busy order, captures both current generations into P1 on the UI thread, and starts the existing worker without path-only reload short-circuiting
module: s19_app/tui/app/project_load.py
examples: (EX-I3-039-D) admitted P-ONLY with A=`7`, I=`4` → one worker receives captured generations `7`, `4` and no image or MAC is fabricated
examples: (EX-I3-047-B) the same project name and same.a2l path contain equal-size NEW bytes after OLD, with no clear → admission starts a fresh worker instead of treating path equality as content equality
examples: (EX-I3-043-C) admitted P-ONLY starts the normal worker with captured generations → later producer failure remains on the existing project failure route, with no UI preparation fallback
oracle: .dev-flow/2026-11-18-a2l-load-performance/inc-3/02-test-cases.md, EX-I3-039-D and EX-I3-047-B

ProjectLoadMixin._prepare_project_load
req: R-A2L-REFRESH.039, R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: ProjectLoadRequest request
out: PreparedProjectLoad result
func: P4 parses and selects as before, prepares all product image/MAC bundles and A2L-only data off UI through F5 and the same Inc2 snapshot producer, uses stage-specific expected pairs, and propagates preparation exceptions without a candidate fallback
module: s19_app/tui/app/project_load.py
examples: (EX-I3-039-C) P-PAIR with A=`7`, I=`4` → image F5 uses prepare_a2l=`False` at `9`, `5`; MAC F5 uses prepare_a2l=`True` at `10`, `6`; Inc2 producer calls=`1`, UI constructions=`0`
examples: (EX-I3-039-E) P-PAIR-NOMAC with A=`7`, I=`4` → image F5 uses prepare_a2l=`True` at `9`, `5`; Inc2 producer calls=`1`, mac=`None`, UI constructions=`0`
examples: (EX-I3-039-D) P-ONLY with A=`7`, I=`4` → the Inc2 producer receives parsed A2L, image_mem_map=`None`, expected pair `9`, `4`; calls=`1`, synthetic LoadedFile count=`0`
examples: (EX-I3-041-A) unexecuted oracle input for three P-PAIR runs has totals `44`, `45`, `46` seconds, all four phases present, and maximum tick lateness `100` ms → median=`45`, maximum=`46`, budget verdict=`True`
examples: (EX-I3-041-A, total-negative) unexecuted totals `44`, `45`, `60` seconds with responsive ticks → median=`45` but individual maximum=`60`, so total-budget verdict=`False`
examples: (EX-I3-041-B) unexecuted oracle input for three P-PAIR-NOMAC runs has totals `42`, `43`, `44` seconds and at least `3` ticks during a `0.20` second worker hold → median=`43`, maximum=`44`, responsiveness and budget verdict=`True`
examples: (EX-I3-042-A) unexecuted oracle input for three P-ONLY runs has totals `43`, `44`, `45` seconds, admission/parse/preparation/install phases but no copy phase → median=`45`, maximum=`45`, budget verdict=`True`
examples: (EX-I3-042-A, total-negative) unexecuted responsive P-ONLY hold of `61` seconds → individual duration bound verdict=`False` independently of tick results
examples: (EX-I3-043-B) P-PAIR producer raises ValueError("PREPARE_CONTROL") → exception reaches the existing project failure route; PreparedProjectLoad candidate count=`0`, reset count=`0`, UI preparation count=`0`
examples: (EX-I3-043-C) P-ONLY producer raises ValueError("PREPARE_CONTROL") → no A2L-only snapshot or candidate installs; cache/reset/widget/success counts=`0`
examples: (EX-I3-043-D) P-PAIR-NOMAC producer raises ValueError("PREPARE_CONTROL") → the existing project failure route receives it; candidates=`0`, resets=`0`, UI preparations=`0`, MAC fabrications=`0`, successes=`0`
examples: (EX-I3-047-B) same-path equal-size A2L NEW replaces OLD with a changed write timestamp → parsing and the single snapshot contain NEW markers, never a path-keyed OLD reuse
examples: (EX-I3-047-C) same-path equal-size image NEW replaces OLD in P-PAIR → image/MAC preparation reads NEW image bytes and current A2L, never OLD image bytes
examples: (EX-I3-047-D) same-path equal-size P-ONLY A2L NEW replaces OLD → a2l_only carries NEW tags/summary/definitions with expected post-reset pair, with no image input invented
examples: (EX-I3-048-F) P-ONLY captured A=`7`, I=`4` → worker snapshot expects `9`, `4`; a later live I=`5` is not read or hidden by this worker
examples: (EX-I3-048-G) test-constructed keyless P-PAIR image bundle at current A=`7`, I=`4` carries A2L expectation `8` instead of required `9` and a2l_enriched_key=`None` → P4 preserves the stale generation-only candidate for P5 pre-reset rejection without repair or producer repair
examples: (EX-I3-048-H) test-constructed keyless P-PAIR image bundle carries image expectation `4` instead of required `5` and a2l_enriched_key=`None` → P4 preserves it for P5 pre-reset rejection; no enrichment key is required
oracle: .dev-flow/2026-11-18-a2l-load-performance/inc-3/E1-rulings.md, D-1, D-3, D-5 and D-7

ProjectLoadMixin._install_prepared_project
req: R-A2L-REFRESH.039, R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043, R-A2L-REFRESH.045, R-A2L-REFRESH.046, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: PreparedProjectLoad prepared
out: None
func: P5 preflights every product stage pair against current UI generations before reset or any candidate mutation, installs accepted prepared values with publish_a2l=False, installs A2L-only snapshots without LoadedFile synthesis, then publishes once after final project identity and before outcome
module: s19_app/tui/app/project_load.py
examples: (EX-I3-045-A) empty session A=`0`, I=`0` accepts P-PAIR → preflight image `2`, `1` and MAC `3`, `2`; reset/image/MAC publications=`0`; final F=`1` after pair `3`, `2` and before OUTCOME
examples: (EX-I3-045-B) outgoing P-PAIR A=`7`, I=`4` accepts incoming P-PAIR → both stages preflight before reset; only incoming final pair `10`, `6` reaches final F=`1`, then OUTCOME
examples: (EX-I3-045-C) empty session A=`0`, I=`0` accepts P-PAIR-NOMAC → image preflight expects `2`, `1`; reset/image publications=`0`, MAC fabrications=`0`, and exactly `1` final F sees image+A2L/project identity before OUTCOME
examples: (EX-I3-046-A) empty session A=`0`, I=`0` accepts P-ONLY → preflight `2`, `0`, reset without F, A2L writer and prepared cache/mapping install, final F=`1`; current_file=`None`, image/MAC count=`0`
examples: (EX-I3-046-B) outgoing image+A2L A=`7`, I=`4` accepts P-ONLY → final A=`9`, I=`4`, F=`1`, current_file=`None`, phantom MAC/image count=`0`, reset publications=`0`
examples: (EX-I3-047-B) same-path P-PAIR A2L OLD→NEW → final publication contains NEW A2L tags/definitions and a newer A2L generation; unchanged image bytes remain byte-identical while image-stage reinstallation may move image generation; OLD markers=`0`, final F=`1`
examples: (EX-I3-047-C) same-path P-PAIR image OLD→NEW → final publication contains NEW image content and a newer image generation; unchanged A2L bytes remain byte-identical while reset/writer stages may move A2L generation; OLD image markers=`0`, mixed-pair publications=`0`
examples: (EX-I3-047-D) same-path P-ONLY A2L OLD→NEW with prior A=`7`, I=`4` → final A=`9`, I=`4`, NEW A2L publishes once and OLD/no-A2L markers=`0`
examples: (EX-I3-047-E) P-PAIR-NOMAC same-path A2L OLD→NEW with prior A=`7`, I=`4` → final pair `9`, `5` contains NEW A2L and its newer generation; unchanged image bytes remain byte-identical while image reinstall may move image generation; MAC/OLD markers=`0`
examples: (EX-I3-047-F) P-PAIR-NOMAC same-path image OLD→NEW with prior A=`7`, I=`4` → final pair `9`, `5` contains NEW image and its newer generation; unchanged A2L bytes remain byte-identical while reset/writer may move A2L generation; MAC/OLD/mixed markers=`0`
examples: (EX-I3-048-C) current A=`7`, I=`4` and MAC snapshot A2L expectation=`9` instead of required `10` → reject before reset; candidate/cache/session/widget/project/publication mutations=`0`; outcome="Load superseded — current state kept."
examples: (EX-I3-048-D) current A=`7`, I=`4` and MAC snapshot image expectation=`5` instead of required `6` → reject before reset with kept project hashes and the same superseded outcome
examples: (EX-I3-048-E) P-ONLY current A=`7`, I=`4` and snapshot A2L expectation=`8` instead of required `9` → reject before reset/A2L/cache/view/project mutation; success count=`0`
examples: (EX-I3-048-F) P-ONLY snapshot expects `9`, `4`, but live I=`5` at installation requires `9`, `5` → reject the whole candidate before reset even though no image would install
examples: (EX-I3-048-I) P-PAIR captured A=`7`, I=`4`, but live A=`8` before P5 entry makes image/MAC requirements (`10`, `5`)/(`11`, `6`) differ from captured (`9`, `5`)/(`10`, `6`) → reject before reset; L1/candidate/widget/sync/publication calls=`0`
examples: (EX-I3-048-J) P-PAIR captured A=`7`, I=`4`, but live I=`5` before P5 entry makes image/MAC requirements (`9`, `6`)/(`10`, `7`) differ from captured (`9`, `5`)/(`10`, `6`) → reject before reset with previous project hashes equal and no L1 call
examples: (EX-I3-048-K) P-PAIR-NOMAC current A=`7`, I=`4` and image snapshot A2L expectation=`8` instead of required `9` → reject before reset; MAC/L1/candidate/publication calls=`0` and outcome="Load superseded — current state kept."
examples: (EX-I3-048-L) P-PAIR-NOMAC current A=`7`, I=`4` and image snapshot image expectation=`4` instead of required `5` → reject before reset with previous project hashes equal; MAC/L1/candidate/publication/success calls=`0`
oracle: .dev-flow/2026-11-18-a2l-load-performance/inc-3/E1-rulings.md, D-3 through D-6 and D-10

LoadedStateMixin._apply_prepared_load
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.041, R-A2L-REFRESH.044, R-A2L-REFRESH.045, R-A2L-REFRESH.048
in: PreparedLoad prepared; Path path; float load_started; bool publish_a2l = True
out: bool accepted
func: changed. Preflight every complete legacy or S1 snapshot generation pair, including a keyless generation-only bundle; reject an incomplete, mutually inconsistent or stale pair before any candidate mutation. Preserve the accepted install and finalization behavior; when S1 is present its enrichment key/tags/summary are authoritative, with one shallow list conversion of each tuple to preserve the existing cache types, and its independent read-only check/patch mapping replaces the accepted picker mapping without a copy before any common refresh. Keep the no-snapshot/two-None legacy constructor arm and publish only under publish_a2l; L1 never enriches or describes.
module: s19_app/tui/app/loaded_state.py
modify: [Data: Prepared load candidate] (replace); [Data: S19TuiApp._accepted_a2l_picker_snapshots] (replace); [Data: A2L-dependent publication] (append)
volatile: path, load_started
oracle: ../01-requirements.md R-A2L-REFRESH.039 through .045 and .048; ../E1-rulings.md D-3 through D-5
examples: (EX-I3-039-A, DIRECT) direct attach with captured A=`7`, I=`4` supplies Inc2 pair `(8, 4)` and independent `check`/`patch` snapshots through A4 → expect none
examples: (EX-I3-039-B) loose image with captured A=`7`, I=`4` carries snapshot pair `(8, 5)` and read-only `check`/`patch` entries → accepted `True`; that exact mapping is installed before F and UI preparation calls=`0`
examples: (EX-I3-039-C) P-PAIR with captured A=`7`, I=`4` has keyless image pair `(9, 5)`, then MAC snapshot pair `(10, 6)` → both accepted `True`; the image stage leaves the mapping unchanged, the MAC stage installs it once, and route producer calls=`1`
examples: (EX-I3-039-D, A2L_ONLY) P-ONLY with captured A=`7`, I=`4` supplies P2/P5 snapshot pair `(9, 4)` without a synthetic PreparedLoad or current_file → expect none
examples: (EX-I3-039-E) P-PAIR-NOMAC with captured A=`7`, I=`4` carries image snapshot pair `(9, 5)` → accepted `True` with publish_a2l=`False`; its mapping precedes P5's sole F and route producer calls=`1`
examples: (EX-I3-040-A) case_06 with `220040` tags, captured A=`7`, I=`4` and snapshot pair `(8, 5)` → accepted `True`; each of `3` serial request-to-outcome runs includes parse and `4` named phases, has total <`60` s and median ≤`45` s; the `0.20` s worker hold yields ≥`3` ticks each ≤`100` ms late and final current pair `(8, 5)`
examples: (EX-I3-041-A) P-PAIR with captured A=`7`, I=`4`, keyless image pair `(9, 5)` and MAC snapshot pair `(10, 6)` → accepted `True` at both stages; each of `3` runs includes parse and `4` phases, has total <`60` s and median ≤`45` s, every tick is ≤`100` ms late, and no intermediate F occurs
examples: (EX-I3-041-B) P-PAIR-NOMAC with captured A=`7`, I=`4` and image snapshot pair `(9, 5)` → accepted `True`; each of `3` runs has total <`60` s and median ≤`45` s with parse included, every tick is ≤`100` ms late, and no MAC or intermediate F appears
examples: (EX-I3-042-A, INSTALL) P-ONLY case_06 uses P2/P5 pair `(9, 4)`, has no current_file/image/MAC, records admission/parse/preparation/install-publication with no copy phase, and each of `3` totals is <`60` s with median ≤`45` s → expect none
examples: (EX-I3-043-A, PREPARE) image-route producer raises ValueError("PREPARE_CONTROL") → expect none; candidate installs=`0`, UI preparation calls=`0`, success outcomes=`0`, and the existing image failure route keeps previous state
examples: (EX-I3-043-B, PREPARE) P-PAIR producer raises ValueError("PREPARE_CONTROL") → expect none; resets=`0`, candidate installs=`0`, UI preparation calls=`0`, and previous project files/state remain equal
examples: (EX-I3-043-C, PREPARE) P-ONLY producer raises ValueError("PREPARE_CONTROL") → expect none; resets=`0`, A2L/cache/widget mutations=`0`, UI preparation calls=`0`, and no success occurs
examples: (EX-I3-044-A) first loose image over attached OLD A2L with matching pair `(8, 5)` → accepted `True`; timeline is final install → mapping/cache install → F count=`1` → OUTCOME, with no pre-install F
examples: (EX-I3-044-B) different-path NEW image over outgoing image+OLD A2L with matching pair `(9, 6)` → accepted `True`; exactly `1` F sees NEW image and current A2L before OUTCOME and no outgoing pair is published
examples: (EX-I3-044-C) same-path equal-size different-content NEW image replacement with matching pair `(10, 7)` → accepted `True`; exactly `1` F sees NEW raw values/definitions, OLD values are absent, and OUTCOME follows F
examples: (EX-I3-045-A) empty session accepts P-PAIR image pair `(9, 5)` then MAC pair `(10, 6)` with publish_a2l=`False` → accepted `True` twice and L1 F count=`0`; P5 publishes final image+MAC+A2L/project identity exactly `1` time before OUTCOME
examples: (EX-I3-045-B) outgoing P-PAIR replaced by incoming P-PAIR accepts final stage pair `(12, 8)` with publish_a2l=`False` → accepted `True`; no reset/image-only/MAC-stage F occurs and P5's sole F precedes OUTCOME
examples: (EX-I3-048-A) loose image requires pair `(8, 5)` but snapshot records A2L generation `7` → accepted `False`; candidate cache/session/widget/sync/publication calls=`0`, previous state is equal, and OUTCOME is `Load superseded — current state kept.`
examples: (EX-I3-048-B) loose image requires pair `(8, 5)` but snapshot records image generation `4` → accepted `False`; no candidate image, enrichment, picker mapping or success is installed and OUTCOME is `Load superseded — current state kept.`
examples: (EX-I3-048-C, PRE_RESET) P-PAIR MAC stage requires `(10, 6)` but its snapshot A2L generation is `9` → expect none; P5 rejects before reset/project/widget/publication with `Load superseded — current state kept.`
examples: (EX-I3-048-D, PRE_RESET) P-PAIR MAC stage requires `(10, 6)` but its snapshot image generation is `5` → expect none; P5 rejects before reset/install/sync/publication with previous project hashes equal
examples: (EX-I3-048-E, PRE_RESET) P-ONLY requires `(9, 4)` but its P2 snapshot A2L generation is `8` → expect none; P5 rejects before reset/A2L/cache/view/project/publication and keeps the exact superseded outcome
examples: (EX-I3-048-F, PRE_RESET) P-ONLY requires `(9, 4)` after a test-controlled live-image change but its snapshot image generation is `3` → expect none; P5 rejects before reset/publication even though no candidate image exists
examples: (EX-I3-048-A, INCOMPLETE_PAIR) loose image has legacy A2L generation `8`, legacy image generation `None`, and no snapshot → accepted `False` before candidate mutation; an either-field guard may not compare or install a partial pair
examples: (EX-I3-048-B, DISAGREEING_PAIRS) loose image legacy pair `(8, 5)` coexists with snapshot pair `(8, 4)` while the stage requires `(8, 5)` → accepted `False`; no representation may select a different generation truth

## Entities

[Data: FileLoadRequest]
desc: F1 frozen UI-captured route context; product workers treat all referenced payloads as read-only and never resolve current session state themselves.

[Data: A2LAttachSnapshot]
in: A2LAttachSnapshot
desc: unchanged Inc2 dependency. Its expected_a2l_generation, expected_image_generation, enrichment_key, enriched_tags, summary_lines and picker_snapshots names match the concurrent Inc2 graph and are accepted by root I-ALP-2.2. The complete pair and all A2L payloads are consumed only after L1 preflight; the snapshot is authoritative, so legacy duplicate fields cannot select different content.

[Data: PreparedLoad]
in: PreparedLoad
desc: S1 changed data contract. Retain every existing field, default, positional order and the mutable legacy dataclass; append a2l_preparation after a2l_cache with type Optional[A2LAttachSnapshot] and default None. A type-checking-only import of A2LAttachSnapshot from file_load.py plus the existing deferred annotations avoids a runtime shared.py to file_load.py to shared.py cycle. The nested Inc2 snapshot is frozen and its payloads remain read-only; None preserves legacy non-prepared construction and is never product-worker evidence.

[Data: Session artifacts]
desc: current A2L path/data/cache, current file and both generation counters are read only during F2/F3 UI capture, never by the F1 product worker arm.

[I/O: case_06 A2L]
desc: committed 37742888-byte fixture whose E1 parser probe produced 220040 tags and zero parse errors; this fixture fact is not a load timing result.

[Data: Project request]
in: ProjectLoadRequest
desc: frozen admission data and UI-captured generations passed from P3 to P4

[Data: Prepared project candidate]
in: PreparedProjectLoad
desc: frozen prepared bundles, parsed project data and optional A2L-only snapshot passed from P4 to P5

[Data: Project session]
in: Project session state
desc: current A2L/image/MAC artifacts, both generations, project identity, prepared caches and picker mapping; P5 reads current generations before any write
sequence:
  pair_install: ProjectLoadMixin._install_prepared_project (!) → ProjectLoadMixin._reset_project_session → LoadedStateMixin._apply_prepared_load → ProjectLoadMixin._install_prepared_project wins → A2lViewMixin._refresh_a2l_dependent_views
  a2l_only_install: ProjectLoadMixin._install_prepared_project (!) → ProjectLoadMixin._reset_project_session → A2lViewMixin._replace_current_a2l → ProjectLoadMixin._install_prepared_project wins → A2lViewMixin._refresh_a2l_dependent_views

[Data: Project publication]
in: int
desc: common A2L-dependent-view publication count; reset and bundle stages publish zero and the single final publication precedes the successful outcome
sequence:
  pair_success: ProjectLoadMixin._reset_project_session → LoadedStateMixin._apply_prepared_load → A2lViewMixin._refresh_a2l_dependent_views wins → end_busy
  a2l_only_success: ProjectLoadMixin._reset_project_session → A2lViewMixin._replace_current_a2l → A2lViewMixin._refresh_a2l_dependent_views wins → end_busy

[Data: S19TuiApp._accepted_a2l_picker_snapshots]
in: Mapping[str, A2LPickerSnapshot]
desc: latest accepted Inc2 mapping, stored as MappingProxyType with independent check and patch entries. L1 replaces rather than merges it when S1 is present, before common refresh; stale candidates and keyless generation-only stages do not replace it. Existing adapter generation/signature/source invalidation remains unchanged.

[Data: Prepared load candidate]
in: current artifacts, generations, caches and project/session/widget state
desc: all candidate-side effects of L1 remain after the complete stage preflight. False means none of these candidate mutations occurred in L1; project-level pre-reset rejection is separately owned by P5.

[Data: A2L-dependent publication]
in: ordered F and OUTCOME observations
desc: L1 retains the optional existing common refresh only after accepted state and picker mapping installation. Project bundle stages pass publish_a2l=False so P5 alone performs the final publication before success.

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

ProjectLoadMixin._handle_load_project ──▶ [Data: Project request]
[Data: Project request] ──▶ ProjectLoadMixin._prepare_project_load
ProjectLoadMixin._prepare_project_load ──▶ [Data: Prepared project candidate]
[Data: Prepared project candidate] ──▶ ProjectLoadMixin._install_prepared_project
[Data: Project session] ──▶ ProjectLoadMixin._install_prepared_project
ProjectLoadMixin._install_prepared_project ──▶ [Data: Project session]
ProjectLoadMixin._install_prepared_project ──▶ [Data: Project publication]

[Data: PreparedLoad].a2l_view_generation ──▶ LoadedStateMixin._apply_prepared_load
[Data: PreparedLoad].a2l_image_generation ──▶ LoadedStateMixin._apply_prepared_load
[Data: PreparedLoad].a2l_preparation ──▶ LoadedStateMixin._apply_prepared_load
[Data: A2LAttachSnapshot] ──▶ LoadedStateMixin._apply_prepared_load
LoadedStateMixin._apply_prepared_load ──▶ [Data: S19TuiApp._accepted_a2l_picker_snapshots]
when: a complete legacy/snapshot generation preflight matched and prepared.a2l_preparation is not None
LoadedStateMixin._apply_prepared_load ──▶ [Data: Prepared load candidate]
when: every supplied generation representation is complete, mutually equal and equal to the live installation-stage pair
LoadedStateMixin._apply_prepared_load ──▶ [Data: A2L-dependent publication]
when: accepted is True and publish_a2l is True, after candidate and accepted-picker-mapping installation

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

finding E2-P-01 completed Inc2 layering is unavailable at the pinned E1 tree
anchor: ProjectLoadMixin._prepare_project_load
seen: the corrected Inc2 graph now exists and is lint-clean; this integration phase explicitly performs no product marks/extraction and claims no completed Inc2 product tree
cause: Inc3 has a sequential product dependency on Inc2 even though graph integration can now proceed
effect: graph contracts integrate, but product-layered extraction and runtime verdicts remain outside this phase
decision: CLOSED for E2 graph integration — consume the accepted Inc2 graph/root producer; any later product extraction must use a throwaway clone and rule its findings before E4

finding E2-P-02 project preflight must use current UI generations
anchor: ProjectLoadMixin._install_prepared_project
seen: EX-I3-048-F changes live image generation after the worker snapshot was captured, although the A2L-only candidate installs no image
cause: comparing only with request-captured generations would accept the old image expectation
effect: a captured-only check would violate whole-load stale rejection
decision: CLOSED — P5 derives every required stage pair from current UI counters at installation entry and checks all of them before reset; P1 captures values only for worker preparation

finding E2-P-03 same-path project generation wording needs a ruling
anchor: ProjectLoadMixin._install_prepared_project
seen: corrected REFRESH.047 and project B/C now distinguish changed-artifact generation from byte-identical unchanged content and permit writer/reset/reinstall generation movement
cause: project reload reinstalls the pair through reset and apply stages even when only one artifact's bytes changed
effect: B/C no longer imply an unchanged-artifact generation freeze and the stage matrix remains authoritative
decision: CLOSED — E1 D-6 applies root I-ALP-3; changed content gets a newer generation, unchanged bytes remain identical and stage reinstallation may increment generation

finding E2-P-04 project adaptation names and producer call signature remain proposals
anchor: ProjectLoadRequest
seen: root I-ALP-3 now pins captured_a2l_generation/captured_image_generation, P2 image/MAC unions and a2l_only; root I-ALP-2.2 pins the five keyword-only route-neutral producer inputs
cause: the E1 slice defined behavior and defaults while leaving exact adaptation details to E2
effect: incompatible request fields, synthetic LoadedFile/A2LAttachRequest and ambiguous A2L-only calls are excluded
decision: CLOSED — use the root P1/P2/S1 and producer names verbatim; PROP-I3-P-01/02 are accepted and this lane edits no root rule

finding E2-LS-1 keyless generation expectations bypass the baseline guard
anchor: LoadedStateMixin._apply_prepared_load
seen: static baseline loaded_state.py:589-599 and baseline.md L1 show preflight conditioned on a2l_enriched_key rather than on either expected generation; this is a disk observation, not an executed defect
cause: the baseline uses enrichment presence as a proxy for generation-bearing preparation, while Inc3 adds a keyless project image stage
effect: without the delta a stale generation-only image bundle could reach candidate installation without the required stage comparison
decision: CLOSED — trigger on a snapshot or either legacy generation, require complete coherent pairs, and keep rejection before the first candidate mutation; P5 rejects keyless image-stage mismatches before reset. D-10's synchronous UI invariant removes STAGE_RACE as unreachable and adds no rollback.

finding E2-LS-2 a runtime snapshot import would close a module cycle
anchor: PreparedLoad
seen: static imports at shared.py:13-30 and file_load.py:34-39 already include file_load.py importing PreparedLoad from shared.py
cause: importing A2LAttachSnapshot from file_load.py at shared.py runtime would make each module depend on the other during import
effect: a runtime import risks import failure and violates the no-cycle handoff requirement
decision: retain deferred annotations and import A2LAttachSnapshot only under TYPE_CHECKING; append the defaulted field after every existing field

finding E2-LS-3 A2L-only preparation does not traverse L1 or S1
anchor: LoadedStateMixin._apply_prepared_load
seen: E1-slice.md section 3 and static project_load.py:1618-1623 place A2L-only installation in P5 through the A2L writer with no current_file; no runtime route was executed
cause: an A2L-only project has no LoadedFile bundle for PreparedLoad to carry
effect: treating S1 as the A2L-only carrier or requiring L1 would fabricate phantom image state and violate REFRESH.042/.046
decision: keep P2.a2l_only and P5 as that route's carrier/installer; EX-I3-039-D, EX-I3-042-A and the P-ONLY stale arms are explicit L1 expect-none boundaries

finding E2-LS-4 Inc2 interface ruling and product extraction remain integration dependencies
anchor: A2LAttachSnapshot
seen: root I-ALP-2.2/I-ALP-2.3/I-ALP-3 now accept all six A7 consumer members, S1's optional carrier, coherent generation pairs and accepted-installation mapping rule; no product extraction is permitted in this integration phase
cause: the L+S proposals required conductor reconciliation, while product extraction requires an implemented Inc2 tree
effect: interface uncertainty is closed without claiming product-layered extraction or runtime success
decision: CLOSED for interface/design — adopt every accepted root rule verbatim; any later product extraction remains a throwaway-clone prerequisite, not work claimed here
