# Inc 3 baseline Code-Wire graph

Base `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c`; E0 tree `d658dfea` has identical product content. Every node below is baseline behavior, not the proposed delta. Marks are permitted only in the throwaway local clone used by the recorded extractor command.

## Nodes

FileLoadMixin.load_from_path
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.043
in: Path path
out: None
func: baseline admits/copies a loose file and starts the load worker without an explicit captured A2L/generation request
module: s19_app/tui/app/file_load.py
examples: (E1-baseline-F1) image path with attached A2L → worker starts with path and busy generation

FileLoadMixin._load_workarea_file
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.047
in: str name
out: None
func: baseline admits a workarea file and starts the same load worker without explicit captured A2L/generation context
module: s19_app/tui/app/file_load.py
examples: (E1-baseline-F2) workarea image name with attached A2L → worker starts in place

FileLoadMixin._parse_loaded_file
req: R-A2L-REFRESH.039, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: Path path; Optional[list[Path]] a2l_files = None; Optional[list[A2LCacheEntry]] a2l_cache_out = None
out: Optional[LoadedFile] result
func: baseline resolves A2L/current-file inputs by reading live app state and parses the data file
module: s19_app/tui/app/file_load.py
examples: (E1-baseline-F3) image path and no explicit A2L list → current A2L path/data/current file are read

FileLoadMixin._prepare_load_payload
req: R-A2L-REFRESH.039, R-A2L-REFRESH.040, R-A2L-REFRESH.041, R-A2L-REFRESH.043
in: LoadedFile loaded; Optional[int] a2l_view_generation = None; Optional[int] image_generation = None
out: PreparedLoad result
func: baseline directly enriches A2L and builds MAC/validation/render caches with predicted generation fields
module: s19_app/tui/app/file_load.py
examples: (E1-baseline-F4) loaded image+A2L and explicit expected generations → precomputed PreparedLoad

FileLoadMixin._start_load_worker
req: R-A2L-REFRESH.040, R-A2L-REFRESH.043, R-A2L-REFRESH.044, R-A2L-REFRESH.048
in: Path path; Optional[list[Path]] a2l_files = None; int gen; bool sync_project = True
out: None
func: baseline parses and prepares off thread, reads live generations, falls back to a minimal bundle on preparation failure, then dispatches completion
module: s19_app/tui/app/file_load.py
examples: (E1-baseline-F5) worker preparation raises → non-precomputed PreparedLoad falls back

ProjectLoadMixin._handle_load_project
req: R-A2L-REFRESH.039, R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043
in: Optional[str] name; bool routed = False
out: None
func: baseline admits a project and creates a frozen request without captured post-install generation expectations
module: s19_app/tui/app/project_load.py
examples: (E1-baseline-P1) admitted project pair → ProjectLoadRequest starts one worker

ProjectLoadMixin._prepare_project_load
req: R-A2L-REFRESH.039, R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043
in: ProjectLoadRequest request
out: PreparedProjectLoad result
func: baseline parses project A2L/image/MAC off thread but never prepares a load payload or A2L enrichment snapshot
module: s19_app/tui/app/project_load.py
examples: (E1-baseline-P2) project pair request → parsed image/MAC and no prepared payload

ProjectLoadMixin._install_prepared_project
req: R-A2L-REFRESH.041, R-A2L-REFRESH.042, R-A2L-REFRESH.043, R-A2L-REFRESH.045, R-A2L-REFRESH.046, R-A2L-REFRESH.048
in: PreparedProjectLoad prepared
out: None
func: baseline wraps parsed image/MAC in non-precomputed bundles, resets, installs without intermediate common publication, then publishes once
module: s19_app/tui/app/project_load.py
examples: (E1-baseline-P3) parsed project image+MAC+A2L → two minimal PreparedLoad bundles and one final publication

ProjectLoadMixin._reset_project_session
req: R-A2L-REFRESH.045, R-A2L-REFRESH.046, R-A2L-REFRESH.048
in: (none)
out: None
func: baseline clears outgoing project state through the single A2L writer, incrementing A2L generation without common publication
module: s19_app/tui/app/project_load.py
examples: (E1-baseline-P4) outgoing A2L generation A → reset clears path/data and reaches A+1

LoadedStateMixin._apply_prepared_load
req: R-A2L-REFRESH.044, R-A2L-REFRESH.045, R-A2L-REFRESH.048
in: PreparedLoad prepared; Path path; float load_started; bool publish_a2l = True
out: bool accepted
func: baseline preflights only a non-None A2L enrichment key before installation and optionally publishes once
module: s19_app/tui/app/loaded_state.py
examples: (E1-baseline-L1) stale keyed snapshot → False before current-file mutation; keyless generation-only bundle → no preflight

A2lViewMixin._replace_current_a2l
req: R-A2L-REFRESH.039, R-A2L-REFRESH.046, R-A2L-REFRESH.047, R-A2L-REFRESH.048
in: Optional[Path] a2l_path; Optional[dict] a2l_data
out: None
func: baseline sole writer replaces current A2L path/data, increments A2L generation and invalidates derived caches without publishing
module: s19_app/tui/app/a2l_view.py
examples: (E1-baseline-C1) changed content at the same path → path/data replaced and generation strictly increases

enrich_tags_and_render
req: R-A2L-REFRESH.039
in: Optional[dict] a2l_data; Optional[dict[int, int]] mem_map; int max_tag_lines = 500
out: tuple[list[dict[str, Any]], list[str]] result
func: baseline canonical service builds enriched tags and summary lines; Inc 3 must reach it only through Inc 2's producer
module: s19_app/tui/services/a2l_service.py
examples: (E1-baseline-C2) parsed OLD A2L and image map → OLD enriched rows and summary
