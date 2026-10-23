# Code-Wire graph F5: project save → load → re-save (data audit, reverse)

> Format B, Code-Wire v2.6. Reverse direction from `s19_app` `9793fcd`. Node name = code qualname.
> Thread T5: `cwaudit/test_t5_project.py`. Recordings: `trace-t5.json` (T5a: project `P` from `case_01` S19 + MAC + A2L, a declared region `cal 0x80000000..0x80000010`, second save with a batch, load in a fresh app, default re-save) and `trace-t5b.json` (T5b: project `Q` from `case_01` S19 only, save with batch + assignment, load, default re-save). The handlers are driven headless with the payload that `SaveProjectScreen` yields: its SelectionLists start unselected (`screens.py:572-590`), so a re-save with no change gives `batch=()`, `assignments={}`.
> The project round-trip investigation (P-H-1..5, P-M-1..7) covers the file copies and the session leaks. This graph adds the manifest fields and the re-save.

## Nodes

S19TuiApp._handle_save_dialog
req: R-TUI-012, R-PROJ-001, LLR-005.1, LLR-017.2, LLR-017.3, LLR-015.3
in: S19TuiApp self; SaveProjectPayload? payload
out: None
func: validates the target folder, refuses when the folder already holds an A2L and an A2L is loaded, copies the loaded files, then writes and verifies `project.json` from the payload
module: s19_app/tui/app.py
modify: [I/O: project folder] (replace); [I/O: project.json] (replace)
inner: copy_into_workarea, write_project_manifest
examples: (T5, t5a) payload {project_name "P", batch ["patch.json"], assignments {firmware ["patch.json"]}} into P that holds firmware.a2l → None; the status line says the project already has an A2L file; project.json keeps batch [] (C16 cannot see a status line or an entity write)
examples: (T5b, t5b) payload {project_name "Q", batch [], assignments {}} after Load project Q → None; project.json batch [] (it held patch.json)

write_project_manifest
req: R-MAN-SER-001, LLR-017.2, HLR-027
in: ProjectVariantSet variant_set; Path project_dir; Sequence[str] batch = (); Mapping[str, Sequence[str]]? assignments = None; Sequence[DeclaredRegion] declared_regions = (); Mapping[str, Sequence[str]]? gathered = None
out: tuple(Path? path, list[ValidationIssue] issues)
func: serialises the manifest envelope and writes it atomically
module: s19_app/tui/services/manifest_writer.py
modify: [I/O: project.json] (replace)
examples: (T5b, t5b) variant_set {project_name "Q", variant_id "firmware"} → path ".../workarea/Q/project.json", issues []

read_project_manifest
req: R-VAR-002, LLR-017.4
in: Path project_dir
out: ProjectManifest manifest {active_variant, batch, assignments, declared_regions, issues}
func: reads `project.json`, resolves the batch and assignment entries, collects issues
module: s19_app/tui/services/variant_execution_service.py
examples: (T5b, t5b) project_dir ".../workarea/Q" after the batch save → manifest {active_variant "firmware", batch [".../workarea/Q/patch.json"]}
examples: (T5, t5a) project_dir ".../workarea/P" → manifest {declared_regions [{name "cal", start `2147483648`, end `2147483664`}], issues []}

S19TuiApp._handle_load_project
req: R-TUI-013, R-RPT-REGION-PERSIST-002, R-PROJ-002
in: S19TuiApp self; str? name
out: None
func: lists the project files, reads the manifest, keeps `declared_regions` and `active_variant`, then loads the first data file, the first MAC and the first A2L
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_file] (replace); [Data: S19TuiApp._declared_regions] (replace)
inner: read_project_manifest
examples: (T5b, t5b) name "Q" → None; the manifest batch is read and not kept in the session
examples: (T5, t5a) name "P" → None; the declared region named cal comes back (read from the session after the call)

## Entities

[I/O: project folder]
in: bytes
desc: `<workarea>/<name>/` with copies of the loaded files

[I/O: project.json]
in: str
desc: the manifest: schema_version, active_variant, batch, assignments, declared_regions, gathered

[Data: S19TuiApp.current_file]
in: LoadedFile?
desc: the in-memory image; Save project copies its `path`, not its `mem_map` (P-H-1)

[Data: S19TuiApp._declared_regions]
in: tuple[DeclaredRegion, ...]
desc: the declared regions of the session; saved and restored

## Edges

[Data: S19TuiApp.current_file] ──▶ S19TuiApp._handle_save_dialog
S19TuiApp._handle_save_dialog ──▶ write_project_manifest.batch
S19TuiApp._handle_save_dialog ──▶ write_project_manifest.assignments
[Data: S19TuiApp._declared_regions] ──▶ write_project_manifest.declared_regions
write_project_manifest ──▶ [I/O: project.json]
[I/O: project.json] ──▶ read_project_manifest.project_dir
read_project_manifest.manifest ──▶ S19TuiApp._handle_load_project
S19TuiApp._handle_load_project ──▶ [Data: S19TuiApp._declared_regions]

## Boundary

[Outside: SaveProjectScreen] ──▶ S19TuiApp._handle_save_dialog.payload
[Outside: LoadProjectScreen] ──▶ S19TuiApp._handle_load_project.name
discarded: write_project_manifest.path — the verify step re-reads the file

## Findings

CW-D-13
anchor: S19TuiApp._handle_save_dialog
what: a re-save into a project folder that holds an A2L is refused whenever an A2L is loaded, even the same A2L. After Load project the A2L is always loaded, so no project with an A2L can be saved again. The MAC check compares names; the A2L check does not
evidence: T5 t5a second save → status «Project already has an A2L file.»; project.json batch stays []; the folder was created before the check (`app.py:7918` mkdir, `:7936` refusal)
consequence: the per-variant assignment UI (LLR-017.3, "re-saved existing multi-variant project") can never persist for a project with an A2L; a patched image cannot be saved back into its project through Save project. The status is honest (a refusal), but it blocks a specified flow. Req ↔ code mismatch

CW-D-14
anchor: read_project_manifest.manifest ──▶ S19TuiApp._handle_load_project
what: Load project reads `batch` and `assignments` and drops them. The Save dialog does not pre-select them. A default re-save writes them empty and reports success
evidence: T5b: save → batch ["patch.json"]; load read → batch [".../Q/patch.json"]; re-save → project.json batch [], assignments {}; status "Project saved + manifest verified"
consequence: the variant-execution plan of the project (LLR-017.4 consumer) is lost on any re-save. LLR-017.3 specifies "empty fields ⇒ batch==[]", so the requirement allows it; no requirement says a re-save keeps the composition

CW-D-15
anchor: [Data: S19TuiApp._declared_regions]
what: the declared regions round-trip (clean)
evidence: T5 t5a declared_regions [{name "cal", start 2147483648, end 2147483664}] after load
consequence: closes the "not probed" row of the round-trip investigation (§5)
