# s19_app — Architecture

**Audience:** a technical contributor about to read or change code.
**Purpose:** describe the three-layer architecture, the Direction B TUI shell, the `changes/` and `operations/` data-processing packages, the Patch Editor flow, the path-safety and JSON safety contracts, the engine layer, the testing architecture, and the dev-flow process that built it.

For point-in-time per-batch detail (decisions, test verdicts, post-mortems), follow the per-batch cross-references in [overview.md](./overview.md) §7.

---

## 1. Three-layer architecture

`s19_app` has three layers. They should be modified together when behaviour crosses boundaries; otherwise they stay independent.

| Layer | Modules | Role |
|---|---|---|
| **1 — Parsers** | `s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/tui/a2l.py` (+ `a2l_*` facades), `s19_app/tui/mac.py` | parse one artefact each into a sparse memory map / structured records; **collect** validation failures per record and per file rather than aborting |
| **2 — Range / validation engine** | `s19_app/range_index.py`, `s19_app/validation/engine.py`, `s19_app/validation/rules.py`, `s19_app/validation/model.py`, `s19_app/tui/color_policy.py` | binary-search range membership; cross-artefact rule evaluation; `ValidationIssue` / `ValidationSeverity` / `CoverageMetrics` model; severity → CSS class single source of truth |
| **3 — TUI services + view** | `s19_app/tui/services/*` (orchestration seam), `s19_app/tui/changes/*` + `s19_app/tui/operations/*` (data-processing packages), `s19_app/tui/screens_directionb.py`, `s19_app/tui/app.py` (orchestration only) | service-mediated calls into the engine; pure-Python data-processing of change-sets, checks, CRC algorithms and flows; Textual view layer |

**The rule.** Behaviour that crosses a layer boundary is modified in the same commit. Engine modules (layers 1 and 2) stay **read-only consumers** for view-layer / change-set work — the feature batches that built the TUI shell and the Patch Editor treated them as frozen (see §7).

The CLI (`s19_app/cli.py`) is a separate, simpler consumer: it reaches the parsers directly and does not use the TUI services.

## 2. Direction B TUI shell

The TUI uses the **Direction B (Rail + Command)** layout introduced by batch `2026-05-20-batch-02`. Two persistent navigation surfaces are mounted on every screen:

- **Activity rail (left).** Exactly twelve ordered items — keys `1`–`0` plus two non-digit bindings, `=` (Check Editor) and `]` (Flow Execution), both `show=False` (batch-94's R-1 closure; probe evidence `.dev-flow/2026-10-12-batch-94/evidence/pdr_rail_key_probe.txt` + `.dev-flow/2026-10-12-batch-94/evidence/inc003_rail12_probe.txt`) — with exactly one active marker, glyph + per-item ASCII fallback. Rail items toggle twelve sibling screen containers via the `.hidden` CSS class (not a `push_screen` stack), so the rail and command bar stay persistently mounted.
- **Command bar (top).** Searchable command palette (`Ctrl+K`), find input (`/` → routes to `find_string_in_mem`), go-to-address input (`g` → routes to `_handle_goto`), plus the project-name / A2L-filename status labels.

### The twelve rail screens

| Key | Container id | Screen | Status |
|---|---|---|---|
| 1 | `#screen_workspace` | Workspace (3-pane: ranges/sections · hex · context) | functional; hosts the Loaded-artifacts panel with per-artifact unload |
| 2 | `#screen_a2l` | A2L Explorer (symbol table + hex pane) | functional; enriched tags, 19-field filter, windowed rendering |
| 3 | `#screen_mac` | MAC View (record table + hex pane) | functional; per-row status, malformed lines flagged not dropped |
| 4 | `#screen_map` | Memory Map | functional — real coverage from `LoadedFile.ranges` plus entropy bands from `services/entropy_service.py` |
| 5 | `#screen_issues` | Issues Report | functional — grouped, filterable, paged view of the validation engine's findings; each issue is shown under its own severity, ERROR then WARNING then INFO across pages (batch-101 Inc 11 removed the batch-94 view-level triage of standard A2L blocks to INFO) |
| 6 | `#screen_patch` | Patch Editor | **functional** — change-set rows, validate/check, save/load v2 JSON, apply + patched-image emit, undo/redo |
| = | `#screen_check_editor` | Check Editor | **functional** (batch-94 Inc-001) — write/validate `.chk.json` check specs, struck-APPLY no-apply doctrine |
| 7 | `#screen_diff` | A↔B Diff | **functional** — second-image load, classified diff runs, Markdown/HTML report |
| 8 | `#screen_flow` | Flow Builder | **functional** — fb_a palette/canvas block builder with typed cables, template save/load (moved to `flow_screens.py`, batch-94 Inc-002) |
| ] | `#screen_flow_execution` | Flow Execution | **functional** (batch-94 Inc-003) — per-chain lanes, input rebinding, sequential(default)/parallel runs, chain-set save/load |
| 9 | `#screen_checks` | Checks | functional — read-only grouped-by-outcome mirror of the last check run |
| 0 | `#screen_crc_designer` | CRC Designer | functional — parametric CRC form, preset catalogue, live known-answer verdict, `*.crc.json` templates |

Modal screens complement the rail (load file, save/load project, variant select/help, change-set and entry JSON editors, flow save/load, confirm-discard, confirm-write, legend, report viewer, operations). The batch-02 **Bookmarks** screen no longer exists — the rail's last three slots are Flow Execution, Checks and CRC Designer (Check Editor on `=`, Flow Execution on `]`, both `show=False`).

### Two-regime responsive layout

One layout, width-responsive, governed by a 120-column terminal breakpoint:

- **Fixed regime — width ≥ 120 columns.** Rail full fixed width; Workspace `left 22 · right 40 · center 1fr`; MAC `hex 40 · table 1fr`.
- **Proportional regime — width < 120 columns.** Rail collapses to icon-only (~4 cols); Workspace `left 24% · right 30% · center 1fr`; MAC `hex 35% · table 1fr`.

Layout integrity is guarded by the `pytest-textual-snapshot` SVG baseline matrix (29 baselines) plus 119/120 boundary tests. The A2L Explorer panes are the **exception** — flat 3/7 hex ÷ 4/7 tags at all widths (the iteration-3 two-regime A2L split rendered the hex view too narrowly at ≥ 120 cols and was superseded; see `R-TUI-037`).

## 3. The `changes/` and `operations/` packages

`s19_app/tui/changes/` and `s19_app/tui/operations/` are the **data-processing layer**. They are **pure Python** — stdlib plus the engine and workspace helpers, but **never `textual`** — so every module is unit-testable without an app instance.

*Historic:* batches 03–04 put this layer in `s19_app/tui/cdfx/` (a CDF 2.0 `.cdfx` reader/writer plus the v1 "unified change-set" JSON). That package is **deleted**; the v2 change-set JSON + patched-image emit below is the shipped replacement, and the v1 envelope is rejected by the v2 reader (`CHG-V1-FORMAT`).

### `tui/changes/` — the v2 change-set engine (`s19app-changeset`, version `2.0`)

| Module | Purpose |
|---|---|
| `model.py` | the pure-data half: `ChangeEntry` (address-keyed, `encoded_bytes` as an immutable tuple) composed into a kind-discriminated `ChangeDocument` (`"change"` / `"check"`). |
| `validate.py` | the intra-document collision rule — every entry's target byte range checked against its siblings. |
| `io.py` | the wire grammar: strict reader/writer for the v2 JSON (`FORMAT_ID = "s19app-changeset"`, `FORMAT_VERSION = "2.0"`); v1 detection runs before generic format validation and yields exactly one `CHG-V1-FORMAT` with zero entries; collect-don't-abort `CHG-*` findings. Also the emitters `emit_s19_from_mem_map` / `emit_intel_hex_from_mem_map` that serialise a memory map back to records. |
| `display.py` | change-entry value display (hex primary, companions) — display never mutates stored bytes. |
| `apply.py` | the apply engine: `classify_containment` stamps each entry against the loaded image's ranges; `apply_change_document` gates on any ERROR issue or `kind != "change"` (zero writes, all dispositions `blocked`) and produces a deterministic `ChangeSummary`; `save_patched_image` emits the patched `.s19` / `.hex` through the staged-containment write path. |
| `check.py` | the check engine — re-verifies a `kind="check"` document's expectations against the image; one `CheckRunEntry` per entry. |
| `verify.py` | verify-on-save: re-reads a just-written image with the matching parser and diffs the re-read memory map against intent. |

### `tui/operations/` — the operation registry and the CRC family

| Module | Purpose |
|---|---|
| `registry.py` | static, deterministic operation registry (`crc`, `extract`, `split_by_segment`) — no entry points, no reflection. |
| `crc.py` | the legacy CRC-32 streaming operation (`crc32_stream`), 32-bit-only. |
| `crc_kernel.py` | the width-general parametric (Rocksoft) CRC kernel — any width in 8..64, independent input/output reflection, with the `PRESETS` catalogue; the seed algorithm reproduces `crc32_stream` / `zlib.crc32` byte-for-byte. |
| `crc_designer_model.py` | the CRC Designer's model: `*.crc.json` algorithm-template load/save with the collect-don't-abort loader posture, plus the serialization (output address, store width/endianness) fields. |
| `crc_template.py` | thin re-export facade over `crc_designer_model` (the a2l-facade convention). |
| `crc_config.py` | the evolved per-firmware CRC job config (algorithm ref + coverage + placement). |

**Dependency direction (strict).** The `changes/` model is a leaf; `validate` / `display` depend on it; `io` reads and writes it; `apply` / `check` consume documents plus read-only `LoadedFile` snapshots; `verify` consumes the emitted image. `operations/` is independent of `changes/`; the Flow Builder (`services/flow_model.py` + `flow_execution_service.py`) threads a working `(mem_map, ranges)` pair through both.

## 4. Patch Editor flow

The Patch Editor demonstrates the orchestration contract end-to-end:

```
PatchEditorPanel  ───emits───►  ActionRequested message
                                       │
                                       ▼
                          tui/app.py — Patch Editor handler
                                       │  (routing wiring only —
                                       │   no json parsing, no model logic)
                                       ▼
                  tui/services/change_service.py — ChangeService
                                       │  (owns the ChangeDocument;
                                       │   add/edit/remove, undo/redo,
                                       │   validate / run_checks /
                                       │   apply / save_patched)
                                       ▼
                       s19_app/tui/changes/* (the package)
                                       │
                                       ▼
              PatchEditorPanel refreshes its rows / status
```

The screen is **presentational**; `app.py` carries only the UI-state wiring that routes the message to `ChangeService`. The JSON and memory-map model logic lives in the `changes/` package, never in `app.py`. The same pattern repeats for the other layer-3 consumers: the Flow Builder routes through `services/flow_execution_service.py`, variant-scoped runs through `services/variant_execution_service.py`, and the A↔B Diff through `services/compare_service.py` + `diff_report_service.py`.

## 5. Path-safety contract

Every file write resolves under `.s19tool/workarea/` through `s19_app/tui/workspace.py`. The contract is enforced at the function boundary, not by convention:

- **Writes** go through `copy_into_workarea` — symbolic-link / NTFS reparse-point traversal is **rejected** (`_path_traverses_reparse_point`); an existing filename is **dedup-suffixed**; the resolved target must be inside `.s19tool/workarea/`. The patched-image writer (`changes/apply.py::save_patched_image`), the change-set JSON writer (`changes/io.py`) and the project-manifest writer (`services/manifest_writer.py`) all share this staged-containment pattern: stage under `.s19tool/workarea/temp/`, re-run the containment checks against the destination, then place.
- **Reads** of a user-supplied path go through `resolve_input_path` (the loader path that walks the app cwd and the nearest repo root). The change-set reader, the CRC template loader and the manifest reader use it — with one deliberate exception: `project.json` `batch` / `assignments` entries resolve **against the project directory only** (an absolute or escaping path is one ERROR finding and the entry is skipped).
- **Failures are surfaced, never raised.** A containment failure, reparse-point rejection, overwrite refusal or path-resolution failure becomes a `ValidationIssue` (the `CHG-*` family for change-sets), not an uncaught exception.

## 6. JSON safety

The change-set reader (`changes/io.py`) treats its input as **untrusted**, stdlib `json` only — no new dependency:

- `json.JSONDecodeError` and `RecursionError` are both caught and surfaced as findings — a deeply-nested input that would exceed the recursion limit is not allowed to crash the load.
- The shared 256 MB on-disk size cap is probed **before** parsing.
- A structural-shape check runs **before any field indexing** — no `KeyError` escapes.
- **v1 hard break:** a document carrying the retired `s19app-unified-changeset` token (or the v1 `parameters`/`memory` shape) is detected before generic format validation and yields exactly one `CHG-V1-FORMAT` finding with zero entries — there is no read-compat shim.
- Unrecognised `format` / `kind` / `version` values and per-entry faults collect their own `CHG-*` findings; the reader never raises on malformed input.

*Historic:* the batch-03 CDFX XML reader applied the same posture to XML (DOCTYPE / entity rejection before expansion, 256 MB cap, nesting bound). It was removed with the `cdfx/` package.

## 7. Engine layer stability

The parsing / validation engine remains the read-only foundation that layer-3 work consumes but does not modify:

- `s19_app/core.py`
- `s19_app/hexfile.py`
- `s19_app/range_index.py`
- `s19_app/validation/` (entire directory)
- `s19_app/tui/a2l.py`
- `s19_app/tui/mac.py`
- `s19_app/tui/color_policy.py` — **frozen from `2026-10-11-batch-92`** (operator-confirmed 2026-10-11, US-92-5 OUT): the batch's premise freezes it even though it is absent from the older frozen **test-file** lists (the retired pinning tests of the historic mechanism below covered only the six entries above); the severity→CSS policy (`css_class_for_severity`) stays here.

*Historic mechanism:* across batches 02–04 this was pinned by line-ending-normalised SHA-256 comparisons (`tests/test_cdfx_unchanged.py`, TC-027) and a writer-freeze test (TC-030); those pinning tests were retired together with the `cdfx/` package they protected. The discipline stands: adding behaviour that needs to cross into one of those modules is allowed, but it changes the engine's stability story and must be called out in the batch's requirements phase.

## 8. Testing architecture

The test suite under `tests/` is organised by module — `tests/test_core_*`, `tests/test_hexfile.py`, `tests/test_range_index.py`, `tests/test_validation_*`, `tests/test_tui_*`, `tests/test_changes_*`, `tests/test_crc_*`, `tests/test_flow_*`, `tests/test_entropy_*`, `tests/test_compare*`, `tests/test_manifest*`, `tests/test_variant*`, plus the per-example smoke suites (`tests/test_examples_*`). A registry guard (`tests/test_id_registry.py`) keeps every declared requirement/test id traceable to its verifier node.

Markers (registered in `pyproject.toml`):

- **`slow`** — stress / perf smoke tests. `pytest -q -m "not slow"` skips them. No example smoke case is currently pinned `@pytest.mark.slow`: the former ~490s `pv__case_06_large_nested_a2l` duplicate was pruned in batch-36 (US-060), and the large-A2L pipeline is now covered by the retained 36 MB top-level `case_06_large_nested_a2l` in the normal suite.
- **`snapshot`** — `pytest-textual-snapshot` baselines.

Visual regression: 29 SVG baselines under `tests/__snapshots__/`, generated only against the public synthetic fixtures (`examples/case_00_public/` and the `tests/conftest.py` generators) — **never against client firmware, A2L or MAC artefacts** (`R-TUI-034`, the TC-031 no-leak inspection).

Per-case Pilot / GIF evidence lives under `tests/test_examples_*`.

`pytest-textual-snapshot` is declared under `[project.optional-dependencies]` in `pyproject.toml` (dev-only); the runtime dependency set (`rich`, `textual`) is unchanged (`R-TUI-032`).

## 9. The dev-flow process that built it

Every feature batch follows GRNDIA's six-phase V-model dev-flow:

1. **Requirements** — user stories, HLR, LLR, TC plan, constraints.
2. **Cross-agent review** — architect / qa / security pass over the plan; findings closed before any code is written.
3. **Implementation** — supervised increments capped at ≤ 4 source files, each closed by a review packet.
4. **Validation** — per-TC verdict register; suite + boundary + security checks; verdict `pass` / `pass-with-gaps` / `fail`.
5. **Post-mortem** — what worked, what didn't, follow-up batches scoped.
6. **Docs** — executive summary, functionality orientation, traceability matrix, architecture diagrams.

Per-batch artefacts are archived under `.dev-flow/<YYYY-MM-DD>-batch-NN/`. The repo-root [REQUIREMENTS.md](../REQUIREMENTS.md) holds the strict EARS requirement rows (`| Id | Form | Requirement |`) per module S0–S17 and absorbs each batch's stable requirements. The rationale is in [requirements/review/](./requirements/review/), the earlier canon in [requirements/history/](./requirements/history/). Ids are kept stable; test ids live in `AT-TC-REGISTRY.jsonl`, not in the canon.

## 10. Composition — the modules, by path

**The `Paths it owns` column is the mechanical part.** It is what makes this a map and not an essay:
any touched file is classified by path prefix, so the A-family triggers can be evaluated by a script.
Measured 2026-08-24 over `git ls-files` — **266 tracked source files** (`.py`), every one classified
below except the single exception named after the table.

| Module | Paths it owns | What it encapsulates | What it EXPOSES | What does NOT belong to it |
|---|---|---|---|---|
| **product** | `s19_app/**` | the shipped application: the Direction-B TUI shell and its sub-packages (`tui/changes`, `tui/operations`, `tui/services`), plus `validation/` — all described in §1–§7; the batch-92 `render/` sub-package is declared at file granularity in the sub-module declarations below | the TUI entry point, `ChangeService`, the `changes` package API | test scaffolding · throwaway prototypes · flow tooling |
| **tests** | `tests/**` | the whole verification surface: unit, acceptance, snapshot baselines (`__snapshots__/`), goldens (`goldens/`), generated evidence (`_artifacts/`, gitignored) | nothing — it is a consumer, never a dependency of the product | product logic that drifted into a fixture |
| **tools** | `tools/**` | repository-local developer utilities | command-line entry points | anything the shipped app imports at runtime |
| **flow** | `.dev-flow/**` | the batch record and its local tooling; `_derived/` is DERIVED and guarded by V20 | the batch artifacts, cited by id | product or test code |
| **docs** | `docs/**` | this map and the orientation notes | the map itself, read as an oracle by the A-family triggers | code with behaviour |

**The one file no module can own, and why that is a finding rather than an omission.** `setup.py`
sits at the repository root. The staleness check extracts prefixes matching `` `path/**` `` and tests
`file.startswith(prefix + "/")`, so **a root-level file is unclassifiable by construction** — no
declarable prefix can ever match it. It is named here so the resulting notice reads as *known and
bounded* rather than as a stale map. **Registered as flow input for batch-88**: the rule should
either admit a root sentinel or state that root files are out of its scope; silently reporting them
as orphans conflates *"the map is stale"* with *"the rule cannot express this"*.

**Rationale for the five-module cut.**

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| 1 | Five **top-level, non-overlapping** prefixes | Declaring `s19_app/tui/changes/**` and friends as separate modules | Overlapping prefixes are a defect of this document, not an ambiguity to resolve case by case — and the sub-packages are already described in §1–§3. Re-open if a sub-package acquires an independently-consumed interface. |
| 2 | `tests/**` is one module, not one per layer | Mirroring the product's layering | Nothing reads the split mechanically today. Re-open when a lane plan needs test file sets to be disjoint by layer. |

### Sub-modules inside product

The three sub-modules inside `s19_app/**` are declared at file granularity; the facts below are the
standing map and each holds on the tree.

| Sub-module | Encapsulates | Exposes | Must not import |
|---|---|---|---|
| `s19_app/render/hexview.py` | the pure hex-window renderer: hex/ASCII rendering of a memory map, in-memory string search, and the memory-map builders | `render_hex_view`, `render_hex_view_text`, `build_mem_map_s19`, `build_range_validity_s19`, `build_range_validity_hex`, `build_row_bases`, `find_string_in_mem`; constants `HEX_WIDTH`, `MAX_HEX_ROWS`, `MAX_HEX_BYTES`, `FOCUS_CONTEXT_ROWS`, `SEARCH_ENCODING` | `s19_app.tui` modules — it imports `rich.text`, `..core`, `..hexfile`, `..range_index` and `.format` |
| `s19_app/render/format.py` | presentation-neutral formatting primitives: the `microbar` gauge and the pure style constants | `microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE` | `s19_app.tui` modules — it imports `rich.text` only |
| `s19_app/tui/flow_screens.py` | the flow surfaces: `FlowBuilderPanel` and `FlowExecutionPanel` with their message types | the two panel classes and their message types, consumed by `tui/app.py` and `tui/screens.py` | `not declared` |

## 11. Interfaces — the contracts between modules

**Changing one of these is trigger A3** — it fires ARQ, PDR *and* DDR, and it is never done inside a
lane. A **frozen** interface is one the current batch committed to at PDR: no lane touches it; the
work returns to the trunk instead. Every row below is a declared contract between modules — a
surface, a message family, a persisted file shape or an invariant. A later contract is added as a
row of this one table, never as a new table.

| Interface | Owner module | Consumers | Shape | Frozen? |
|---|---|---|---|---|
| `loaded_panel` — Part B contract | product | 18 declared consumers | 6 outputs; `PARENT : screen_workspace` | no |
| `screen_workspace` — Part B contract | product | 94 declared consumers | 31 outputs; `PARENT : workspace_body` | no |
| `workspace_body` — Part B contract | product | 139 declared consumers | 42 outputs; `PARENT : workspace_shell` | no |
| `render.hexview` surface | `s19_app/render/hexview.py` | views and report services | the renderer functions and constants of §10, consumed as plain data (`Text`/`str`) | no |
| `render.format` surface | `s19_app/render/format.py` | services and views | `microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE` | no |
| `utils.safe_text` contract | `s19_app/utils.py` | `checks_view`, `issues_view`, the flow surfaces | security contract — deletes every C0/DEL/C1 codepoint and wraps the remainder as a literal `Text`, never `Text.from_markup` | no |
| `tui/__init__` re-export surface | `s19_app/tui/__init__.py` | view and service importers | the range_index wrappers are removed; the renderer names stay, repointed to `render.hexview` | no |
| `PatchEditorPanel.ActionRequested` contract | `s19_app/tui/screens_directionb.py` | `app.py`, `screens.py` | the message family the panel emits (edit-json requests, entry edit-json); the variant request retired with the variant selector | no |
| `.chk.json` artifact contract | `s19_app/tui/changes/io.py` | the A2B Diff report builder | saved file | no |
| `flow_screens` module surface | `s19_app/tui/flow_screens.py` | `app.py`, `screens.py` | the two panel classes and their message types | no |
| flow template / chain-set artifacts | `s19_app/tui/services/flow_*` | the flow surfaces and report services | saved file | no |
| rail invariant | `s19_app/tui/app.py` | the rail census tests | twelve ordered rail surfaces — keys `1`–`0` plus `=` (Check Editor) and `]` (Flow Execution, both `show=False`) | no |
| `B97-I-1` chip families | `s19_app/tui/services/folder_open_service.py`, `s19_app/tui/open_folder_chip.py` | `open_folder_chip.py`, `app.py`, `screens.py` | six chip families with `no_project_reason(family)`, `chip_family_root(project_dir, base_dir)`, `is_openable_chip_dir(target, root)`; `OpenFolderChip(family, *, id_suffix=None)` | no |
| `B97-I-2` / `B97-I-3` `PatchEditorPanel.refresh_entries` | `s19_app/tui/screens_directionb.py` | `app.py`, the panel's own calls | `refresh_entries(rows, mem_map=_UNSET, document=_UNSET)`; `document: PatchDocumentView` feeds the ribbon identity and the JSON tab | no |
| `B97-I-4` `window_help.SHIPPED_WINDOW_KEYS` | `s19_app/tui/window_help.py` | `tests/test_window_usage_help.py`, the `WindowHelpChip` sites | the shipped window keys, including `check_editor` and `flow_execution` | no |
| `B97-I-5` tokens | `s19_app/tui/insight_style.py` | `flow_screens.py`, `styles.tcss` | `WAITING_HUMAN`, `CRC_FAMILY` plus their TCSS mirrors | no |
| `B97-I-6` NUL refusal | `s19_app/tui/services/flow_persistence_service.py`, `s19_app/tui/services/flow_execution_service.py`, `s19_app/tui/services/variant_execution_service.py` | `app.py` load / import / run handlers | the refusal shapes `FLOW-UNSAFE-REF` / `CHAIN-SET-UNSAFE-REF` / `MANIFEST-PATH-ESCAPE` | no |
| `B97-I-7` `FlowExecutionPanel` surface | `s19_app/tui/flow_screens.py` | `app.py` | `ModeToggle`, `confirm_attention()`, `confirmed_blocks(lane_index)`, `render_confirm_error(lane_index, line)`; the panel owns the attention state | no |
| `B97-I-8` `FlowBuilderPanel.RunRequested` | `s19_app/tui/flow_screens.py` | `app.py` | always `FLOW_SCOPE_SINGLE`; the message shape is unchanged | no |
| `B97-I-9` the D12 names | `s19_app/tui/flow_screens.py`, `s19_app/tui/window_help.py` | the batch TCs/ATs and the `window_help` bodies | the ids, classes, constants and vocabularies of D12 | no |
| `B97-I-10` the window-key table | `s19_app/tui/window_help.py` | `KeyBar`, `WindowHelpScreen`, `tests/test_b97_key_bar.py` | `KeyEntry`, `GLOBAL_KEYS`, `WINDOW_KEYS` / `WINDOW_GO_KEYS` over the 13 windows, `KeyToken`, `resolve_window_tokens(app, window)` | no |
| `B97-I-11` `S19TuiApp.check_action` | `s19_app/tui/app.py` | the `KeyBar`, `styles.tcss` | `confirm_attention` → `flow_execution`; `page_next_context` / `page_prev_context` → `a2l`/`mac`; `hex_page_prev` / `hex_page_next` → `workspace`; the `KeyBar` replaces `Footer` | no |
| `B99-I1` the S19 memory-map contract | `s19_app/core.py`, `s19_app/render/hexview.py` | `load_service`, `flow_execution_service`, `variant_execution_service`, `compare_service`, `before_after_service`, `change_service`, `changes/verify.py`, `tui/__init__.py`, `cli.py` | every address in the map, the ranges, the validity list and the overlap set comes from an S1/S2/S3 record; S0 bytes live only in `LoadedFile.source_s0_header` | no |
| `B99-I2` the write placement | `s19_app/tui/changes/apply.py`, `s19_app/tui/workspace.py` | every writer (images, reports, manifests, check specs) | private staging under `temp/.staging/`, `O_EXCL` name claim, `_<N>` naming, `os.replace` with retries, `WorkareaPlacementError` on exhaustion | no |
| `B99-I2a` group placement | `s19_app/tui/workspace.py` | `segment_split_view.py` | places several files sharing one stem (a BIN and its `.addr` sidecar) in one call, one `_<N>` per name | no |
| `B99-I3` `ChainRunOutcome` and the PATCH block status | `s19_app/tui/services/flow_execution_service.py` | the lane painter, `write_chain_set_report`, `app.py`, `flow_report_service.py` | `change_records`, `refusals`, `image_ranges`; the PATCH status derives from the summary dispositions and refusals | no |
| `B99-I4` A2L encode / decode | `s19_app/tui/a2l.py` | `change_service`, the A2L decode consumers, the A2L card | byte order follows tag → `RECORD_LAYOUT` → `MOD_COMMON BYTE_ORDER`; RAT_FUNC INT = f(PHYS) per ASAM | no |
| `B99-I5` CRC coverage | `s19_app/tui/operations/crc.py` | the flow arm, `write_crc_image`, the operation execute path, the CRC Designer | a region with 0 present bytes is an error and injects nothing; partial coverage reports the absent count | no |
| `B99-I6` the split / export writer | `s19_app/tui/segment_split_view.py`, `s19_app/segment_ops.py` | `SplitJoinWindow` | one ASCII allowlist sanitiser, plan-time collision refusal, work-area containment, BIN and sidecar claiming one `_<N>` together | no |
| `B99-I7` the editor image | `s19_app/tui/services/change_service.py` | `app.py`, the before/after readers | the image after apply, and the image saved, equal the source plus the document's current entries; restored in place | no |
| `B99-I8` the Bytes token grammar | `s19_app/tui/services/change_service.py` | `change_service`, the grammar text in `window_help` | one base for every token of one field (`parse_new_bytes`) | no |
| `B99-I9` the project list | `s19_app/tui/app.py`, `s19_app/tui/workspace.py` | the Load project dialog, `_load_from_item` | lists every work-area folder not in `RESERVED_WORKAREA_HOMES` | no |
| `B99-I10` the loader-notice codes | `s19_app/core.py`, `s19_app/hexfile.py` | the flow SOURCE arm, the issues panel | five stable codes `S19-NO-TERMINATOR`, `S19-COUNT-MISMATCH`, `S19-AFTER-TERMINATOR`, `HEX-NO-EOF`, `HEX-AFTER-EOF` | no |
| `B99-I11` the chain-set start check | `s19_app/tui/services/flow_execution_service.py` | `app.py` | refuses before any lane runs when two lanes resolve to one output name (case-folded) | no |
| `B99-I12` the flow WRITE-OUT verify | `s19_app/tui/services/flow_execution_service.py` | the lane cell, the flow report | after placement, `verify_written_image` re-reads the file; a mismatch is an error naming the first differing address | no |
| `B100-I1` the `project.json` envelope | `s19_app/tui/services/manifest_writer.py` | `app.py` | saved file | no |
| `B100-I2` the manifest reader | `s19_app/tui/services/variant_execution_service.py` | `app.py`, `manifest_writer.py`, the Load dialog preview | reads `gathered`, `files`, `active_document`, `derived_from`; a malformed record gives one `MANIFEST-BAD-STRUCTURE`, an unsafe key one `MANIFEST-PATH-ESCAPE`; capped at 1 MiB and 1 000 entries per array | no |
| `B100-I3` the Load-side project check | `s19_app/tui/services/manifest_writer.py` | `_handle_load_project`, `compose_load_announcement`, the Load dialog preview | returns manifest and disk problems only, never parses an image, never raises | no |
| `B100-I4` the project-session reset seam | `s19_app/tui/app.py` | `_handle_load_project` | resets the session inventory; never resets monotonic counters or view preferences; guarded by `_session_snapshot()` | no |
| `B100-I5` `image_differs_from_source` | `s19_app/tui/services/change_service.py` | `_handle_save_dialog` | a read-only fast path into the data comparison, never the copy decision | no |
| `B100-I6` `copy_into_workarea` reuse rule | `s19_app/tui/workspace.py` | the 15 direct call sites | reuse the first byte-identical file, else claim the lowest free `_<N>` (amends B99-I2) | no |
| `B100-I7` the one manifest-writing seam | `s19_app/tui/app.py` | Save project, save-back, the variant / MAC / A2L syncs | every write of `project.json` goes through it; every key it does not own is carried unchanged | no |
| `B100-I8` the Load dialog result | `s19_app/tui/screens.py` | the one app router | `LoadChoice(kind, value)` with `kind` in project / workarea / recent / path | no |
| `B100-I9` the recent-sources store | `s19_app/tui/workspace.py` | `load_from_path`, `load_a2l_from_path`, the Load dialog | saved file | no |
| `B100-I10` `SaveProjectPayload.parent_folder` | `s19_app/tui/screens.py` | `_handle_save_dialog` | the field stays; the handler refuses any parent outside the work area before `mkdir` | no |
| `B100-I11` project-name rules | `s19_app/tui/workspace.py` | `_handle_save_dialog`, `list_projects`, the save plan | reserved names match case-insensitively; a 64-character cap; Windows device names refused | no |
| `B100-I12` the busy/progress seam | `s19_app/tui/app.py` | the `set_progress` callers | `begin_busy` / `step_busy` / `end_busy`, keyed by action; one owner of `#status_text` | no |
| `B100-I13` the one placement function | `s19_app/tui/workspace.py` | `copy_into_workarea`, `_sync_loaded_file_to_project`, `segment_split_view.py` | `find_identical` and `place_into_workarea` hold every placement guard; `copy_into_workarea` is a one-line wrapper | no |
| `B100-I14` this-work-area containment | `s19_app/tui/workspace.py` | every `copy_into_workarea` caller, `save_patched_image`, `list_projects` | `contained_in_workarea(path, workarea)` — true iff the path is inside this app's work area after resolving every link | no |
| `B100-I15` the `save_patched` split | `s19_app/tui/services/change_service.py` | the save-back, Save project | `rederive_for_save` / `emit_and_verify`; Save project emits iff the re-derived data differs from the source (additive to B99-I7) | no |
| `B100-I16` the per-variant manifest key `derived_from` | `s19_app/tui/services/manifest_writer.py` | the save-back, Save project, the manifest reader | saved file | no |
| `B100-I17` the save plan | `s19_app/tui/services/project_gather_service.py` | `_handle_save_dialog`, `SaveProjectScreen` | `plan_project_save(...)` computes the target, rows and image description without writing | no |
| `B100-I18` the unsaved-state predicate | `s19_app/tui/services/change_service.py` | the load seam, the save plan | `mark_saved` / `differs_from_last_saved` decide the load question and the pending line, nothing else | no |
| `B100-I19` the session snapshot | `s19_app/tui/app.py` | the session-reset guard, the worker-vs-main-thread comparison | `_session_snapshot()` derives its domain from the live app, never a hand list | no |
| `B100-I20` the one load seam | `s19_app/tui/app.py` | the Load dialog router, the Workarea Files pick, the variant switch, project load | every image-replacing route passes one unsaved-work guard before it loads | no |
| `B100-I21` the manifest-keys mode | `s19_app/tui/services/variant_execution_service.py` | `read_project_manifest`, `_reject_unsafe_entry` | `_resolve_manifest_entry(..., mode=...)` — in manifest-keys mode refuses a drive, a root, a colon, a trailing dot or space, or a device name | no |
| `B100-I22` `predict_placement` | `s19_app/tui/workspace.py` | `plan_project_save` | answers where `place_into_workarea` would put a file, without writing | no |
