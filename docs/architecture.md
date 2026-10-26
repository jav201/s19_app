# s19_app — Architecture

**Audience:** a technical contributor about to read or change code.
**Purpose:** describe the three-layer architecture, the Direction B TUI shell, the `changes/` and `operations/` data-processing packages, the Patch Editor flow, the path-safety and JSON safety contracts, the engine layer, the testing architecture, and the dev-flow process that built it.

For the visual call-graph (system, TUI shell, two-regime layout, memory layer), see [diagrams/architecture.md](./diagrams/architecture.md) — it is the canonical living diagram and is updated whenever a structural change lands. For point-in-time per-batch detail (decisions, test verdicts, post-mortems), follow the per-batch cross-references in [overview.md](./overview.md) §7.

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

- **Activity rail (left).** Exactly twelve ordered items — keys `1`–`0` plus two non-digit bindings, `=` (Check Editor) and `]` (Flow Execution), both `show=False` (batch-94's R-1 closure; probe evidence `evidence/pdr_rail_key_probe.txt` + `evidence/inc003_rail12_probe.txt`) — with exactly one active marker, glyph + per-item ASCII fallback. Rail items toggle twelve sibling screen containers via the `.hidden` CSS class (not a `push_screen` stack), so the rail and command bar stay persistently mounted.
- **Command bar (top).** Searchable command palette (`Ctrl+K`), find input (`/` → routes to `find_string_in_mem`), go-to-address input (`g` → routes to `_handle_goto`), plus the project-name / A2L-filename status labels.

### The twelve rail screens

| Key | Container id | Screen | Status |
|---|---|---|---|
| 1 | `#screen_workspace` | Workspace (3-pane: ranges/sections · hex · context) | functional; hosts the Loaded-artifacts panel with per-artifact unload |
| 2 | `#screen_a2l` | A2L Explorer (symbol table + hex pane) | functional; enriched tags, 19-field filter, windowed rendering |
| 3 | `#screen_mac` | MAC View (record table + hex pane) | functional; per-row status, malformed lines flagged not dropped |
| 4 | `#screen_map` | Memory Map | functional — real coverage from `LoadedFile.ranges` plus entropy bands from `services/entropy_service.py` |
| 5 | `#screen_issues` | Issues Report | functional — grouped, filterable, paged view of the validation engine's findings; batch-94 triages curated standard A2L blocks to INFO |
| 6 | `#screen_patch` | Patch Editor | **functional** — change-set rows, validate/check, save/load v2 JSON, apply + patched-image emit, undo/redo |
| = | `#screen_check_editor` | Check Editor | **functional** (batch-94 Inc-001) — write/validate `.chk.json` check specs, struck-APPLY no-apply doctrine |
| 7 | `#screen_diff` | A↔B Diff | **functional** — second-image load, classified diff runs, Markdown/HTML report |
| 8 | `#screen_flow` | Flow Builder | **functional** — fb_a palette/canvas block builder with typed cables, template save/load (moved to `flow_screens.py`, batch-94 Inc-002) |
| ] | `#screen_flow_execution` | Flow Execution | **functional** (batch-94 Inc-003) — per-chain lanes, input rebinding, sequential(default)/parallel runs, chain-set save/load |
| 9 | `#screen_checks` | Checks | functional — read-only grouped-by-outcome mirror of the last check run |
| 0 | `#screen_crc_designer` | CRC Designer | functional — parametric CRC form, preset catalogue, live known-answer verdict, `*.crc.json` templates |

Fourteen modal screens complement the rail (load file, save/load project, variant select/help, change-set and entry JSON editors, flow save/load, confirm-discard, confirm-write, legend, report viewer, operations). The batch-02 **Bookmarks** screen no longer exists — the rail's last three slots are Flow Execution, Checks and CRC Designer (batch-94 grew the rail 10→12: Check Editor on `=`, Flow Execution on `]`, both `show=False`).

### Two-regime responsive layout

One layout, width-responsive, governed by a 120-column terminal breakpoint:

- **Fixed regime — width ≥ 120 columns.** Rail full fixed width; Workspace `left 22 · right 40 · center 1fr`; MAC `hex 40 · table 1fr`.
- **Proportional regime — width < 120 columns.** Rail collapses to icon-only (~4 cols); Workspace `left 24% · right 30% · center 1fr`; MAC `hex 35% · table 1fr`.

Layout integrity is guarded by the `pytest-textual-snapshot` SVG baseline matrix (29 baselines) plus 119/120 boundary tests. The A2L Explorer panes are the **exception** — flat 3/7 hex ÷ 4/7 tags at all widths (the iteration-3 two-regime A2L split rendered the hex view too narrowly at ≥ 120 cols and was superseded; see `R-TUI-037`).

The diagrams in [diagrams/architecture.md](./diagrams/architecture.md) §2 and §3 render this visually.

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

Roughly **2760 tests** under `tests/` (collected 2026-10-11), organised by module — `tests/test_core_*`, `tests/test_hexfile.py`, `tests/test_range_index.py`, `tests/test_validation_*`, `tests/test_tui_*`, `tests/test_changes_*`, `tests/test_crc_*`, `tests/test_flow_*`, `tests/test_entropy_*`, `tests/test_compare*`, `tests/test_manifest*`, `tests/test_variant*`, plus the per-example smoke suites (`tests/test_examples_*`). A registry guard (`tests/test_id_registry.py`) keeps every declared requirement/test id traceable to its verifier node.

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
3. **Implementation** — supervised increments capped at ≤ 5 files, each closed by a review packet.
4. **Validation** — per-TC verdict register; suite + boundary + security checks; verdict `pass` / `pass-with-gaps` / `fail`.
5. **Post-mortem** — what worked, what didn't, follow-up batches scoped.
6. **Docs** — executive summary, functionality orientation, traceability matrix, architecture diagrams.

Per-batch artefacts are archived under `.dev-flow/<YYYY-MM-DD>-batch-NN/`. The repo-root [REQUIREMENTS.md](../REQUIREMENTS.md) is the living `R-*` index that absorbs each batch's stable requirements.

---

> **Amended at ARQ by `2026-08-24-batch-88`** (2026-08-24). Family A fired, so this station ran.
> Sections 1–9 are **unchanged**: this map is a standing project artifact and batches amend it, they
> do not recreate it. What follows adds the two **mechanical** viewpoints the map was missing — the
> ones a script can read. **Deliberately NOT renumbered** to the template's viewpoint order
> (`Composition` is §2 there, `Interfaces` §4): every existing citation of "§4 · Patch Editor flow"
> would silently retarget. The template's numbering is a scaffold, not a contract; the tables below
> are self-identifying by their column headers, which is what a checker should key on.

> **Amended at DOC by `2026-10-11-batch-92`** (2026-10-11; base `410cde5`, branch
> `kimi/batch-92-layer-inversions`). Unlike batch-88, this amendment **does touch an earlier
> section**: §7's frozen list gains `s19_app/tui/color_policy.py` (finding F-1 of the batch
> record — the batch's premise froze it and the post-gate amendment lands it here). Everything
> else lands under §10 (sub-module declarations for the new `s19_app/render/` package inside
> product, changed-module entries, a retired path, dependency-edge amendments, and two flow
> inputs) and under §11 (four batch-92 surface contracts). §1–§6 and §8–§9 are otherwise
> unchanged: §1–§3 prose still walks the pre-batch-92 tree, which the retired-path declaration
> under §10 explains. The batch-88 census line below ("266 tracked source files", measured
> 2026-08-24) remains that batch's dated measurement; batch-92's net path change is +3 new files
> under the unchanged `s19_app/**` prefix (`render/__init__.py`, `render/hexview.py`,
> `render/format.py`) and −1 retired (`s19_app/tui/hexview.py`) — no prefix change, so no
> checker rule change is required for this batch.
>
> **Post-gate amendment (PDR condition C2, discharged at the DDR 2026-10-12).** Three stale
> "the residuals survive" leftovers from the intake-time draft are flipped to the ratified P1
> disposition (review C1-(c), operator-ratified): the two residual rows
> `render/hexview → tui/color_policy` and `render/hexview → tui/insight_style` in the §10
> dependency table now read **KILLED by batch-92** (TC-655 pins the frozen copies), the
> `render/hexview.py` "Deps — allowed" row no longer lists the tui constant sources, and
> rationale R3 records its own P1 reversal. `tui/color_policy.py` remains frozen and untouched;
> the killed edges are import edges, not the freeze.

> **Amended at ARQ by `2026-10-12-batch-94`** (2026-10-13; base `8e056bd`, branch
> `kimi/batch-94-flows-and-editors`, worktree `s19_app-b94`; A1/A2/A3 fired). This amendment
> touches **no earlier section's prose**: §2's "exactly ten ordered items" rail invariant and
> rail table describe the shipped tree and stay true until the increments land — the batch's
> declarations below are **planned** module changes, and the residue updates as each increment
> merges. What follows adds the batch-94 sub-module declarations under §10 (one NEW module
> inside product, four CHANGED modules, the parallelisation-rule verdict, rationales R8–R12)
> and batch-94 interface rows under §11. The architect role was **self-executed by the
> orchestrator** (no sub-agent independence needed at ARQ: the map's gate is the operator's
> approval, here the standing grant of 2026-10-13); downstream reviewer roles (P2 cross-review,
> per-increment code-review, the PR-level qa pass) are spawned as generic subagents per
> `SKILL.md` step 5. The batch record's `design/module-map-delta.md` carries the full evidence.

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
| **prototypes** | `prototypes/**` | throwaway design probes, kept as evidence of what was tried | nothing — **no product code may import from here** | anything that has graduated: graduating means moving into `s19_app/**` |
| **flow** | `.dev-flow/**` | the batch record and its local tooling; `_derived/` is DERIVED and guarded by V20 | the batch artifacts, cited by id | product or test code |
| **docs** | `docs/**` | this map, the diagrams, the orientation notes | the map itself, read as an oracle by the A-family triggers | code with behaviour |

**The one file no module can own, and why that is a finding rather than an omission.** `setup.py`
sits at the repository root. The staleness check extracts prefixes matching `` `path/**` `` and tests
`file.startswith(prefix + "/")`, so **a root-level file is unclassifiable by construction** — no
declarable prefix can ever match it. It is named here so the resulting notice reads as *known and
bounded* rather than as a stale map. **Registered as flow input for batch-88**: the rule should
either admit a root sentinel or state that root files are out of its scope; silently reporting them
as orphans conflates *"the map is stale"* with *"the rule cannot express this"*.

**Rationale for the six-module cut.**

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| 1 | Six **top-level, non-overlapping** prefixes | Declaring `s19_app/tui/changes/**` and friends as separate modules | Overlapping prefixes are a defect of this document, not an ambiguity to resolve case by case — and the sub-packages are already described in §1–§3. Re-open if a sub-package acquires an independently-consumed interface. |
| 2 | `prototypes/**` is a declared module rather than excluded | Leaving it undeclared | Undeclared means every prototype file reads as *"the map is stale"*. Declaring it with **"no product code may import from here"** turns a permanent false alarm into a stated boundary. |
| 3 | `tests/**` is one module, not one per layer | Mirroring the product's layering | Nothing reads the split mechanically today. Re-open when a lane plan needs test file sets to be disjoint by layer. |

### Batch-92 sub-module declarations — `s19_app/render/` inside product

*`2026-10-11-batch-92` (layer-inversion kills). The six-module cut above stands: `render/` is declared at **sub-module (file) granularity inside product**, not as a 7th top-level module — carving `s19_app/render/**` out of product would make two prefixes overlap (a defect per rationale #1) and the staleness checker's `startswith(prefix + "/")` rule cannot express a hole in `s19_app/**`; see the flow input below. Full evidence: the batch record's `design/module-map-delta.md`; what follows is the standing-map residue.*

#### NEW `s19_app/render/hexview.py` (+ `s19_app/render/__init__.py` marker)

Relocates `s19_app/tui/hexview.py` (measured 477 LOC, 0 classes — AST census re-confirmed at base).

| Viewpoint | Declaration |
|---|---|
| **Encapsulates** | the pure hex-window renderer: `render_hex_view` / `render_hex_view_text`; memory-map builders `build_mem_map_s19`, `build_range_validity_s19`, `build_range_validity_hex`, `build_row_bases`; `find_string_in_mem`; layout constants `HEX_WIDTH`, `MAX_HEX_ROWS`, `MAX_HEX_BYTES`, `FOCUS_CONTEXT_ROWS`, `SEARCH_ENCODING`. |
| **Boundaries** | pure Python + `rich.text` only. **No Textual import, no widgets, no app state** (verified at base: imports `bisect`, `typing`, `rich.text`, `..core`, `..hexfile`, `..range_index`, two `color_policy` constants, three `insight_style` constants — nothing else). Callable headless: it is the renderer the Markdown/HTML report services already consume as plain strings. |
| **EXPOSES** | the 9 functions + 5 constants above, imported by views and services directly from `s19_app.render.hexview`. No re-export chain: consumers do NOT source it via `tui/__init__` after US-92-2 (see the `tui/__init__` contract in §11). |
| **Does NOT belong** | range-membership primitives (`build_sorted_range_index` / `address_in_sorted_ranges` / `range_in_sorted_ranges` re-export wrappers are **deleted**, US-92-2 — ownership stays in the engine `s19_app/range_index.py`); severity→CSS policy (`css_class_for_severity`, stays in `tui/color_policy.py`, US-92-5 OUT); any Textual/window/widget concern. |
| **Deps — allowed** | `rich.text`; `s19_app.core`, `s19_app.hexfile`, `s19_app.range_index`; style *constants* from in-package `s19_app.render.format` (the two `color_policy`-kin copies pinned by TC-655). **Zero `s19_app.tui.*` deps** — the pre-batch constant imports from `tui/color_policy` / `tui/insight_style` are killed, not residual (P1 amendment; ratified disposition in the dependency table below). |
| **Deps — forbidden** | every other `s19_app.tui.*` symbol; `textual`; `s19_app.validation`; any `tui/services/*`. (This forbidden set is the entire point of the batch: service→presentation edges die here.) |

Rationale (structural decisions):

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R1 | Move the file whole, byte-preserving, into the new package `s19_app/render/` | Gradual copy-and-repoint (old module left as a shim) | A shim would keep the `tui.hexview` import address alive — exactly the inverted edge US-92-1 kills; and 11 test files already pin the new address by repointing. The batch is behaviour-preserving; a coexistence window adds a second source of truth for zero benefit. |
| R2 | `render/` is a package, not two flat modules dropped into `s19_app/` | Flat `s19_app/hexview.py` + `s19_app/format.py` | The two modules share one boundary rule (pure-Rich, no-Textual, service-consumable). A package states that rule once at the directory level and leaves room for the next renderer (report formatters) without another ARQ cycle. The package marker `__init__.py` is empty of logic. |
| R3 | Style *constants* are owned by `render/format` (moved THIS batch); style *policy* may not cross into `render/` — **amended at P1** (review C1-(c), operator-ratified): the original "import-as-data residual" posture was superseded once TC-655 existed to pin the frozen copies | Moving the constants into `render/` now — the original rejection, reversed at P1 | `color_policy.py` is frozen (operator-confirmed, US-92-5 OUT — now listed in §7) and `insight_style` carries view-side helpers that must stay put. The freeze is honoured by value-equal copies pinned to the frozen origins, not by edits — drift between `render/format` and the frozen tui origins fails TC-655. |

#### NEW `s19_app/render/format.py`

| Viewpoint | Declaration |
|---|---|
| **Encapsulates** | presentation-neutral formatting primitives services need: `microbar` + its private glyphs `MICROBAR_FILLED` / `MICROBAR_EMPTY` + the pure style constants of the `GREEN` / `LABEL` / `VALUE` kin. |
| **Boundaries** | pure Python + `rich.text` (verified: `microbar` body uses only `Text` + the two glyphs). No Textual, no CSS, no tui imports. |
| **EXPOSES** | `microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE`. New service consumers MUST import from here, never from `tui.insight_style`. |
| **Does NOT belong** | the view-side helpers that stay in `insight_style`: `human_bytes`, `label_value`, `threshold_style`, `cap_gauge_style` and the rest of the palette (`YELLOW/RED/HILITE/LBLUE/DGRAY/PURPLE/CYAN/MAGENTA`, `DEPTH_*`). |
| **Deps — allowed** | `rich.text` only. |
| **Deps — forbidden** | `s19_app.tui.*`, `textual`, engine, services. |

Rationale:

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R4 | Canonical ownership moves to `render/format.py`; `insight_style` keeps a **re-export shim** | Full repoint of all 7 view consumers (`app`, `checks_view`, `issues_view`, `crc_designer_view`, `json_highlight`, `screens_directionb` — measured) | The increment file budget (≤5 files) and behaviour-preservation: a shim repoints exactly one service edge (`validation_service`) while the view surface is untouched — 0 snapshot risk. The asymmetry with US-92-2 is deliberate and declared: US-92-2 deletes *engine* re-exports (addressing correctness), R4 keeps a *presentation* shim (cosmetic convenience), and the shim's consumer rule ("services use render/format") is written here so it is not mistaken for an edge to "fix". |
| R5 | `microbar` moves **with** its glyphs and the service-needed constants as one unit | Splitting constants into a third module | `microbar`'s contract includes the glyph pair; splitting them creates a dependency between two tiny modules to save nothing. One module, one boundary rule (R2). |

#### CHANGED `s19_app/utils.py`

| Viewpoint | Declaration |
|---|---|
| **Encapsulates** | (existing) `format_bytes`, `is_printable`, `safe_decode`. **Gains `safe_text`** moved from `tui/screens_directionb.py`, together with its private byte-class table `_CONTROL_SCRUB` (C0/DEL/C1 class — the normative, load-bearing shape per the source comment there). |
| **Boundaries** | stdlib + `rich.text` only. **No Textual.** Stays importable from any layer (currently only `tui/*` consumes it; the address is presentation-neutral by construction). |
| **EXPOSES** | `safe_text(value, style="") -> Text` as the **canonical markup-/control-safety primitive** (security contract in §11). |
| **Does NOT belong** | any screen/widget logic; `safe_text`'s previous address is retired — `screens_directionb` becomes a consumer like everyone else. |
| **Deps — allowed / forbidden** | allowed: `rich.text`; forbidden: `s19_app.tui.*`, `textual`. |

Rationale:

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R6 | Canonical home is the app-root `utils.py`, not `render/` | Putting `safe_text` in `render/format.py` | `safe_text` is a *safety* primitive (C-17/B-1, §11), not a formatter: `checks_view`/`issues_view` consume it as a security sink, and a future non-render consumer must not drag presentation deps in. Root `utils` is the address with zero layer meaning. |
| R7 | `_CONTROL_SCRUB` moves **with** the function, private | Leaving the table in `screens_directionb` as an import | The table is `safe_text`'s single-use private dependency; a cross-module constant import for it recreates the very `screens_directionb`-coupling US-92-3 removes. |

#### CHANGED `s19_app/tui/insight_style.py`

Keeps: full palette, `DEPTH_*`, `human_bytes`, `label_value`, `threshold_style`, `cap_gauge_style`. **Loses canonical ownership** of `microbar` + `MICROBAR_*` + `GREEN`/`LABEL`/`VALUE` (→ `render/format.py`, R4); **gains a re-export shim** for exactly those symbols so the view consumers (`app.py`, `checks_view.py`, `issues_view.py`, `crc_designer_view.py`, `json_highlight.py`, `screens_directionb.py` — all measured at base) are untouched. New edge `insight_style → render/format` is **allowed and declared**: presentation consuming presentation-neutral primitives is the permitted direction. Forbidden (unchanged): Textual, engine internals beyond existing use.

#### CHANGED `s19_app/tui/screens_directionb.py`

Loses `safe_text` + `_CONTROL_SCRUB` (→ `utils.py`, R6/R7); becomes their consumer. Gains nothing. Its other surfaces (screens, panels, the lazy `hexview` imports repointed by Inc-A) are unchanged in ownership. Remains the Direction-B screen shell; still does not own engine primitives (already imports `range_index` directly — the posture US-92-2 generalises).

#### CHANGED consumers (repoint-only, no ownership change)

| Module | Change | Evidence |
|---|---|---|
| `tui/app.py` | hexview import → `render.hexview`; range_index wrappers → direct `range_index`; `safe_text` → `utils` | measured (§7.2 of the batch record) |
| `tui/__init__.py` | drops the 3 range_index wrappers; renderer re-export surface preserved, sourced from `render.hexview` | measured |
| `tui/screens.py` | hexview import → `render.hexview` | measured — **not named in US-92-1's story text** |
| `tui/checks_view.py`, `tui/issues_view.py` | `safe_text` → `utils` | measured |
| `services/load_service.py`, `services/report_service.py`, `services/diff_report_service.py` | hexview imports → `render.hexview` | measured |
| `services/validation_service.py` | `GREEN, LABEL, VALUE, microbar` → `render.format` | measured |

#### RETIRED path

`s19_app/tui/hexview.py` — **deleted** by batch-92 (Inc-A). Declared here so no reader of §1–§9 prose (which still walks the old tree) mistakes it for drift, and so the post-batch staleness sweep keys correctly.

#### Batch-92 dependency amendments

**Edges killed** (the batch's product; the batch record's intake caption is "6 of 7 measured at intake" — the 7th measured inversion, `services/change_service → tui/color_policy`, survives as a declared residual below):

- `services/load_service → tui/hexview` · `services/report_service → tui/hexview` · `services/diff_report_service → tui/hexview`
- `services/validation_service → tui/insight_style`
- `tui/app → tui/hexview` (range_index indirection) · `tui/__init__ → tui/hexview` (wrapper chain) — via US-92-2's direct-to-engine rule
- `checks_view` / `issues_view → screens_directionb` (the `safe_text` edge)

**New edges (allowed, declared):** `services/* → render.hexview` · `services/validation_service → render.format` · `views → render.hexview` / `render.format` · `insight_style → render/format` (shim, R4) · `any layer → utils.safe_text`.

**Declared residuals** (declared, not hidden):

| Edge | Symbols | Disposition |
|---|---|---|
| `render/hexview → tui/color_policy` | `FOCUS_HIGHLIGHT_STYLE`, `MAC_ADDRESS_OVERLAY_STYLE` | **KILLED by batch-92** (P1 amendment, review C1-(c), operator-ratified): the edge is dead — `render/hexview` carries zero `s19_app.tui.*` imports and sources all five style constants from in-package `render/format`, which holds value-equal **pinned copies** of the two `color_policy` styles (TC-655). `tui/color_policy.py` itself stays frozen and untouched (US-92-5 OUT, §7). |
| `render/hexview → tui/insight_style` | `CYAN`, `DGRAY`, `VALUE` | **KILLED by batch-92** (same P1 amendment): `render/format` is the canonical owner of the 5 constants; `render/hexview` imports them in-package (`from .format import …`) and `tui/insight_style` retains them only as a re-export shim (Inc-B). |
| `services/change_service → tui/color_policy` | `css_class_for_severity` | US-92-5 OUT (operator freeze) — the 7th measured inversion; deferred to BACKLOG-CODE.md lane A. |
| `tui/insight_style → render/format` | shim re-exports | **New, deliberate** (R4). Not an inversion — presentation → presentation-neutral is the allowed direction. Declared so a future dependency radiography does not "fix" it. |

**Registered as flow input for batch-92 (from the batch record §6.2 — `tests/**` granularity).** Batch-88 rationale #3 kept `tests/**` as one module, re-open condition *"when a lane plan needs test file sets to be disjoint by layer"*. Batch-92's ARQ is that trigger: the batch's sequential verdict depends on file-level test sets (`test_tui_directionb.py`, `test_tui_hexview_classed.py`, `test_tui_issues_view.py` sit in both lanes' repoint sets — harmless sequential, fatal parallel). For batch-92 the parallelisation rule is applied at file granularity inside `tests/**` (rationale #3's letter honoured, its spirit — nothing mechanically reads the split today — preserved: the staleness checker's prefix classification is untouched). A **permanent** sub-split of `tests/**` is deferred as a flow input; the batch-92 verdict does not depend on it.

**Registered as flow input for batch-92 (from the batch record §6.3 — checker expressiveness).** The staleness checker's `startswith(prefix + "/")` rule cannot express a hole in `s19_app/**` — the same expressive limit as the root-level `setup.py` case named above. The rule should either admit exclusion patterns or state that sub-package carve-outs are expressed as in-product declarations (as `render/` is declared here); otherwise a future genuinely-independent render interface silently reads as *stale map*.

### Batch-94 declarations — the editor split and the flow surfaces

*`2026-10-12-batch-94` (Cambio1–7: Patch/Check Editor split + rework, Flow Builder redesign, Flow Execution). The six-module cut stands: the one NEW module is declared at **sub-module granularity inside product**, following the `render/` precedent (batch-92 rationale #1's overlap rule). **All entries below landed** — each declaration names the increment that landed it (Inc-001…004) and the batch-94 work is complete. Evidence: the batch record's `design/module-map-delta.md` (authored at ARQ, landed with the batch's close); spike design input `flow_bench.NOTES.md` / `editor_bench.NOTES.md` (operator decisions D1–D5).*

#### NEW `s19_app/tui/flow_screens.py` (landed — Inc-002 fb_a step, Inc-003 fx_a step)

| Viewpoint | Declaration |
|---|---|
| **Encapsulates** | the flow surfaces: the reworked `FlowBuilderPanel` (fb_a: palette + canvas + refined cable routing, block types patch/CRC/A2B-diff) and the new `FlowExecutionPanel` (fx_a: per-chain carriles + run-log; template import; per-chain input rebinding; sequential(default)/parallel-per-chain control; chain-set save/load). Pure view layer: panels + their `ActionRequested`-kin messages; no engine, no service logic. |
| **Boundaries** | Textual view code, same discipline as `screens_directionb.py` (presentational; services own logic). May import `tui/changes`, `tui/operations`, engine primitives read-only — never the reverse: no engine/services module may import `flow_screens`. |
| **EXPOSES** | the two panel classes + their message types, consumed by `tui/app.py` routing only. |
| **Does NOT belong** | flow execution **semantics** (stays in `services/flow_*`); the change-set/check engines (`changes/`); the rail/chrome (stays `app.py`). |
| **Deps — allowed** | `textual`, `s19_app.utils.safe_text` (C-17 sink), `tui/insight_style` constants, read-only engine/types. |
| **Deps — forbidden** | `s19_app.validation` internals beyond the read-only consumer posture; `tui/services/*` imports into view logic (routing messages out, services in — never called directly). |

#### CHANGED `s19_app/tui/screens_directionb.py` (landed — Inc-001 editor split, Inc-002 B2 vacate)

Keeps: every existing surface (Memory Map from batch-93, the A↔B Diff host, the editors' siblings). **Inc-001:** `PatchEditorPanel` is reworked in place (pe_b: single-file editing — variant selector removed, Edit-JSON + validate flow, dirty-guarded Load, Apply-loaded-changes) and gains its check twin `CheckEditorPanel` (ce_a: report-oriented, `.chk.json` content panel, write/validate only). *(Naming ratified per the contract's HLR-001/003 rationales: the shipped twins are **pe_b + ce_a with ce_b folded in** — the spike's "pe_a/ce_b" survives only as §2.6 shorthand in older contract text.)* **Inc-002 step:** loses `FlowBuilderPanel` (→ `flow_screens.py`, B2 move census below). Remains the Direction-B shell; the C-34 full-guard-host obligation stays with this file for every render increment that touches it.

#### CHANGED `s19_app/tui/services/flow_*` (landed — Inc-002 builder/A2B/templates, Inc-003 execution/chain-set)

The flow services (`flow_model.py`, `flow_execution_service.py`, `flow_report_service.py`, `flow_fused_report_service.py` — all existing) grow the execution semantics US-005/007 require: builder templates (flow save/load beyond today's `flow.json`), chain composition with per-chain input provenance recorded in the report (operator decision D1), sequential(default)/parallel-per-chain run control (D4), chain-set save/load (inputs + outputs, US-007). The A2B diff block is configurable per block with both inputs declared as flow-output-or-file and the provenance stated in the report. Dependency direction unchanged: services consume `changes/` + `operations/` + engine read-only; the view (`flow_screens`) never enters them.

#### CHANGED `s19_app/tui/changes/io.py` (landed — Inc-001)

Gains the **suffix-distinguished** `.chk.json` save/load path: same `s19app-changeset` v2 wire grammar, `kind="check"` documents, no schema change (operator ruling from the spike — no `from`/`to` fields, `DUMMY_CHANGESET_TEXT` shape at `io.py:136` is the reference). **No change to `apply.py` is needed for the "check files must never apply" ruling — `apply_change_document` already gates on `kind != "change"` (zero writes); the ce_a panel adds no apply path.** The A2B Diff file dropdown gains the check-spec listing (suffix-filtered, same directory).

#### CHANGED `s19_app/tui/app.py` (landed — Inc-001…004)

Rail grew **10 → 12** surfaces: the `Check Editor` and `Flow Execution` entries landed with keys `=` and `]` respectively — both `show=False`, ratified at the PDR by the executed rail-key probe (the `1`–`0` digit space is exhausted; the F-key candidates were rejected as terminal-swallow hazards). Routing handlers for the two new panels (message → service, the §4 pattern); the guard-host rail census constants (`EXPECTED_RAIL`, screen counts) moved with the landing increments (11 at Inc-001, 12 at Inc-003, LLR-002.2 — never before).

#### The US-004 seam — a frozen-layer flag (decided at P1: view-level; landed Inc-004)

The warnings triage (`A2L_UNRECOGNIZED_BLOCK` class) has two candidate seams: **parser-level** recognition in `s19_app/tui/a2l.py` / `s19_app/validation/rules.py` (both frozen per §7) — which "changes the engine's stability story and must be called out in the requirements phase" — or **view-level** reclassification in the Issues surface. ARQ declared the candidates and their costs; P1 picked the **view-level** seam (R12) with the freeze consequence stated, and it shipped in Inc-004: the curated-set reclassification in `issues_view.py` with the engine frozen (the in-run byte-check, TC-B94-18). No module boundary moves either way.

#### Batch-94 dependency amendments (landed)

**New edges (allowed, declared):** `flow_screens → utils.safe_text` / `insight_style` (view posture, same as `screens_directionb`) · `services/flow_* → changes/io.py` (`.chk.json` path) — both the permitted directions · `flow_screens → services/flow_model` (read-only data import of the block-type constants/dataclasses — `A2BBlock` / `BLOCK_A2B` at `flow_screens.py:71-75`, landed with Inc-002's A2B block; the view→model posture per `screens_directionb.py`'s historic idiom, declared at the PDR so a future dependency radiografía does not "fix" it).

**B2 move census (Inc-002 — executed):** `FlowBuilderPanel`'s address change `screens_directionb → flow_screens` triggers the reader census (C-14): `grep -rl "FlowBuilderPanel\|screen_flow" tests/ s19_app/` — known consumers today: `tests/test_flow_builder_render.py`, `tests/test_flow_crc_block.py`, `tests/test_flow_crc_ribbon.py`, the guard host (`test_tui_directionb.py` rail/screen census), `app.py` routing. The census re-ran at the increment cut and its output lands in the packet.

**Parallelisation-rule verdict (mechanical):** with the flow surfaces **in** `screens_directionb.py`, Inc-001 ∩ Inc-002 = {`screens_directionb.py`} ∪ {`app.py`} ≠ {} — the increments would not be parallelisable. The rule's second exit is taken **here in ARQ**: the module boundary moves (`flow_screens.py`), after which Inc-001's and Inc-002/003's file sets are disjoint except `app.py` rail rows, which are touched by every increment sequentially anyway. In this batch the increments still run sequentially (A4 not fired, one worktree); the re-cut is what keeps the increments separable for review and future parallel lanes.

Rationale (structural decisions):

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R8 | Flow surfaces get their own module `tui/flow_screens.py`; `FlowBuilderPanel` moves address in Inc-002 | (a) Redesign in place inside `screens_directionb.py` — file past 5 000 LOC growing ~2×, and every flow increment drags the C-34 guard host of the whole Direction-B file; (c) a full per-surface re-cut of `screens_directionb` — out of proportion for this batch | A third flow-family surface landing, or a measured guard-host runtime blowup, would argue for the full re-cut (c); until then the single-purpose module carries the family |
| R9 | Editors stay in `screens_directionb.py` (their historic home); only the flow family leaves | Moving the editors too (one "screens split" for the whole batch) | The editor split is presentational (one panel becomes two twins sharing the entries table idiom); moving both families in one batch doubles the B2 census surface for zero review benefit |
| R10 | `.chk.json` is a **suffix distinction on the existing v2 grammar** (`kind="check"`), not a new package or schema | A parallel `checkspec/` package; a v3 envelope | The v2 model already discriminates `"change"`/`"check"` and `apply.py` already refuses non-change kinds — the operator's ruling (schema unchanged) maps onto machinery that exists; a second grammar would double the reader/validator surface for one dropdown distinction |
| R11 | The rail grows to 12 with the key-binding question **open to P1/PDR** | Binding the new surfaces to ad-hoc keys at ARQ; or a sub-rail design invented here | Textual `Binding` key space and the operator's muscle memory decide; ARQ declares the invariant change, not the keys |
| R12 | US-004's seam is **flagged, not decided** | Picking parser-level recognition at ARQ by default | If P1 finds the view-level reclassification falsifies a real warning class (a genuinely malformed block read as benign), the seam moves parser-ward with the §7 freeze consequence stated |

**ARQ evidence checklist (architect role, self-executed):** constraints stated — the frozen engine list (§7), the ≤5-files-per-increment budget, the rail key space, C-17/C-42 (file-derived text rendered) — all `executed` (this map); alternatives considered — R8/R10 each name the rejected candidates `executed`; risks — R8's guard-host split, R11's key binding, R12's frozen-layer crossing, listed; recommendation rationale tied to the parallelisation rule `executed`; what would re-open each decision — per-row `executed`; two-layer requirements note — the behavioral+functional chains are owed at P1 (this station precedes derivation, per `p1-arq.md`).

### Batch-97 declarations — the b94 polish port (no module created, no boundary moved)

*`2026-10-19-batch-97` (US-134..US-139: port the operator-approved round `prototypes/b94_polish/`, verdict A on all four screens, into the four batch-94 panels; brief `.dev-flow/design/HANDOFF-b94-polish-2026-10-20.md`). Triggers A2 + A3 fired; A1, A4, B2 not fired. **Declared at ARQ, nothing landed** — "Inc" names the handoff §6 increment expected to land each row.*

**A1 not fired — evidence.** Every file the batch touches already exists under `s19_app/**` (product): `git status --short s19_app/` at ARQ is empty and the handoff §6 lists name existing paths only. No panel changes address (B2 not fired), so §10's six-module table and the batch-92/94 sub-module declarations stand unchanged. `prototypes/b94_polish/` is ported by **re-composition, never imported** (the `prototypes/**` boundary).

| Path (all CHANGED) | What the change encapsulates | Inc |
|---|---|---|
| `s19_app/tui/screens_directionb.py` | `PatchEditorPanel` (pe_A ledger + inspector + JSON tab, `:4383`) and `CheckEditorPanel` (ce_A, `:6864`) re-composed at their shipped widget ids; the double column/geometry work removed (E-1) | 1, 2 |
| `s19_app/tui/flow_screens.py` | `FlowBuilderPanel` (fb_A pipeline rail, six-kind palette F-5, IO clipped to the card F-1) and `FlowExecutionPanel` (fx_A per-lane pipeline, cable status, English log — e.g. `:2254` `"(sin proyecto activo)"`) | 4, 5 |
| `s19_app/tui/app.py` | headers: the bare `Label("Check Editor")` (`:3082`) → `titled_header` + chip + help; Flow Execution (`:2438`) and Flow Builder (`:2404`) gain their chips; the geometry re-apply on show (E-2, now `:6978` — the handoff's `:6848` drifted) deleted or retargeted; the JSON-tab/identity feed at the `refresh_entries` sites (I-2, I-3) | 1, 2, 4, 5 |
| `s19_app/tui/services/folder_open_service.py` + `s19_app/tui/open_folder_chip.py` | two chip families, `flows` and `session` (I-1) | 3 |
| `s19_app/tui/window_help.py` | two new window keys + rewritten `patch` / `flow` entries (I-4) | 1, 2, 4, 5 |
| `s19_app/tui/styles.tcss` | the four screens' rules, the E-3 rules **replaced**, not overridden | all |
| `s19_app/tui/insight_style.py` | the burnt-orange CRC token (R-5.1) — **not in the handoff's file lists**; see R16 | 3 or 4 |

**Interface deltas (A3) — consumers measured by `grep -rn` over `s19_app/` + `tests/`:**

| # | Surface | Delta | Consumers | Freeze |
|---|---|---|---|---|
| I-1 | chip family table (`folder_open_service.py:57-68` `CHIP_FAMILY_*` / `CHIP_FAMILIES`, `resolve_chip_target` `:232`, `create_chip_home` `:279`) | + `flows` → `project_dir / FLOWS_SUBDIR` (`flow_persistence_service.py:95`, the dir `save_flow_json` writes, `:973`); + `session` → `active_project_dir()` itself (the value `_publish_flow_session_dir` pushes to `set_session_dir`, `app.py:8121-8137`). Both project-only. The no-project status `REPORTS_NO_PROJECT_REASON` (`:78`) names *Reports* verbatim and `open_folder_chip.py:115`/`:160` emit it for **any** `None` target — it must become per-family | `open_folder_chip.py:36-43` (the one importer of the table) · `app.py:12756` (refresh loop over every mounted chip — no change) · `app.py:6388` / `screens.py:1668` (seam / Reports chip — unaffected) · `project_gather_service.py:598` (docstring only) · `tests/test_open_folder_chips.py` (`_RAIL_CHIPS` `:94`) | PDR, before Inc 3 |
| I-2 | `PatchEditorPanel.refresh_entries(rows, mem_map)` (`screens_directionb.py:6104`) | **candidate:** the document identity for the ribbon (E-5) — available today as `ChangeDocument.source_path` / `.kind` (`changes/model.py:197`), no service change | `app.py:3265`, `:3451`, `:5279`, `:10758` + the panel's own `:5662`; tests: 27 calls in 6 files (`test_tui_patch_card.py`, `test_tui_patch_editor_b94.py`, `test_tui_snapshot.py:815`, …) | shape at PDR |
| I-3 | the JSON-tab feed (E-6) | today the only JSON surface is `#patch_paste_text` (`screens_directionb.py:5192`), an input buffer seeded with `DUMMY_CHANGESET_TEXT`; the app writes it only on the popup write-back (`app.py:3725`). The document lives in `ChangeService.document` (`change_service.py:696`) and has one canonical serialiser, `changes/io.serialize_change_document` (`io.py:1392`, already reused by `entry_seed_json`, `change_service.py:1225`). **Seam: app → panel at the I-2 sites**; the writer is untouched (B4 stays not fired) | the same four `app.py` sites; live vs `Update JSON` decided at PDR (US-134) | PDR, before Inc 2 |
| I-4 | `window_help.SHIPPED_WINDOW_KEYS` (`:270`) | + a Check Editor key and a Flow Execution key (`checks` is the Checks *result* view, `flow` is the Builder) | `tests/test_window_usage_help.py:250` (equality census) · the `WindowHelpChip(...)` header sites in `app.py` | Inc 1 / Inc 5 |
| — | `FlowExecutionPanel.render_run(record)` (`flow_screens.py:2399`, sole caller `app.py:2821`) | **read, not changed**: fx_A takes per-block status from the retained record (F-8). If PDR finds the record lacks per-block status or a lane key, the record shape changes → A3 on `services/flow_execution_service`, declared here first | — | — |

**Dependencies.** One new edge, permitted direction: `services/folder_open_service → services/flow_persistence_service` (`FLOWS_SUBDIR`) — a sibling-service import, the posture the seam's own docstring allows (`folder_open_service.py:33`); no cycle (`flow_persistence_service` imports `validation.model`, `flow_model`, `variant_execution_service`, `workspace` only). `session` adds no edge (its input is the `project_dir` `resolve_chip_target` already receives). `flow_screens → insight_style` exists (`flow_screens.py:70`). View → services direction unchanged; no service imports a view.

**Parallelisation verdict (mechanical): sequential.** Inc 1 ∩ Inc 2 = {`screens_directionb.py`, `app.py`, `window_help.py`, `styles.tcss`}; Inc 4 ∩ Inc 5 = {`flow_screens.py`, `app.py`, `window_help.py`, `styles.tcss`}; every pair shares at least `styles.tcss`. Neither exit is taken: a re-cut cannot remove the shared stylesheet / header file, and splitting `styles.tcss` per screen is a boundary move out of proportion for a polish batch. A4 not fired, one worktree.

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R13 | The four panels are re-composed **in place**; no module, no shared "ledger + inspector" widget module | extracting pe_A/ce_A's common layout into a new module | a third ledger + inspector screen — then the shared widget earns its module |
| R14 | `flows` / `session` ride the **project-only limb** of `resolve_chip_target` (the Reports precedent), not `_family_homes` (`:186`, which raises for families without a common home) | inventing a common flows library so they fit `_family_homes` | flows gaining a common (no-project) library |
| R15 | The flows dir is imported (`FLOWS_SUBDIR`), not re-declared | a second `"flows"` literal in `folder_open_service` | — (two homes for one dir is the defect LLR-139.1 forbids) |
| R16 | The burnt-orange CRC token lives in `insight_style.py`, the declared token home (`flow_screens.py:1799`) | a literal in `flow_screens.py` | — |
| R17 | The JSON tab renders `ChangeService.document` through the canonical serialiser | the panel re-serialising its display rows (lossy) or a second writer | — |

**ARQ evidence checklist (architect, self-executed):** constraints — 4 source files per increment, the frozen engine (§7), C-17 for the new file-derived renders (trigger C8) `executed`; alternatives — R13/R14/R17 name the rejected candidates `executed`; where no real decision exists (R15, R16) the row says so instead of inventing one; risks — the Reports-worded status for new project-only families (I-1), the chip id collision (below), line drift in the handoff (E-2), listed; cost/latency `n/a — local TUI, no runtime cost`; diagram `n/a — no new edge beyond one sibling import`; two-layer chains owed at P1.

**Open for PDR:** (1) the Check Editor's chip reuses family `checks`, so its id `open_folder_checks` (`open_folder_chip.py:77`) duplicates the Checks screen's (`app.py:2321`) — `#id` lookups such as `_RAIL_CHIPS` become ambiguous; scope or suffix the id. (2) Is `flows` / `session` offered the create-on-press (`_CREATABLE_FAMILIES`, `:86`)? (3) I-2/I-3 call shape: a keyword with the `mem_map` sentinel idiom vs a separate setter. (4) R-5.1's premise: shipped flow code paints **no** CRC family colour and the wait state uses `YELLOW #f6ff8f` (`_S_PAUSE`, `flow_screens.py:1800`), not amber `#d9a35b` — the "replace" is a prototype-kit fact (`_flows_kit.py:55`); the token is new and the wait colour must be confirmed.

### Batch-99 declarations — read/write integrity (no module created, no boundary moved)

*`2026-10-25-batch-99` (US-141..US-151: the HIGH findings H-1..H-10 of `.dev-flow/design/INVESTIGATION-read-write-integrity-2026-10-22.md`, PH-3 (its H-3 row) of `INVESTIGATION-project-roundtrip-2026-10-23.md`, CW-D-4 / CW-D-7 / CW-D-10 of `AUDIT-codewire-data-2026-10-23.md`, and the `_load_from_item` sibling of CW-U-1). Triggers A2 + A3 fired; A1 and B2 not fired; A4 (fork) evaluated and **not recommended**. **Landed at `e7732f6`** (all 12 increments merged; DDR `design/DDR-architect.md`). "Inc" names the increment that landed each row; the Paths column is the **as-built** set, per `git show --stat` of each commit. Line numbers are re-located at HEAD `307065f` (the investigations cite `9793fcd`). The `LoadedFile.mem_map` writer census, the pairwise parallelisation matrix and the re-cuts live in the batch record's `design/ARQ-batch-99.md`.*

**No boundary move — evidence.** Every path below already exists under `s19_app/**` (product) or is new under `tests/**` (tests); `git status --short s19_app/ tests/` at ARQ is empty, and no symbol changes address. The six-module table and the batch-92/94/97 declarations stand unchanged. One path correction to the draft: the export helper is `s19_app/segment_ops.py` (app-root, still product), not `tui/segment_ops.py`.

**Frozen-engine crossing (§7) — called out here, owed to P1.** Inc 2 and Inc 9 change `s19_app/core.py`, Inc 9 changes `s19_app/hexfile.py`, Inc 10 changes `s19_app/tui/a2l.py`. §7 permits this but requires the requirements phase to name the crossing: each of those LLRs must say so.

| Inc | Story | Paths as built (all CHANGED unless marked NEW) | What the change encapsulates |
|---|---|---|---|
| 1 `a52e2be` | US-141 | NEW `tests/fixtures/synth/**` (generator + manifest + files) · NEW `tests/support/independent_reader.py` | the corpus that holds its own oracle, and a reader sharing no code with `s19_app` — **0 product files** |
| 2 `c62c842` | US-142 | `s19_app/core.py` · `s19_app/render/hexview.py` | only S1/S2/S3 data records feed the image, its ranges, validity and overlaps; S0 stays in `LoadedFile.source_s0_header` |
| 3a `f1ba70c` | US-144 + PH-3 | `s19_app/tui/changes/apply.py` · `s19_app/tui/changes/io.py` · `s19_app/tui/workspace.py` · `s19_app/tui/app.py` | one private staging location per write; race-free exclusive placement (LLR-155.1..155.4, 155.7); Save project survives a missing source |
| 3b `4ee51a6` | US-144 | `s19_app/tui/services/flow_execution_service.py` · `s19_app/tui/services/project_gather_service.py` (the delete-and-recopy now places through `copy_into_workarea`, LED .7) · `s19_app/tui/app.py` (status paint, 3b review F2) | the chain-set start check (D7, LLR-155.5), the WRITE-OUT verify (D9, LLR-155.6), and the immutability invariant for placed final names (LLR-155.3) |
| 4 `c58b02d` | US-146 | `s19_app/tui/services/change_service.py` · `s19_app/tui/app.py` (final save-back status, UX-C6) | the editor image = source + current document; `models.py` untouched |
| 5 `e7732f6` | US-148 + LLR-155.8 | `s19_app/tui/operations/crc.py` · `s19_app/tui/services/flow_execution_service.py` · `s19_app/tui/flow_screens.py` (`_crc_absent_note`, lane rider) | a region with 0 present bytes fails closed; partial coverage names the absent count; the count travels on the CRC region result (R23) |
| 6 `87dcd3a` | US-149 | `s19_app/tui/segment_split_view.py` · `s19_app/tui/workspace.py` (`place_group_into_workarea`); **`s19_app/segment_ops.py` untouched** | sanitised names, containment under the destination, coverage read from `ranges`, BIN + sidecar placed as one group; bytes come from `emit_bin_from_mem_map` / `bin_addr_sidecar` |
| 7 `d62b0c1` | US-151 | `s19_app/tui/app.py` · `s19_app/tui/workspace.py` (`RESERVED_WORKAREA_HOMES`) | load the picked item by name; the project list shows projects only |
| 8 `7ffad92` | US-145 | `s19_app/tui/services/flow_execution_service.py` · `s19_app/tui/services/flow_report_service.py` · `s19_app/tui/flow_screens.py` | the PATCH status follows the dispositions; every run record carries what was not applied |
| 9 `725d474` | US-143 | `s19_app/core.py` · `s19_app/hexfile.py` · `s19_app/tui/services/flow_execution_service.py` · `s19_app/tui/app.py` (interactive load status, UX-C7) | terminator / EOF / count defects reported as stable notice codes; `SRecord` parses S6 |
| 10 `9d7fb18` | US-147 | `s19_app/tui/a2l.py` · `s19_app/tui/app.py` (the `n/a` cell, UX-C8); `change_service.py` untouched | ASAM conversion direction and module byte order, both ways |
| 11 `5021bb6` | US-150 | `s19_app/tui/services/change_service.py` · `s19_app/tui/screens_directionb.py` · `s19_app/tui/window_help.py` | one base per Bytes field (D1) |

Merge order was 1, 2, 11, 10, 9, 4, 3a, 8, 7, 3b, 6, 5 (`git log 307065f..e7732f6`); the numbering above is the plan's, not the merge order. Every commit stays within 4 source files.

**Dependencies.** No new edge is required. `render/hexview → core` exists and is allowed (batch-92 declaration). One edge, permitted direction, **decided at PDR and landed** (`segment_split_view.py:72-83`): `tui/segment_split_view → tui/workspace` (reuse of the name-sanitising / containment helpers for US-149 and of the B99-I2 / B99-I2a placement). `segment_split_view → services/project_gather_service._check_home_contained` was declared in B99-I6. `changes/apply.py`, `changes/io.py` and `operations/crc.py` already imported `workspace`; only the symbol `_private_stage_dir` is new. No service imports a view; no view imports a service it did not already import.

Rationale (structural decisions):

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R18 | One data-record predicate, defined once in `core.py` and imported by `render/hexview.py`, gates all six record walks | patching each walk separately | The two builders duplicated the record walk, which is how both leaked S0; one predicate is one place to be wrong. Re-open: a format whose data records are not S1/S2/S3 (none in scope). |
| R19 | `copy_into_workarea` keeps its parameters and its B8 byte-identical reuse; only its placement becomes exclusive (claim the name with `O_CREAT \| O_EXCL`, then `os.replace` from a private staging directory). **As built (LLR-155.1):** every writer stages in `tempfile.mkdtemp` under `temp/.staging/stage-*`, with both levels (`temp`, `temp/.staging`) checked for reparse points, so the placed name stays `safe_name` | a new placement function used by the writers only; `tempfile.mkstemp` as the staged file | 13 call sites (load-into-temp, project save, flow persistence, CRC write) share the same check-then-copy race; one internal fix covers all of them with zero caller edits. `mkstemp` alone would change the placed name, because the target is named after the source (`workspace.py:349`). Re-open: a caller that needs overwrite semantics (M-5, D8). |
| R20 | US-146 restores the image **in place** (the same dict object), never rebinds `LoadedFile.mem_map` | building a fresh dict per apply | The dict is shared by the merged `LoadedFile`s (`app.py:9894`, `:9946`, `replace()` at `:1258` / `:1300`) and handed to the Patch panel (`refresh_entries`, `app.py:3289`); a rebind leaves those holders on the stale map. |
| R21 | Export coverage is read from `ranges`, the source the confirm already reads | removing the MAC placeholder map (`app.py:9698`) | The placeholder map has other readers (MAC overlay); the defect is the writer reading a different source than the confirm. Re-open: a requirement that defines the MAC map (the audit found none). |
| R22 | `ChainRunOutcome` gains fields with default factories, copied from `FlowRunResult`, which already carries `change_records` / `refusals` / `image_ranges` (`flow_model.py:748-758`) | a second record type for chain-set runs | One constructor site (`:1531`); every test that builds the outcome stays valid. |
| R23 | **Decided at PDR, landed Inc 5:** the CRC coverage count travels on the CRC region result, so the flow arm, `write_crc_image` (`:1325`) and the operation execute path (`:1539`) read one number | the flow arm calling `crc_diagnostics` only | `crc_diagnostics` is silent for legacy regions and the flow arm does not call it today (H-7). |

**Parallelisation verdict (mechanical): sequential, one worktree.** At file granularity (the batch-92 precedent inside product), the non-empty intersections are Inc 2 ∩ 9 = {`core.py`}, Inc 3 ∩ 7 = {`app.py`}, Inc 4 ∩ 11 = {`change_service.py`}, Inc 5 ∩ 8 = {`flow_execution_service.py`}, plus conditional ones under D4 / D6. Four file-disjoint lanes exist on paper ({2,9} · {3,7,6} · {4,11,10} · {5,8}, Inc 1 first), but every increment is 1–3 source files, Inc 1's reader and Inc 2's S0 change feed the whole test suite, four increments wait on decisions D1–D6, and a worktree runs the main checkout's package under `pip -e` unless `PYTHONPATH` points at it. Matrix and reasons: `design/ARQ-batch-99.md` §3.

**ARQ evidence checklist (architect, self-executed):** constraints — 4 source files per increment, the frozen engine (§7), public-repo wording `executed`; alternatives — R19/R20/R21/R23 name the rejected candidates; where no real decision exists (R22) the row says so; risks — the S0 change rippling through range counts and snapshot baselines, the 0-byte name claim left by a crash between claim and replace, the `before_bytes` meaning change under US-146, listed in the batch record; cost/latency `n/a — local TUI, no runtime cost`; diagram `n/a — no new edge`; two-layer chains owed at P1.

### Batch-100 declarations — Load + projects (no module created, no boundary moved)

*`2026-10-26-batch-100`: the open project round-trip findings of `.dev-flow/design/INVESTIGATION-project-roundtrip-2026-10-23.md` (PH-1, PH-2, PH-4, PH-5, M-1..M-7, L-2, L-4), the unified Load dialog, G-005, CW-U-2/5/12/13, reserved project names and the progress indicator (N5). Operator decisions D1–D7 are in `design/veredicto-b100.json`. Triggers A2 + A3 fired; A1 and A4 not fired. **Planned at ARQ, base `1d677ba`; nothing landed.** The Paths column is the **planned** set. DDR replaces it with the as-built set, as batch-99 did. The session-state inventory, the reader census, the reuse rule, the re-cuts and the open decisions O-1..O-11 live in the batch record's `design/ARQ-batch-100.md`.*

**No boundary move — evidence.** Every path below already exists under `s19_app/**` (product). No file is created, and no symbol changes address. The six-module table and the batch-92/94/97/99 declarations stand unchanged. **A1 not fired:** the recent-sources store is two functions in `tui/workspace.py` (R31), not a new module. **No §7 crossing:** no increment touches `core.py`, `hexfile.py` or `tui/a2l.py`.

| Inc | Story / finding | Paths (planned; all CHANGED) — **round-2 re-derivation** (P2 architect r2 §3, `P2-dispositions-r2.md`) | What the change encapsulates | # |
|---|---|---|---|---|
| 1 | M-1, G-005 | `s19_app/tui/workspace.py` · `s19_app/tui/segment_split_view.py` · `s19_app/tui/app.py` | `find_identical`, `place_into_workarea` → `PlacementResult`, `predict_placement`, this-work-area containment inside the placement (B100-I13, I14, I22; B100-I6 amended); the export's `reused` word from the placement; the "Added variant" status for a reused file; tc018 / at031b / tc_b99_31 re-pinned | 3 |
| 2 | M-4, M-7, reserved and device names, L-3 rest | `s19_app/tui/app.py` · `s19_app/tui/workspace.py` | name rules (B100-I11): case-folded reserved and device names (one predicate), 64-character cap plus the full-path check, disguised clash refused, one `OSError` handler, no folder left by a refused save. The exact-name **merge** arm with full carry is at Inc 8a (B-06) | 2 |
| 3 | PH-2 | `s19_app/tui/app.py` | `_reset_project_session()` (B100-I4: S1–S13 + the 11 probe names) and `_session_snapshot()` (B100-I19) | 1 |
| 4 | CW-U-2 | `s19_app/tui/app.py` | focus targets per window; the load tails re-home the focus. Modal-close arms move to the increment of each modal (B-06) | 1 |
| 5 | PH-1, D1, R-PC | `s19_app/tui/app.py` · `s19_app/tui/services/change_service.py` · `s19_app/tui/services/project_gather_service.py` | the `save_patched` split (B100-I15) and the emit decision on data (B-01); the unsaved-state predicate (B100-I18); the save plan (B100-I17) executed by the handler | 3 |
| 6 | PH-4, D2, O-1, P-E | `s19_app/tui/app.py` · `s19_app/tui/services/variant_execution_service.py` · `s19_app/tui/screens.py` (+ `s19_app/tui/styles.tcss` for the panel) | save-back becomes `active_variant`; every in-project writer carries every key it does not own (B100-I7); the reader parses `gathered`; the Load-result panel and `compose_load_announcement` | 3–4 |
| 7 | PH-5, L-4, D3, O-2, O-11, UX-26 | `s19_app/tui/services/manifest_writer.py` · `s19_app/tui/services/variant_execution_service.py` · `s19_app/tui/app.py` (+ `s19_app/tui/services/project_gather_service.py` for the plan's `files` row) | `files`, the problem kinds and their merge (B100-I3), the caps and the manifest-keys mode (B100-I2, I21), private staging, `derived_from` (B100-I16) and the panel's comparison against it | 3–4 |
| 8a | M-2, D4, Q-5 | `s19_app/tui/app.py` · `s19_app/tui/services/manifest_writer.py` · `s19_app/tui/services/variant_execution_service.py` · `s19_app/tui/services/project_gather_service.py` | `active_document` recorded and reopened; the app writes a pasted document as `patches/changes.json`; the merge arm with full carry (B-06) | **4 (at cap)** |
| 8b | M-3 D5, M-6 D6, M-5 D7 (handler), S-02 | `s19_app/tui/app.py` · `s19_app/tui/services/project_gather_service.py` · `s19_app/tui/workspace.py` | save-as copies every sub-folder without following links, with a free-space check; an A2L-only project opens; the parent must be this work area (B100-I10); the listing and load uses of `contained_in_workarea` | 3 |
| 9a | Load request (data), L-2, S-16 | `s19_app/tui/workspace.py` · `s19_app/tui/app.py` | the per-user recent store (B100-I9); one work-area lister; a typed project path routes to the project load; reserved homes never load | 2 |
| 9b | Load dialog (P-A C), D10, CW-U-12/13 | `s19_app/tui/screens.py` · `s19_app/tui/app.py` · `s19_app/tui/styles.tcss` (+ `s19_app/tui/services/variant_execution_service.py` if the shared "what installs" function lives there) | the two-pane dialog, `LoadChoice` (B100-I8), `p` opens it, `LoadProjectScreen` retires | 3–4 |
| 10 | CW-U-5 (P-B A) | `s19_app/tui/screens.py` · `s19_app/tui/app.py` · `s19_app/tui/styles.tcss` (+ `s19_app/tui/screens_directionb.py` for a public dirty-flag accessor) | the one load seam (B100-I20) over the four image-replacing routes | 3–4 |
| 11 | M-4 preview, D7 dialog half (P-C B) | `s19_app/tui/screens.py` · `s19_app/tui/app.py` · `s19_app/tui/styles.tcss` | the Save dialog paints the save plan (B100-I17); no parent field, no Browse… | 3 |
| 12a + 12b (one unit) | N5 (P-D A), O-7, R-PD | `s19_app/tui/app.py` · `s19_app/tui/styles.tcss` (+ `s19_app/tui/screens.py`) | the keyed busy seam and its action table (B100-I12); project load, Save project and the A2L parse on workers (Save's re-derive on the main thread, emit on the worker through B100-I15) | 2–3 |

Every planned increment stays within 4 source files (`styles.tcss` counted). Inc 8a is at the cap with no slack, and Inc 6, 7, 9b and 10 reach 4 only through the bracketed conditional file. Each conditional is decided at PDR and recorded in that increment's packet. Inc 8 as drafted reached 5 and is split into 8a/8b. Inc 9 is split to keep the prototype-free half apart, and 12a/12b land together (R-PD). The ARQ-gate (round-1) table is in git at `11763af`.

**Dependencies.** No new edge. Every import the plan needs exists at `1d677ba`:
- `app → changes.io` (`write_change_document`, `app.py:41-46`)
- `app → services/manifest_writer` (`:154-155`)
- `app → services/variant_execution_service` (`:175-179`)
- `services/manifest_writer → services/variant_execution_service` (`manifest_writer.py:59-64`)
- `services/project_gather_service → workspace` (`project_gather_service.py:70-75`)

`hashlib` is stdlib. No service imports a view.

*Round 2:* still no new edge.
- The save plan takes the emitted image's digest as an input, so `project_gather_service` does not import `changes` or `change_service`.
- The app writes the pasted document through the existing `app → changes.io` edge.
- The manifest-keys mode, the one load seam and the containment helper live in files that already hold their callers' imports.

Rationale (structural decisions):

| # | Decision | Alternative rejected | What would re-open it |
|---|---|---|---|
| R24 | PH-2 is closed by **one** seam, `_reset_project_session()`, called only by `_handle_load_project` after validation and before the first install. The change service is **rebound** (`self._change_service = ChangeService()` + `set_image_generation`) | a `ChangeService.reset()` that lists ~14 fields; resets spread across the load path | The service is constructed once (`app.py:1600`) and never handed to another holder (`grep "_change_service[,)]"` → 0), so a new object is complete by construction. A hand-listed reset decays with the next field. Re-open: a second holder of the service appears. |
| R25 | The app-side reset set is guarded by a **derived** set (`vars(app)` diff, cold load vs load-over, with an allow-list of the kept counters and preferences), not a hand-written list of attributes (C-31) | an AT that checks the three observed leaks (MAC, A2L, entries) | the observed leaks are three of at least nine latent members (`_last_template_path`, `_diff_*`, `_last_flow_run`, `current_a2l_data`, …) |
| R26 | Save project emits a patched image through `ChangeService.save_patched` (B99-I7), triggered by a new public predicate `image_differs_from_source` (journal-based, O(patched addresses)) | `save_patched_image` + `verify_written_image` called from the app (no re-derive); a predicate that re-parses the file via `verify_written_image` | Two save paths with two rules for "the saved image" is the conflict B99-I7 settled, and the predicate is called on every dialog open (Inc 10/11), so it must be cheap. Re-open: the operator rules that Save project must not apply pending entries (O-5/O-6). |
| R27 | `project.json` grows by **additive** keys (`files`, `active_document`), and `schema_version` stays `1` | bump to `2` | the `declared_regions` / `gathered` precedent and the `test_manifest_writer.py:481` pin; the reader accepts any version and reads named keys only. Re-open: a change to an existing key's meaning. |
| R28 | `_write_and_verify_manifest` (`app.py:8272`) is the **one** manifest writer; it computes `files` from disk itself, and the verify drift domain covers the new keys | each caller passing digests; a targeted "update active_variant" writer | a caller with stale digests, or a second serialiser, is how a manifest lies |
| R29 | `files` covers what Load opens (top-level S19/HEX/MAC/A2L + the active document), not the project homes other features write later | digest every file in the folder | a digest of `reports/` or `flows/` drifts by design after any later run (O-2) |
| R30 | M-1: reuse is decided over the **enumerated** set `<name>` ∪ `<stem>_<N><suffix>` (size precheck, then bytes); `place_group_into_workarea` keeps "requested names only" | walking `_<N>` until the first gap; changing the group rule too | A gap hides an identical later copy. The group rule is the batch-99 PDR C3(e) decision, and split exports are not reloaded. |
| R31 | The recent-sources store lives in `tui/workspace.py` (owner of the `.s19tool/` layout), file `.s19tool/recent_sources.json`, at most 20 entries, outside sources only | a new `services/recent_sources_service.py` (fires A1) | recents gaining behaviour (pin, clear, per-project) or a consumer outside `app.py` |
| R32 | The unified dialog returns one tagged result `LoadChoice(kind, value)`, routed by one app handler; a work-area pick loads in place (no second copy) | keeping two modals behind one key | two result contracts and two routers are how Load file and Load project drifted (L-2) |
| R33 | The progress seam widens `set_progress` (`app.py:13615`) into begin/step/end with one main-thread timer; main-thread actions paint once via `call_after_refresh` | a modal progress screen per action; a timer per worker | an indicator cannot tick while the main thread is blocked; which actions move to workers is O-7 |
| R25a | *(round 2, amends R25)* the leak guard compares `_session_snapshot()`, whose domain is derived from the names `S19TuiApp`'s source assigns (minus declared Textual internals) | a hand-listed 12-kind projection | the round-1 probe: `vars(app)` holds 178 names, 31 of them framework, and 11 app-owned names differed outside the inventory |
| R26a | *(round 2, amends R26)* Save project emits iff re-deriving the **change** document onto a copy changes the data (B100-I15); `save_patched` is split, not bypassed, so B99-I7 stays one rule | the "differs or document has entries" trigger of round 2; `save_patched_image` called from the app | a check document blocked every Save project (B-01, executed) |
| R31a | *(round 2, amends R31)* the recent store moves to `%APPDATA%\s19_app\recent_sources.json` (operator decision on S-16) | keeping it under `.s19tool/` | zipping or syncing `.s19tool` shared absolute local paths |
| R34 | one save plan, painted by the dialog and executed by the handler; its names come from `predict_placement`, the placement code itself (B100-I17, I22) | a dialog preview computed separately; a plan with its own name logic | the operator's P-C note: an error here overwrites or renames work |
| R35 | every placement guard lives in `place_into_workarea`; `copy_into_workarea` is a one-line wrapper (B100-I13, I14) | changing `copy_into_workarea`'s return type (15 call sites); a containment check per writer | per-writer checks drift; the wrapper keeps every caller covered by construction |
| R36 | one load seam asks for every image-replacing route (B100-I20) | the question in the Load dialog's router only | the rail pick and the variant switch replaced an unsaved image with no question (B-02) |
| R37 | the path tightening is a manifest-keys **mode** of the shared check (B100-I21) | tightening the shared predicate for every caller | it broke a batch-97 flow-reference test (B-03, executed) |

**Parallelisation verdict (mechanical): sequential, one worktree per increment.** `app.py` is in every increment except Inc 1, so every pair among 2…12b intersects. Inc 1 is disjoint from all but 2 and 9a (`workspace.py`) and lands first. A re-cut cannot remove `app.py`, and splitting it is out of proportion, so neither exit is taken. A4 not fired. Hard order and prototype gates: `design/ARQ-batch-100.md` §8; the pairwise reasoning is in §9.

**ARQ evidence checklist (architect, self-executed):**
- Constraints `executed`: 4 source files per increment (the re-cuts 8a/8b, 9a/9b, 12a/12b), frozen B99-I2 / B99-I7 / batch-97 I-7, no §7 crossing, public-repo wording.
- Alternatives: R24, R26, R27, R30, R31, R32, R33 name the rejected candidates.
- Risks are listed in the batch record §11: Save applying pending entries, manifest rewrite amplification, main-thread hash cost (estimated, not measured), reuse widening, older builds dropping the new keys, the C8 exposure in two list builders, the threading change under 12b.
- Cost/latency: hashing `planned` (estimate only); runtime cost `n/a — local TUI`.
- Diagram: the Load-project sequence in the batch record §3.4.
- Two-layer chains owed at P1.

## 11. Interfaces — the contracts between modules

**Changing one of these is trigger A3** — it fires ARQ, PDR *and* DDR, and it is never done inside a
lane. A **frozen** interface is one the current batch committed to at PDR: no lane touches it; the
work returns to the trunk instead.

The rows below are the project's declared **Information Flow Contracts** (C-54 Part B). They are not
prose: each is a `COMPONENT` block in a batch record, and `V19` confirms all three are declared
exactly once, `V11` that all **79** outputs carry an address and a consumer list.

| Interface | Owner module | Consumers | Shape | Frozen? |
|---|---|---|---|---|
| `loaded_panel` — Part B contract | product | **18** declared | **6** outputs; `PARENT : screen_workspace` | **✅ frozen for `2026-08-24-batch-88`** |
| `screen_workspace` — Part B contract | product | **94** declared | **31** outputs; `PARENT : workspace_body` | **✅ frozen for `2026-08-24-batch-88`** |
| `workspace_body` — Part B contract | product | **139** declared | **42** outputs; `PARENT : workspace_shell` | **✅ frozen for `2026-08-24-batch-88`** |

**The containment chain, which is what balancing checks:**
`workspace_shell` → `workspace_body` → `screen_workspace` → `loaded_panel`.
`workspace_shell` is the outermost declared parent and is **not** itself a `COMPONENT` — it is the
shell boundary, and `SYSTEM` was **refuted** as its value by measurement at `app.py:1919`.

**Why all three are frozen for this batch.** batch-88 does not change any contract; it adds Layer C
verification rows that **cite** them. An interface a batch reads but does not touch is exactly what
"frozen" means, and it is what gives the new rule real consumers instead of a synthetic fixture.

**Note for whoever implements the Layer C rule.** Key it on **this table's shape** — the column
header `Frozen?` — and never on a section number. Section numbers differ per project (the template
calls this viewpoint §4; here it is §11) and a rule that keys on a number is broken by any project
that numbers its map differently, which is every project that had a map before adopting the template.

**Batch-92 interface amendments** (from `2026-10-11-batch-92`; the table above is the Part B
contracts, these four are sub-module surface contracts of the same kind — changing any of them is
trigger A3 and is never done inside a lane):

| Surface | Owner | Contract | Frozen? |
|---|---|---|---|
| `render.hexview` surface | product (`s19_app/render/hexview.py`) | the 9 functions + 5 constants declared in §10, consumed as plain data (`Text`/`str`) by both views and report emitters; a name/signature change is trigger A3 | **✅ frozen at PDR for `2026-10-11-batch-92`** once Inc-A lands; Inc-B must not touch it |
| `render.format` surface | product (`s19_app/render/format.py`) | `microbar`, `MICROBAR_FILLED`, `MICROBAR_EMPTY`, `GREEN`, `LABEL`, `VALUE` — same plain-data rule | **✅ frozen at PDR for `2026-10-11-batch-92`** after Inc-B |
| `utils.safe_text` contract | product (`s19_app/utils.py`) | **security contract** (context viewpoint feeding the security family): delete every C0/DEL/C1 codepoint (`_CONTROL_SCRUB`, LLR-116.7), wrap the remainder as a literal `Text` — never `Text.from_markup` (C-17). The batch-77 precedent stands: the move must not weaken or split the two halves. Oracle: the hostile-input acceptance tests (`tests/test_tui_hostile_map.py`, `test_tui_checks_view.py`, `test_tui_issues_view.py`) | standing contract, carried with the function to its new address |
| `tui/__init__` re-export surface | product (`s19_app/tui/__init__.py`) | the 3 range_index names are **removed** (US-92-2, breaking-by-design, consumer set fully enumerated in the batch record §5); the renderer names stay, repointed to `render.hexview` | change lands with batch-92 Inc-A |

**Batch-94 interface amendments** (from `2026-10-12-batch-94`; landed — all five froze at their named increments (`PDR-2026-10-12-batch-94#D1`–`#D5`); changing any of them is trigger A3 and is never done inside a lane):

| Surface | Owner | Contract | Frozen? |
|---|---|---|---|
| `PatchEditorPanel.ActionRequested` contract | product (`s19_app/tui/screens_directionb.py`) | the message family the panel emits and `app.py`/`screens.py` consume (edit-json requests, entry edit-json, variant help — the variant request **retires** with the variant selector, US-002); the split adds the ce_a twin's sibling messages. Consumer set enumerated at P1 | **✅ frozen at Inc-001** (`PDR-2026-10-12-batch-94#D1`) |
| `.chk.json` artifact contract | product (`s19_app/tui/changes/io.py`) | the v2 grammar with `kind="check"`, distinguished from patch files by **suffix** in the A2B Diff dropdown listing; **write/validate only — never applied** (`apply.py`'s `kind != "change"` gate is the enforcement, not convention); consumed by the A2B Diff report builder (provenance in report) | **✅ frozen at Inc-001** (`PDR-2026-10-12-batch-94#D2`) |
| `flow_screens` module surface | product (`s19_app/tui/flow_screens.py`) | the two panel classes + message types of R8; `FlowBuilderPanel`'s address change is B2 — the reader census output landed in Inc-002's packet | **✅ frozen at Inc-002** (`PDR-2026-10-12-batch-94#D3`) |
| flow template / chain-set artifacts | product (`s19_app/tui/services/flow_*`) | the persisted JSON shapes: builder templates (flow save/load) and chain-sets (chains + inputs + outputs, US-007); input provenance recorded per run in the report (operator decision D1); sequential(default)/parallel-per-chain control (D4) | **✅ frozen in halves — template at Inc-002, chain-set at Inc-003** (`PDR-2026-10-12-batch-94#D4`) |
| rail invariant | product (`s19_app/tui/app.py`) | "exactly ten ordered items bound to `1`–`0`" became twelve surfaces (`=` Check Editor, `]` Flow Execution, both `show=False`); the census constants (`EXPECTED_RAIL`, screen counts) moved with the landing increments — 11 at Inc-001, 12 at Inc-003 — never before (a census updated early green-lights nothing) | **✅ frozen complete at Inc-003 (12 entries)** (`PDR-2026-10-12-batch-94#D5`) |

**Batch-97 interface amendments** (from `2026-10-19-batch-97`; copied verbatim from `design/design-proposal.md` §4 at Inc-1, the PDR's freeze record `PDR-2026-10-19-batch-97`. I-1 landed at Inc-1; I-2..I-9 land at the increments their rows name. Changing any of them after PDR is trigger A3 and is never done inside a lane):

| Interface | Current | After | Consumers | **Frozen for the fork?** |
|---|---|---|---|---|
| I-1 chip families (`folder_open_service.py:57-90`, `open_folder_chip.py:59`) | 4 families; `REPORTS_NO_PROJECT_REASON` for any `None`; `OpenFolderChip(family)`; guard = `exists()` | + `CHIP_FAMILY_FLOWS`, `CHIP_FAMILY_SESSION` (`CHIP_FAMILIES` = 6); `no_project_reason(family) -> str` (the Reports constant kept, equal to `no_project_reason("reports")`); `_CREATABLE_FAMILIES` removed — nothing reads it (Code-Wire H-C2): create-on-press is offered for every non-`None` target except `session`, whose target is the project directory and is never created; `chip_family_root(project_dir, base_dir) -> Path` — the ONE producer of the guard's trust anchor (project dir, else `base_dir / WORKAREA_DIRNAME`, §1.3 "family root"; H-C3); `is_openable_chip_dir(target, root) -> bool`; `OpenFolderChip(family, *, id_suffix=None)`; label `📂 Open <folder>/` where `<folder>` is the leaf of the folder the chip resolves to — the family constant with a project, `patches` for the no-project `checks` chip, whose common home is `workarea/patches` (LED-.6, H-C1) — and `📂 Open session`; the no-project `session` chip is disabled with `📂 Open session: no active project — load a project first.` (LLR-148.3, H-C3) (PC-20) | `open_folder_chip.py`, `app.py` headers + refresh loop `:12756`, `screens.py:1668`, `tests/test_open_folder_chips.py` | **yes — frozen at PDR**, lands Inc-1; Inc-3/5/6 consume it unchanged |
| I-2/I-3 `PatchEditorPanel.refresh_entries(rows, mem_map=_UNSET)` (`screens_directionb.py:6104`) | rows + map; no identity, no JSON feed | `refresh_entries(rows, mem_map=_UNSET, document=_UNSET)`; `document: PatchDocumentView` (D1/D2) | `app.py:3265, :3451, :5279, :10758`; the panel's own `:5662`; 27 test calls in 6 files (the keyword default keeps them valid) | **yes — frozen at PDR**, lands Inc-4 |
| I-4 `window_help.SHIPPED_WINDOW_KEYS` (`:270`) | 8 keys | + `check_editor` (Inc-3), + `flow_execution` (Inc-6) | `tests/test_window_usage_help.py:250`, `_EXPECTED_KEYS` (`:95-107`), `tests/test_changes_file_notation_help.py`, the `WindowHelpChip` sites | **names frozen at PDR**; membership lands per increment |
| I-5 tokens (`insight_style.py`) | none | `WAITING_HUMAN`, `CRC_FAMILY` + the TCSS mirrors | `flow_screens.py`, `styles.tcss`, TC-B97-18 / 52 | **yes — frozen at PDR**, lands Inc-2 |
| I-6 NUL refusal in `load_flow_json`, `load_chain_set`, `_resolve_manifest_entry` | raise `ValueError` (P-36, P-50) | the shipped refusal shapes with `FLOW-UNSAFE-REF` / `CHAIN-SET-UNSAFE-REF` / `MANIFEST-PATH-ESCAPE`; `stat()` guards catch `(OSError, ValueError)` | `app.py` load / import / run handlers; the panels' refusal renders | **yes — return shapes unchanged** (batch-94 `#D4` artifacts untouched), lands Inc-2 |
| I-7 `FlowExecutionPanel` surface | `#fx_mode` is a `Select`; `apply_confirmed_run` always sets `paused_block = None`; the confirm handler sends one confirmation; no attention state | `#fx_mode` is a toggle `Button` (`ModeToggle`); `mode` property; `confirm_attention() -> str` (one of the three I-9 lines); `lane_paint_plain()` kept over the new lane. **Amended 2026-10-22 before Inc-6 and landed at Inc-6:** `confirmed_blocks(lane_index) -> tuple[int, ...]`; `render_confirm_error(lane_index, line)`; `apply_confirmed_run` derives `fail_block` / `paused_block` as `render_run` does and re-arms the attention; the panel alone owns the attention state (per lane `paused_block`, `confirmed`; panel-wide `_attention`, `_attention_block`, `_attention_since`, `_run_start`), `_rearm_attention()` its only writer, the dwell stamped after the attention paint (`_fx_clock`); the app's confirm handler sends one `ExternalStepConfirmation` per confirmed block, so a lane with two external steps ends; Run and every Confirm are disabled while a run or a confirm re-run is in flight (D14), and every exit of both handlers ends in a painter that enables them; one log composer serves the set run and the re-run | `app.py`; `tests/test_tui_flow_execution_b94.py:626, :693` (rewritten Inc-6) | **yes — frozen at PDR**; message types stay frozen by batch-94 `#D3` (`ExternalStepConfirmed(lane_index, block_index)` unchanged) |
| I-11 `S19TuiApp.check_action` (batch-97, amended 2026-10-22, PC-13) | no `check_action` override | created at Inc-6 with one arm: `confirm_attention` → `_active_screen_key == "flow_execution"`; every other action falls through to `App.check_action`; `Binding("c", "confirm_attention", "Confirm", show=False)` in `S19TuiApp.BINDINGS`; Inc-8 (as built) adds D28's arms — `page_next_context` / `page_prev_context` → `_active_screen_key in ("a2l", "mac")`, `hex_page_prev` / `hex_page_next` → `== "workspace"` — `Binding("period", …, key_display=".")`, and the key bar: `KeyBar` `#key_bar` (dock bottom, height 2; rows `#key_bar_global`, `#key_bar_window`) replaces `Footer`, packed by `pack_key_row(tokens, width, *, keep, more, styles=None) -> PackedRow(text, hits, dropped, dimmed=())`; a click runs `app.run_action(action)` or `owner_widget.run_action(action)`, never `simulate_key`; colours through `key-bar--key` / `--description` / `--tag` / `--separator` in the `/* batch-97 key bar */` section of `styles.tcss`; `S19TuiApp.key_condition(when)` evaluates the table's conditions; repaint on `Screen.bindings_updated_signal`, `app.refresh_bindings()` at the end of `action_show_screen` / `action_open_split_join_export`, in `watch_current_file`, in `_patch_document_view` and in the `_variant_set` property setter (PC-23) | `app.py` (`action_confirm_attention`, the ^K palette's `Confirm` entry), Inc-8's key bar | **yes — frozen at the 2026-10-20 delta**, first arm lands Inc-6 |
| I-10 the window-key table (`window_help.py`, batch-97 Inc-8) | no table; keys only in `S19TuiApp.BINDINGS` (P-62) | `KeyEntry(key, when=None, owner=None)` (frozen dataclass); `GLOBAL_KEYS` (7 keys + the command-palette token); `WINDOW_KEYS` / `WINDOW_GO_KEYS` over the 13 windows (the five rendered rows as frozen at the 2026-10-20 delta; a2l, mac, map, issues, diff, checks, crc_designer, split_join derived from each action's guard, the guards' `file:line` held and asserted by `tests/test_b97_key_bar.py` `DERIVED_GUARDS`); `HELP_KEY_WINDOW`; `KeyToken(key, key_display, label, action, owner, enabled, when, lead, tag)`; `resolve_window_tokens(app, window)` (raises `KeyError` on an unbound key, `ValueError` on an empty description), `global_tokens(app)`, `more_token(app)`, `window_tag(app, window)`, `window_keys_text(app, help_key)` (the help modal's `#window_help_keys` block beneath `#window_help_body`); **amended at the Inc-8 gate (2026-10-23, LED-…97.39 / .41):** an `owner` entry is enabled only while the focus is inside its window and the owner's `check_action` allows its action; a disabled token paints whole in `key-bar--dim` | `KeyBar`, `WindowHelpScreen`, `tests/test_b97_key_bar.py`, TC-B97-32 (parses the keys block) | **yes — frozen at the 2026-10-20 delta**, landed Inc-8; a row edit is a table edit reviewed on the operator's review page |
| I-8 `FlowBuilderPanel.RunRequested` | carries the selector's scope | always `FLOW_SCOPE_SINGLE`; shape unchanged | `app.py:2518` (branch deleted, D8) | **yes — shape frozen** (batch-94 `#D3`) |
| I-9 the NEW names of D12 (ids, classes, constants, vocabularies) | — | as D12 | the batch's TCs / ATs, the `window_help` bodies | **yes — frozen at PDR**; a rename after PDR is A3 |

**Batch-99 interface amendments** (from `2026-10-25-batch-99`; **landed at `e7732f6`; every row frozen** — each froze at the point named in its row (PDR or P1/P2 round) before the increment that built it, and the as-built surface is recorded below (DDR-A3). Consumers measured by `grep -rn` over `s19_app/` + `tests/` at `307065f`. Changing any of them after PDR is trigger A3 and is never done inside a lane):

| Interface | Contract after batch-99 | Consumers | Freeze |
|---|---|---|---|
| B99-I1 the S19 memory-map contract — `S19File.get_memory_map` / `get_memory_ranges` / `get_record_for_address` / `_build_overlap_map` (`core.py:485`, `:496`, `:436`, `:452`) and `build_mem_map_s19` / `build_range_validity_s19` (`render/hexview.py:60`, `:69`) | every address in the map, the ranges, the validity list and the overlap set comes from an S1/S2/S3 record; S0 bytes live only in `LoadedFile.source_s0_header`. **Names and parameters unchanged** (the batch-92 `render.hexview` freeze holds); the meaning changes, so this is A3 (R18) | `load_service.py:59-60` → every S19 `LoadedFile`: app load, flow SOURCE (`flow_execution_service.py:314`, `:727`), variants (`variant_execution_service.py:763`), `compare_service.py:169`, `before_after_service.py:178`, `change_service.py:2356`, `app.py:5863`; the verify reader `changes/verify.py:115` (so verify shares the fix and is **not** an independent oracle — Inc 1's reader is); overlaps `app.py:10433`; `app.py:10612`; re-export `tui/__init__.py:23`; `cli.py`; 32 test files call one of the builders (P1 census of S0-bearing range counts) | Frozen: PDR, before Inc 2. **Landed:** Inc 2 `c62c842` |
| B99-I2 the write placement — `save_patched_image` (`changes/apply.py:625`) and `copy_into_workarea(source, destination, max_size_bytes)` (`workspace.py:262`) | every caller (images, reports, manifests, check specs) stages in a private `mkdtemp` directory under `temp/.staging/` (both levels checked for reparse points) holding the requested name; the final name is claimed with `O_EXCL`, taken names get the next free `_<N>` (B8 reuse of identical bytes kept), the claim handle is closed, then `os.replace` with ≤5 retries in ≤1 s on `PermissionError`; on exhaustion the own claim is removed and `WorkareaPlacementError` (subclass of `WorkareaContainmentError`) is raised, so the `Path` return contract and zero caller edits hold; `source` is never moved; only owned staging is deleted (LLR-155.1/155.2/155.7, P2 round 2) | `save_patched_image`: `change_service.py:1730`, `flow_execution_service.py:519`, `variant_execution_service.py:797`. `copy_into_workarea`: 15 direct call sites at `e7732f6` (`git grep -n "copy_into_workarea("`): `app.py:8173`, `:8178`, `:8181`, `:8591`, `:8622`, `:8630`, `:8652`, `:8755`, `:8826`; `changes/apply.py:781`; `operations/crc.py:1507`; `segment_split_view.py:940`; `services/flow_execution_service.py:1108`; `services/flow_persistence_service.py:1106`; `services/project_gather_service.py:364`; plus the injected path in `changes/io.py` (private stage, `:1602-1624`). **Placement contract, not private (D-3):** `_private_stage_dir`, `_is_reparse_point`, `_find_workarea_root` and `WORKAREA_STAGING_DIRNAME` (`tui/workspace.py`) are part of this contract and are imported by `changes/apply.py`, `changes/io.py`, `operations/crc.py` and `segment_split_view.py`. Each importer repeats stage → `copy_into_workarea` → owned cleanup, so a write stages twice (one extra local copy). Backlog idea: a bytes-in placement entry point that retires the four duplicated blocks (PDR C3(a) recommended bytes in; the proposal chose paths in) | Frozen: PDR, before Inc 3; Inc 6 consumes it unchanged. **Landed:** Inc 3a `f1ba70c` |
| B99-I2a group placement (`tui/workspace.py` `place_group_into_workarea`, NEW) | places several files that must share one stem (a BIN and its `.addr` sidecar) in one call: one private staging directory, one `_<N>` claimed for every name of the group with `O_EXCL` before any is written, then `os.replace` per file; reuse only when every file of the group is byte-identical; same failure contract as B99-I2 (`WorkareaPlacementError`). Inc 6 consumes B99-I2 for single files and B99-I2a for BIN pairs (LLR-160.4, P2 round 3 A3-1) | `segment_split_view.py` only (`:949`). `segment_ops.write_bin_with_sidecar` is **not** a consumer: it is a headless engine API outside HLR-155 placement, bypassed (not converted) by Inc 6, with no product caller (only `tests/test_segment_ops.py` calls it); it stays a direct writer, allow-listed in the TC-B99-13 census | Frozen: P2 round 3. **Landed:** Inc 6 `87dcd3a` |
| B99-I3 `ChainRunOutcome` (`flow_execution_service.py:1366`) and the PATCH block status | `+ change_records`, `+ refusals`, `+ image_ranges` (default factories, copied from `FlowRunResult`, R22); the PATCH `BlockResult.status` derives from the summary dispositions and refusals (rule = D5), no longer the constant `ok`; the chain-set report lists written paths, non-applied records and refusals **Additive (D-8):** `FlowReportState.refusals` (`flow_report_service.py:226`). | lane painter `flow_screens.py:3295-3384`; `write_chain_set_report` `:1661`; `ChainSetRunRecord.outcomes` `:1378`; `app.py:2800`, `:2890` (`run_chain_set` → `render_run`); `flow_report_service.py:316-330`, `:408`; TC-714 (`tests/test_changes_symbol_entries.py:734`) re-pinned; chain-set tests (`test_flow_chainset_b94.py`, `test_b97_flow_execution.py`, …) | Frozen: PDR after D5, before Inc 8. **Landed:** Inc 8 `7ffad92` |
| B99-I4 A2L encode / decode (`tui/a2l.py`) | byte order = tag → RECORD_LAYOUT → `MOD_COMMON BYTE_ORDER` (source and decode coupling = D3); RAT_FUNC is INT = f(PHYS) per ASAM — encode evaluates it, decode inverts it (D2); a COMPU_TAB value whose decode(encode(x)) differs from x is refused or flagged (D4). `encode_physical_to_raw_bytes` (`:2093`) keeps its `(raw_bytes, error, flags)` return | sole product encode consumer `change_service.py:540`; decode consumers inside `a2l.py` (`:2597`, `:2615`, `:2816`, `:2847`, `:2894`, `:2989`, `:2996`); the A2L card `app.py:833`; `tests/test_a2l_record_layout_walker.py`, `test_changes_symbol_entries.py`, `test_tui_a2l_detail.py` | Frozen: PDR after D2–D4, before Inc 10; §7 crossing. **Landed:** Inc 10 `9d7fb18` |
| B99-I5 CRC coverage (`operations/crc.py:757`, `:861`) | a region with 0 present bytes is an error and injects nothing; partial coverage reports the absent count, legacy regions included (carrier = R23, PDR) | flow arm `flow_execution_service.py:646`; `write_crc_image` `:1325`; operation execute `:1539`; the CRC Designer `screens.py:2694` reads the result (its writes stay out of scope) | Frozen: PDR, before Inc 5. **Landed:** Inc 5 `e7732f6` |
| B99-I6 the split / export writer (`segment_split_view.py:534-552`, `:1153`; `segment_ops.py`) | one ASCII allowlist sanitiser builds `<stem>_<segment>` (reserved device names prefixed, segment ≤ 100, basename ≤ 200), BIN `.addr` sidecars included; a plan-time pass refuses case-folded collisions and over-long paths before any write; containment is anchored to the work-area root through `_check_home_contained` (`project_gather_service.py:200`, reused across modules as a declared contract) before any mkdir, refusing links; a zero-coverage file reads coverage from `ranges` and writes header-only S19/HEX; files are placed through B99-I2, a BIN and its sidecar claiming one `_<N>` together (LLR-160.1/160.2/160.4/160.5) **Additive (D-8):** `PlacedExport`, `ExportRefusedError`, `ExportWriteError` (`segment_split_view.py:576`, `:547`, `:562`); `write_split_join_export` returns `List[PlacedExport]` and takes a `declared_ranges` keyword. | `SplitJoinWindow` (`app.py:163`) only | Frozen: PDR, before Inc 6. **Landed:** Inc 6 `87dcd3a` |
| B99-I7 the editor image (`ChangeService.apply` `:1602`, `save_patched` `:1668`) | the image after apply, and the image saved, equal the source plus the document's current entries; the dict is restored in place (R20). `before_bytes` (`apply.py:335`) then means the **source** byte, also on a repeated apply **Additive (D-8):** `ChangeService.source_image_view` (`change_service.py:1878`, consumer `app.py:3950`), `last_save_applied` / `last_save_not_applied` (`:912-913`), `save_back_status_suffix` (`:131`). | `app.py:3221` (apply), `:3378` (save); `before_bytes` readers `report_service.py`, `diff_report_service.py`, `flow_report_service.py`, the before/after card | Frozen: PDR, before Inc 4. **Landed:** Inc 4 `c58b02d` |
| B99-I8 the Bytes token grammar (`change_service.py:170` `parse_new_bytes`) | one base for every token of one field (rule = D1); amends batch-07 LLR-001.2 | `change_service.py:1000` (add / edit entry); `tests/test_change_service.py:600-603`, `test_tui_memory_patch.py:136-144`; the grammar text `window_help.py:84`, `:491`, `:510`; docstring `changes/io.py:18` | Frozen: PDR after D1, before Inc 11. **Landed:** Inc 11 `5021bb6` |
| B99-I9 the project list (`app.py:8314` `list_projects`) and the Workarea Files list (`refresh_files`, `_load_from_item` `:8816`) | lists every work-area folder not named in the constant tuple `RESERVED_WORKAREA_HOMES` (`tui/workspace.py`: `temp`, `patches`, `templates`, `logs`, `crc`, `flows`, `flowsets`, `splits`, `reports`) — P2 round 1 chose a closed reserved set over the `validate_project_files` allow-list so that a legacy project without `project.json` stays listed (LLR-162.2); the Workarea Files list reads the load folder and stores each name on its item (LLR-162.1/162.3) | the Load project dialog `app.py:6544`; `_load_from_item` `:8816` | Frozen: P1 round 2. **Landed:** Inc 7 `d62b0c1` |
| B99-I10 the loader-notice codes (`core.py` `_load`, `hexfile.py` `_load`) | five stable codes `S19-NO-TERMINATOR`, `S19-COUNT-MISMATCH`, `S19-AFTER-TERMINATOR`, `HEX-NO-EOF`, `HEX-AFTER-EOF` in the loaded file's issues; records after the end are counted, never parsed or loaded (LLR-154.1/154.2) | the flow SOURCE arm `flow_execution_service.py:357-372` maps exactly these five to `error` (LLR-154.3); the issues panel | Frozen: P1 round 2. **Landed:** Inc 9 `725d474` |
| B99-I11 the chain-set start check (`flow_execution_service.py:1443` `run_chain_set`) | refuses before any lane runs when two lanes resolve to one output name (case-folded), returning a refusal that names them (D7, LLR-155.5) | `app.py:2800`, `:2890` (chain-set run handlers show it in the status line) | Frozen: P1 round 2. **Landed:** Inc 3b `4ee51a6` |
| B99-I12 the flow WRITE-OUT verify (`flow_execution_service.py` WRITE-OUT arm) | after placement, `verify_written_image` re-reads the file; a mismatch is `error` naming the first differing address (D9, LLR-155.6). Inc 3 then touches `changes/apply.py`, `workspace.py`, `app.py`, `flow_execution_service.py` (the 4-file cap), and creates file intersections 3∩5, 3∩8 with the sequential plan unchanged | the lane cell; the flow report | Frozen: P1 round 2. **Landed:** Inc 3b `4ee51a6` |

**Batch-100 interface amendments** (from `2026-10-26-batch-100`; **planned at ARQ, base `1d677ba`; none frozen yet.** **Amended at P2 round 2:** rows B100-I2..I9, I11 and I12 carry a "Round 2" clause, and B100-I13..I22 are new (P2 architect r2 B-07, `design/P2-dispositions-r2.md`). Each freezes at the point its row names, before the increment that builds it. Consumers were measured by `grep -rn` over `s19_app/` and `grep -rlF --include=*.py` over `tests/` at `1d677ba`. Changing any of them after PDR is trigger A3 and is never done inside a lane):

| Interface | Contract after batch-100 (planned) | Consumers | Freeze |
|---|---|---|---|
| B100-I1 the `project.json` envelope — `serialize_manifest` / `write_project_manifest` / `verify_written_manifest` (`manifest_writer.py:225`, `:414`, `:632`) | + `files`: `{<project-relative POSIX path>: {"size": int, "sha256": "<64 lowercase hex>"}}` over the top-level S19/HEX/MAC/A2L files and the active document (R29); + `active_document`: project-relative path. Both are additive, written only when non-empty, and every key goes through `_reject_unsafe_entry`; `schema_version` stays `1` (R27). The verify drift domain grows from `active_variant` / `batch` / `assignments` (`:717-723`) to include `files` and `active_document`. Output is byte-identical when neither key is passed | `app.py:8344`, `:8365` (the seam, B100-I7); `tests/test_manifest_writer.py` (pins `:99`, `:216`, `:481` stay valid), `test_manifest_verify.py`, `test_tui_manifest_save.py` | Frozen: PDR, before Inc 7 (`files`) / Inc 8a (`active_document`) |
| B100-I2 the manifest reader — `read_project_manifest` / `ProjectManifest` (`variant_execution_service.py:376`, `:160`) | + `gathered: dict[str, list[Path]]` (Inc 6, so the manifest can be rewritten with its composition carried), + `files: dict[Path, FileRecord]` (Inc 7), + `active_document: Optional[Path]` (Inc 8a), + `derived_from` (B100-I16, Inc 7). A malformed record gives one `MANIFEST-BAD-STRUCTURE` and is skipped; an unsafe key gives one `MANIFEST-PATH-ESCAPE`. An absent key → empty, no issue. Unknown keys are still ignored. **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** reads at most 1 MiB (`MANIFEST-SIZE-CAP`) and caps **every** manifest array (`batch`, `assignments`, `declared_regions`, `gathered`, `files`, `derived_from`) at 1 000 entries (security R2-03). A `files` key is accepted only if it is a top-level name with a `PROJECT_DATA_EXTENSIONS \| A2L_EXTENSIONS` suffix or equals `active_document`; `active_document` only under `patches/` or `checks/` with a `.json` suffix. Every manifest key goes through the shared path check in its **manifest-keys mode** (B100-I21) | **content readers:** `app.py:8468` (`_handle_load_project`), `manifest_writer.py:701` (verify re-read), `variant_execution_service.py:672-688`, `:957`; the Load dialog preview (on a worker, bounded read, Inc 9b); **presence-only readers (unaffected):** `app.py:4319`, `:4793`, `:4901`; **predicate-only, default mode (unaffected):** `flow_persistence_service.py:84` and its call sites, `flow_execution_service.py:117` and its call sites (round 2: `flow_execution_service.py` was missing from the ARQ census; measured with `grep -rnF _resolve_manifest_entry s19_app`); 8 test files call `read_project_manifest` | Frozen: PDR, before Inc 6 (`gathered`); the caps and the `files` / `derived_from` rules before Inc 7; `active_document` before Inc 8a |
| B100-I3 the Load-side project check (NEW, `manifest_writer.py`) | `file_record(path) -> FileRecord(size, sha256)` (streamed `hashlib.sha256`) and `check_project_files(project_dir, manifest) -> list[ProjectFileProblem]`. Never raises. **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** returns **manifest and disk** problems only and **parses no image**: `manifest damaged` (parse, size cap, top-level structure, an over-cap array) · `no project.json` · `missing` · `changed on disk` (only `S_ISREG` files are hashed; any other type is `not readable`) · `not recorded` (a top-level data or A2L file absent from a present `files`; restored by A-01 because three writers bypass the seam, `BACKLOG-CODE.md:1468`) · `no digests saved`. `not readable` (load errors or an empty `mem_map`) comes from the install result in `_handle_load_project`, which merges both lists and keeps **one problem per file** by the precedence `manifest damaged` / `no project.json` > `missing` > `not readable` > `changed on disk` > `not recorded` > `no digests saved` (A-05, QA-07). Problems are painted in user terms; the internal code goes to the log only (QA R2-09) | `_handle_load_project` (the merge, LLR-169.9); `compose_load_announcement` (LLR-178.1, the B100-I8 panel); the Load dialog preview (Inc 9b) | Frozen: PDR, before Inc 7 |
| B100-I4 the project-session reset seam (NEW, `S19TuiApp._reset_project_session`, `app.py`) | resets the inventory S1–S12 of `design/ARQ-batch-100.md` §2.2 (`current_file`, `current_a2l_path`, `current_a2l_data`, the change service by **rebind**, variant/pending ids, declared regions, `_last_template_path`, `_diff_*`, `_last_flow_run`, `_last_execution`, `_report_filter_path`, A2L derived views); never resets `_image_generation` / `_diff_compare_generation` (monotonic) or view preferences (R24). **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** also resets the 11 S13 names the round-1 probe found differing (the seven `_mac_view_cache_*`, `_validation_issues`, `_validation_report`, `_mac_row_key_to_address`, `_a2l_row_key_to_tag`). Its completeness is guarded by `_session_snapshot()` (B100-I19), not by a hand list. An A2L-only load sets `_variant_set = build_variant_set(name, [])` after the reset, so later seam writes still run (A-14). The reset runs only after the one load seam's question (B100-I20) is answered | `_handle_load_project` only (`app.py:8444`), behind the one load seam (B100-I20); TC-B100-08..11 | Frozen: P1, before Inc 3 |
| B100-I5 `ChangeService.image_differs_from_source(mem_map) -> bool` (NEW, `change_service.py`) | true iff the journal is bound to this dict (`_image_map is mem_map`, `:895`) and some journaled address (`_journal`, `:887`) now holds a byte other than its source byte; read-only; never iterates `mem_map`; O(patched addresses). **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** **narrowed.** It no longer decides the load question or the Save summary's pending line; those use the unsaved-state predicate (B100-I18), and the two are never merged (A-08). It no longer decides emit-or-copy on its own either: per the B-01 ruling, Save project re-derives the **change** document onto a copy (B100-I15) and emits iff the re-derived data differs from the source data; a check document never counts. PDR decides whether it survives as a cheap pre-check of that decision or is dropped; it is used for nothing else | `_handle_save_dialog` (Inc 5, pre-check only, if kept); TC-B100-14 | Frozen: PDR, before Inc 5 |
| B100-I6 `copy_into_workarea` reuse rule (`workspace.py:402`; **amends B99-I2**) | reuse the first regular, non-link, non-empty, same-size, byte-identical file among `<name>` and every enumerated `<stem>_<N><suffix>` in `destination`; else claim the lowest free `_<N>` as before. Parameters, `Path` return, staging and failure contract unchanged; `place_group_into_workarea` unchanged (R30). **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** the rule lives in **one** function, `find_identical`, and the placement in **one** function, `place_into_workarea` (both B100-I13). `copy_into_workarea` becomes exactly `return place_into_workarea(...).path`, with **no second claim loop**. The Split/Join export takes its `reused` / `wrote` word from the `PlacementResult` of the placement it performed, and `_export_reuse_target` (`segment_split_view.py:673`) holds no byte-identity rule of its own (LLR-163.6) | **15** direct call sites at `1d677ba` (the round-2 contract's "17" counts 2 docstring lines, `crc.py:1443` and `flow_persistence_service.py:1096`), the injected path in `changes/io.py`; tests: 15 files reference `copy_into_workarea`; re-pinned: `test_unified_write.py::test_tc018…`, `test_tui_patch_editor_v2.py::test_at031b…` (G-005) and `test_b99_export.py::test_tc_b99_31_changed_bytes_take_the_next_free_name` (P-22, confirmed by the architect's M-1 prototype run) | Frozen: P1, before Inc 1 |
| B100-I7 the one manifest-writing seam — `S19TuiApp._write_and_verify_manifest` (`app.py:8272`) | every write of `project.json` goes through it. It computes `files` from disk after every copy (Inc 7) and takes `active_document` (Inc 8a) (R28). **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** every writer passes **every key it does not own** unchanged: `batch`, `assignments`, `declared_regions`, `gathered`, `active_document`, `derived_from`, and the `files` records of untouched files. Those keys are converted from the reader's absolute `Path`s back to project-relative POSIX strings (A-02, A-03; executed: `serialize_manifest` refuses the whole manifest on one absolute entry). An exact-name Save into an existing project that is not open is a **merge**: the target's keys are carried, not replaced by the session's (A-09). The seam requires `contained_in_workarea` (B100-I14) and stages privately (O-11). Three writers still bypass it: flow WRITE-OUT (`flow_execution_service.py:679`), the external-step copy (`:1108`) and variant execution (`variant_execution_service.py:797`). Their files show as `not recorded` (B100-I3) until `BACKLOG-CODE.md:1468` lands | Save project (`app.py:8262`), including the merge (LLR-164.2 b); save-back into the open project (Inc 6, `:3364`); the variant-append / MAC / A2L syncs (`:8591`, `:8622`, `:8630`, `:8652`); AT-B100-20 (each sync writer → `project.json` → fresh Load and Execute scope); `tests/` 1 file calls it directly | Frozen: PDR, before Inc 6; the merge arm with full carry is at Inc 8a (B-06) |
| B100-I8 the Load dialog result — `LoadChoice(kind, value)` (NEW, `screens.py`) | `kind ∈ {project, workarea, recent, path}`; one app router; a work-area pick loads in place through `load_selected_file`; a typed project folder or `project.json` routes to the project load (L-2, Inc 9a). **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** the P-A verdict C fixes the shape: one two-pane dialog with the `pa_C` ids (`#load_dialog`, `#load_list`, `#load_path`, `#load_preview`, `#load_reason`, `#load_ok`, `#load_cancel`). `l`, `ctrl+l` **and `p`** open it; `p` highlights the open project's row, or the first project (UX-37). `LoadProjectScreen`, `#project_list` and `#project_ok` retire; `_handle_load_project(name)` stays the direct entry. The initial focus is the path field (UX-05, correcting `pa_C`). `_handle_load_dialog` keeps accepting a `Path`, routed as `path`. The router hands every image-replacing kind to the one load seam (B100-I20). The preview's `●` marks come from the same function that chooses what `_handle_load_project` installs, and a project preview reads the manifest on a worker with a bounded read. The Load-result panel (P-E B, `pe_B` ids `#result_body`, `#result_variant`, `#result_ok`) is pushed after a project load, and its `v` routes through B100-I20 | replaces the dismiss contracts of `LoadFileScreen` (`screens.py:179`, → `_handle_load_dialog` `app.py:8674`) and `LoadProjectScreen` (`screens.py:691`); bindings `ctrl+l` / `l` / `p` (`app.py:1425`, `:1430`, `:1438`); tests: `LoadFileScreen` 4 files, `LoadProjectScreen` / `#project_list` 7 (re-pinned at Inc 9b); `#load_path` / `#load_ok` kept | Frozen: PDR, before Inc 9b (the dialog); the panel before Inc 6 |
| B100-I9 the recent-sources store (NEW, `workspace.py`) | `record_recent_source(path)` keeps the list newest first, de-duplicated by resolved path, ≤ 20 entries, outside sources only. It stages under a unique `mkstemp` name and places with `os.replace` after a reparse check. The list is never copied into a project or a report (R31). **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** **the file moves to a per-user location**, `%APPDATA%\s19_app\recent_sources.json` (operator decision on S-16), and no longer sits in `.s19tool/`. R31's re-open condition is met, and R31 is amended (R31a). The reader returns `RecentSources(entries, problem)` instead of `list[RecentSource]`:<br>- it reads `65 536 + 1` bytes, gives `too large` above the cap, and returns empty on a parse failure;<br>- it keeps only local drive paths (no UNC, no `\\?\` or `\\.\` prefix, no drive-relative path, no device name; a mapped drive is not claimed local);<br>- it keeps only entries with no C0/C1 control characters and a `kind` that matches the suffix;<br>- it never raises.<br>The dialog never stats, previews or reads a recent entry before Enter | `load_from_path` (`app.py:8710`), `load_a2l_from_path` (`:8789`), the Load dialog (B100-I8); 0 test files at `1d677ba` | Frozen: P1, before Inc 9a (with the S-16 location) |
| B100-I10 `SaveProjectPayload.parent_folder` (`screens.py:144`) — D7 | the field stays (7 test files construct the payload; every handler-driving test passes the app's work area, and the two `"p"` payloads at `tests/test_tui_manifest_save.py:616`, `:624` only construct the dataclass); `_handle_save_dialog` refuses, **before `mkdir`**, any parent that does not resolve to the app's own work area. The dialog stops offering a parent field and Browse… (Inc 11) | `_handle_save_dialog` (`app.py:8087`); `SaveProjectScreen` (`screens.py:483`, Browse… `:555`, `:660-675`); tests using `#project_parent_path`: 2 files | Frozen: P1, before Inc 8b |
| B100-I11 project-name rules (`workspace.py`: `RESERVED_WORKAREA_HOMES` `:40`, `sanitize_project_name` `:1028`) | reserved names match case-insensitively (casefold) in both Save and `list_projects` (`app.py:8519-8524`); a length cap with a status instead of a crash; the sanitised name is reported when it differs from the typed one . **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** the cap is `PROJECT_NAME_MAX_CHARS = 64`, plus a full-path check (`len(str(workarea / name)) + 53 > 259`, the `_MAX_FULL_PATH` idiom). Windows device names are refused case-folded, on the raw name and on every path component, through **one** device-name predicate in `workspace.py`. The name rules, the manifest-keys mode (B100-I21) and the recent store share it (B-12); the two older lists, `changes/apply.py:107` and `segment_split_view.py:524`, stay and are named in the backlog. A disguised clash (case-folded equal, typed name different) is refused with "choose another name"; only the exact name merges (UX-35, B100-I7) | `_handle_save_dialog`, `list_projects` (3 test files), the save plan (B100-I17), the Save dialog (Inc 11) | Frozen: P1, before Inc 2 |
| B100-I12 the busy/progress seam (`set_progress`, `app.py:13615`; `ProgressBar#progress_bar` `:2106`) | **Round 2 (P2, `0c7ca1d` + `design/P2-dispositions-r2.md`):** `begin_busy(key, label, steps)` / `step_busy(key, text, fraction=None)` / `end_busy(key, outcome)`, keyed by action.<br>- **One owner of `#status_text`:** while an action is busy, the seam owns the label (spinner, label, step `n/m`, elapsed). At the end, one final writer applies the stated order: outcome, then the project + file line, then the file state (UX-29, B-11).<br>- **The bar:** it shows progress **within a step** where that is measurable (bytes copied, read or parsed), and steps only for indivisible steps. It is hidden when idle and never left at a stale 100 % (UX-30).<br>- **Timing:** one main-thread `set_interval` drives the spinner and the elapsed time; worker calls keep `call_from_thread`; `end_busy` runs on every exit.<br>- **Census:** an action table maps every `set_progress` site at `1d677ba` (24 calls in 12 functions, P-29) to exactly one action's **begin, step or end** (B-10).<br>- **While a worker runs:** every action that replaces the image or the project is refused, with the `busy` token naming it (load, unload, `v`, save-back, Save project). Quit asks, then waits for the worker.<br>- **Main thread:** the A2L tag-table build stays there; its step is named before it starts, and its freeze is declared (R33) | today's `set_progress` callers: `app.py:4115`, `:4184-4211`, `:4805`, `:4891-4962`, `:5035`, `:6149`, `:6203-6239`, `:8750-8769`, `:8823-8868`, `:11455`, `:11488`; `set_file_status` (`:13587`, 4 test files); `#status_text` (20 test files); tests: 5 files reference `set_progress` | Frozen: PDR, before Inc 12a (12a and 12b land as one unit) |
| B100-I13 the one placement function — `find_identical(destination, name, staged) -> Optional[Path]` and `place_into_workarea(source, destination, …) -> PlacementResult(path, reused)` (NEW, `workspace.py`) | `find_identical` holds the B100-I6 byte-identity rule: candidates enumerated from the listing, size checked before bytes, and links, reparse points and 0-byte files never reused. `place_into_workarea` holds **every** placement guard: the reparse checks, this-work-area containment (B100-I14), the size cap, private staging, and the `O_EXCL` claim of the lowest free `_<N>`. `copy_into_workarea` is exactly `return place_into_workarea(...).path`, with no second claim loop, so its 15 callers keep a `Path` and are covered by construction (security R2-02). `reused` is true only when the returned file existed before the call | `copy_into_workarea` (15 call sites); `_sync_loaded_file_to_project` (`app.py:8526`, the "added" vs existing status, LLR-163.5); the Split/Join export (`segment_split_view.py:939-946`, LLR-163.6); `predict_placement` (B100-I22) | Frozen: PDR, before Inc 1 |
| B100-I14 this-work-area containment — `contained_in_workarea(path, workarea) -> bool` (NEW, `workspace.py`) | true iff the path, after resolving every link and junction, is inside `workarea.resolve()` of **this** app, never inside some other `.s19tool/workarea`. It is enforced **inside `place_into_workarea`** (B100-I13) and **inside `save_patched`'s emit path** (B100-I15). The emitter places through `copy_into_workarea`, so the second holds by construction; the Save target also gets a reparse-point check **before** `resolve()`. `list_projects`, `_handle_load_project` (picked or typed), the manifest seam and the save-as walk also require it. A project folder that is itself a link or junction is never listed, loaded or written (S-02, security R2-01) | every `copy_into_workarea` caller (by construction); `save_patched_image` (`changes/apply.py:781`); `list_projects`; `_handle_load_project`; `_write_and_verify_manifest`; the save-as walk; TC-B100-62 (one arm per writer) | Frozen: PDR, before Inc 1 (it lands with `place_into_workarea`, so every later writer is covered from the start); the listing and load uses follow at Inc 8b (LLR-171.4) |
| B100-I15 the `save_patched` split (`ChangeService`, `change_service.py:2009`; **additive to B99-I7**) | two NEW public steps:<br>- `rederive_onto_copy(mem_map, ranges, mac_records, a2l_tags) -> RederivedImage(mem_map_copy, summary, blocked)` re-derives the source plus the current **change** document onto a copy, never touching the session map;<br>- `emit_and_verify(rederived, dest_dir, filename, *, source_kind, bytes_per_line, s0_header, source_image_path) -> ChangeActionResult` emits through `save_patched_image` and verifies with `verify_written_image`.<br>`save_patched` becomes their composition plus the in-place view update, so **B99-I7's rule is unchanged**: the saved image equals the source plus the document's current entries. Save project decides emit-or-copy on **data**: it emits iff the re-derived copy differs from the source data. A check document never counts, and it is saved to `checks/` without blocking the save (B-01) | the save-back (`app.py:3428`, through `save_patched`, unchanged); Save project (Inc 5); the save plan's image digest, computed once per dialog open (B100-I17); the Inc 12b Save worker (re-derive on the main thread, `emit_and_verify` on the worker from the copy); tests: 10 files reference `save_patched` | Frozen: PDR, before Inc 5 |
| B100-I16 the per-variant manifest key `derived_from` (`project.json`, additive; B100-I1 / B100-I2) | `"derived_from": {"<variant file, project-relative>": {"source": "<source file name>", "sha256": "<64 lowercase hex of the source bytes>"}}`. It is written only for a variant that a save-back or Save project's emit produced, every key goes through the manifest-keys mode (B100-I21), and every rewrite **carries** it (B100-I7). The Load-result panel's "patched, N bytes differ" compares against the project file whose SHA-256 equals the recorded one, never against the first variant by name (UX-26). When no project file matches, the panel says the base is not in the project instead of counting. `schema_version` stays `1` | `on_patch_editor_panel_save_back_decision` (`app.py:3364`); Save project's emit; `compose_load_announcement` (LLR-178.1); the manifest reader and verify | Frozen: PDR, before Inc 7. Writer and reader land with `manifest_writer.py` and `variant_execution_service.py`, which are already in Inc 7; recording it at Inc 5 or 6 would put `manifest_writer.py` there and break the cap. The panel's comparison arm moves to Inc 7 |
| B100-I17 the save plan — `plan_project_save(...) -> SavePlan` (NEW, a pure function in `services/project_gather_service.py`) | computes, **without writing**:<br>- the target folder and its kind (new, the open project, a merge);<br>- one row per top-level file, one per sub-folder (with its file count) and one for `project.json`, each with its source, its landing name from `predict_placement` (B100-I22) and its action word (new / replace / keep / merge / rewrite);<br>- the image description (source + N entries, K applied by this save, or an unchanged copy);<br>- the document, the skipped links and the manifest keys — or the refusal with its tokens.<br>The emitted image's bytes and digest are an **input**, computed by the app once per dialog open through B100-I15. Name changes are debounced (≥ 150 ms) and recompute only names and actions, with no hashing (UX-33, B-04). **`_handle_save_dialog` executes exactly this plan, and the P-C dialog paints exactly this plan (R-PC).** The handler checks every landed `PlacementResult` against its row and reports a mismatch naming both paths. No new import edge: `project_gather_service → workspace` exists | `_handle_save_dialog` (Inc 5); `SaveProjectScreen` `#save_summary` (Inc 11, LLR-175.4); AT-B100-21 (plan rows vs the written tree, read from the plan object) | Frozen: PDR, before Inc 5. It grows at Inc 7 (`files` row), Inc 8a (document row) and Inc 8b (sub-folder rows, merge carry); each growth is re-frozen in that increment's packet |
| B100-I18 the unsaved-state predicate — `ChangeService.mark_saved(mem_map)` / `differs_from_last_saved(mem_map) -> bool` (NEW, `change_service.py`) | `mark_saved` records the bytes of the journaled addresses at a load, a successful save-back and a successful Save project. `differs_from_last_saved` reports whether any journaled or recorded address now holds a different byte. Cost O(journaled addresses); it never iterates `mem_map`. It decides the load question (B100-I20) and the Save summary's pending line (B100-I17) **and nothing else**. It is never merged with `image_differs_from_source` (B100-I5) or with the emit decision (B100-I15) (A-08). Once the document is written, Save project also clears the Patch Editor's dirty flag through the existing `PatchEditorPanel.mark_saved()` (`screens_directionb.py:5805`) (UX-27) | the load seam (Inc 10); the save plan (Inc 5 / 11); the load path, the save-back and Save project (the writers of the record); TC-B100-58 | Frozen: PDR, before Inc 5 |
| B100-I19 the session snapshot — `S19TuiApp._session_snapshot() -> dict` (NEW, `app.py`, a test seam) | the domain is **derived from the live app**: every name that `S19TuiApp`'s own source assigns (`self.<name> =`, found by a census at test time), minus a declared exclusion list of Textual internals, each with its reason. Values are normalised: paths relative to the base, `current_*` as `(type, relative path, image digest)`, the change service as its public counts, other objects as counts or keys. Every census name is either in the domain or excluded with a reason (0 unclassified). The domain is never hand-listed (C-31, A-07); the round-1 probe found 178 `vars(app)` names, 31 of them framework | TC-B100-09 (cold P2 vs P2-over-P1, with K1/K2 allow-listed); HLR-177's worker-vs-main-thread comparison | Frozen: P1, before Inc 3 |
| B100-I20 the one load seam — the unsaved-work question for every image-replacing route (NEW, `app.py`) | every route that replaces the image or the project passes one guard **before** it loads:<br>- the Load dialog router (B100-I8);<br>- the Workarea Files pick (`_load_from_item` → `load_selected_file`, `app.py:8879`, `:9021`);<br>- the variant switch (`v`, `SelectVariantScreen` → `_handle_select_variant` → `load_from_path`, `app.py:6733-6736`; and the panel's `v`);<br>- project load.<br>It asks only when something would be lost: for an image load, unsaved image data (B100-I18); for a project load, also a dirty Patch Editor document or unsaved Flow Builder edits (`flow_screens.py:1354`). Loading a MAC or an A2L only attaches it and never asks (QA R2-02). There is one short question (`pb_A`), with the focus on No, and the answer is taken before `_reset_project_session` (B100-I4). `LoadGuardScreen` keeps guarding the Patch Editor's own document load | the four routes above. `_handle_load_project(name)` called directly (tests) meets no modal. The Patch Editor dirty flag is read through an accessor; adding one puts `screens_directionb.py` in Inc 10, still ≤ 4 | Frozen: PDR, before Inc 10 |
| B100-I21 the manifest-keys mode of the shared path check — `_resolve_manifest_entry(…, mode=…)` (`variant_execution_service.py:205`) | a NEW keyword mode; the default is today's behaviour. In manifest-keys mode it also refuses, with `MANIFEST-PATH-ESCAPE`, an entry that has a drive or a root, a `:` anywhere, a trailing dot or space, or a device name on any component (B100-I11's predicate). Only `read_project_manifest` and `_reject_unsafe_entry` (`manifest_writer.py:179`) use the mode. Flow references keep the default, so `test_b97_flow_builder.py::test_tc_b97_20_hostile_refs_render_literally` stays green (B-03: executed, the shared tightening failed it) | manifest mode: `read_project_manifest`, `_reject_unsafe_entry`; default mode (unchanged): `flow_persistence_service.py` and `flow_execution_service.py` call sites; TC-B100-60 | Frozen: PDR, before Inc 7 |
| B100-I22 `predict_placement(staged_bytes, destination, name) -> PlacementResult` (NEW, `workspace.py`) | answers, **without writing**, where `place_into_workarea` would put these bytes. It shares `find_identical` and the free-name walk (names taken per `os.lstat`, directories and links included) with B100-I13, so the plan and the placement are one rule. A claim race can still make them differ; the handler then reports the mismatch (B100-I17, B-05) | `plan_project_save` (B100-I17); TC arm: a directory named `firmware_1.s19` in the target → plan and file both `firmware_2.s19` | Frozen: PDR, before Inc 1 (with B100-I13) |
