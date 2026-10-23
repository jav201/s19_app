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
| I-11 `S19TuiApp.check_action` (batch-97, amended 2026-10-22, PC-13) | no `check_action` override | created at Inc-6 with one arm: `confirm_attention` → `_active_screen_key == "flow_execution"`; every other action falls through to `App.check_action`; `Binding("c", "confirm_attention", "Confirm", show=False)` in `S19TuiApp.BINDINGS`; Inc-8 adds D28's four arms and the key bar | `app.py` (`action_confirm_attention`, the ^K palette's `Confirm` entry), Inc-8's key bar | **yes — frozen at the 2026-10-20 delta**, first arm lands Inc-6 |
| I-8 `FlowBuilderPanel.RunRequested` | carries the selector's scope | always `FLOW_SCOPE_SINGLE`; shape unchanged | `app.py:2518` (branch deleted, D8) | **yes — shape frozen** (batch-94 `#D3`) |
| I-9 the NEW names of D12 (ids, classes, constants, vocabularies) | — | as D12 | the batch's TCs / ATs, the `window_help` bodies | **yes — frozen at PDR**; a rename after PDR is A3 |
