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

- **Activity rail (left).** Exactly ten ordered items bound to keys `1`–`0`, with exactly one active marker, glyph + per-item ASCII fallback. Rail items toggle ten sibling screen containers via the `.hidden` CSS class (not a `push_screen` stack), so the rail and command bar stay persistently mounted.
- **Command bar (top).** Searchable command palette (`Ctrl+K`), find input (`/` → routes to `find_string_in_mem`), go-to-address input (`g` → routes to `_handle_goto`), plus the project-name / A2L-filename status labels.

### The ten rail screens

| Key | Container id | Screen | Status |
|---|---|---|---|
| 1 | `#screen_workspace` | Workspace (3-pane: ranges/sections · hex · context) | functional; hosts the Loaded-artifacts panel with per-artifact unload |
| 2 | `#screen_a2l` | A2L Explorer (symbol table + hex pane) | functional; enriched tags, 19-field filter, windowed rendering |
| 3 | `#screen_mac` | MAC View (record table + hex pane) | functional; per-row status, malformed lines flagged not dropped |
| 4 | `#screen_map` | Memory Map | functional — real coverage from `LoadedFile.ranges` plus entropy bands from `services/entropy_service.py` |
| 5 | `#screen_issues` | Issues Report | functional — grouped, filterable, paged view of the validation engine's findings |
| 6 | `#screen_patch` | Patch Editor | **functional** — change-set rows, validate/check, save/load v2 JSON, apply + patched-image emit, undo/redo |
| 7 | `#screen_diff` | A↔B Diff | **functional** — second-image load, classified diff runs, Markdown/HTML report |
| 8 | `#screen_flow` | Flow Builder | **functional** — typed block chain, `flow.json` persistence, variant-scoped execution with fused report |
| 9 | `#screen_checks` | Checks | functional — read-only grouped-by-outcome mirror of the last check run |
| 0 | `#screen_crc_designer` | CRC Designer | functional — parametric CRC form, preset catalogue, live known-answer verdict, `*.crc.json` templates |

Fourteen modal screens complement the rail (load file, save/load project, variant select/help, change-set and entry JSON editors, flow save/load, confirm-discard, confirm-write, legend, report viewer, operations). The batch-02 **Bookmarks** screen no longer exists — the rail's last three slots are Flow Builder, Checks and CRC Designer.

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

## 10. Composition — the modules, by path

**The `Paths it owns` column is the mechanical part.** It is what makes this a map and not an essay:
any touched file is classified by path prefix, so the A-family triggers can be evaluated by a script.
Measured 2026-08-24 over `git ls-files` — **266 tracked source files** (`.py`), every one classified
below except the single exception named after the table.

| Module | Paths it owns | What it encapsulates | What it EXPOSES | What does NOT belong to it |
|---|---|---|---|---|
| **product** | `s19_app/**` | the shipped application: the Direction-B TUI shell and its sub-packages (`tui/changes`, `tui/operations`, `tui/services`), plus `validation/` — all described in §1–§7 | the TUI entry point, `ChangeService`, the `changes` package API | test scaffolding · throwaway prototypes · flow tooling |
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
