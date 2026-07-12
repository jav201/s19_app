# s19_app — Architecture

**Audience:** a technical contributor about to read or change code.
**Purpose:** describe the three-layer architecture, the Direction B TUI shell, the `cdfx/` data-processing package, the Patch Editor flow, the path-safety and XML/JSON safety contracts, the engine invariant, the testing architecture, and the dev-flow process that built it.

For the visual call-graph (system, TUI shell, two-regime layout, CDFX package, memory layer), see [diagrams/architecture.md](./diagrams/architecture.md) — it is the canonical living diagram and is updated whenever a structural change lands. For point-in-time per-batch detail (decisions, test verdicts, post-mortems), follow the per-batch cross-references in [overview.md](./overview.md) §7.

---

## 1. Three-layer architecture

`s19_app` has three layers. They should be modified together when behaviour crosses boundaries; otherwise they stay independent.

| Layer | Modules | Role |
|---|---|---|
| **1 — Parsers** | `s19_app/core.py`, `s19_app/hexfile.py`, `s19_app/tui/a2l.py` (+ `a2l_*` facades), `s19_app/tui/mac.py` | parse one artefact each into a sparse memory map / structured records; **collect** validation failures per record and per file rather than aborting |
| **2 — Range / validation engine** | `s19_app/range_index.py`, `s19_app/validation/engine.py`, `s19_app/validation/rules.py`, `s19_app/validation/model.py`, `s19_app/tui/color_policy.py` | binary-search range membership; cross-artefact rule evaluation; `ValidationIssue` / `ValidationSeverity` / `CoverageMetrics` model; severity → CSS class single source of truth |
| **3 — TUI services + view** | `s19_app/tui/services/*` (orchestration seam), `s19_app/tui/cdfx/*` (data-processing package), `s19_app/tui/screens_directionb.py`, `s19_app/tui/app.py` (orchestration only) | service-mediated calls into the engine; pure-Python data-processing of change-sets and CDFX; Textual view layer |

**The rule.** Behaviour that crosses a layer boundary is modified in the same commit. Engine modules (layers 1 and 2) stay **read-only consumers** for view-layer / change-set work — the four feature batches that built the TUI shell and the Patch Editor all left the engine byte-for-byte unchanged (see §6).

The CLI (`s19_app/cli.py`) is a separate, simpler consumer: it reaches the parsers directly and does not use the TUI services.

## 2. Direction B TUI shell

The TUI uses the **Direction B (Rail + Command)** layout introduced by batch `2026-05-20-batch-02`. Two persistent navigation surfaces are mounted on every screen:

- **Activity rail (left).** Exactly eight ordered items bound to keys `1`–`8`, with exactly one active marker, glyph + per-item ASCII fallback. Rail items toggle eight sibling screen containers via the `.hidden` CSS class (not a `push_screen` stack), so the rail and command bar stay persistently mounted.
- **Command bar (top).** Searchable command palette (`Ctrl+K`), find input (`/` → routes to `find_string_in_mem`), go-to-address input (`g` → routes to `_handle_goto`), plus the project-name / A2L-filename status labels (the `R-TUI-016` content promoted into the persistent bar when the Issues table moved to its own screen).

### The eight rail screens

| Key | Container id | Screen | Status |
|---|---|---|---|
| 1 | `#screen_workspace` | Workspace (3-pane: ranges/sections · hex · context) | restyle of the pre-batch Main view |
| 2 | `#screen_a2l` | A2L Explorer (symbol table + hex pane) | restyled; A2L panes use a flat 3/7 hex ÷ 4/7 tags split at all widths (`R-TUI-037`) |
| 3 | `#screen_mac` | MAC View (record table + hex pane) | restyled |
| 4 | `#screen_map` | Memory Map | scaffold rendering real coverage from `LoadedFile.ranges` |
| 5 | `#screen_issues` | Issues Report | promoted to a dedicated screen (`R-TUI-025`) |
| 6 | `#screen_patch` | Patch Editor | **functional** — parameter + memory change rows, save/load unified, selective export |
| 7 | `#screen_diff` | A↔B Diff | scaffold (static placeholder; diff logic deferred) |
| 8 | `#screen_bookmarks` | Bookmarks | placeholder (persistence deferred) |

### Two-regime responsive layout

One layout, width-responsive, governed by a 120-column terminal breakpoint:

- **Fixed regime — width ≥ 120 columns.** Rail full fixed width; Workspace `left 22 · right 40 · center 1fr`; MAC `hex 40 · table 1fr`.
- **Proportional regime — width < 120 columns.** Rail collapses to icon-only (~4 cols); Workspace `left 24% · right 30% · center 1fr`; MAC `hex 35% · table 1fr`.

Layout integrity is guarded by the `pytest-textual-snapshot` 27-baseline matrix plus 119/120 boundary tests. The A2L Explorer panes are the **exception** — flat 3/7 hex ÷ 4/7 tags at all widths (the iteration-3 two-regime A2L split rendered the hex view too narrowly at ≥ 120 cols and was superseded; see `R-TUI-037`).

The diagrams in [diagrams/architecture.md](./diagrams/architecture.md) §2 and §3 render this visually.

## 3. The `cdfx/` package

`s19_app/tui/cdfx/` is the **data-processing layer** added by batch-03 and extended by batch-04. It is **pure Python** — it imports `xml.etree.ElementTree`, `json`, the existing `validation/`, the A2L module and the workspace helpers, but **never `textual`** — so every module is unit-testable without an app instance.

| Module | Added | Purpose |
|---|---|---|
| `changelist.py` | batch-03 | `ChangeListEntry`, `ChangeList`, `ResolutionStatus` — parameter change-list model. Entry identity `(parameter_name, array_index)`; `array_index` is `Optional[int]` so a scalar entry and element 0 of an array are distinct identities. **Byte-unchanged in batch-04.** |
| `resolve.py` | batch-03 | `resolve_against_a2l` — looks up each entry against the **enriched** A2L pipeline (`parse_a2l_file → enrich_a2l_tags_with_values`, not bare `extract_a2l_tags`) and stamps `unresolved` / `index-out-of-range` / `unresolved-no-a2l` without raising. **Byte-unchanged in batch-04** (SHA-256-pinned). |
| `display.py` | batch-03 | `format_value` — type-driven display form (decimal for unsigned ints with a hex companion when integral; signed decimal for signed ints; fractional decimal for IEEE floats; quoted string for ASCII). Display never mutates stored values. |
| `writer.py` | batch-03 | `write_cdfx` — emits a CDF 2.0 `.cdfx` backbone (`MSRSW → SW-SYSTEMS → SW-SYSTEM → SW-INSTANCE-SPEC → SW-INSTANCE-TREE`); coalesces array entries into one `VAL_BLK` `SW-INSTANCE` (rejects sparse / non-zero-based groups with `W-ARRAY-SPARSE`, **never gap-fills**); leading `Created with s19_app CDF 2.0 Writer` tool note; full-precision float `V` text. Carries the standalone `validate_w_rules` validator (the eight `W-*` codes). **Byte-frozen post-batch-03** (SHA-256-pinned). |
| `reader.py` | batch-03 | `read_cdfx` — namespace-tolerant local-name matching; `VAL_BLK` expansion back into `(name, 0…N-1)` entries; decimal / exponential / hex `V` decoding; the nine `R-*` read-time rules; A2L cross-check producing `R-NAME-NOT-IN-A2L` and `R-ARRAY-LEN-MISMATCH` warnings; **collect-don't-abort** — every finding is a `ValidationIssue`, never an exception. |
| `memory.py` | batch-04 | `MemoryStatus`, `MemoryChange`, `MemoryChangeList` — memory-change model, address-keyed, insertion-ordered. Bytes stored as an **immutable tuple**. `ValueError` on construction with an empty / negative / >255 byte run (the opposite failure mode to the validator). |
| `memory_validate.py` | batch-04 | `validate_memory_changes` — tests each entry's addressed byte range against `LoadedFile.ranges` (read-only, never re-parses), stamps `inside` / `partial` / `outside` / `unvalidated-no-image`; one warning per partial/outside entry; one warning per inter-entry overlap; message references the address and byte-count summary but **does not embed the raw bytes**. |
| `memory_display.py` | batch-04 | `format_memory_value` — hex primary, ASCII companion (with the pinned `.` `0x2E` placeholder for non-printables), decimal companion. |
| `changeset.py` | batch-04 | `UnifiedChangeSet` — **composes** (not subclasses) `ChangeList` + `MemoryChangeList`. Each half is independently inspectable, mutable, counted; empty-state query. |
| `unified_io.py` | batch-04 | `serialize_unified`, `write_unified_to_workarea`, `read_unified` — single JSON file (stdlib `json`, no new dependency) carrying the format identifier `s19app-unified-changeset`, version `1.0`, the parameter half and the memory half (`address` is an integer-valued field, never an object key). Applies the ten `MF-*` rules (`MF-JSON-PARSE`, `MF-BAD-STRUCTURE`, `MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`, `MF-VERSION-UNKNOWN`, `MF-SIZE-CAP`, `MF-ENTRY-LIMIT`, `MF-PATH-UNRESOLVED`, `MF-WRITE-CONTAINMENT`); 256 MB on-disk cap; decoded-structure entry-count / run-length ceiling; explicit `RecursionError` catch; structural-shape check precedes any half-indexing. |
| `export.py` | batch-04 | `export_unified` — splits the unified change-set into **two** distinct work-area files: re-resolves the parameter half against the loaded A2L at export time (via batch-03 `resolve_against_a2l`), invokes the **unchanged** batch-03 `write_cdfx_to_workarea` for the `.cdfx`, then writes a separate memory-field JSON file. Combines per-half issues onto `ValidationIssue.artifact`; neither half aborts because the other produced issues. |

**Dependency direction (strict).** `changelist.py` and `memory.py` are leaves. `resolve.py` / `display.py` / `writer.py` / `reader.py` depend on `changelist.py`; `memory_validate.py` / `memory_display.py` / `changeset.py` depend on `memory.py`; `changeset.py` also composes `changelist.py`; `unified_io.py` depends on `changeset.py`; `export.py` depends on `changeset.py`, `unified_io.py`, the batch-03 `writer.py` and `resolve.py`.

## 4. Patch Editor flow

The Patch Editor demonstrates the orchestration contract end-to-end:

```
PatchEditorPanel  ───emits───►  ActionRequested message
                                       │
                                       ▼
                          tui/app.py — Patch Editor handler
                                       │  (routing wiring only —
                                       │   no xml.etree.ElementTree import,
                                       │   no json import, no model logic;
                                       │   verified by TC-027)
                                       ▼
                  tui/services/cdfx_service.py — CdfxService
                                       │  (owns one UnifiedChangeSet;
                                       │   parameter + memory ops;
                                       │   save_unified / load_unified /
                                       │   export_selective)
                                       ▼
                       s19_app/tui/cdfx/* (the package)
                                       │
                                       ▼
              PatchEditorPanel refreshes its rows / status
```

The screen is **presentational**; `app.py` carries only the UI-state wiring that routes the message to `CdfxService`. The XML and JSON model logic lives in the package, never in `app.py`. This contract is asserted by tests — see `tests/test_tui_patch_editor.py::test_tc028_app_py_holds_no_cdfx_xml_logic` and `test_tc028_patch_action_handler_routes_through_the_service`, plus `tests/test_cdfx_unchanged.py::TC-027` for the batch-04 equivalent.

## 5. Path-safety contract

Every file write resolves under `.s19tool/workarea/` through `s19_app/tui/workspace.py`. The contract is enforced at the function boundary, not by convention:

- **Writes** go through `copy_into_workarea` (the dedup-suffix path that the project save flow already used) — symbolic-link / NTFS reparse-point traversal is **rejected** (`_path_traverses_reparse_point`); an existing filename is **dedup-suffixed**; the resolved target must be inside `.s19tool/workarea/`. The CDFX writer (`writer.write_cdfx_to_workarea`), the unified writer (`unified_io.write_unified_to_workarea`) and the export writer (`export.write_memory_field_to_workarea`) all share this same path.
- **Reads** of a user-supplied path go through `resolve_input_path` (the loader path that walks the app cwd and the nearest repo root). The CDFX reader (`reader._resolve_source`) and the unified reader use it.
- **No new write path** has been added by the CDFX / memory / export work — the writers in `cdfx/` are thin adaptors over the existing workspace primitives.
- **Failures are surfaced, never raised.** A containment failure, reparse-point rejection, overwrite refusal or path-resolution failure becomes a `ValidationIssue` (`R-PATH-*` for CDFX, `MF-PATH-UNRESOLVED` / `MF-WRITE-CONTAINMENT` for the unified file), not an uncaught exception. Test coverage: `tests/test_cdfx_path_containment.py`, `tests/test_tui_patch_containment.py`, `tests/test_unified_*.py`.

`R-CDFX-018` documents the CDFX side of this contract verbatim; the unified-file side maps to `LLR-006.4 / LLR-006.5` under `R-MEM-004`.

## 6. XML / JSON safety

Both readers treat their input as **untrusted**.

**CDFX reader (`cdfx/reader.py`).** Uses stdlib `xml.etree.ElementTree` only — no `defusedxml` dependency.
- A `DOCTYPE` or `<!ENTITY>` declaration is rejected by an `expat`-level handler that raises (`_UnsafeXmlError`) **before any entity is expanded** — no external file read, no entity blow-up. Surfaced as exactly one `R-XML-PARSE` issue with an empty change-list.
- File size is **probed before parsing** against a 256 MB byte cap (the existing `workspace.DEFAULT_COPY_SIZE_CAP_BYTES`). Over-cap files are rejected.
- XML element nesting depth is bounded.
- Malformed XML and producer-specific variation (other vendors' `ADMIN-DATA`, `SW-CS-HISTORY`, `SW-CS-FLAGS`, namespaced root elements, leading writer tool-notes) are tolerated.
- All findings are `ValidationIssue`s; the reader **never raises** on malformed input.

**Unified JSON reader (`cdfx/unified_io.py`).** Uses stdlib `json` only — no new dependency.
- `json.JSONDecodeError` and `RecursionError` are both caught and surfaced as `MF-JSON-PARSE` / `MF-BAD-STRUCTURE`. A deeply-nested input that would exceed the recursion limit is not allowed to crash the load.
- A 256 MB on-disk size cap (`MF-SIZE-CAP`) and a decoded-structure entry-count / run-length ceiling (`MF-ENTRY-LIMIT`, the `MF_ENTRY_COUNT_CEILING` / `MF_RUN_LENGTH_CEILING` constants) bound what enters memory.
- A structural-shape check runs **before any half-indexing** — no `KeyError` escapes.
- Per-entry rules (`MF-NO-ADDRESS`, `MF-EMPTY-BYTES`, `MF-BYTE-RANGE`) and a version-token tolerance rule (`MF-VERSION-UNKNOWN`) collect their own findings.

Both readers were cleared by a dedicated security review in their respective batches (batch-03 for CDFX, batch-04 for the unified JSON).

## 7. Engine invariant

The parsing / validation engine is **byte-for-byte unchanged across batches 02–04**:

- `s19_app/core.py`
- `s19_app/hexfile.py`
- `s19_app/range_index.py`
- `s19_app/validation/` (entire directory)
- `s19_app/tui/a2l.py`
- `s19_app/tui/mac.py`

This is asserted by **line-ending-normalised SHA-256** comparisons in `tests/test_cdfx_unchanged.py` (TC-027) and pinned by the writer-freeze test (TC-030) for the batch-03 CDFX writer/resolver in batch-04. Phase-4 `git diff main` over those files has been empty for every batch since batch-02. Adding behaviour that needs to cross into one of those modules is allowed, but it changes the engine invariant and must be called out in the batch's requirements phase.

## 8. Testing architecture

Roughly **763 tests** under `tests/` at the close of batch-04 (762 pass + 1 boundary), organised by module — `tests/test_core_*`, `tests/test_hexfile.py`, `tests/test_range_index.py`, `tests/test_validation_*`, `tests/test_tui_*`, `tests/test_cdfx_*`, `tests/test_memory_*`, `tests/test_unified_*`, plus the per-example smoke suites (`tests/test_examples_*`).

Markers (registered in `pyproject.toml`):

- **`slow`** — stress / perf smoke tests. `pytest -q -m "not slow"` skips them. No example smoke case is currently pinned `@pytest.mark.slow`: the former ~490s `pv__case_06_large_nested_a2l` duplicate was pruned in batch-36 (US-060), and the large-A2L pipeline is now covered by the retained 36 MB top-level `case_06_large_nested_a2l` in the normal suite.
- **`snapshot`** — `pytest-textual-snapshot` baselines.

Visual regression: 27 SVG baselines under `tests/__snapshots__/`, generated only against the public synthetic fixtures (`examples/case_00_public/` and the `tests/conftest.py` generators) — **never against client firmware, A2L or MAC artefacts** (`R-TUI-034`, the TC-031 no-leak inspection).

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
