# s19_app — Overview

**Audience:** technical or semi-technical stakeholder (project lead, partner, calibration engineer evaluating the tool, new contributor before they touch code).
**Purpose:** explain what `s19_app` is, who it is for, what it does today, and where to look for more depth.

This document sits above the per-batch dev-flow archives. For point-in-time detail (requirements, test verdicts, decisions) of any single feature, follow the cross-references in §7.

---

## 1. What `s19_app` is

`s19_app` (distribution name `s19tool`) is an offline desktop tool for **embedded / automotive firmware engineering**. It parses, validates, visualises and patches automotive memory artefacts — S-record / Intel HEX firmware images, ASAM A2L description files, and MAC `TAG=hexaddr` symbol tables — and authors calibration changes as versioned change-set JSON documents that it can apply to produce a patched firmware image.

It is written in Python and ships one console entry point (configured in `pyproject.toml`):

- **`s19tui`** — a Textual terminal interface (a "TUI") for interactive exploration, cross-artefact validation and calibration-change authoring. It uses the **Direction B** layout: a left activity rail + a top command bar + ten single-context screens.

A legacy Rich-formatted command line (`info`, `verify`, `dump`, `patch-hex`, `patch-str`, …) survives as a **module-only** invocation — `python -m s19_app.cli` — with no console script; the TUI is the product surface.

There is no GUI, no daemon, no network surface and no external service dependency. Everything runs locally in a terminal, against files on disk.

## 2. Who it is for

Embedded **calibration engineers** working with ASAM A2L description files and ECU flash images. The typical user:

- reads and writes S-record (`.s19`) and Intel HEX (`.hex` / `.ihex`) firmware images,
- works with ASAM A2L (`.a2l`) descriptions of calibration symbols,
- works with MAC (`TAG=hexaddr`) symbol-map files,
- authors calibration changes as a versioned change-set JSON document and applies them to emit a patched firmware image,
- needs a single offline workstation tool to triage issues, build a change-set, and hand it off.

## 3. Current capabilities

The shipped app, as it stands today:

- **Engine + validation.** S-record / Intel-HEX parsing, sparse memory map, contiguous range index, A2L structural parsing and enrichment, MAC parsing, and a cross-artefact validation engine producing `ValidationIssue` records with severity / coverage metrics — **17 public issue codes** (five `MAC_*`, five `A2L_*`, and seven `CROSS_*` / `TRIPLE_*`) that the test suite asserts on. Engine reference: [REQUIREMENTS.md](../REQUIREMENTS.md) §R-READ / R-PARSE / R-VAL / R-HEX / R-A2L.
- **Direction B TUI shell.** Activity rail + command bar + **ten** rail screens: Workspace, A2L Explorer, MAC View, Memory Map, Issues Report, Patch Editor, A↔B Diff, Flow Builder, Checks, CRC Designer (keys `1`–`0`), plus fourteen modal screens (load/save project, load file, variant selection, report viewer, legend, operations, flow save/load, and friends). Calm Dark theme; density toggle; responsive two-regime layout (fixed ≥ 120 cols, proportional < 120).
- **Change-set engine v2 + apply.** The Patch Editor authors an address-keyed change-set, saves/loads it as a versioned JSON document (`"format": "s19app-changeset"`, `"version": "2.0"` — `s19_app/tui/changes/`), validates and checks it against the loaded image, and **applies** it to emit a **patched S19/HEX image** into the workarea. Undo/redo is shipped (`Ctrl+Z` / `Ctrl+Y`).
- **Projects and variants.** A saved project carries a `project.json` manifest with named **variants** (per-variant image/A2L/MAC assignments); change-set runs and flows execute variant-scoped, one image at a time, and leave a single fused report.
- **Flow Builder.** Ordered chains of typed blocks (`SOURCE` → `PATCH` → `WRITE-OUT`, plus CRC) executed over a project image or variant-scoped, persisted to `flow.json`.
- **A↔B Diff.** Two-image comparison into classified runs (`changed` / `only_a` / `only_b`) with Markdown and self-contained HTML diff reports.
- **CRC family.** A width-general (8–64) parametric Rocksoft CRC kernel with a named-preset catalogue, `*.crc.json` algorithm-template load/save, a legacy CRC-32 operation, and the **CRC Designer** screen with live known-answer verification.
- **Operations.** A deterministic registry (`crc`, `extract`, `split_by_segment`) executable from the in-app Operations modal.
- **Entropy service.** Per-window Shannon entropy over the loaded image, classified into four bands (`constant/padding` · `low` · `medium` · `high/random`), feeding the Memory Map's banding and the report/viewer surfaces.

**Superseded history.** Batches `2026-05-21-batch-03`/`batch-04` shipped an ASAM CDF 2.0 (`.cdfx`) reader/writer and a v1 "unified change-set" JSON as the calibration-change hand-off to Vector vCDM. **Both are removed**: the `s19_app/tui/cdfx/` package no longer exists, and the v2 reader recognises the v1 envelope only to reject it with a `CHG-V1-FORMAT` finding. The shipped replacement is the v2 change-set JSON + the patched-image emit described above.

**Test suite:** `pytest --collect-only -q` reports **2760 collected tests** (measured 2026-10-11). CI runs the lean suite on pull requests and the full suite on pushes to `main`.

## 4. Key formats handled

| Format | Role in the workflow | Where it is touched |
|---|---|---|
| **S19** (Motorola S-record) | firmware memory image — primary input | `s19_app/core.py` (`S19File`, `SRecord`) |
| **Intel HEX** (`.hex` / `.ihex`) | firmware memory image — alternative input | `s19_app/hexfile.py` (`IntelHexFile`) |
| **A2L** (ASAM) | calibration-symbol metadata: type, layout, conversion, axis | `s19_app/tui/a2l.py` (canonical module + `a2l_*` facades) |
| **MAC** (`TAG=hexaddr`) | flat tag → address map; cross-checked against A2L | `s19_app/tui/mac.py` |
| **Change-set JSON (v2)** | this project's change-envelope: `"format": "s19app-changeset"`, `"version": "2.0"` | `s19_app/tui/changes/io.py` |
| **Patched S19/HEX image** | the applied change-set emitted back as a firmware image | `s19_app/tui/changes/apply.py` (`save_patched_image`) |
| **`*.crc.json`** | CRC algorithm template (parametric Rocksoft model) | `s19_app/tui/operations/crc_template.py` → `crc_designer_model.py` |
| **`project.json`** | saved-project manifest: variants and per-variant assignments | `s19_app/tui/services/variant_execution_service.py` (read) · `manifest_writer.py` (write) |
| **`flow.json`** | persisted Flow Builder block chain | `s19_app/tui/services/flow_persistence_service.py` |

*Historic:* CDF 2.0 / `.cdfx` (ASAM MCD-2 CAL) was the calibration-exchange format in batches 03–04; the `tui/cdfx/` package is removed and the v2 change-set JSON + patched-image emit is its replacement.

## 5. Typical workflow

The shipped surfaces assemble into one calibration workflow:

1. **Load.** Launch `s19tui`, load a firmware image (`.s19` / `.hex`) and an A2L (`.a2l`); optionally a MAC (`.mac`). Files are copied into `.s19tool/workarea/` first (every read and write resolves under that root — see §5 in [architecture.md](./architecture.md)). Saving a project writes a `project.json` manifest, which can declare per-variant artefact assignments (`v` selects the active variant).
2. **Review issues and coverage.** The **Issues Report** rail screen lists every `ValidationIssue` the cross-artefact engine collected, with severity colouring driven by `tui/color_policy.SEVERITY_CLASS_MAP`. The **Memory Map** screen shows firmware coverage (ranges, gaps) from `LoadedFile.ranges` plus entropy banding from the entropy service.
3. **Explore A2L and MAC.** Inspect parameter metadata in the **A2L Explorer** (table + hex pane) and address mappings in the **MAC View**.
4. **Build a change-set.** In the **Patch Editor**, add address-keyed entries (address + new bytes). Entries validate against the loaded image's ranges, and a check run re-verifies them; the **Checks** screen mirrors the results grouped by outcome. Edits are undoable (`Ctrl+Z` / `Ctrl+Y`).
5. **Save the change-set.** One versioned JSON file (`s19app-changeset`, version `2.0`) under `.s19tool/workarea/` holds the whole patch set as one working document.
6. **Apply and emit.** **Apply** writes the entries into a working copy of the image; **Save patched** emits the result as a real `.s19` / `.hex` file into the workarea (through the staged-containment write path). For repeat work, the **Flow Builder** chains the same steps as blocks and can run them variant-scoped with a single fused report.

A change-set round-trip is exact: a value saved to the v2 JSON and re-loaded comes back equal. The v1 "unified change-set" envelope from batches 03–04 is deliberately **not** read-compatible — the reader rejects it with one `CHG-V1-FORMAT` finding.

## 6. What's deferred

`s19_app` is in active development. The following capabilities are deliberately out of the current scope and tracked for future batches:

| Deferred capability | Scope | Tracked under |
|---|---|---|
| **PDF report export** | export the Issues Report to PDF | batch-02 post-mortem `B-3D` |

Formerly deferred, **now shipped** (kept here so old citations resolve): apply-the-change-set / patched-image export, undo/redo, the CRC engine and designer, and the A↔B firmware diff are all live surfaces (§3). The batch-02 **Bookmarks** placeholder screen was superseded — the rail's ten screens no longer include it. The **live vCDM round-trip** row is moot: the CDFX exchange surface itself was removed.

## 7. Where things live

| You need to know… | Look in |
|---|---|
| project-level architecture | [architecture.md](./architecture.md) |
| living Mermaid diagrams (system, TUI shell, layout, memory) | [diagrams/architecture.md](./diagrams/architecture.md) |
| living `R-*` requirement traceability (engine + every batch) | [../REQUIREMENTS.md](../REQUIREMENTS.md) |
| coding conventions, common commands, file-layer rules | [../CLAUDE.md](../CLAUDE.md) |
| per-batch executive summary (stakeholder-level, what shipped) | `.dev-flow/<batch>/06-docs/executive-summary.md` |
| per-batch functionality orientation (technical, terminology) | `.dev-flow/<batch>/06-docs/functionality.md` |
| per-batch requirements, review, validation, post-mortem | `.dev-flow/<batch>/{01-requirements,02-review,04-validation,05-postmortem}.md` |
| per-batch test→requirement traceability matrix | `.dev-flow/<batch>/06-docs/traceability-matrix.md` |
| current dev-flow batch state | `.dev-flow/state.json` |
| run / install / CLI examples | [../README.md](../README.md) |
