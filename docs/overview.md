# s19_app — Overview

**Audience:** technical or semi-technical stakeholder (project lead, partner, calibration engineer evaluating the tool, new contributor before they touch code).
**Purpose:** explain what `s19_app` is, who it is for, what it does today, and where to look for more depth.

This document sits above the per-batch dev-flow archives. For point-in-time detail (requirements, test verdicts, decisions) of any single feature, follow the cross-references in §7.

---

## 1. What `s19_app` is

`s19_app` (distribution name `s19tool`) is an offline desktop tool for **embedded / automotive firmware engineering**. It parses, validates, visualises and patches automotive memory artefacts — S-record / Intel HEX firmware images, ASAM A2L description files, and MAC `TAG=hexaddr` symbol tables — and exchanges calibration changes with Vector vCDM through the ASAM CDFX (`.cdfx`) format.

It is written in Python and ships two console entry points (configured in `pyproject.toml`):

- **`s19tool`** — a Rich-formatted command-line interface for one-shot inspection and patching (`info`, `verify`, `dump`, `patch-hex`, `patch-str`, …).
- **`s19tui`** — a Textual terminal interface (a "TUI") for interactive exploration, cross-artefact validation and calibration-change authoring. As of batch-02 it uses the **Direction B** layout: a left activity rail + a top command bar + eight single-context screens.

There is no GUI, no daemon, no network surface and no external service dependency. Everything runs locally in a terminal, against files on disk.

## 2. Who it is for

Embedded **calibration engineers** working with ASAM A2L description files and ECU flash images. The typical user:

- reads and writes S-record (`.s19`) and Intel HEX (`.hex` / `.ihex`) firmware images,
- works with ASAM A2L (`.a2l`) descriptions of calibration symbols,
- works with MAC (`TAG=hexaddr`) symbol-map files,
- exchanges calibration-parameter changes with **Vector vCDM** as CDF 2.0 `.cdfx` files,
- needs a single offline workstation tool to triage issues, build a change-set, and hand it off.

## 3. Current capabilities

Four feature batches have shipped, each delivered through GRNDIA's V-model dev-flow (req → review → impl → val → post-mortem → docs). Headline capabilities, in delivery order:

- **Engine + validation (pre-batch-02 baseline).** S-record / Intel-HEX parsing, sparse memory map, contiguous range index, A2L structural parsing, MAC parsing, cross-artefact validation engine producing `ValidationIssue` records with severity / coverage metrics. Engine reference: [REQUIREMENTS.md](../REQUIREMENTS.md) §R-READ / R-PARSE / R-VAL / R-HEX / R-A2L.
- **Direction B TUI shell (batch `2026-05-20-batch-02`).** Activity rail + command bar + eight rail screens (Workspace, A2L Explorer, MAC View, Memory Map, Issues Report, Patch Editor, A↔B Diff, Bookmarks); Calm Dark theme; density toggle; responsive two-regime layout (fixed ≥ 120 cols, proportional < 120). View-layer-only — engine byte-for-byte unchanged. 16 living `R-TUI-021..R-TUI-037` rows in `REQUIREMENTS.md`.
- **Functional Patch Editor + ASAM CDFX I/O (batch `2026-05-21-batch-03`).** Parameter change-list model; A2L resolution; type-driven value display; CDF 2.0 `.cdfx` read and write (round-trip exact); the eight `W-*` write-time and nine `R-*` read-time structural rules; XML-safety hardening (DOCTYPE / entity rejection, 256 MB size cap, nesting-depth bound, path containment). 18 living `R-CDFX-001..R-CDFX-018` rows.
- **Memory-value editing + unified change-set + selective export (batch `2026-05-21-batch-04`).** `MemoryChangeList` (address-keyed raw-memory edit *intent*); validation against `LoadedFile.ranges`; hex / ASCII / decimal display; `UnifiedChangeSet` composing the parameter `ChangeList` and the `MemoryChangeList`; unified JSON file I/O with the ten `MF-*` structural rules; selective export to `.cdfx` (parameter half via the unchanged batch-03 writer) + a separate memory-field JSON file. 5 living `R-MEM-001..R-MEM-005` rows.

**Test suite:** **762 passing** (3 xfailed, 2 skipped) at the close of batch-04 — up from 275 before batch-02. **0 failures, 0 regressions** at every increment.

**Engine invariant:** the parsing / validation engine (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`) is **byte-for-byte unchanged** across batches 02–04. This is pinned by line-ending-normalised SHA-256 comparisons in `tests/test_cdfx_unchanged.py` (TC-027) and the writer-freeze test (TC-030).

## 4. Key formats handled

| Format | Role in the workflow | Where it is touched |
|---|---|---|
| **S19** (Motorola S-record) | firmware memory image — primary input | `s19_app/core.py` (`S19File`, `SRecord`) |
| **Intel HEX** (`.hex` / `.ihex`) | firmware memory image — alternative input | `s19_app/hexfile.py` (`IntelHexFile`) |
| **A2L** (ASAM) | calibration-symbol metadata: type, layout, conversion, axis | `s19_app/tui/a2l.py` (canonical module + `a2l_*` facades) |
| **MAC** (`TAG=hexaddr`) | flat tag → address map; cross-checked against A2L | `s19_app/tui/mac.py` |
| **CDF 2.0 / `.cdfx`** (ASAM) | calibration-data exchange XML for vCDM (round-trip) | `s19_app/tui/cdfx/writer.py`, `s19_app/tui/cdfx/reader.py` |
| **Unified change-set JSON** | this project's change-envelope: parameter + memory halves in one working document | `s19_app/tui/cdfx/unified_io.py`, `cdfx/changeset.py` |
| **Memory-field JSON** | the memory half of a selective export | `s19_app/tui/cdfx/export.py` |

## 5. Typical workflow

The four shipped batches assemble into one calibration workflow:

1. **Load.** Launch `s19tui`, load a firmware image (`.s19` / `.hex`) and an A2L (`.a2l`); optionally a MAC (`.mac`). Files are copied into `.s19tool/workarea/` first (every read and write resolves under that root — see §6 in [architecture.md](./architecture.md)).
2. **Review issues and coverage.** The **Issues Report** rail screen lists every `ValidationIssue` the cross-artefact engine collected, with severity colouring driven by `tui/color_policy.SEVERITY_CLASS_MAP`. The **Memory Map** screen shows firmware coverage (ranges, gaps) from `LoadedFile.ranges`.
3. **Explore A2L and MAC.** Inspect parameter metadata in the **A2L Explorer** (table + hex pane, 3/7 ÷ 4/7 split) and address mappings in the **MAC View**.
4. **Build a change-list.** In the **Patch Editor**, add parameter-change entries (`PARAMETER[0] : 23` form) and/or raw-memory-change entries (address + new bytes). Values render in the form best suited to the resolved A2L data type (decimal / hex / signed / float / quoted string for parameters; hex + ASCII + decimal for memory).
5. **Save the unified change-set.** One unified JSON file under `.s19tool/workarea/` holds both halves — the engineer's whole patch set as one working document.
6. **Selective export.** Export the unified change-set as **two** distinct work-area files: a `.cdfx` for the parameter half (consumed by Vector vCDM) and a separate memory-field JSON file for the memory half (which has no natural place in CDF 2.0).

A round-trip is exact: a value saved to either `.cdfx` or the unified JSON and re-loaded comes back equal (TC-024 for CDFX, TC-025 for the unified file). Float values round-trip via full-precision (`repr`-equivalent) `V` text — no float tolerance required.

## 6. What's deferred

`s19_app` is in active development. The following capabilities are deliberately out of the current scope and tracked for future batches:

| Deferred capability | Scope | Tracked under |
|---|---|---|
| **Apply-the-change-set / export-modified-S19** | take the unified change-set and produce a modified firmware image | named follow-up after batch-04 post-mortem; will require a full security review (touches firmware images) |
| **Undo / redo** | reversible edits in the Patch Editor | deferred from batch-03 and batch-04 |
| **CRC / checksum engine** | firmware-integrity computation | batch-02 post-mortem `B-3A` |
| **Bookmarks persistence** | the Bookmarks rail screen is currently a placeholder | batch-02 post-mortem `B-3C` |
| **A↔B firmware diff** | the A↔B Diff screen is a static three-column placeholder; no second-file load, no diff computation | batch-02 post-mortem `B-3C` |
| **PDF report export** | export the Issues Report to PDF | batch-02 post-mortem `B-3D` |
| **Live vCDM round-trip** | a real `.cdfx` produced by `s19_app` opens correctly in vCDM | client-side check; not automatable in-repo |

The memory-change model in batch-04 records edit *intent* only — no firmware image is modified.

## 7. Where things live

| You need to know… | Look in |
|---|---|
| project-level architecture | [architecture.md](./architecture.md) |
| living Mermaid diagrams (system, TUI shell, layout, CDFX, memory) | [diagrams/architecture.md](./diagrams/architecture.md) |
| living `R-*` requirement traceability (engine + every batch) | [../REQUIREMENTS.md](../REQUIREMENTS.md) |
| coding conventions, common commands, file-layer rules | [../CLAUDE.md](../CLAUDE.md) |
| per-batch executive summary (stakeholder-level, what shipped) | `.dev-flow/<batch>/06-docs/executive-summary.md` |
| per-batch functionality orientation (technical, terminology) | `.dev-flow/<batch>/06-docs/functionality.md` |
| per-batch requirements, review, validation, post-mortem | `.dev-flow/<batch>/{01-requirements,02-review,04-validation,05-postmortem}.md` |
| per-batch test→requirement traceability matrix | `.dev-flow/<batch>/06-docs/traceability-matrix.md` |
| current dev-flow batch state | `.dev-flow/state.json` |
| run / install / CLI examples | [../README.md](../README.md) |
