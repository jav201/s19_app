# Requirements Document — s19_app — Batch batch-02-direction-b-restyle

> **Strict normative convention — IEEE 830 + EARS**
> - `shall` = normative, binding, verifiable requirement. **Only** inside HLR / LLR statements.
> - `should` = informative / explanatory text, **NOT binding**. **Only** outside HLR / LLR statements (rationale, description, context).
> - Any use of `should` inside an HLR / LLR statement is a **writing error** and will be flagged as a blocker in phase 2.
> - `may` = optional. `will` = future declaration or fact about an external actor.

---

## 1. Introduction

### 1.1 Purpose

This document specifies the requirements for **Batch 02 — Direction B (Rail + Command) restyle** of the existing `s19_app` Textual TUI (`s19tui`). The batch re-layouts the existing TUI to the "Hex Lab — Direction B" visual language and adds the new Direction B view screens. It is a **view-layer-only** batch: it changes how information is arranged, navigated and themed, and adds view scaffolds for new screens, all wired to the **existing** parsing, validation and service engine.

This document produces User Stories (`US-NNN`), High-Level Requirements (`HLR-NNN`), Low-Level Requirements (`LLR-NNN.M`), and traceability to the living `R-*` requirements in `REQUIREMENTS.md`. It does not contain validation methods or test cases — those are added in a separate qa-reviewer pass (see Section 5).

### 1.2 Scope

**In scope (view layer only):**
- Re-layout of the existing three views (Main / A2L Tags / MAC) into Direction B's single-context workspace.
- A left activity rail (items 1–8) and a top command bar (`Ctrl+K` palette, `/` find, `g` go-to).
- A "Calm Dark" theme: one accent hue (cyan-blue) plus the severity colors defined by `color_policy.SEVERITY_CLASS_MAP`, dark mode only.
- A density toggle (`Ctrl+D`: compact / comfortable).
- New **view scaffolds** for: Memory Map screen, Patch Editor screen, A↔B Firmware Diff screen.
- Re-skinned Load / Save / Load-Project modals.
- Re-mapped keyboard bindings and refreshed status bar.

**Out of scope (explicitly deferred to follow-up batches):**
- Any change to data-processing behavior: `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py` (parse/validate), `tui/mac.py` (parse) remain behaviorally untouched.
- New runtime dependencies. The handoff `PLAN.md` proposal to add `bincopy` / `pya2l` / `crcmod` and to create a from-scratch `hexlab/` package "to replace the CLI" is **rejected as outdated** — the app already has a full TUI and engine. Requirements target the evolution of the existing `s19_app/tui/` package.
- The **logic** behind new screens: CRC / checksum computation engine, patch undo/redo, bookmark persistence, A↔B diff computation, PDF export. Where a Direction B screen implies one of these, this batch delivers the **view shell only** and the logic is deferred.

### 1.3 Definitions, acronyms, abbreviations

| Term | Definition |
|------|------------|
| TUI | Text User Interface — the `s19tui` Textual desktop terminal application. |
| Direction B | "Rail + Command" design from the Hex Lab handoff: left activity rail + top command bar + single-context workspace. |
| Activity rail | Vertical VS-Code-style navigation column on the left, items 1–8, one item active at a time. |
| Command bar | Top bar exposing the command palette (`Ctrl+K`), find (`/`) and go-to (`g`). |
| Rail item / screen | A selectable destination; selecting it swaps the workspace content. |
| Calm Dark theme | Dark-only theme with a single cyan-blue accent plus the severity colors defined by `color_policy.SEVERITY_CLASS_MAP`. |
| Density | Layout compactness mode: `compact` or `comfortable`, toggled by `Ctrl+D`. |
| Severity colors | The status colors defined by `color_policy.SEVERITY_CLASS_MAP` — the five `sev-*` classes (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`). The map's additional preserved styles `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE` are also unchanged in name and meaning. |
| View shell / scaffold | A screen that lays out panes and wires existing read-only data, with no new processing logic. |
| Engine | The existing parsing + validation + service stack under `s19_app/` and `s19_app/tui/services/`. |
| LoadedFile | The snapshot dataclass (`tui/models.py`) every renderer reads. |
| `R-*` | A living requirement entry in repo-root `REQUIREMENTS.md`. |
| EARS | Easy Approach to Requirements Syntax. |

### 1.4 References

- `REQUIREMENTS.md` (repo root) — living `R-*` requirements with traceability and status.
- `CLAUDE.md`, `PROJECT_RULES.md` (repo root) — project conventions, docstring contract, layering rules.
- `.dev-flow/2026-05-20-batch-02/design-input/handoff/PLAN.md`, `CLAUDE.md`, `README.md` — Hex Lab handoff (treated as visual + architectural reference only; the `hexlab/` rewrite framing is rejected).
- `.dev-flow/2026-05-20-batch-02/design-input/handoff/src/hexlab/` — Textual sketch (Direction B reference; not code to import).
- `.dev-flow/2026-05-20-batch-02/design-input/Hex-Lab-mock.html` — rendered artboards; the Direction B artboards are the spec for pane proportions, density and screen inventory.
- IEEE 830-1998 — Software Requirements Specifications.
- EARS (Mavin et al.) — requirement syntax patterns.

### 1.5 Document overview

Section 2 gives the overall description, constraints, the existing-vs-new screen inventory, and the source user stories. Section 3 lists the High-Level Requirements (EARS). Section 4 decomposes them into Low-Level Requirements. Section 5 is a placeholder for the qa-reviewer validation pass. Section 6 holds appendices: the `R-*` traceability map, candidate new `R-*` entries, assumptions, gaps and open questions.

---

## 2. Overall description

### 2.1 Product perspective

`s19_app` is a Python tool for embedded/automotive firmware engineering, shipping a Rich CLI (`s19tool`) and a Textual TUI (`s19tui`). The TUI today (`s19_app/tui/app.py`, ~5k lines) presents three mutually-exclusive layouts toggled by a top button bar / keys `1`/`2`/`3`:

- **Main view** (`#main_layout`): 5-tile grid — Workarea Files, Data Sections, Hex Viewer, A2L summary, Status (with the validation Issues `DataTable`).
- **Alt view** (`#alt_layout`): A2L Tags `DataTable` + a secondary Hex Viewer.
- **MAC view** (`#mac_layout`): MAC records `DataTable` + a secondary Hex Viewer.

The orchestration-only `S19TuiApp` routes parsing/validation through `tui/services/` (`load_service`, `a2l_service`, `validation_service`); renderers read the `LoadedFile` snapshot (`tui/models.py`). This batch restyles the **view layer** that sits on top of that engine. It introduces Direction B navigation (rail + command bar) and three new view scaffolds, without altering the engine, the `LoadedFile` contract, or any parsing/validation behavior.

### 2.2 Product functions

1. Navigate the TUI through a left activity rail (items 1–8) and a top command bar.
2. Present the existing Main, A2L and MAC views re-laid-out within a single-context Direction B workspace.
3. Present three new view scaffolds — Memory Map, Patch Editor, A↔B Firmware Diff — wired to existing read-only data.
4. Present validation issues as a dedicated Issues/Report screen.
5. Apply a dark-only "Calm Dark" theme with one accent hue plus the severity colors defined by `color_policy.SEVERITY_CLASS_MAP`.
6. Toggle layout density (compact / comfortable).
7. Re-skinned Load / Save / Load-Project modals.
8. Preserve every existing keyboard-reachable action under refreshed bindings and a refreshed status bar.

### 2.3 User characteristics

Primary users are embedded/automotive **calibration engineers** working with ASAM A2L description files and ECU flashing artifacts (S19 / Intel-HEX). They are technical, keyboard-oriented, and work with large symbol lists and large memory images. They expect a calm, low-density, dark interface and keyboard reachability for every action. No multi-user, permission, or web concerns apply — this is a single-user desktop TUI.

### 2.4 Constraints

- **C-1 — No data-processing changes.** The **parse and validate functions** of `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, and `tui/mac.py` shall remain behaviorally unchanged. (Constraint, restated in HLR-014.) **Scope clarification (A-01 resolved):** the freeze targets the parsing/validation *engine*, not the view layer. The A2L *rendering* helper `render_a2l_view` (in `tui/a2l.py`) and the thin `a2l_render.py` re-export facade are **view-layer code** and are explicitly re-stylable within this batch (HLR-009 / LLR-009.1); only the parse/validate/extract functions of `a2l.py` / `mac.py` are frozen. A change to `render_a2l_view` or `a2l_render.py` for layout/theme reasons does not violate C-1.
- **C-2 — No new runtime dependencies.** No new runtime or build dependency may be added; the `s19tui` runtime dependency set (`rich`, `textual`) is unchanged and the batch evolves `s19_app/tui/` only. **Scoped exception (OQ-5 resolved, approved):** `pytest-textual-snapshot` is permitted as a **dev-only optional dependency** declared under `[project.optional-dependencies]` in `pyproject.toml`; it is never added to `[project] dependencies`. This exception is dev/test-only and does not affect the runtime footprint. **Version constraint (S-5 resolved):** the `pytest-textual-snapshot` entry shall carry a version constraint — at minimum a `>=` lower-bound floor consistent with the `textual` `>=` floor of C-8 (OQ-13); a fully-pinned `==` version for CI reproducibility is an acceptable alternative. The optional-dependency block lands in `pyproject.toml` **only**; the legacy pre-PEP-621 `project.toml` at the repo root is not edited and is kept aligned per the `CLAUDE.md` "keep them aligned" rule.
- **C-3 — No new `hexlab/` package.** The handoff `hexlab/` rewrite is a visual/architectural reference only; no code is imported from it.
- **C-4 — Engine read-only.** New screens consume the existing `LoadedFile` snapshot and existing services; they introduce no new feature logic.
- **C-5 — Deferred logic.** CRC/checksum engine, patch apply/undo/redo, bookmark persistence, A↔B diff computation, and PDF export are out of scope; affected screens deliver the view shell only.
- **C-6 — Color budget.** The theme uses exactly one accent hue plus the severity colors already defined by `color_policy.SEVERITY_CLASS_MAP` — the five `sev-*` classes (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`). No new severity semantics. The map's further preserved styles `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE` are also kept unchanged in name and meaning.
- **C-7 — Dark mode only.** No light theme is in scope.
- **C-8 — Textual framework.** The TUI remains a Textual app; the `textual` / `rich` runtime dependency set is unchanged. **Acknowledged dependency-set note (OQ-13 resolved):** tied to the OQ-5 exception, `textual` gains a `>=` version floor (a minimum-version bound required by `pytest-textual-snapshot`) with **no hard upper ceiling**. This is a minor, acknowledged tightening of an existing declaration, not a new dependency.
- **C-9 — Keyboard reachability.** Every action reachable by mouse shall also be reachable by keyboard (existing project rule; restated in HLR-013).
- **C-10 — Increment discipline.** Implementation follows the supervised incremental workflow (max 5 files per increment unless approved); requirements are written so HLRs can be sequenced into independent increments.

### 2.5 Assumptions and dependencies

- **A-1** — The existing engine, services and `LoadedFile` snapshot are stable and correct; this batch does not need to fix them. If false, the batch is invalidated.
- **A-2** — The Direction B artboards in `Hex-Lab-mock.html` are the authoritative visual spec for pane proportions, density and screen inventory; the handoff Textual sketch is a structural reference only.
- **A-3** — The rail uses Unicode glyphs with a defined ASCII fallback (OQ-4 resolved): the sketch glyphs (`◫ ≡ ◉ ▤ ! ✎ ⏚ ✶`) are the default, and an ASCII-only fallback set is provided for terminals that cannot render them.
- **A-4** — "Bookmarks" is rail item 8 in the handoff sketch; bookmark persistence logic is deferred (C-5). OQ-3 resolved: the rail keeps **eight** items and the Bookmarks slot opens a neutral "coming soon" placeholder screen (no persistence logic this batch).
- **A-5** — The existing `validate_project_files` rule (one S19/HEX + one A2L + one MAC per project) and the `.s19tool/` workarea layout are unchanged; modal restyling does not alter them.
- **A-6** — `pytest-textual-snapshot` is approved (OQ-5 resolved) as a dev-only optional dependency for snapshot validation; see C-2 scoped exception.
- **A-7** — Direction B's single-context workspace replaces the current three-layout toggle; no requirement depends on the old `#view_bar` button bar surviving. The retired `#view_bar` button bar and the `view_main` / `view_alt` / `view_mac` actions are **superseded** by rail items 1 / 2 / 3 (Workspace / A2L Explorer / MAC View) — see LLR-004.4 — and their disappearance is an intended design change, not a regression.
- **A-8** — The Workspace pane layout has **two width regimes** governed by a 120-column breakpoint (A-03 resolved by the product owner): at terminal widths `>= 120` columns the side panes and rail use pinned fixed column widths; below 120 columns (down to the 80×24 minimum) the side panes become proportional and the rail collapses to an icon-only width, so the layout never clips. Both regimes are normatively specified in LLR-007.1 / LLR-008.1 / LLR-009.1 / LLR-010.1. 80×24 remains a supported size.

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**.

| ID | User Story | Source |
|----|------------|--------|
| US-001 | As a calibration engineer, I want a left activity rail listing the tool's screens, so that I can move between workspace, A2L, MAC, map, issues, patch and diff without hunting through menus. | Direction B handoff; mock artboards; owner intent |
| US-002 | As a calibration engineer, I want a top command bar with a command palette, find and go-to, so that any address or symbol is one keystroke away from any screen. | Direction B handoff; design-chat intent |
| US-003 | As a calibration engineer, I want a calm, modern, dark-only interface with restrained color, so that long calibration sessions are less visually fatiguing. | Owner intent ("modern minimal — calmer, more whitespace, less density. Dark mode only") |
| US-004 | As a calibration engineer, I want a density toggle, so that I can switch between a compact information-dense layout and a comfortable spacious one. | Owner intent ("density compact/comfortable"); handoff `Ctrl+D` |
| US-005 | As a calibration engineer, I want to load and explore a single hex/S19 file in a 3-pane workspace (hex dump + ranges/sections + context), so that I can inspect firmware memory efficiently. | Existing Main view; Direction B `b-workspace` artboard |
| US-006 | As a calibration engineer, I want to explore A2L symbols against memory in a dedicated screen, so that I can cross-reference symbols and jump to their addresses. | Existing Alt/A2L view; Direction B A2L artboard |
| US-007 | As a calibration engineer, I want to review MAC tags against A2L and memory in a dedicated screen, so that I can validate authentication tags. | Existing MAC view; Direction B MAC artboard |
| US-008 | As a calibration engineer, I want a dedicated validation Issues/Report screen with severity and jump-to-source, so that I can triage cross-artifact problems. | Existing Issues `DataTable`; Direction B validation artboard |
| US-009 | As a calibration engineer, I want a memory-map visualization screen, so that I can see firmware coverage and gaps at a glance. | Owner intent ("memory-map visualization"); Direction B `b-map` artboard |
| US-010 | As a calibration engineer, I want a patch-editor screen layout, so that the tool is ready to host memory patching once the patch logic lands. | Owner intent ("patch editor"); Direction B `b-patch` artboard; logic deferred (C-5) |
| US-011 | As a calibration engineer, I want an A↔B firmware-diff screen layout, so that the tool is ready to host firmware comparison once the diff logic lands. | Owner intent ("compare two firmware images / diff"); Direction B `b-diff` artboard; logic deferred (C-5) |
| US-012 | As a calibration engineer, I want re-skinned load/save/load-project dialogs consistent with the new theme, so that the modal experience matches the rest of the app. | Direction B handoff; existing modal screens |
| US-013 | As a calibration engineer, I want every action reachable from the keyboard with a visible status bar of bindings, so that I can operate the tool without a mouse. | Project rules (handoff `CLAUDE.md`); existing `BINDINGS` |
| US-014 | As a maintainer, I want the restyle to leave all parsing and validation behavior bit-for-bit identical, so that the tool's firmware-engineering correctness is not regressed by a cosmetic change. | Owner instruction ("do not change anything in regards of the data processing") |

---

## 3. High-level requirements (HLR)

### Screen inventory — existing vs new (input to increment planning)

> This table is normative input for downstream increment sequencing. "Restyle" = re-layout the existing screen and its widgets into Direction B; existing data wiring is reused. "New scaffold" = new screen that lays out panes and wires existing read-only data/services; no new processing logic.

| # | Direction B screen | Classification | Existing basis in `s19_app/tui/` | Notes |
|---|--------------------|----------------|----------------------------------|-------|
| 1 | Workspace (rail + 3-pane: ranges/sections · hex view · context) | **Restyle** | `#main_layout` in `app.py::compose` (Workarea Files, Data Sections, Hex Viewer, A2L summary, Status tiles); `hexview.py` | Re-layout the existing 5-tile grid into the Direction B 3-pane workspace. Hex view render caps and renderers unchanged. |
| 2 | A2L Explorer | **Restyle** | `#alt_layout` (A2L Tags `DataTable` + secondary Hex Viewer); `update_a2l_tags_view`, `_filter_a2l_tags`, A2L paging actions | Re-layout existing A2L Tags table + hex pane; filtering, paging, jump-to-address logic reused. |
| 3 | MAC View | **Restyle** | `#mac_layout` (MAC records `DataTable` + secondary Hex Viewer); `update_mac_view`, `update_mac_hex_view`, MAC paging | Re-layout existing MAC table + hex pane; MAC overlay highlight reused. |
| 4 | Validation / Issues Report | **Restyle** (promote to dedicated screen) | `validation_issues_list` `DataTable` currently embedded in the Main-view Status tile; `update_validation_issues_view`, `validation_issues_*` paging, issue filters | Today the Issues table lives inside the Main-view Status tile. Direction B promotes it to a full rail screen. Severity colors and jump-to-source reused. |
| 5 | Memory Map | **New scaffold** | Coverage data exists in `LoadedFile.ranges` / `range_validity`; no dedicated screen today | New screen rendering ranges/gaps/coverage from existing `LoadedFile`. No new coverage computation. |
| 6 | Patch Editor | **New scaffold** | None. CLI has `patch-hex`; TUI has no patch screen | View shell only: before/after hex panes layout + address/value input fields, **not wired to apply logic**. Patch apply / undo / redo deferred (C-5). |
| 7 | A↔B Firmware Diff | **New scaffold (static placeholder)** | None | View shell only: three-column layout (range list · hex A · hex B). OQ-7 resolved: **static placeholder scaffold** — NO real second-file load path and NO diff computation this batch; all three columns render placeholder data. "Placeholder data" is defined concretely in LLR-012.3: static, clearly-labelled sample hex rows in each of the three columns, visibly marked as placeholder content. |
| 8 | Load / Save / Load-Project modals | **Restyle** | `screens.py` (`LoadFileScreen`, `SaveProjectScreen`, `LoadProjectScreen`) | Re-skin to the Calm Dark theme; modal behavior, `validate_project_files` and workarea layout unchanged. |
| — | Bookmarks (rail item 8 in sketch) | **Placeholder screen** | None; persistence deferred (C-5) | OQ-3 resolved: the rail **keeps eight items**; the Bookmarks slot opens a neutral "coming soon" placeholder screen (see HLR-002 / LLR-002.2). No bookmark persistence logic this batch. |
| — | (retired) `#view_bar` button bar + `view_main` / `view_alt` / `view_mac` actions | **Superseded — not a regression** | `#view_bar` and the three `view_*` actions in `app.py` | A-02 resolved: the pre-batch top button bar and its three view-toggle actions are **superseded by rail items 1 / 2 / 3** (Workspace / A2L Explorer / MAC View). Their removal is an intended Direction B design change; the underlying Workspace / A2L / MAC screens remain keyboard-reachable via the rail and the command palette (see LLR-004.4). A Phase 4 keyboard-reachability check shall treat this as a designed supersession, not a lost action. |

> **Increment-planning note (informative):** screens 1–4 are restyles of working screens and carry regression risk against `R-TUI-*` / `R-A2L-*`; screens 5–7 are additive scaffolds with lower regression risk. A natural increment split is: (i) theme + density tokens, (ii) rail + command bar shell, (iii) restyle screens 1–4, (iv) new scaffolds 5–7, (v) modal re-skin. Final sequencing is decided in Phase 2/3.

---

### HLR-001 — Activity rail navigation
- **Traceability:** US-001
- **Statement:** The system shall present a persistent left activity rail listing exactly eight Direction B screens (Workspace, A2L Explorer, MAC View, Memory Map, Issues Report, Patch Editor, A↔B Diff, Bookmarks) with exactly one rail item marked active at a time.
- **Rationale (informative):** Direction B replaces the three-layout toggle with a single-context workspace navigated from a VS-Code-style rail. The Bookmarks slot is a permanent rail item that opens a placeholder screen this batch (OQ-3 resolved); persistence logic is deferred (C-5).
- **Validation:** demo + test
- **Priority:** high

### HLR-002 — Rail screen swap
- **Traceability:** US-001
- **Statement:** When the user activates a rail item, the system shall swap the workspace content to that screen and update the active-item marker.
- **Rationale (informative):** Selecting a rail item is the primary navigation gesture; activating the Bookmarks slot swaps to a neutral placeholder screen (OQ-3 resolved — see LLR-002.2).
- **Validation:** demo + test
- **Priority:** high

### HLR-003 — Top command bar
- **Traceability:** US-002
- **Statement:** The system shall present a top command bar that exposes a command palette, a find input, and a go-to-address input, reachable from every Direction B screen.
- **Rationale (informative):** Keeps addresses and symbols one keystroke away regardless of the active screen.
- **Validation:** demo + test
- **Priority:** high

### HLR-004 — Command-bar key bindings
- **Traceability:** US-002, US-013
- **Statement:** When the user presses `Ctrl+K`, `/`, or `g`, the system shall focus the command palette, the find input, and the go-to-address input respectively.
- **Rationale (informative):** Mirrors the binding contract from the Direction B handoff status bar.
- **Validation:** test
- **Priority:** high

### HLR-005 — Calm Dark theme
- **Traceability:** US-003
- **Statement:** The system shall render all Direction B screens with a dark-only theme that uses exactly one accent hue plus the severity colors defined by `color_policy.SEVERITY_CLASS_MAP`.
- **Rationale (informative):** Owner asked for a calmer, restrained, dark-only aesthetic; the color budget is fixed to avoid semantic drift. `SEVERITY_CLASS_MAP` defines five severity classes (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`); its further preserved styles `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE` are also unchanged.
- **Validation:** inspection + demo
- **Priority:** high

### HLR-006 — Density toggle
- **Traceability:** US-004
- **Statement:** When the user presses `Ctrl+D`, the system shall cycle the workspace layout density between compact and comfortable.
- **Rationale (informative):** Owner exposed density as a tweak; compact serves dense inspection, comfortable serves calm reading.
- **Validation:** demo + test
- **Priority:** medium

### HLR-007 — Density layout integrity
- **Traceability:** US-004
- **Statement:** While any density mode is active, the system shall keep every Direction B screen laid out without overlapping or clipped panes at each supported terminal size (80×24 minimum, 120×30 primary, 160×40), applying the two-regime width layout defined in LLR-007.1 — fixed pane widths at terminal widths `>= 120` columns and proportional pane widths at terminal widths `< 120` columns.
- **Rationale (informative):** A density change must not break any screen's layout. OQ-1/OQ-9 resolved: the supported size matrix is exactly {80×24, 120×30, 160×40}; the layout must not clip or overlap at the 80×24 minimum, and the calm/comfortable density target is validated principally at the 120×30 primary size. A-03 resolved (product owner): the prior contradiction between the pinned fixed pane widths (rail 22 + side panes 22 + 40 = 84 columns of fixed chrome) and the 80-column minimum is closed by making the layout width-responsive — the fixed widths apply only at `>= 120` columns, and below the 120-column breakpoint the side panes become proportional and the rail collapses to an icon-only width so the 80×24 minimum never clips.
- **Validation:** inspection + demo
- **Priority:** medium

### HLR-008 — Workspace 3-pane re-layout
- **Traceability:** US-005
- **Statement:** Where the Workspace screen is active, the system shall present a three-pane layout containing the data ranges/sections, the hex view, and a context pane, populated from the existing `LoadedFile` snapshot.
- **Rationale (informative):** Restyle of the current Main-view 5-tile grid into the Direction B `b-workspace` artboard proportions.
- **Validation:** demo + inspection
- **Priority:** high

### HLR-009 — A2L Explorer re-layout
- **Traceability:** US-006
- **Statement:** Where the A2L Explorer screen is active, the system shall present the existing A2L symbol table and hex pane re-laid-out to the Direction B A2L artboard, with the existing filtering, paging and jump-to-address behavior preserved.
- **Rationale (informative):** Restyle of the current Alt view; symbol-list logic is unchanged.
- **Validation:** demo + test
- **Priority:** high

### HLR-010 — MAC View re-layout
- **Traceability:** US-007
- **Statement:** Where the MAC View screen is active, the system shall present the existing MAC record table and hex pane re-laid-out to the Direction B MAC artboard, with the existing MAC overlay highlighting preserved.
- **Rationale (informative):** Restyle of the current MAC view; MAC parsing and overlay rules are unchanged.
- **Validation:** demo + test
- **Priority:** high

### HLR-011 — Validation Issues screen
- **Traceability:** US-008
- **Statement:** Where the Issues Report screen is active, the system shall present the existing validation issues table as a dedicated full screen with severity coloring and row-level jump-to-source preserved.
- **Rationale (informative):** Direction B promotes the Issues table out of the Main-view Status tile into its own rail screen.
- **Validation:** demo + test
- **Priority:** high

### HLR-012 — New view scaffolds (Memory Map, Patch Editor, A↔B Diff)
- **Traceability:** US-009, US-010, US-011
- **Statement:** The system shall provide view scaffolds for the Memory Map, Patch Editor, and A↔B Firmware Diff screens that lay out their panes per the Direction B artboards and render only data already available from the existing engine, with the A↔B Firmware Diff screen rendered as a static placeholder scaffold (no second-file load path, no diff computation).
- **Rationale (informative):** These screens establish the Direction B shell; CRC, patch-apply/undo/redo, bookmark, diff-computation and PDF-export logic is deferred to a follow-up batch (C-5). OQ-7 resolved: the A↔B Diff screen this batch is a Direction B 3-column view shell with placeholder data only — no real second-file load path and no diff computation are in scope.
- **Validation:** inspection + demo
- **Priority:** medium

### HLR-013 — Keyboard reachability and status bar
- **Traceability:** US-013
- **Statement:** The system shall keep every action reachable by keyboard and shall display the active screen's key bindings in a status bar.
- **Rationale (informative):** Existing project rule; the restyle must not introduce a mouse-only action.
- **Validation:** inspection + test
- **Priority:** high

### HLR-014 — Data-processing behavior preserved
- **Traceability:** US-014
- **Statement:** The system shall keep the parsing and validation behavior of `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, and `tui/mac.py` unchanged after the restyle.
- **Rationale (informative):** Owner instruction — the restyle is cosmetic and must not regress firmware-engineering correctness; this is the master non-regression requirement.
- **Validation:** test (existing suite) + inspection
- **Priority:** high

### HLR-015 — Modal re-skin
- **Traceability:** US-012
- **Statement:** The system shall re-skin the Load, Save and Load-Project modal screens to the Calm Dark theme while preserving their existing behavior, including `validate_project_files` enforcement and the `.s19tool/` workarea layout.
- **Rationale (informative):** Modal dialogs must visually match the new theme without changing project-file rules.
- **Validation:** demo + test
- **Priority:** medium

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level. ID format `LLR-<HLR>.<M>`. EARS regime applies.

### LLR-001.1 — Rail widget composition
- **Traceability:** HLR-001
- **Statement:** The TUI shall compose a left activity-rail widget containing exactly eight ordered rail items bound to keys `1`–`8`.
- **Acceptance criteria (informative):**
  - The rail is present in the workspace screen composition.
  - Rail items are ordered Workspace, A2L, MAC, Map, Issues, Patch, Diff, Bookmarks.
  - OQ-3 resolved: the count is fixed at eight; the Bookmarks slot is a permanent rail item (no "omit" variant).
  - Cross-reference (CV-02): the rail's width is governed by the two-regime width layout — at terminal widths `< 120` columns the rail collapses to an icon-only fixed width of 4 columns ±1 column, as normatively specified in LLR-008.1 / LLR-009.1 / LLR-010.1. The collapsed rail is asserted by TC-016 / TC-017.

### LLR-001.3 — Rail glyph rendering with ASCII fallback
- **Traceability:** HLR-001
- **Statement:** The TUI shall render each rail item with the Unicode glyph paired to that item's screen by the glyph→screen mapping table below, and shall provide the paired ASCII-only fallback glyph for terminals that cannot render the Unicode glyphs.
- **Glyph→screen mapping table (normative):**

  | Rail position / key | Screen | Unicode glyph | ASCII fallback glyph |
  |---|---|---|---|
  | 1 | Workspace | `◫` | `#` |
  | 2 | A2L Explorer | `≡` | `=` |
  | 3 | MAC View | `◉` | `@` |
  | 4 | Memory Map | `▤` | `M` |
  | 5 | Issues Report | `!` | `!` |
  | 6 | Patch Editor | `✎` | `P` |
  | 7 | A↔B Diff | `⏚` | `D` |
  | 8 | Bookmarks | `✶` | `*` |

- **Rationale (informative):** A-04 resolved: the eight-item rail order (LLR-001.1) and the Unicode/ASCII glyph set were previously paired only by the positional order of two separate LLRs. The table above makes the glyph→screen pairing explicit and directly testable. The Unicode column is the sketch set `◫ ≡ ◉ ▤ ! ✎ ⏚ ✶` in rail order; the ASCII column is a defined per-item fallback. The ASCII fallback glyphs are illustrative defaults — the implementer may refine individual fallback characters in Phase 3 provided each rail item retains a distinct, defined ASCII fallback.
- **Acceptance criteria (informative):**
  - Each of the eight rail items renders the Unicode glyph paired to its screen in the table above, and has a paired, defined ASCII fallback glyph.
  - The glyph→screen pairing matches the table for all eight items; the pairing is no longer implied only by positional order.
  - OQ-4 resolved: Unicode is the default; the ASCII fallback is selectable/automatic for non-supporting terminals.

### LLR-001.2 — Single active rail item
- **Traceability:** HLR-001
- **Statement:** While the TUI is running, the rail shall mark exactly one item as active with an accent-colored marker.
- **Acceptance criteria (informative):**
  - At startup the Workspace item is active.
  - Activating another item moves the active marker and clears the previous one.
  - Cross-reference (CV-02): the active-item marker remains a single accent-colored marker in the `< 120`-column collapsed-rail (icon-only, 4±1 columns) regime defined in LLR-008.1 / LLR-009.1 / LLR-010.1.

### LLR-002.1 — Rail-driven content swap
- **Traceability:** HLR-002
- **Statement:** When a rail item is activated by key or click, the TUI shall show that item's screen content and hide the other rail screens' content.
- **Acceptance criteria (informative):**
  - Only one rail screen's content is visible at a time.
  - The swap reuses the existing show/hide layout mechanism (analogous to the current `#main_layout` / `#alt_layout` / `#mac_layout` class toggling).

### LLR-002.2 — Bookmarks placeholder screen
- **Traceability:** HLR-002
- **Statement:** When the Bookmarks rail item is activated, the TUI shall swap the workspace content to a neutral placeholder screen indicating the feature is coming soon, without invoking any bookmark-persistence logic.
- **Acceptance criteria (informative):**
  - Activating Bookmarks does not raise an error.
  - The placeholder screen text states the feature is not yet available / coming soon.
  - No bookmark persistence is read or written this batch (C-5).
  - OQ-3 resolved: the Bookmarks slot is always present; the "omit" option is closed. TC-005 (Bookmarks-omitted variant) is now N/A; TC-004 is the sole Bookmarks verdict.

### LLR-002.3 — Empty-state panel when no file is loaded
- **Traceability:** HLR-002
- **Statement:** Where a rail screen is activated while no file is loaded, the TUI shall display a neutral empty-state panel prompting the user to load a file.
- **Acceptance criteria (informative):**
  - With no `LoadedFile` present, activating Workspace, A2L Explorer, MAC View, or Memory Map shows an empty-state panel instead of an error or blank pane.
  - The empty-state text prompts a load action (e.g. "no file loaded — Ctrl+L to load").
  - OQ-11 resolved: rail screens have a defined neutral empty state for the no-file-loaded condition. A "rail navigation before any load" test case is now specifiable for LLR-002.3.

### LLR-003.1 — Command-bar composition
- **Traceability:** HLR-003
- **Statement:** The TUI shall compose a top command-bar widget exposing a command-palette trigger, a find input, and a go-to-address input.
- **Acceptance criteria (informative):**
  - The command bar is mounted above the rail/workspace body.
  - The command bar is visible on every Direction B screen.

### LLR-003.2 — Command palette population
- **Traceability:** HLR-003
- **Statement:** The command palette shall list the existing TUI actions (load file, save/load project, rail navigation, paging, dump A2L JSON) as selectable commands.
- **Rationale (informative):** A-06 resolved: the action list previously named a phantom "export" command. There is no `export` action in the pre-batch `BINDINGS`; the only export-like binding is `j` → `dump_a2l_json` (`R-A2L-003`). The list now names "dump A2L JSON", consistent with the wording in LLR-004.4.
- **Acceptance criteria (informative):**
  - Every action currently in `BINDINGS` has a corresponding palette entry.
  - Selecting a palette entry invokes the same action handler as its key binding.

### LLR-003.3 — Command palette type-to-filter search
- **Traceability:** HLR-003
- **Statement:** While the command palette is open, the TUI shall filter the listed commands to those matching the text typed into the palette input.
- **Acceptance criteria (informative):**
  - Typing in the palette narrows the visible command list to matching entries.
  - Clearing the filter text restores the full command list.
  - OQ-10 resolved: the palette is searchable (type-to-filter), not a static list. A filter-behavior test case is needed for LLR-003.3 (TC-007 currently covers population only).

### LLR-004.1 — Find binding
- **Traceability:** HLR-004
- **Statement:** When the user presses `/`, the TUI shall move keyboard focus to the command-bar find input.
- **Acceptance criteria (informative):**
  - Pressing `/` from any Direction B screen focuses the find input.

### LLR-004.6 — Find input routes to the existing validated search handler
- **Traceability:** HLR-003, HLR-004
- **Statement:** When the user submits text in the command-bar find input, the TUI shall route that text to the existing search handler `find_string_in_mem` and shall not introduce any new string-decoding or search-parsing code; invalid or non-matching input shall be reported through the existing `set_status` path exactly as it is today.
- **Rationale (informative):** S-1 resolved (security-reviewer): the command bar is a new input surface. Pinning it to the already-validated `find_string_in_mem` handler prevents a re-wire during implementation from silently adding a fresh, unguarded string-decoding code path — the batch is view-layer only (C-1, C-4) and must not expand the input/defect surface. `find_string_in_mem` already honors `SEARCH_ENCODING`; no new encoding logic is in scope.
- **Acceptance criteria (informative):**
  - Submitted find text is handled by `find_string_in_mem`; no new search/decoding function is added.
  - Non-matching or malformed find input is surfaced via `set_status`, not via a new error path.

### LLR-004.2 — Go-to binding and routing to the existing validated handler
- **Traceability:** HLR-003, HLR-004
- **Statement:** When the user presses `g`, the TUI shall move keyboard focus to the command-bar go-to-address input; and when the user submits text in that input, the TUI shall route that text to the existing go-to-address handler `_handle_goto` and shall not introduce any new address-parsing code; invalid input shall be reported through the existing `set_status` path exactly as it is today.
- **Rationale (informative):** S-1 resolved (security-reviewer): the go-to input is a new input surface. Pinning submission to the already-validated `_handle_goto` handler (which reads the go-to input off the widget tree and parses/validates the address as it does today) prevents a re-wire from introducing fresh, unguarded address-parsing code — the batch is view-layer only (C-1, C-4). `_handle_goto` already reports malformed addresses via `set_status`; that behavior is preserved unchanged.
- **Acceptance criteria (informative):**
  - Pressing `g` focuses the go-to input.
  - Submitting an address invokes the existing `_handle_goto` handler; no new address-parsing function is added.
  - Malformed go-to input is surfaced via `set_status`, not via a new error path.

### LLR-004.3 — Command palette binding
- **Traceability:** HLR-004
- **Statement:** When the user presses `Ctrl+K`, the TUI shall open or focus the command palette.
- **Acceptance criteria (informative):**
  - `Ctrl+K` from any Direction B screen opens the palette.

### LLR-004.4 — Binding regression guard
- **Traceability:** HLR-004, HLR-013
- **Statement:** The TUI shall retain a keyboard path (key binding or command-palette entry) for every action present in the pre-batch `BINDINGS` set (load, refresh, open workarea, save/load project, dump A2L JSON, view switch, paging, quit).
- **Rationale (informative):** A-02 / Q-04 resolved: the retired `#view_bar` button bar and the `view_main` / `view_alt` / `view_mac` view-switch actions, and the prior meaning of the `1` / `2` / `3` keys, are **intentionally superseded** by rail items 1 / 2 / 3 (Workspace / A2L Explorer / MAC View). This is a designed Direction B change, not a regression: the three keys are remapped from view-toggle to rail-item activation, the `#view_bar` surface is removed, and the underlying Workspace / A2L / MAC screens remain keyboard-reachable via the rail keys `1`/`2`/`3` and via the command palette. A Phase 4 keyboard-reachability check shall treat the disappearance of `#view_bar` and the `1`/`2`/`3` remap as designed supersession rather than a lost action.
- **Acceptance criteria (informative):**
  - No pre-batch action becomes keyboard-unreachable; the Workspace / A2L / MAC screens behind the retired `view_*` actions remain reachable via rail items 1/2/3 and the palette.
  - The `1`/`2`/`3` → rail-item remap and the removal of `#view_bar` are recorded as intended supersession, not regressions.
  - Re-mapped keys are documented in the status bar / palette.

### LLR-004.5 — Single-key binding suppression during input focus
- **Traceability:** HLR-004, HLR-013
- **Statement:** While a command-bar input (find, go-to-address, or palette input) holds keyboard focus, the TUI shall route every unmodified single-key binding — `g`, the digits `1`–`8`, and the paging keys `+`, `-`, `,`, `.` — as text into the focused input rather than firing the binding action.
- **Rationale (informative):** Q-05 resolved: the suppression rule previously covered only `g` and `1`–`8`, but the pre-batch `BINDINGS` also include single-key paging bindings (`+`, `-`, `,`, `.`). These are unmodified single keys that would collide with typed search/go-to text — typing `,` into the find input would otherwise fire a page action. The rule now covers all unmodified single-key bindings. A-07 resolved: this suppression applies only to *unmodified* single keys; **modified** bindings (`Ctrl+K` command palette, `Ctrl+D` density toggle, and any other `Ctrl`/`Alt`-modified binding) remain active while a command-bar input holds focus, so the palette and density toggle stay operable while the user is typing.
- **Acceptance criteria (informative):**
  - Typing `g`, a digit `1`–`8`, or any of `+` `-` `,` `.` into a focused find/go-to/palette input inserts the character and does not trigger go-to focus, rail navigation, or a paging action.
  - Modified-key bindings (`Ctrl+K`, `Ctrl+D`) stay active during input focus and fire normally.
  - Single-key bindings resume normal behavior once the input loses focus.
  - OQ-8/OQ-12 resolved: keystrokes go to the input while it holds focus; the final keybinding map is proposed by the implementer in Phase 3 increment 1. TC-008/TC-009/TC-029 each carry an "input has focus" sub-case asserting the binding does not fire.

### LLR-005.1 — Theme tokens
- **Traceability:** HLR-005
- **Statement:** The TUI stylesheet shall define a dark-only token set with a single accent variable and the five severity classes that map one-to-one to `color_policy.SEVERITY_CLASS_MAP` (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`).
- **Rationale (informative):** Q-01 resolved: `SEVERITY_CLASS_MAP` defines **five** severity classes, not three. The token set maps one-to-one to all five. The map's further preserved styles `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE` are also retained unchanged in name and meaning by the restyle.
- **Acceptance criteria (informative):**
  - Exactly one accent hue is defined.
  - All five severity CSS classes (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`) are unchanged in name and meaning.
  - `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE` are preserved unchanged in name and meaning.
  - No light-theme variant is introduced.

### LLR-005.2 — Severity color source of truth
- **Traceability:** HLR-005, HLR-014
- **Statement:** The TUI shall continue to derive severity row colors from `color_policy.css_class_for_severity` without adding new severity values.
- **Acceptance criteria (informative):**
  - `SEVERITY_CLASS_MAP` is read unchanged.
  - No new `ValidationSeverity` value is introduced by this batch.

### LLR-006.1 — Density cycle action
- **Traceability:** HLR-006
- **Statement:** When the user presses `Ctrl+D`, the TUI shall toggle a density CSS class on the workspace root between a compact and a comfortable variant.
- **Acceptance criteria (informative):**
  - `Ctrl+D` cycles compact ↔ comfortable.
  - The active density is indicated to the user (status bar or notification).

### LLR-006.2 — Density default
- **Traceability:** HLR-006
- **Statement:** At startup, the TUI shall apply the Comfortable density mode as the default.
- **Acceptance criteria (informative):**
  - The startup density class on the workspace root is the Comfortable variant.
  - OQ-2 resolved: the default startup density is Comfortable.

### LLR-007.1 — Density layout integrity across both width regimes
- **Traceability:** HLR-007
- **Statement:** While each density mode is active, every Direction B screen shall render without overlapping or clipped panes at terminal sizes 80×24, 120×30, and 160×40, observing the two-regime width layout: while the terminal width is `>= 120` columns the panes shall use the fixed widths of LLR-008.1 / LLR-009.1 / LLR-010.1, and while the terminal width is `< 120` columns the panes shall use the proportional widths of those same LLRs.
- **Rationale (informative):** A-03 resolved (product owner): a single fixed-width layout cannot satisfy both the pinned pane widths (84 columns of fixed chrome) and the 80×24 minimum. The two-regime layout closes the contradiction — fixed widths above the 120-column breakpoint, proportional widths below it. 80×24 remains a supported size and renders in the proportional regime.
- **Acceptance criteria (informative):**
  - Each screen renders correctly in compact and comfortable at each of 80×24, 120×30, 160×40.
  - At 120×30 and 160×40 (both `>= 120` columns) the panes render in the fixed-width regime per LLR-008.1 / LLR-009.1 / LLR-010.1.
  - At 80×24 (`< 120` columns) the panes render in the proportional regime per LLR-008.1 / LLR-009.1 / LLR-010.1; no clipping or pane overlap occurs and no pane is allocated a negative or zero width.
  - The calm/comfortable density target is validated principally at 120×30.
  - OQ-1/OQ-9 resolved: the size matrix is exactly {80×24, 120×30, 160×40}. A-03 resolved: 120 columns is the regime breakpoint.

### LLR-007.2 — Snapshot baselines render only public synthetic fixtures
- **Traceability:** HLR-007
- **Statement:** The `pytest-textual-snapshot` SVG baselines shall be rendered only against the public synthetic fixtures — the artifacts under `examples/case_00_public/` and the deterministic generators in `tests/conftest.py` (`make_large_s19` / `make_large_a2l` / `make_large_mac`) — and shall not be rendered against any client firmware, A2L, or MAC artifact.
- **Rationale (informative):** S-2 resolved (security-reviewer): `pytest-textual-snapshot` SVG baselines render actual screen content. A baseline captured against a real client artifact would embed that file's bytes, addresses, symbol names and MAC tags as committed `.svg` — proprietary client data committed to a shared, version-controlled repo, an easily-overlooked exfiltration channel. Restricting baseline rendering to the public synthetic fixtures eliminates that channel; every committed `.svg` traces back to a non-confidential, in-repo source.
- **Acceptance criteria (informative):**
  - Every committed snapshot `.svg` baseline traces back to a public synthetic fixture (`examples/case_00_public/` or a `tests/conftest.py` generator).
  - No snapshot baseline is captured from a client artifact or any non-public file.

### LLR-008.1 — Workspace three-pane structure (two-regime width layout)
- **Traceability:** HLR-008
- **Statement:** The Workspace screen shall compose three horizontally-arranged panes — data ranges/sections (left), hex view (center), and context (right) — with a width layout governed by a 120-column terminal-width breakpoint:
  - **While the terminal width is `>= 120` columns**, the left ranges/sections pane shall be a fixed width of 22 columns ±2 columns, the right context pane shall be a fixed width of 40 columns ±2 columns, and the center hex-view pane shall consume the remaining width as a single flexible `1fr` unit (the Direction B `b-workspace` artboard proportions).
  - **While the terminal width is `< 120` columns**, the left ranges/sections pane shall be a proportional width of 24% ±3 percentage points of the workspace body width, the right context pane shall be a proportional width of 30% ±3 percentage points of the workspace body width, and the center hex-view pane shall consume the remaining width as a single flexible `1fr` unit; in this regime the activity rail shall additionally collapse to an icon-only fixed width of 4 columns ±1 column.
- **Rationale (informative):** A-03 resolved (product owner — proportional panes below a 120-column breakpoint). The fixed-width targets are derived from the Direction B handoff Textual sketch, the authoritative encoding of the artboard proportions (A-2, PLAN.md §5.1 "match in `.tcss` using `width: <fr>`"): the workspace body is `Rail(width: 22)` │ `#main(width: 1fr)` │ `Inspector(width: 40)`. At `>= 120` columns the fixed side panes use Textual fixed-column `width` and the center pane uses one `fr` unit. Below 120 columns those same fixed widths plus the 22-column rail sum to 84 columns of chrome, which cannot coexist with the 80-column minimum; the proportional regime resolves this — the side panes use percentage/`fr` widths and the rail collapses to icon-only so the hex pane always receives a positive remainder (worked example at 80×24: rail 4 + left ≈18 (24%) + right ≈23 (30%) leaves ≈35 columns for the hex pane — the 24% / 30% proportions applied to the ≈76-column workspace body). The ±2-column / ±3-point tolerances absorb border/padding rounding (`border-left`/`border-right: solid` add one column each) without permitting layout drift.
- **Acceptance criteria (informative):**
  - Three named panes are present, ordered left-to-right: ranges/sections, hex view, context.
  - At a `>= 120`-column terminal width: the left ranges/sections pane is 22 ±2 columns wide; the right context pane is 40 ±2 columns wide; the center hex-view pane is the `1fr` flexible remainder. Objectively testable at 120×30 / 160×40.
  - At a `< 120`-column terminal width: the left ranges/sections pane is 24% ±3 points of the workspace body width; the right context pane is 30% ±3 points; the center hex-view pane is the `1fr` flexible remainder and is allocated a strictly positive width; the rail is collapsed to 4 ±1 columns. Objectively testable at 80×24.
  - These ratios are objectively testable against the stated numeric tolerances in both regimes (no longer "match the artboard" by inspection only).

### LLR-008.2 — Workspace data wiring unchanged
- **Traceability:** HLR-008, HLR-014
- **Statement:** The Workspace panes shall be populated by the existing `update_sections`, `update_hex_view`, and related renderers reading the `LoadedFile` snapshot.
- **Acceptance criteria (informative):**
  - No renderer is modified to parse data.
  - Hex rendering still respects `MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`.

### LLR-009.1 — A2L Explorer layout (flat 3/7 hex : 4/7 tags proportional ratio)
- **Traceability:** HLR-009
- **Statement:** The A2L Explorer screen shall present the existing A2L symbol `DataTable` and a hex pane re-laid-out to the Direction B A2L proportions as a flat proportional split at all terminal widths: the hex pane shall be 3/7 of the A2L panes content width ±3 percentage points, and the A2L symbol `DataTable` shall be the remaining 4/7 ±3 percentage points.
- **Supersession note (informative):** Increment-13 review feedback amends this LLR. The iteration-3 two-regime split for A2L — a pinned fixed `40 ±2`-column hex pane while the terminal width is `>= 120` columns and a `35% ±3`-point hex pane while it is `< 120` columns — is **superseded for A2L only** by the flat 3/7 : 4/7 proportional ratio above. **Reason:** on review of the running app the fixed 40-column A2L hex pane was too narrow to show the hex content correctly; widening the hex pane to a flat 3/7 share fixes this at every terminal width. The `width-narrow` two-regime distinction is no longer relevant to the A2L panes (the `3fr : 4fr` ratio is already proportional and width-responsive). **`LLR-010.1` / MAC View is unchanged** — the MAC View keeps the iteration-3 two-regime `40 ±2` / `35% ±3` layout. The activity-rail collapse below 120 columns (LLR-001.1 CV-02 / LLR-008.1) is governed by `#workspace_shell` and is unaffected by this A2L pane change.
- **Rationale (informative):** A-03's two-regime layout was designed around the handoff Textual sketch's fixed 40-column secondary column. Review of the running A2L Explorer showed 40 columns is too narrow to render the hex view correctly — a 16-byte hex row plus address gutter and ASCII margin needs more horizontal room. A flat 3/7 hex share gives the hex pane a substantially wider, width-proportional allocation at every size while the symbol table keeps the larger 4/7 share. The ±3-point tolerance absorbs border/padding integer rounding.
- **Acceptance criteria (informative):**
  - The A2L symbol table and hex pane are both present.
  - At every supported terminal width: the hex pane is 3/7 (≈42.9%) ±3 points of the A2L panes content width; the A2L symbol `DataTable` is the remaining 4/7 (≈57.1%) ±3 points and is allocated a strictly positive width. Objectively testable at 80×24, 120×30 and 160×40.
  - The 3/7 : 4/7 ratio holds at ALL terminal widths — there is no longer a 120-column regime split for the A2L panes.
  - This ratio is objectively testable against the stated numeric tolerance (no longer "match the artboard" by inspection only).

### LLR-009.2 — A2L behavior preserved
- **Traceability:** HLR-009, HLR-014
- **Statement:** The A2L Explorer shall preserve the existing tag filtering, find-next, page navigation, and jump-to-address behavior.
- **Acceptance criteria (informative):**
  - Field/mode filtering (`R-A2L-007`) still works.
  - Page navigation buttons and `+`/`-` paging (`R-TUI-019`, `R-TUI-020`) still work.
  - Selecting a tag row still jumps the hex pane (`R-TUI-018`).

### LLR-010.1 — MAC View layout (two-regime width layout)
- **Traceability:** HLR-010
- **Statement:** The MAC View screen shall present the existing MAC record `DataTable` and a hex pane re-laid-out to the Direction B MAC proportions, with a width layout governed by a 120-column terminal-width breakpoint:
  - **While the terminal width is `>= 120` columns**, the MAC record `DataTable` shall consume the available width as a single flexible `1fr` unit and the hex pane shall be a fixed width of 40 columns ±2 columns.
  - **While the terminal width is `< 120` columns**, the hex pane shall be a proportional width of 35% ±3 percentage points of the screen body width and the MAC record `DataTable` shall consume the remaining width as a single flexible `1fr` unit; in this regime the activity rail shall collapse to an icon-only fixed width of 4 columns ±1 column.
- **Rationale (informative):** A-03 resolved (product owner — proportional panes below a 120-column breakpoint). The fixed-width targets are derived from the Direction B handoff Textual sketch (A-2, PLAN.md §5.1). The MAC View applies the same handoff body convention as the A2L Explorer — a `1fr` flexible primary column plus a fixed 40-column companion at `>= 120` columns, and a proportional hex pane plus collapsed rail below 120 columns so the layout holds down to the 80×24 minimum. The ±2-column / ±3-point tolerances absorb border/padding rounding.
- **Acceptance criteria (informative):**
  - The MAC record table and hex pane are both present.
  - At a `>= 120`-column terminal width: the MAC record `DataTable` is the `1fr` flexible remainder; the hex pane is 40 ±2 columns wide. Objectively testable at 120×30 / 160×40.
  - At a `< 120`-column terminal width: the hex pane is 35% ±3 points of the screen body width; the MAC record `DataTable` is the `1fr` flexible remainder and is allocated a strictly positive width; the rail is collapsed to 4 ±1 columns. Objectively testable at 80×24.
  - These ratios are objectively testable against the stated numeric tolerances in both regimes (no longer "match the artboard" by inspection only).

### LLR-010.2 — MAC behavior preserved
- **Traceability:** HLR-010, HLR-014
- **Statement:** The MAC View shall preserve the existing MAC record paging, row severity coloring, MAC address overlay highlighting, and jump-to-address behavior.
- **Acceptance criteria (informative):**
  - MAC paging still works.
  - The MAC overlay highlight style is preserved.
  - Selecting a MAC row still jumps the hex pane (`R-TUI-018`).

### LLR-011.1 — Issues screen layout
- **Traceability:** HLR-011
- **Statement:** The Issues Report screen shall present the existing `validation_issues_list` `DataTable` as the primary content of a dedicated rail screen.
- **Acceptance criteria (informative):**
  - The Issues table is no longer nested inside the Workspace Status tile.
  - The Issues screen has its own rail item.

### LLR-011.2 — Issues behavior preserved
- **Traceability:** HLR-011, HLR-014
- **Statement:** The Issues Report screen shall preserve the existing issue severity coloring, severity filters (All/Errors/Warnings), paging, and row jump-to-source behavior.
- **Acceptance criteria (informative):**
  - Severity colors round-trip through `css_class_for_severity`.
  - Issue filter buttons and paging still work.
  - Selecting an issue row still jumps to its source.

### LLR-011.3 — Project-name / A2L-filename status content relocation
- **Traceability:** HLR-011, HLR-013
- **Statement:** When the Issues table is promoted out of the Main-view Status tile, the TUI shall render the project-name and A2L-filename status content (`R-TUI-016`) in the persistent command bar so that it remains visible from every Direction B screen.
- **Rationale (informative):** A-05 resolved (G-2 closed): promoting the Issues `DataTable` to a dedicated rail screen (LLR-011.1) orphans the project-name / A2L-filename status content the old Status tile carried, which `R-TUI-016` protects. Its new home is the command bar — a surface present on every screen (LLR-003.1) — so the information stays continuously visible rather than being tied to one screen. Placing it in the status/footer bar would be an acceptable alternative, but the command bar is chosen because it is always mounted at the top of the workspace and is the natural home for project-context labels.
- **Acceptance criteria (informative):**
  - The project name and A2L filename remain visible after the Issues table moves out of the Status tile.
  - The relocated content is shown in the command bar and is visible on every Direction B screen.
  - No project-name / A2L-filename information is lost in the move (`R-TUI-016` not regressed).

### LLR-012.1 — Memory Map scaffold
- **Traceability:** HLR-012
- **Statement:** The Memory Map screen shall render firmware coverage from the existing `LoadedFile.ranges` and `range_validity` without computing new coverage data.
- **Acceptance criteria (informative):**
  - The screen renders ranges and gaps from existing data.
  - No new coverage computation is added.

### LLR-012.2 — Patch Editor view shell
- **Traceability:** HLR-012
- **Statement:** The Patch Editor screen shall lay out a before/after hex-pane structure and address/value input fields without wiring to any patch-apply, undo, or redo logic.
- **Acceptance criteria (informative):**
  - The screen renders the layout.
  - Input fields are present but not connected to a patch engine.
  - The screen states that patch logic is deferred.

### LLR-012.3 — A↔B Diff view shell (static placeholder)
- **Traceability:** HLR-012
- **Statement:** The A↔B Firmware Diff screen shall lay out a three-column structure (range list, hex A, hex B) populated with placeholder data only — defined as static, clearly-labelled sample hex rows in each of the three columns, visibly marked as placeholder content — without a second-file load path and without wiring to any diff-computation logic.
- **Rationale (informative):** A-08 resolved: "placeholder data" was previously undefined, leaving an implementer and a Phase 4 reviewer free to disagree on whether empty panes, a single label, or sample rows satisfy it. The placeholder is now concretely defined: each of the three columns renders static sample hex rows (a small fixed set of constant rows, not data sourced from any loaded file or from any diff computation), and each column carries a visible marker (e.g. a "PLACEHOLDER" caption or watermark) so the content is unambiguously not real diff output.
- **Acceptance criteria (informative):**
  - The three-column layout renders with placeholder content in all three columns: each column shows static, constant sample hex rows.
  - Each column is visibly marked as placeholder content (a caption/label/watermark identifying it as not real data).
  - The placeholder rows are not sourced from any `LoadedFile` and not produced by any diff computation.
  - No control to load a second ("B") firmware file is present or wired this batch.
  - The screen states that diff computation and the second-file load path are deferred.
  - OQ-7 resolved: this batch delivers a static placeholder scaffold only.

### LLR-012.4 — Deferred-logic guard
- **Traceability:** HLR-012
- **Statement:** If a Direction B screen would require CRC/checksum, patch undo/redo, bookmark persistence, diff computation, or PDF export, then the screen shall render only its view shell and shall not invoke or import logic for that capability.
- **Acceptance criteria (informative):**
  - No new processing module is created for these capabilities.
  - Deferred capabilities are clearly marked in the UI.

### LLR-013.1 — No mouse-only actions
- **Traceability:** HLR-013
- **Statement:** The TUI shall provide a keyboard path for every interactive control introduced by the Direction B restyle (rail items, command bar, density toggle, new-screen controls).
- **Acceptance criteria (informative):**
  - Every new control is reachable by key.

### LLR-013.2 — Status bar bindings
- **Traceability:** HLR-013
- **Statement:** The TUI shall display the active screen's key bindings in a footer/status bar.
- **Acceptance criteria (informative):**
  - The footer shows the current screen's `show=True` bindings.

### LLR-013.3 — Command bar does not log typed input or rendered content
- **Traceability:** HLR-003, HLR-013
- **Statement:** The Direction B command bar shall not write user-typed search, go-to-address, or command-palette text, nor rendered file content, to the rotating log under `.s19tool/logs/` (`R-TUI-015`) beyond the existing `set_status` behavior, and the batch shall not increase log verbosity above the pre-batch baseline.
- **Rationale (informative):** S-3 resolved (security-reviewer): the command bar accepts typed search / go-to / palette text and screens render loaded file content; `R-TUI-015` keeps a rotating log. No requirement previously forbade the new input surfaces from logging typed text or rendered file content into that log. This clause pins the log surface — the new command bar adds no new logging of user input or file content, and overall log verbosity stays at the pre-batch level.
- **Acceptance criteria (informative):**
  - No user-typed find / go-to / palette text is written to `.s19tool/logs/`.
  - No rendered file content is written to `.s19tool/logs/` by the command bar.
  - Log verbosity does not exceed the pre-batch baseline.

### LLR-014.1 — Engine parse/validate functions untouched
- **Traceability:** HLR-014
- **Statement:** This batch shall not modify the **parse and validate functions** of `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, or `tui/mac.py`.
- **Rationale (informative):** A-01 resolved: the freeze targets the parsing/validation *engine*, not the view layer. The A2L *rendering* helper `render_a2l_view` in `tui/a2l.py` and the thin `a2l_render.py` re-export facade are view-layer code (see C-1) and are explicitly re-stylable within this batch under HLR-009 / LLR-009.1 — a layout/theme change to `render_a2l_view` or `a2l_render.py` is in scope and does not violate this LLR. Only the parse/validate/extract functions of the listed modules are frozen.
- **Acceptance criteria (informative):**
  - Diff of the parse/validate functions of these modules shows no behavioral change (cosmetic-only or no change).
  - A view-layer-only edit to `render_a2l_view` / `a2l_render.py` for the A2L Explorer restyle is permitted and is not counted as an engine change.

### LLR-014.2 — Existing test suite passes
- **Traceability:** HLR-014
- **Statement:** The existing `pytest` suite shall pass unchanged after the restyle, except for tests that assert on pre-batch UI structure, which shall be updated to the new layout without weakening their intent.
- **Acceptance criteria (informative):**
  - Engine/parser/validation tests pass with no modification.
  - Any updated UI test still encodes the same behavioral intent.

### LLR-015.1 — Modal re-skin
- **Traceability:** HLR-015
- **Statement:** The `LoadFileScreen`, `SaveProjectScreen`, and `LoadProjectScreen` modals shall adopt the Calm Dark theme tokens.
- **Acceptance criteria (informative):**
  - Modal styling matches the new theme.

### LLR-015.2 — Modal behavior preserved
- **Traceability:** HLR-015, HLR-014
- **Statement:** The re-skinned modals shall preserve their existing behavior, including path resolution, `validate_project_files` enforcement, and the `.s19tool/` workarea layout.
- **Acceptance criteria (informative):**
  - One-data-file + one-A2L + one-MAC project rule still enforced.
  - Save/load still operate on the workarea layout unchanged.

---

## 5. Validation Strategy

> Owned by the qa-reviewer pass. This section assigns a validation method to every HLR and LLR, defines the `TC-NNN` test cases with traceability, records the snapshot-testing decision (OQ-5), flags weakly-testable requirements, and states the batch acceptance criteria. The architect's per-HLR `Validation` field (Section 3) was treated as input; the final method assignment below is authoritative for Phases 2–4.

### 5.1 Methods

- **test** — automated execution. For this batch, almost all `test` cases run through Textual's `App.run_test()` async harness (the pattern already established in `tests/test_tui_app.py`: an `async def _drive()` body wrapped by `asyncio.run`, using `async with app.run_test() as pilot` and `await pilot.pause()`). Widget-state and rendered-text assertions are read back via `app.query_one(...)` and `DataTable.get_row_at(...)`. Pure helper-level logic (binding maps, density-class computation) is `test`-able without the harness, as a synchronous unit test, like the existing `_filter_a2l_tags` / `_a2l_tag_row_severity` tests.
- **demo** — observed execution of behavior in a live `s19tui` session, recorded against a manual checklist. Used where the requirement is about *perceived* navigation/UX flow that an automated assertion cannot fully capture (rail feel, command-bar discoverability), always paired with a `test` so the demo is corroboration, not the sole evidence.
- **inspection** — static review of code, stylesheet, or rendered artifact against a written checklist. Used for aesthetic/structural requirements (theme token budget, artboard pane proportions, docstring contract) that have no objective runtime assertion. The inspection-method test cases (TC-012, TC-016, TC-031, TC-033, TC-039) each carry their checklist inline in Section 5.3 so the pass/fail verdict is not reviewer-subjective (Q-11 resolved). (CV-05: TC-039 is the inspection-method case — command bar logs no typed text; TC-038 is a `test (run_test)` case — project-name / A2L-filename visibility — and is not an inspection-checklist case.)
- **analysis** — formal or quantitative reasoning. Not the primary method for any requirement in this view-only batch; applied only as a supporting method for the no-regression argument on HLR-014 (diff analysis of the engine modules).

**Method-selection rules applied:**
- Screen *routing*, *keyboard reachability*, *command-bar focus behavior*, and the *density toggle* are state changes observable from the widget tree → `test` (primary).
- *Pane-ratio* requirements (LLR-008.1 / LLR-009.1 / LLR-010.1) carry pinned numeric column tolerances since iteration 3 (fixed panes 22±2 / 40±2 columns, flexible center `1fr`), so the ratio is objectively assertable as a number → `test` (primary), `inspection` (corroboration). The remaining *aesthetic* requirements (accent-hue budget, calm spacing) are not objectively assertable as numbers in this batch → `inspection` (primary), `demo` (corroboration). The snapshot baseline (OQ-5 approved) corroborates the pane-ratio checks as a layout-drift guard.
- *No-regression* requirements re-use the existing `pytest` suite unchanged → `test`, with `inspection` of the module diff.

### 5.2 Per-requirement validation-method table

> `Primary` = the method that produces the pass/fail verdict. `Supporting` = corroborating evidence. Every requirement has at least one `TC-NNN`. Snapshot test cases (suffix `-S`) are unconditional: OQ-5 is resolved (approved) and `pytest-textual-snapshot` is an approved dev-only optional dependency — see Section 5.5.

#### High-level requirements

| Requirement | Primary | Supporting | Test Case(s) | Justification |
|-------------|---------|------------|--------------|---------------|
| HLR-001 — Activity rail navigation | test | inspection | TC-001, TC-002, TC-035 | Rail composition, the single-active-item invariant, and per-item glyph rendering with ASCII fallback are widget-tree facts assertable via `run_test()`. |
| HLR-002 — Rail screen swap | test | demo | TC-003, TC-004, TC-037 | Content visibility after activation is observable; the Bookmarks placeholder and the no-file empty state are discrete states. |
| HLR-003 — Top command bar | test | inspection | TC-006, TC-007, TC-036 | Presence on every screen, palette population, and type-to-filter search are assertable from the widget tree. |
| HLR-004 — Command-bar key bindings | test | — | TC-008, TC-009, TC-010, TC-011 | Focus moves after a simulated keypress are deterministic under the pilot; input-focus binding suppression is covered as a sub-case of TC-008/TC-009. |
| HLR-005 — Calm Dark theme | inspection | demo | TC-012, TC-013 | Token budget (one accent + the five `sev-*` classes of `SEVERITY_CLASS_MAP`) is a stylesheet fact; visual calmness is corroborated by demo. |
| HLR-006 — Density toggle | test | demo | TC-014, TC-015 | The density CSS class on the workspace root and the default at startup are assertable. |
| HLR-007 — Density layout integrity | test (snapshot) | inspection | TC-016-S, TC-016 | OQ-5 approved: the `pytest-textual-snapshot` SVG baseline (the narrowed 27-baseline set defined in TC-016-S / §5.5) is the primary verdict; the TC-016 inspection checklist corroborates. TC-016-S / TC-016 also carry the LLR-007.2 public-fixture-only rule. |
| HLR-008 — Workspace 3-pane re-layout | test | inspection | TC-017, TC-018 | Three named panes present + data wired is assertable; iteration 3 pinned numeric pane-ratio tolerances, so the proportion is now asserted as a number rather than inspected, with inspection retained as corroboration. |
| HLR-009 — A2L Explorer re-layout | test | inspection | TC-019, TC-020 | Filtering / paging / jump-to-address are behavioral and already covered by existing-pattern tests. |
| HLR-010 — MAC View re-layout | test | inspection | TC-021, TC-022 | MAC paging, overlay highlight and jump are behavioral and assertable. |
| HLR-011 — Validation Issues screen | test | inspection | TC-023, TC-024, TC-038 | The Issues `DataTable` is already driven headlessly (existing snapshot-harness skeleton); promotion to a rail screen is a routing fact. TC-038 guards that the project-name / A2L-filename status content (`R-TUI-016`) stays visible after the Issues table moves (LLR-011.3). |
| HLR-012 — New view scaffolds | test | inspection | TC-025, TC-026, TC-027, TC-028 | Each scaffold's pane structure renders and the deferred-logic marker is present; both are assertable. |
| HLR-013 — Keyboard reachability and status bar | test | inspection | TC-029, TC-030, TC-039 | Every interactive control has a key path; the footer shows the active screen's bindings. TC-039 inspects that the command bar logs no typed text or file content (LLR-013.3). |
| HLR-014 — Data-processing behavior preserved | test | analysis, inspection | TC-031, TC-032 | The full existing engine suite passing unchanged is the verdict; a module diff analysis corroborates. |
| HLR-015 — Modal re-skin | test | inspection | TC-033, TC-034 | Modal behavior (`validate_project_files`, workarea layout) is behavioral; theme adoption is inspected. |

#### Low-level requirements

| Requirement | Primary | Supporting | Test Case(s) | Justification |
|-------------|---------|------------|--------------|---------------|
| LLR-001.1 — Rail widget composition | test | inspection | TC-001 | Eight ordered items bound to `1`–`8` is a composition assertion. |
| LLR-001.2 — Single active rail item | test | — | TC-002 | Exactly-one-active and startup-on-Workspace are state assertions. |
| LLR-001.3 — Rail glyph rendering with ASCII fallback | test | inspection | TC-035 | The Unicode-default / ASCII-fallback glyph pairing is a composition fact readable from the rail widget; the glyph set itself is inspected against the sketch. |
| LLR-002.1 — Rail-driven content swap | test | — | TC-003 | Only one screen visible after activation; reuses show/hide mechanism. |
| LLR-002.2 — Bookmarks placeholder behavior | test | — | TC-004 | Placeholder renders without error (OQ-3 resolved: rail keeps eight items; TC-005 is N/A). |
| LLR-002.3 — Empty-state panel when no file is loaded | test | — | TC-037 | Activating a rail screen with no `LoadedFile` shows a neutral empty-state panel — an observable widget-tree state, no error, no blank pane. |
| LLR-003.1 — Command-bar composition | test | — | TC-006 | Command bar mounted above the body, present on every screen. |
| LLR-003.2 — Command palette population | test | inspection | TC-007 | Every `BINDINGS` action has a palette entry invoking the same handler. |
| LLR-003.3 — Command palette type-to-filter search | test | — | TC-036 | Typing in the palette narrows the visible command list; clearing restores it — both are assertable on the palette widget. |
| LLR-004.1 — Find binding | test | — | TC-008 | `/` focuses the find input from any screen; TC-008 includes the input-focus suppression sub-case. |
| LLR-004.2 — Go-to binding and routing to the existing validated handler | test | — | TC-009 | `g` focuses the go-to input; submitting an address produces the observable effect of the existing `_handle_goto` handler (hex view scrolled to the address, `Goto 0x…` status); malformed input is surfaced via `set_status`; TC-009 includes the input-focus suppression sub-case. |
| LLR-004.3 — Command palette binding | test | — | TC-010 | `Ctrl+K` opens/focuses the palette from any screen. |
| LLR-004.4 — Binding regression guard | test | inspection | TC-011 | Every pre-batch `BINDINGS` action keeps a keyboard path. |
| LLR-004.5 — Single-key binding suppression during input focus | test | — | TC-008, TC-009, TC-029 | While a command-bar input holds focus, `g`, `1`–`8` and the paging keys `+ - , .` are routed as text and the binding does not fire — covered as the input-focus sub-case of TC-008/TC-009/TC-029, each of which includes at least one punctuation paging key (Q-05). |
| LLR-004.6 — Find input routes to the existing validated search handler | test | — | TC-008 | Submitted find text is handled by `find_string_in_mem` with no new search/decoding code; malformed/non-matching input is surfaced via `set_status` — covered by the find-routing and malformed-input assertions of TC-008. |
| LLR-005.1 — Theme tokens | inspection | — | TC-012 | One accent variable, the five `sev-*` classes, `MAC_ADDRESS_OVERLAY_STYLE` / `FOCUS_HIGHLIGHT_STYLE` preserved, no light variant — a stylesheet fact. |
| LLR-005.2 — Severity color source of truth | test | inspection | TC-013 | `SEVERITY_CLASS_MAP` read unchanged; no new severity value — the existing color round-trip test re-runs as a no-regression anchor, plus a new assertion that the TUI stylesheet defines a CSS rule for each of the five `sev-*` classes. |
| LLR-006.1 — Density cycle action | test | — | TC-014 | `Ctrl+D` toggles the density class compact↔comfortable; the active mode is surfaced. |
| LLR-006.2 — Density default | test | — | TC-015 | The startup density is a defined, assertable value (OQ-2). |
| LLR-007.1 — Density layout snapshot integrity | test (snapshot) | inspection | TC-016-S, TC-016 | OQ-5 approved: no-overlap/no-clip at the fixed {80×24, 120×30, 160×40} matrix is objectively verified by the snapshot baseline (the narrowed 27-baseline set — see TC-016-S / §5.5); the TC-016 inspection checklist corroborates. |
| LLR-007.2 — Snapshot baselines render only public synthetic fixtures | test | inspection | TC-016-S, TC-031 | Every committed `.svg` baseline traces to a public synthetic fixture (`examples/case_00_public/` or a `tests/conftest.py` generator) — asserted in TC-016-S's fixture-setup check and inspected in TC-031's no-leak checklist item. |
| LLR-008.1 — Workspace three-pane structure (two-regime width layout) | test | inspection | TC-017 | Three named panes present; iteration 4 two-regime layout — fixed widths (left 22±2, right 40±2, rail 22, center `1fr`) asserted at the `>= 120`-column sizes 120×30 / 160×40, proportional widths (left 24%±3, right 30%±3, rail collapsed 4±1, center `1fr` strictly positive) asserted at 80×24. TC-017 queries each pane under `run_test()` and asserts its rendered `region.width` / `size.width` against the regime-appropriate tolerance. Inspection corroborates the artboard match. |
| LLR-008.2 — Workspace data wiring unchanged | test | — | TC-018 | Renderers reused; hex caps `MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`FOCUS_CONTEXT_ROWS`/`HEX_WIDTH` still honored. |
| LLR-009.1 — A2L Explorer layout (flat 3/7 hex : 4/7 tags proportional ratio) | test | inspection | TC-019 | A2L table + hex pane both present; increment-13 flat ratio (supersedes the iteration-3 two-regime A2L split — review feedback: fixed-40 hex pane too narrow) — the hex pane is 3/7 (≈42.9%) ±3 points and the tags `DataTable` 4/7 (≈57.1%) ±3 points of the A2L panes content width at ALL terminal widths. TC-019 queries each pane under `run_test()` and asserts its rendered `region.width` against the 3/7 : 4/7 tolerance at 80×24 / 120×30 / 160×40. Inspection corroborates the artboard match. |
| LLR-009.2 — A2L behavior preserved | test | — | TC-020 | Filtering, paging, jump-to-address preserved — `R-A2L-007`, `R-TUI-018/019/020`. |
| LLR-010.1 — MAC View layout (two-regime width layout) | test | inspection | TC-021 | MAC table + hex pane both present; iteration 4 two-regime layout — fixed widths (hex pane 40±2, MAC record `DataTable` `1fr`) asserted at 120×30 / 160×40, proportional widths (hex pane 35%±3, MAC record `DataTable` `1fr` strictly positive, rail collapsed 4±1) asserted at 80×24. TC-021 queries each pane under `run_test()` and asserts its rendered `region.width` / `size.width` against the regime-appropriate tolerance. Inspection corroborates the artboard match. |
| LLR-010.2 — MAC behavior preserved | test | — | TC-022 | MAC paging, severity coloring, overlay highlight, jump preserved. |
| LLR-011.1 — Issues screen layout | test | — | TC-023 | Issues table is the primary content of its own rail screen, no longer nested in the Status tile. |
| LLR-011.2 — Issues behavior preserved | test | — | TC-024 | Severity coloring round-trips, filters and paging and jump-to-source preserved. |
| LLR-011.3 — Project-name / A2L-filename status content relocation | test | — | TC-038 | The project name and A2L filename render in the command bar and stay visible on every Direction B screen after the Issues table leaves the Status tile (`R-TUI-016` not regressed). |
| LLR-012.1 — Memory Map scaffold | test | inspection | TC-025 | Ranges/gaps render from existing `LoadedFile`; no new coverage computation. |
| LLR-012.2 — Patch Editor view shell | test | — | TC-026 | Before/after panes + input fields render; inputs not wired to a patch engine; deferral stated. |
| LLR-012.3 — A↔B Diff view shell | test | — | TC-027 | Three-column layout renders; deferral stated. |
| LLR-012.4 — Deferred-logic guard | test | inspection | TC-028 | Positive guard: no new processing module appears under `s19_app/` outside the view layer, and `bincopy` / `pya2l` / `crcmod` are absent from imports and `pyproject.toml`; plus a runtime no-error check. |
| LLR-013.1 — No mouse-only actions | test | — | TC-029 | Every new control (rail, command bar, density, scaffold controls) reachable by key. |
| LLR-013.2 — Status bar bindings | test | — | TC-030 | Footer shows the active screen's `show=True` bindings; the per-screen expected `show=True` set is pinned in Phase 3 increment 1 (OQ-8 keymap). |
| LLR-013.3 — Command bar does not log typed input or rendered content | inspection | — | TC-039 | The command bar writes no user-typed find/go-to/palette text or rendered file content to `.s19tool/logs/`, and log verbosity does not exceed the pre-batch baseline — a code/log inspection against a written checklist. |
| LLR-014.1 — Engine modules untouched | inspection | analysis | TC-031 | Diff of `core.py`/`hexfile.py`/`range_index.py`/`validation/`/`tui/a2l.py`/`tui/mac.py` shows no behavioral change, classified against the explicit cosmetic-only rubric in TC-031. |
| LLR-014.2 — Existing test suite passes | test | — | TC-032 | Engine/parser/validation tests pass unmodified; updated UI tests keep their intent. |
| LLR-015.1 — Modal re-skin | inspection | demo | TC-033 | Modal styling adopts Calm Dark tokens — a stylesheet fact. |
| LLR-015.2 — Modal behavior preserved | test | — | TC-034 | `validate_project_files` (one data + one A2L + one MAC) and `.s19tool/` workarea layout unchanged. |

### 5.3 Test cases (`TC-NNN`)

> Each TC names its target LLR(s) and parent HLR. Unless noted, `run_test()` cases follow the established harness pattern in `tests/test_tui_app.py`. The Actual / Pass-Fail columns are intentionally left blank for the human/CI to fill at Phase 4; no result is asserted here. New TCs land in `tests/test_tui_app.py` unless a more specific module is named.

| TC | Title | Covers | Type | Steps (summary) | Expected |
|----|-------|--------|------|-----------------|----------|
| TC-001 | Rail composes 8 ordered items on keys 1–8 | LLR-001.1 / HLR-001 | test (`run_test`) | Mount `S19TuiApp`; query the rail widget; read item order and per-item binding. | Eight items in order Workspace, A2L, MAC, Map, Issues, Patch, Diff, Bookmarks; each bound to its `1`–`8` key. (OQ-3 resolved: the count is fixed at eight.) |
| TC-002 | Exactly one rail item active; Workspace active at startup | LLR-001.2 / HLR-001 | test (`run_test`) | Mount app; read the active-marker state of all rail items at startup, then activate item 3 and re-read. | At startup only Workspace carries the accent active marker; after activating item 3 only MAC carries it; previous marker cleared. |
| TC-003 | Rail activation swaps workspace content | LLR-002.1 / HLR-002 | test (`run_test`) | Activate each rail item in turn; after each, query which screen container is visible. | Exactly one screen's content visible at a time; activating an item shows its screen and hides the others. |
| TC-004 | Bookmarks slot shows non-blocking placeholder | LLR-002.2 / HLR-002 | test (`run_test`) | Activate the Bookmarks rail item. | No exception raised; a placeholder is shown whose text states the feature is deferred / not yet available. (OQ-3 resolved: Bookmarks is a permanent placeholder slot — TC-004 is the sole Bookmarks verdict.) |
| TC-005 | Bookmarks slot omitted cleanly — **N/A** | LLR-002.2 / HLR-002 | — | *N/A. OQ-3 is resolved to "keep eight rail items"; the "Bookmarks-omitted" outcome no longer exists. This row is retired and superseded by TC-004.* | *N/A — no verdict produced.* |
| TC-006 | Command bar present on every screen | LLR-003.1 / HLR-003 | test (`run_test`) | Navigate to each of the 7–8 rail screens; query for the command-bar widget each time. | Command-bar widget (palette trigger + find input + go-to input) is mounted above the body and present on every screen. |
| TC-007 | Command palette lists every `BINDINGS` action | LLR-003.2 / HLR-003 | test (`run_test`) + inspection | Enumerate the **full** pre-batch `BINDINGS` set; open the palette; for **each** action assert a palette entry exists, and assert each palette entry dispatches the **same action id** as its key binding. Not a one-entry spot-check — every action is iterated so a palette missing entries fails. | Every `BINDINGS` action has exactly one corresponding palette entry; each palette entry dispatches the same action id as its key binding; no action is missing a palette entry. |
| TC-008 | `/` focuses the find input; routes to `find_string_in_mem`; bindings suppressed while it has focus | LLR-004.1, LLR-004.5, LLR-004.6 / HLR-003, HLR-004 | test (`run_test`) | (a) From each rail screen, `await pilot.press("slash")`; read `app.focused`. (b) **Input-focus sub-case (OQ-12 / Q-05):** with the find input focused, `await pilot.press("g")`, a digit `1`–`8`, **and at least one punctuation paging key (`comma` or `plus`)**; read the input value and the active rail item / hex page state. (c) **Find-routing sub-case (LLR-004.6):** with a fixture loaded, submit a valid search string in the find input; assert the search is handled by the existing `find_string_in_mem` and that no new search/decoding function is added. (d) **Malformed-input sub-case (S-1):** submit a malformed / non-matching find string; assert it is reported via the existing `set_status` path with no new error path and no exception. | (a) Keyboard focus is on the command-bar find input from every screen. (b) The `g`, digit and punctuation paging keys are inserted as text into the find input; go-to focus is NOT taken, the active rail item does NOT change, and no paging action fires; single-key bindings resume once the input loses focus. (c) Submitted find text reaches `find_string_in_mem`; no new string-decoding or search-parsing code path exists. (d) Malformed / non-matching find input is surfaced via `set_status`; no new error path; no exception raised. |
| TC-009 | `g` focuses go-to; submit produces the `_handle_goto` observable effect; bindings suppressed while it has focus | LLR-004.2, LLR-004.5 / HLR-003, HLR-004 | test (`run_test`) | (a) With a fixture loaded, press `g`; assert focus on go-to input; submit a valid hex address. `_handle_goto` (`app.py:4993`) takes **no address argument** — it reads `#goto_input` off the widget tree — so assert the **observable effect**: the hex view is scrolled to that address and the status line reads `Goto 0x…`. (b) **Input-focus sub-case (OQ-12 / Q-05):** with the go-to input focused, `await pilot.press` a digit `1`–`8` **and at least one punctuation paging key (`comma` or `plus`)**; read the input value and the active rail item / hex page state. (c) **Malformed-input sub-case (S-1):** submit a malformed go-to address (e.g. non-hex, out-of-range); assert it is reported via the existing `set_status` path with no new error path and no exception. | (a) `g` focuses the go-to input; submitting a valid address scrolls the hex view to that address and sets the status line to `Goto 0x…` — the observable effect of the existing `_handle_goto` handler; no new address-parsing function is added. (b) The digit and punctuation paging keys are inserted as text into the go-to input; rail navigation does NOT fire, the active rail item does NOT change, and no paging action fires; single-key bindings resume once the input loses focus. (c) Malformed go-to input is surfaced via `set_status`; no new error path; no exception raised. |
| TC-010 | `Ctrl+K` opens/focuses the command palette | LLR-004.3 / HLR-004 | test (`run_test`) | From each rail screen, press `ctrl+k`; assert the palette is open/focused. | Palette opens or gains focus from every Direction B screen. |
| TC-011 | No pre-batch binding becomes keyboard-unreachable; `1`/`2`/`3` remap is intended supersession | LLR-004.4 / HLR-004, HLR-013 | test (`run_test`) + inspection | Capture the pre-batch `BINDINGS` action set (load, refresh, open workarea, save/load project, dump A2L JSON, view switch, paging, quit); for each, assert a key path still exists (binding or palette). **Supersession sub-case (Q-04):** assert that the `1`/`2`/`3` → rail-item remap (and the removal of `#view_bar` / the `view_main` / `view_alt` / `view_mac` actions) is **intended supersession, not a regression** — and that the underlying Workspace / A2L / MAC screens stay keyboard-reachable via rail keys `1`/`2`/`3` and the command palette. | Every pre-batch action remains keyboard-reachable; re-mapped keys are reflected in the status bar / palette. The `1`/`2`/`3` → rail remap and the `#view_bar` removal are recorded as designed supersession; the Workspace / A2L / MAC screens behind the retired `view_*` actions remain reachable. |
| TC-012 | Theme token budget — one accent + the five `sev-*` classes, dark only | LLR-005.1 / HLR-005 | inspection | Review the TUI stylesheet against the inline checklist below. **Inspection checklist (Q-11):** ☐ exactly one accent hue / accent variable is defined; ☐ all **five** `sev-*` class names are present and unchanged in name and meaning — `sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`; ☐ `MAC_ADDRESS_OVERLAY_STYLE` is preserved unchanged in name and meaning; ☐ `FOCUS_HIGHLIGHT_STYLE` is preserved unchanged in name and meaning; ☐ no light-theme variant / no second non-dark token set is present; ☐ no severity class is dropped or renamed and no sixth severity class is added. | All six checklist items pass: exactly one accent hue; the five `sev-*` classes present and unchanged; `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE` preserved; no light-theme variant; no severity class added/dropped/renamed. (Not a literal count of three — the verdict is the five named classes plus the two preserved styles.) |
| TC-013 | Severity colors still derive from `SEVERITY_CLASS_MAP`; stylesheet defines a rule per `sev-*` class | LLR-005.2 / HLR-005, HLR-014 | test | (a) **No-regression anchor:** re-run the existing `test_color_policy_round_trip.py` unchanged — assert every rendered severity routes through `css_class_for_severity` and no new `ValidationSeverity` value exists. (b) **New stylesheet-binding assertion (Q-12):** parse the new TUI `.tcss` stylesheet and assert it defines a CSS rule for **each** of the five `sev-*` classes (`sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`) — a stylesheet missing a rule for any class would silently break severity coloring. | (a) `test_color_policy_round_trip.py` passes unchanged; `SEVERITY_CLASS_MAP` read unchanged; no new severity value introduced by the batch. (b) The stylesheet defines a CSS rule for all five `sev-*` classes; no class is left without a rule. |
| TC-014 | `Ctrl+D` cycles density compact↔comfortable | LLR-006.1 / HLR-006 | test (`run_test`) | Read the density class on the workspace root; press `ctrl+d`; re-read; press again; re-read. | The root density class cycles compact → comfortable → compact; the active mode is surfaced in the status bar / a notification. |
| TC-015 | Startup density default is the documented value | LLR-006.2 / HLR-006 | test (`run_test`) | Mount the app; read the initial density class before any keypress. | Density equals the documented default (provisionally comfortable — pending OQ-2). |
| TC-016 | Density layout integrity — no overlap/clipping (checklist) | LLR-007.1 / HLR-007 | inspection | At each terminal size of the fixed matrix {80×24, 120×30, 160×40} (OQ-1/OQ-9 resolved), in both compact and comfortable, visit every screen and walk the inline checklist below. **Inspection checklist (Q-11):** ☐ no two panes overlap; ☐ no pane content is clipped or truncated; ☐ no scrollbar appears where the artboard shows none; ☐ at the `>= 120`-column sizes (120×30, 160×40) the fixed-width regime is in effect (rail 22, side panes 22±2 / 40±2, center `1fr`); ☐ at 80×24 the proportional regime is in effect (rail collapsed to 4±1, side panes proportional, center `1fr` strictly positive — A-03 two-regime layout); ☐ no pane is allocated a negative or zero width at 80×24. | Every screen renders cleanly in both density modes at all three target sizes; the correct width regime is in effect at each size; corroborates the TC-016-S snapshot verdict. **Note (CV-04):** the proportional regime is exercised at a single `< 120` size (80×24); a 119-column boundary check (assert the proportional regime is in effect at width 119 and the fixed regime at width 120) is added to guard the 119/120 breakpoint and is implemented in increment 12. |
| TC-016-S | Density layout integrity — snapshot SVG | LLR-007.1, LLR-007.2 / HLR-007 | test (snapshot) | Capture `pytest-textual-snapshot` SVGs over the **narrowed matrix (Q-06)**: the **4 restyled screens** (Workspace, A2L Explorer, MAC View, Issues Report) × {compact, comfortable} × the fixed size matrix {80×24, 120×30, 160×40} = **24 baselines**; plus the **3 additive scaffold screens** (Memory Map, Patch Editor, A↔B Diff) at the **120×30 primary size only** = **3 baselines** — **27 baseline `.svg` files total**. Compare against approved baselines. **Public-fixture sub-case (S-2 / LLR-007.2):** assert every baseline is rendered only against the public synthetic fixtures (`examples/case_00_public/` or the `tests/conftest.py` generators) — the snapshot test setup loads no client artifact. | All 27 snapshots match baseline; any diff is a reviewed, intentional layout change. Every committed `.svg` traces back to a public synthetic fixture; no baseline is captured from a client artifact. OQ-5 approved: this is the primary verdict for LLR-007.1, not a contingent variant. **Note (CV-03):** the 27-baseline matrix renders only file-loaded public fixtures, so the no-file empty-state layout (LLR-002.3) is **not** captured by any snapshot baseline; empty-state layout is functionally covered by TC-037, and only empty-state layout *drift* is unguarded. An optional 120×30 empty-state baseline is deferred to increment 12 (snapshot increment) at the implementer's discretion. |
| TC-017 | Workspace presents three named panes at the two-regime tolerances | LLR-008.1 / HLR-008 | test (`run_test`) + inspection | Activate Workspace with a fixture loaded; query the three panes (ranges/sections, hex view, context) and the rail via `app.query_one(...)`; read each pane's rendered width (`region.width` / `size.width`). **Run at three pinned sizes:** (a) fixed-width regime at **120×30** and **160×40** (`>= 120` columns); (b) proportional regime at **80×24** (`< 120` columns). | Three named panes present, ordered left-to-right ranges/sections, hex view, context. **(a) At 120×30 / 160×40 (fixed regime):** rail is 22 columns; left ranges/sections pane is 22±2 columns (20–24 inclusive); right context pane is 40±2 columns (38–42 inclusive); center hex-view pane is the `1fr` flexible remainder (body width minus the two side panes, within rounding). **(b) At 80×24 (proportional regime):** left ranges/sections pane is 24%±3 points of the workspace body width; right context pane is 30%±3 points; center hex-view pane is the `1fr` remainder and is strictly positive (no clip, no overlap); rail is collapsed to 4±1 columns. Inspection corroborates the `b-workspace` artboard match. **Note (CV-04):** a 119-column boundary check (proportional regime in effect at width 119, fixed regime at width 120) is added to guard the 119/120 breakpoint and is implemented in increment 12. |
| TC-018 | Workspace data wiring unchanged; hex caps honored | LLR-008.2 / HLR-008, HLR-014 | test (`run_test`) | Load a fixture S19; assert panes are populated by `update_sections` / `update_hex_view`; assert hex output still respects `MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH` (re-use `test_tui_hexview.py::TC-023` invariants). | Panes populate from `LoadedFile`; no renderer parses data; hex render caps unchanged. |
| TC-019 | A2L Explorer presents table + hex pane at the two-regime tolerances | LLR-009.1 / HLR-009 | test (`run_test`) + inspection | Activate A2L Explorer with an A2L loaded; query the A2L symbol `DataTable`, the hex pane and the rail via `app.query_one(...)`; read each pane's rendered width (`region.width` / `size.width`). **Run at three pinned sizes:** (a) fixed-width regime at **120×30** and **160×40**; (b) proportional regime at **80×24**. | Both widgets present. **(a) At 120×30 / 160×40 (fixed regime):** hex pane is 40±2 columns wide (38–42 inclusive); A2L symbol `DataTable` is the `1fr` flexible remainder (body width minus the hex pane, within rounding). **(b) At 80×24 (proportional regime):** hex pane is 35%±3 points of the screen body width; A2L symbol `DataTable` is the `1fr` remainder and is strictly positive (no clip); rail is collapsed to 4±1 columns. Inspection corroborates the A2L artboard match. |
| TC-020 | A2L filtering, paging and jump-to-address preserved | LLR-009.2 / HLR-009, HLR-014 | test | Re-run/extend the existing A2L tests (`_filter_a2l_tags`, `action_a2l_tags_page_next/prev`, `_focus_a2l_tag_absolute_index`) against the restyled screen. | Field/mode filtering, `+`/`-` and button paging, and row-select jump (`R-A2L-007`, `R-TUI-018/019/020`) all still work. |
| TC-021 | MAC View presents table + hex pane at the two-regime tolerances | LLR-010.1 / HLR-010 | test (`run_test`) + inspection | Activate MAC View with a MAC loaded; query the MAC record `DataTable`, the hex pane and the rail via `app.query_one(...)`; read each pane's rendered width (`region.width` / `size.width`). **Run at three pinned sizes:** (a) fixed-width regime at **120×30** and **160×40**; (b) proportional regime at **80×24**. | Both widgets present. **(a) At 120×30 / 160×40 (fixed regime):** hex pane is 40±2 columns wide (38–42 inclusive); MAC record `DataTable` is the `1fr` flexible remainder (body width minus the hex pane, within rounding). **(b) At 80×24 (proportional regime):** hex pane is 35%±3 points of the screen body width; MAC record `DataTable` is the `1fr` remainder and is strictly positive (no clip); rail is collapsed to 4±1 columns. Inspection corroborates the MAC artboard match. |
| TC-022 | MAC paging, severity coloring, overlay highlight, jump preserved | LLR-010.2 / HLR-010, HLR-014 | test | Re-run/extend existing MAC tests (`action_mac_records_page_next/prev`, `_mac_record_ui_state`, MAC overlay highlight) against the restyled screen. | MAC paging works; severity colors and overlay highlight style preserved; row-select still jumps the hex pane (`R-TUI-018`). |
| TC-023 | Issues Report is a dedicated rail screen | LLR-011.1 / HLR-011 | test (`run_test`) | Activate the Issues rail item; assert `#validation_issues_list` is the screen's primary content and is not nested inside the Workspace Status tile. | Issues table is a full rail screen with its own rail item. |
| TC-024 | Issues severity coloring, filters, paging, jump preserved | LLR-011.2 / HLR-011, HLR-014 | test (`run_test`) | Re-use the existing Issues harness (`update_validation_issues_view`, `_query_issues_panel_codes`, `action_validation_issues_page_next/prev`, severity filter modes); drive on the restyled screen. | Severity colors round-trip through `css_class_for_severity`; All/Errors/Warnings filters and paging work; row-select jumps to source. |
| TC-025 | Memory Map scaffold renders coverage from `LoadedFile` | LLR-012.1 / HLR-012 | test (`run_test`) | Load a fixture with multiple ranges and gaps; activate Memory Map; assert ranges/gaps render from `LoadedFile.ranges` / `range_validity`. | Coverage rendered from existing data; no new coverage computation module present. |
| TC-026 | Patch Editor view shell renders; inputs not wired | LLR-012.2 / HLR-012 | test (`run_test`) | Activate Patch Editor; assert before/after hex-pane structure and address/value input fields are present; assert no patch-apply handler is wired and the deferral notice is shown. | Layout renders; inputs present but inert; UI states patch logic is deferred. |
| TC-027 | A↔B Diff view shell renders three columns | LLR-012.3 / HLR-012 | test (`run_test`) | Activate A↔B Diff; assert the three-column structure (range list, hex A, hex B); assert no diff-computation is invoked and the deferral notice is shown. | Three-column layout renders; UI states diff computation is deferred. |
| TC-028 | Deferred-logic guard — no new processing module appears outside the view layer | LLR-012.4 / HLR-012 | test + inspection | **Positive guard (Q-08)** — reframed from the prior negative search for modules that do not exist in the repo. (a) Enumerate the modules under `s19_app/` and assert **no new processing module** is added outside the view layer (`tui/` view code) — the new screens are view-layer modules only. (b) AST-walk the new screen modules (mirroring `test_tui_hexview.py::test_tc_023_app_does_not_import_private_hexview_helpers`) and assert `bincopy`, `pya2l`, and `crcmod` are **absent** from their imports. (c) Assert `bincopy`, `pya2l`, and `crcmod` are absent from `pyproject.toml`. (d) Activate every scaffold and assert no exception. | (a) No new processing module is added under `s19_app/` outside the view layer. (b) `bincopy` / `pya2l` / `crcmod` do not appear in the new modules' imports. (c) `bincopy` / `pya2l` / `crcmod` do not appear in `pyproject.toml`. (d) Scaffolds render without error; deferred capabilities marked in the UI. |
| TC-029 | Every new control reachable by keyboard; bindings suppressed during input focus | LLR-013.1, LLR-004.5 / HLR-013 | test (`run_test`) | (a) Enumerate the new interactive controls (rail items, command-bar inputs, density toggle, scaffold controls); for each, drive it via a keypress and confirm it responds. (b) **Input-focus sub-case (OQ-12):** focus a command-bar input, press `g` and a digit `1`–`8`, and confirm the keystrokes reach the input. | (a) Every new control has a working keyboard path; none is mouse-only. (b) While a command-bar input holds focus the single-key bindings (`g`, `1`–`8`) do NOT fire; the keystrokes are routed to the focused input. |
| TC-030 | Status bar shows the active screen's bindings | LLR-013.2 / HLR-013 | test (`run_test`) | On each rail screen, read the footer/status-bar content; compare against that screen's `show=True` bindings. **Note (Q-09):** the new scaffold screens (Memory Map, Patch Editor, A↔B Diff) have no defined binding set yet — OQ-8 defers the final keymap to Phase 3 increment 1. The expected per-screen `show=True` binding set is therefore **pinned in Phase 3 increment 1** when the implementer proposes the keymap; TC-030's Expected column is filled in at that point and stays blank for those screens until then. | Footer displays the current screen's visible bindings; updates on screen change. The per-screen expected `show=True` set is pinned in Phase 3 increment 1 (OQ-8 keymap dependency). |
| TC-031 | Engine modules show no behavioral change; no snapshot baseline leaks a non-public fixture | LLR-014.1, LLR-007.2 / HLR-014, HLR-007 | inspection + analysis | (a) Diff `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py` against the pre-batch branch; classify each change against the explicit **cosmetic-only rubric (Q-11)**: whitespace, comments, and import-order changes are **cosmetic**; changes to logic, constants, or function signatures are **NOT cosmetic** and fail the TC. Only the parse/validate/extract functions are in scope — a view-layer-only edit to `render_a2l_view` / `a2l_render.py` is not counted as an engine change (LLR-014.1). (b) **No-leak inspection (S-2 / LLR-007.2):** inspect every committed `.svg` snapshot baseline and confirm none contains content traceable to a non-public fixture (no client firmware bytes, addresses, symbol names, or MAC tags) — every baseline traces to `examples/case_00_public/` or a `tests/conftest.py` generator. | (a) Every engine-module change is cosmetic-only per the rubric, or there is no change; no logic/constant/signature change in any listed module. (b) No committed `.svg` baseline traces to a non-public fixture; no client data is embedded in any baseline. |
| TC-032 | Existing pytest suite passes unchanged | LLR-014.2 / HLR-014 | test | Run `pytest -q`; separately confirm engine/parser/validation tests were not modified; review any UI-test edit for intent preservation. | All engine/parser/validation tests pass with no modification; updated UI tests still encode the same behavioral intent; no test silently skipped. |
| TC-033 | Modals adopt the Calm Dark theme | LLR-015.1 / HLR-015 | inspection | Review `screens.py` (`LoadFileScreen`, `SaveProjectScreen`, `LoadProjectScreen`) and their styling against the inline checklist below. **Inspection checklist (Q-11):** ☐ each of the three modals references the Calm Dark theme tokens (accent variable + the shared dark token set), not hard-coded colors; ☐ no off-theme / hard-coded hex color or non-token color appears in the modal styling; ☐ the accent hue used by the modals is the single shared accent (no second accent introduced); ☐ no light-theme color appears; ☐ severity coloring inside the modals, if any, routes through the five `sev-*` classes. | All five checklist items pass: the three modals adopt the Calm Dark tokens; no off-theme or hard-coded colors; single shared accent; no light-theme color; severity coloring uses the `sev-*` classes. |
| TC-034 | Modal behavior — project-file rules and workarea layout preserved | LLR-015.2 / HLR-015, HLR-014 | test | Re-run the existing modal/workspace tests (`validate_project_files` cardinality, `copy_into_workarea` containment, save-under-workarea); confirm pass against the re-skinned modals. **Path-traversal sub-case (S-4, optional hardening):** submit a `..\..\`-style traversal path into a modal path input and assert `resolve_input_path` / `validate_project_files` keep the resolved path contained within the app cwd / repo root and the `.s19tool/` workarea — no escape outside the containment boundary. | One-data-file + one-A2L + one-MAC rule still enforced; `.s19tool/` workarea layout and path resolution unchanged; a `..\..\`-style traversal input stays contained and does not escape the workarea boundary. |
| TC-035 | Rail items render a Unicode glyph with an ASCII fallback | LLR-001.3 / HLR-001 | test (`run_test`) + inspection | Mount `S19TuiApp`; query the rail widget and read each item's glyph; assert each of the eight items carries a Unicode glyph and a paired ASCII-fallback glyph; force the ASCII-fallback mode and re-read. Inspect the glyph set against the sketch set `◫ ≡ ◉ ▤ ! ✎ ⏚ ✶`. | Each of the eight rail items has a Unicode glyph (default) and a defined ASCII-fallback glyph; selecting the fallback mode renders the ASCII set and raises no error. |
| TC-036 | Command palette filters commands as the user types | LLR-003.3 / HLR-003 | test (`run_test`) | Open the palette; read the full command list; type a substring matching a subset of commands into the palette input; re-read the visible list; clear the filter text; re-read. | Typing narrows the visible command list to entries matching the typed text; clearing the filter text restores the full command list. |
| TC-037 | Rail navigation before any file load shows an empty-state panel | LLR-002.3 / HLR-002 | test (`run_test`) | Mount `S19TuiApp` with no file loaded; activate Workspace, A2L Explorer, MAC View, and Memory Map in turn; after each, query the screen content. | Each screen shows a neutral empty-state panel (not an error and not a blank pane) whose text prompts a load action (e.g. "no file loaded — Ctrl+L to load"); no exception is raised. **Note (CV-03):** TC-037 is the functional verdict for the no-file empty state; the empty-state *layout* is not captured by any snapshot baseline (TC-016-S renders only file-loaded fixtures), so empty-state layout drift is unguarded — an optional 120×30 empty-state baseline is deferred to increment 12. |
| TC-038 | Project name + A2L filename stay visible after the Issues table moves | LLR-011.3 / HLR-011, HLR-013 | test (`run_test`) | With a project loaded (data file + A2L), activate the Issues rail item so the Issues table is promoted out of the old Status tile; then visit each Direction B rail screen and query the command bar. Assert the project name and the current A2L filename are rendered in the persistent command bar and remain visible/reachable on every screen. | The project name and A2L filename render in the command bar and are visible on every Direction B screen after the Issues table leaves the Status tile; no project-name / A2L-filename information is lost (`R-TUI-016` not regressed). |
| TC-039 | Command bar logs no typed text or rendered file content | LLR-013.3 / HLR-003, HLR-013 | inspection | Inspect the command-bar widget and `app.py` wiring, and the rotating log under `.s19tool/logs/`, against the inline checklist below. **Inspection checklist (Q-11):** ☐ no code path writes user-typed find / go-to / palette text to `.s19tool/logs/`; ☐ no code path writes rendered file content to `.s19tool/logs/` via the command bar; ☐ the command bar's only user-visible status surface is the existing `set_status` path, not the log; ☐ no new log level / logger / handler raises verbosity above the pre-batch baseline; ☐ a driven session that types find / go-to / palette text produces a log file with no occurrence of that typed text or of loaded file content. | All five checklist items pass: no typed text or rendered file content is written to `.s19tool/logs/` by the command bar; log verbosity does not exceed the pre-batch baseline. |

**Coverage check:** every HLR (001–015 — **15 HLRs**) and every LLR (001.1–015.2 — **38 LLRs total**, comprising the iteration-2 additions LLR-001.3, LLR-002.3, LLR-003.3, LLR-004.5 and the iteration-4 additions LLR-004.6, LLR-007.2, LLR-011.3, LLR-013.3) maps to at least one TC. The TC set is TC-001…TC-039 plus the snapshot case TC-016-S. TC-005 is retired as **N/A** (OQ-3 resolved to "keep eight rail items"). Net active count: 39 numbered cases minus the 1 retired (TC-005) = **38 active test cases** (TC-016-S included; all unconditional — OQ-5 approved, no contingent cases remain). The iteration-4 additions are: TC-038 (LLR-011.3 — project-name / A2L-filename relocation, Q-10) and TC-039 (LLR-013.3 — command bar logs no typed text / file content); LLR-004.6 is folded into TC-008's find-routing and malformed-input sub-cases, and LLR-007.2 into TC-016-S's public-fixture sub-case and TC-031's no-leak inspection.

**Resolution log — architect inline `[qa: update needed]` flags (Section 4 LLR notes).** Each flag the architect left in the LLR acceptance-criteria text is resolved here; the Section 4 LLR text itself is left to the architect to clear:

| Flag location (Section 4) | What it asked for | Resolved by |
|---------------------------|-------------------|-------------|
| LLR-002.2 — "TC-005 now N/A" | Retire the Bookmarks-omitted variant | TC-005 marked N/A in 5.3; removed from 5.2 / 5.4; TC-004 is the sole verdict. |
| LLR-002.3 — "rail navigation before any load" TC | Add an empty-state test case | New **TC-037** added; LLR-002.3 added to 5.2 / 5.4. |
| LLR-003.3 — palette filter-behavior TC | Add a type-to-filter test case | New **TC-036** added; LLR-003.3 added to 5.2 / 5.4. |
| LLR-004.5 — TC-008/009/029 "input has focus" sub-case | Add a binding-suppression sub-case to three TCs | TC-008, TC-009, TC-029 each gained an input-focus sub-case; LLR-004.5 added to 5.2 / 5.4. |
| Section 5.3 — four iteration-2 LLRs need TCs | Assign TCs and re-state the LLR ID range | TC-035/036/037 added; LLR-001.3 → TC-035; ID range re-stated (now "38 LLRs" after the iteration-4 additions). |
| Section 5 — four iteration-4 LLRs need TCs | Assign TCs to LLR-004.6 / LLR-007.2 / LLR-011.3 / LLR-013.3 and re-state the LLR count | LLR-004.6 → TC-008 sub-cases; LLR-007.2 → TC-016-S + TC-031; LLR-011.3 → new TC-038; LLR-013.3 → new TC-039. LLR count re-stated as 38 in 5.3 / 5.8. |
| Section 5.7 — OQ-9–OQ-13 `[qa: update needed]` | Bake the resolutions into the strategy | All applied; Section 5.7 rewritten as "resolved and applied". |

### 5.4 Coverage table (HLR → LLR → TC)

| HLR | LLR | TC |
|-----|-----|----|
| HLR-001 | LLR-001.1, LLR-001.2, LLR-001.3 | TC-001, TC-002, TC-035 |
| HLR-002 | LLR-002.1, LLR-002.2, LLR-002.3 | TC-003, TC-004, TC-037 *(TC-005 retired — N/A)* |
| HLR-003 | LLR-003.1, LLR-003.2, LLR-003.3, LLR-004.6 *(LLR-004.6 also traces to HLR-004)* | TC-006, TC-007, TC-036, TC-008 *(LLR-004.6 find-routing sub-case)* |
| HLR-004 | LLR-004.1, LLR-004.2, LLR-004.3, LLR-004.4, LLR-004.5, LLR-004.6 | TC-008, TC-009, TC-010, TC-011 (LLR-004.5 covered by the input-focus sub-cases of TC-008/TC-009, plus TC-029; LLR-004.6 covered by the find-routing and malformed-input sub-cases of TC-008) |
| HLR-005 | LLR-005.1, LLR-005.2 | TC-012, TC-013 |
| HLR-006 | LLR-006.1, LLR-006.2 | TC-014, TC-015 |
| HLR-007 | LLR-007.1, LLR-007.2 | TC-016-S (primary), TC-016 (corroborating); LLR-007.2 covered by TC-016-S (public-fixture sub-case) and TC-031 (no-leak inspection) |
| HLR-008 | LLR-008.1, LLR-008.2 | TC-017, TC-018 |
| HLR-009 | LLR-009.1, LLR-009.2 | TC-019, TC-020 |
| HLR-010 | LLR-010.1, LLR-010.2 | TC-021, TC-022 |
| HLR-011 | LLR-011.1, LLR-011.2, LLR-011.3 | TC-023, TC-024, TC-038 |
| HLR-012 | LLR-012.1, LLR-012.2, LLR-012.3, LLR-012.4 | TC-025, TC-026, TC-027, TC-028 |
| HLR-013 | LLR-013.1, LLR-013.2, LLR-013.3 | TC-029, TC-030, TC-039 |
| HLR-014 | LLR-014.1, LLR-014.2 | TC-031, TC-032 (+ TC-013, TC-018, TC-020, TC-022, TC-024, TC-034 as no-regression contributors) |
| HLR-015 | LLR-015.1, LLR-015.2 | TC-033, TC-034 |

### 5.5 Snapshot-testing decision (OQ-5 — RESOLVED, approved)

OQ-5 is resolved: the product owner approved `pytest-textual-snapshot` as a **dev-only optional dependency**. Constraint C-2 is scoped to *runtime/build* dependencies; a dev-only test dependency is the explicitly granted scoped exception (see C-2, A-6). The snapshot strategy below is now the **primary** layout/proportion verdict for the batch — it is no longer contingent.

**Adopted approach — `pytest-textual-snapshot` as a dev-only optional dependency.**
- `pytest-textual-snapshot` is declared under a `[project.optional-dependencies] dev` (or `test`) group in `pyproject.toml`, never under `[project] dependencies`. The `s19tui` runtime dependency set (`rich`, `textual`) stays untouched, honoring the spirit of C-2; `textual` gains a `>=` version floor with no hard ceiling (OQ-13).
- SVG baselines are captured over the **narrowed matrix (Q-06 resolved)** — **27 baseline `.svg` files total**: the **4 restyled screens** (Workspace, A2L Explorer, MAC View, Issues Report) × {compact, comfortable} × the fixed size matrix {80×24, 120×30, 160×40} = **24 baselines**, plus the **3 additive scaffold screens** (Memory Map, Patch Editor, A↔B Diff) at the **120×30 primary size only** = **3 baselines**. The full {2 density × 3 size} matrix is applied only where the regression risk is — the 4 restyled screens; the additive scaffolds, which have no pre-batch behavior to regress, are pinned at the 120×30 primary size. The prior un-narrowed matrix (~8 screens × 2 × 3 ≈ 48 SVGs) was reduced because a 48-file snapshot diff in a PR invites rubber-stamping; 27 baselines are reviewable while keeping regression coverage where it matters. These baselines are the objective verdict for HLR-007 (primary) and a layout-drift guard for the HLR-012 scaffold layouts. For the HLR-008/009/010 pane-ratio clauses (LLR-008.1/009.1/010.1), iteration 3 pinned numeric column tolerances and iteration 4 split them into a two-regime layout, so the pane ratio is verified primarily by direct `run_test()` width assertions at pinned sizes (TC-017/019/021); the snapshot baseline corroborates those clauses as a drift guard rather than being their sole verdict.
- Per LLR-007.2 (S-2 resolved): all 27 baselines are rendered **only** against the public synthetic fixtures — `examples/case_00_public/` and the `tests/conftest.py` generators (`make_large_s19` / `make_large_a2l` / `make_large_mac`) — never against a client firmware / A2L / MAC artifact, so no committed `.svg` embeds proprietary client data. TC-016-S asserts the fixture source; TC-031 inspects the committed baselines for leaks.
- A `snapshot` pytest marker is registered (alongside the existing `slow` marker) so snapshot tests can be deselected on constrained environments.
- TC-016-S is the **primary** verdict for LLR-007.1. The pane-ratio checks in TC-017/019/021 no longer depend on the snapshot baseline for correctness: iteration 3 pinned numeric column tolerances (22±2, 40±2, `1fr` remainder), so those checks run as direct `run_test()` width assertions; the snapshot baseline still corroborates them as a layout-drift guard.
- Baseline regeneration is a reviewed action — a snapshot diff in a PR is treated as an intentional-change gate, not an auto-accept.

**Harness baseline.** Behavioral (non-layout) `test` cases continue to run on the **existing** `App.run_test()` harness proven in `tests/test_tui_app.py` (the `_drive()` / `asyncio.run` / `pilot.pause()` skeleton and `_query_issues_panel_codes` reader). Widget-state and rendered-text assertions — pane presence and IDs, child counts, `DataTable` row contents, the density CSS class on the workspace root, `app.focused` after a simulated keypress, footer text — remain the verdict for routing, focus and behavior. Snapshots add the layout-integrity verdict on top; they do not replace the behavioral harness.

**Outcome.** With OQ-5 approved, the layout-integrity requirement (HLR-007) and the scaffold-layout clauses of HLR-012 are regression-guarded in CI rather than degrading to inspection-only. The HLR-008/009/010 pane-ratio clauses are additionally verified by direct numeric width assertions (iteration 3 tolerances), with the snapshot baseline as a drift guard. `pytest-textual-snapshot` is the Textual-ecosystem standard for this, carries no runtime footprint, and is deselectable via the `snapshot` marker.

### 5.6 Testability assessment — weakly-testable requirements

| Requirement | Why it is not objectively verifiable as written | What would make it testable |
|-------------|--------------------------------------------------|-----------------------------|
| HLR-005 — "Calm Dark" theme | "Calm" and "modern minimal" are subjective; only the *color budget* (one accent hue plus the five `sev-*` classes of `SEVERITY_CLASS_MAP`, with `MAC_ADDRESS_OVERLAY_STYLE` / `FOCUS_HIGHLIGHT_STYLE` preserved) is objective. | Splitting it as written already isolates the objective part into LLR-005.1 (token set — inspectable/testable). The subjective "calm" aspect can only be `demo` + owner sign-off; recommend the batch acceptance criterion treat the LLR-005.1 token budget as the binding verdict and the aesthetic as advisory. |
| HLR-007 / LLR-007.1 — "without overlapping or clipped panes" at "supported terminal sizes" | **Resolved.** OQ-1/OQ-9 fixed the size matrix to {80×24, 120×30, 160×40}; OQ-5 approved the snapshot baseline. | Now objectively verifiable: TC-016-S is the automated verdict over the fixed matrix, with TC-016 inspection as corroboration. No residual concern. |
| LLR-008.1 / LLR-009.1 / LLR-010.1 — pane ratios | **Resolved.** Iteration 3 pinned explicit numeric pane-ratio tolerances; iteration 4 (A-03 resolved) split them into a **two-regime width layout** — fixed column counts ±2 columns at terminal widths `>= 120` columns (rail 22, left ranges pane 22±2, right context / hex panes 40±2, center `1fr`), and proportional widths ±3 percentage points at widths `< 120` columns (side panes 24%±3 / 30%±3 / 35%±3, rail collapsed to 4±1, center `1fr` strictly positive). The pane ratio is an objectively assertable number in each regime, not only a snapshot-drift signal. | Now objectively verifiable in both regimes: the pane widths are readable from the widget tree under `App.run_test()` (`app.query_one(...)`, then assert rendered `region.width` / `size.width`) — fixed tolerances asserted at the pinned `>= 120`-column sizes 120×30 / 160×40, proportional tolerances asserted at 80×24. TC-017/019/021 carry the regime-split numeric expected values; the snapshot baseline corroborates as a drift guard. No residual concern. |
| LLR-006.2 — "a defined default density" | **Resolved.** OQ-2 fixed the default to Comfortable. | TC-015 now has a concrete expected value (Comfortable). No residual concern. |
| LLR-002.2 — Bookmarks placeholder | **Resolved.** OQ-3 fixed the outcome to a permanent placeholder slot. | TC-004 is the sole live verdict; TC-005 is retired as N/A. No residual concern. |
| HLR-001 / LLR-001.1 — "eight ordered rail items" | **Resolved.** OQ-3 fixed the rail at eight items; the "omit" option is closed and the LLR-001.1 text is consistent. | TC-001 expects exactly eight items. No residual concern. |

> Note: every row above is now resolved — **no residual testability concern is carried out of the validation pass.** The former open item, the pane-ratio item (LLR-008.1 / LLR-009.1 / LLR-010.1), is closed: iteration 3 pinned explicit numeric column tolerances and iteration 4 (A-03 resolved) split them into a two-regime layout — fixed tolerances (rail 22, side panes 22±2 / 40±2, center `1fr`) at `>= 120`-column widths and proportional tolerances (24%±3 / 30%±3 / 35%±3, rail collapsed 4±1, center `1fr` strictly positive) at `< 120`-column widths — so the pane ratio is an assertable number in each regime, verified by `run_test()` width assertions at pinned sizes (TC-017/019/021), with the snapshot baseline retained only as a drift guard. The remaining rows were flagged in iteration 1 only because their governing open questions were unanswered; OQ-1/OQ-2/OQ-3/OQ-5/OQ-9 are now all resolved, so they are objectively verifiable and are no longer weakly-testable. This agrees with AC-B9 in Section 5.8, which records the same closure.

### 5.7 Open questions raised by the validation pass — all resolved and applied

> Iteration 2 status: every OQ below is resolved by the product owner and the validation strategy has been updated to match. No `[qa: update needed]` flag remains in Section 5.

- **OQ-9 — RESOLVED, applied.** The target-size matrix is exactly {80×24, 120×30, 160×40} (same set as OQ-1). Baked into HLR-007 and LLR-007.1. TC-016 and TC-016-S now carry the fixed size matrix.
- **OQ-10 — RESOLVED, applied.** The command palette is type-to-filter **searchable**. Baked into LLR-003.3; covered by new TC-036 (TC-007 still covers population only).
- **OQ-11 — RESOLVED, applied.** Rail screens opened with no file loaded show a neutral empty-state panel ("no file loaded — Ctrl+L to load"). Baked into LLR-002.3; covered by new TC-037 ("rail navigation before any load").
- **OQ-12 — RESOLVED, applied.** While a command-bar input holds focus, single-key bindings (`g`, `1`–`8`) go to the input and the binding does not fire. Baked into LLR-004.5; TC-008, TC-009 and TC-029 each carry an "input has focus" sub-case.
- **OQ-13 — RESOLVED, applied.** With OQ-5 approved, `textual` gains a `>=` version floor (no hard ceiling) — recorded as a minor, acknowledged dependency-set note in C-8, tied to the OQ-5 exception.

### 5.8 Batch acceptance criteria

The batch is accepted at the Phase 4 gate when all of the following hold:

- **AC-B1 — Full traceability.** Every HLR (001–015 — 15 HLRs) and every LLR (the **38 LLRs** spanning LLR-001.1 through LLR-015.2, including the iteration-2 additions LLR-001.3, LLR-002.3, LLR-003.3, LLR-004.5 and the iteration-4 additions LLR-004.6, LLR-007.2, LLR-011.3, LLR-013.3) maps to at least one `TC-NNN` (Section 5.4), and every active TC has a recorded pass result. TC-005 is retired as N/A and produces no verdict. No requirement is left without an assigned validation method.
- **AC-B2 — No-regression suite green.** `pytest -q` passes; the engine/parser/validation tests (`test_core_*`, `test_hexfile`, `test_range_index`, `test_validation_*`, `test_tui_a2l`, `test_tui_mac`) pass with **zero source modification**; no test is skipped silently (TC-031, TC-032).
- **AC-B3 — Severity policy intact.** `SEVERITY_CLASS_MAP` and the `sev-*` class names are unchanged; no new `ValidationSeverity` value exists; the color round-trip test passes (TC-012, TC-013).
- **AC-B4 — Hex-view caps intact.** `MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH` still govern hex rendering with no change in value or effect (TC-018, plus `test_tui_hexview` TC-023 invariants).
- **AC-B5 — Project-file rules intact.** `validate_project_files` (one data file + one A2L + one MAC) and the `.s19tool/` workarea layout / path resolution are unchanged (TC-034).
- **AC-B6 — Keyboard reachability intact.** No pre-batch `BINDINGS` action becomes keyboard-unreachable, and every new Direction B control has a keyboard path (TC-011, TC-029, TC-030).
- **AC-B7 — Layout verdict.** Every Direction B screen renders cleanly in both density modes at each size of the fixed matrix {80×24, 120×30, 160×40}, observing the two-regime width layout (fixed widths `>= 120` columns, proportional widths `< 120` columns) — verified primarily by the `pytest-textual-snapshot` baseline over the narrowed 27-baseline set (TC-016-S, OQ-5 / Q-06 resolved) and corroborated by the inspection checklist (TC-016). All 27 baselines are rendered only against public synthetic fixtures (LLR-007.2, TC-016-S / TC-031).
- **AC-B8 — No blocker fails.** Zero blocker-severity fails in the validation run; any non-blocker fail is logged with an owner-approved disposition.
- **AC-B9 — Open questions resolved.** All thirteen open questions (OQ-1 through OQ-13) are resolved by the product owner (Section 5.7 and 6.3); the iteration-2 resolutions are applied to the requirements and to this validation strategy. The former residual concern — the un-pinned pane-ratio tolerance for LLR-008.1/009.1/010.1 — is closed, and the iteration-3 fixed-width-vs-80×24 contradiction (review finding A-03) is also closed: iteration 4 resolves A-03 with a **two-regime width layout** split at a 120-column breakpoint — fixed pane widths (rail 22, side panes 22±2 / 40±2 cols, center `1fr`) while the terminal width is `>= 120` columns, and proportional pane widths (side panes as `%`/`fr`, rail collapsed to an icon-only 4±1 cols, center `1fr`) while the terminal width is `< 120` columns. Both regimes carry explicit numeric tolerances in LLR-007.1 / 008.1 / 010.1, so the pane ratios are objectively testable against a numeric target in each regime and 80×24 remains a supported size that never clips. There is no residual concern carried out of the requirements pass. *(Note for the qa-reviewer pass: the pane-width test cases TC-016/016-S/017/021 must be reconciled to the two-regime layout — fixed-width assertions pinned at the `>= 120`-column sizes 120×30 / 160×40, proportional assertions pinned at 80×24.)* **Increment-13 amendment:** review feedback superseded the two-regime A2L pane split *for A2L only* with a flat 3/7 hex : 4/7 tags proportional ratio at all widths (the fixed-40 hex pane was too narrow to render the hex view correctly); see the LLR-009.1 supersession note. LLR-009.1 is therefore no longer a two-regime requirement and its pane ratio is pinned by a single flat numeric tolerance; LLR-010.1 / MAC View still carries the two-regime layout unchanged. TC-019 is reconciled to the flat 3/7 : 4/7 ratio at all three sizes.

---

## 6. Appendices

### 6.1 Traceability to existing `R-*` requirements (must NOT regress)

> These living `REQUIREMENTS.md` entries are touched by the restyle and shall not be regressed. They are non-negotiable constraints on the implementation.

| `R-*` entry | What it protects | Interaction with this batch |
|-------------|------------------|-----------------------------|
| `R-TUI-001` | Workarea created at startup | Unchanged; rail/workspace shell must not break startup wiring. |
| `R-TUI-002`, `R-TUI-011` | Loaded file copied into workarea/temp | Unchanged; modal re-skin must not alter copy behavior. |
| `R-TUI-003` | Layout exposes the existing tiles | **Re-layout target** — superseded by Direction B Workspace; a candidate replacement `R-*` is drafted in 6.2. |
| `R-TUI-004`, `R-TUI-007`, `R-TUI-010`, `R-TUI-017` | Hex view rendering, context, scroll, search/goto | Hex panes re-laid-out; render caps `MAX_HEX_BYTES` / `MAX_HEX_ROWS` / `FOCUS_CONTEXT_ROWS` / `HEX_WIDTH` and search/goto behavior must be preserved. |
| `R-TUI-005`, `R-TUI-006` | Path resolution / unique workarea names | Unchanged; modal re-skin must not alter. |
| `R-TUI-008` | Open workarea in OS explorer | Action must remain keyboard-reachable under new bindings. |
| `R-TUI-009`, `R-TUI-018` | Section / tag / MAC row selection jumps hex view | Jump-to-address behavior preserved in restyled Workspace, A2L and MAC screens. |
| `R-TUI-012`, `R-TUI-013`, `R-PROJ-001`, `R-PROJ-002` | Project save/load, sync of files into project folders | Unchanged; modal re-skin only. |
| `R-TUI-014` | One data file + one A2L per project (`validate_project_files`) | Unchanged; explicitly preserved by LLR-015.2. |
| `R-TUI-015` | Rotating log under `.s19tool/logs` | Unchanged. |
| `R-TUI-016` | Status tile shows project name and A2L filename | Status content must survive the move out of the old Status tile; LLR-011.3 relocates it to the persistent command bar (A-05). |
| `R-TUI-019`, `R-TUI-020` | A2L/MAC page navigation buttons + `+`/`-` paging | Preserved in restyled A2L Explorer and MAC View (LLR-009.2, LLR-010.2). |
| `R-A2L-002`, `R-A2L-006`, `R-A2L-007` | A2L view rendering, columns, filtering | Preserved in restyled A2L Explorer. |
| `R-A2L-003` | Export A2L to JSON via key binding | Action must remain keyboard-reachable / palette-reachable. |
| `R-DOC-001` | TUI module + key-method docstrings | New/changed view code must follow the `PROJECT_RULES.md` docstring contract. |
| A2L / MAC / Issues severity-color policy ("A2L Tag/Parameter Validation Criteria", "MAC Tag/Parameter Validation Criteria", "Issues Tile Severity Policy") | Red/Green/White/Grey/Orange row semantics via `color_policy.SEVERITY_CLASS_MAP` | The theme shall not change severity semantics or class names (LLR-005.1, LLR-005.2). |

### 6.2 Candidate NEW `R-*` entries (for the human to add to `REQUIREMENTS.md` later)

> Drafted, not yet inserted. Numbers are placeholders to be reconciled with the living file.

- **`R-TUI-021` (candidate) — Activity rail navigation.** The TUI must present a left activity rail of eight items with one active item, swapping the workspace content on rail selection; rail items use Unicode glyphs with an ASCII fallback. Code: new rail widget + `app.py` routing. Status: `Manual`/`Partial` pending tests. (Covers LLR-001.1, LLR-001.3.)
- **`R-TUI-022` (candidate) — Top command bar.** The TUI must present a top command bar with a searchable (type-to-filter) command palette plus find and go-to inputs reachable from every screen. Code: new command-bar widget + `app.py`. (Covers LLR-003.1–003.3.)
- **`R-TUI-023` (candidate) — Density toggle.** The TUI must support a `Ctrl+D` density toggle (compact/comfortable, default Comfortable) that does not break any screen layout at 80×24 / 120×30 / 160×40, observing the two-regime width layout (fixed pane widths `>= 120` columns, proportional pane widths `< 120` columns — A-03 resolved). Code: stylesheet density classes + `app.py` action. (Covers LLR-006.1, LLR-006.2, LLR-007.1.)
- **`R-TUI-024` (candidate) — Calm Dark theme.** The TUI must apply a dark-only theme with one accent hue and the severity colors defined by `color_policy.SEVERITY_CLASS_MAP` — the five `sev-*` classes — preserving `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE` unchanged. Code: TUI stylesheet. (Covers LLR-005.1.)
- **`R-TUI-025` (candidate) — Dedicated Issues Report screen.** The validation issues table must be presented as a dedicated rail screen, preserving severity coloring, filters and jump-to-source. Code: new screen + `update_validation_issues_view`.
- **`R-TUI-026` (candidate) — Memory Map screen.** The TUI must present a memory-map screen rendering coverage from existing `LoadedFile` data. Code: new screen.
- **`R-TUI-027` (candidate, view-shell only) — Patch Editor screen.** The TUI must present a patch-editor view shell (before/after panes + input fields); patch-apply/undo/redo logic is deferred. Code: new screen.
- **`R-TUI-028` (candidate, view-shell only) — A↔B Diff screen (static placeholder).** The TUI must present a three-column firmware-diff view shell with placeholder data only; no second-file load path and no diff computation this batch. Code: new screen.
- **`R-TUI-029` (candidate) — Workspace re-layout supersedes `R-TUI-003`.** The TUI must present the data ranges/sections, hex view and context as a three-pane Direction B Workspace. This replaces the five-tile layout described by `R-TUI-003`; `R-TUI-003` should be marked superseded once `R-TUI-029` is accepted.
- **`R-TUI-030` (candidate) — Rail-screen empty state.** When a rail screen is activated with no file loaded, the TUI must show a neutral empty-state panel prompting a load action. Code: new screen empty-state panels + `app.py`. (Covers LLR-002.3.)
- **`R-TUI-031` (candidate) — Single-key binding suppression during input focus.** While a command-bar input holds focus, single-key bindings (`g`, `1`–`8`) must be routed to the input and not fire their binding action. Code: `app.py` binding/focus handling. (Covers LLR-004.5.)
- **`R-TUI-032` (candidate, dev-tooling note) — Snapshot test dependency.** `pytest-textual-snapshot` is added as a dev-only optional dependency under `[project.optional-dependencies]` in `pyproject.toml` **only** (the legacy `project.toml` is not edited and is kept aligned), carrying a version constraint — at minimum a `>=` lower-bound floor consistent with the `textual` `>=` floor of C-8, with a fully-pinned `==` version for CI reproducibility as an acceptable alternative. `textual` gains a `>=` version floor. This is a dev/test-tooling note, not a runtime requirement; recorded for traceability against C-2/C-8 (S-5 resolved).
- **`R-TUI-033` (candidate) — Command-bar inputs route to existing validated handlers.** The command-bar find and go-to inputs must route submitted text to the existing `find_string_in_mem` and `_handle_goto` handlers respectively, introducing no new string-decoding or address-parsing code; invalid input is reported via the existing `set_status` path. Code: command-bar widget + `app.py` wiring. (Covers LLR-004.2, LLR-004.6; S-1.)
- **`R-TUI-034` (candidate) — Snapshot baselines use public fixtures only.** `pytest-textual-snapshot` SVG baselines must be rendered only against the public synthetic fixtures (`examples/case_00_public/`, the `tests/conftest.py` generators) and never against client artifacts. Code: snapshot test setup. (Covers LLR-007.2; S-2.)
- **`R-TUI-035` (candidate) — Command bar does not log typed input or rendered content.** The command bar must not write user-typed find/go-to/palette text or rendered file content to the `.s19tool/logs/` rotating log beyond the existing `set_status` behavior; log verbosity must not exceed the pre-batch baseline. Code: command-bar widget + `app.py`. (Covers LLR-013.3; S-3.)
- **`R-TUI-036` (candidate) — Project-name / A2L-filename relocated to the command bar.** When the Issues table is promoted to its own rail screen, the project-name and A2L-filename status content (`R-TUI-016`) must render in the persistent command bar so it stays visible from every screen. Code: command-bar widget + `app.py`. (Covers LLR-011.3; A-05. `R-TUI-016` is not regressed by the move.)

### 6.3 Critical assumptions, gaps and open questions

**Critical assumptions** (also in 2.5): A-1 engine is stable and correct; A-2 mock artboards are the authoritative visual spec; A-7 the single-context workspace fully replaces the old three-layout toggle (the `#view_bar` and `view_*` actions are superseded by rail items 1/2/3, not regressions); A-8 the Workspace pane layout has two width regimes split at a 120-column breakpoint (A-03 resolved — fixed widths `>= 120` cols, proportional widths `< 120` cols).

**Gaps identified:**
- **G-1** — The existing TUI has a `settings_menu` for viewer page-size only; it has **no** density mechanism today. Density (HLR-006) is genuinely new UI behavior, not a restyle of an existing feature.
- **G-2 — closed (A-05 resolved).** The Issues table is currently embedded inside the Main-view Status tile. Promoting it to a dedicated screen (HLR-011) orphans the project-name / A2L-filename status content (`R-TUI-016`). Its new home is now specified by **LLR-011.3**: the content renders in the persistent command bar so it stays visible from every Direction B screen.
- **G-3 — closed (OQ-3 resolved).** The handoff sketch lists "Bookmarks" as rail item 8 and bookmark persistence is deferred (C-5); the batch keeps the slot as a permanent placeholder screen, so the rail stays at eight items.
- **G-4 — closed (OQ-6 resolved).** The handoff exposed "font (monospace family)" and "highlight color for MAC overlays" as tweaks; the owner confirmed these are **out of scope / deferred** for this batch — no HLR/LLR covers them. The density toggle remains in scope.
- **G-5 — closed (OQ-7 resolved).** The A↔B Diff screen scaffold (HLR-012 / LLR-012.3) has no real second-file data source; the owner confirmed a static placeholder scaffold is acceptable this batch — no second-file load path is built, and the diff-logic batch will source a "B" file later.

**Open questions for the human:** *(all 13 resolved by the product owner — iteration 2)*
- **OQ-1 — RESOLVED.** Supported terminal sizes are exactly 80×24 (minimum), 120×30 (primary), 160×40; layout must not clip/overlap at 80×24. Baked into HLR-007, LLR-007.1.
- **OQ-2 — RESOLVED.** Default startup density is **Comfortable**. Baked into LLR-006.2.
- **OQ-3 — RESOLVED.** Bookmarks is a permanent placeholder: the rail keeps **eight** items and the Bookmarks slot opens a neutral "coming soon" placeholder screen (no persistence). Baked into HLR-001, HLR-002, LLR-001.1, LLR-002.2; LLR-001.1 inconsistency fixed.
- **OQ-4 — RESOLVED.** Unicode rail glyphs with a defined ASCII fallback. Baked into A-3 and new LLR-001.3.
- **OQ-5 — RESOLVED (approved).** `pytest-textual-snapshot` is permitted as a **dev-only optional dependency** under `[project.optional-dependencies]`; runtime set (`rich`, `textual`) untouched. Baked into C-2 scoped exception and A-6.
- **OQ-6 — RESOLVED (deferred, out of scope).** No HLR/LLR for monospace-font-family or MAC-overlay highlight-color tweaks. The density toggle remains in scope. See G-4.
- **OQ-7 — RESOLVED.** The A↔B Diff screen is a **static placeholder scaffold** — Direction B 3-column shell with placeholder data only, no second-file load path, no diff computation. Baked into HLR-012, LLR-012.3, screen-inventory row 7.
- **OQ-8 — RESOLVED.** The final keybinding map is proposed by the implementer in Phase 3 increment 1; single-key bindings (`g`, `1`–`8`) are suppressed while a command-bar input holds focus. Baked into new LLR-004.5.
