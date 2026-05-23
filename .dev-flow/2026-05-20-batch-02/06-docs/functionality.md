# Functionality — s19_app — 2026-05-20-batch-02 (Direction B restyle)

**Audience:** a technical stakeholder, future engineer, or QA reviewer who needs to understand what the Direction B restyle changed in the `s19tui` TUI — what the rail, command bar and eight screens do, how they are laid out, and what was deliberately left unbuilt.

**Purpose:** describe (a) what the Direction B restyle is, (b) how the user navigates the new TUI (rail + command bar), (c) what each of the eight screens does, (d) the theme and density system, (e) the two-regime responsive layout, and (f) what is explicitly deferred to a follow-up batch.

**Scope:** this is the **orientation document**. It is *not* the requirements specification ([`01-requirements.md`](../01-requirements.md)), *not* the per-test verdict register ([`04-validation.md`](../04-validation.md)), and *not* the traceability matrix ([`traceability-matrix.md`](traceability-matrix.md)). It lets a new reader navigate those artefacts. For the visual call-graph see [`diagrams/architecture.md`](diagrams/architecture.md).

---

## 1. What the Direction B restyle is

`s19_app` (distribution name `s19tool`) is an offline desktop tool for parsing, validating and visualising automotive memory artefacts — S-record / Intel HEX firmware images, ASAM A2L description files, and MAC `TAG=hexaddr` symbol files. It ships two entry points: `s19tool` (Rich CLI) and `s19tui` (Textual TUI).

Batch `2026-05-20-batch-02` re-layouts the **`s19tui` TUI** to the "Hex Lab — Direction B" visual language. Before this batch the TUI presented **three mutually-exclusive layouts** toggled by a top button bar and keys `1`/`2`/`3` (a 5-tile Main view, an A2L Tags view, a MAC view). Direction B replaces that with a **single-context workspace**: a persistent left **activity rail** of eight screens and a persistent top **command bar**, where selecting a rail item swaps the workspace content.

This is a **view-layer-only batch.** It changes how information is arranged, navigated and themed, and adds three new view scaffolds — but it does **not** change a single byte of the parsing/validation engine. The seven engine modules (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) are frozen; the Phase 4 `git diff main` over all of them is empty (HLR-014). Every screen reads the same `LoadedFile` snapshot (`tui/models.py`) and routes through the same `tui/services/` (`load_service`, `a2l_service`, `validation_service`) as before.

### 1.1 What the batch delivered

| Output | Count | Where |
|--------|-------|-------|
| User stories | 14 (US-001..US-014) | [`01-requirements.md`](../01-requirements.md) §2.6 |
| High-level requirements | 15 (HLR-001..HLR-015) | [`01-requirements.md`](../01-requirements.md) §3 |
| Low-level requirements | 38 | [`01-requirements.md`](../01-requirements.md) §4 |
| Active test cases | 38 (TC-001..TC-039 + TC-016-S; TC-005 retired) | [`01-requirements.md`](../01-requirements.md) §5.3; verdicts in [`04-validation.md`](../04-validation.md) §4 |
| Phase 3 increments | 12 | [`03-increments/increment-001.md`](../03-increments/increment-001.md) … [`increment-012.md`](../03-increments/increment-012.md) |
| New `s19_app/tui/` modules | 3 (`rail.py`, `command_bar.py`, `screens_directionb.py`) + `styles.tcss` | see §7 |
| Net new tests | +144 (suite 275 → 419) + 27 snapshot baselines | [`traceability-matrix.md`](traceability-matrix.md) §2.2 |
| Candidate living `R-*` entries | 16 (`R-TUI-021`..`R-TUI-036`) | [`01-requirements.md`](../01-requirements.md) §6.2 — now merged into the living [`REQUIREMENTS.md`](../../../REQUIREMENTS.md) |
| Phase 4 verdict | `pass-with-gaps` (0 blockers) | [`04-validation.md`](../04-validation.md) §8 |

---

## 2. How the user navigates — the rail and the command bar

Direction B has two persistent navigation surfaces, both visible on every screen.

### 2.1 The activity rail (left)

A vertical VS-Code-style column listing exactly **eight** ordered screens, bound to keys `1`–`8`, with **exactly one** item marked active at a time by an accent-colored marker (HLR-001). At startup the **Workspace** item is active. Selecting a rail item — by key or click — swaps the workspace content to that screen and moves the active marker (HLR-002). The swap reuses the existing show/hide mechanism: eight sibling screen containers, with the `.hidden` CSS class toggled (the same technique the pre-batch `#main_layout`/`#alt_layout`/`#mac_layout` toggle used).

Each rail item renders a Unicode glyph with a defined per-item ASCII fallback for terminals that cannot render Unicode (LLR-001.3):

| Key | Screen | Unicode | ASCII fallback |
|-----|--------|---------|----------------|
| 1 | Workspace | `◫` | `#` |
| 2 | A2L Explorer | `≡` | `=` |
| 3 | MAC View | `◉` | `@` |
| 4 | Memory Map | `▤` | `M` |
| 5 | Issues Report | `!` | `!` |
| 6 | Patch Editor | `✎` | `P` |
| 7 | A↔B Diff | `⏚` | `D` |
| 8 | Bookmarks | `✶` | `*` |

The rail's width is **responsive** (see §5): it pins to a fixed width at terminal widths `≥ 120` columns and collapses to an icon-only 4-column strip below 120 columns so the layout never clips.

### 2.2 The command bar (top)

A persistent top bar — mounted above the rail/workspace body, present on every Direction B screen (HLR-003) — that exposes three keyboard-driven controls:

- **Command palette** — `Ctrl+K` opens or focuses it. It lists every existing TUI action (load file, save/load project, rail navigation, paging, dump A2L JSON) as a selectable command, and **filters as the user types** (type-to-filter narrows the list; clearing restores it). Selecting a palette entry invokes the same action handler as that action's key binding.
- **Find** — `/` focuses the find input. Submitting text routes to the **existing** validated search handler `find_string_in_mem`; no new string-decoding code was added (LLR-004.6, security finding S-1). Non-matching/malformed input is reported via the existing `set_status` path.
- **Go-to** — `g` focuses the go-to-address input. Submitting an address routes to the **existing** `_handle_goto` handler; no new address parser was added (LLR-004.2). Malformed input is reported via `set_status`.

The command bar also carries the **project name and A2L filename** labels (LLR-011.3). These previously lived in the Main-view Status tile; promoting the Issues table to its own screen (§3) orphaned them, so they were relocated to the always-mounted command bar where they stay visible from every screen. This keeps `R-TUI-016` from regressing.

**Single-key suppression (LLR-004.5):** while any command-bar input (find, go-to, palette) holds focus, every *unmodified* single-key binding — `g`, the digits `1`–`8`, and the paging keys `+`, `-`, `,`, `.` — is routed into the input as text rather than firing its binding action, so typing `,` into the find input does not fire a page action. *Modified* bindings (`Ctrl+K`, `Ctrl+D`) stay live during input focus.

**Binding supersession (LLR-004.4):** the pre-batch top `#view_bar` button bar and the `view_main`/`view_alt`/`view_mac` actions are **retired**. The `1`/`2`/`3` keys are remapped from view-toggle to rail-item activation. This is an *intended* Direction B change, not a regression — the underlying Workspace / A2L / MAC screens stay keyboard-reachable on those same keys and via the command palette. Every other pre-batch `BINDINGS` action (load, refresh, open workarea, save/load project, dump A2L JSON, paging, quit) keeps a key path. The active screen's bindings are shown in a footer/status bar (LLR-013.2).

---

## 3. The eight screens

Selecting a rail item swaps the workspace to one of these. Screens 1–4 are **restyles** of working pre-batch screens (re-laid-out, same data wiring). Screens 5–7 are **new view scaffolds**. Screen 8 is a placeholder.

### 3.1 Workspace (rail 1 — restyle)

A three-pane layout — **data ranges/sections** (left), **hex view** (center), **context** (right) — re-laid-out from the pre-batch 5-tile Main view (HLR-008). The panes are populated by the existing `update_sections` / `update_hex_view` renderers reading the `LoadedFile` snapshot; the hex render caps (`MAX_HEX_BYTES`, `MAX_HEX_ROWS`, `FOCUS_CONTEXT_ROWS`, `HEX_WIDTH`) are unchanged. Selecting a data section still jumps the hex view to that section.

### 3.2 A2L Explorer (rail 2 — restyle)

The existing A2L symbol `DataTable` plus a hex pane, re-laid-out to the Direction B A2L proportions (HLR-009). All existing behavior is preserved: field/mode filtering (All/Invalid/In-Memory), page-navigation buttons and `+`/`-` paging, and row-select jump-to-address. The A2L *rendering* helper `render_a2l_view` is view-layer code and was eligible for re-styling, but the re-layout (increment 6) re-nested containers in `app.py` only and reused every A2L widget subtree verbatim.

### 3.3 MAC View (rail 3 — restyle)

The existing MAC record `DataTable` plus a hex pane, re-laid-out to the Direction B MAC proportions (HLR-010). MAC paging, row severity coloring, the MAC address overlay highlight, and row-select jump-to-address are all preserved.

### 3.4 Issues Report (rail 5 — restyle, promoted to a dedicated screen)

The validation `validation_issues_list` `DataTable` — which pre-batch lived **inside the Main-view Status tile** — is promoted to its own full rail screen (HLR-011). Severity coloring (routed through `color_policy.css_class_for_severity`), the All/Errors/Warnings severity filters, paging, and row-level jump-to-source are all preserved. The old `#workspace_carryover` container is removed and the status/log widgets re-homed.

### 3.5 Memory Map (rail 4 — new scaffold)

A new screen that renders firmware coverage — ranges, gaps and validity — from the **existing** `LoadedFile.ranges` and `range_validity` data (HLR-012, LLR-012.1). No new coverage computation is added; this is a read-only visualization of data the engine already produces.

### 3.6 Patch Editor (rail 6 — new scaffold, view shell only)

A view shell: a before/after hex-pane layout plus address/value input fields (LLR-012.2). The input fields are **inert** — they are not connected to any patch-apply, undo, or redo logic. The screen carries a visible notice that patch logic is deferred. The CLI's `patch-hex` command is unaffected; the TUI patch *engine* is a follow-up batch.

### 3.7 A↔B Firmware Diff (rail 7 — new scaffold, static placeholder)

A static three-column placeholder shell — range list, hex A, hex B (LLR-012.3). All three columns render **constant, clearly-labelled sample hex rows** marked as `PLACEHOLDER` content; none is sourced from a `LoadedFile` or any diff computation. There is **no control to load a second ("B") firmware file** this batch, and no diff computation. The screen states that diff computation and the second-file load path are deferred.

### 3.8 Bookmarks (rail 8 — placeholder)

Activating the Bookmarks rail item swaps to a neutral "coming soon" placeholder screen (LLR-002.2). No bookmark-persistence logic is read or written this batch. The slot is a permanent rail item — the rail always has eight items (OQ-3 resolved).

### 3.9 Empty state

When any rail screen (Workspace, A2L Explorer, MAC View, Memory Map) is activated while **no file is loaded**, the screen shows a neutral empty-state panel prompting a load action (e.g. "no file loaded — Ctrl+L to load") instead of an error or a blank pane (LLR-002.3).

### 3.10 Modals

The Load, Save and Load-Project modal screens (`screens.py`) are re-skinned to the Calm Dark theme (HLR-015). Their behavior is unchanged: the one-data-file + one-A2L + one-MAC project rule (`validate_project_files`), the `.s19tool/` workarea layout, path resolution, and the `SaveProjectPayload` contract all hold. The modals style via theme tokens — no hard-coded color.

---

## 4. Theme and density

### 4.1 Calm Dark theme

A dark-only theme (HLR-005). The stylesheet was extracted out of the inline `S19TuiApp.CSS` into a dedicated `s19_app/tui/styles.tcss` (increment 1) so the theme can be parsed and asserted independently. The color budget is fixed: **exactly one accent hue** (`$accent-calm: #4ec9d4`, a cyan-blue) plus the five severity classes already defined by `color_policy.SEVERITY_CLASS_MAP` — `sev-error`, `sev-warning`, `sev-info`, `sev-ok`, `sev-neutral`. No new severity semantics, no new `ValidationSeverity` value, no light-theme variant. The map's further preserved styles `MAC_ADDRESS_OVERLAY_STYLE` and `FOCUS_HIGHLIGHT_STYLE` are unchanged in name and meaning.

### 4.2 Density toggle

`Ctrl+D` cycles the workspace layout density between **compact** (information-dense) and **comfortable** (calm, spacious) by toggling a density CSS class on the workspace root (HLR-006). The startup default is **Comfortable** (OQ-2). The active mode is surfaced to the user. A density change must not break any screen's layout at any supported terminal size.

---

## 5. The two-regime responsive layout

The Direction B layout is **width-responsive**, governed by a **120-column breakpoint** (HLR-007, A-03 resolved by the product owner). This closes a contradiction: the pinned fixed pane widths (rail 22 + side panes summing to 84 columns of fixed chrome) cannot coexist with the supported 80×24 minimum.

- **At terminal width `≥ 120` columns (fixed regime):** the side panes use pinned fixed column widths and the rail uses its full fixed width. Workspace: left ranges/sections pane 22±2 columns, right context pane 40±2 columns, center hex view the flexible `1fr` remainder. A2L Explorer / MAC View: hex pane 40±2 columns, symbol/record table the `1fr` remainder.
- **At terminal width `< 120` columns (proportional regime):** the side panes become proportional and the rail collapses to an icon-only 4±1 columns, so the layout never clips down to the 80×24 minimum. Workspace: left pane 24%±3, right pane 30%±3 of the body width, center `1fr`. A2L Explorer / MAC View: hex pane 35%±3, table the `1fr` remainder.

The supported terminal-size matrix is exactly **{80×24 (minimum), 120×30 (primary), 160×40}**. Layout integrity — no overlap, no clipping, no zero/negative pane width — is verified by the 27-baseline `pytest-textual-snapshot` matrix (24 restyled-screen cells across `{workspace,a2l,mac,issues}` × `{compact,comfortable}` × `{80x24,120x30,160x40}` + 3 scaffold cells) and corroborated by the CV-04 119/120-column boundary tests.

---

## 6. What is deferred

Direction B delivers the **shell** for several capabilities; the *logic* behind them is explicitly out of scope (constraint C-5) and is the subject of a follow-up batch:

- **Patch apply / undo / redo** — the Patch Editor screen is a view shell; its inputs are inert.
- **A↔B diff computation and the second-file load path** — the A↔B Diff screen is a static placeholder; no second firmware image can be loaded this batch.
- **Bookmark persistence** — the Bookmarks slot is a "coming soon" placeholder.
- **CRC / checksum computation engine and PDF export** — not in scope; no screen wires them.

A **deferred-logic guard** (LLR-012.4, TC-028) enforces this: `screens_directionb.py` imports no `bincopy`/`pya2l`/`crcmod`, no new processing module exists at the `s19_app/` root, and none of those packages is in `pyproject.toml`. The only dependency change is `pytest-textual-snapshot` declared as a **dev-only optional** dependency under `[project.optional-dependencies]` (the runtime set `rich` + `textual` is unchanged; `textual` gains a `>=` floor).

---

## 7. New modules and how to verify

| Module | Role | Built in |
|--------|------|----------|
| `s19_app/tui/styles.tcss` | Calm Dark token set, 5 `sev-*` rules, two-regime layout rules, modal block | increment 1 (extended 5/6/8) |
| `s19_app/tui/rail.py` | `Rail` / `RailItem` widgets — 8 ordered items, glyphs + ASCII fallback, single active marker | increment 3 |
| `s19_app/tui/command_bar.py` | `CommandBar` widget — palette, find, go-to, project labels | increment 4 |
| `s19_app/tui/screens_directionb.py` | Memory Map, Patch Editor, A↔B Diff, Bookmarks scaffold widgets | increments 9–10 |

The new widget classes live in new modules under `s19_app/tui/` (rather than growing the ~5k-line `app.py`), consistent with the `PROJECT_RULES.md` decomposition note. `app.py` remains orchestration-only.

**To run the suite and read verdicts:**

```bash
pytest -q                        # full suite — 419 passed / 0 failed / 3 xfailed / 2 skipped
pytest -q -m snapshot            # the 27-baseline pytest-textual-snapshot matrix
pytest -q -m "not slow"          # skip the 3 stress/perf smoke tests
pytest tests/test_tui_directionb.py     # rail / screens / density / no-regression
pytest tests/test_tui_commandbar.py     # command bar / palette / find / go-to
pytest tests/test_tui_theme.py          # Calm Dark theme tokens
```

The Direction B behavior tests live in `tests/test_tui_directionb.py`, `tests/test_tui_commandbar.py` and `tests/test_tui_theme.py`; the snapshot matrix lives in `tests/test_tui_snapshot.py` with its `.svg` baselines under `tests/__snapshots__/test_tui_snapshot/`. The pre-existing 2 skips and 3 xfails are inherited batch-01 baseline cases — they are **not** Direction B cases.

**To launch the restyled TUI:**

```bash
s19tui --load examples/case_00_public/prg.s19
```

---

## 8. Where to go next

- The full requirement → test trace: [`traceability-matrix.md`](traceability-matrix.md).
- The per-test and per-requirement verdicts: [`04-validation.md`](../04-validation.md).
- The visual architecture and screen-routing diagrams: [`diagrams/architecture.md`](diagrams/architecture.md).
- The four `-with-gaps` items (manual TUI pass, `ruff` in CI, the TC-030 design note, the empty-state snapshot): [`04-validation.md`](../04-validation.md) §7 and [`traceability-matrix.md`](traceability-matrix.md) §3.
- The living requirements with the 16 new `R-TUI-*` rows: repo-root [`REQUIREMENTS.md`](../../../REQUIREMENTS.md).
