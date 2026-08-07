# Requirements Document — s19_app — batch `2026-08-06-batch-78` (ARCHITECT lane)

**Objective:** Command-bar deletion + context re-home (Lane 1, S-1…S-4) · A2B diff master–detail (Lane 2, S-5…S-9)
**Charter INPUT:** `prototypes/cmdbar_a2bdiff.HANDOFF.md` · **Phase-0:** `00-measurements.md`
**Branch:** `claude/batch-78-cmdbar-a2bdiff` @ `4df335b` · **Base:** `origin/main` @ `f6ff1d3`
**Language:** English · **Lane:** A (`.dev-flow/BACKLOG-CODE.md`)
**Normative keyword:** `shall`, and it appears ONLY inside HLR/LLR **Statement** lines.
**Scope:** S-1…S-9 only. **Lane 3 (S-10…S-13) is OUT** — carries for its handoff charter are collected in §6.4.

---

## BLUF — five findings that change the work, before anything else

| # | Finding | Verdict | Who decides |
|---|---|---|---|
| **F-1** | **The width primitive is wrong by 2 cells, and it is the wrong producer.** §9.1 measured **81** from `render_hex_view_text`. The A2B diff panel imports and calls **`render_hex_view`** (`screens_directionb.py:7021`, `:7030-7031`), whose emitted row is **79** cells — the 2-cell delta is `render_hex_view_text`'s leading indent. Every S-7 threshold in the charter and in §9.4 rests on the wrong number from the wrong producer. **Reached independently by this lane, the QA lane and the orchestrator** — three derivations, one number. | ⚠️ **corrects §9** | architect — §2.7 P-31 |
| **F-2** | **S-7's binding constraint is the VERTICAL axis, not the horizontal one, and none of the three chartered options addresses it.** Measured: at **120×30** `#diff_hex_a` has **0** content rows today, **0** after S-8 alone, and **2** only after S-8 **and** Lane-1's bar deletion. At **80×24** it is **0** in every configuration. The diff result area is not "wrapping badly" at 120 — it is **structurally invisible**. | ❌ **re-scopes S-7 + reorders the batch** | architect — §2.8 D-1 |
| **F-3** | **Two of the charter's width claims are arithmetically dead, and one dies at exactly the width it was proposed for.** The side-by-side bound is **`L + 5 + 79 + 5 ≤ C`**, i.e. **`L ≤ C − 89`** (executed, P-32b). At 120 that budget is **3 cells**, so the chartered 12-cell fallback is impossible there. At 132 it is **15 cells**, so the chartered *"22-col list at ≥ ~130"* does not work at 132 either — its first fit is **139**, and **the charter's own 132×44 capture is on the fallback side of its own recommended line.** | ❌ **eliminates two options** | architect — §2.8 D-1 |
| **F-4** | **Half of S-3 is already shipped, and an acceptance for it would be vacuous.** Executed with a real `LoadedFile`: `#loaded_panel` already renders `'… A2L \| ECU_CAL.a2l  0 tags …'`. The A2L filename is **already in the Loaded panel** (`_slot_state`, `screens_directionb.py:1891`). What is genuinely absent from every non-bar surface is the **project + active-variant** string. | ⚠️ **re-scopes S-3** | architect — §2.7 P-35 |
| **F-5** | **S-1/S-4's blast radius is wider than Phase 0 recorded, and S-4 will trip the registry guard.** `#cmdbar_project` is the *observable* two more test files read (`tests/test_tui_patch_variant.py:85`, `tests/test_tui_variants.py:78`) — 6 Lane-1 test files, not 3. And `TC-007/008/009/039` are `LIVE` registry rows whose `nodes` name `tests/test_tui_commandbar.py::…`; deleting those tests turns **G2** red. | ⚠️ **widens S-4** | architect — §2.7 P-36/P-37 |

**One open decision needs a ruling before Inc-9 (§8 OQ-1): the S-7 regime pair.** Everything else is derivable and derived below. Nothing here blocks Inc-1…Inc-8.

---

## 1. Introduction

### 1.1 Purpose
Derive the HLR/LLR set for batch-78 from the nine READY user stories in `PLAN.md §3`, under IEEE 830 + EARS, with every code claim verified against disk at draft time.

### 1.2 Scope

**In:** US-78-1 … US-78-9 (charter S-1…S-9). The Direction-B command bar row and what it carried; the A2B Firmware Diff panel's run list, hex windows, width regimes and selection rows.

**Out:** Lane 3 (S-10…S-13, operations staged removal) — a separate handoff charter is a deliverable of this batch's close (`PLAN.md` D-3); diff variants B and C; the 80×24 unwrapped-row guarantee (§2.8 D-1, measured impossible); the `Enter → open-in-hex` clause of S-9 (§2.8 D-2, ruled out with cause).

### 1.3 Definitions

| Term | Definition |
|---|---|
| **emitted hex row** | One line of `hexview.render_hex_view` output — address + 16 hex pairs + ASCII gutter. **79 cells, executed** (§2.7 P-31). Distinct from `render_hex_view_text`'s 81 (2-cell indent). |
| **box chrome** | The columns a bordered `#diff_*` box spends on itself: **5** — `border: round` (2) + `padding: 1` (2) + `margin-right: 1` (1). Measured, not derived (§2.7 P-32). `Widget.size.width` is the **content** width, inside all five. |
| **content width** | `widget.size.width` — what the widget may paint into. |
| **wrapped row** | An emitted hex row whose length exceeds its window's content width, so Textual folds it onto a second visual line. |
| **wide regime / fallback regime** | The two S-7 layouts, selected by terminal width at a single named breakpoint (§4, LLR-124.1). Mirrors the `width-narrow` precedent (`app.py:6205`). |
| **active screen** | `S19TuiApp._active_screen_key` (`app.py:5816`). **The only sound discriminator** — nothing unmounts on screen switch (Phase-0 P-10). |
| **context surface** | A widget that names the loaded project / A2L. After S-3 there are two: `#loaded_panel` (workspace only) and `#workspace_status_bar` (all 10 screens). |

### 1.4 References
`REQUIREMENTS.md` (R-TUI-* space; `## Retired ids`) · `docs/engineering-rules.md` (C-13, C-13.1, C-22, C-23, C-26, C-28, C-29, C-30, C-32, C-34, C-37, C-38, C-42) · `.dev-flow/AT-TC-REGISTRY-SPEC.md` §4 + G1–G7 · `.dev-flow/2026-08-01-batch-77/01-requirements-architect.md` (structure + the `j`/`k` shadowing precedent) · `00-measurements.md` (Phase 0).

### 1.5 Document overview
§2 description + the mandatory **§2.7 premise table** and **§2.8 decision tables** · §3 HLR · §4 LLR · §5 validation + dual traceability · §6 appendices + carries · §7 increment plan · §8 open decisions · §9 evidence checklist.

---

## 2. Overall description

### 2.1 Product perspective

**Lane 1.** `CommandBar` (`command_bar.py:69`) is composed once, app-level, at `app.py:1878` — a sibling of `#workspace_shell`, so it renders on all 10 screens. Its `compose` (`:139`) yields two children: `#command_bar_row` (`:140`) holding the prompt, the two context labels and the two duplicate find/goto inputs, and `#command_palette` (`:150`) holding the Ctrl+K palette. **The palette is a sibling of the row, not a child**, so the row deletes without touching the palette. Batch-78 deletes `#command_bar_row`, re-points `action_focus_find` / `action_focus_goto` (`app.py:5980` / `:5984`) at the active screen's own inputs, and moves the project/A2L context to two surviving surfaces.

**Lane 2.** `AbDiffPanel` (`screens_directionb.py:6566`) composes four stacked `Horizontal` rows plus a status line plus `#diff_columns` (`:6769`), three rigid `1fr` boxes (`styles.tcss:1481-1490`). `render_comparison` (`:6879`) caps runs (`_apply_display_caps`, `:6925`), renders the list into a `Static` (`_render_run_list`, `:6958`), and renders **only run 0**'s windows (`_render_run_windows(0)`, called once at `:6921`). Batch-78 turns the list into a selectable widget, drives the windows off selection, derives context rows from pane height, compacts the four control rows, and adds a width-regime split.

### 2.2 Product functions
(a) removal of the duplicate find/goto surface and its ~3 rows of app-wide chrome; (b) `/`·`g` acting on the pane the operator is looking at; (c) project/A2L context that survives the bar's removal on every screen; (d) keyboard- and mouse-reachability of every diff run; (e) hex windows that follow selection and size themselves to the pane; (f) an unwrapped hex row at the project's supported wide and fallback widths; (g) control rows that do not starve the result area.

### 2.3 User characteristics
A firmware/calibration engineer comparing two S-record images in a terminal, at the project's snapshot regimes 80×24, 120×30 and 160×40. Single operator, no permissions model. No new file I/O, no new network surface, no new credential handling anywhere in this batch.

### 2.4 Constraints

| # | Constraint | Value | Evidence |
|---|---|---|---|
| C1 | Supported terminal regimes | **80×24, 120×30, 160×40** — the snapshot matrix. **NOT 132×44** (the charter's capture size) | `ls tests/__snapshots__/test_tui_snapshot/` → 29 cells across exactly these three sizes |
| C2 | Only diff golden | `[diff-comfortable-120x30]`, **1** cell | same listing |
| C3 | Emitted hex row | **79** cells | executed, §2.7 P-31 |
| C4 | Box chrome | **5** columns per bordered `#diff_*` box | measured, §2.7 P-32 |
| C5 | `#diff_columns` content width | 80→**70** · 120→**92** · 132→**104** · 160→**132** · 170→**142** | executed, §2.7 P-32 |
| C6 | Rail width | **22** at ≥120; **4** below (measured at 80 and at 110) | executed, §2.7 P-32 |
| C7 | Diff result-area height | `#diff_hex_a` content rows: 80×24 → **0** · 120×30 → **0** · 160×40 → **3** | executed, §2.7 P-33 |
| C8 | Display caps (G-9) bound the PANEL, never the report | `DISPLAY_MAX_RUNS = 128` `:6623`, `DISPLAY_MAX_TOTAL_BYTES = 2_097_152` `:6624` | verified on disk |
| C9 | Snapshot regen is **CI-only** | textual **8.2.8** pin | `docs/engineering-rules.md` C-30 / project rule |
| C10 | Frozen keymap guard | 14 tuples; **neither `slash` nor `g`** | re-derived, `tests/test_tui_directionb.py:6058-6072` |
| C11 | C-17 markup safety | any file-derived text on a markup surface → `markup=False` **at construction** | precedent `app.py:1916` (`#status_text`) |
| C12 | Textual internal-name shadowing | no `_nodes` / `_context` members on new widgets | project rule |
| C13 | `styles.tcss` id selectors beat subclass `DEFAULT_CSS` | new styling owns new ids or edits `styles.tcss` | charter §3, re-hit in the prototype |
| C14 | AT/TC ids are **batch-scoped** | `AT-B78-nn` / `TC-B78-nn`; `AT-TC-REGISTRY.jsonl` untouched **except** the G2 repair of §2.7 P-37 | `PLAN.md` D-7; `docs/engineering-rules.md:48` |
| C15 | Existing width-regime machinery | `_apply_width_regime` `app.py:6205`; breakpoint is a **bare literal `120`** at `app.py:6232` — **no named constant exists** | verified on disk |

### 2.5 Assumptions and dependencies
Every load-bearing assumption is evaluated in §2.7. Two claims are carried forward unverified and are explicitly flagged in-line: LLR-123.2's row-centring arithmetic (`assumed — measure in Phase 3`) and LLR-124.3's overlay dismissal path (`assumed — verify in target framework at Phase 3`).

### 2.6 Source user stories

Verbatim from `PLAN.md §3`; DoR status inherited from Phase 0, **amended** where this lane's execution changed it.

| ID | User story (Connextra) | Source | DoR status (this lane) |
|---|---|---|---|
| **US-78-1** | As a firmware engineer, I want the command-bar row gone, so that its three rows of duplicate chrome go back to the screen I am actually reading. | S-1 | 🟢 **READY** |
| **US-78-2** | As a firmware engineer, I want `/` and `g` to act on the pane I am looking at, so that a find on the A2L screen searches the A2L. | S-2 | 🟢 **READY** — and it fixes a latent wrong-pane defect |
| **US-78-3** | As a firmware engineer, I want to see which project and A2L are loaded on every screen, so that deleting the bar does not blind me. | S-3 | 🟡 **READY — RE-SCOPED** (F-4: the A2L half is already shipped) |
| **US-78-4** | As a maintainer, I want the dead find/goto surface deleted, so that the codebase stops carrying a second, wrong implementation. | S-4 | 🟢 **READY** — depends on US-78-1…3 |
| **US-78-5** | As a firmware engineer, I want to select any differing run, so that I can inspect more than the first one. | S-5 | 🟢 **READY** |
| **US-78-6** | As a firmware engineer, I want the hex windows to follow my selection and fill the pane, so that the window shows what the pane can hold. | S-6 | 🟢 **READY** — depends on US-78-5 |
| **US-78-7** | As a firmware engineer, I want an unwrapped hex row at the widths I actually use, so that a byte column means one thing. | S-7 | 🟡 **READY-WITH-DECISION** — §2.8 D-1; **hard-depends on US-78-8** |
| **US-78-8** | As a firmware engineer, I want the selection and action rows to stop eating the results area, so that a comparison shows results. | S-8 | 🔴 **PROMOTED to prerequisite** (was cosmetic; F-2 makes it load-bearing) |
| **US-78-9** | As a firmware engineer, I want the run-list keyboard path to be discoverable. | S-9 | 🟡 **READY — PARTIALLY RULED OUT** (§2.8 D-2) |

#### Refinement deltas this lane introduced
**US-78-3 — re-scoped.** Its `V` (valuable) survives but its content changes: the A2L filename already reaches the Loaded panel, so the story's real payload is the **project + active-variant** string and its presence on the 9 non-workspace screens.
**US-78-8 — promoted 🟢 → 🔴 prerequisite.** Its `I` (independent) fails in the direction that matters: US-78-6 and US-78-7 are **unobservable at 120×30 until US-78-8 lands**, because the result area has zero content rows. This inverts the charter's ordering, which lists S-8 last.
**US-78-9 — halved.** The `Enter → open-in-hex` clause is ruled OUT with cause (§2.8 D-2); the discoverability clause is ruled IN.

### 2.7 Premise evaluation (C-43) — one row per premise

Tier: **axiom** (validated + verified) · **hypothesis** (this batch/charter introduces) · **premise** (claim about the world). Phase-0's P-1…P-20 are **not restated**; this table carries only what THIS lane newly relies on, newly corrects, or re-derived because an acceptance rests on it. **Every evidence cell is a command I ran in this session.** A citation of another document is not evidence.

| # | Premise as a truth-apt proposition | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| **P-31** | 🆕 **The A2B diff panel's emitted hex row is 81 cells** (§9.1 of Phase 0, and the charter's headline figure) | premise | ❌ **FALSE — 79, and measured off the wrong producer** | The panel imports `render_hex_view` at `screens_directionb.py:7021` and calls it at `:7030-7031`; its docstrings name it at `:6606` and `:7016`. It does **not** use `render_hex_view_text`. Executed over a 64-byte map: `render_hex_view` (`hexview.py:330`) → `79 '0x00001000  00 01 … \|…\|'`; `render_hex_view_text` (`hexview.py:360`) → `81 '  0x00001000 …'`; `delta = 2` — exactly the two-space left indent. Confirmed end-to-end on the **panel's own rendered widget text** @132×44: line widths `[38, 79, 79, 79, 79, 79, 79]`. | **Corrects §9.1.** Every S-7 threshold below uses **79**. **81 remains correct for the workspace hex pane.** ✅ **Independently reproduced by the orchestrator and the QA lane** (`00-measurements.md` §10) — three separate derivations, same number. |
| **P-32** | Box chrome is 5 columns and `#diff_columns` content width is terminal − rail − 6 | premise | ✅ **TRUE, re-derived** | Single-window config, executed: `120: diff_columns=92 content=87 → chrome=5` · `132: 104/99 → 5` · `160: 132/127 → 5`. Shipped 3-column widths: 80→`18/18/19` in 70 · 120→`25/26/26` in 92 · 132→`29/30/30` in 104 · 170→`42/42/43` in 142 · 190→`49/49/49` in 162. Rail: **4** @80, **4** @110, **22** @120+. | Confirms §9.2 **except** that §9 states the rail collapses only at 80 — it is 4 at 110 too. |
| **P-32b** | 🆕 **"a 22-column list" is unambiguous** | premise | ❌ **FALSE — box and content differ by 4, and the two readings give different breakpoints** | Textual's CSS `width: N` sets the **border-box**; `size.width` reports the **content** inside `border: round` (2) + `padding: 1` (2), with `margin-right: 1` outside. Executed: `styles.width = 12` → `size.width = 8`. So a CSS `width: 22` list is **18** content cells. Sweep at both readings, window content vs terminal: **css 22 (L=18)** → `120:64 ✗ · 132:76 ✗ · 136:80 ✅` · **css 26 (L=22)** → `120:60 ✗ · 132:72 ✗ · 138:78 ✗ · 139:79 ✅ · 160:100 ✅`. | **Reconciles my 136 with the orchestrator's 139 — both are right in their own units.** The side-by-side bound is `L + 5 + 79 + 5 ≤ C`, i.e. **`L ≤ C − 89`** in content units; at `L = 22` it needs `C ≥ 111`, i.e. a terminal of **139**, and the measurement lands on 139 **to the column**. This document adopts **content units** and **139** — the more demanding reading. |
| **P-33** | 🆕 **The 120-col problem is horizontal** (charter S-7, and §9.4's framing) | premise | ❌ **FALSE — it is vertical first** | Executed `#diff_columns.height / #diff_hex_a.height`: `80×24 → 1/0` shipped, `1/0` with S-8 compaction, `1/0` with S-8 **and** the bar hidden. `120×30 → 1/0` shipped, `3/0` compacted, **`6/2`** compacted + no bar. `160×40 → 7/3` shipped, `13/9` compacted, **`16/12`** compacted + no bar. | **BLOCKS the charter's S-7 framing.** Drives §2.8 D-1 and the US-78-8 promotion. |
| **P-34** | 🆕 **A 12-col run list beside the window fits an unwrapped row at 120** (charter S-7 option a) | hypothesis | ❌ **FALSE at 120, by a wide margin** | Sweep of window content width vs terminal width, restyling the shipped tree (`stacked` / `beside22` / `list12`, CSS-box widths): `80 → 65 / 42 / 52` · `120 → 87 / 64 / 74` · `130 → 97 / 74 / 84` · `132 → 99 / 76 / 86` · `136 → 103 / 80 / 90` · `160 → 127 / 104 / 114`. Against **79**: `list12` is ❌ at 120. `stacked` fits from 100 up, ❌ at 80. Cross-checked against the closed form `L ≤ C − 89` (P-32b): the **maximum** list content width beside an unwrapped window is **3** at 120 (`C=92`), **15** at 132 (`C=104`), **43** at 160 (`C=132`). | **Eliminates charter option (a):** a 12-cell list needs `C ≥ 101`, i.e. a terminal of ~**129** — it is impossible at 120 whichever unit you read it in (12 > 3). **Also eliminates the charter's "22-col list at ≥ ~130"**: 22 > 15, so it does not work at 132 either. Drives §2.8 D-1. |
| **P-35** | 🆕 **The A2L filename does not reach the Loaded panel today** (charter S-3, "re-home") | premise | ❌ **FALSE — already shipped** | Executed with a synthetic `LoadedFile(a2l_path=Path("ECU_CAL.a2l"), mac_path=Path("CAL.mac"), …)`: `#loaded_panel` renders `'Loaded \| S19 \| IMG.s19  1 B · 1 rng \| MAC \| CAL.mac  0 records \| A2L \| ECU_CAL.a2l  0 tags \| unload all'`. `'ECU_CAL.a2l' in panel → True`; `'PROJ_X' in panel → False`. Source: `_slot_state` (`screens_directionb.py:1891`) reads `loaded.a2l_path`. | **Re-scopes US-78-3.** An "A2L name in the Loaded panel" acceptance would be **GREEN today** — vacuous. |
| **P-36** | 🆕 **`#workspace_status_bar` renders on all 10 screens and carries no project/A2L text today** | premise | ✅ **TRUE** | Executed per screen @120×30: all 10 report `size=116x7 labels=7 display=True`. Content with a project + A2L set: `'Ready. \| 0% \| --:--:-- \|  \|  \|  \| '` — **no project, no A2L**. Composed at `app.py:1930`, a sibling of `#workspace_shell`. | US-78-3's status-bar half is genuinely net-new. ⚠️ It is **7 rows tall already** — see LLR-120.3. |
| **P-37** | 🆕 **Deleting `tests/test_tui_commandbar.py` nodes is registry-neutral** | hypothesis | ❌ **FALSE — it turns G2 red** | `grep -c "test_tui_commandbar" AT-TC-REGISTRY.jsonl` → **4** rows: `TC-007`, `TC-008`, `TC-009`, `TC-039`, all `"status": "LIVE"`. G2 = *"every `LIVE` entry's `nodes` all exist"* (`tests/test_id_registry.py:223`, `.dev-flow/AT-TC-REGISTRY-SPEC.md:270`). `TC-008`'s `nodes` names 5 `test_tui_commandbar.py` node ids. | **Widens US-78-4** by one file: `AT-TC-REGISTRY.jsonl` node-list repair. |
| **P-38** | 🆕 **`#cmdbar_project` has 1 test consumer** (Phase-0 §5 named 3 Lane-1 files) | premise | ❌ **FALSE — 3 consumers in 3 files, 2 of them unnamed by Phase 0** | `grep -rn "cmdbar_project\|_project_label" tests --exclude-dir=__pycache__`: `tests/test_tui_patch_variant.py:85` `return str(bar.query_one("#cmdbar_project").content)` (helper `_project_label`, defined `:82`, called at `:153, :155, :233, :305, :583, :599, :607, :772`) · `tests/test_tui_variants.py:78` (identical helper) · `tests/test_tui_directionb.py:897`. Both helpers are the **observable** those suites use to assert variant switching. | **US-78-3 must land BEFORE US-78-1** so the consumers have a surviving observable to re-point at. Drives §7 Inc-1→Inc-2→Inc-4. |
| **P-38b** | 🆕 **`tests/test_tui_app.py` is a fourth `#cmdbar_project` consumer** (orchestrator's correction) | premise | ⚠️ **PARTIALLY — the file IS coupled, but not by reading the label** | Same grep: `tests/test_tui_app.py` contains **zero** `#cmdbar_project` references. Its three hits are `monkeypatch.setattr(app, "update_project_labels", …)` at `:70`, `:233` and `:1338` — it **stubs the producer** HLR-120 rewrites. | **Accepted with its nature corrected.** The coupling is real and belongs in the census, but it is the opposite kind: these three tests will **not break** when the label moves — they will be **blind** to HLR-120's new behaviour, because they replace the entry point with a no-op. Recorded so no one mistakes their green for coverage. **Lane-1 test files = 7**: the 3 of P-38, plus `test_tui_app.py`, `test_tui_commandbar.py`, `test_loadfilescreen_input.py`, `test_universal_paste.py`. |
| **P-38c** | 🆕 **The project label has one display form** (my own §3 draft asserted a `(1/1)` counter — **this row corrects my own defect**) | hypothesis | ❌ **FALSE — there are two forms and the single-variant one is pinned by a live test** | `app.py:11328` `project_name = self.current_project or "(none)"`; the suffixed form is built **only** inside `if … len(variant_set.variants) > 1 …` (`:11329-11333`), yielding `f"{project}:{display} ({i}/{N})"` (`:11345-11348`). So **N == 1 renders the plain project name with no counter**, and `tests/test_tui_variants.py:259` `test_single_s19_project_label_plain` pins exactly that under **LLR-005.3** — *"A single-S19 project shows the plain project name — no `(1/1)`"* (`:260`). | **Corrects my own `TC-B78-11`, which asserted `(1/1)`** and would have false-failed a correct implementation while contradicting a live acceptance. **S-3 owes the display FORM, both branches** — new LLR-120.5. |
| **P-39** | The palette command set is invariant under the row deletion (US-78-1's control) | hypothesis | ✅ **TRUE by construction, baseline executed** | `visible_palette_labels()` → **37** entries; `focus_find`/`focus_goto` present as `('focus_find','Find')`, `('focus_goto','Go-to')`. Entries are derived from `BINDINGS` (`app.py:5758-5772`), not from the row. `/`·`g` are **re-homed, not deleted**, so both entries survive. Ctrl+K executed on all 10 screens: `palette_is_open=True` **10/10**. | Gives US-78-1 a non-vacuous control: **37 and 10/10**, both RED-able. |
| **P-40** | `/` and `g` focus the bar inputs on every screen, and `Esc` does not return focus | premise | ✅ **TRUE, re-derived with an asserted blur** | Per screen, `app.set_focus(None)` + `assert app.focused is None` before each press: all 10 → `'/' → find_input`, `escape → find_input` (**unchanged**), `'g' → cmdbar_goto_input`. Local inputs exist on 3 of 10 (`workspace`/`a2l`/`mac`). | Confirms P-6/P-11/P-12. **US-78-2's Esc clause is net-new**, on all 10. |
| **P-41** | 🆕 **29 of 29 goldens render the bar** (Phase-0 §5's drift claim) | premise | ✅ **TRUE, but the per-cell reason differs (C-22)** | `grep -lF` over the 29 SVGs: `'Project:'` → **29/29** · `'A2L:'` → **29/29** · `'Goto&#160;0xADDR'` → **8/29** · `'Find&#160;ASCII'` → **0/29**. The **labels** are what render everywhere; the find placeholder renders in **none**, the goto placeholder in 8. | Drift count **29** confirmed. Per-cell reason recorded per C-22. |
| **P-42** | 🆕 **The charter's `j`/`k`/`n`/`p` run-list keys are free** (S-5) | premise | ❌ **FALSE for 3 of 4** | `app.py:1352` `Binding("o","open_workarea",…,show=False)` · `:1354` `Binding("p","load_project",…,show=False)` · `:1356` `Binding("j","dump_a2l_json",…,show=False)` · `:1359` `Binding("k","show_legend","Legend",show=True)`. **`n` is unbound.** A focused widget's binding shadows the App's (batch-77 P-23, textual 8.2.8). | **Strikes `j`/`k`/`p` from US-78-5.** Same defect batch-77 blocked on, one batch later. Drives LLR-122.2. |
| **P-43** | 🆕 **`Enter → open-in-hex` is implementable for a diff run** (charter S-9) | hypothesis | ❌ **FALSE as chartered — it would show the wrong bytes** | `on_memory_map_panel_open_in_hex_requested` (`app.py:10261`) does `action_show_screen("workspace")` + `update_hex_view(focus_address=…)`, which renders **`current_file`**. A diff compares two images that are frequently both external (`ImageRef(source_kind="external")`) and neither is `current_file`. There is no existing route to render an arbitrary image in the hex view. | **Rules the clause OUT** — §2.8 D-2. Carried, §6.4. |
| **P-44** | The width-regime split can reuse the existing breakpoint machinery | premise | ⚠️ **PARTIALLY — the machinery exists, the constant does not** | `_apply_width_regime` at `app.py:6205`, driven by `on_resize` at `:6239`; the threshold is a **bare literal**: `narrow = width < 120` (`app.py:6232`). No named constant anywhere. | LLR-124.1 **requires** a named constant — C-39 forbids an AT quoting a value. |
| **P-45** | The Lane-1 / Lane-2 test-file collision (`PLAN.md` R-2) is unavoidable | hypothesis | ❌ **FALSE — it is avoidable by routing** | Lane 2's ATs have a natural home in `tests/test_tui_diff_screen.py` (already the `AbDiffPanel` suite: `render_comparison` ×5, `DISPLAY_MAX_RUNS` ×4). Lane 1's belong in `tests/test_tui_commandbar.py`. Neither lane needs to **edit** `tests/test_tui_directionb.py` except US-78-3's one consumer at `:897` and US-78-4's cleanup — both in Lane 1. | **R-2 dissolved by construction**, not by sequencing. C-34 still requires the full file to **run** at every render gate. |
| **P-46** | The touched suites are green on the base tree (the RED-today baseline) | premise | ✅ **TRUE** | `python -m pytest tests/test_tui_commandbar.py tests/test_tui_diff_screen.py tests/test_tui_diff_compare_realpath.py tests/test_id_registry.py -q -m "not slow"` → **`38 passed in 36.26s`** (**LEAN form** — `-m "not slow"`). | Baseline for §7's gates. Form stated per the project reference rule. |
| **P-47** | 🆕 **`n` and the arrow keys are enough for US-78-5, with no new app binding** | hypothesis | ⚠️ **UNDECIDABLE at Phase 1 — framework claim** | Textual's stock `ListView` binds `up`/`down`/`enter` on itself. Whether those fall through / shadow correctly under this app's `priority=True` bindings (`app.py:1339-1342`) is **not executed here**. | `assumed — verify in target framework at Phase 3`. LLR-122.2's AT **must press real keys**, never call `.focus()`. |

**Gate rule:** ❌ and ⚠️ block unless dispositioned. **P-31/P-33/P-34/P-35/P-37/P-38/P-42/P-43/P-45 are ❌ and every one is self-dispositioning** — each corrects a prior claim and the correction has landed in this document's body. **P-47 is an honest UNDECIDABLE** and is flagged in the LLR it feeds rather than smoothed over. **P-33 and P-34 jointly drive the one open operator decision, §2.8 D-1 / §8 OQ-1.**

### 2.8 Decision tables

#### D-1 · S-7's regime pair — the charter's three options against the measured budget

**The measurement.** Emitted row **79** (P-31). The side-by-side bound, closed form and executed to the column (P-32b): a run list of content width `L` leaves an unwrapped window only when

> **`L + 5 + 79 + 5 ≤ C`**, i.e. **`L ≤ C − 89`**, where `C` = `#diff_columns` content width = terminal − rail − 6.

| terminal | `C` | **max list content width beside an unwrapped window** |
|---|---|---|
| **80×24** | 70 | **−19** — impossible at any list width, and a full-width window reaches only 65 |
| **120×30** | 92 | **3** |
| 132×44 | 104 | **15** |
| **160×40** | 132 | **43** |

Window content width by layout at the project's three supported regimes (C1):

| layout | 80 | 120 | 160 |
|---|---|---|---|
| shipped 3-column | 18 ❌ | 26 ❌ | ~42 ❌ |
| **(a)** 12-cell list beside one window | 52 ❌ | **74 ❌** (needs `C ≥ 101` → ~129) | 114 ✅ |
| **(b)** list as overlay, one full-width window | 65 ❌ | **87 ✅** | 127 ✅ |
| **(c)** list stacked above, windows full-width | 65 ❌ | **87 ✅** | 127 ✅ |
| 22-cell list beside one window (charter "variant A") | 42 ❌ | 60 ❌ | **100 ✅** (first fit **139**) |

And the vertical budget, `#diff_hex_a` content rows after US-78-8 + Lane-1's bar deletion (P-33): **80×24 → 0** · **120×30 → 2** · **160×40 → 12**.

⚠️ **Two charter claims die here, both by arithmetic rather than by judgement.** *"12-col list at 120"* needs `L ≤ 3` and asks for 12. *"22-col list + full-width windows at ≥ ~130"* needs `L ≤ 15` at 132 and asks for 22 — the first width at which it fits is **139**, so **the charter's own 132×44 capture is on the fallback side of its own recommended line.**

| Option | What the HLR would say | Expected result | Consequences |
|---|---|---|---|
| **①** *(recommended)* **Two regimes at a new named breakpoint.** Wide (`≥ _DIFF_WIDE_MIN`, **139**): 22-cell run list beside a full-height window column, windows stacked inside it. Fallback (`< 139`): list as a dismissible overlay, one full-width window column. | "…when the terminal width is at least `_DIFF_WIDE_MIN`, `#diff_columns` **shall** render the run list beside the window column; otherwise it **shall** render the run list as an overlay and the window column at full content width; **and** in both regimes each window's content width **shall** be at least the emitted hex-row width" | ✅ Both project regimes land unwrapped: 160 → 100, 120 → 87. ✅ Each regime owns exactly one existing snapshot cell (160×40 wide, 120×30 fallback) — no new cell needed. ✅ The list stays **visible** at 160, which is the operator's "accessibility of information is first-class". ✅ Mirrors `width-narrow`'s shape. ✅ **139 is the measured first fit for a 22-cell list** (`L ≤ C − 89` → `C ≥ 111`), confirmed to the column: 138 → 78 ✗, 139 → 79 ✅. | ⚠️ Adds a second breakpoint to the app; `_DIFF_WIDE_MIN = 139` is a **new** constant. ⚠️ The overlay needs a dismissal path (`assumed — verify Phase 3`). ⚠️ **132 falls in the fallback regime** — the charter's capture width is on the wrong side of its own recommended line, and that must be said out loud in the postmortem. ⚠️ Note the breakpoint's real property: **any value in `[121, 160]` separates the two supported regimes identically** (C1); 139 is simply the one with a derivation behind it rather than a round number. |
| **②** **One regime everywhere: list always an overlay, window always full-width.** | "…`#diff_columns` **shall** render one full-width window column at every terminal width…" | ✅ Simplest possible: no breakpoint, no second CSS class, no resize branch. ✅ Unwrapped from 100 columns up. | ❌ **The run list is never visible beside the bytes**, at any width — including 160×40 where there is room for both. That is a direct accessibility regression against the operator's stated first-class concern, paid to save one constant. ❌ Loses the wide cell's regression value: both goldens would then render the same layout. |
| **③** **Charter option (a): 12-cell list, one regime.** | — | ❌ **Fails at 120 — the budget is `L ≤ 3` and the option asks for 12** (P-32b/P-34), i.e. at exactly the regime it was proposed to rescue, and the only regime with a diff golden. | ❌ **Reject on measurement.** Struck at draft time per C-13.1 (a rung whose recovery is smaller than the deficit is not bikeshedded at the gate). |
| **④** **Keep 132×44 as the wide regime, tune the list to fit.** | — | ❌ At 132 the budget is `L ≤ 15`, so a list narrower than 16 cells fits **there** — but the same list dies at 120, where the budget is `L ≤ 3`. **No positive list width satisfies both.** | ❌ **Reject.** Also: 132 is not a supported regime (C1) — tuning to it optimises a width the project does not test, and a 3-cell list is not a list. |

**Recommendation: ①.** Rationale tied to the constraints: C1 says the project supports 80/120/160 and C2 says only one diff cell exists today; option ① is the only candidate that puts **each** supported wide/fallback width on the correct side of a measured line **and** keeps the run list visible where the budget allows it. `_DIFF_WIDE_MIN = 139` is the measured first fit for a 22-cell list (`L ≤ C − 89`, P-32b), not a round number.
**What would change this recommendation:** if Phase 2 finds the overlay's dismissal path costs more than a CSS class and one binding, ② becomes the right trade — the accessibility loss at 160 is real but bounded, and simplicity is this project's stated tiebreak. **Not measured; the overlay mechanism is `assumed — verify in target framework at Phase 3`.**

#### D-2 · S-9 — ruled IN and OUT, explicitly (the charter forbids silent absorption)

| Clause | Verdict | Basis |
|---|---|---|
| Keyboard path (↑/↓/Enter/click) is **discoverable** — surfaced on the run list itself and via the stock `?` help panel (`app.py:5836`, bound at `:1364`) | ✅ **IN** | Near-zero marginal cost: the list's own bindings appear in the stock help panel automatically, and the batch already drifts all 29 goldens (P-41), so the C-28 shared-chrome census is **already paid**. |
| A **new app-level `show=True` Footer binding** for run navigation | ❌ **OUT** | Would add a second C-28 obligation for a key the focused widget already owns. No measured need. |
| `j`/`k`/`n`/`p` vim aliases | ❌ **OUT** | P-42: `j`, `k`, `p` are bound app-wide; `k` is `show_legend` with `show=True`, so a shadowing binding would make a **Footer hint false on the screen displaying it**. Exactly batch-77's B-2. Only `n` is free, and a lone `n` is not a keymap. |
| `Enter` posts an open-in-hex message | ❌ **OUT — carried** | P-43: the existing handler renders `current_file`, which is generally **neither** image A nor image B. Shipping it would show the operator the wrong bytes with no error. Needs a "render an arbitrary image in the hex view" capability that does not exist. **Carry C-78-d**, §6.4. |

**Recommendation: adopt as tabled.** `Enter` is left bound to the list's own `Selected` message with **no** app-side handler, so the key is inert rather than wrong.

---

## 3. High-level requirements (HLR)

> **ID basis (executed):** `grep -rhoIE 'HLR-[0-9]{2,4}' REQUIREMENTS.md .dev-flow tests docs s19_app --exclude-dir=__pycache__ | sed 's/HLR-//' | sort -n | uniq | tail` → high-water **117** (batch-77). **Next free = `HLR-118` / `LLR-118`.**
> **`R-TUI-*` (executed):** highest **defined** row is `R-TUI-103` (`REQUIREMENTS.md:5922`, `:5974`). `R-TUI-111`/`112` appear **only** as prose in `REQUIREMENTS.md` and have **0** live citations in `tests/`, `s19_app/`, `docs/` — they were re-pointed at `R-TUI-103` under batch-77's D-17 and no row was ever created. **This batch claims `R-TUI-104`**, following batch-77's own precedent of taking the next *defined* number.
> **No global `AT-NNN` / `TC-NNN` is minted here.** Ids are **batch-scoped** `AT-B78-nn` / `TC-B78-nn` per `PLAN.md` D-7; `AT-TC-REGISTRY.jsonl` is touched **only** for the G2 node-list repair of P-37.

---

### HLR-118 — the command-bar row is gone and the palette is untouched
- **Traceability:** US-78-1
- **Statement:** When the application renders any screen, the widget tree **shall not** contain `#command_bar_row` or any of its children, and the Ctrl+K command palette **shall** open on every screen of `SCREEN_CONTAINER_IDS` with a command set identical to the pre-change set.
- **Rationale (informative):** `#command_bar_row` (`command_bar.py:140`) costs 3 rows on all 10 screens (Phase-0 P-9). `#command_palette` (`:150`) is its **sibling**, not its child, so the row deletes without touching the palette; the palette's entries are derived from `BINDINGS` (`app.py:5758-5772`), not from the row, so the command set is invariant by construction — which is exactly why the acceptance must assert it rather than assume it.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_commandbar.py -v` **plus** the full `tests/test_tui_directionb.py` (C-34 render-increment guard host)
- **Numeric pass threshold:** `len(app.query("#command_bar_row")) == 0` on **all 10** screens (today: 1 on all 10); palette opens on **10 of 10** (today 10 of 10 — the control); palette entry count **== 37** and the action list is **set-equal** to the pre-change list (today 37, executed P-39)
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome:**
  - **Observable outcome:** the operator sees three more rows of the screen they are on, and Ctrl+K still opens the same command list from anywhere.
  - **Shipped surface:** `App.run_test(size=…)` → `action_show_screen(k)` for each `k` → `app.query("#command_bar_row")`; then `set_focus(None)` → `pilot.press("ctrl+k")` → `CommandBar.palette_is_open` (a **property**, not a method — verified at `command_bar.py:195-196`)
  - **Deliverable + observation:** the rendered widget tree per screen. ⚠️ **C-40:** "the row is absent" is trivially green on a screen that mounted nothing — the AT co-asserts `len(app.query("#command_palette")) == 1` **and** that the screen's own container is present, in the same run.
  - **Acceptance test(s):** `AT-B78-01` zero `#command_bar_row` across all 10 screens **with** the palette container co-asserted present · `AT-B78-02` Ctrl+K opens the palette on all 10 screens (**blur asserted before each press**, per Phase-0 §7) · `AT-B78-03` the palette's action list is set-equal to the committed pre-change list of 37
  - **Boundary catalog (QC-3):** ☑ **empty** — no file loaded → row still absent, palette still opens, `TC-B78-01` · ☑ **boundary** — the palette opened, then a screen switch, then Ctrl+K again, `TC-B78-02` · ☑ **invalid** — `action_show_screen` with an unknown key (guarded at `app.py:5814`) leaves the tree unchanged, `TC-B78-03` · ☐ **error** — **N/A:** removal of a static widget set admits no new input class.

---

### HLR-119 — `/` and `g` act on the active screen, and `Esc` returns focus to the pane
- **Traceability:** US-78-2
- **Statement:** While a screen is active, the `focus_find` action **shall** move keyboard focus to that screen's own find input and the `focus_goto` action **shall** move it to that screen's own go-to input; when the active screen owns no such input, the action **shall** emit exactly one status-line notice and **shall not** raise; and when focus is on a find or go-to input, `Escape` **shall** move focus off that input.
- **Rationale (informative):** Executed on all 10 screens (P-40): `/` → `find_input`, `g` → `cmdbar_goto_input`, and `escape` → **still `find_input`**. Because `action_show_screen` swaps a `hidden` class and nothing unmounts (Phase-0 P-10), **all eight** find/goto inputs resolve on every screen — so routing **shall** key on `_active_screen_key` (`app.py:5816`), never on which inputs exist. The routing defect this fixes is not cosmetic: Phase-0 §8 executed `CommandBar.Find("BOOT")` with **A2L active** and it wrote `'BOOT'` into the **workspace** `#search_input`. The no-local-input notice is the **majority** path — 7 of 10 screens (P-40).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_commandbar.py -v` + full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** on `workspace` `/` focuses `#search_input` and `g` focuses `#goto_input`; on `a2l` `#alt_search_input` / `#alt_goto_input`; on `mac` `#mac_search_input` / `#mac_goto_input` (today: `find_input` / `cmdbar_goto_input` on **all 10**); on the other **7** screens `app.focused` is unchanged and `#status_text` differs from its prior value, with **0** exceptions raised; after `Escape` from a focused find input, `app.focused` **is not** that input (today it **is**, on all 10)
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a find started on the A2L screen searches the A2L; a find started where there is nothing to search says so instead of silently searching another pane.
  - **Shipped surface:** `pilot.press("slash")` / `pilot.press("g")` / `pilot.press("escape")` against the live app — **real key events only**, never `.focus()`
  - **Deliverable + observation:** `app.focused.id` after each press; `#status_text` rendered text for the notice arm. ⚠️ **The blur guard is mandatory:** `app.set_focus(None)` followed by `assert app.focused is None` **before every press**. Phase-0 §7 records a probe that skipped it and produced a plausible, false `g → find_input` reading on every screen; my own P-40 run asserts the blur and is the corrected form.
  - **Acceptance test(s):** `AT-B78-04` `/` and `g` focus the **local** inputs on `workspace`/`a2l`/`mac` (RED today: bar inputs on all three) · `AT-B78-05` on each of the 7 screens without local inputs, exactly one status notice and no exception · `AT-B78-06` **the wrong-pane arm** — with `a2l` active, driving a find writes into `#alt_search_input` and leaves `#search_input` empty (RED today, executed inverse in Phase-0 §8) · `AT-B78-07` `Escape` from a focused find input moves focus off it (RED today on all 10)
  - **Boundary catalog (QC-3):** ☑ **empty** — no file loaded: focus still moves, the handler still refuses cleanly at its existing "No file loaded." guard, `TC-B78-04` · ☑ **boundary** — `/` pressed twice without an intervening blur (idempotent, no second notice), `TC-B78-05` · ☑ **boundary** — screen switched **while** an input is focused; the next `/` follows the **new** screen, `TC-B78-06` · ☑ **invalid** — `focus_find` invoked while `_active_screen_key` names a screen not in the local-input map → the notice path, `TC-B78-07` · ☑ **error** — `focus_find` invoked before the tree is mounted → no raise, `TC-B78-08`

---

### HLR-120 — the loaded project and A2L are named on every screen
- **Traceability:** US-78-3
- **Statement:** When a project or A2L is loaded, `#workspace_status_bar` **shall** present the active project string and the A2L filename on every screen of `SCREEN_CONTAINER_IDS`, and `#loaded_panel` **shall** present the active project string; both surfaces **shall** present the project in the **same two display forms the command bar presents today** — the plain project name when the project holds at most one variant, and the `project:variant (index/total)` form when it holds more than one; both surfaces **shall** be refreshed by the same update entry point; the widget receiving file-derived text **shall** be constructed with `markup=False`; and the addition **shall not** increase the rendered height of `#workspace_status_bar`.
- **Rationale (informative):** Measured (P-35): `#loaded_panel` **already** renders the A2L filename via `_slot_state` (`screens_directionb.py:1891`) — an acceptance for that half would be green today. What is absent everywhere except the bar is the **project string**, composed at `app.py:11328-11348`. Measured (P-36): `#workspace_status_bar` renders `116x7` on **all 10** screens and carries no project or A2L text. **The story owes the display FORM, not merely the name** (P-38c): the suffixed `(i/N)` form is produced *only* under `len(variant_set.variants) > 1` (`app.py:11332`), and a single-S19 project renders the plain name — pinned live by `tests/test_tui_variants.py:259` under LLR-005.3. An implementation that re-homes the string but flattens it to one form breaks a shipped acceptance. The **two-surface** design is the operator's ruling (option C) and it creates two update paths, so each needs its own discriminating arm — a single test observing one surface is green on an implementation that updates only that one. The height clause exists because the status bar is **already 7 rows** on a 30-row terminal: an eighth row would spend a third of Lane 1's own 3-row reclaim, app-wide, and the diff pane (C7) cannot afford it.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_commandbar.py -k context -v` + `pytest tests/test_tui_variants.py tests/test_tui_patch_variant.py -v` + full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** with `current_project="PROJ_X"` and a loaded A2L, the status bar's rendered text contains `PROJ_X` **and** the A2L filename on **10 of 10** screens (today **0 of 10**); `#loaded_panel` text contains `PROJ_X` (today **absent** — executed `'PROJ_X' in panel → False`); `#workspace_status_bar.size.height == 7` after the change (today **7**)
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** on any screen the operator can read which project, variant and A2L they are working on, without going back to the workspace.
  - **Shipped surface:** set the load state → `update_project_labels()` → `_refresh_loaded_panel()` → read `#workspace_status_bar` and `#loaded_panel` rendered text per screen
  - **Deliverable + observation:** the concatenated rendered text of each surface's `Label`/`Static` children, plus `#workspace_status_bar.size.height`. ⚠️ **C-40, and this is the one the operator's ruling forces:** the two surfaces need **two separate arms**. An implementation that updates only the status bar passes a Loaded-panel-blind test and vice versa. ⚠️ **C-40 again:** a substring assertion is green on a surface that rendered the string for an unrelated reason — the A2L arm **must** use a filename that appears nowhere else in the composed text, and the project arm asserts the **variant counter** `(1/1)` too, not the bare project name.
  - **Acceptance test(s):** `AT-B78-08` status bar names project **and** A2L on all 10 screens (RED today: 0 of 10) · `AT-B78-09` `#loaded_panel` names the project (RED today: absent) · `AT-B78-10` **the discriminating arm** — after a variant switch, **both** surfaces report the **new** variant in the same run (the arm that catches a single-surface implementation and a stale-cache implementation at once) · `AT-B78-11` `#workspace_status_bar.size.height` is unchanged at 7 · `AT-B78-30` **the display-form arm** — a one-variant project renders the **plain** name on both surfaces with **no** `(1/1)`, and a two-variant project renders `project:variant (1/2)` on both
  - **Boundary catalog (QC-3):** ☑ **empty** — nothing loaded → both surfaces render the `(none)` sentinels, not a blank, `TC-B78-09` · ☑ **boundary** — project loaded but **no** A2L, `TC-B78-10` · ☑ **boundary** — a single-variant project renders the **plain project name and no counter** ⚠️ **an earlier draft of this catalog said `(1/1)` and was wrong** — `app.py:11332` gates the suffix on `> 1` and `tests/test_tui_variants.py:259` pins the plain form under LLR-005.3, so the `(1/1)` assertion would have false-failed a correct implementation *and* contradicted a live acceptance, `TC-B78-11` · ☑ **invalid** — a hostile filename `[red]evil[/].a2l` renders **verbatim** and raises no `MarkupError` (C-17; the `#status_text` precedent at `app.py:1916` is `markup=False` **at construction**, which persists across `.update()`), `TC-B78-12` · ☑ **error** — `update_project_labels` called before mount → no raise, `TC-B78-13`

---

### HLR-121 — the duplicate find/goto surface is deleted, and the surviving handlers are unchanged
- **Traceability:** US-78-4
- **Statement:** The `CommandBar.Find` and `CommandBar.Goto` message classes, their application-side adapters, the `focus_find` / `focus_goto` / `set_context_labels` helpers and the `#command_bar_row` style block **shall** be absent from the source tree; the workspace, A2L and MAC search and go-to handlers **shall** be byte-identical to their pre-change form; and every registry entry naming a deleted test node **shall** be reconciled.
- **Rationale (informative):** These are the "second, wrong implementation": `on_command_bar_find` (`app.py:5995`) writes `event.query` into `#search_input` and calls `_handle_search()` regardless of which screen is active. Once HLR-118 removes the inputs the messages cannot be posted, and once HLR-119 re-points the actions the helpers have no callers — so this requirement is the cleanup, and its **control** is that `_handle_search` (`:11448`), `_handle_goto` (`:11518`), `_handle_search_alt` (`:11538`), `_handle_goto_alt` (`:11568`), `_handle_search_mac` (`:11589`) and `_handle_goto_mac` (`:11618`) are not touched. The registry clause is not bookkeeping: `TC-007/008/009/039` are `LIVE` rows whose `nodes` name `tests/test_tui_commandbar.py::…` (P-37), and G2 fails on a `LIVE` entry naming a node that does not exist.
- **Validation:** `test` + `inspection`
- **Executed verification:** `pytest tests/test_tui_commandbar.py tests/test_id_registry.py -v` + full `tests/test_tui_directionb.py` (C-34) + `git diff origin/main -- s19_app/tui/app.py` over the six handler bodies
- **Numeric pass threshold:** `grep -c` over `s19_app/` for each of `class Find`, `class Goto`, `on_command_bar_find`, `on_command_bar_goto`, `def focus_find`, `def focus_goto`, `def set_context_labels` → **0** each (today: 1 each); `styles.tcss` contains **0** `#command_bar_row` / `#cmdbar_project` / `#cmdbar_a2l` / `#find_input` / `#cmdbar_goto_input` rules; `git diff` line count over the six surviving handler bodies → **0**; `tests/test_id_registry.py` G1–G7 **green**
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** searching on the workspace, A2L and MAC screens behaves exactly as before; nothing else in the app references the deleted surface.
  - **Shipped surface:** the existing workspace/A2L/MAC search flows, driven end-to-end; plus source inspection for the absence half
  - **Deliverable + observation:** the search/goto results rendered by each of the three screens, compared against pre-change behaviour; and an **AST/grep census** over `s19_app/` for the deleted symbols. ⚠️ **C-42 mechanic 5:** the source census is an **AST** census, not a line regex — an implicitly-concatenated f-string is one template, not the lines it occupies. ⚠️ **C-40:** the absence census is green on an empty corpus; it co-asserts that the module list it swept is non-empty and contains `command_bar.py`.
  - **Acceptance test(s):** `AT-B78-12` **the control** — workspace, A2L and MAC find + goto produce the same rendered result as the committed pre-change capture, all three screens · `AT-B78-13` source census: zero references to the seven deleted symbols, with the swept module list co-asserted non-empty · `AT-B78-14` `tests/test_id_registry.py` green after the node-list reconciliation
  - **Boundary catalog (QC-3):** ☑ **boundary** — a search with no hits on each of the three screens, `TC-B78-14` · ☑ **invalid** — a malformed go-to address on each of the three screens still routes to `set_status` and raises nothing (the pre-existing contract), `TC-B78-15` · ☑ **empty** — no file loaded: each handler bails at its own guard, unchanged, `TC-B78-16` · ☐ **error** — **N/A:** deletion introduces no new input class.

---

### HLR-122 — every displayed run is reachable by keyboard and by mouse
- **Traceability:** US-78-5
- **Statement:** When a comparison has rendered at least one run, `#diff_range_list` **shall** present one selectable entry per displayed run; each entry **shall** be reachable by arrow-key navigation and by mouse click; the entry holding the selection **shall** be visually distinguished from the others; entries beyond the viewport **shall** be reachable by scrolling; the display caps and the "showing N of M" notice **shall** be preserved; and the run list **shall not** bind any key that the application binds at App level.
- **Rationale (informative):** `#diff_range_list` is a `Static` today (`screens_directionb.py:6766`) — the run lines are text, so no run is selectable and `_render_run_windows` is called exactly once, with the literal `0` (`:6921`). The final clause is the **anti-regression** half and it is why the charter's `j`/`k`/`n`/`p` are absent from this requirement: `j`, `k` and `p` are bound at App level (P-42) and `k` is `show_legend` with `show=True`, so a shadowing binding would make a **Footer hint false on the screen showing it** — batch-77 blocked on exactly this. The caps clause preserves G-9: `DISPLAY_MAX_RUNS` (`:6623`) and `DISPLAY_MAX_TOTAL_BYTES` (`:6624`) bound the **panel**, never the persisted report.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -v` + full `tests/test_tui_directionb.py` (C-34) + full `tests/test_tui_diff_compare_realpath.py`
- **Numeric pass threshold:** with a 5-run comparison, **5** selectable entries (today **0**); after 4 `down` presses the selected index is **4**; after a click on entry 2 the selected index is **2**; with 200 runs the list shows `DISPLAY_MAX_RUNS` entries and the notice text is present; the literal keys `"j"`, `"k"`, `"p"` appear **0** times in the run list's `BINDINGS`
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator can walk every differing run with the arrow keys or the mouse, and can see which one they are on.
  - **Shipped surface:** `action_show_screen("diff")` → `AbDiffPanel.render_comparison(...)` → `pilot.press("down")` / `pilot.click(...)` → read the list's selected index and the entries' classes
  - **Deliverable + observation:** the list's entry set and its selection index. ⚠️ **C-38:** this changes the widget **type** `#diff_range_list` resolves to. `grep -rn "diff_range_list" tests/` returns **8 hits across 3 files** (`test_tui_diff_screen.py`, `test_tui_diff_compare_realpath.py`, `test_tui_directionb.py`) — every one is re-pointed or widened **before** the change runs, not after a green suite hides it. ⚠️ **C-40:** "5 entries exist" is invariant under a list that cannot be selected — the gate arm is the **selection index after a real keypress**, and the entry-count arm is labelled a **regression pin**, not a gate.
  - **Acceptance test(s):** `AT-B78-15` keyboard: 5 runs, 4 `down` presses, selected index 4, by **real keypress** (RED today: no selectable entries) · `AT-B78-16` mouse: a click on entry 2 selects entry 2 · `AT-B78-17` the selected entry is visually distinguished and **exactly one** entry is (the arm that catches an append-only implementation) · `AT-B78-18` **caps preserved** — a comparison exceeding `DISPLAY_MAX_RUNS` shows `DISPLAY_MAX_RUNS` entries plus the notice, quoting the **constant**, never the value (C-39) · `AT-B78-19` **anti-shadow** — with the run list focused, `k` still opens the legend and `j` still reaches its App action
  - **Boundary catalog (QC-3):** ☑ **empty** — a comparison with **0** differing runs keeps the existing "no differing runs" text and mounts no entries, `TC-B78-17` · ☑ **boundary** — exactly one run (`up`/`down` are no-ops, no crash), `TC-B78-18` · ☑ **boundary** — `up` on the first entry and `down` on the last, `TC-B78-19` · ☑ **boundary** — more runs than the viewport holds; the last entry is reachable under scroll, `TC-B78-20` · ☑ **invalid** — a run with `end == start`, `TC-B78-21` · ☑ **error** — a click landing below the last entry selects nothing and raises nothing, `TC-B78-22`

---

### HLR-123 — the hex windows follow the selection and are sized by the pane
- **Traceability:** US-78-6
- **Statement:** When the operator changes the run-list selection, both hex windows **shall** re-render to the selected run; the number of hex rows each window renders **shall** be derived from that window's rendered height at render time and **shall not** be a compile-time constant; the rendered window **shall** always include at least the selected run's own bytes plus `DISPLAY_CONTEXT_BYTES` of context on each side; and the window **shall** carry a header naming the run's index, address range and classification.
- **Rationale (informative):** `_render_run_windows` (`:7003`) derives its row set from `DISPLAY_CONTEXT_BYTES = 16` (`:6627`) alone — `low = start - 16`, `high = end + 16` (`:7026`, `:7028`) — so the row count is a function of the **run size**, not of the pane. Executed at 132×44 the widget produced `[38, 79, 79, 79, 79, 79, 79]`: one header plus **6** rows, and that 6 is identical at every terminal height. The floor clause keeps the current behaviour as a **lower bound** rather than retiring the constant outright, so a very short pane degrades to today's window instead of to nothing.
- **⚠️ C-29 flag — this requirement is height-bound, and the height is borrowed from two other stories.** Measured `#diff_hex_a` content rows (P-33): **160×40 → 3** today, **9** after US-78-8, **12** after US-78-8 **and** HLR-118. **120×30 → 0** today, **0** after US-78-8 alone, **2** only after both. **80×24 → 0** in every configuration. So the row-count-differs acceptance **shall** be observed at 160×40 (12 rows, a real spread) and **shall not** be keyed to 80×24, where the budget is physically zero. Per C-29 the threshold is relaxed at draft time rather than shipping a physically impossible AT.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -k "window" -v` + full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** after selecting run 3, both windows' header text names run index **3** and that run's start address (today: always run **0**); the rendered hex-row count at 160×40 **differs** from the count at 120×30 for the same run (today: **identical** — 6 and 6, executed); the rendered address span always covers `[start - DISPLAY_CONTEXT_BYTES, end + DISPLAY_CONTEXT_BYTES)`
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** picking a run shows that run's bytes, and a taller terminal shows more of them.
  - **Shipped surface:** as HLR-122, then reading `str(app.query_one("#diff_hex_a").render())` and `#diff_hex_b`
  - **Deliverable + observation:** the windows' **produced text**, split into lines. ⚠️ **C-32 layer split, stated deliberately:** this requirement's claim is about what the **producer emits**, so it is observed at the widget's rendered text — the *right* layer for a content claim. HLR-124's claim is about **geometry**, so it is observed at `size.width`. Neither AT may borrow the other's layer. ⚠️ **C-40:** "the header names run 3" is green on a window that rendered only a header — the arm co-asserts at least one emitted hex row in the same read.
  - **Acceptance test(s):** `AT-B78-20` selecting run 3 re-renders **both** windows to run 3, asserting the **address**, not merely "changed" (RED today: run 0 always) · `AT-B78-21` **the height-derivation arm** — the emitted hex-row count at 160×40 is strictly greater than at 120×30 for the same run (RED today: equal; this is the arm that kills the ±16 constant) · `AT-B78-22` the emitted span always covers the run ± `DISPLAY_CONTEXT_BYTES`, quoting the **constant** (C-39)
  - **Boundary catalog (QC-3):** ☑ **empty** — 0 runs → the existing "no differing runs" text in both windows, unchanged, `TC-B78-23` · ☑ **boundary** — a run at address 0 (the `max(0, start - context)` clamp at `:7026`), `TC-B78-24` · ☑ **boundary** — a run longer than the pane can show; the window renders the pane's worth and does not raise, `TC-B78-25` · ☑ **boundary** — a run whose bytes are absent from one of the two maps (the window renders the blank-gutter form, executed: `'0x00000FF0                    …\|…\|'`), `TC-B78-26` · ☑ **invalid** — selection index outside `_runs` → the existing early return at `:7024`, `TC-B78-27` · ☑ **error** — a re-render triggered while the pane has zero height → no raise, `TC-B78-28`

---

### HLR-124 — no hex row wraps at the supported wide and fallback widths
- **Traceability:** US-78-7 · 🟡 **the regime pair assumes §2.8 D-1 option ①; the statement below is void under option ②**
- **Statement:** When the terminal width is at least the wide-regime breakpoint, `#diff_columns` **shall** render the run list alongside the hex-window column; when it is below the breakpoint, `#diff_columns` **shall** render the hex-window column at the full content width of `#diff_columns` and **shall** present the run list without permanently reserving columns or rows from that width; and in both regimes each hex window's content width **shall** be greater than or equal to the width of the widest row `hexview.render_hex_view` emits.
- **Rationale (informative):** Measured against the emitted row of **79** cells (P-31) and a per-box chrome of **5** (P-32): the shipped three-`1fr` split gives each window **26** cells at 120 and about **42** at 160 — so **every** hex row wraps at **every** supported width, which is worse than the charter's "wraps below ~170" and strengthens the story. The regime pair is measured, not chosen, and it follows from the closed form **`L ≤ C − 89`** (P-32b): a full-width single window reaches **87** at 120 ✅ and **127** at 160 ✅; a 22-cell list beside a window reaches **100** at 160 ✅ but only **60** at 120 ❌ and **72** at 132 ❌, **first fitting at 139**. The charter's 12-cell fallback needs a budget of 12 where 120 offers **3** — it fails at the one width it was proposed for, and at the only width with a diff golden (C2). **80×24 is outside this requirement's guarantee**: even a full-width window reaches only 65 there, and the pane has **zero** content rows in every configuration (P-33), so a wrap guarantee at 80 would be unobservable as well as unachievable.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -k "regime or wrap" -v` + full `tests/test_tui_directionb.py` (C-34) + a C-22 per-cell snapshot census
- **Numeric pass threshold:** at **160×40** and at **120×30**, `#diff_hex_a.size.width >= max(len(line) for line in render_hex_view(...).splitlines())` — today `42 >= 79` **False** and `26 >= 79` **False**; the breakpoint is read from a **named module constant**, and the literal `139` appears **0** times in the test
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** at both widths the operator uses, a byte column lines up down the window instead of folding onto the next line.
  - **Shipped surface:** `App.run_test(size=(160,40))` and `size=(120,30)` → diff screen → `render_comparison` → `app.query_one("#diff_hex_a").size.width`
  - **Deliverable + observation:** the window's **content width** compared against the **emitted** row width, which the test derives by **calling `render_hex_view` itself** at test time. ⚠️ **C-36/C-39:** the test **shall not** hard-code `79`. `79` is a measurement, not a defined constant on disk — a literal `79` in an acceptance is a phantom that will false-fail the day `HEX_WIDTH` or the address format changes. The predicate compares two computed quantities. ⚠️ **C-32:** this is the **geometry** arm and it reads `size.width`; the content arm belongs to HLR-123.
  - **Acceptance test(s):** `AT-B78-23` at 160×40 the window's content width is ≥ the emitted row width (RED today: 42 < 79) · `AT-B78-24` at 120×30, same (RED today: 26 < 79) · `AT-B78-25` at 160×40 the run list is **visible beside** the window; at 120×30 it reserves **0** permanent columns from `#diff_columns`
  - **Boundary catalog (QC-3):** ☑ **boundary** — one column **below** the breakpoint and one at it: the layout flips exactly once, `TC-B78-29` · ☑ **boundary** — a resize **across** the breakpoint after a comparison is already rendered; the layout follows and the windows do not blank, `TC-B78-30` · ☑ **empty** — no comparison rendered: the regime still applies and nothing raises, `TC-B78-31` · ☑ **boundary** — **80×24 is explicitly out of guarantee**; the AT asserts only that the panel renders and raises nothing, `TC-B78-32` · ☑ **invalid** — a terminal 1 column wide, `TC-B78-33` · ☐ **error** — **N/A:** layout selection consumes only the terminal width, already validated by Textual.

---

### HLR-125 — the control rows do not starve the result area
- **Traceability:** US-78-8 · **prerequisite of HLR-123 and HLR-124**
- **Statement:** The A-selection row, the B-selection row and the action row **shall** each occupy one rendered row, and at a terminal of 120×30 with the command-bar row removed the hex windows **shall** render at least one hex row of content.
- **Rationale (informative):** This is the story the charter listed last and the measurement promotes to first. Executed (P-33): `#diff_select_row_a/b` and `#diff_action_row` are **3 rows each** (`styles.tcss:1130-1132`, Textual's default for `Input`/`Button`/`Select`), plus `#diff_status` at 1 — **10 rows of controls** out of an `#ab_diff_panel` that measures **11** at 120×30. `#diff_hex_a` therefore has **0** content rows at 120×30 **and** at 80×24 today. Compaction alone moves 120×30 to `#diff_columns` **3** / `#diff_hex_a` **0**; compaction **plus** the command-bar deletion reaches **6 / 2**. So the second clause is a genuine, measured joint threshold across two stories, and it is the smallest honest one — 2 rows, not a comfortable number.
- **⚠️ C-13 transfer note:** the 1-row target is **not** transferred from another container. It is the residual required to satisfy the second clause at the measured 120×30 budget, and Phase 3 **shall** re-measure the whole `#ab_diff_panel` budget — every sibling — rather than only the three rows, per C-23.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -k "row_height or budget" -v` + full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** `#diff_select_row_a.size.height == 1`, `#diff_select_row_b.size.height == 1`, `#diff_action_row.size.height == 1` (today **3** each, executed); at 120×30 with the bar removed, the count of emitted hex rows visible in `#diff_hex_a` is **≥ 1** (today **0**)
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a comparison at 120×30 actually shows bytes instead of an empty strip below the controls.
  - **Shipped surface:** as HLR-124, reading each row widget's `size.height` and `#diff_hex_a.size.height`
  - **Deliverable + observation:** the four heights, all read in the same run. ⚠️ **C-32:** this is entirely a geometry claim — a content-only oracle over the rows' text is blind to it, which is precisely how a 0-row result area shipped. ⚠️ **C-40:** `height == 1` on the control rows is invariant under a change that also collapses the result area to zero — the second clause is what makes the pair a gate, and it **shall** be asserted in the same test, not in a sibling.
  - **Acceptance test(s):** `AT-B78-26` the three control rows are 1 row each (RED today: 3 each) · `AT-B78-27` **the joint arm** — at 120×30 with the bar removed, `#diff_hex_a` renders ≥ 1 hex row (RED today: 0), asserted in the same run as `AT-B78-26`
  - **Boundary catalog (QC-3):** ☑ **boundary** — 80×24: the requirement's second clause is **not** claimed there (measured 0 rows in every configuration); the AT asserts only that the panel renders and the controls are reachable under scroll, `TC-B78-34` · ☑ **boundary** — a very long external path typed into a selection row does not re-expand it to 3 rows, `TC-B78-35` · ☑ **empty** — no project loaded, so the `Select`s hold only the external sentinel, `TC-B78-36` · ☑ **invalid** — the widest variant label the dropdown can hold, `TC-B78-37` · ☐ **error** — **N/A:** styling change, no new input class.

---

### HLR-126 — the run-list keyboard path is discoverable
- **Traceability:** US-78-9 · **scope reduced by §2.8 D-2**
- **Statement:** When the run list holds focus, the application's help panel **shall** list the run list's own navigation keys, and the run list **shall** carry a visible affordance naming how to move the selection.
- **Rationale (informative):** The three-tier discoverability rule wants a key to be findable without reading source. The run list's own bindings surface in the stock help panel (`action_show_help_panel`, `app.py:5836`, bound at `app.py:1364`) for free once the list is focusable, so the marginal cost of this requirement is the visible affordance alone. **What this requirement deliberately does not do:** add an App-level `show=True` Footer binding (a second C-28 obligation for a key the focused widget already owns), bind `j`/`k`/`n`/`p` (P-42 — three of four are taken and one is `k`, whose Footer hint would become false), or post an open-in-hex message on `Enter` (P-43 — the existing handler renders `current_file`, which is generally neither compared image, so the operator would be shown the wrong bytes with no error; carried as **C-78-d**).
- **Validation:** `test` + `inspection`
- **Executed verification:** `pytest tests/test_tui_diff_screen.py -k "discover" -v` + full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** with the run list focused, the help panel's rendered text names the navigation keys; the run list's rendered text contains the affordance string; **0** new App-level `Binding(..., show=True)` are added (a `git diff` over `app.py:1338-1375` of **0** lines)
- **Priority:** low
- **Acceptance (black-box):**
  - **Observable outcome:** an operator who has never used the diff screen can find out how to walk the runs without reading the source.
  - **Shipped surface:** focus the run list → `pilot.press("question_mark")` → read the help panel's rendered text; and read `#diff_range_list`'s rendered text
  - **Deliverable + observation:** the help panel text and the list's affordance text. ⚠️ **C-40:** "the help panel names the keys" is green on a help panel that lists **every** binding in the app — the arm asserts the keys appear **while the run list is focused** and co-asserts a key the run list does **not** bind is absent from the same focused section.
  - **Acceptance test(s):** `AT-B78-28` the focused run list's keys appear in the help panel, with a negative co-assertion · `AT-B78-29` **the no-regression arm** — `git diff` over the App `BINDINGS` block is **0** lines
  - **Boundary catalog (QC-3):** ☑ **empty** — help panel opened with no comparison rendered: no raise, `TC-B78-38` · ☑ **boundary** — help panel opened, dismissed, re-opened, `TC-B78-39` · ☐ **invalid** / ☐ **error** — **N/A:** read-only surface over existing state.

---

## 4. Low-level requirements (LLR)

> ID format `LLR-<HLR>.<M>`. Every LLR traces to a parent HLR. **Every named symbol carries a `file:line` I re-derived in this session** (line numbers in this repo drift constantly; none is copied from the charter or from a prior batch) or a `NEW — created in Phase 3` flag. Every geometry constant carries a measurement or an `assumed` flag. The **Symbols** field is the C-26 input.

### HLR-118 → LLR-118.x

**LLR-118.1 — the row leaves `compose`**
- **Traceability:** HLR-118
- **Statement:** `CommandBar.compose` **shall not** yield `#command_bar_row` or any of its five children.
- **Symbols:** `CommandBar.compose` `command_bar.py:139`; `Horizontal(id="command_bar_row")` `:140`; `#command_bar_prompt` `:141`, `#cmdbar_project` `:142`, `#cmdbar_a2l` `:143`, `#find_input` `:144-146`, `#cmdbar_goto_input` `:147-149`; `#command_palette` `:150` (**preserved — a sibling of the row, not a child**).
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_commandbar.py -v` + full `tests/test_tui_directionb.py`
- **Numeric pass threshold:** `len(app.query("#command_bar_row")) == 0` on all 10 screens (today 1 on all 10)
- **Acceptance criteria:** `#command_palette` remains a direct child of `CommandBar`; `CommandBar` remains composed at `app.py:1878` (the palette must not move screens).

**LLR-118.2 — the palette command set is invariant**
- **Traceability:** HLR-118
- **Statement:** The palette entry set **shall** remain derived from `S19TuiApp.BINDINGS` and **shall not** change in content as a consequence of the row's removal.
- **Symbols:** `_build_palette_entries` `app.py:5758-5772`; `EXTRA_PALETTE_ENTRIES` (appended at `:5771-5772`); `visible_palette_actions` `command_bar.py:204`; `palette_is_open` **property** `command_bar.py:195-196`.
- **Validation:** `test (integration)` · **Executed verification:** as LLR-118.1 · **Numeric pass threshold:** **37** entries, action list set-equal to the committed pre-change list (executed baseline: 37, including `focus_find`/`focus_goto`)
- **Acceptance criteria:** ⚠️ `palette_is_open` is a **property**. My own draft-time probe called it as `palette_is_open()` and raised `TypeError: 'bool' object is not callable` — recorded in §6.3 F-2. Any AT touching it uses the attribute form.

**LLR-118.3 — the CSS block is removed with the row**
- **Traceability:** HLR-118
- **Statement:** The style rules for the deleted row and its children **shall** be removed from `styles.tcss`, and the `#command_palette` rules **shall not** be.
- **Symbols:** the deletable span is bounded by the `#command_palette` block that follows it — Phase 0 measured `styles.tcss:55-102` with `#command_palette` beginning at `:104`. ⚠️ **`assumed — re-derive the exact span at Phase 3`**: I did not re-execute this range in this session, and a stale span is exactly the class of error this document exists to avoid. The Phase-3 gate **shall** re-derive it by `grep -n '#command_bar\|#cmdbar_\|#find_input\|#command_palette' s19_app/tui/styles.tcss`.
- **Validation:** `inspection` · **Numeric pass threshold:** 0 surviving rules for the five deleted ids; the `#command_palette` rules unchanged

### HLR-119 → LLR-119.x

**LLR-119.1 — routing keys on the active screen, never on widget presence**
- **Traceability:** HLR-119
- **Statement:** `action_focus_find` and `action_focus_goto` **shall** resolve their target from `self._active_screen_key` through a screen-to-input mapping, and **shall not** resolve it by querying which inputs exist in the tree.
- **Symbols:** `action_focus_find` `app.py:5980`, `action_focus_goto` `app.py:5984` (both currently delegate to `CommandBar.focus_find`/`focus_goto`, `command_bar.py:208`/`:212`); `_active_screen_key` set at `app.py:5816`; `SCREEN_CONTAINER_IDS` `app.py:5693-5704` (**10** entries); target inputs `#search_input` `app.py:1993` / `#goto_input` `:1995`, `#alt_search_input` `:5152` / `#alt_goto_input` `:5155`, `#mac_search_input` `:5230` / `#mac_goto_input` `:5233`. The screen→input map is **NEW — created in Phase 3**.
- **Rationale (informative):** `action_show_screen` (`app.py:5775`) swaps the `hidden` class across `SCREEN_CONTAINER_IDS.values()` (`:5818`); nothing unmounts, so all eight inputs are `query_one`-resolvable on every screen. A presence-based implementation would be **green while wrong** — the exact defect Phase-0 P-10 recorded.
- **Validation:** `test (e2e)` · **Executed verification:** `pytest tests/test_tui_commandbar.py -k "focus" -v` · **Numeric pass threshold:** 3 screens route to locals; **7** route to the notice; **0** exceptions
- **Acceptance criteria:** the map's key set is asserted **set-equal to `SCREEN_CONTAINER_IDS.keys()`** so a screen added later cannot fall through silently — the set comes from the RULE, not from the implementation's own list (C-40 limb 2).

**LLR-119.2 — the no-local-input notice**
- **Traceability:** HLR-119
- **Statement:** When the active screen has no entry in the screen-to-input map, the action **shall** call `set_status` exactly once and **shall** return without raising.
- **Symbols:** `set_status` writes `#status_text` at `app.py:11643-11644`; `#status_text` constructed `markup=False` at `app.py:1916`.
- **Validation:** `test (e2e)` · **Numeric pass threshold:** exactly **1** `set_status` call per press on each of the 7 screens; `#status_text` differs from its prior value
- **Acceptance criteria:** ⚠️ **C-40:** "no exception raised" is green on an action that does nothing at all. The gate arm is the **status-text delta**; the no-raise arm is a **regression pin** and is labelled as such.

**LLR-119.3 — `Escape` releases a focused find/goto input**
- **Traceability:** HLR-119
- **Statement:** When a find or go-to input holds focus, `Escape` **shall** move focus off that input.
- **Symbols:** the six local inputs listed in LLR-119.1. The `Escape` handler is **NEW — created in Phase 3**; `grep -n 'escape' s19_app/tui/app.py` is the Phase-3 pre-check.
- **Rationale (informative):** executed on all 10 screens, `escape` leaves focus on `find_input` (P-40) — a Textual `Input` keeps focus through `escape`. This clause is **net-new work**, not a preserved control, and it must not be written as one.
- **Validation:** `test (e2e)` · **Numeric pass threshold:** `app.focused is not <the input>` after `Escape` (today it **is**, all 10)
- **Acceptance criteria:** **`pilot.press("escape")` only.** A test that calls `.blur()` does not discharge this LLR. And the blur guard of LLR-119.4 applies to the setup, not to the assertion.

**LLR-119.4 — every focus AT asserts its own precondition**
- **Traceability:** HLR-119
- **Statement:** Each acceptance test of HLR-119 **shall** call `app.set_focus(None)` and **shall** assert `app.focused is None` before dispatching a single-letter key.
- **Rationale (informative):** an `Input` swallows a bare `g` as text rather than dispatching it as a binding, so a probe that blurs with `escape` reports a plausible and false result. Phase-0 §7 records that exact self-caught defect; my P-40 run is the corrected form and asserts the blur on all 10 screens.
- **Validation:** `inspection` · **Numeric pass threshold:** every HLR-119 AT contains the assertion

### HLR-120 → LLR-120.x

**LLR-120.1 — one update entry point drives both surfaces**
- **Traceability:** HLR-120
- **Statement:** `update_project_labels` **shall** write the project-and-variant string and the A2L filename to `#workspace_status_bar` and **shall** trigger the `#loaded_panel` refresh, replacing its current single write to the command bar.
- **Symbols:** `update_project_labels` `app.py:11290`; the plain-form default `project_name = self.current_project or "(none)"` `app.py:11328`; the multi-variant guard `if … len(variant_set.variants) > 1 …` `app.py:11329-11333`; `_variant_display_options` call `:11338`; the suffixed composition `:11345-11348`; the A2L name `:11350`; the call to be replaced `self.query_one(CommandBar).set_context_labels(project_name, a2l_name)` **`app.py:11351`** (`set_context_labels` defined `command_bar.py:216` — **exactly one call site**); `_refresh_patch_variant_select` `:11352`; `_refresh_loaded_panel` `app.py:8649`; `LoadedArtifactsPanel.render_slots` `screens_directionb.py:1848`; `_slot_state` `screens_directionb.py:1891`; `#workspace_status_bar` composed `app.py:1930`.
- **⚠️ Stubbed consumers (P-38b):** `tests/test_tui_app.py:70`, `:233`, `:1338` replace `update_project_labels` with a no-op or a recorder. They will stay green through this change **without exercising it** — their green is not evidence for this LLR and must not be counted as such at the gate.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_commandbar.py -k context -v` · **Numeric pass threshold:** both surfaces carry the new variant after one call (today: neither carries the project at all)
- **Acceptance criteria:** ⚠️ **the operator's two-surface ruling creates two update paths.** A single test observing one surface is green on an implementation that updates only that one — `AT-B78-10` is the arm that closes this, and it must read **both** surfaces in **one** run after **one** variant switch.

**LLR-120.2 — the project row in the Loaded panel; the A2L slot is untouched**
- **Traceability:** HLR-120
- **Statement:** `LoadedArtifactsPanel` **shall** render a row naming the active project and variant, and **shall not** alter the existing three artifact slots.
- **Symbols:** `LoadedArtifactsPanel` `screens_directionb.py:1738`; `compose` yields `#loaded_title` and `#loaded_slots`; `render_slots` `:1848`; `_SLOTS` iterated at `:1885`; re-mounted children carry **classes, never ids** (`:1854-1855`) — the `DuplicateIds` discipline the new row must follow.
- **Rationale (informative):** executed (P-35), the A2L slot already renders `'A2L | ECU_CAL.a2l  0 tags'`. **The A2L half of the charter's S-3 is already shipped**; the new content is the project row only, and an acceptance asserting the A2L filename in this panel would be vacuous.
- **Validation:** `test (integration)` · **Numeric pass threshold:** `'PROJ_X'` present (today absent, executed); the three slot rows' text is **unchanged** before vs after (set equality)
- **Acceptance criteria:** the new row is added to `render_slots`' remount set with **classes only**; C-12 applies — no `_nodes` / `_context` member on any new widget.

**LLR-120.3 — the status-bar addition spends no row**
- **Traceability:** HLR-120
- **Statement:** The addition to `#workspace_status_bar` **shall not** increase its rendered height.
- **Symbols:** `#workspace_status_bar` `app.py:1930`; its current children `#status_text` `:1916`, `#progress_bar`, `#log_line_1..4`.
- **Geometry:** measured **116×7 on all 10 screens @120×30** (P-36). An eighth row would cost 1 row app-wide against Lane 1's 3-row reclaim, and the diff pane has **2** content rows at 120×30 to begin with (P-33). **The mechanism is deliberately unspecified** — sharing a row with `#status_text` is the obvious candidate; Phase 3 owns it. `assumed — re-measure the whole status-bar budget at Phase 3` per C-23.
- **Validation:** `test (integration)` · **Numeric pass threshold:** `#workspace_status_bar.size.height == 7` after the change, at 120×30, on all 10 screens

**LLR-120.5 — both display forms are preserved on both surfaces**
- **Traceability:** HLR-120
- **Statement:** The project string presented on each context surface **shall** be the plain project name when the active project holds at most one variant, and the `project:variant (index/total)` form when it holds more than one.
- **Symbols:** the branch that produces the two forms — `app.py:11328` (plain) and `app.py:11329-11348` (suffixed, gated on `len(variant_set.variants) > 1` at `:11332`); `_variant_display_options` `:11338`; the live pin `tests/test_tui_variants.py:259` `test_single_s19_project_label_plain` — *"A single-S19 project shows the plain project name — no `(1/1)`"* (`:260`), attributed to **LLR-005.3**; the helpers that read it, `tests/test_tui_variants.py:76-78` and `tests/test_tui_patch_variant.py:82-85`.
- **Rationale (informative):** the re-home is not just of a **name** but of a **form**. `#cmdbar_project` is the observable a live acceptance uses to assert the single-variant back-compat form; an implementation that emits one uniform string satisfies "the project is named" and still breaks LLR-005.3. This LLR exists because my own first draft of `TC-B78-11` asserted a `(1/1)` counter that the shipped code does not produce and a shipped test forbids — recorded in §6.3 F-4 rather than quietly fixed.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_variants.py tests/test_tui_patch_variant.py -v` · **Numeric pass threshold:** a 1-variant project's rendered string contains **no** `(` on either surface; a 2-variant project's contains `(1/2)` on **both**
- **Acceptance criteria:** the two forms are asserted on **both** surfaces, i.e. **four** observations. Asserting the form on one surface only is green on an implementation that flattens the other.

**LLR-120.4 — the new label is markup-inert at construction**
- **Traceability:** HLR-120
- **Statement:** Any widget receiving the project or A2L string **shall** be constructed with `markup=False`.
- **Symbols:** precedent `Label("Ready.", id="status_text", markup=False)` `app.py:1916`, with the rationale in the comment at `app.py:1910-1915`.
- **Rationale (informative):** the A2L name is `current_a2l_path.name` and the project name is a directory name — both file-derived. `markup=False` **at construction** persists across `.update()`; pre-escaping does not, and the project's own comment says so.
- **Validation:** `test (integration)` + `inspection` · **Numeric pass threshold:** a filename `[red]evil[/].a2l` renders **verbatim** and raises no `MarkupError` (`TC-B78-12`)

### HLR-121 → LLR-121.x

**LLR-121.1 — the message classes and their adapters are deleted**
- **Traceability:** HLR-121
- **Statement:** `CommandBar.Find`, `CommandBar.Goto`, `on_command_bar_find`, `on_command_bar_goto`, `focus_find`, `focus_goto` and `set_context_labels` **shall** be absent from `s19_app/`.
- **Symbols:** `class Find(Message)` `command_bar.py:111`, `class Goto(Message)` `:118`; `focus_find` `:208`, `focus_goto` `:212`, `set_context_labels` `:216`; `on_command_bar_find` `app.py:5995`, `on_command_bar_goto` `app.py:6025`. **`class PaletteAction(Message)` `command_bar.py:125` is PRESERVED** — it is the palette's dispatch message, not part of the find/goto surface.
- **Validation:** `inspection` · **Numeric pass threshold:** `grep -c` → 0 for each of the seven; **1** for `PaletteAction`
- **Acceptance criteria:** ⚠️ **C-42 mechanic 5** — the census is an **AST** census over `s19_app/`, not a line regex.

**LLR-121.2 — the surviving search handlers are byte-identical**
- **Traceability:** HLR-121
- **Statement:** `_handle_search`, `_handle_goto`, `_handle_search_alt`, `_handle_goto_alt`, `_handle_search_mac` and `_handle_goto_mac` **shall** be unchanged.
- **Symbols:** `_handle_search` `app.py:11448`, `_handle_goto` `:11518`, `_handle_search_alt` `:11538`, `_handle_goto_alt` `:11568`, `_handle_search_mac` `:11589`, `_handle_goto_mac` `:11618`; their button dispatch `on_button_pressed` `app.py:11354-11371`.
- **Validation:** `inspection` + `test (e2e)` · **Executed verification:** `git diff origin/main -- s19_app/tui/app.py` restricted to the six bodies · **Numeric pass threshold:** **0** diff lines
- **Acceptance criteria:** the behavioural control (`AT-B78-12`) is captured from the **pre-change** tree, in its own commit, before any deletion. A control captured after the change proves nothing.

**LLR-121.3 — the registry's node lists are reconciled**
- **Traceability:** HLR-121
- **Statement:** Every `LIVE` `AT-TC-REGISTRY.jsonl` entry naming a deleted test node **shall** have that node removed from its `nodes` list.
- **Symbols:** `TC-007`, `TC-008`, `TC-009`, `TC-039` — the **4** rows matching `test_tui_commandbar` (executed count). `TC-008` alone names 5 `tests/test_tui_commandbar.py::…` nodes. Guard: `tests/test_id_registry.py:223` (`g2_live_entries_have_nodes`), registered at `:361`, asserted at `:388-390`.
- **Rationale (informative):** G2 is *"every `LIVE` entry's `nodes` all exist"*. Deleting the tests without the reconciliation turns it red, and `docs/engineering-rules.md:52-53` says the fix is the cause, not the threshold.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_id_registry.py -v` · **Numeric pass threshold:** G1–G7 green
- **Acceptance criteria:** ⚠️ **`_meta.next_free` and `high_water` are NOT touched** — this batch mints no global id (C14). Only `nodes` arrays shrink. If a row would be left with an **empty** `nodes` list, its `status` is changed per the spec's status semantics rather than the row being deleted; **`assumed — confirm the correct status transition against `.dev-flow/AT-TC-REGISTRY-SPEC.md` §3.3 at Phase 3`**.

**LLR-121.4 — the `#cmdbar_project` test consumers are re-pointed before the label dies**
- **Traceability:** HLR-121 (sequencing constraint on HLR-118)
- **Statement:** The test helpers reading `#cmdbar_project` **shall** be re-pointed at a surviving context surface in an increment that lands **before** the increment deleting the label.
- **Symbols — the executed census (P-38), all three sites:** `tests/test_tui_patch_variant.py:85` `return str(bar.query_one("#cmdbar_project").content)` · `tests/test_tui_variants.py:78` (identical helper) · `tests/test_tui_directionb.py:897` `project = str(bar.query_one("#cmdbar_project").content)`.
- **Rationale (informative):** these helpers are the **observable** those suites use to assert variant switching — they are not incidental references. Phase-0 §5 named three Lane-1 test files and these two are not among them.
- **Validation:** `inspection` + `test` · **Numeric pass threshold:** `grep -rn 'cmdbar_project' tests/` → **0** after the sequence completes (today **3**)

### HLR-122 → LLR-122.x

**LLR-122.1 — the run list becomes a selectable widget**
- **Traceability:** HLR-122
- **Statement:** `#diff_range_list` **shall** be a widget that maintains a selection index over one entry per displayed run, replacing the `Static` that renders the runs as text.
- **Symbols:** `Static("Runs", id="diff_range_list", markup=True)` `screens_directionb.py:6766`; `_render_run_list` `:6958`, its terminal write `self.query_one("#diff_range_list", Static).update("\n".join(lines))` `:7001`; the per-run line composition `:7062-7069`-region (the `_KIND_MARKUP` / `_KIND_LABEL` colouring loop); the caps notice appended when `len(self._runs) < total_runs`. CSS `styles.tcss:1481-1490`.
- **⚠️ C-38 — this is a widget-type swap, i.e. a test-API change.** Executed reverse-grep: `diff_range_list` **8 hits / 3 files** (`tests/test_tui_diff_screen.py`, `tests/test_tui_diff_compare_realpath.py`, `tests/test_tui_directionb.py`); `render_comparison` **5 hits / 3 files**; `AbDiffPanel` **25 hits / 5 files** (adds `tests/test_tui_patch_big.py:714`, `tests/test_tui_patch_json.py:791-792` — the latter pins the panel's kind colours). Every `query_one("#diff_range_list", Static)` **shall** be re-pointed or widened **before** the change runs; a green suite can hide a narrowed query that now matches nothing.
- **⚠️ C-17:** the list currently renders with `markup=True` and escapes the artifact summaries with `rich.markup.escape` at `:6986`. The replacement **shall** preserve that escape or render `markup=False`; the summaries are service-derived text.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_diff_screen.py -v` + full `tests/test_tui_directionb.py` · **Numeric pass threshold:** 5 runs → 5 selectable entries (today 0)

**LLR-122.2 — navigation binds no App-level key**
- **Traceability:** HLR-122
- **Statement:** The run list's bindings **shall not** include `j`, `k`, `p` or `o`, and the batch **shall** carry a regression test that `k` still opens the legend while the run list has focus.
- **Symbols:** `Binding("o","open_workarea",…,show=False)` `app.py:1352`; `Binding("p","load_project",…,show=False)` `:1354`; `Binding("j","dump_a2l_json",…,show=False)` `:1356`; `Binding("k","show_legend","Legend",show=True)` `:1359`. `n` is **unbound** app-wide (executed).
- **Rationale (informative):** a focused widget's binding shadows the App's on textual 8.2.8 (batch-77 P-23, executed there). `k` is `show=True`, so the Footer advertises it on every screen — a shadowing binding would make a hint false exactly where it is displayed. This is batch-77's B-2, and this LLR is its pre-emption.
- **⚠️ P-47, honest UNDECIDABLE:** whether the stock `ListView`'s `up`/`down`/`enter` interact correctly with this app's four `priority=True` bindings (`app.py:1339-1342`) is **not executed at Phase 1**. `assumed — verify in target framework at Phase 3`.
- **Validation:** `test (e2e)` + `inspection` · **Numeric pass threshold:** the literals `"j"`, `"k"`, `"p"`, `"o"` appear **0** times in the run list's `BINDINGS`; `AT-B78-19` green
- **Acceptance criteria:** `pilot.press` only, with the LLR-119.4 blur guard.

**LLR-122.3 — the display caps and the notice survive**
- **Traceability:** HLR-122
- **Statement:** The selectable list **shall** present exactly the entries `_apply_display_caps` returns and **shall** retain the "showing N of M" notice, and the persisted report **shall** remain complete.
- **Symbols:** `_apply_display_caps` `screens_directionb.py:6925`; `DISPLAY_MAX_RUNS = 128` `:6623`; `DISPLAY_MAX_TOTAL_BYTES = 2_097_152` `:6624`; the notice branch `if len(self._runs) < total_runs:` `:6994`; existing coverage `tests/test_tui_diff_screen.py` (`DISPLAY_MAX_RUNS` **4 hits**).
- **Validation:** `test (integration)` · **Numeric pass threshold:** entry count `== DISPLAY_MAX_RUNS` on an over-cap comparison
- **Acceptance criteria:** the AT **quotes `DISPLAY_MAX_RUNS`, never the literal `128`** (C-39).

### HLR-123 → LLR-123.x

**LLR-123.1 — selection drives the window render**
- **Traceability:** HLR-123
- **Statement:** A change of run-list selection **shall** invoke the window renderer with the selected index.
- **Symbols:** `_render_run_windows` `screens_directionb.py:7003`, its **single** call site `self._render_run_windows(0)` `:6921` inside `render_comparison` (`:6879`); the phantom handler its docstring cites (`on_data_table_row_selected`, `:7019`) has **0** definitions in the module.
- **Validation:** `test (e2e)` · **Numeric pass threshold:** after selecting run 3, both window headers name run **3** (today always **0**)

**LLR-123.2 — the row count derives from the rendered pane height**
- **Traceability:** HLR-123
- **Statement:** The number of `row_bases` passed to `render_hex_view` **shall** be computed from the window widget's rendered height at render time, subject to a lower bound of the run's own bytes plus `DISPLAY_CONTEXT_BYTES` on each side.
- **Symbols:** `DISPLAY_CONTEXT_BYTES = 16` `:6627`, used at `:7026` (`low = max(0, start - self.DISPLAY_CONTEXT_BYTES)`) and `:7028` (`high = end + self.DISPLAY_CONTEXT_BYTES`); `row_bases` built `:7029`; `render_hex_view` / `HEX_WIDTH` / `MAX_HEX_ROWS` imported at `:7022` from `hexview` (`HEX_WIDTH = 16` `hexview.py:21`, `MAX_HEX_ROWS = 512` `:23`, `render_hex_view` `:330`); the two window writes `:7033-7034`.
- **Geometry:** measured `#diff_hex_a` content rows (P-33) — **160×40 → 12** and **120×30 → 2** after HLR-118 + HLR-125; **80×24 → 0** in every configuration. The centring arithmetic (which rows to drop when the run exceeds the pane) is **`assumed — measure in Phase 3`**; C-23 requires a pilot measurement of the whole `#ab_diff_panel` budget, not just this widget.
- **Validation:** `test (integration)` · **Numeric pass threshold:** emitted row count at 160×40 **>** at 120×30 for the same run (today equal: **6** and **6**, executed)
- **Acceptance criteria:** ⚠️ **the floor is a floor, not the value.** An implementation that keeps `±16` and merely *also* reads the height passes a "≥ floor" test. The gate is the **strict inequality between two heights**, which `±16` cannot satisfy.

**LLR-123.3 — the header names index, range and kind**
- **Traceability:** HLR-123
- **Statement:** Each window **shall** carry a header naming the selected run's index, its address range and its classification.
- **Symbols:** current header `header = f"Run #{run_index} 0x{start:08X}-0x{end:08X}"` `:7032` — it names index and range but **not** kind; `_KIND_LABEL` maps `changed` / `only_a` / `only_b` to `changed` / `only A` / `only B` (defined immediately after `_KIND_MARKUP` in the `AbDiffPanel` class body, `screens_directionb.py:6631`-region — **`assumed — re-derive the exact line at Phase 3`**).
- **Validation:** `test (integration)` · **Numeric pass threshold:** the header contains the kind label for a run of each of the three kinds
- **Acceptance criteria:** ⚠️ **C-17:** `#diff_hex_a` / `#diff_hex_b` are constructed `markup=False` (`:6767-6768`) and **shall** remain so. The header composes only integers and constant labels — no file-derived text — so B3 holds by construction.

### HLR-124 → LLR-124.x

**LLR-124.1 — a named breakpoint, not a literal**
- **Traceability:** HLR-124
- **Statement:** The wide/fallback selection **shall** read a named module-level constant, and the layout **shall** be applied by a CSS class toggled on resize.
- **Symbols:** the precedent is `_apply_width_regime` `app.py:6205`, called from `on_resize` `app.py:6239`, toggling `width-narrow` on `#workspace_shell` and `#workspace_body` `app.py:6233-6238`. Its threshold is a **bare literal**: `narrow = width < 120` `app.py:6232`. The new constant and the new class are **NEW — created in Phase 3**.
- **Measured value:** the recommended breakpoint is **139** — the first width at which a **22-cell (content)** run list beside one window reaches the emitted row width. Derived from `L ≤ C − 89` (`L = 22` → `C ≥ 111` → terminal ≥ 139) and confirmed to the column by execution: `138 → 78 ✗`, `139 → 79 ✅`. ⚠️ **Units matter and cost this document a correction:** Textual's CSS `width: N` sets the **border-box**, so a 22-cell content list is authored as `width: 26`. A CSS `width: 22` list is 18 cells and would move the breakpoint to 136. **The constant is defined in content units** and Phase 3 asserts against `size.width`, never against the CSS declaration.
- **Validation:** `test (integration)` + `inspection` · **Numeric pass threshold:** the literals `139` and `26` appear **0** times in the acceptance tests (C-39: an AT quotes the constant, never its value — and here there are **two** values to avoid, the breakpoint and the CSS box width)
- **Acceptance criteria:** ⚠️ **do not overload `width-narrow`.** It is toggled at 120 and read by workspace, map, patch and rail rules (`styles.tcss:243, 247, 322, 326, 332, 762, 875, 953, 979, 1828-1829`). Reusing it for a 136 breakpoint would silently change all of those. The new regime owns its own class.

**LLR-124.2 — the wide layout**
- **Traceability:** HLR-124
- **Statement:** At or above the breakpoint, `#diff_columns` **shall** allocate a fixed-width run-list column and give the remainder to a single window column holding both hex windows.
- **Geometry:** measured at 160 (P-32b): a 22-cell list leaves the window **100** content cells ≥ **79** ✅. At 132 the whole budget is `L ≤ 15`, so a 22-cell list leaves **72** ✗ — which is why the breakpoint is 139 and why the charter's 132 capture is on the **fallback** side of its own recommended line. The general bound the layout must satisfy is **`L + 5 + 79 + 5 ≤ C`**.
- **Symbols:** `#diff_columns` `screens_directionb.py:6769`, CSS `styles.tcss:1152-1155`; `#diff_range_list, #diff_hex_a, #diff_hex_b { width: 1fr; height: 100%; border: round $rule; padding: 1; margin-right: 1; }` `styles.tcss:1481-1490` — the three-way `1fr` split that must go.
- **Validation:** `test (integration)` · **Numeric pass threshold:** at 160×40, `#diff_hex_a.size.width >= len(widest emitted row)` (today `42 >= 79` **False**)

**LLR-124.3 — the fallback layout**
- **Traceability:** HLR-124
- **Statement:** Below the breakpoint, the hex-window column **shall** occupy the full content width of `#diff_columns` and the run list **shall** be presented without permanently reserving columns or rows from it.
- **Geometry:** measured at 120, where `C = 92` and the side-by-side budget is therefore **`L ≤ 3`** (P-32b): a single full-width window reaches **87** ≥ **79** ✅; a 22-cell list beside it leaves **60** ✗ and a 12-cell list **74** ✗. **No usable list width fits beside the window at 120** — this is arithmetic, not a preference. The vertical budget at 120×30 is **2** content rows (P-33), which is why the list must also cost **zero permanent rows** — a stacked list would spend the entire remaining budget.
- **⚠️ Mechanism:** an overlay is the recommended form; its dismissal path is **`assumed — verify in target framework at Phase 3`**. §2.8 D-1 option ② (always-overlay, no breakpoint) is the pre-committed fallback if the overlay proves costlier than a CSS class plus one binding.
- **Validation:** `test (integration)` · **Numeric pass threshold:** at 120×30, `#diff_hex_a.size.width >= len(widest emitted row)` (today `26 >= 79` **False**); the run list contributes **0** to `#diff_columns`' permanently allocated width

**LLR-124.4 — 80×24 is out of guarantee, and says so**
- **Traceability:** HLR-124
- **Statement:** At terminal widths below the fallback layout's own fit width, the panel **shall** render and **shall not** raise, and the unwrapped-row guarantee **shall not** be claimed.
- **Geometry:** measured — a full-width window at 80 reaches **65** cells against a 79-cell row (✗), and `#diff_hex_a` has **0** content rows there in **every** configuration tested (P-33). Per C-29 the acceptance is relaxed at draft time rather than shipping a physically impossible AT.
- **Validation:** `test (integration)` · **Numeric pass threshold:** at 80×24 the panel mounts and no exception is raised (`TC-B78-32`)
- **Acceptance criteria:** this is explicitly a **regression pin**, not a gate, and is labelled as such (C-40 limb 1).

### HLR-125 → LLR-125.x

**LLR-125.1 — the three control rows compact to one line**
- **Traceability:** HLR-125
- **Statement:** `#diff_select_row_a`, `#diff_select_row_b` and `#diff_action_row` **shall** each render at a height of one row.
- **Symbols:** composed at `screens_directionb.py:6739-6759` (`#diff_select_row_a`, `#diff_select_row_b`, `#diff_action_row`); CSS `styles.tcss:1130-1132`; `#diff_status` `styles.tcss:1144`; `#ab_diff_panel { width: 100%; height: 1fr; padding: 1 2; }` `styles.tcss:923-927`. Children: `Select` `#diff_select_a`/`#diff_select_b`, `OsClipboardInput` `#diff_path_a`/`#diff_path_b`/`#diff_report_dest`, `Button` `#diff_compare_button`/`#diff_report_button`.
- **Geometry:** measured **3 rows each** at every regime; `#ab_diff_panel` is **5** rows at 80×24, **11** at 120×30, **25** at 132×44 (executed).
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_diff_screen.py -v` + full `tests/test_tui_directionb.py` · **Numeric pass threshold:** each `size.height == 1` (today **3**)
- **Acceptance criteria:** **Compare and Report handlers are unchanged** — `on_button_pressed` routing and `CompareRequested` / `ReportRequested` are untouched. `AbDiffPanel` has **25** references across **5** test files (executed); the C-26 sweep runs over all five before this lands.

**LLR-125.2 — the joint vertical threshold**
- **Traceability:** HLR-125
- **Statement:** At 120×30 with `#command_bar_row` removed, `#diff_hex_a` **shall** render at least one hex row of content.
- **Geometry:** the executed ladder — `#diff_columns` height / `#diff_hex_a` height at 120×30: shipped **1/0**, compaction alone **3/0**, compaction **and** bar removal **6/2**. This threshold is the smallest honest one the measurement supports; **2 rows is what the budget yields**, and the requirement claims 1.
- **Validation:** `test (integration)` · **Numeric pass threshold:** ≥ **1** emitted hex row visible at 120×30 (today **0**)
- **Acceptance criteria:** ⚠️ **C-40:** asserted in the **same test** as LLR-125.1's heights. Separated, the height assertion is invariant under an implementation that compacts the rows and still leaves the result area at zero.

### HLR-126 → LLR-126.x

**LLR-126.1 — the help panel and the visible affordance**
- **Traceability:** HLR-126
- **Statement:** The run list **shall** carry a visible affordance naming its navigation keys, and the batch **shall not** add an App-level `Binding` with `show=True`.
- **Symbols:** `action_show_help_panel` `app.py:5836`, bound `Binding("question_mark","show_help_panel","Help",show=True)` `app.py:1364`; the App `BINDINGS` block `app.py:1338-1375`.
- **Rationale (informative):** a new `show=True` App binding triggers a C-28 shared-chrome census over every snapshot cell that renders the Footer. The batch already drifts all 29 (P-41), so the census is paid — but adding a *second* obligation for a key the focused widget already owns buys nothing.
- **Validation:** `test (e2e)` + `inspection` · **Numeric pass threshold:** `git diff origin/main -- s19_app/tui/app.py` restricted to `:1338-1375` → **0** lines

---

## 5. Validation strategy

### 5.1 Methods

**Layer A (white-box, `TC-B78-nn`):** `test (unit)` / `test (integration)` / `test (e2e)` / `inspection` over the HLR/LLR mechanism.
**Layer B (black-box, `AT-B78-nn`):** Textual Pilot e2e — `App.run_test(size=…)` → `action_show_screen(k)` → drive the shipped surface → query the shipped widget tree. **Never** `_render_run_windows` or `_build_palette_entries` called directly (C-35). Regimes **80×24 / 120×30 / 160×40** (C1) — the project's snapshot matrix, **not** the charter's 132×44.

**Standing observation rules for this batch:**
1. **Read the layer that holds the fact** (C-32/C-37). Content claims (HLR-123's row count, HLR-120's label text) → the widget's rendered text. Geometry claims (HLR-124's wrap, HLR-125's heights) → `size.width` / `size.height`. **Neither AT may borrow the other's layer**, and the split is stated per-HLR rather than assumed.
2. **Every absence assertion carries a presence co-assertion** (C-40). There are five: `AT-B78-01`, `AT-B78-13`, `AT-B78-19`, `AT-B78-28`, and the notice half of `AT-B78-05`.
3. **Every threshold quotes its constant, not its value** (C-39): `DISPLAY_MAX_RUNS`, `DISPLAY_MAX_TOTAL_BYTES`, `DISPLAY_CONTEXT_BYTES`, `SCREEN_CONTAINER_IDS`, the new wide-regime constant. **The emitted hex-row width is derived by calling `render_hex_view` at test time** — `79` is a measurement, not a constant on disk, and a literal `79` would be a C-36 phantom.
4. **Every focus AT asserts its own blur precondition** (LLR-119.4).
5. **C-34:** every increment touching `screens_directionb.py`, `app.py`'s compose/render path, `command_bar.py` or `styles.tcss` runs the **full** `tests/test_tui_directionb.py` at its gate, not a `-k` subset.
6. **`tui-ci` form:** PRs run `-m "not slow"`; the **full** suite runs before merge. Every ledger figure states which form produced it. The baseline in §7 is **LEAN** (`38 passed in 36.26s` over the four touched files).

### 5.2 Dual-traceability

**Behavioral chain (black-box) — every RED-today verdict below is from a command I executed this session:**

| US | Observable outcome | Shipped surface | AT | RED today? |
|---|---|---|---|---|
| US-78-1 | no bar row anywhere; Ctrl+K unchanged | widget tree ×10 · `palette_is_open` | `AT-B78-01…03` | ✅ row present 10/10 |
| US-78-2 | `/`·`g` act on the visible pane; notice elsewhere; `Esc` releases | `pilot.press` ×10 | `AT-B78-04…07` | ✅ bar inputs 10/10; `esc → find_input` 10/10 |
| US-78-3 | project + A2L readable on every screen, in both display forms | `#workspace_status_bar` · `#loaded_panel` | `AT-B78-08…11`, `AT-B78-30` | ✅ project absent 10/10 |
| US-78-4 | local search unchanged; dead surface gone | 3 search flows · AST census | `AT-B78-12…14` | ✅ 7 symbols present |
| US-78-5 | every run reachable by key and mouse | run list selection index | `AT-B78-15…19` | ✅ 0 selectable entries |
| US-78-6 | windows follow selection; taller pane shows more | window rendered text | `AT-B78-20…22` | ✅ always run 0; **6 rows at every height** |
| US-78-7 | no wrapped hex row at 160 or 120 | `#diff_hex_a.size.width` | `AT-B78-23…25` | ✅ `42 < 79` and `26 < 79` |
| US-78-8 | a comparison at 120×30 shows bytes | four `size.height` values | `AT-B78-26…27` | ✅ rows 3/3/3; **hex_a height 0** |
| US-78-9 | the keyboard path is findable | help panel text · `git diff` | `AT-B78-28…29` | ✅ list not focusable |

**Functional chain (white-box):** HLR-118 → LLR-118.1…3 → `TC-B78-01…03` · HLR-119 → LLR-119.1…4 → `TC-B78-04…08` · HLR-120 → LLR-120.1…5 → `TC-B78-09…13` · HLR-121 → LLR-121.1…4 → `TC-B78-14…16` · HLR-122 → LLR-122.1…3 → `TC-B78-17…22` · HLR-123 → LLR-123.1…3 → `TC-B78-23…28` · HLR-124 → LLR-124.1…4 → `TC-B78-29…33` · HLR-125 → LLR-125.1…2 → `TC-B78-34…37` · HLR-126 → LLR-126.1 → `TC-B78-38…39`.

**Both chains exist for all nine stories. ✅**

### 5.3 Batch acceptance criteria
- 100 % of LLRs covered by ≥1 TC with a pass result.
- Every US has ≥1 passing AT observing its outcome through the shipped surface, with boundary + negative evidence.
- **Every AT demonstrated RED on the pre-change tree** — the column above is executed for all nine.
- 0 blocker findings at the merge gate; frozen-engine diff **= 0** (source **and** `_ENGINE_TEST_FILES`, C-27); `_PRE_BATCH_BINDINGS` unchanged (re-derived: 14 tuples, no `slash`, no `g`).
- Full suite green in the **FULL** form before merge.
- `tests/test_id_registry.py` G1–G7 green after LLR-121.3.

### 5.4 AT/TC sizing (batch-scoped — no registry allocation)
**30 `AT-B78-nn` + 39 `TC-B78-nn` = 69 batch-scoped ids.** Per `PLAN.md` D-7 and `docs/engineering-rules.md:48` these are outside `AT-TC-REGISTRY.jsonl`'s authority by spec §2.3 (letter-initial bodies) and **cannot collide by construction**. No reservation PR. `_meta.next_free` (`AT-282` / `TC-613`) is **not** advanced.

---

## 6. Appendices

### 6.1 Extended glossary — see §1.3.

### 6.2 Relevant design decisions
- **D-3 (Phase 0, operator):** Lane 1 + Lane 2 only. **Upheld**; Lane-3 carries collected in §6.4.
- **D-7 (Phase 0, autonomous):** batch-scoped ids. **Upheld** and sized in §5.4.
- **NEW D-9 (architect, autonomous):** the batch claims **`R-TUI-104`** and **`HLR-118`/`LLR-118`**, both derived from a union-corpus grep with `__pycache__` excluded (§3 preamble). `R-TUI-111`/`112` are dangling prose with **0** live citations and are not treated as spending the space — following batch-77's own precedent.
- **NEW D-10 (architect, autonomous):** **US-78-8 is promoted to a prerequisite** of US-78-6 and US-78-7. Basis: the measured vertical budget (P-33). This inverts the charter's ordering and is the single largest change this lane makes to the plan.
- **NEW D-11 (architect, autonomous):** **`Enter → open-in-hex` is ruled OUT** of US-78-9 (P-43, §2.8 D-2), carried as C-78-d. The charter marks S-9 optional and forbids silent absorption; this is the explicit ruling it requires.
- **NEW D-12 (architect, autonomous):** **US-78-3's Loaded-panel clause is re-scoped to the project/variant string only** (P-35). The A2L half is already shipped and an acceptance for it would be vacuous.

### 6.3 Self-caught defects at draft time (recorded, not hidden)

| # | Defect | Consequence |
|---|---|---|
| **F-1** | My first geometry probe measured the hex row with **`render_hex_view_text`** — the same producer §9 used — and reported **81**. The A2B panel calls **`render_hex_view`** (**79**). I caught it only because I ran the panel's *own* rendered widget text as a second arm and got `[38, 79, 79, …]`, which disagreed with the standalone figure. **Had I written the S-7 thresholds against 81, every one would have been 2 cells conservative and the `136` breakpoint would have been wrong.** Same family as *assert the emitted encoding*: the producer's identity is part of the measurement. |
| **F-2** | I called `CommandBar.palette_is_open()` as a method; it is a **property** (`command_bar.py:195-196`) and the probe raised `TypeError: 'bool' object is not callable`. It failed loudly, no measurement was corrupted. Recorded in LLR-118.2 so the AT does not repeat it. |
| **F-3** | Both probes raised `PermissionError [WinError 32]` on `TemporaryDirectory` cleanup, holding `.s19tool/logs/s19tui.log` — **the same failure batch-77 recorded as its F-1**. Fixed with `ignore_cleanup_errors=True`. It is now a two-batch recurrence and belongs in the test-harness backlog, not in another postmortem. **Carry C-78-e.** |
| **F-4** | **I wrote a phantom value into an acceptance.** `TC-B78-11`'s first draft asserted a single-variant project renders `(1/1)`. It does not: `app.py:11332` gates the counter on `len(variant_set.variants) > 1`, and `tests/test_tui_variants.py:259` **pins the plain form** under LLR-005.3. The literal `(1/1)` matched no constant and no behaviour on disk — a **C-36 phantom that would have false-failed a correct implementation while contradicting a shipped acceptance.** Caught by the orchestrator's `_project_label` pointer, not by me. Corrected in HLR-120's statement and catalog, and given its own **LLR-120.5**. Root cause is exactly the rule this document quotes at others: *I asserted a display form I had not executed.* |
| **F-5** | **I reported the S-7 breakpoint as 136 without stating its units.** My sweep set the CSS `width: 22`, which is a **border-box** width and therefore an **18-cell** list; the orchestrator's 139 was for a **22-cell content** list. Neither figure was wrong; my *reporting* was, because a breakpoint with no unit is not re-derivable. Reconciled by execution across 9 widths (P-32b) and the document now carries the closed form `L ≤ C − 89` in content units so the question cannot recur. |

### 6.4 Open risks and carries

| # | Risk / carry | Disposition |
|---|---|---|
| **C-78-a** | 🆕 **The batch's own snapshot goldens are not per-cell reasoned yet.** 29/29 contain `Project:`/`A2L:` and will drift; but `Goto&#160;0xADDR` renders in only **8/29** and `Find&#160;ASCII` in **0/29**, so the *reason* differs per cell. | C-22 per-cell census is owed at **Phase 3**, not now. Regen **CI-only** (C9). |
| **C-78-b** | 🆕 **`tests/test_tui_patch_json.py:791-792` cites `screens_directionb.py:4269` / `:4270` for `AbDiffPanel`'s kind colours.** Those constants are now in the `AbDiffPanel` body near `:6631`. The citations are **~2 400 lines stale**. | **Lane-A carry.** Out of scope here — noting it, not fixing it. |
| **C-78-c** | 🆕 **`app.py:6232`'s width breakpoint is a bare literal `120`.** Every regime rule in `styles.tcss` depends on it and nothing names it. | **Lane-A carry.** LLR-124.1 introduces a *new* named constant rather than retrofitting this one, to keep the increment bounded. |
| **C-78-d** | 🆕 **`Enter → open-in-hex` from the diff screen needs a "render an arbitrary image in the hex view" capability.** `on_memory_map_panel_open_in_hex_requested` (`app.py:10261`) renders `current_file`, which is generally neither compared image. | **Lane-A carry.** Ruled out of US-78-9 (D-11). |
| **C-78-e** | 🆕 **`TemporaryDirectory` cleanup fails on Windows because the app holds `s19tui.log`.** Second batch running (batch-77 F-1). | **Lane-A carry** — a shared probe/test helper, not another postmortem note. |
| **C-78-f** | **Lane-3 handoff input.** Nothing in S-1…S-9 reaches into S-10…S-13. Two facts this lane established that the Lane-3 charter should inherit: (i) the `x` key does **not** become free this batch; (ii) `AT-TC-REGISTRY.jsonl`'s G2 will fire the same way when S-13 deletes `test_operations.py` nodes — the reconciliation pattern of LLR-121.3 is the template. | **Lane-3 handoff charter** (a deliverable of this batch's close). |
| **R-1** | 29-golden drift makes any local run diverge from CI | Regen in canonical CI only; state which suite form produced any ledger figure (§5.1 rule 6). |
| **R-2** | Both lanes edit `tests/test_tui_directionb.py` | **Dissolved by routing** (P-45): Lane 2's ATs live in `tests/test_tui_diff_screen.py`; Lane 1 owns the two `test_tui_directionb.py` edits. C-34 still requires the full file to **run** at every render gate. |
| **R-3** | P-19's width figures were unverified | **Closed and corrected** — P-31/P-32/P-33/P-34. The headline figure was wrong (81 → 79) and the framing was wrong (horizontal → vertical). |
| **R-4** | S-3 reduces label availability 10 → 1 | **Closed by the operator's option-C ruling**; HLR-120 requires **both** surfaces, with a discriminating arm per surface. |
| **R-5** | Focus ATs that blur with `escape` are unsound | LLR-119.4 makes the blur assertion a requirement, not a convention. |
| **R-6** | The palette must keep working on all 10 screens | `AT-B78-02`/`AT-B78-03`; baseline executed at **10/10** and **37** entries. |
| **R-7** | 🆕 **The widget-type swap at `#diff_range_list` can empty a query silently** | C-38: 8 hits / 3 files re-pointed **before** the change runs (LLR-122.1). |
| **R-8** | 🆕 **Security posture:** the batch adds no file I/O, no network surface, no credential path, no new external-tool integration. The only new data path is display text (project name, A2L filename) reaching a rendered label. | Bounded by C-17: LLR-120.4 requires `markup=False` **at construction**, with `TC-B78-12` driving a hostile filename. No `security-reviewer` sign-off is required for this scope, and I state that as a judgement, not as a finding. |

---

## 7. Increment plan (dependency-ordered, ≤5 files each)

**Ordering constraints, all derived above:** US-78-3 lands **before** US-78-1 (P-38 — the label's test consumers need a surviving observable) · US-78-4 lands **after** US-78-1…3 (charter) · **US-78-8 lands before US-78-6 and US-78-7** (P-33/D-10 — they are unobservable at 120×30 until it does) · US-78-6 after US-78-5 (charter) · the snapshot regen is **last** (C-30).

| Inc | Content | Files | Gate |
|---|---|---|---|
| **Inc-0** | **Behavioural control capture** — the pre-change workspace/A2L/MAC find+goto results (`AT-B78-12`'s golden) and the 37-entry palette action list (`AT-B78-03`'s golden), in their own commit **before any production edit** | `tests/test_tui_commandbar.py`, golden fixture (2) | goldens committed; captured from the **shipped surface**, not from an internal call (C-35) |
| **Inc-1** | **HLR-120** — project/A2L context onto both surfaces (producer side), **preserving both display forms** (LLR-120.5) | `app.py`, `screens_directionb.py`, `styles.tcss`, `tests/test_tui_commandbar.py` (4) | full `tests/test_tui_directionb.py` (C-34); `AT-B78-08…11` + `AT-B78-30` green; `#workspace_status_bar.size.height == 7`. ⚠️ `tests/test_tui_app.py`'s three `update_project_labels` stubs (P-38b) are **not** evidence at this gate |
| **Inc-2** | **LLR-121.4** — re-point the three `#cmdbar_project` consumers at the new surface, **while both still exist** | `tests/test_tui_patch_variant.py`, `tests/test_tui_variants.py`, `tests/test_tui_directionb.py` (3) | those three suites green; `grep -rn 'cmdbar_project' tests/` → 0 |
| **Inc-3** | **HLR-119** — re-home `/`·`g` onto `_active_screen_key`; the notice path; the `Esc` release | `app.py`, `tests/test_tui_commandbar.py` (2) | full `tests/test_tui_directionb.py`; `AT-B78-04…07` green; `_PRE_BATCH_BINDINGS` unchanged |
| **Inc-4** | **HLR-118** — delete `#command_bar_row` + its CSS | `command_bar.py`, `styles.tcss`, `tests/test_tui_commandbar.py` (3) | full `tests/test_tui_directionb.py`; `AT-B78-01…03` green; palette **10/10**, **37** entries |
| **Inc-5** | **HLR-121** — delete the messages, adapters and helpers; reconcile the registry node lists | `command_bar.py`, `app.py`, `tests/test_tui_commandbar.py`, `tests/test_tui_directionb.py`, `AT-TC-REGISTRY.jsonl` (5) | full `tests/test_tui_directionb.py` **and** `tests/test_id_registry.py` G1–G7; `git diff` over the six surviving handlers = **0** lines |
| **Inc-6** | **HLR-125** — compact the three control rows *(Lane 2 opens here; it must precede Inc-8/Inc-9)* | `styles.tcss`, `tests/test_tui_diff_screen.py` (2) | full `tests/test_tui_directionb.py`; `AT-B78-26…27` green — **the joint arm needs Inc-4 merged**, so Inc-6 gates after it |
| **Inc-7** | **HLR-122** — selectable run list, with the C-38 sweep landing in the same increment | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_diff_screen.py`, `tests/test_tui_diff_compare_realpath.py` (4) | full `tests/test_tui_directionb.py` + full `tests/test_tui_diff_compare_realpath.py` + full `tests/test_tui_patch_big.py` (C-26, `AbDiffPanel` 25 refs / 5 files) |
| **Inc-8** | **HLR-123** — windows follow selection; height-derived rows | `screens_directionb.py`, `tests/test_tui_diff_screen.py` (2) | full `tests/test_tui_directionb.py`; `AT-B78-21`'s strict inequality green at 160×40 vs 120×30 |
| **Inc-9** | **HLR-124** — the width regimes. **Gated on §8 OQ-1.** | `screens_directionb.py`, `app.py`, `styles.tcss`, `tests/test_tui_diff_screen.py` (4) | full `tests/test_tui_directionb.py`; `AT-B78-23…25` green; C-22 per-cell census |
| **Inc-10** | **HLR-126** — discoverability | `screens_directionb.py`, `tests/test_tui_diff_screen.py` (2) | full `tests/test_tui_directionb.py`; `git diff` over `app.py:1338-1375` = 0 lines |
| **Inc-11** | **Snapshot regen — canonical CI only**, collapsed into one PR | 29 snapshot SVGs | full suite (**FULL** form); C-22 per-cell reasoning |

**Sequencing rationale.** Inc-0 precedes everything because a control captured after the change proves nothing. Inc-1→Inc-2→Inc-4 is forced by P-38: the label's three test consumers must have a surviving observable before the label dies, and the re-point must happen while both exist. Inc-3 precedes Inc-4 so `action_focus_find` has already stopped calling `CommandBar.focus_find` before the input it queries is deleted. Inc-6 precedes Inc-8/Inc-9 because those two stories are **unobservable at 120×30** until the vertical budget exists (P-33) — this is D-10 and it is the charter's ordering inverted. Inc-11 is last per C-30, so every earlier increment marks only its own cells and the untouched cells stay live as regression guards. **No increment edits a file another increment in flight also edits**, and Lane 1 / Lane 2 share no test file (P-45).

---

## 8. Open decisions

| # | Question | Options | Recommendation | Blocks | Owner |
|---|---|---|---|---|---|
| **OQ-1** | **S-7's regime pair** — two regimes at a new `_DIFF_WIDE_MIN = 139` (content units), or one always-overlay regime? | §2.8 D-1, four options, each with measured window widths at 80/120/160 and the closed form `L ≤ C − 89` | **①** two regimes. It is the only candidate that puts both supported widths on the correct side of a measured line **and** keeps the run list visible at 160. ② is the acceptable simpler fallback if the overlay mechanism proves costly. | Inc-9 | **OPERATOR** (or architect at the Phase-2 gate if the operator defers) |
| **OQ-2** | The charter's capture width **132×44 is not a supported regime** (C1: 80/120/160) and falls on the **fallback** side of the recommended breakpoint. Should a 132 snapshot cell be added? | add a cell (+1 golden, +1 regen surface) · leave the matrix at 3 sizes | **Leave it at 3.** The matrix is the project's contract; adding a cell for a prototype's screenshot width optimises a width nobody tests. | Inc-11 | architect — recorded, not escalated |
| **OQ-3** | LLR-121.3: when a registry row's `nodes` list would be left **empty** by the deletion, what is the correct status transition? | `RETIRED` · `BURNED` · keep `LIVE` with a re-pointed node | **`assumed — confirm against `.dev-flow/AT-TC-REGISTRY-SPEC.md` §3.3 at Phase 3.`** I did not read the status semantics section in this session and will not guess at it. | Inc-5 | Phase 3 |
| **OQ-4** | LLR-118.3: the exact `styles.tcss` deletable span. Phase 0 measured `:55-102`; I did **not** re-execute it. | — | **`assumed — re-derive at Phase 3`** by grep. Flagged rather than copied, because a copied line range is exactly the error class this document exists to prevent. | Inc-4 | Phase 3 |
| **OQ-5** | LLR-122.2 / P-47: do the stock `ListView` bindings interact correctly with this app's four `priority=True` App bindings? | — | **`assumed — verify in target framework at Phase 3`.** Honest UNDECIDABLE; the AT presses real keys so a wrong answer surfaces as a red test rather than a silent one. | Inc-7 | Phase 3 |

---

## 9. Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | §2.4 — 15 constraints, each with a `file:line` I re-derived this session or an executed value |
| ≥2 alternatives considered | ✓ | §2.8 D-1 — 4 options with a measured window-width matrix at 3 regimes; D-2 — 4 clauses ruled individually |
| Recommendation tied to constraints | ✓ | D-1/① tied to C1 (the 80/120/160 matrix) and C2 (the single diff golden); D-2's exclusions tied to P-42 and P-43 |
| Risks listed (operational, security, cost, lock-in) | ✓ | §6.4 — 6 carries + 8 risks + 3 self-caught draft defects. **Security = R-8**, stated as a bounded judgement with its C-17 control named |
| Cost / latency estimated where relevant | ✓ | Column and row budgets are this design's cost axis: §2.4 C3–C7, §2.8 D-1's matrix, LLR-123.2, LLR-124.2/.3, LLR-125.2. No new I/O, no new compute, no new dependency |
| Diagram included when flow is non-trivial | ✗ | **Deliberate.** Both lanes are linear producer chains stated in three lines each (§2.1). The one genuinely non-obvious relationship — the S-7 budget — is a **matrix of measured numbers**, which a diagram would blur rather than sharpen |
| What would change the recommendation is stated | ✓ | §2.8 D-1 closing paragraph; OQ-1's fallback to ② |
| Two-layer requirements: Acceptance block + AT, both chains | ✓ | All 9 HLRs carry a first-class **Acceptance (black-box)** block with observable outcome + shipped surface + deliverable/observation + AT ids + a QC-3 boundary catalog; §5.2 carries both chains for all 9 |
| Every AT demonstrated RED pre-change | ✓ | §5.2 "RED today?" — 9 of 9, each from a command executed in this session |
| No global `AT-NNN` / `TC-NNN` minted | ✓ | Batch-scoped `AT-B78-01…29` / `TC-B78-01…39`; `_meta.next_free` untouched (§5.4) |
| Every code claim verified or flagged | ✓ | ~80 `file:line` citations, all re-derived this session. **Four** claims are explicitly flagged rather than asserted: LLR-118.3's CSS span, LLR-123.2's centring arithmetic, LLR-123.3's `_KIND_LABEL` line, LLR-124.3's overlay mechanism — plus OQ-3 and OQ-5 |
| Orchestrator corrections addressed | ✓ | **(1)** `render_hex_view` / 79 — already this lane's independent finding, now cross-attributed (P-31, F-1). **(2)** `L ≤ C − 89` and the 139 breakpoint — **reconciled by execution across 9 widths** (P-32b); my 136 and the orchestrator's 139 are the same fact in box vs content units; the document adopts **content units and 139** (LLR-124.1/.2). **(3)** The census: `tests/test_tui_app.py` is genuinely coupled but **does not read `#cmdbar_project`** — it stubs `update_project_labels` at `:70/:233/:1338`, so it goes **blind**, not red (P-38b). **(4)** The LLR-005.x display FORM — **this caught a real defect of mine** (a phantom `(1/1)`); fixed in HLR-120's statement, given **LLR-120.5** and `AT-B78-30`, and recorded as F-4 |
| Normative keyword discipline | ✓ | `shall` appears only in HLR/LLR **Statement** lines and in the **proposed** statement texts inside §2.8's option tables. **No `should` appears in any requirement statement** |
| Concurrency respected | ✓ | Only this file was created. `prototypes/memmap2.*`, `.dev-flow/state.json`, `00-measurements.md` and `AT-TC-REGISTRY.jsonl` were **read, never written**. No `git add -A`, no `git stash`, no mutation run against the working tree — all probes ran read-only from a scratchpad directory |
