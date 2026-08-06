# Requirements Document — s19_app — batch `2026-08-06-batch-78` (MERGED, Phase-1 FOLD)

**Objective:** Command-bar deletion + context re-home (Lane 1, S-1…S-4) · A2B diff master–detail (Lane 2, S-5…S-9)
**Charter INPUT:** `prototypes/cmdbar_a2bdiff.HANDOFF.md` · **Phase-0:** `00-measurements.md`
**Lane inputs folded:** `01-requirements-architect.md` (HLR/LLR, increments) + `01b-qa-validation.md` (black-box acceptance, falsifiability, 1 081 lines, read in full)
**Branch:** `claude/batch-78-cmdbar-a2bdiff` @ `4df335b` · **Base:** `origin/main` @ `f6ff1d3`
**Language:** English · **Lane:** A (`.dev-flow/BACKLOG-CODE.md`)
**Normative keyword:** `shall`, and it appears ONLY inside HLR/LLR **Statement** lines.
**Scope:** S-1…S-9. **Lane 3 (S-10…S-13) is OUT** — carries in §6.4 feed its handoff charter.

---

## BLUF — the fold changed six things, and four of them were my own lane's errors

| # | Finding | Verdict | Source |
|---|---|---|---|
| **F-1** | **The width primitive was 81 from the wrong producer; it is 79.** The diff panel imports `render_hex_view` (`screens_directionb.py:7021`), not `render_hex_view_text`. **Three lanes derived this independently.** | ✅ settled | both lanes + orchestrator |
| **F-2** | **S-7's binding constraint is VERTICAL.** At 120×30 the results area has a **clipped visible height of ZERO**, and the shipped golden contains no `Runs`/`Image A`/`Image B` text. **S-8 is the enabling story, not polish.** The orchestrator executed my ladder and confirmed it; the orchestrator's own additive derivation (6 rows) was wrong — `#diff_columns` goes 1→3 under S-8, not 1→7. | ✅ settled, **executed table governs** | architect + QA, confirmed by orchestrator |
| **F-3** | **My side-by-side bound is exact; QA's is off by one.** Fine sweep 130→140: a list of **18** content cells first fits at **135**, one of **22** at **139**. My `L ≤ C − 89` predicts both **to the column**; QA's `L_outer ≤ C − 84` predicts 134 and 138, and measurement says 78 ✗ at both. QA's form omits the window box's `margin-right`. | ⚠️ **architect's bound adopted** | settled by execution this session |
| **F-4** | **QA's full-width floor is exact and mine was coarse: `W ≥ 94`, not "from 100 up".** Measured 93 → 78 ✗, 94 → 79 ✅. Also **no dead zone at the rail switch** (119 → 104 ✅, 120 → 87 ✅). | ⚠️ **QA's figure adopted** | QA, re-executed here |
| **F-5** | **`set_status` does not write `#status_text`.** `app.py:11638-11639` is `self._append_log_line(message)`; `#status_text` moves only via `set_file_status` (`:11641-11644`). **My LLR-119.2 cited those lines as `set_status` and was wrong — its acceptance would have been vacuous.** | ❌ **my defect, QA caught it** | QA B-8, verified here |
| **F-6** | **A cap AT that expects the constant certifies the constant, not the capping.** QA's first display-cap predicate stayed **GREEN under `DISPLAY_MAX_RUNS 128 → 100000`** because its expected value was read from the class under test. **My `AT-B78-18` had exactly that shape** ("the predicate quotes `DISPLAY_MAX_RUNS`"). Rewritten. | ❌ **my defect, QA's self-catch generalised to me** | QA §10.1 |

**Plus two corrections to shipped requirements** (§6.5): `R-TUI-022` mandates the bar's find/goto inputs; `R-TUI-036` mandates the context labels render *in the command bar*. Both are amended, with Before/After.

**Open decisions: ZERO.** `OQ-1` is **closed by operator ruling R-1** (three regimes). All four of QA's blockers (B-1, B-2, B-3, S-9 in/out) are ruled in §2.8.

---

## 1. Introduction

### 1.1 Purpose
Derive the merged HLR/LLR/AT/TC set for batch-78 from the nine READY user stories in `PLAN.md §3`, under IEEE 830 + EARS, with every code claim verified against disk at draft time and every acceptance discharged for falsifiability by execution.

### 1.2 Scope
**In:** US-78-1 … US-78-9 (charter S-1…S-9).
**Out:** Lane 3 (S-10…S-13); diff variants B and C; the `Enter → open-in-hex` clause of S-9 (§2.8 D-2, ruled out by R-3 on measured evidence); an unwrapped-row guarantee below the derived two-axis floor (§2.8 D-1, replaced by an explicit notice regime per R-1).

### 1.3 Definitions

| Term | Definition |
|---|---|
| **emitted hex row** | One line of `hexview.render_hex_view` output. **79 cells, executed** (P-31). `render_hex_view_text`'s 81 is the *workspace* producer and does not apply to the diff panel. |
| **content width / height** | `widget.size.*` — inside `border` + `padding`, outside `margin`. |
| **outer width** | `widget.region.width` = content + 4. |
| **clipped visible height** | `widget.region.intersection(screen_host.region).height` — **the painted layer** (C-32). At 120×30 this is 0 for `#diff_hex_a` while `region.height` reads 4; a predicate on `region` alone ships the bug green. |
| **box chrome** | The columns a bordered `#diff_*` box costs its parent: **5** (border 2 + padding 2 + margin-right 1). Measured (P-32). |
| **`C`** | `#diff_columns` content width `= W − rail − 6`. rail = **4** for `W ≤ 119`, **22** for `W ≥ 120` (breakpoint measured exactly at 120). |
| **side-by-side bound** | `L + 5 + 79 + 5 ≤ C`, i.e. **`L ≤ C − 89`**, `L` in **content** cells. Exact at both sampled list widths (P-32b/P-34b). |
| **active screen** | `S19TuiApp._active_screen_key` (`app.py:5816`). The only sound discriminator — nothing unmounts on screen switch (Phase-0 P-10). |
| **GATE / PIN** | A **gate** can go RED under a named, executed mutation of its declared subject. A **PIN** is invariant under the change it accompanies and guards against regression only. **A PIN is never counted as a discharged gate.** |

### 1.4 References
`REQUIREMENTS.md` (`R-TUI-022`, `R-TUI-036`, `R-TUI-016`; `## Retired ids`) · `docs/engineering-rules.md` (C-13, C-13.1, C-22, C-23, C-26, C-28, C-29, C-30, C-32, C-34, C-37, C-38, C-42) · `.dev-flow/AT-TC-REGISTRY-SPEC.md` §2.3/§3.3/§4, G1–G7 · `.dev-flow/2026-08-01-batch-77/01-requirements.md` (structure; the `j`/`k` shadowing precedent) · both Phase-1 lane documents.

### 1.5 Document overview
§2 description, **§2.7 premise table**, **§2.8 rulings** · §3 HLR with a first-class Acceptance block per story · §4 LLR with touched symbols · §5 validation, falsifiability table, dual traceability, **§5.5 the 22-row ID reconciliation** · §6 appendices, carries, **§6.5 amendments** · §7 increment plan · §8 open decisions · §9 evidence checklist.

---

## 2. Overall description

### 2.1 Product perspective

**Lane 1.** `CommandBar` (`command_bar.py:69`) is mounted into `Container(id="command_bar_slot")` at `app.py:1879` — a sibling of `#workspace_shell`, so it renders on all 10 screens. Its `compose` (`:139`) yields `#command_bar_row` (`:140`: prompt, two context labels, two duplicate find/goto inputs) and `#command_palette` (`:150`). **The palette is a sibling of the row, not a child.** Batch-78 deletes the row, re-points `action_focus_find` / `action_focus_goto` (`app.py:5980` / `:5984`) at the active screen's own inputs, and moves the project/A2L context to two surviving surfaces.

**Lane 2.** `AbDiffPanel` (`screens_directionb.py:6566`) composes three 3-row control rows, a status line, and `#diff_columns` (`:6769`) — three rigid `1fr` boxes (`styles.tcss:1481-1490`). `render_comparison` (`:6879`) caps runs (`_apply_display_caps`, `:6925`), renders the list into a `Static` (`_render_run_list`, `:6958`), and renders **only run 0** (`_render_run_windows(0)`, single call site `:6921`).

### 2.2 Product functions
(a) removal of the duplicate find/goto surface and its 3 rows of app-wide chrome; (b) `/`·`g` acting on the pane in front of the operator; (c) project/A2L context surviving on every screen; (d) keyboard- and mouse-reachability of every diff run; (e) hex windows that follow selection and size to the pane; (f) an unwrapped hex row wherever the measured budget allows it, and an **explicit notice** where it does not; (g) control rows that do not starve the result area.

### 2.3 User characteristics
A firmware/calibration engineer comparing two S-record images in a terminal at 80×24, 120×30 or 160×40. Single operator, no auth surface anywhere in the app. This batch adds no file I/O, no network surface, no credential path and no external-tool integration; the only new data path is display text reaching a rendered label, bounded by C-17 (LLR-120.4).

### 2.4 Constraints

| # | Constraint | Value | Evidence |
|---|---|---|---|
| C1 | Supported terminal regimes | **80×24, 120×30, 160×40** — the snapshot matrix. **NOT 132×44** | `ls tests/__snapshots__/test_tui_snapshot/` → 29 cells across these three sizes |
| C2 | Only diff golden | `[diff-comfortable-120x30]`, **1** cell; it renders **no** `Runs`/`Image A`/`Image B` | executed entity-decoded scan (P-33b) |
| C3 | Emitted hex row | **79** cells | executed (P-31) |
| C4 | Box chrome | **5** columns | measured (P-32) |
| C5 | `C` by terminal | 80→70 · 120→92 · 132→104 · 160→132 | measured (P-32) |
| C6 | Rail width | **4** for `W ≤ 119`, **22** for `W ≥ 120` | measured, breakpoint exact (P-32) |
| C7 | Diff result area, `#diff_hex_a` **clipped** rows | 80×24 → **0** · 120×30 → **0** · 132×44 → **11** · 160×40 → 7 content | measured (P-33) |
| C8 | Display caps (G-9) bound the PANEL, never the report | `DISPLAY_MAX_RUNS = 128` `:6623`, `DISPLAY_MAX_TOTAL_BYTES` `:6624`; report reads `_diff_last_result` (`app.py:4953`), never `panel._runs` | verified |
| C9 | Snapshot regen **CI-only** | textual **8.2.8** pin | project rule |
| C10 | Frozen keymap guard | 14 tuples; `j` and `p` **frozen**; neither `slash` nor `g` present | re-derived, `tests/test_tui_directionb.py:6058-6072` |
| C11 | C-17 markup safety | file-derived text → `markup=False` **at construction** | precedent `app.py:1916` |
| C12 | Textual internal-name shadowing | no `_nodes` / `_context` on new widgets | project rule |
| C13 | `styles.tcss` id selectors beat subclass `DEFAULT_CSS` | new styling owns new ids or edits `styles.tcss` | charter §3 |
| C14 | AT/TC ids **batch-scoped** | `AT-B78-nn` / `TC-B78-nn`; registry touched **only** for the G2 node repair | `PLAN.md` D-7; `engineering-rules.md:48` |
| C15 | Existing width-regime machinery | `_apply_width_regime` `app.py:6205`; threshold is a **bare literal `120`** at `:6232` | verified |
| C16 | Footer chip budget | **14** chips in a 78-column Footer at 80×24 | QA-executed census |

### 2.5 Assumptions and dependencies
Every load-bearing assumption is in §2.7. Five claims are flagged `assumed — verify at Phase 3` rather than asserted: LLR-123.2's row-centring arithmetic, LLR-124.3's overlay dismissal mechanism, LLR-124.4's derived height constant, LLR-119.3's `Escape` mechanism, and LLR-121.3's registry status transition.

### 2.6 Source user stories

| ID | User story (Connextra) | DoR status (merged) |
|---|---|---|
| **US-78-1** | As a firmware engineer, I want the command-bar row gone, so that its three rows of duplicate chrome go back to the screen I am reading. | 🟢 **READY** |
| **US-78-2** | As a firmware engineer, I want `/` and `g` to act on the pane I am looking at, so that a find on the A2L screen searches the A2L. | 🟢 **READY** — fixes a latent wrong-pane defect |
| **US-78-3** | As a firmware engineer, I want to see which project and A2L are loaded on every screen, so that deleting the bar does not blind me. | 🟡 **READY — RE-SCOPED** (the A2L half is already shipped) |
| **US-78-4** | As a maintainer, I want the dead find/goto surface deleted, so that the codebase stops carrying a second, wrong implementation. | 🟢 **READY** — after US-78-1…3 |
| **US-78-5** | As a firmware engineer, I want to select any differing run, so that I can inspect more than the first one. | 🟢 **READY** — keymap ruled by R-2 |
| **US-78-6** | As a firmware engineer, I want the hex windows to follow my selection and fill the pane. | 🟢 **READY** — after US-78-5 |
| **US-78-7** | As a firmware engineer, I want an unwrapped hex row where the terminal allows it, and to be told when it does not. | 🟢 **READY** — three regimes ruled by R-1 |
| **US-78-8** | As a firmware engineer, I want the control rows to stop eating the results area, so that a comparison shows results. | 🔴 **PROMOTED to prerequisite** of US-78-6/7 |
| **US-78-9** | As a firmware engineer, I want the run-list keyboard path to be discoverable. | 🟡 **READY — HALVED** by R-3 |

**Refinement deltas.** US-78-3 re-scoped: `#loaded_panel` already renders the A2L filename, so the payload is the **project string and its two display forms**. US-78-8 promoted: US-78-6/7 are unobservable at 120×30 until it lands. US-78-9 halved: the `Enter` clause is ruled out with cause.

### 2.7 Premise evaluation (C-43)

Tier: **axiom** · **hypothesis** · **premise**. Phase-0's P-1…P-20 are not restated. Every evidence cell is a command executed by one of the two lanes; rows marked **⚑** were re-executed at the fold because the lanes disagreed.

| # | Proposition | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| **P-31** | The diff panel's emitted hex row is 81 cells (Phase-0 §9.1) | premise | ❌ **FALSE — 79, wrong producer** | Panel imports `render_hex_view` `screens_directionb.py:7021`, calls it `:7030-7031`. `render_hex_view` → **79**; `render_hex_view_text` → **81**; delta = the 2-space indent. Confirmed on the panel's own rendered text @132×44: `[38, 79, 79, 79, 79, 79, 79]`. | **Corrects §9.1.** 81 remains correct for the workspace pane. |
| **P-32** | Box chrome 5; `C = W − rail − 6`; rail 4/22 | premise | ✅ **TRUE** | Single-window: `120: C=92 win=87 → 5` · `132: 104/99 → 5` · `160: 132/127 → 5`. Rail breakpoint **exactly 120** (QA ladder; 119 → rail 4, 120 → rail 22). | Both lanes agree. |
| **P-32b** ⚑ | "a 22-column list" is unambiguous | premise | ❌ **FALSE — box vs content differ by 4** | Textual CSS `width: N` sets the **border-box**; `size.width` is content. Executed `styles.width = 12` → `size.width = 8`. | Forces content units everywhere below. |
| **P-34b** ⚑ | The side-by-side bound (architect `L ≤ C − 89` vs QA `L_outer ≤ C − 84`) | hypothesis | ⚠️ **architect's is exact; QA's is off by one** | Fine sweep 130→140, both list widths: `L=18` → `132:76 ✗ 134:78 ✗ **135:79 ✅**`; `L=22` → `136:76 ✗ 138:78 ✗ **139:79 ✅**`. `L ≤ C − 89` predicts 135 and 139 **exactly**; `L_outer ≤ C − 84` predicts 134 and 138 — both measured ✗. QA's form omits the window box's `margin-right`. | **`L ≤ C − 89` adopted.** Max list content: **3** @120, **15** @132, **43** @160. |
| **P-34c** ⚑ | The full-width floor (architect "from 100 up" vs QA `W ≥ 94`) | premise | ⚠️ **QA's is exact; mine was a coarse sample** | `93 → 78 ✗`, **`94 → 79 ✅`**, `95 → 80 ✅`. And **no dead zone at the rail switch**: `119 → 104 ✅`, `120 → 87 ✅`. | **`W ≥ 94` adopted** as the width half of R-1's condition. |
| **P-33** | The 120-col problem is horizontal | premise | ❌ **FALSE — vertical first** | `#diff_hex_a` **clipped** rows: `80×24 → 0` shipped / 0 with S-8 / 0 with S-8+S-1. `120×30 → 0 / 0 / ` **2** content. `160×40 → 3 / 9 / 12` content. Orchestrator re-executed and confirmed; its additive derivation (6) was wrong — `#diff_columns` goes 1→3 under S-8, not 1→7. | Promotes US-78-8; drives R-1. |
| **P-33b** | The shipped diff golden shows the results columns | premise | ❌ **FALSE** | Entity-decoded scan of `[diff-comfortable-120x30].svg`: `Runs` **False**, `Image A` **False**, `Image B` **False**; `Compare` **True**, `Report` **True**. | **The strongest single measurement in the batch.** |
| **P-33c** ⚑ | R-1's height threshold is derivable | hypothesis | ✅ **TRUE — H ≥ 29 at W=120, post S-8+S-1** | Height sweep, content rows of `#diff_hex_a`: `H=28 → 0`, **`H=29 → 1`**, `H=30 → 2`, `H=32 → 4`, `H=40 → 12`. Same floor at W=80 (`80×24 → 0`, `80×30 → 2`), so the height budget is width-independent. | **Derives R-1's second axis.** The literal 29 is `assumed — re-derive at Phase 3` (my S-8 simulation is `styles.height = 1`, an approximation of the real implementation). |
| **P-35** | The A2L filename does not reach the Loaded panel (charter S-3) | premise | ❌ **FALSE — already shipped** | Both lanes, independently. QA: `'engine_v3.a2l' in loaded_panel → True`, `'DemoProj' → False`. Architect: `'Loaded \| S19 \| IMG.s19 … \| A2L \| ECU_CAL.a2l  0 tags \| unload all'`. Source `_slot_state` `screens_directionb.py:1891`. | Re-scopes US-78-3; an A2L-in-panel AT would be **GREEN today**. |
| **P-36** | `#workspace_status_bar` renders on all 10 and carries neither name | premise | ✅ **TRUE** | All 10 screens `size=116x7 labels=7 display=True`; content `'Ready. \| 0% \| --:--:-- \|  \|  \|  \| '`. | US-78-3's status-bar half is net-new. **Already 7 rows** → LLR-120.3. |
| **P-37** | Deleting `test_tui_commandbar.py` nodes is registry-neutral | hypothesis | ❌ **FALSE — G2 goes red** | 4 `LIVE` rows name it: `TC-007`, `TC-008`, `TC-009`, `TC-039`; `TC-008` alone names 5 such nodes. G2 = *"every LIVE entry's nodes all exist"* (`tests/test_id_registry.py:223`). | Widens US-78-4 by one file. |
| **P-38** | `#cmdbar_project` has 1 test consumer | premise | ❌ **FALSE — 3 helpers, 16 call sites, 2 files Phase 0 never named** | `tests/test_tui_patch_variant.py:85` (helper `_project_label` `:82`, **9** calls) · `tests/test_tui_variants.py:78` (**7** calls) · `tests/test_tui_directionb.py:897`. | **US-78-3 must land BEFORE US-78-1.** |
| **P-38b** ⚑ | `tests/test_tui_app.py` is a fourth `#cmdbar_project` consumer | premise | ⚠️ **coupled, but goes BLIND not red** | Zero `#cmdbar_project` references; its three hits monkeypatch `update_project_labels` (`:70`, `:233`, `:1338`). | Its green is **not evidence** at Inc-2's gate. |
| **P-38c** | The project label has one display form | hypothesis | ❌ **FALSE — two, and the single-variant one is pinned** | `app.py:11328` plain default; the suffixed form is gated on `len(variant_set.variants) > 1` (`:11332`) → `f"{p}:{d} ({i}/{N})"` (`:11345-11348`). `tests/test_tui_variants.py:259` `test_single_s19_project_label_plain` pins *"no `(1/1)`"* under LLR-005.3. | **Corrected my own phantom `(1/1)`** (F-4 in §6.3). Drives LLR-120.5. |
| **P-39** | The palette command set is invariant under the row deletion | hypothesis | ✅ **TRUE — 37, and it stays 37** | `visible_palette_actions()` n=**37**, contains `focus_find` **and** `focus_goto`. Entries derive from `BINDINGS` (`app.py:5758-5772`). **S-2 re-points the App actions and S-4 deletes only the `CommandBar` helpers**, so `BINDINGS` is untouched. Ctrl+K executed on **10/10**. | **Resolves QA's B-3 at 37** (§2.8 D-3). The Ctrl+K half is a **PIN** (green today). |
| **P-40** | `/`·`g` focus the bar inputs on every screen; `Esc` does not release | premise | ✅ **TRUE, both lanes, blur-asserted** | Per screen, `set_focus(None)` + `assert app.focused is None` before each press: 10/10 `/ → find_input`, `escape → find_input` **unchanged**, `g → cmdbar_goto_input`. QA re-ran the wrong-pane arm **with an image loaded**: `active=a2l → {'search_input':'BOOT','alt_search_input':'','mac_search_input':''}` and the search actually executed. | US-78-2's `Esc` clause is net-new; the wrong-pane defect is real, not theoretical. |
| **P-40b** | `set_status` writes `#status_text` | premise | ❌ **FALSE** | `app.py:11638-11639`: `def set_status(self, message): self._append_log_line(message)`. `#status_text` is written only by `set_file_status` (`:11641-11644`). QA observed `#status_text == 'Ready.'` through nine searches. | **Corrects my LLR-119.2.** The notice AT reads `#log_line_4` + the line-count delta. |
| **P-41** | 29 of 29 goldens render the bar | premise | ✅ **TRUE, per-cell reason recorded** | `'Project:'` **29/29**, `'A2L:'` **29/29**; `'Goto&#160;0xADDR'` **8/29**, `'Find&#160;ASCII'` **0/29**. Both lanes; QA confirms the C-42/4 entity trap does not bite on these two tokens. | Drift count 29 confirmed; C-22 per-cell reason recorded. |
| **P-42** | `j`/`k`/`n`/`p` are free for run navigation (charter S-5) | premise | ❌ **FALSE — only `n` is free, and 2 are FROZEN** | `app.py:1352` `o`→`open_workarea` · `:1354` `p`→`load_project` · `:1356` `j`→`dump_a2l_json` · `:1359` `k`→`show_legend` **`show=True`**. `j` and `p` are in `_PRE_BATCH_BINDINGS`, guarded by live **`TC-011`**. Unbound among the proposed: `down`, `enter`, `escape`, `n`, `tab`, `up`. | **Ruled by R-2** (§2.8 D-4). Batch-77's B-2, one batch later. |
| **P-43** | `Enter → open-in-hex` is implementable for a diff run | hypothesis | ❌ **FALSE — it would show the wrong bytes** | `on_memory_map_panel_open_in_hex_requested` (`app.py:10261`) does `action_show_screen("workspace")` + `update_hex_view(...)`, rendering **`current_file`**. A diff compares two images frequently both external; neither is `current_file`. | **Ruled OUT by R-3.** Carry C-78-d. |
| **P-44** | The regime split can reuse the existing breakpoint | premise | ⚠️ **machinery yes, constant no** | `_apply_width_regime` `app.py:6205` ← `on_resize` `:6239`; threshold is the bare literal `narrow = width < 120` (`:6232`). `width-narrow` is read by 11 rules across workspace/map/patch/rail (`styles.tcss:243…1829`). | LLR-124.1 introduces its **own** class and constant; overloading `width-narrow` would silently change all 11. |
| **P-45** | The Lane-1/Lane-2 test-file collision is unavoidable | hypothesis | ❌ **FALSE — avoidable by routing** | Lane 2's ATs belong in `tests/test_tui_diff_screen.py` (already the `AbDiffPanel` suite); Lane 1's in `tests/test_tui_commandbar.py`. | **R-2 of `PLAN.md` dissolved by construction.** C-34 still requires the full guard host to **run**. |
| **P-46** | Regression baselines | premise | ✅ **TRUE, forms stated** | Architect 4-file set: **`38 passed in 36.26s`** (LEAN, `-m "not slow"`). QA 4-file set: **`58 passed in 70.10s`** (FULL-file form). Different file sets; both stated with their form. | §7 gate baselines. |
| **P-47** | Stock `ListView` bindings interact correctly with the four `priority=True` App bindings | hypothesis | ❓ **UNDECIDABLE at Phase 1** | Not executed by either lane. | `assumed — verify in target framework at Phase 3`; LLR-122.2's AT presses real keys so a wrong answer is a red test, not a silent one. |
| **P-48** ⚑ | `tests/test_universal_paste.py` is at risk from S-4 | premise | ❌ **FALSE** | It drives `#palette_input` (`:201`) and runs an AST census for **stock `Input()`** over `_TUI_DIR.rglob("*.py")` (`:52`). Deleting two `OsClipboardInput` constructions adds no stock `Input()`. | **Lane-1 at-risk test files = 6, not 7.** Corrects both my earlier count and the orchestrator's adoption of it. |
| **P-49** ⚑ | The deletable CSS span is `styles.tcss:55-102` (Phase-0 P-8) | premise | ❌ **FALSE — it is `:66-102`** | `#command_bar_slot` `:51` and `#command_bar` `:61-64` **both survive** (the slot still hosts the palette). Deletable: `#command_bar_row` `:66`, `#command_bar_prompt` `:73`, `#cmdbar_project` `:80`, `#cmdbar_a2l` `:88`, `#find_input` `:96`, `#cmdbar_goto_input` `:100-102`; `#command_palette` begins `:104`. | **Closes my OQ-4.** Phase-0's span would have deleted the surviving `#command_bar` block. |
| **P-50** | The persisted diff report is complete (uncapped) | premise | ✅ TRUE by construction | `on_ab_diff_panel_report_requested` reads `self._diff_last_result` (`app.py:4953`), never `panel._runs`. | **A code fact, so the AT still observes it through the written FILE** (C-12) — `AT-B78-31`. |
| **P-51** | Footer chip budget | premise | ✅ **14 chips / 78 columns @80×24** | QA census: `ctrl+k ctrl+d ctrl+l ctrl+s slash g q x k question_mark plus minus comma period`, identical at every size. | Bounds S-9 (LLR-126.1). |

**Gate rule:** ❌/⚠️/❓ block unless dispositioned. Every ❌ above is self-dispositioning — each corrects a prior claim and the correction has landed in the body. **P-47 is an honest UNDECIDABLE** and is flagged in the LLR it feeds.

### 2.8 Rulings

#### D-1 · S-7 — THREE regimes (operator ruling R-1), with the boundary DERIVED

**The condition, normative and two-axis.** An unwrapped hex row is deliverable iff **both** hold:

> **Width:** a full-width window has `C − 5 ≥ 79`, i.e. `C ≥ 84`, i.e. **`W ≥ 94`** (measured exact: 93 → 78 ✗, 94 → 79 ✅; continuous across the rail switch, 119 → 104 ✅, 120 → 87 ✅).
> **Height:** the window has at least one visible content row — measured floor **`H ≥ 29`** post-US-78-8 + US-78-1 (28 → 0, 29 → 1, 30 → 2), width-independent.

| Regime | Condition | Layout |
|---|---|---|
| **Wide** | `W ≥ _DIFF_WIDE_MIN` (**139**, the first fit for a 22-cell list, `L ≤ C − 89`) | run list **beside** the window column; windows stacked inside it |
| **Fallback** | `94 ≤ W < 139` **and** `H ≥ _DIFF_MIN_ROWS_H` | run list as a **dismissible overlay** (dedicated key); window at full `C`; the visible hex rows are a **paginable viewport** over the selected run — at 120×30 that is **2 rows**, accepted explicitly by the operator |
| **Notice** | `W < 94` **or** `H < _DIFF_MIN_ROWS_H` | an explicit notice naming **which axis** is unsatisfied and the value required, instead of a silently empty panel |

**Why a notice regime is not optional:** at 80×24 the panel today renders **nothing** in its results area and says nothing about why (P-33, P-33b). The notice closes that hole.
**Why the notice must name the axis:** the two conditions are independent. `80×30` **passes** height (2 rows) and **fails** width (65 < 79); `120×24` passes width and fails height. A single "terminal too small" message would be wrong half the time.
**Max list content width beside an unwrapped window** (`L ≤ C − 89`): **3** @120 · **15** @132 · **43** @160. This strikes the charter's 12-cell fallback (impossible at 120) **and** its "22-col list at ≥ ~130" (impossible at 132; first fit 139) — both at draft time, per C-13.1.

⚠️ **Reported back to the coordinator, as asked:** R-1's premises hold under measurement. The 2-row fallback viewport at 120×30 reproduces exactly. The one refinement measurement forces is the *axis-naming* clause above. `_DIFF_MIN_ROWS_H = 29` is `assumed — re-derive at Phase 3` against the real S-8 implementation, since my simulation set `styles.height = 1` directly.

#### D-2 · S-9 — ruled clause by clause (R-3)

| Clause | Verdict | Basis |
|---|---|---|
| Discoverability via the `?` help panel + a visible affordance on the run list | ✅ **IN** | Free: the list's own bindings surface in the stock panel (`app.py:5836`, bound `:1364`). |
| A new App-level `show=True` Footer binding | ❌ **OUT** | Would contend with the measured **14 chips in 78 columns** at 80×24 (P-51) for a key the focused widget already owns. |
| `j`/`k`/`n`/`p` aliases | ❌ **OUT** | P-42 — see D-4. |
| `Enter` posts open-in-hex | ❌ **OUT — carry C-78-d** | P-43: it would render `current_file`, generally neither compared image. **A defect, not a feature.** |

#### D-3 · The palette control — decided at 37 (closes QA's B-3)

QA correctly refused to pick this silently. It is decidable from the HLR-119/HLR-121 split: **S-2 re-points the App actions `action_focus_find`/`action_focus_goto`; S-4 deletes only the `CommandBar.focus_find`/`focus_goto` helpers.** `BINDINGS` is therefore untouched and the palette action set stays **37**, including `focus_find` and `focus_goto`. The control is valid as worded — and it is a **PIN** (green today), never a gate.

#### D-4 · S-5's keymap — arrows + Enter, widget-scoped (R-2)

`j` and `p` are **frozen** in `_PRE_BATCH_BINDINGS` under live `TC-011`; `k` is a `show=True` Footer chip. Bindings go on the **list widget**, not the App, so `TC-011` stays green and the App actions still fire when focus is elsewhere (the discriminating negative, `AT-B78-19`).
**`n`/`p` next-prev is struck, and no `n`-only replacement is added.** `n` is free, but a lone `n` with no partner is an asymmetric keymap — a discoverability trap that costs a Footer chip and buys nothing, because `ListView`'s native `up`/`down` already provide next/prev. **Absent, deliberately** (LLR-122.2).

---

## 3. High-level requirements (HLR)

> **ID basis (executed):** union-corpus high-water `HLR-117`/`LLR-117` → **next free `HLR-118`**. Highest **defined** `R-TUI` row is **103**; `R-TUI-111/112` are dangling prose with **0** live citations → **this batch claims `R-TUI-104`**, per batch-77's precedent.
> **No global `AT-NNN`/`TC-NNN` is minted.** Batch-scoped `AT-B78-01…31` / `TC-B78-01…45`.

---

### HLR-118 — the command-bar row is gone and the palette is untouched
- **Traceability:** US-78-1
- **Statement:** When the application renders any screen, the widget tree **shall not** contain `#command_bar_row` or any of its children, the rendered height of `#command_bar_slot` **shall** be zero, and the Ctrl+K command palette **shall** open on every screen of `SCREEN_CONTAINER_IDS` with an action set identical to the pre-change set.
- **Rationale (informative):** the row costs 3 rows on all 10 screens. `#command_palette` is its **sibling** (`command_bar.py:150`), so the row deletes without touching the palette, and the palette's entries derive from `BINDINGS`, so the action set is invariant by construction — which is why the acceptance asserts it rather than assuming it (**PIN**, D-3). The `#command_bar_slot` height clause exists because deleting the row from `compose` while leaving a `height` rule on the slot would satisfy every query clause and reclaim **nothing**.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_commandbar.py -v` + **full** `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** `len(app.query("#command_bar_row")) == 0` on **all 10** screens (today 1 on all 10); no widget with an id in `{find_input, cmdbar_goto_input, cmdbar_project, cmdbar_a2l, command_bar_prompt}` resolves anywhere; `#command_bar_slot` rendered height **0** (today 3); palette opens **10/10** and its action set has **37** members
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator sees three more rows of the screen they are on, and Ctrl+K still opens the same command list from anywhere.
  - **Shipped surface:** `App.run_test(size=…)` → `action_show_screen(k)` for each `k` in `SCREEN_CONTAINER_IDS` → DOM query; then `set_focus(None)` (**asserted**) → `pilot.press("ctrl+k")` → `CommandBar.palette_is_open` (a **property**, `command_bar.py:195-196`)
  - **Deliverable + observation:** the rendered widget tree per screen; the slot's height; the palette's action set, derived from `app._build_palette_entries()`, **never hand-listed** (C-31). ⚠️ **C-40:** absence is trivially green on a screen that mounted nothing — the AT co-asserts `len(app.query("#command_palette")) == 1` and the screen's own container present, in the same run.
  - **Acceptance test(s):** **`AT-B78-01`** (GATE) row + child ids absent on all 10, slot height 0, palette co-asserted present · **`AT-B78-02`** (**PIN**) Ctrl+K opens on all 10, blur asserted · **`AT-B78-03`** (**PIN**) the action set equals the producer-derived 37-member set
  - **Boundary catalog:** ☑ **empty** — no file loaded → row absent, palette opens, `TC-B78-01` · ☑ **boundary** — 80×24, the narrowest regime, where a reflow would hide a surviving row, `TC-B78-02` · ☑ **negative** — `crc_designer`, the screen the bar was never designed against, `TC-B78-03` · ☑ **boundary** — palette opened, screen switched, re-opened, `TC-B78-40` · ☐ **error** — **N/A:** removal of a static widget set admits no new input.

---

### HLR-119 — `/` and `g` act on the active screen, and `Esc` releases the input
- **Traceability:** US-78-2
- **Statement:** While a screen is active, the `focus_find` action **shall** move keyboard focus to that screen's own find input and the `focus_goto` action **shall** move it to that screen's own go-to input; a find or go-to initiated from a screen **shall** write only into that screen's own input; when the active screen owns no such input, the action **shall** append exactly one log line naming the absence and **shall not** raise; and when focus is on a find or go-to input, `Escape` **shall** move focus off that input.
- **Rationale (informative):** executed on all 10 screens: `/` → `find_input`, `g` → `cmdbar_goto_input`, `escape` → **still `find_input`**. Because `action_show_screen` swaps a `hidden` class and nothing unmounts (Phase-0 P-10), all eight inputs resolve on every screen — routing **shall** key on `_active_screen_key`, never on presence. The defect is real and executes: with an image loaded and **A2L** active, a find writes `'BOOT'` into the **workspace** `#search_input` and the search actually runs against the workspace map. The notice path is the **majority** — 7 of 10 screens.
- **⚠️ Surface correction (P-40b):** `set_status` appends to the log tail; it does **not** write `#status_text`. An acceptance reading `#status_text` for the notice is **vacuous** — it stays `'Ready.'` through nine searches.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_commandbar.py -v` + full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** on the 3 owning screens `/` and `g` focus that screen's own inputs (today the bar's, 10/10); with A2L active a find yields `#alt_search_input.value == "BOOT"` **and** `#search_input.value == ""`; on the 7 non-owning screens `len(app.log_lines)` grows by **exactly 1** per key and **0** exceptions are raised (today **0** notices); after `Escape`, `app.focused` is not that input (today it is, 10/10)
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a find started on the A2L screen searches the A2L; a find started where there is nothing to search says so instead of silently searching another pane.
  - **Shipped surface:** real `pilot.press("slash")` / `("g")` / `("escape")` — **never `.focus()`** — each preceded by `app.set_focus(None)` **and** `assert app.focused is None`
  - **Deliverable + observation:** `app.focused.id`; each local `Input.value`; `#log_line_4` and the `len(app.log_lines)` delta. ⚠️ The owning set is **computed in the test body** from the tree (C-31) with `assert len(OWNING) == 3` as a completeness guard — a universal over an emptied query is otherwise vacuous.
  - **Acceptance test(s):** **`AT-B78-04`** (GATE) `/`·`g` focus the local inputs on the 3 owning screens · **`AT-B78-05`** (GATE) the 7-screen notice at `#log_line_4` with the exactly-one delta · **`AT-B78-06`** (GATE) the wrong-pane fix, with the `== ""` clause as the load-bearing half · **`AT-B78-07`** (GATE) `Escape` releases the input
  - **Boundary catalog:** ☑ **empty** — no file loaded: focus moves, the existing "No file loaded." line is unchanged, `TC-B78-04` · ☑ **boundary** — `/` twice without an intervening blur (idempotent, no second notice), `TC-B78-05` · ☑ **boundary** — screen switched while an input is focused; the next `/` follows the **new** screen, `TC-B78-06` · ☑ **invalid** — `g` then a malformed address `0xZZ` on a re-homed input → the existing parse-failure line, `TC-B78-07` · ☑ **negative** — `/` while the palette is open **must not** steal focus from `#palette_input` (the one place `/` is a literal character), `TC-B78-08` · ☑ **error** — `focus_find` before mount → no raise, `TC-B78-41`

---

### HLR-120 — the loaded project and A2L are named on every screen, in both display forms
- **Traceability:** US-78-3
- **Statement:** When a project or A2L is loaded, `#workspace_status_bar` **shall** present the active project string and the A2L filename on every screen of `SCREEN_CONTAINER_IDS`, and `#loaded_panel` **shall** present the active project string; both surfaces **shall** present the project as the plain project name when the active project holds at most one variant and as `project:variant (index/total)` when it holds more than one; both **shall** be refreshed by the same update entry point; any widget receiving file-derived text **shall** be constructed with `markup=False`; and the addition **shall not** increase the rendered height of `#workspace_status_bar`.
- **Rationale (informative):** `#loaded_panel` **already** renders the A2L filename (P-35) — that half of the charter's clause is green today. What is absent everywhere except the bar is the **project string**. The **two-surface** design is the operator's option C, and it creates two update paths, so each needs its own arm. The **display-form** clause is not decoration: the suffixed form is gated on `> 1` (`app.py:11332`) and `tests/test_tui_variants.py:259` pins the plain single-variant form under LLR-005.3 — an implementation that re-homes the string but flattens it breaks a shipped acceptance. The height clause exists because the status bar is **already 7 rows** and the diff pane (C7) cannot afford an eighth.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_commandbar.py tests/test_tui_variants.py tests/test_tui_patch_variant.py -v` + full `tests/test_tui_directionb.py`
- **Numeric pass threshold:** with a project and A2L loaded, the status bar's text contains both on **10 of 10** screens (today **0 of 10**); `#loaded_panel` contains the project name (today absent); a 1-variant project's string contains **no** `(`; a 2-variant project's contains `(1/2)`; `#workspace_status_bar.size.height == 7`
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** on any screen the operator can read which project, variant and A2L they are working on.
  - **Shipped surface:** a real project/A2L load and a real variant switch through the shipped affordance — **not** by calling the refresh directly → read both surfaces' rendered text per screen
  - **Deliverable + observation:** the concatenated rendered text of each surface's children, plus `#workspace_status_bar.size.height`. ⚠️ **C-40, forced by the operator's ruling:** two surfaces need **two arms**. An implementation updating only one passes a single-surface test. ⚠️ The A2L arm uses a filename appearing nowhere else in the composed text.
  - **Acceptance test(s):** **`AT-B78-08`** (GATE) status bar names both, all 10 screens · **`AT-B78-09`** (GATE) `#loaded_panel` names the **project** (the A2L clause is dropped — it is green today) · **`AT-B78-10`** (**PIN** until the successor exists, then GATE) the update **path**: after a variant switch **both** surfaces move, asserted `before != after` per surface **and** `after` equal to the expected string computed from the variant set · **`AT-B78-11`** (GATE) the status bar's height is unchanged at 7 · **`AT-B78-30`** (GATE) the display-form arm: plain at `N == 1`, `(1/2)` at `N == 2`, **on both surfaces** — four observations
  - **Boundary catalog:** ☑ **empty** — nothing loaded → both surfaces show the `(none)` sentinels, not a blank, `TC-B78-09` · ☑ **alternative** — A2L loaded with **no** project, `TC-B78-10` · ☑ **boundary** — `N == 1` renders the **plain** name and no counter (⚠️ an earlier draft of mine asserted `(1/1)`; `app.py:11332` gates the suffix on `> 1` and `tests/test_tui_variants.py:259` forbids it — the literal would have false-failed a correct implementation *and* contradicted a shipped acceptance), `TC-B78-11` · ☑ **boundary** — `N == 3`, active index 2 → `(2/3)`, `TC-B78-42` · ☑ **invalid** — a filename `[red]evil[/].a2l` renders verbatim, no `MarkupError` (C-17), `TC-B78-12` · ☑ **negative** — unload all → both surfaces return to `(none)`, `TC-B78-43` · ☑ **error** — `update_project_labels` before mount → no raise, `TC-B78-13`

---

### HLR-121 — the duplicate find/goto surface is deleted, and the surviving handlers are unchanged
- **Traceability:** US-78-4
- **Statement:** The `CommandBar.Find` and `CommandBar.Goto` message classes, their application-side adapters, the `focus_find` / `focus_goto` / `set_context_labels` helpers and the style rules for the deleted row and its children **shall** be absent from the source tree; the workspace, A2L and MAC search and go-to behaviour **shall** be unchanged; and every registry entry naming a deleted test node **shall** be reconciled.
- **Rationale (informative):** `on_command_bar_find` (`app.py:5995`) writes into `#search_input` and calls `_handle_search()` regardless of the active screen. Once HLR-118 removes the inputs the messages cannot be posted, and once HLR-119 re-points the actions the helpers have no callers. **The App actions `action_focus_find`/`action_focus_goto` survive** — only the `CommandBar` helpers go — which is what keeps the palette at 37 (D-3). The registry clause is not bookkeeping: G2 fails on a `LIVE` entry naming a node that does not exist (P-37).
- **Validation:** `test` + `inspection` · **Executed verification:** `pytest tests/test_tui_commandbar.py tests/test_id_registry.py -v` + full `tests/test_tui_directionb.py`
- **Numeric pass threshold:** an AST census finds **0** definitions of the six symbols (today 1 each); `styles.tcss` contains **0** selectors for the six deleted ids and **retains** `#command_bar_slot` and `#command_bar`; the 9-row behaviour payload re-read from disk equals a fresh live capture; `tests/test_id_registry.py` G1–G7 green
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** searching on the workspace, A2L and MAC screens behaves exactly as before; nothing else references the deleted surface.
  - **Shipped surface:** the three screens' shipped **Buttons** (`#search_button`, `#alt_search_button`, `#mac_search_button` and the three go-to buttons), driven over a 9-case matrix (3 screens × {hit, miss, empty})
  - **Deliverable + observation:** an **output-then-consume** pair (C-12) — a test-only commit **ahead of every S-1…S-4 edit** writes the payload to `tests/_artifacts/`, and the AT re-reads it **from disk** and compares to a fresh live capture. No hand-written oracle, no shim across the seam. Executed baseline: `workspace q='BOOT' goto='0x1010' → (…,4102)/(…,4112)`; miss and empty rows `None`; **9 payload rows**. ⚠️ **C-42 mechanic 5:** the source census is an **AST** census, never a line regex. ⚠️ **C-40:** the absence census co-asserts its swept module list is non-empty and contains `command_bar.py`.
  - **Acceptance test(s):** **`AT-B78-12`** (**PIN**) the behaviour control, discharged by substituting `find_string_in_mem → lambda: None` (executed digest `0a159da97fa81714 → 9d6c9b6aeadac6fa → 0a159da97fa81714`) · **`AT-B78-13`** (GATE) the AST + CSS-selector census · **`AT-B78-14`** (GATE) the registry guard green after reconciliation
  - **Boundary catalog:** ☑ **boundary** — a search with no hits on each of the three screens, `TC-B78-14` · ☑ **invalid** — a malformed go-to on each of the three, `TC-B78-15` · ☑ **empty** — no file loaded: each handler bails at its own guard, `TC-B78-16` · ☑ **boundary** — the pre-change artifact capture is committed **before** any production edit, `TC-B78-44` · ☐ **error** — **N/A:** deletion introduces no new input class.

---

### HLR-122 — every displayed run is reachable by keyboard and by mouse
- **Traceability:** US-78-5
- **Statement:** When a comparison has rendered at least one run, `#diff_range_list` **shall** present one selectable entry per displayed run; the set of run indices reachable by keyboard alone and by mouse alone **shall** each equal the full set of displayed run indices; the entry holding the selection **shall** be visually distinguished from every other entry; entries beyond the viewport **shall** be reachable by scrolling; the display caps and the "showing N of M" notice **shall** be preserved; and the run list **shall not** bind any key bound at application level.
- **Rationale (informative):** `#diff_range_list` is a `Static` today (`screens_directionb.py:6766`) — `type = Static`, `can_focus = False`, `ListView` descendants under `#diff_columns` = **0**. No run is selectable and `_render_run_windows` is called once with the literal `0`. The final clause is the anti-regression half (D-4/R-2): `j` and `p` are **frozen** under live `TC-011` and `k` is a `show=True` Footer chip, so widget-scoped bindings are the only form that leaves `TC-011` green.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_diff_screen.py -v` + full `tests/test_tui_directionb.py` + full `tests/test_tui_diff_compare_realpath.py`
- **Numeric pass threshold:** with a 6-run comparison the keyboard-reachable index set equals `set(range(6))` and the mouse-reachable set equals it too (today: **0** selectable entries); exactly **1** entry carries the selection marker and its resolved `(background, color, text_style)` triple differs from every unselected entry's; with a 200-run comparison the painted row count is **strictly less than 200** and the notice's two numbers equal the painted count and 200; the literals `"j"`, `"k"`, `"p"`, `"o"` appear **0** times in the list's `BINDINGS`
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator can walk every differing run with the arrow keys or the mouse, and can see which one they are on.
  - **Shipped surface:** a real comparison through the Compare button → **real key presses and real clicks** (with `scroll_visible` for off-viewport rows) — never `.focus()`, never `_render_run_windows(i)`
  - **Deliverable + observation:** the selected-index set versus `range(R)` with `R` taken from the **fixture's own run list**; the resolved style triple per row; the painted row count and the notice's parsed numbers. ⚠️ **C-38:** this is a **widget-type swap** — `diff_range_list` has **8 hits across 3 files**, `AbDiffPanel` **25 across 5**; every `query_one("#diff_range_list", Static)` is re-pointed **before** the change runs. ⚠️ **C-40, and this one is QA's self-caught defect generalised:** the cap AT's fixture size (200) is fixed **independently of the constant**, with a loud `assert 200 > AbDiffPanel.DISPLAY_MAX_RUNS` guard, and **nothing in the predicate reads `DISPLAY_MAX_RUNS`** — *a cap AT that expects the constant certifies the constant, not the capping.* ⚠️ The style arm requires **≥ 2 rows** and asserts it; with one row "differs from every unselected" is vacuously true.
  - **Acceptance test(s):** **`AT-B78-15`** (GATE) keyboard-only reachability, set equality · **`AT-B78-16`** (GATE) mouse-only, including one row past the viewport · **`AT-B78-17`** (GATE) exactly one entry visibly selected, ≥2-row guard asserted · **`AT-B78-18`** (**PIN**, green today) the caps and notice survive, rewritten per the above · **`AT-B78-19`** (GATE) anti-shadow: with the list focused, `k` still opens the legend and `j` still reaches its App action · **`AT-B78-31`** (**PIN**, green today) the persisted report stays complete, observed by **re-reading the written file** and counting 200 entries
  - **Boundary catalog:** ☑ **empty** — 0 runs → `'Runs: 0'` and `'Image A — no differing runs'`, no crash, no selectable row, `TC-B78-17` · ☑ **boundary** — exactly `DISPLAY_MAX_RUNS` runs → **no** notice (executed: `stored=128 notice=False`), `TC-B78-18` · ☑ **boundary** — 1 run: selectable; the style clause explicitly skipped under the ≥2 guard, `TC-B78-19` · ☑ **boundary** — more runs than the viewport; the last is reachable under scroll, `TC-B78-20` · ☑ **invalid** — a run with `end == start`, `TC-B78-21` · ☑ **negative** — keys pressed with **no comparison yet**: no exception, no phantom selection, `TC-B78-22`

---

### HLR-123 — the hex windows follow the selection and are sized by the pane
- **Traceability:** US-78-6
- **Statement:** When the operator changes the run-list selection through the shipped selection surface, both hex windows **shall** re-render to the selected run with a header naming its index, address range and classification; the number of hex rows each window renders **shall** be derived from that window's rendered height at render time, **shall not** be a compile-time constant, and **shall not** exceed the window's clipped visible height; and the rendered window **shall** always include the selected run's bytes plus `DISPLAY_CONTEXT_BYTES` of context on each side.
- **Rationale (informative):** `_render_run_windows` (`:7003`) derives its rows from `DISPLAY_CONTEXT_BYTES = 16` alone (`:7026`, `:7028`), so the count is a function of the **run size**. Executed at two very different pane heights: `(132, 24) → 4 emitted lines at pane h=0` and `(132, 60) → 4 emitted lines at pane h=23` — **4 == 4, RED**. The mechanism works (calling `_render_run_windows(3)` directly does change the window), which is exactly why the AT must not call it.
- **⚠️ C-29, two axes.** The row-count arm is written at **132×44**, where the pane is **11 clipped rows today** and the AT is observable **without any Lane-1 work** (R-4). It is written as a **relation** (rows track pane height), never an absolute count, because US-78-1 later adds ~3 rows to every screen and would move any absolute number.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_diff_screen.py -k window -v` + full `tests/test_tui_directionb.py`
- **Numeric pass threshold:** after selecting run 3 of 6, both headers name run **3** and its start address (today always run 0); the emitted row counts at two pane heights **differ** and each is **≤** its pane's clipped visible height (today 4 and 4); the emitted span covers `[start − DISPLAY_CONTEXT_BYTES, end + DISPLAY_CONTEXT_BYTES)`
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** picking a run shows that run's bytes, and a taller terminal shows more of them.
  - **Shipped surface:** as HLR-122, then reading the emitted text of `#diff_hex_a` / `#diff_hex_b`
  - **Deliverable + observation:** the windows' **produced text**, split into lines, plus each window's **clipped** height. ⚠️ **C-32 layer split, deliberate:** this requirement's claim is about what the producer emits, observed at the rendered text; HLR-124's claim is geometric, observed at `size.width`. Neither AT borrows the other's layer. ⚠️ **C-40:** "the header names run 3" is green on a window that rendered only a header — the arm co-asserts ≥1 emitted hex row in the same read. The `≤ clipped height` clause is what kills a "just make it 40" fix.
  - **Acceptance test(s):** **`AT-B78-20`** (GATE) selecting run 3 re-renders both windows, asserting the **address** and the first data row's position within `[start − ctx, start]`, not merely "changed" · **`AT-B78-21`** (GATE) the row count differs between two pane heights and each is ≤ its clipped height · **`AT-B78-22`** (GATE) the emitted span covers the run ± `DISPLAY_CONTEXT_BYTES`
  - **Boundary catalog:** ☑ **empty** — 0 runs → the "no differing runs" text stays, `TC-B78-23` · ☑ **boundary** — a run at address 0, exercising the `max(0, …)` clamp at `:7026`, `TC-B78-24` · ☑ **boundary** — a run longer than the pane: paginable, header still names the run, `TC-B78-25` · ☑ **boundary** — a run whose bytes are absent from one map (the blank-gutter form, executed), `TC-B78-26` · ☑ **invalid** — selection index outside `_runs` → the existing early return at `:7024`, `TC-B78-27` · ☑ **error** — a re-render while the pane has zero height → no raise, `TC-B78-28` · ☑ **mechanism** — the emitted row count is no longer a pure function of `DISPLAY_CONTEXT_BYTES` (two pane heights, one constant), `TC-B78-45`

---

### HLR-124 — three width/height regimes, and no silently empty panel
- **Traceability:** US-78-7 · **operator ruling R-1**
- **Statement:** When the terminal width is at least the wide-regime breakpoint, `#diff_columns` **shall** render the run list alongside the hex-window column; when the terminal satisfies the deliverability condition but not the wide breakpoint, `#diff_columns` **shall** render the hex-window column at its full content width, **shall** present the run list without permanently reserving columns or rows from that width, and **shall** make the selected run's remaining bytes reachable by pagination within the visible rows; when the terminal does not satisfy the deliverability condition, the panel **shall** render a notice naming the unsatisfied axis and the value it requires; and in the first two regimes each hex window's content width **shall** be at least the width of the widest row `hexview.render_hex_view` emits.
- **Rationale (informative):** the shipped three-`1fr` split gives each window **26** cells at 120 and ~**42** at 160 against a **79**-cell row — every hex row wraps at every supported width. The regime boundaries are derived, not chosen (D-1): width `W ≥ 94` (measured exact, 93 → 78 ✗, 94 → 79 ✅) and height `H ≥ _DIFF_MIN_ROWS_H` (measured 28 → 0, 29 → 1). The wide breakpoint **139** is the first fit for a 22-cell list under `L ≤ C − 89`, confirmed to the column (138 → 78 ✗, 139 → 79 ✅). **80×24 fails both axes** and is the reason the notice regime exists: today that panel renders nothing and says nothing about why.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_diff_screen.py -k "regime or wrap or notice" -v` + full `tests/test_tui_directionb.py` + a C-22 per-cell census
- **Numeric pass threshold:** at **160×40** and at **132×44**, `#diff_hex_a.size.width >= max(len(line) for line in render_hex_view(...).splitlines())` — today `42 >= 79` **False** and `30 >= 79` **False**; at **120×30** the same holds post-US-78-8/US-78-1; at **80×24** the notice is present and names the width axis; the literals `139`, `94`, `29` and `26` appear **0** times in the tests
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** at the widths the operator uses, a byte column lines up down the window; where the terminal is too small, the panel says so instead of showing an empty box.
  - **Shipped surface:** `App.run_test(size=…)` at 160×40, 132×44, 120×30 and 80×24 → diff screen → `render_comparison` → `#diff_hex_a.size.width`, its clipped region, and the panel's rendered text
  - **Deliverable + observation:** the window's **content width** against the **emitted** row width, which the test derives by **calling `render_hex_view` itself at test time**; plus the clipped visible width, so the window is not merely un-wrapped but actually on screen. ⚠️ **C-36/C-39:** the test **shall not** hard-code `79` — it is a measurement, not a constant on disk, and a literal would be a phantom the day `HEX_WIDTH` changes. Both quantities are computed. ⚠️ **Per-arm verdicts (CC-1):** every arm is reported per resolved node id per size; 120×30 and 132×44 differ by 11 pane rows and a single aggregate verdict would destroy exactly the information this requirement rests on.
  - **Acceptance test(s):** **`AT-B78-23`** (GATE) no wrapped row at 160×40 · **`AT-B78-24`** (GATE) no wrapped row at 132×44 and, post-US-78-8/1, at 120×30 · **`AT-B78-25`** (GATE) the regimes are observably different: at 160 the list is visible beside the window; at 120 it reserves **0** permanent columns and the viewport paginates · **`AT-B78-29`** (GATE) at 80×24 the notice is present and names the **width** axis
  - **Boundary catalog:** ☑ **boundary** — one column below the wide breakpoint and one at it: the layout flips exactly once, `TC-B78-29` · ☑ **boundary** — a resize **across** the breakpoint after a comparison is rendered: the layout follows and the windows do not blank, `TC-B78-30` · ☑ **boundary** — `W = 94` (the measured width floor) and `W = 93` (one below): notice appears exactly once, `TC-B78-31` · ☑ **boundary** — a terminal passing width and failing height (e.g. 120×24) → the notice names the **height** axis, not the width one, `TC-B78-32` · ☑ **empty** — no comparison rendered: the regime still applies, nothing raises, `TC-B78-33` · ☐ **error** — **N/A:** layout selection consumes only the terminal size, already validated by Textual.

---

### HLR-125 — the control rows do not starve the result area
- **Traceability:** US-78-8 · **prerequisite of HLR-123 and HLR-124's fallback/notice arms**
- **Statement:** The A-selection row, the B-selection row and the action row **shall** each occupy one rendered row; the status line **shall** be visible; and at a terminal of 120×30 with the command-bar row removed, the hex windows **shall** render at least one hex row of content.
- **Rationale (informative):** the story the charter listed last and measurement promotes to first. The three rows are **3 rows each** plus a status line, out of an `#ab_diff_panel` measuring 11 at 120×30 — so `#diff_columns` and `#diff_status` both have a **clipped visible height of ZERO**, and the shipped golden proves it by containing `Compare`/`Report` and nothing from the results columns. Compaction alone reaches `#diff_columns` 3 / `#diff_hex_a` 0; compaction **plus** the bar deletion reaches **2** content rows. The threshold claims **1** — the smallest honest number the budget supports.
- **⚠️ C-13/C-23:** the 1-row target is not transferred from another container; it is the residual required to satisfy the second clause. Phase 3 **shall** re-measure the whole `#ab_diff_panel` budget — every sibling — not just these three rows.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_diff_screen.py -k "row_height or budget" -v` + full `tests/test_tui_directionb.py`
- **Numeric pass threshold:** each of the three rows has a **clipped** visible height of **1** (today 3 each; at 80×24 `#diff_select_row_b` clips to 2); `#diff_status` clipped height **≥ 1** (today **0** at 120×30); `#diff_columns` clipped height **≥ 3**; at 120×30 with the bar removed, ≥ **1** emitted hex row is visible (today **0**)
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a comparison at 120×30 actually shows bytes and a status line, instead of an empty strip below the controls.
  - **Shipped surface:** as HLR-124, reading each widget's region **intersected with `#screen_diff`'s region**
  - **Deliverable + observation:** the four clipped heights, all read in the same run. ⚠️ **C-32, and this is the trap:** a predicate on `widget.region.height` alone reads **4** for `#diff_hex_a` at 120×30 and would ship this green. Clipping against the screen host is the painted layer. ⚠️ **C-40:** `height == 1` on the control rows is invariant under a change that also collapses the result area to zero — the second clause is what makes the pair a gate, and it is asserted in the **same** test.
  - **Acceptance test(s):** **`AT-B78-26`** (GATE) the three rows clip to 1 and `#diff_status` is visible · **`AT-B78-27`** (GATE) the joint arm: at 120×30 with the bar removed, `#diff_hex_a` renders ≥ 1 hex row — asserted in the same run as `AT-B78-26`
  - **Boundary catalog:** ☑ **boundary** — 80×24, where the overflow is worst: the same 1-row clause holds and the panel degrades to the HLR-124 notice rather than to nothing, `TC-B78-34` · ☑ **boundary** — 132×44: rows still 1, the results area gains the freed rows, `TC-B78-35` · ☑ **negative** — a long external path typed into `#diff_path_a` does **not** re-expand the row, `TC-B78-36` · ☑ **empty** — no project loaded, the `Select`s hold only the external sentinel, `TC-B78-37` · ☐ **error** — **N/A:** styling change, no new input class.

---

### HLR-126 — the run-list keyboard path is discoverable
- **Traceability:** US-78-9 · **scope reduced by R-3**
- **Statement:** When the run list holds focus, the application's help panel **shall** list the run list's own navigation keys; the run list **shall** carry a visible affordance naming how to move the selection; and the application's footer-visible binding set **shall** be unchanged.
- **Rationale (informative):** the list's bindings surface in the stock help panel (`app.py:5836`, bound `:1364`) once it is focusable, so the marginal cost is the affordance alone. **What this deliberately does not do:** add an App-level `show=True` binding (the Footer already carries **14** chips in **78** columns at 80×24), bind `j`/`k`/`n`/`p` (D-4), or post an open-in-hex message on `Enter` (P-43 — it would render `current_file`, generally neither compared image; carry C-78-d).
- **Validation:** `test` + `inspection` · **Executed verification:** `pytest tests/test_tui_diff_screen.py -k discover -v` + full `tests/test_tui_directionb.py`
- **Numeric pass threshold:** with the list focused the help panel names its navigation keys; the list's rendered text contains the affordance; `app.active_bindings` filtered on `.show and .enabled` still contains all **14** pre-existing chips at 80×24, none truncated; `git diff` over `app.py:1338-1375` is **0** lines
- **Priority:** low
- **Acceptance (black-box):**
  - **Observable outcome:** an operator who has never used the diff screen can find out how to walk the runs without reading source.
  - **Shipped surface:** focus the run list → `pilot.press("question_mark")` → the help panel's rendered text; `#diff_range_list`'s rendered text; `app.active_bindings`
  - **Deliverable + observation:** the help-panel text, the affordance text, and the filtered chip set. ⚠️ **C-40:** "the help panel names the keys" is green on a panel listing *every* binding in the app — the arm asserts the keys appear **while the list is focused** and co-asserts that a key the list does **not** bind is absent from that focused section.
  - **Acceptance test(s):** **`AT-B78-28`** (GATE) the focused list's keys appear in the help panel, with the negative co-assertion, and the 14 chips are undisplaced
  - **Boundary catalog:** ☑ **empty** — help panel opened with no comparison rendered: no raise, `TC-B78-38` · ☑ **boundary** — opened, dismissed, re-opened, `TC-B78-39` · ☐ **invalid** / ☐ **error** — **N/A:** read-only surface over existing state.

---

## 4. Low-level requirements (LLR)

> Every LLR traces to a parent HLR. Every symbol carries a `file:line` re-derived this session, or `NEW — created in Phase 3`. Every geometry constant carries a measurement or an `assumed` flag. The **Symbols** field is the C-26 input.

### HLR-118 → LLR-118.x

**LLR-118.1 — the row leaves `compose`**
- **Statement:** `CommandBar.compose` **shall not** yield `#command_bar_row` or any of its five children.
- **Symbols:** `compose` `command_bar.py:139`; `Horizontal(id="command_bar_row")` `:140`; `#command_bar_prompt` `:141`, `#cmdbar_project` `:142`, `#cmdbar_a2l` `:143`, `#find_input` `:144-146`, `#cmdbar_goto_input` `:147-149`; `#command_palette` `:150` (**preserved — a sibling**); mount slot `Container(id="command_bar_slot")` `app.py:1879`.
- **Validation:** `test (integration)` · **Numeric pass threshold:** 0 on all 10 screens; `#command_bar_slot` height 0

**LLR-118.2 — the palette command set is invariant**
- **Statement:** The palette entry set **shall** remain derived from `S19TuiApp.BINDINGS` and **shall not** change in content.
- **Symbols:** `_build_palette_entries` `app.py:5758-5772`; `visible_palette_actions` `command_bar.py:204`; `palette_is_open` **property** `command_bar.py:195-196`.
- **Validation:** `test (integration)` · **Numeric pass threshold:** **37**, set-equal to the pre-change list
- **Acceptance criteria:** ⚠️ `palette_is_open` is a **property** — my draft-time probe called it as a method and raised `TypeError: 'bool' object is not callable` (§6.3 F-2). The AT uses the attribute form. **This node is a PIN** (green today, D-3), never counted as a discharged gate.

**LLR-118.3 — the CSS block is removed, and only the right part of it**
- **Statement:** The style rules for the deleted row and its children **shall** be removed from `styles.tcss`, and the `#command_bar_slot`, `#command_bar` and `#command_palette` rules **shall not** be.
- **Symbols — re-derived this session (P-49):** deletable **`:66-102`** — `#command_bar_row` `:66`, `#command_bar_prompt` `:73`, `#cmdbar_project` `:80`, `#cmdbar_a2l` `:88`, `#find_input` `:96`, `#cmdbar_goto_input` `:100-102`. **Preserved:** `#command_bar_slot` `:51`, `#command_bar` `:61-64`, `#command_palette` `:104`.
- **Rationale (informative):** Phase-0 P-8 stated `:55-102`, which would delete the surviving `#command_bar` block and the block comment. **Corrected by execution**, not carried. The comment at `:56-60` is **amended** (it describes the row), not deleted.
- **Validation:** `inspection` · **Numeric pass threshold:** 0 surviving rules for the six deleted ids; the three preserved blocks unchanged

### HLR-119 → LLR-119.x

**LLR-119.1 — routing keys on the active screen, never on widget presence**
- **Statement:** `action_focus_find` and `action_focus_goto` **shall** resolve their target from `self._active_screen_key` through a screen-to-input mapping, and **shall not** resolve it by querying which inputs exist.
- **Symbols:** `action_focus_find` `app.py:5980`, `action_focus_goto` `:5984` (both currently delegate to `command_bar.py:208`/`:212`); `_active_screen_key` set `app.py:5816`; `SCREEN_CONTAINER_IDS` `app.py:5693-5704` (**10**); targets `#search_input` `app.py:1993` / `#goto_input` `:1995`, `#alt_search_input` `:5152` / `#alt_goto_input` `:5155`, `#mac_search_input` `:5230` / `#mac_goto_input` `:5233`. The map is **NEW — created in Phase 3**.
- **Rationale (informative):** `action_show_screen` (`:5775`) swaps the `hidden` class across `SCREEN_CONTAINER_IDS.values()` (`:5818`); nothing unmounts, so all eight inputs resolve everywhere. A presence-based implementation would be **green while wrong**.
- **Validation:** `test (e2e)` + `test (white-box)` · **Numeric pass threshold:** 3 screens route to locals, 7 to the notice, 0 exceptions
- **Acceptance criteria:** the map's key set is asserted **set-equal to `SCREEN_CONTAINER_IDS.keys()`** — the set comes from the RULE, not the implementation's own list (C-40 limb 2). `TC-B78-41` additionally asserts that with A2L active `#search_input` is **still resolvable** while the action resolves the A2L input — the white-box discrimination P-10 demands.

**LLR-119.2 — the no-local-input notice, on the surface that actually moves**
- **Statement:** When the active screen has no entry in the map, the action **shall** append exactly one line to the application log tail and **shall** return without raising.
- **Symbols:** `set_status` `app.py:11638-11639` → `_append_log_line` `:11646`; the rendered tail `#log_line_1..4` (`app.py:1926-1929`), constructed `markup=False`; `log_lines`; `set_file_status` `:11641-11644` (writes `#status_text` — **not** this path).
- **Rationale (informative):** ⚠️ **my earlier draft cited `:11643-11644` as `set_status` writing `#status_text` and was wrong** (P-40b). `#status_text` stays `'Ready.'` through nine searches, so an acceptance reading it would be **vacuous**. QA caught it. The AT reads `#log_line_4` and asserts the line-count delta.
- **Validation:** `test (e2e)` · **Numeric pass threshold:** `len(app.log_lines)` grows by **exactly 1** per key on each of the 7 screens; `#log_line_4` names the absence
- **Acceptance criteria:** ⚠️ **C-40:** "no exception raised" is green on an action that does nothing. The gate is the **log-line delta**; the no-raise arm is a **regression PIN** and is labelled so. *Exactly-one* is what separates a notice from a notice-per-keystroke loop.

**LLR-119.3 — `Escape` releases a focused find/goto input**
- **Statement:** When a find or go-to input holds focus, `Escape` **shall** move focus off that input.
- **Symbols:** the six local inputs of LLR-119.1. The handler is **NEW — created in Phase 3**.
- **Rationale (informative):** executed on all 10 screens, `escape` leaves focus on `find_input`. Net-new work, not a preserved control.
- **⚠️ C-16:** the mechanism (an Input-scoped binding, an `on_key`, or a screen-level priority binding) is `assumed — verify in target framework at Phase 3`, and **must not shadow the palette's own `escape`-to-close**, which is live and was exercised in both lanes' probes.
- **Validation:** `test (e2e)` · **Numeric pass threshold:** `app.focused is not <the input>` after `Escape` (today it **is**, 10/10)
- **Acceptance criteria:** **`pilot.press("escape")` only.** A test calling `.blur()` does not discharge this LLR.

**LLR-119.4 — every focus AT asserts its own precondition**
- **Statement:** Each acceptance test of HLR-119 **shall** call `app.set_focus(None)` and **shall** assert `app.focused is None` before dispatching a single-letter key.
- **Rationale (informative):** an `Input` swallows a bare `g` as text rather than dispatching it. Phase-0 §7 records that exact self-caught defect; **both** Phase-1 lanes independently adopted the blur assertion.
- **Validation:** `inspection` · **Numeric pass threshold:** present in every HLR-119 AT

### HLR-120 → LLR-120.x

**LLR-120.1 — one update entry point drives both surfaces**
- **Statement:** `update_project_labels` **shall** write the project string and the A2L filename to `#workspace_status_bar` and **shall** trigger the `#loaded_panel` refresh, replacing its single write to the command bar.
- **Symbols:** `update_project_labels` `app.py:11290`; plain default `:11328`; the multi-variant guard `:11329-11333`; `_variant_display_options` `:11338`; suffixed composition `:11345-11348`; A2L name `:11350`; **the call to be replaced** `self.query_one(CommandBar).set_context_labels(project_name, a2l_name)` **`app.py:11351`** (`set_context_labels` `command_bar.py:216`, **exactly one call site**); `_refresh_patch_variant_select` `:11352`; `_refresh_loaded_panel` `app.py:8649`; `render_slots` `screens_directionb.py:1848`; `_slot_state` `:1891`; `#workspace_status_bar` `app.py:1930`.
- **⚠️ Stubbed consumers (P-38b):** `tests/test_tui_app.py:70`, `:233`, `:1338` monkeypatch `update_project_labels`. They stay green **without exercising this change** — their green is **not evidence** at the gate.
- **Validation:** `test (integration)` · **Numeric pass threshold:** both surfaces carry the new variant after one call

**LLR-120.2 — the project row in the Loaded panel; the A2L slot untouched**
- **Statement:** `LoadedArtifactsPanel` **shall** render a row naming the active project, and **shall not** alter the existing three artifact slots.
- **Symbols:** `LoadedArtifactsPanel` `screens_directionb.py:1738`; `render_slots` `:1848`; `_SLOTS` iterated `:1885`; re-mounted children carry **classes, never ids** (`:1854-1855` — the `DuplicateIds` discipline).
- **Rationale (informative):** the A2L slot already renders the filename (P-35), so an acceptance for it would be vacuous. Only the project row is new.
- **Validation:** `test (integration)` · **Numeric pass threshold:** project name present (today absent); the three slot rows' text unchanged (set equality)

**LLR-120.3 — the status-bar addition spends no row**
- **Statement:** The addition to `#workspace_status_bar` **shall not** increase its rendered height.
- **Symbols:** `#workspace_status_bar` `app.py:1930`; children `#status_text` `:1916`, `#progress_bar`, `#log_line_1..4`.
- **Geometry:** measured **116×7 on all 10 screens** @120×30. An eighth row costs 1 row app-wide against Lane 1's 3-row reclaim, and the diff pane has **2** content rows to begin with. **The mechanism is deliberately unspecified** — sharing a row with `#status_text` is the obvious candidate; `assumed — re-measure the whole status-bar budget at Phase 3` (C-23).
- **Validation:** `test (integration)` · **Numeric pass threshold:** `size.height == 7` after the change, all 10 screens

**LLR-120.4 — the new sinks are markup-inert at construction**
- **Statement:** Any widget receiving the project or A2L string **shall** be constructed with `markup=False`, or the text **shall** be routed through `safe_text`.
- **Symbols:** precedent `Label("Ready.", id="status_text", markup=False)` `app.py:1916`, rationale in the comment `:1910-1915`.
- **Rationale (informative):** the A2L name is `current_a2l_path.name` and the project name a directory name — both file-derived. `markup=False` **at construction** persists across `.update()`; pre-escaping does not.
- **Validation:** `test (integration)` + `inspection` · **Numeric pass threshold:** `[red]evil[/].a2l` renders verbatim, no `MarkupError`

**LLR-120.5 — both display forms are preserved on both surfaces**
- **Statement:** The project string on each context surface **shall** be the plain project name when the active project holds at most one variant, and the `project:variant (index/total)` form when it holds more than one.
- **Symbols:** the branch producing the two forms — `app.py:11328` (plain) and `:11329-11348` (suffixed, gated `> 1` at `:11332`); `_variant_display_options` `:11338`; the live pin `tests/test_tui_variants.py:259` `test_single_s19_project_label_plain` (*"no `(1/1)`"*, `:260`, LLR-005.3); the reading helpers `tests/test_tui_variants.py:76-78` (**7** calls) and `tests/test_tui_patch_variant.py:82-85` (**9** calls).
- **Rationale (informative):** the re-home is of a **form**, not just a name. An implementation emitting one uniform string satisfies "the project is named" and still breaks LLR-005.3. This LLR exists because my own first draft asserted a `(1/1)` counter the code does not produce and a shipped test forbids (§6.3 F-4).
- **Validation:** `test (integration)` · **Numeric pass threshold:** a 1-variant project's string contains **no** `(` on either surface; a 2-variant project's contains `(1/2)` on **both** — four observations

### HLR-121 → LLR-121.x

**LLR-121.1 — the message classes and helpers are deleted**
- **Statement:** `CommandBar.Find`, `CommandBar.Goto`, `on_command_bar_find`, `on_command_bar_goto`, `focus_find`, `focus_goto` and `set_context_labels` **shall** be absent from `s19_app/`.
- **Symbols:** `class Find(Message)` `command_bar.py:111`, `class Goto(Message)` `:118`; `focus_find` `:208`, `focus_goto` `:212`, `set_context_labels` `:216`; `on_command_bar_find` `app.py:5995`, `on_command_bar_goto` `:6025`. **`class PaletteAction(Message)` `command_bar.py:125` is PRESERVED** — the palette's dispatch message. **`action_focus_find`/`action_focus_goto` (`app.py:5980`/`:5984`) are PRESERVED and re-pointed by LLR-119.1** — this is what keeps the palette at 37 (D-3).
- **Validation:** `inspection` (AST census, C-42 mechanic 5) · **Numeric pass threshold:** 0 for the seven; **1** for `PaletteAction`; **1** each for the two App actions

**LLR-121.2 — the surviving search behaviour is unchanged, proven output-then-consume**
- **Statement:** The workspace, A2L and MAC search and go-to behaviour **shall** be unchanged, evidenced by an artifact captured from the pre-change tree and re-read from disk.
- **Symbols:** `_handle_search` `app.py:11448`, `_handle_goto` `:11518`, `_handle_search_alt` `:11538`, `_handle_goto_alt` `:11568`, `_handle_search_mac` `:11589`, `_handle_goto_mac` `:11618`; dispatch `on_button_pressed` `:11354-11371`.
- **Validation:** `test (e2e)` + on-disk golden (C-12) · **Numeric pass threshold:** the 9-row payload re-read from disk equals a fresh live capture
- **Acceptance criteria:** the artifact is captured in **its own commit before any production edit**; `-text` in `.gitattributes` if any byte-exact blob is stored (the `core.autocrlf` hazard). **This node is a PIN**, discharged by substituting `find_string_in_mem → lambda: None` — executed, digest `0a159da97fa81714 → 9d6c9b6aeadac6fa → 0a159da97fa81714`.

**LLR-121.3 — the registry's node lists are reconciled**
- **Statement:** Every `LIVE` registry entry naming a deleted test node **shall** have that node removed from its `nodes` list.
- **Symbols:** `TC-007`, `TC-008`, `TC-009`, `TC-039` — the 4 rows matching `test_tui_commandbar`; `TC-008` names 5 such nodes. Guard `tests/test_id_registry.py:223`, registered `:361`, asserted `:388-390`.
- **Validation:** `test` · **Numeric pass threshold:** G1–G7 green
- **Acceptance criteria:** ⚠️ `_meta.next_free` and `high_water` are **NOT** touched — this batch mints no global id. If a row would be left with an **empty** `nodes` list, its `status` changes per the spec's semantics rather than the row being deleted; `assumed — confirm the transition against `.dev-flow/AT-TC-REGISTRY-SPEC.md` §3.3 at Phase 3`.

**LLR-121.4 — the RED-by-design assertions are re-pointed, never deleted**
- **Statement:** The live assertions that this batch invalidates **shall** be re-pointed at the surviving surfaces in an increment that lands **before** the increment deleting their observable.
- **Symbols — the merged census (P-38, QA §3.4), 8 named sites across 5 files:** `test_tui_commandbar.py:169, 279` (`/`→`find_input`), `:369` (`g`→`cmdbar_goto_input`), `:251-256, 419, 545` (typing/paste into the bar inputs) · `test_tui_directionb.py:753-754` (the bar carries both inputs — **inverted** by `AT-B78-01`), `:897-898` (`#cmdbar_project`/`#cmdbar_a2l`), `:6325-6326` (`/`·`g` targets) · `test_tui_variants.py` **×7** and `test_tui_patch_variant.py` **×9** (`_project_label()`) · `test_loadfilescreen_input.py:54` (a comment citing `action_focus_goto`, inspection only).
- **⚠️ Not at risk (P-48, executed):** `tests/test_universal_paste.py` targets `#palette_input` and an AST census of **stock** `Input()`; deleting two `OsClipboardInput`s cannot redden it. **Lane-1 at-risk test files = 6.**
- **Validation:** `inspection` + `test` · **Numeric pass threshold:** `grep -rn 'cmdbar_project' tests/` → **0** after the sequence (today **3** definitions, 16 call sites)

### HLR-122 → LLR-122.x

**LLR-122.1 — the run list becomes a selectable widget**
- **Statement:** `#diff_range_list` **shall** be a widget maintaining a selection index over one entry per displayed run, replacing the `Static` that renders the runs as text.
- **Symbols:** `Static("Runs", id="diff_range_list", markup=True)` `screens_directionb.py:6766`; `_render_run_list` `:6958`, terminal write `:7001`; the caps-notice branch `:6994`; CSS `styles.tcss:1481-1490`.
- **⚠️ C-38 blast radius, executed:** `diff_range_list` **8 hits / 3 files**; `render_comparison` **5 / 3**; `AbDiffPanel` **25 / 5** (adds `tests/test_tui_patch_big.py:714`, `tests/test_tui_patch_json.py:791-792`). Every `query_one(..., Static)` re-pointed or widened **before** the change runs.
- **⚠️ C-17:** the list renders `markup=True` and escapes the artifact summaries with `rich.markup.escape` (`:6986`). The replacement **shall** preserve that escape or render `markup=False`.
- **Validation:** `test (integration)` · **Numeric pass threshold:** 6 runs → 6 selectable entries (today 0; `type = Static`, `can_focus = False`, `ListView` descendants 0)

**LLR-122.2 — navigation binds no application-level key**
- **Statement:** The run list's bindings **shall not** include `j`, `k`, `p` or `o`, and the batch **shall** carry a regression test that those keys still perform their application actions when the run list does not hold focus.
- **Symbols:** `app.py:1352` `o` · `:1354` `p` · `:1356` `j` · `:1359` `k` (`show=True`); `_PRE_BATCH_BINDINGS` `tests/test_tui_directionb.py:6058-6072` (**`j` and `p` frozen**, guarded by live `TC-011`).
- **Rationale (informative):** R-2. `n` is the only free key among the chartered four, and **no `n`-only next/prev pair is added**: `ListView`'s native `up`/`down` already provide next/prev, and a lone `n` is an asymmetric keymap — a discoverability trap that costs a Footer chip and buys nothing. **Absent, deliberately.**
- **⚠️ P-47, honest UNDECIDABLE:** whether the stock `ListView` bindings interact correctly with the four `priority=True` App bindings (`app.py:1339-1342`) is **not executed at Phase 1**. `assumed — verify in target framework at Phase 3`.
- **Validation:** `test (e2e)` + `inspection` · **Numeric pass threshold:** the four literals appear **0** times in the list's `BINDINGS`; `AT-B78-19` green; `TC-011` green

**LLR-122.3 — the display caps and the notice survive, without certifying the constant**
- **Statement:** The selectable list **shall** present exactly the entries `_apply_display_caps` returns and **shall** retain the "showing N of M" notice.
- **Symbols:** `_apply_display_caps` `screens_directionb.py:6925`; `DISPLAY_MAX_RUNS = 128` `:6623`; `DISPLAY_MAX_TOTAL_BYTES` `:6624`; the notice branch `:6994`.
- **Acceptance criteria:** ⚠️ **the predicate shall not read `DISPLAY_MAX_RUNS` for its expected value.** QA's first form fed `DISPLAY_MAX_RUNS + 5` runs and expected `f"showing {DISPLAY_MAX_RUNS} of {n}"` — it stayed **GREEN under `128 → 100000`** because the fixture and the expectation moved together. The rewritten form fixes the fixture at **200** independently, guards with `assert 200 > DISPLAY_MAX_RUNS`, and asserts only the **painted** row count and the notice's own two numbers. It reddens under two independent mutations (§5.3). **C-39's "quote the constant, never its value" applies to the *guard*, not to the *expectation*.**
- **Validation:** `test (integration)` · **Numeric pass threshold:** painted rows **< 200**; notice numbers `(painted, 200)`

**LLR-122.4 — the persisted report stays complete, observed through the file**
- **Statement:** The written diff report **shall** contain every run of the comparison, independent of the panel's display caps.
- **Symbols:** `on_ab_diff_panel_report_requested` `app.py:4952-4977`, reading `self._diff_last_result` (`:4953`) — the **uncapped** service result — and `panel.mem_map_a/b`; it never reads `panel._runs`.
- **Rationale (informative):** correct today by construction (P-50), so this is a **PIN**. But it is a *code* fact, and C-12 requires the observation to go through the **written file**, not the line citation.
- **Validation:** `test (e2e)` + file re-read · **Numeric pass threshold:** the written file holds **200** run entries against **128** painted
- **Acceptance criteria:** discharged at the increment gate by substituting `runs=panel._runs` into the report kwargs and confirming the file-level count drops to the cap. **Executed, or the node is a file rather than a control.**

### HLR-123 → LLR-123.x

**LLR-123.1 — selection drives the window render**
- **Statement:** A change of run-list selection **shall** invoke the window renderer with the selected index.
- **Symbols:** `_render_run_windows` `screens_directionb.py:7003`, **single** call site `:6921` with the literal `0`, inside `render_comparison` (`:6879`); the phantom handler its docstring cites (`on_data_table_row_selected`, `:7019`) has **0** definitions in the module.
- **Validation:** `test (e2e)` · **Numeric pass threshold:** after selecting run 3, both headers name run 3
- **Acceptance criteria:** driven through the shipped selection surface — **never** by calling `_render_run_windows`. Calling it directly *does* work today, which is exactly why the AT must not.

**LLR-123.2 — the row count derives from the rendered pane height**
- **Statement:** The number of `row_bases` passed to `render_hex_view` **shall** be computed from the window widget's rendered height at render time, bounded below by the run's bytes plus `DISPLAY_CONTEXT_BYTES` each side and above by the window's clipped visible height.
- **Symbols:** `DISPLAY_CONTEXT_BYTES = 16` `:6627`, used `:7026` and `:7028`; `row_bases` `:7029`; import `:7021` (`HEX_WIDTH = 16` `hexview.py:21`, `MAX_HEX_ROWS = 512` `:23`, `render_hex_view` `:330`); the window writes `:7033-7034`.
- **Geometry:** measured `#diff_hex_a` rows — **132×44 → 11 clipped today**, **160×40 → 12** post-S-8/S-1, **120×30 → 2** post-S-8/S-1, **80×24 → 0** always. The centring arithmetic (which rows to drop when the run exceeds the pane) is **`assumed — measure in Phase 3`** over the whole `#ab_diff_panel` budget (C-23).
- **Validation:** `test (integration)` · **Numeric pass threshold:** row counts at two pane heights **differ** (today 4 and 4) and each is **≤** its clipped height
- **Acceptance criteria:** ⚠️ **the floor is a floor, not the value.** An implementation keeping `±16` and *also* reading the height passes a "≥ floor" test. The gate is the **strict inequality between two heights**, which `±16` cannot satisfy. Written at **132×44**, where the pane is already 11 rows today (R-4) — observable without any Lane-1 work.

**LLR-123.3 — the header names index, range and kind**
- **Statement:** Each window **shall** carry a header naming the selected run's index, address range and classification.
- **Symbols:** current header `f"Run #{run_index} 0x{start:08X}-0x{end:08X}"` `:7032` — names index and range but **not** kind; `_KIND_LABEL` in the `AbDiffPanel` body (`screens_directionb.py:6631`-region — **`assumed — re-derive the exact line at Phase 3`**).
- **Validation:** `test (integration)` · **Numeric pass threshold:** the header contains the kind label for a run of each of the three kinds
- **Acceptance criteria:** ⚠️ **C-17:** `#diff_hex_a`/`#diff_hex_b` are constructed `markup=False` (`:6767-6768`) and **shall** remain so. The header composes only integers and constant labels — B3 holds by construction.

### HLR-124 → LLR-124.x

**LLR-124.1 — named constants, not literals; its own class, not `width-narrow`**
- **Statement:** The regime selection **shall** read named module-level constants for the wide breakpoint and for the deliverability floors, and the layout **shall** be applied by a CSS class distinct from `width-narrow`.
- **Symbols:** precedent `_apply_width_regime` `app.py:6205` ← `on_resize` `:6239`, toggling `width-narrow` on `#workspace_shell`/`#workspace_body` `:6233-6238`; its threshold is the bare literal `narrow = width < 120` `:6232`. The new constants and class are **NEW — created in Phase 3**.
- **Measured values:** `_DIFF_WIDE_MIN = 139` (content units — the first fit for a 22-cell list under `L ≤ C − 89`; confirmed 138 → 78 ✗, 139 → 79 ✅). `_DIFF_MIN_W = 94` (93 → 78 ✗, 94 → 79 ✅). `_DIFF_MIN_ROWS_H = 29` (28 → 0, 29 → 1) — **`assumed — re-derive at Phase 3`** against the real S-8 implementation, since the measurement simulated it with `styles.height = 1`.
- **⚠️ Units:** Textual's CSS `width: N` is the **border-box**, so a 22-cell content list is authored `width: 26`. A CSS `width: 22` list is 18 cells and moves the breakpoint to 135. **The constants are in content units**; Phase 3 asserts against `size.width`, never against the CSS declaration.
- **⚠️ Do not overload `width-narrow`:** it is toggled at 120 and read by 11 rules across workspace, map, patch and rail (`styles.tcss:243, 247, 322, 326, 332, 762, 875, 953, 979, 1828-1829`).
- **Validation:** `test (integration)` + `inspection` · **Numeric pass threshold:** the literals `139`, `94`, `29`, `26` appear **0** times in the acceptance tests

**LLR-124.2 — the wide layout**
- **Statement:** At or above `_DIFF_WIDE_MIN`, `#diff_columns` **shall** allocate a fixed-width run-list column and give the remainder to a single window column holding both hex windows.
- **Geometry:** at 160 a 22-cell list leaves the window **100** ≥ 79 ✅. At 132 the budget is `L ≤ 15`, so a 22-cell list leaves **72** ✗ — which is why the breakpoint is 139 and why the charter's 132×44 capture sits on the **fallback** side of its own recommended line.
- **Symbols:** `#diff_columns` `screens_directionb.py:6769`, CSS `styles.tcss:1152-1155`; the three-way `1fr` split `styles.tcss:1481-1490` that must go.
- **Validation:** `test (integration)` · **Numeric pass threshold:** at 160×40 `#diff_hex_a.size.width >= len(widest emitted row)` (today `42 >= 79` False)

**LLR-124.3 — the fallback layout, with a paginable viewport**
- **Statement:** Below `_DIFF_WIDE_MIN` and above the deliverability floors, the hex-window column **shall** occupy the full content width of `#diff_columns`, the run list **shall** be presented without permanently reserving columns or rows from it, and the selected run's bytes beyond the visible rows **shall** be reachable by pagination.
- **Geometry:** at 120, `C = 92` and the side-by-side budget is **`L ≤ 3`** — no usable list fits beside the window; a full-width window reaches **87** ≥ 79 ✅. The vertical budget is **2** content rows, which is why the list must cost **zero permanent rows** too. **The operator accepted the 2-row viewport explicitly** (R-1); pagination is what makes 2 rows a viewport rather than a truncation.
- **⚠️ Mechanism:** an overlay on a dedicated key; its dismissal path is **`assumed — verify in target framework at Phase 3`** and **must not** shadow the palette's `escape`-to-close (LLR-119.3's constraint applies here too).
- **Validation:** `test (integration)` · **Numeric pass threshold:** at 120×30 (post-US-78-8/1) `#diff_hex_a.size.width >= len(widest emitted row)`; the run list contributes **0** to `#diff_columns`' permanent width; paging moves the window's first address

**LLR-124.4 — the notice regime names its unsatisfied axis**
- **Statement:** When the terminal fails either deliverability floor, the panel **shall** render a notice naming the unsatisfied axis and the value required, and **shall not** render an empty results area.
- **Geometry:** 80×24 fails **both** (65 < 79 and 0 rows). `80×30` fails **width only** (2 rows available); `120×24` fails **height only**. A single "terminal too small" message would be wrong in each of those cases — **the axis-naming clause is what measurement forces on R-1's third regime.**
- **Validation:** `test (integration)` · **Numeric pass threshold:** at 80×24 the notice names width; at a height-only failure it names height; at `W = 94` / `H = _DIFF_MIN_ROWS_H` exactly, the notice is **absent**
- **Acceptance criteria:** this replaces the earlier "80×24 is out of guarantee" regression pin with a **gate** — R-1 made the silent-empty-panel case a defect to fix, not a case to exclude.

### HLR-125 → LLR-125.x

**LLR-125.1 — the control rows compact to one line**
- **Statement:** `#diff_select_row_a`, `#diff_select_row_b` and `#diff_action_row` **shall** each render at a clipped visible height of one row, and `#diff_status` **shall** have a clipped visible height of at least one.
- **Symbols:** composed `screens_directionb.py:6739-6759`; CSS `styles.tcss:1130-1132`; `#diff_status` `styles.tcss:1144`; `#ab_diff_panel` `styles.tcss:923-927`. Children: `Select` `#diff_select_a`/`_b`, `OsClipboardInput` `#diff_path_a`/`_b`/`#diff_report_dest`, `Button` `#diff_compare_button`/`#diff_report_button`.
- **Geometry:** measured 3 rows each at every regime; at 120×30 `#diff_status` and `#diff_columns` both clip to **0**; at 80×24 `#diff_select_row_b` itself clips to 2.
- **Validation:** `test (integration)` · **Numeric pass threshold:** each clipped height **1**; `#diff_status` **≥ 1**
- **Acceptance criteria:** **Compare and Report handlers unchanged** — `on_button_pressed` routing and `CompareRequested`/`ReportRequested` untouched, covered by the existing `tests/test_tui_diff_screen.py` TC-021/TC-024 nodes. **Check for duplication before minting a new node** (C-18 asks for one node per AT, not a new file).

**LLR-125.2 — the joint vertical threshold**
- **Statement:** At 120×30 with `#command_bar_row` removed, `#diff_hex_a` **shall** render at least one hex row of content.
- **Geometry:** the executed ladder, `#diff_columns` / `#diff_hex_a`: shipped **1/0**, compaction alone **3/0**, compaction **and** bar removal **6/2**.
- **Validation:** `test (integration)` · **Numeric pass threshold:** ≥ **1** emitted hex row visible (today 0)
- **Acceptance criteria:** ⚠️ **C-40:** asserted in the **same test** as LLR-125.1. Separated, the height assertion is invariant under an implementation that compacts the rows and still leaves the result area at zero.

### HLR-126 → LLR-126.x

**LLR-126.1 — discoverability without displacing the Footer**
- **Statement:** The run list **shall** carry a visible affordance naming its navigation keys, and the batch **shall not** add an application-level `Binding` with `show=True`.
- **Symbols:** `action_show_help_panel` `app.py:5836`, bound `Binding("question_mark","show_help_panel","Help",show=True)` `app.py:1364`; the App `BINDINGS` block `app.py:1338-1375`.
- **Geometry:** **14** chips in a **78**-column Footer at 80×24, identical at every size measured.
- **Validation:** `test (e2e)` + `inspection` · **Numeric pass threshold:** `git diff` over `app.py:1338-1375` → **0** lines; the 14 chips all still `.show and .enabled` at 80×24

---

## 5. Validation strategy

### 5.1 Methods

**Layer A (white-box, `TC-B78-nn`):** `test (unit)` / `test (integration)` / `test (e2e)` / `inspection` over the mechanism.
**Layer B (black-box, `AT-B78-nn`):** Textual Pilot e2e — drive the shipped surface, read the shipped surface. **Never** `_render_run_windows`, `_build_palette_entries` or `.focus()` in an assertion path. `demo` is **never** used for acceptance — it is perceptual and unfalsifiable.

**Standing observation rules:**
1. **Read the layer that holds the fact** (C-32/C-37). Content → rendered text. Geometry → `size.*`. **Visibility → the region intersected with `#screen_diff`** — `region.height` alone reads 4 for `#diff_hex_a` at 120×30 and ships the bug green. Colour intent → `render().spans`.
2. **Every absence assertion carries a presence co-assertion** (C-40): `AT-B78-01`, `AT-B78-13`, `AT-B78-19`, `AT-B78-28`, and the notice half of `AT-B78-05`.
3. **Every quantified set comes from the RULE, not the implementation** (C-31): the 10 screens from `SCREEN_CONTAINER_IDS`; the owning set computed in the test body with `assert len(OWNING) == 3`; `R` from the fixture's own run list.
4. **Every threshold quotes its constant, not its value** (C-39) — **except a cap's expected value**, which must be independent of the constant under test (LLR-122.3). The emitted hex-row width is **derived by calling `render_hex_view` at test time**; a literal `79` would be a C-36 phantom.
5. **Every focus AT asserts its own blur precondition** (LLR-119.4).
6. **C-34:** every increment touching `command_bar.py`, `app.py`'s compose/render path, `screens_directionb.py` or `styles.tcss` runs the **full** `tests/test_tui_directionb.py` at its gate — the markup-safety scans, the rail census, the footer census and `TC-011` all live there.
7. **Per-arm verdicts (CC-1):** RED/GREEN per resolved node id **per size arm**. An exit code over parametrized tests hid 4 surviving arms in batch-76.
8. **State the suite form with every ledger figure.** PR lane `-m "not slow"`; the FULL suite before merge.

### 5.2 Gate suite
Every gate runs: full `tests/test_tui_directionb.py` (C-34) + `tests/test_tui_commandbar.py` + `tests/test_tui_diff_screen.py` + `tests/test_tui_variants.py` + `tests/test_tui_patch_variant.py` + `tests/test_loadfilescreen_input.py` + the frozen dual guard (source **and** `_ENGINE_TEST_FILES`, C-27). Baselines: **`38 passed in 36.26s`** (LEAN, architect's 4-file set) and **`58 passed in 70.10s`** (FULL-file, QA's 4-file set).

### 5.3 Falsifiability table (C-40, discharged by EXECUTION)

**PINs are labelled and are never counted as discharged gates.**

| AT | Declared subject | Subject in its own expression? | Reddening mutation (substituted VALUE) | Executed transcript | Verdict |
|---|---|:-:|---|---|---|
| `AT-B78-01` | the row is absent on every screen | ✅ queries the id + slot height on all 10 | none needed | `#command_bar_row present=True height=3`, 10/10 | **GATE — RED today** |
| `AT-B78-02` | Ctrl+K opens everywhere | ✅ | `action_focus_palette` body → `None` | `pre GREEN → mutated RED → restored GREEN` | **PIN — discharged as a pin** |
| `AT-B78-03` | the palette action set | ✅ derived from the producer | as `AT-B78-02` | set n=37, contains `focus_find`/`focus_goto` | **PIN** (D-3) |
| `AT-B78-04` | `/`·`g` focus the active screen's inputs | ✅ | none needed | `/ → find_input`, `g → cmdbar_goto_input`, 10/10 | **GATE — RED today** |
| `AT-B78-05` | 7 screens get exactly one notice | ✅ reads `#log_line_4` + the count delta | none needed | focus moves on all 10; **zero** notices | **GATE — RED today** |
| `AT-B78-06` | the find acts on the pane in front of you | ✅ incl. the `== ""` clause | none needed | `a2l active → search_input='BOOT', alt_search_input=''`, image loaded, search executed | **GATE — RED today** |
| `AT-B78-07` | `Esc` releases the input | ✅ | none needed | `after '/' find_input → after 'escape' find_input` | **GATE — RED today**; mechanism `assumed` (C-16) |
| `AT-B78-08` | both names on the status bar, 10 screens | ✅ | none needed | bar = `Ready.` + progress + 4 log lines | **GATE — RED today** |
| `AT-B78-09` | the **project** name in the Loaded panel | ✅ | none needed | `'DemoProj' in loaded_panel → False` | **GATE — RED today** |
| — | *(the charter's A2L clause on that surface)* | ✅ | n/a | `'engine_v3.a2l' in loaded_panel → True` | ❌ **VACUOUS — dropped** |
| `AT-B78-10` | the update PATH moves both surfaces | ✅ `before != after` per surface | remove the successor call from `update_project_labels` | feature does not exist yet | **PIN — discharge owed at the Inc gate** |
| `AT-B78-11` | the status bar spends no row | ✅ reads `size.height` | set the new label to its own row | 7 today | **GATE** |
| `AT-B78-12` | local search/goto unchanged | ✅ 9-row payload digest | `find_string_in_mem → lambda: None` | `0a159da97fa81714 → 9d6c9b6aeadac6fa → 0a159da97fa81714` | **PIN — discharged as a pin** |
| `AT-B78-13` | the dead symbols and CSS are gone | ✅ AST + selector census | none needed | all six symbols + all six selectors exist | **GATE — RED today** |
| `AT-B78-14` | the registry guard | ✅ | none needed | 4 LIVE rows name the doomed nodes | **GATE — RED after deletion** |
| `AT-B78-15/16/17` | every run reachable + visibly selected | ✅ | none needed | `type=Static can_focus=False`; `ListView under #diff_columns = 0` | **GATE — RED today** |
| `AT-B78-18` | the caps and their notice survive | ✅ **after rewrite** | (a) `DISPLAY_MAX_RUNS` **128 → 100000** · (b) `_render_run_list(total_runs=…)` → `len(self._runs)` | `GREEN → RED (rendered_rows=200, notice=None) → GREEN` and `GREEN → RED (notice=None) → GREEN` | **PIN — discharged, after the first form proved INERT** |
| `AT-B78-19` | App keys survive off-list focus | ✅ | none needed | `j`/`p` frozen, `k` show=True | **GATE** |
| `AT-B78-20` | the windows follow the selection | ✅ headers + first row address | none needed | one call site `:6921`, literal `0` | **GATE — RED today** |
| `AT-B78-21` | row count derives from pane height | ✅ compares two heights | none needed | `(132,24) 4 lines @h=0` vs `(132,60) 4 lines @h=23` | **GATE — RED today** |
| `AT-B78-22` | the span covers the run ± context | ✅ | none needed | derived from the constant today | **GATE** |
| `AT-B78-23/24` | no hex row wraps | ✅ widest emitted vs content width | none needed | `79 > 18/26/29/30/42/49` at 80/120/130/132/160/190 | **GATE — RED today** |
| `AT-B78-25` | the regimes are observably different | ✅ **unblocked by R-1** | force one regime for all widths | — | **GATE** |
| `AT-B78-26/27` | the results area is actually visible | ✅ clipped heights vs `#screen_diff` | none needed | `120×30: rows 3/3/3, #diff_columns clipped=(92,0)` | **GATE — RED today** |
| `AT-B78-28` | discoverability without displacing the 14 | ✅ `active_bindings` filtered | add a `show=True` binding | 14 chips / 78-col Footer measured | **GATE** |
| `AT-B78-29` | the notice names its axis | ✅ **new under R-1** | force the notice text to a single generic string | 80×24 renders nothing today | **GATE — RED today** |
| `AT-B78-30` | both display forms, both surfaces | ✅ four observations | flatten to one form | `(1/1)` is **not** produced today (P-38c) | **GATE** |
| `AT-B78-31` | the persisted report is complete | ✅ counts entries in the **written file** | route the report off `panel._runs` | correct today by construction | **PIN — mutation owed at the Inc gate** |

**Restore proof.** Every mutation was applied **in-process** (monkeypatch on the imported object), reverted in the same process, and the predicate re-run to GREEN. `git diff --stat -- s19_app/ tests/` is **empty**. A hash alone would not prove this — a same-size in-place edit plus a sub-second restore is invisible to `git status` — so the proof is the predicate returning GREEN plus an empty source diff.

### 5.4 Dual traceability

**Behavioral chain (black-box) — every RED-today verdict executed:**

| US | Observable outcome | Shipped surface | AT | RED today? |
|---|---|---|---|---|
| US-78-1 | no bar row anywhere; Ctrl+K unchanged | widget tree ×10 · `palette_is_open` | `AT-B78-01…03` | ✅ row present 10/10 |
| US-78-2 | `/`·`g` act on the visible pane; notice elsewhere; `Esc` releases | `pilot.press` ×10 · `#log_line_4` | `AT-B78-04…07` | ✅ bar inputs 10/10; 0 notices |
| US-78-3 | project + A2L readable everywhere, both forms | `#workspace_status_bar` · `#loaded_panel` | `AT-B78-08…11`, `AT-B78-30` | ✅ project absent 10/10 |
| US-78-4 | local search unchanged; dead surface gone | 3 screens' Buttons · AST census | `AT-B78-12…14` | ✅ 7 symbols present |
| US-78-5 | every run reachable by key and mouse | run list selection set | `AT-B78-15…19`, `AT-B78-31` | ✅ 0 selectable entries |
| US-78-6 | windows follow selection; taller pane shows more | window rendered text | `AT-B78-20…22` | ✅ always run 0; 4 rows at every height |
| US-78-7 | no wrapped row where deliverable; a notice where not | `#diff_hex_a.size.width` · panel text | `AT-B78-23…25`, `AT-B78-29` | ✅ `42 < 79`, `30 < 79`; 80×24 silently empty |
| US-78-8 | a comparison at 120×30 shows bytes | clipped heights | `AT-B78-26…27` | ✅ clipped height 0 |
| US-78-9 | the keyboard path is findable | help panel · `active_bindings` | `AT-B78-28` | ✅ list not focusable |

**Functional chain (white-box):** HLR-118 → LLR-118.1…3 → `TC-B78-01…03, 40` · HLR-119 → LLR-119.1…4 → `TC-B78-04…08, 41` · HLR-120 → LLR-120.1…5 → `TC-B78-09…13, 42, 43` · HLR-121 → LLR-121.1…4 → `TC-B78-14…16, 44` · HLR-122 → LLR-122.1…4 → `TC-B78-17…22` · HLR-123 → LLR-123.1…3 → `TC-B78-23…28, 45` · HLR-124 → LLR-124.1…4 → `TC-B78-29…33` · HLR-125 → LLR-125.1…2 → `TC-B78-34…37` · HLR-126 → LLR-126.1 → `TC-B78-38, 39`.

**Both chains exist for all nine stories. Zero orphans on either side.**

### 5.5 ID reconciliation — QA lane → canonical (C-40 limb 2, instance ii)

**Rule applied:** the architect allocation is canonical (superset, bound to the LLR structure). Every QA AT is mapped **by subject, never by number**. **Zero QA ATs are unaccounted for.**

| QA id | QA subject | → Canonical | Disposition | Reason |
|---|---|---|---|---|
| `AT-B78-01` | row absent + child ids + `#command_bar_slot` height 0 | **`AT-B78-01`** | **MERGED** | Same subject. **QA's clauses adopted wholesale** — the child-id set and the slot-height clause are stronger than my query-only form; the slot clause defeats a delete-the-row-keep-the-height implementation. |
| `AT-B78-02` | Ctrl+K + action set from the producer | **`AT-B78-02` + `AT-B78-03`** | **MERGED (split)** | Same subject, two observables. **QA's PIN labelling adopted** — I had it as an ordinary AT and it is green today. |
| `AT-B78-03` | `/`·`g` on the 3 owning screens, `OWNING` derived | **`AT-B78-04`** | **MERGED** | Same subject. **QA's derived-set + `len(OWNING) == 3` completeness guard adopted** — my version hand-named the three screens. |
| `AT-B78-04` | wrong-pane, `== ""` clause | **`AT-B78-06`** | **MERGED** | Same subject; both lanes had the `== ""` clause. **QA's loaded-image fixture adopted** — mine rested on Phase-0's unloaded probe, where `_handle_search` bails before searching. |
| `AT-B78-05` | 7-screen notice at `#log_line_4` + count delta | **`AT-B78-05`** | **MERGED** | Same subject. **QA's surface corrects mine** — I specified `#status_text`, which `set_status` never writes (P-40b). Without this merge the AT would have been vacuous. |
| `AT-B78-06` | `Esc` releases | **`AT-B78-07`** | **MERGED** | Same subject. **QA's "must not shadow the palette's `escape`-to-close" constraint adopted** into LLR-119.3. |
| `AT-B78-07` | Loaded panel carries the PROJECT name | **`AT-B78-09`** | **MERGED** | Same subject; both lanes independently found the A2L half vacuous and dropped it. |
| `AT-B78-08` | status bar carries both, 10 screens | **`AT-B78-08`** | **MERGED** | Same subject, identical scope. |
| `AT-B78-09` | the update PATH, variant switch, both surfaces | **`AT-B78-10`** | **MERGED** | Same subject. **QA's PIN labelling and its "record the substituted value" discharge adopted.** |
| `AT-B78-10` | local search/goto unchanged (C-12 pair) | **`AT-B78-12`** | **MERGED** | Same subject. **QA's output-then-consume shape adopted over mine** — I said "compare against a committed capture", QA specifies a prior-commit artifact re-read **from disk**, which removes the hand-written oracle. Its executed digest triple is carried into §5.3. |
| `AT-B78-11` | AST + CSS-selector census | **`AT-B78-13`** | **MERGED** | Same subject; both lanes specify an AST census (C-42 mechanic 5). **My CSS span is corrected to `:66-102`** (P-49) — QA carried Phase-0's `:55-102`, which would delete the surviving `#command_bar` block. |
| `AT-B78-12` | keyboard reachability, `set(range(R))` | **`AT-B78-15`** | **MERGED** | Same subject. **QA's set-equality over `range(R)` adopted** — my "4 downs → index 4" is weaker and would pass an implementation that can reach only a prefix. |
| `AT-B78-13` | mouse-only, incl. off-viewport row | **`AT-B78-16`** | **MERGED** | Same subject. **QA's `scroll_visible` + off-viewport clause adopted** — it closes the "list scrolls past the viewport" clause I had left to inspection. |
| `AT-B78-14` | selection visible, style triple, ≥2-row guard | **`AT-B78-17`** | **MERGED** | Same subject. **QA's resolved-style-triple observable and the ≥2-row vacuity guard adopted** — mine asserted a class, which is style *intent*, not the resolved result. |
| `AT-B78-15` | caps + notice, rewritten | **`AT-B78-18`** | **MERGED** | Same subject. **QA's rewrite replaces my form outright.** Mine said "the predicate quotes `DISPLAY_MAX_RUNS`" — precisely the shape QA's mutation proved **INERT**. This merge fixes a defect of mine. |
| `AT-B78-16` | report completeness through the written FILE | **`AT-B78-31`** | 🆕 **NEW** | **No counterpart in my set.** I asserted the caps bound the panel but never observed the report. A genuine gap; minted from `AT-B78-31`. |
| `AT-B78-17` | windows follow selection, key/click-driven | **`AT-B78-20`** | **MERGED** | Same subject. **QA's "first data row address within `[start−ctx, start]`" clause adopted** — stronger than my address-in-header check. |
| `AT-B78-18` | row count derives from pane height | **`AT-B78-21`** | **MERGED** | Same subject. **QA's `≤ clipped visible height` clause adopted** — it kills a "just make it 40" fix that my strict-inequality form alone would pass. |
| `AT-B78-19` | no wrapped row, both regimes | **`AT-B78-23` + `AT-B78-24`** | **MERGED (split by arm)** | Same subject. Sizes re-based to 160×40 / 132×44 / 120×30 per R-4 and C1; **QA's "actually on screen" clipped-width clause adopted.** |
| `AT-B78-20` | the regimes are observably different | **`AT-B78-25`** | **MERGED, and UNBLOCKED** | Same subject. QA labelled it a PIN blocked on B-2; **R-1's three-regime ruling unblocks it and it becomes a GATE.** |
| `AT-B78-21` | clipped heights, rows 1, results ≥3 | **`AT-B78-26` + `AT-B78-27`** | **MERGED (split)** | Same subject. **QA's `#diff_status` visible clause adopted** — my form omitted the status line, which also clips to 0 today. |
| `AT-B78-22` | discoverability + 14 chips undisplaced | **`AT-B78-28`** | **MERGED** | Same subject. **QA's 14-chip / 78-column census adopted** as the numeric bound. |

**Outcome: 21 MERGED · 1 NEW (`AT-B78-31`) · 0 RETIRED.** No QA observable was dropped. In **nine** cases QA's predicate was stronger than mine and replaced it; in **two** of those (`AT-B78-05`'s surface, `AT-B78-18`'s cap form) the merge corrected an outright defect in my lane.

**QA `TC` reconciliation:** `TC-01` (slot height) → merged into `AT-B78-01` + `TC-B78-40` · `TC-02` (routing on `_active_screen_key`) → 🆕 `TC-B78-41` · `TC-03` (C-17 both new sinks) → merged into `TC-B78-12` · `TC-04` (`DISPLAY_CONTEXT_BYTES` retires/floors) → 🆕 `TC-B78-45` · `TC-05` (80×24 bounded degradation) → merged into `TC-B78-32`, **upgraded from a pin to a gate by R-1** · `TC-06` (pre-change artifact capture) → 🆕 `TC-B78-44` · `TC-07` (palette entry set) → merged into `AT-B78-03`, **decided at 37** (D-3) · `TC-08` (per-arm CC-1 harness) → folded into §5.1 rule 7 as a standing gate rule rather than a node. **3 merged · 3 new · 2 folded.**

### 5.6 ID sizing
**31 `AT-B78-nn` + 45 `TC-B78-nn` = 76 batch-scoped ids.** Outside `AT-TC-REGISTRY.jsonl`'s authority by spec §2.3 (letter-initial bodies); no reservation PR; `_meta.next_free` (`AT-282`/`TC-613`) **not** advanced.

---

## 6. Appendices

### 6.1 Glossary — §1.3.

### 6.2 Design decisions
- **D-3 (Phase 0, operator):** Lane 1 + Lane 2 only. Upheld; Lane-3 carries in §6.4.
- **D-7 (Phase 0, autonomous):** batch-scoped ids. Upheld, sized §5.6.
- **D-9 (architect):** `R-TUI-104`, `HLR-118`/`LLR-118`, both from union-corpus greps.
- **D-10 (architect):** **US-78-8 promoted to prerequisite** of US-78-6/7 — measured, confirmed by the orchestrator's own re-execution.
- **D-11 (R-3):** `Enter → open-in-hex` OUT, carry C-78-d.
- **D-12 (architect):** US-78-3's Loaded-panel clause re-scoped to the project string.
- **D-13 (R-1, operator):** **three regimes**, boundary derived two-axis (§2.8 D-1). Closes OQ-1.
- **D-14 (R-2):** S-5's keymap is arrows + Enter, **widget-scoped**; `n`-only next/prev deliberately absent.
- **D-15 (R-4):** **Lane 2 first, Lane 1 last**; Lane-2 ATs written at 132×44.
- **D-16 (fold):** QA's `L_outer ≤ C − 84` superseded by the architect's `L ≤ C − 89`; QA's `W ≥ 94` supersedes the architect's "from 100 up". Both settled by execution (P-34b/P-34c).

### 6.3 Self-caught defects at draft time

| # | Defect | Consequence |
|---|---|---|
| **F-1** | The architect's first geometry probe measured the row with `render_hex_view_text` (**81**) — the same producer §9 used. Caught only by running the panel's *own* rendered text as a second arm and getting 79. **Every S-7 threshold would have been 2 cells conservative.** |
| **F-2** | `CommandBar.palette_is_open` called as a method; it is a **property** → `TypeError: 'bool' object is not callable`. Failed loudly; recorded in LLR-118.2. |
| **F-3** | `TemporaryDirectory` cleanup raised `PermissionError [WinError 32]` holding `.s19tool/logs/s19tui.log` — **the same failure batch-77 recorded as its F-1**. Two-batch recurrence → carry C-78-e. |
| **F-4** | **A phantom value in an acceptance.** `TC-B78-11` first asserted `(1/1)` for a single-variant project. `app.py:11332` gates the counter on `> 1` and `tests/test_tui_variants.py:259` pins the plain form — a **C-36 phantom that would have false-failed a correct implementation while contradicting a shipped acceptance.** Root cause: *a display form asserted without executing it.* |
| **F-5** | **A breakpoint reported without its units.** 136 (CSS box) vs 139 (content) are the same fact; my *reporting* was wrong because a breakpoint with no unit is not re-derivable. Reconciled across 9 widths (P-32b/P-34b). |
| **F-6** | **QA's cap predicate was INERT and the shape was mine too.** QA's first form stayed GREEN under `DISPLAY_MAX_RUNS 128 → 100000` because its expected value was read from the class under test; **my `AT-B78-18` said "the predicate quotes `DISPLAY_MAX_RUNS`"** — the same defect. Rewritten (LLR-122.3). *A cap AT that expects the constant certifies the constant, not the capping.* |
| **F-7** | QA's first `active_bindings` reader crashed on `too many values to unpack (expected 3)` — the binding tuple shape differs from what batch-77's document assumed. No conclusion was drawn from the crashed run. **A probe that dies after printing partial results is the shape that gets misread as complete.** |
| **F-8** | QA's first geometry probe read `region.width` and looked like it contradicted Phase 0, which read `size.width`. **A disagreement between two honest measurements is usually an undefined term** — here "column width". §1.3 now states which of the two any figure is. |

### 6.4 Carries

| # | Carry | Disposition |
|---|---|---|
| **C-78-a** | Snapshot per-cell census owed at Phase 3: 29/29 carry `Project:`/`A2L:`, but `Goto&#160;0xADDR` renders in only 8/29 and `Find&#160;ASCII` in 0/29 | C-22 at Phase 3; regen CI-only |
| **C-78-b** | `tests/test_tui_patch_json.py:791-792` cites `screens_directionb.py:4269/:4270` for `AbDiffPanel`'s kind colours — **~2 400 lines stale** | Lane-A carry |
| **C-78-c** | `app.py:6232`'s width breakpoint is a bare literal `120` that 11 CSS rules depend on | Lane-A carry |
| **C-78-d** | `Enter → open-in-hex` needs a "render an arbitrary image in the hex view" capability that does not exist | Lane-A carry (D-11) |
| **C-78-e** | `TemporaryDirectory` cleanup fails on Windows because the app holds `s19tui.log` — second batch running | Lane-A carry (test helper) |
| **C-78-f** | **Lane-3 handoff input:** (i) `x` does **not** become free this batch; (ii) G2 will fire the same way when S-13 deletes `test_operations.py` nodes — **LLR-121.3 is the template**; (iii) the `wire-kernel-into-crc.py` deferred item intersects S-10…S-12 and its relationship must be stated (supersedes / defers / absorbs), not silently absorbed | **Lane-3 handoff charter**, a deliverable of this close |
| **R-1** | 29-golden drift diverges local runs from CI | Regen in canonical CI only; state the suite form |
| **R-2** | Lane collision in `tests/test_tui_directionb.py` | **Dissolved by routing** (P-45) |
| **R-7** | The widget-type swap can empty a query silently | C-38: 8 hits / 3 files re-pointed before the change runs |
| **R-8** | **Security posture:** no new I/O, network, credential or external-tool surface. The only new data path is display text reaching a label | Bounded by C-17 (LLR-120.4), driven by `TC-B78-12`. No `security-reviewer` sign-off required for this scope — stated as a judgement, not a finding |
| **R-9** | 🆕 **A parallel session is writing `prototypes/memmap2.*` in this tree.** Both lanes observed a *different* untracked set than Phase 0 recorded | Increment ordering must assume concurrent writes; **no lane touched those files** |

### 6.5 Requirement amendments (Before / After)

#### Amendment A — `R-TUI-022` (`REQUIREMENTS.md:594-602`)

- **Before** (verbatim, `:594-596`):
  > "**R-TUI-022**: The TUI must present a persistent top command bar exposing a searchable (type-to-filter) command palette plus a find input and a go-to-address input, reachable from every Direction B screen."
- **After:**
  > "**R-TUI-022**: The TUI must present a persistent, searchable (type-to-filter) command palette reachable from every Direction B screen. Find and go-to-address are reached by the `/` and `g` bindings, which act on the active screen's own find and go-to inputs; a screen owning neither surfaces a single log-tail notice."
- **Deleted tokens:** "top command bar", "plus a find input and a go-to-address input".
- **New tokens:** the palette as the bar's sole content; the `/`·`g` active-screen routing; the notice path.
- **Preserved:** the palette's type-to-filter behaviour, its reachability from **every** screen, and its `Code:` pointer to `command_bar.py`.
- **Verifier impact:** `tc006` (present on every screen) and `tc036` (type-to-filter) survive unchanged; `tc007`'s palette-population clause survives at **37** actions (D-3). The find/goto clauses of `LLR-003.1`/`004.1`/`004.2` are **retired**, superseded by `HLR-119`.

#### Amendment B — `R-TUI-036` (`REQUIREMENTS.md:1130-1138`)

- **Before** (verbatim, `:1130-1133`):
  > "**R-TUI-036**: When the validation issues table is promoted to its own rail screen, the project-name and A2L-filename status content (see `R-TUI-016`) must render in the persistent command bar so it stays visible from every Direction B screen. `R-TUI-016` is not regressed by the move."
- **After:**
  > "**R-TUI-036**: The project-name and A2L-filename status content (see `R-TUI-016`) must render in the persistent status bar (`#workspace_status_bar`) so it stays visible from every Direction B screen, and the project name must additionally render in the Workspace Loaded panel. `R-TUI-016` is not regressed by the move."
- **Deleted tokens:** "in the persistent command bar"; the issues-table framing (spent).
- **New tokens:** `#workspace_status_bar` as the app-wide home; the Loaded panel as the second surface.
- **⚠️ Preserved deliberately — and it is the reason the operator's option C is right:** *"so it stays visible from every Direction B screen"* is this requirement's **stated intent**, and it is exactly the property `#loaded_panel` alone cannot satisfy (it is composed inside `#screen_workspace` only). Re-homing to the Loaded panel alone would have silently regressed `R-TUI-036`'s own clause from 10 screens to 1.
- **Verifier impact:** `tc038` is re-pointed at the two new surfaces; the display-form contract (LLR-005.3/005.5) moves with it, guarded by the 16 re-pointed `_project_label()` call sites (LLR-121.4).

---

## 7. Increment plan (dependency-ordered, ≤5 files each) — **Lane 2 first, Lane 1 last (R-4)**

**Why this order.** The conflict between D-10 (S-8 first) and C-30 (snapshot sequencing) dissolves on measurement: **the diff result area is already visible at 132×44 with 11 clipped rows today**, so Lane 2's acceptances are observable at 132×44 **without any Lane-1 work**. C-30 therefore governs — S-1 drifts **29 of 29** cells while each Lane-2 increment drifts **1**, so Lane 1 first would `xfail` 28 cells from increment 1 and ship all of Lane 2 with no snapshot coverage.
**The exception, made explicit:** `AT-B78-24`'s 120×30 arm, `AT-B78-25`'s fallback arm, `AT-B78-27` and `AT-B78-29` depend on **US-78-8 and US-78-1**. Those arms land in **Inc-9**, on the Lane-1 side.

| Inc | Content | ATs realized | Files | Gate |
|---|---|---|---|---|
| **Inc-0** | Pre-change artifact capture: the 9-row search/goto payload + the 37-action palette list, **own commit, before any production edit** | (enables `AT-B78-12`, `AT-B78-03`) | `tests/test_tui_commandbar.py`, `tests/_artifacts/…`, `.gitattributes` (3) | artifacts committed; captured from the **shipped surface** (C-35); `git show` confirms the stored blob |
| **Inc-1** | **HLR-125** — compact the control rows *(Lane 2 opens; enables everything below)* | `AT-B78-26` | `styles.tcss`, `tests/test_tui_diff_screen.py` (2) | full `test_tui_directionb.py` (C-34); clipped-height arms at 120×30 **and** 132×44 |
| **Inc-2** | **HLR-122** — selectable run list + the C-38 sweep in the same increment | `AT-B78-15…19` | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_diff_screen.py`, `tests/test_tui_diff_compare_realpath.py` (4) | C-34 + full `test_tui_diff_compare_realpath.py` + full `test_tui_patch_big.py` (C-26, 25 refs / 5 files); `TC-011` green |
| **Inc-3** | **LLR-122.4** — report completeness through the written file | `AT-B78-31` | `tests/test_tui_diff_screen.py` (1) | C-34; the `runs=panel._runs` mutation **executed** and pasted |
| **Inc-4** | **HLR-123** — windows follow selection; height-derived rows | `AT-B78-20…22` | `screens_directionb.py`, `tests/test_tui_diff_screen.py` (2) | C-34; `AT-B78-21`'s strict inequality green at **132×44 vs 132×60** |
| **Inc-5** | **HLR-124** wide + fallback layouts and the notice regime *(width arms only)* | `AT-B78-23`, `AT-B78-25` (wide arm) | `screens_directionb.py`, `app.py`, `styles.tcss`, `tests/test_tui_diff_screen.py` (4) | C-34; C-22 per-cell census on the single diff cell |
| **Inc-6** | **HLR-126** — discoverability | `AT-B78-28` | `screens_directionb.py`, `tests/test_tui_diff_screen.py` (2) | C-34; `git diff` over `app.py:1338-1375` = 0 lines |
| **Inc-7** | **HLR-120** — context onto both surfaces, both display forms *(Lane 1 opens)* | `AT-B78-08…11`, `AT-B78-30` | `app.py`, `screens_directionb.py`, `styles.tcss`, `tests/test_tui_commandbar.py` (4) | C-34; ⚠️ `tests/test_tui_app.py`'s three stubs are **not** evidence (P-38b) |
| **Inc-8** | **LLR-121.4** — re-point the 16 `_project_label()` call sites + the `test_tui_directionb.py` reads, **while both surfaces exist** | (protects `AT-B78-30`) | `tests/test_tui_patch_variant.py`, `tests/test_tui_variants.py`, `tests/test_tui_directionb.py` (3) | those three suites green; `grep -rn 'cmdbar_project' tests/` → 0 |
| **Inc-9** | **HLR-119** — re-home `/`·`g`; the notice at the log tail; the `Esc` release. **Plus HLR-124's fallback/notice arms**, which need S-8 **and** the bar's rows | `AT-B78-04…07`, `AT-B78-24`, `AT-B78-25` (fallback), `AT-B78-27`, `AT-B78-29` | `app.py`, `screens_directionb.py`, `tests/test_tui_commandbar.py`, `tests/test_tui_diff_screen.py` (4) | C-34; `_PRE_BATCH_BINDINGS` unchanged; per-arm verdicts at 80×24 / 120×30 / 132×44 / 160×40 |
| **Inc-10** | **HLR-118** — delete `#command_bar_row` + CSS `:66-102` | `AT-B78-01…03` | `command_bar.py`, `styles.tcss`, `tests/test_tui_commandbar.py` (3) | C-34; palette **10/10**, **37** entries; `#command_bar_slot` height 0 |
| **Inc-11** | **HLR-121** — delete the messages, adapters and helpers; reconcile the registry | `AT-B78-12…14` | `command_bar.py`, `app.py`, `tests/test_tui_commandbar.py`, `tests/test_tui_directionb.py`, `AT-TC-REGISTRY.jsonl` (5) | C-34 **and** `test_id_registry.py` G1–G7; `git diff` over the six handlers = 0 |
| **Inc-12** | **Snapshot regen — canonical CI only**, one PR | — | 29 snapshot SVGs | full suite (**FULL** form); C-22 per-cell |

**No increment edits a file another in-flight increment edits.** Lane 2 (Inc-1…Inc-6) touches `tests/test_tui_diff_screen.py`; Lane 1 (Inc-7…Inc-11) touches `tests/test_tui_commandbar.py` and `tests/test_tui_directionb.py`. Inc-9 is the single crossing point and it lands after both lanes' prerequisites.

---

## 8. Open decisions

**None blocking.** `OQ-1` is **CLOSED by operator ruling R-1** (three regimes, boundary derived in §2.8 D-1). QA's B-1 closed by R-2, B-2 by R-1, B-3 by D-3, B-4 by D-12, B-5 by P-31, B-6 by P-38, B-7 by R-4/D-10, B-8 by P-40b.

Five items carry an explicit `assumed — verify at Phase 3` flag rather than a guess:

| # | Flagged claim | Owner |
|---|---|---|
| **A-1** | `_DIFF_MIN_ROWS_H = 29` — derived from a simulation (`styles.height = 1`), not from the real S-8 implementation | Inc-5/Inc-9 |
| **A-2** | The fallback overlay's dismissal mechanism, which must not shadow the palette's `escape` | Inc-5 |
| **A-3** | `Escape`-to-release's mechanism (Input-scoped binding / `on_key` / screen-level priority) | Inc-9 |
| **A-4** | Stock `ListView` bindings vs the four `priority=True` App bindings (P-47, honest UNDECIDABLE) | Inc-2 |
| **A-5** | The registry status transition for a row left with an empty `nodes` list | Inc-11 |
| **A-6** | `LLR-123.2`'s row-centring arithmetic and `LLR-123.3`'s `_KIND_LABEL` line | Inc-4 |

---

## 9. Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | §2.4 — 16 constraints, each a `file:line` re-derived this session or an executed value |
| ≥2 alternatives considered | ✓ | §2.8 D-1 (four layouts × three regimes, measured matrix), D-2 (four clauses ruled individually), D-4 (two binding policies) |
| Recommendation tied to constraints | ✓ | D-1's regimes tied to C1/C2 and to the derived two-axis floor; D-4 tied to C10 (`TC-011`) and C16 (the 14-chip Footer) |
| Risks listed | ✓ | §6.4 — 6 carries + 5 risks; **security = R-8**, a bounded judgement with its C-17 control named |
| Cost / latency estimated | ✓ | Column and row budgets are this design's cost axis: §2.4 C3–C7, §2.8 D-1, LLR-123.2, LLR-124.2/.3/.4, LLR-125.2. No new I/O or compute |
| Diagram when flow is non-trivial | ✗ | **Deliberate.** Both lanes are linear producer chains (§2.1). The one non-obvious relationship — the S-7 budget — is a **matrix of measured numbers**, which a diagram would blur |
| What would change the recommendation | ✓ | §2.8 D-1 (option ② if the overlay proves costlier than a class + one binding); §8's six flagged assumptions |
| Two-layer requirements: Acceptance block + AT, both chains | ✓ | All 9 HLRs carry a first-class **Acceptance (black-box)** block; §5.4 carries both chains, **zero orphans** |
| Every AT demonstrated RED pre-change | ✓ | §5.4's RED-today column — 9 of 9, each executed; §5.3's per-predicate transcripts |
| **PINs labelled and never counted as gates** | ✓ | §5.3 — **6 PINs** (`AT-B78-02, 03, 10, 12, 18, 31`) explicitly labelled; four carry an owed mutation at their increment gate |
| **ID reconciliation complete** | ✓ | §5.5 — **22 of 22** QA ATs accounted: 21 MERGED, 1 NEW, 0 RETIRED; plus 8 QA TCs (3 merged, 3 new, 2 folded). **Nine QA predicates replaced mine; two of those corrected outright defects in my lane** |
| Every code claim verified or flagged | ✓ | ~95 `file:line` citations, all re-derived this session. Six claims flagged `assumed — verify at Phase 3` (§8) |
| Normative keyword discipline | ✓ | `shall` appears only in HLR/LLR **Statement** lines and in §6.5's proposed requirement texts. **No `should` in any requirement statement** |
| Probe hygiene (C-46) | ✓ | Every mutation applied **in-process** and reverted, with the predicate re-run GREEN; `git diff --stat -- s19_app/ tests/` **empty**; probes ran from an out-of-repo scratchpad with `PYTHONDONTWRITEBYTECODE=1`. **`state.json`, `PLAN.md`, `00-measurements.md`, `AT-TC-REGISTRY.jsonl` and `prototypes/memmap2.*` were read, never written** |
