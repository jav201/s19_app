# Requirements Document — s19_app — Batch 2026-06-09-batch-06

> **Strict normative convention — IEEE 830 + EARS**
> - `shall` = normative, binding, verifiable requirement. **Only** inside HLR / LLR statements.
> - `should` = informative / explanatory text, **NOT binding**. **Only** outside HLR / LLR statements (rationale, description, context).
> - Any use of `should` inside an HLR / LLR statement is a **writing error** and will be flagged as a blocker in phase 2.
> - `may` = optional. `will` = future declaration or fact about an external actor.

> **Verifiability rule — captured at draft, not at phase-2 gate**
> Every requirement labelled `test` or `analysis` **must** carry TWO fields on its line:
> - **Executed verification:** what EXACTLY runs / is inspected (e.g. `pytest tests/test_tui_mac_layout.py -t TC-001`, `git diff styles.tcss inspection`).
> - **Numeric pass threshold:** the quantitative pass criterion (e.g. `0 errors`, `LLR coverage ≥ 100 %`).
>
> For `demo` (perceptual): describe the observable procedure + the named qualitative criterion.
> For `inspection` (structural): name the file / commit / section to inspect + the observable condition.
>
> **Any `test`/`analysis` LLR missing these two fields is a phase-2 blocker.**

> **LLR symbol-citation rule — captured at draft, not at the phase-3 boundary**
> **Any LLR (or its Acceptance criteria / Executed verification) that names a concrete code symbol — a private field, method, function, class, or widget id — MUST cite a grep-verified `file:line` for that symbol at draft time.** If the symbol does not yet exist (it will be created by the increment), it MUST be explicitly flagged `NEW — created in Phase 3`. Layout-geometry / magic-number constants (pane widths, row counts, byte offsets) MUST either cite a measured value with the measurement method, or be flagged `assumed — verify in Phase 3`.
>
> **Two phase-2 blockers enforce this:** (a) any LLR that names a symbol without a `file:line` citation and without a `NEW` flag; (b) any layout/magic-number constant asserted as fact without a measurement citation or an `assumed` flag.

> **Testing-strategy-vs-ADR rule** — every `test (...)` label is cross-checked against the actual `pyproject.toml` test stack (pytest + Textual `.region`-geometry harness). The repo uses `pytest -q`; CI runs on Python 3.11 (authoritative gate). Local dev may run newer Python (3.14.x). **Textual SVG snapshot baselines are NOT used in this batch** and must never be regenerated locally (project memory).

---

## 1. Introduction

### 1.1 Purpose
Define the requirements for **US-001 — MAC View ↔ A2L Explorer layout parity**: the MAC View hex pane is capped at a fixed width and does not grow with the terminal, while the A2L Explorer hex pane is proportional and grows. This batch brings the MAC View hex pane to A2L's proportional behavior **while guaranteeing a full hex row never truncates** (via a minimum-width floor). TUI/CSS-only.

### 1.2 Scope
**In scope:** the MAC View pane-width / responsive-layout rules in `s19_app/tui/styles.tcss` (`#mac_hex_pane`, `#mac_records_pane`, the two `width-narrow #mac_*` blocks) + the MAC layout tests. **CSS-only** — Phase-1 analysis (§6.2) confirms `_compose_screen_mac` is structurally identical to `_compose_screen_a2l` and needs no change.

**Out of scope (deferred to batch-07+):** US-002 (single JSON hex-first change system; cfdx/.cdfx retired), US-003 (declarative check files), US-004 (project report), US-005 (multiple S19 variants). No parser/engine/model (`core.py`, `hexfile.py`, `range_index.py`, `validation/*`, `models.py`) changes in this batch.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| A2L Explorer | TUI workspace screen (`_compose_screen_a2l`, `app.py:1368`) — tags pane + hex pane, flat `4fr:3fr` proportional split |
| MAC View | TUI workspace screen (`_compose_screen_mac`, `app.py:1449`) — records pane + hex pane |
| hex pane | sub-pane rendering the hex/ASCII dump (`#a2l_hex_pane` / `#mac_hex_pane`) |
| `fr` unit | Textual fractional (proportional) CSS width unit; responsive at every width |
| full hex row | one rendered hex/ASCII line; ~82 cells wide for `HEX_WIDTH=16` (`hexview.py:20`), per batch-05 LLR-002.1 arithmetic |
| floor | `min-width` clamp keeping the hex pane ≥ a full hex row regardless of terminal width |
| width-narrow | CSS class toggled below 120 cols. The **MAC** `width-narrow` rules are removed this batch; the class itself **still toggles** at 120 because it also drives the workspace activity rail (`#workspace_shell.width-narrow #activity_rail`, `styles.tcss:781-786`) — this is out of scope and unchanged |
| body_w | the laid-out width of `#workspace_body` (the pane's parent). **Regime-dependent** (Phase-2 measured): `body_w = term − 24` for term ≥ 120 (activity rail shown), `body_w = term − 6` for term < 120 (rail collapsed). At 120 cols `body_w = 96`; at 250 cols `body_w = 226` |

### 1.4 References
- `CLAUDE.md` (TUI architecture: `app.py` orchestration-only; styles in `styles.tcss`).
- `REQUIREMENTS.md` → `R-TUI-039` (batch-05: MAC pane fixed `width: 82`) — **superseded by this batch** (§6.2).
- batch-05 `01-requirements.md` LLR-002.1 (`#mac_hex_pane width 82`, full-row arithmetic), LLR-002.4 (records-pane ≥1-cell invariant), increment-13 (A2L flat `4fr:3fr` migration).
- Source conversation: operator refinement of 5 user stories (2026-06-09).

### 1.5 Document overview
Standard IEEE-830 layout. §2.6 carries all 5 source stories; only US-001 is active. §3–§5 derived by `/dev-flow` phase 1 (architect + qa-reviewer).

---

## 2. Overall description

### 2.1 Product perspective
The TUI exposes two side-by-side inspection screens that both embed a hex pane. A2L Explorer was migrated (batch-05 increment 13) to a flat `4fr:3fr` proportional split (`styles.tcss:254-262`) that keeps its hex pane responsive at all terminal widths. MAC View was left on the older increment-6 model: `#mac_hex_pane width: 82` fixed (`styles.tcss:282-285`) plus a `width-narrow 35%` regime (`styles.tcss:298-304`). The fixed `82` does not grow on wide terminals — the operator perceives MAC as narrower than A2L on a wide screen.

### 2.2 Product functions
- Size the MAC View hex pane proportionally like A2L Explorer (grows with the terminal), with a minimum-width floor so a full hex row is always readable without truncation.

### 2.3 User characteristics
Single role: **operator** (firmware engineer inspecting MAC records against the S19/hex image in a terminal, typically ≥120 columns wide).

### 2.4 Constraints
- TUI/CSS-only — no parser/engine/model changes.
- Must not regress A2L Explorer, the Patch Editor, or the hex viewer.
- CI gate is Python 3.11 (`.github/workflows/tui-ci.yml`, `pytest -q`).
- No Textual SVG snapshot baseline is created or regenerated (project memory: regenerate only in canonical CI env).
- Documented minimum supported terminal width is 120 columns (carried from batch-05 layout invariants).

### 2.5 Assumptions and dependencies
- **[decided]** Operator chose **proportional + floor** over strict A2L parity: MAC mirrors A2L's `4fr:3fr` ratio AND adds a `min-width: 82` floor on the hex pane, so hex width = `max(82, round(3/7·body_w))` — grows like A2L yet never truncates a full row (strict A2L parity would drop MAC hex to ~41 cells at 120 cols, narrower than today).
- **[decided — Phase-2 gate]** Operator **confirmed keeping floor = 82** after the Phase-2 finding M-1: because `body_w = term − 24` at ≥120 cols, `round(3/7·body_w) < 82` until `body_w ≥ 192` (i.e. terminal ≈ **216 cols**). So the MAC hex pane is **floored at 82 for all widths 120–215 cols** and only grows proportionally above ~216. At common widths MAC hex (82) is therefore *wider* than A2L hex (≈42 at 120) — the floor over-satisfies "full row readable" (the operator's explicit benefit) at the cost of not visibly "growing like A2L" until very wide terminals. Tradeoff accepted.
- **[confirmed — Phase-2 cross-review]** Textual honors `min-width` as a clamp over an `fr` width (an `fr`-sized pane is widened to `min-width` when its proportional share is smaller). **Empirically reproduced by both Phase-2 reviewers** (a `3fr` pane whose share is 41 was widened to 82 at 120 cols). TC-004 remains the regression guard.
- **[measured — Phase-2]** `body_w` is **regime-dependent**, NOT a flat `term − 6`: `body_w = term − 24` for term ≥ 120 (activity rail shown), `body_w = term − 6` for term < 120 (rail collapsed via `styles.tcss:781-786`). Measured anchors: 120→`body_w 96`, 250→`body_w 226`, 119→`body_w 113`. Phase-3 tests read `#workspace_body.region.width` live (so the tests are robust to this); only fixed predictions use these constants.
- A full hex row is **82 cells** (carried from batch-05 LLR-002.1; `HEX_WIDTH=16` at `hexview.py:20`). The floor value reuses this number for traceability.
- A2L Explorer's `4fr:3fr` model is correct and is the reference; the records-pane ≥1-cell invariant (batch-05 LLR-002.4) is carried forward.

### 2.6 Source user stories

> Connextra format: **"As a `<role>`, I want `<goal>`, so that `<benefit>`"**.

| ID | User Story | Source | Status this batch |
|----|------------|--------|-------------------|
| US-001 | As an operator inspecting MAC records against the hex image, I want the MAC View hex pane to use the same proportional, responsive layout as A2L Explorer, so that I can read a full hex row without truncation. | Operator refinement 2026-06-09 | **ACTIVE** |
| US-002 | As an operator, I want a single JSON file as the source of all changes to the loaded S19 (declaring encoding + char-vs-number, supporting alphanumeric-string patches and single-address patches, with collision checks and a per-location summary of whether it is standalone memory or linked to MAC/A2L), so that I stop juggling multiple cfdx/memory/unified windows. **Decision: retire the cfdx/.cdfx parameter flow; JSON is the single source of truth (ASAM .cdfx export dropped).** | Operator refinement 2026-06-09 | Deferred → batch-07 |
| US-003 | As a QA-responsible operator, I want declarative check files (expected values) compared against the real S19/hex contents, runnable automatically per project, so that each project can assert and report its expected state. | Operator refinement 2026-06-09 | Deferred → batch-07 |
| US-004 | As an operator, I want a project report declaring modified files, changed values (before→after), executed checklists, and a hexdump of each modified region with ±64 adjustable surrounding bytes, so that the project's changes are auditable. | Operator refinement 2026-06-09 | Deferred → batch-07 |
| US-005 | As an operator, I want several S19 variants in one project sharing the same A2L and MAC, so that change scripts and checks can run in batch or per-variant, all reflected in the report. | Operator refinement 2026-06-09 | Deferred → batch-07 |

> **Refinement decisions locked 2026-06-09:** (1) US-002 retires cfdx/.cdfx in favor of a single JSON system; ASAM `.cdfx` export dropped. (2) Batching: batch-06 = US-001 only; batch-07 carries US-002→US-005. (3) US-001 layout model = **proportional + min-width floor** (not strict A2L parity). (4) **Phase-2 gate:** operator confirmed keeping **floor = 82** despite the M-1 finding that, with `body_w = term − 24`, the MAC hex pane stays floored at 82 for all widths 120–215 cols (proportional growth begins ~216 cols). Benefit prioritized: a full hex row is always readable at ≥120 cols.

---

## 3. High-level requirements (HLR)

### HLR-001 — MAC View hex pane uses A2L's proportional layout with a full-row floor
- **Traceability:** US-001
- **Statement:** While the MAC View screen is displayed at a terminal width ≥ 120 columns, the TUI **shall** size `#mac_records_pane` at `4fr` and `#mac_hex_pane` at `3fr` — the same flat proportional ratio A2L Explorer applies to `#a2l_tags_pane` (`4fr`, `styles.tcss:254-257`) and `#a2l_hex_pane` (`3fr`, `styles.tcss:259-262`) — and **shall** clamp `#mac_hex_pane` to a minimum width of 82 cells, such that the MAC hex pane width equals `max(82, round(3/7 · body_w))` at every such width, with no fixed-width cap and no width-breakpoint regime.
- **Rationale (informative):** A2L's flat `4fr:3fr` split keeps its hex pane growing with the terminal; MAC's fixed `width: 82` cap does not grow, and its `35%` narrow regime is a second code path the operator perceives as inconsistent. Mirroring A2L removes the cap and the breakpoint; the `82`-cell floor guarantees a full hex row stays readable even when the proportional share would be smaller (the operator's explicit benefit).
- **Validation:** `test` + `inspection`
- **Executed verification:** `pytest -q tests/test_tui_mac_layout.py tests/test_tui_directionb.py` driving `App.run_test(size=(W,H))` at `W ∈ {120, 250}`; plus `git diff main -- s19_app/tui/styles.tcss s19_app/tui/app.py` confirming the change is confined to MAC selectors and `#a2l_*` + `app.py` are byte-identical.
- **Numeric pass threshold:** 0 test failures; at 120 cols `80 ≤ #mac_hex_pane.region.width ≤ 86` (floor active); at 250 cols `#mac_hex_pane.region.width > 86` and within `round(3/7·body_w) ± 6` (proportional active); `#mac_records_pane.region.width ≥ 1` at both; `git diff` shows 0 changed lines in any `#a2l_*` block and 0 changed lines in `app.py`.
- **Priority:** high

---

## 4. Low-level requirements (LLR)

> Anchors below are grep-verified (architect, Phase 1) — see §6.4. A2L reference: `#a2l_tags_pane 4fr` (`styles.tcss:254-257`), `#a2l_hex_pane 3fr` (`styles.tcss:259-262`), no `width-narrow` A2L rule (`styles.tcss:240-241`).

### LLR-001.1 — `#mac_hex_pane` width becomes `3fr`, mirroring `#a2l_hex_pane`
- **Traceability:** HLR-001
- **Statement:** The `#mac_hex_pane` rule in `s19_app/tui/styles.tcss` (currently `width: 82;`, `styles.tcss:282-285`) **shall** declare `width: 3fr;`, matching `#a2l_hex_pane` (`width: 3fr;`, `styles.tcss:259-262`).
- **Validation:** `test (integration)` + `inspection`
- **Executed verification:** (inspection) read `styles.tcss`, confirm `#mac_hex_pane` block contains literal `width: 3fr;` and zero `width: 82`; (test) `pytest -q tests/test_tui_mac_layout.py::test_mac_hex_pane_proportional_at_wide_terminal` driving `App.run_test(size=(250,40))` asserting the hex pane grows past 82.
- **Numeric pass threshold:** exactly one `width: 3fr` in `#mac_hex_pane`; 0 occurrences of `width: 82` in the file; at 250 cols `#mac_hex_pane.region.width > 86`.
- **Acceptance criteria:** `width: 3fr` present and byte-equal to `#a2l_hex_pane:261`; pane width is a non-decreasing function of terminal width above the floor.

### LLR-001.2 — `#mac_records_pane` width becomes `4fr`, mirroring `#a2l_tags_pane`
- **Traceability:** HLR-001
- **Statement:** The `#mac_records_pane` rule (currently `width: 1fr;`, `styles.tcss:277-280`) **shall** declare `width: 4fr;`, matching `#a2l_tags_pane` (`width: 4fr;`, `styles.tcss:254-257`).
- **Validation:** `test (integration)` + `inspection`
- **Executed verification:** (inspection) confirm `#mac_records_pane` block contains `width: 4fr;`; (test) `pytest -q tests/test_tui_mac_layout.py::test_mac_records_pane_proportional_at_wide_terminal` driving `App.run_test(size=(250,40))` asserting `records_pct ≈ 57%` and `records_w > hex_w`.
- **Numeric pass threshold:** exactly one `width: 4fr` in `#mac_records_pane`; at 250 cols `100·records_w/body_w` within `57% ± 6pts` and `records_w > hex_w`.
- **Acceptance criteria:** `width: 4fr` present and byte-equal to `#a2l_tags_pane:256`; records pane holds the larger share where proportional dominates.

### LLR-001.3 — `#mac_hex_pane` gains a `min-width: 82` full-row floor
- **Traceability:** HLR-001
- **Statement:** The `#mac_hex_pane` rule **shall** declare `min-width: 82;` (`NEW — created in Phase 3`), so that when `round(3/7·body_w) < 82` the hex pane is widened to 82 cells, keeping a full hex row (82 cells, batch-05 LLR-002.1) readable without truncation.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_tui_mac_layout.py::test_mac_hex_pane_floor_at_120` driving `App.run_test(size=(120,30))` (where `body_w = 96`, so `round(3/7·96) = 41 < 82`) asserting the hex pane is held at the floor.
- **Numeric pass threshold:** at 120 cols `80 ≤ #mac_hex_pane.region.width ≤ 86`; the value is NOT within ±3 of `round(3/7·body_w)` (proves the floor, not the proportional share, is in effect).
- **Acceptance criteria:** `min-width: 82` token present in `#mac_hex_pane`; full hex row fits at the 120-col documented minimum.

### LLR-001.4 — MAC `width-narrow` two-regime is removed (A2L has none)
- **Traceability:** HLR-001
- **Statement:** The two MAC narrow-regime rules — `#workspace_body.width-narrow #mac_hex_pane { width: 35%; }` (`styles.tcss:298-300`) and `#workspace_body.width-narrow #mac_records_pane { width: 1fr; }` (`styles.tcss:302-304`) — **shall** be deleted, so the flat `4fr:3fr` + floor model (LLR-001.1/.2/.3) is the single layout regime at all widths, matching A2L which declares no `width-narrow` rule (`styles.tcss:240-241`).
- **Validation:** `test (integration)` + `inspection`
- **Executed verification:** (inspection) grep `s19_app/tui/styles.tcss` for `width-narrow #mac` → 0 matches; (test) `pytest -q tests/test_tui_mac_layout.py::test_mac_hex_floor_holds_across_retired_breakpoint` driving `App.run_test` at `(121,30)` and `(119,30)` asserting the hex pane is held at the floor on both sides of the retired MAC breakpoint.
- **Numeric pass threshold:** 0 selectors matching `width-narrow.*#mac_` in `styles.tcss`; `hex_w(121)` and `hex_w(119)` are each within `80 ≤ hex_w ≤ 86` (both floored to 82 — the retired MAC `35%` regime no longer applies on either side).
- **Acceptance criteria:** both narrow-regime MAC blocks removed; the MAC hex pane obeys the single `4fr:3fr`+floor regime at all widths. **Note (Phase-2 M-2):** a residual *body-width* discontinuity persists at 120 cols (`body_w` jumps 113→97 as the activity rail appears, `styles.tcss:781-786`) — that is the rail's, NOT a MAC-selector discontinuity, and is out of scope. This LLR verifies the absence of a *MAC-rule* regime switch (floor pins both sides), not body continuity.

### LLR-001.5 — Records pane keeps ≥1 cell at the 120-col boundary (carry-forward of batch-05 LLR-002.4)
- **Traceability:** HLR-001
- **Statement:** While the terminal width is ≥ 120 columns, `#mac_records_pane.region.width` **shall** be ≥ 1 cell under the new `4fr` + floor model, preserving the batch-05 LLR-002.4 records-pane invariant (at 120 cols, with hex floored to 82 of `body_w = 96`, records receives `= 14` cells — ≥1 with a ~14-cell margin; floored records `= body_w − 82`).
- **Validation:** `test (integration)`
- **Executed verification:** `pytest -q tests/test_tui_mac_layout.py::test_mac_records_pane_positive_width_at_wide_terminal` (existing test, reused unchanged) driving `App.run_test(size=(120,30))` asserting `query_one("#mac_records_pane").region.width >= 1`.
- **Numeric pass threshold:** 0 failures; `#mac_records_pane.region.width ≥ 1` at 120 cols.
- **Acceptance criteria:** existing TC passes without modification under the new model.

### LLR-001.6 — Change is CSS-only; `#a2l_*` rules and `app.py` untouched; diff confined
- **Traceability:** HLR-001
- **Statement:** The increment **shall** modify only the MAC selector rules in `s19_app/tui/styles.tcss` (`#mac_hex_pane`, `#mac_records_pane`, the two deleted `width-narrow #mac_*` blocks) plus the MAC layout test files; it **shall** leave `#a2l_tags_pane` / `#a2l_hex_pane` (`styles.tcss:254-262`) byte-identical and **shall not** modify `_compose_screen_mac` (`app.py:1449`) or any other `app.py` / parser / engine / model file.
- **Validation:** `inspection` + `test (integration)` guard
- **Executed verification:** `git diff main -- s19_app/tui/styles.tcss s19_app/tui/app.py`; plus `pytest -q tests/test_tui_directionb.py -k "a2l"` as an automated A2L-width regression guard.
- **Numeric pass threshold:** `app.py` diff = 0 lines; `#a2l_*` blocks = 0 changed lines; 0 parser/engine/model files (`core.py`, `hexfile.py`, `range_index.py`, `validation/*`, `models.py`) in the diff; A2L width guard test passes.
- **Acceptance criteria:** diff confined to MAC CSS rules + tests; A2L reference model provably preserved. The **`git diff` byte-identity of the `#a2l_*` blocks is the authoritative A2L-invariance guard** (Phase-2 m-2); the `-k a2l` band test is a secondary behavioral backstop only (a `3fr→43%` swap would pass the band but fail the diff). **Comment-block update (Phase-2 m-1):** the MAC layout comment at `styles.tcss:264-270` is updated to the proportional+floor model — pass threshold: 0 references to `35%`, `width: 40`, `width: 82`, or `fixed-width` remain in MAC comments (the comment is currently stale: it still says `width: 40`).

---

## 5. Validation strategy

### 5.1 Methods
- **Test (integration) — primary.** The existing suite boots the live app via `App.run_test(size=(W,H))`, switches to the MAC screen, and reads laid-out `#id.region.width` cell geometry (`tests/test_tui_mac_layout.py`, helper `_mac_layout_dims`). This exercises the real TCSS cascade + Textual layout solver; deterministic because terminal size is pinned by `size=`. Reuse verbatim; assert **percentage-of-body bands** (±5–6 pts) and the floor band, not exact cell counts (robust to ±1-cell border rounding).
- **Inspection — secondary.** `git diff` confirms A2L rules byte-identical, `app.py` untouched, diff confined to MAC rules. Backed by an automated A2L-width pytest guard so a silent A2L breakage still fails CI.
- **Demo / analysis — not applicable** (pass criterion is numeric cell-width geometry, not perceptual or formal).
- **Snapshot tests — deliberately NOT used.** `.region`-geometry assertions give the same guarantee without an SVG baseline; per project memory, baselines may only be regenerated in the canonical CI env. The whole batch stays local-safe.

### 5.2 Coverage table

| Requirement | Method | Test Case ID | Executed verification | Numeric pass threshold |
|-------------|--------|--------------|-----------------------|------------------------|
| HLR-001 | test + inspection | TC-001 (roll-up) | `pytest -q tests/test_tui_mac_layout.py tests/test_tui_directionb.py` | 100% of TC-002…TC-007 pass; 0 failures |
| LLR-001.1 | test (integration) + inspection | TC-002 | `pytest -q tests/test_tui_mac_layout.py::test_mac_hex_pane_proportional_at_wide_terminal` (`size=(250,40)`) | hex_w > 86 AND `100·hex_w/body_w` within 43% ± 6pts |
| LLR-001.2 | test (integration) + inspection | TC-003 | `pytest -q tests/test_tui_mac_layout.py::test_mac_records_pane_proportional_at_wide_terminal` (`size=(250,40)`) | `100·records_w/body_w` within 57% ± 6pts AND records_w > hex_w |
| LLR-001.3 | test (integration) | TC-004 | `pytest -q tests/test_tui_mac_layout.py::test_mac_hex_pane_floor_at_120` (`size=(120,30)`) | 80 ≤ hex_w ≤ 86; hex_w NOT within ±3 of round(3/7·body_w) |
| LLR-001.4 | test (integration) + inspection | TC-005 | grep `width-narrow #mac` → 0; `pytest -q tests/test_tui_mac_layout.py::test_mac_hex_floor_holds_across_retired_breakpoint` (`(121,30)` and `(119,30)`) | 0 `width-narrow.*#mac_` selectors; `hex_w(121)` and `hex_w(119)` each within `80 ≤ hex_w ≤ 86` (both floored — no MAC-rule regime switch) |
| LLR-001.5 | test (integration) | TC-006 | `pytest -q tests/test_tui_mac_layout.py::test_mac_records_pane_positive_width_at_wide_terminal` (existing, `size=(120,30)`) | records_w ≥ 1 at 120 cols (measured ≈ 14) |
| LLR-001.6 | inspection + test guard | TC-007 | `git diff main -- s19_app/tui/styles.tcss s19_app/tui/app.py`; `pytest -q tests/test_tui_directionb.py -k a2l` | app.py 0 lines; `#a2l_*` 0 lines (authoritative); 0 engine/parser/model files; A2L guard passes; 0 stale MAC-comment refs (`35%`/`width: 40`/`width: 82`) |
| (re-band existing) | test (integration) | TC-021′ | `pytest -q tests/test_tui_directionb.py::test_tc021_mac_two_panes_fixed_regime` (`test_tui_directionb.py:1355`, band at `:1389`) | old `80 ≤ hex ≤ 84` absolute band (`:1389`) replaced by floor band `80 ≤ hex ≤ 86`; green at (120,30) and (160,40) |

> **Phase-3 must-fix (Phase-2 corrected disposition — measured live, B-2/F-Q-04/F-Q-05):** the batch-05 MAC tests resolve as follows:
> - **REWRITE** `test_mac_hex_pane_narrow_regime_unchanged` (`tests/test_tui_mac_layout.py:139`) — asserts `hex_w < 82` at 119; **fails** (floors to 82). Replacement: TC-005.
> - **REWRITE** `test_tc021_mac_two_panes_proportional_regime` (`tests/test_tui_directionb.py:1399`) — asserts MAC hex 31–39% of body at 80×24 (the `35%` regime); **fails** (becomes ~110% / floored). *This is the test the Phase-1 draft missed.* Replacement: delete (below the 120-col documented minimum) or re-band to the floor model.
> - **RE-BAND** `test_tc021_mac_two_panes_fixed_regime` (`tests/test_tui_directionb.py:1355`, band `:1389`) — = TC-021′ above.
> - **SURVIVES UNCHANGED** `test_mac_hex_pane_width_at_wide_terminal` (`tests/test_tui_mac_layout.py:82`) — asserts `hex_w ≥ 82` (a floor, compatible) + `narrow==0` at 120; both still hold. *(The Phase-1 draft wrongly listed this as must-fix.)*
> - **SURVIVES UNCHANGED** `test_mac_hex_scroll_fills_pane_height` (`:102`), `test_mac_records_pane_positive_width_at_wide_terminal` (`:171` = TC-006), `test_tc021_mac_pane_order_table_then_hex` (`:1438`, pane order unchanged).
>
> Per CLAUDE.md rule 9, rewritten tests encode the new proportional+floor intent — do not loosen bands to mask the contract change.

### 5.3 Batch acceptance criteria
- **LLR coverage = 100%** — every LLR (001.1–001.6) covered by ≥1 passing TC; HLR-001 covered by the TC-001 roll-up.
- **0 regressions** in `pytest -q -m "not slow"` (Python 3.11 CI gate authoritative).
- **Superseded tests resolved** — 0 tests left asserting the retired `35%` MAC narrow regime or the `hex ≤ 84` fixed upper-band cap; the 2 rewrite-targets (`test_tui_mac_layout.py:139`, `test_tui_directionb.py:1399`) and the re-band (`test_tui_directionb.py:1355`) are done and green; the 4 surviving tests pass unchanged.
- **A2L parity guarantee** — A2L-width guard test passes with 0 changes to `#a2l_*` TCSS rules (`styles.tcss:254-262` byte-identical in `git diff`).
- **Diff confinement** — `git diff` touches only `styles.tcss` (`#mac_*` rules), the MAC layout test files, and the dev-flow/requirements docs. 0 files under `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `models.py`, or `app.py`.
- **No SVG snapshot baseline created or regenerated.**

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3.

### 6.2 Relevant design decisions
**Supersede `R-TUI-039`** (batch-05: `#mac_hex_pane { width: 82 }` + two-regime `width-narrow 35%`) with a flat proportional split mirroring A2L's increment-13 model, plus a `min-width: 82` floor.

Exact CSS before → after (`s19_app/tui/styles.tcss`):
```
#mac_records_pane { width: 1fr; }   →   #mac_records_pane { width: 4fr; }
#mac_hex_pane     { width: 82;  }   →   #mac_hex_pane     { width: 3fr; min-width: 82; }

/* DELETE (styles.tcss:298-304): */
#workspace_body.width-narrow #mac_hex_pane     { width: 35%; }
#workspace_body.width-narrow #mac_records_pane { width: 1fr; }
```
`#mac_hex_scroll` (`styles.tcss:290-293`, `height: 100%; overflow: auto`) is kept as-is. The informative MAC layout comment block (`styles.tcss:264-270`) is updated to describe the proportional+floor model (no rule change). **Verdict: CSS-only** — `_compose_screen_mac` (`app.py:1449-1519`) already emits `Horizontal(records_pane, hex_pane)`, structurally identical to `_compose_screen_a2l`. **Phase-6 action:** update REQUIREMENTS.md `R-TUI-039` to the proportional-parity+floor row and repoint its file/test pointers.

### 6.3 Open risks
- **Textual `min-width`-over-`fr` behavior** is **confirmed working** (Phase-2 cross-review: both reviewers reproduced the clamp — a `3fr` pane sharing 41 cells was widened to 82 at 120 cols). TC-004 remains the regression guard; the earlier fallback path is no longer needed.
- **Records-pane starvation (Phase-2 M-3, corrected bounds)**: floored records = `body_w − 82`. With the rail shown (≥120 cols, `body_w = term − 24`), records ≥ 1 ⟺ **term ≥ 107**; with the rail collapsed (<120, `body_w = term − 6`), records ≥ 1 ⟺ **term ≥ 89**. At the 120-col documented minimum, records = `96 − 82 = 14` cells (≥1, ~14-cell margin — tight but safe). Below 107 cols the records pane can clip to empty — out of scope (below the 120-col minimum; graceful clipping, not a crash, per the Phase-2 security pass). The invariant is asserted only at ≥120 (LLR-001.5).
- **Design tradeoff (Phase-2 M-1, operator-accepted)**: with `body_w = term − 24`, the MAC hex pane is floored at 82 for all widths 120–215 cols and grows proportionally only above ~216 cols. So "grows like A2L" materializes only on very wide terminals; at common widths MAC hex (82) is wider than A2L hex (~42). Accepted because the operator prioritized "full hex row always readable" over visible parity.
- **Snapshot-baseline drift**: no snapshot test is added; if anyone proposes one in Phase 3, baseline regen is a CI-env-only action (project memory).
- **Superseded batch-05 tests** must be rewritten, not deleted blindly (intent preservation, CLAUDE.md rule 9). See §5.2 corrected disposition.

### 6.4 Grep-verified anchors (architect, Phase 1)
| Symbol | file:line | Current value |
|---|---|---|
| `#a2l_tags_pane` | `styles.tcss:254-257` | `width: 4fr` |
| `#a2l_hex_pane` | `styles.tcss:259-262` | `width: 3fr` |
| A2L "no width-narrow needed" comment | `styles.tcss:240-241` | informative |
| `#mac_panes` | `styles.tcss:271-274` | `layout: horizontal; height: 100%` |
| `#mac_records_pane` | `styles.tcss:277-280` | `width: 1fr` → `4fr` |
| `#mac_hex_pane` | `styles.tcss:282-285` | `width: 82` → `3fr; min-width: 82` |
| `#mac_hex_scroll` | `styles.tcss:290-293` | `height: 100%; overflow: auto` (unchanged) |
| `#workspace_body.width-narrow #mac_hex_pane` | `styles.tcss:298-300` | `width: 35%` → deleted |
| `#workspace_body.width-narrow #mac_records_pane` | `styles.tcss:302-304` | `width: 1fr` → deleted |
| `_compose_screen_a2l` | `app.py:1368` | `Horizontal(tags_pane, hex_pane)` |
| `_compose_screen_mac` | `app.py:1449` | `Horizontal(records_pane, hex_pane)` — unchanged |
| `HEX_WIDTH` | `hexview.py:20` | `16` (→ ~82-col full row) |
| activity-rail narrow rule (drives `body_w` regime) | `styles.tcss:781-786` | `#workspace_shell.width-narrow #activity_rail` — collapses rail <120 cols; **NOT changed this batch** (explains `body_w = term−24` ≥120 / `term−6` <120) |
| `test_mac_hex_pane_width_at_wide_terminal` | `tests/test_tui_mac_layout.py:82` | asserts `hex_w ≥ 82` + `narrow==0` — **SURVIVES** |
| `test_mac_hex_scroll_fills_pane_height` | `tests/test_tui_mac_layout.py:102` | **SURVIVES** |
| `test_mac_hex_pane_narrow_regime_unchanged` | `tests/test_tui_mac_layout.py:139` | asserts `hex_w < 82` at 119 — **REWRITE** (→ TC-005) |
| `test_mac_records_pane_positive_width_at_wide_terminal` | `tests/test_tui_mac_layout.py:171` | **SURVIVES** (= TC-006) |
| `test_tc021_mac_two_panes_fixed_regime` | `tests/test_tui_directionb.py:1355` (band `:1389`) | **RE-BAND** (= TC-021′) |
| `test_tc021_mac_two_panes_proportional_regime` | `tests/test_tui_directionb.py:1399` | asserts `35%` regime at 80×24 — **REWRITE** |
| `test_tc021_mac_pane_order_table_then_hex` | `tests/test_tui_directionb.py:1438` | pane order unchanged — **SURVIVES** |
| A2L guard tests (`-k a2l`) | `tests/test_tui_directionb.py:1239,1281,1317` (`test_tc019_a2l_*`) | A2L width regression guard for TC-007 |
