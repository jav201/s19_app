# Requirements — s19_app — batch-28 (R-TUI-042) — ARCHITECT SLICE (§3 HLR · §4 LLR · §6 appendices)

> **Merge note (orchestrator):** this file supplies **§3 HLR**, **§4 LLR**, and **§6 appendices** only. §1/§2/§5 (incl. the black-box `AT-NNN` acceptance blocks, boundary catalogs, and the validation-strategy tables) are owned by the qa-reviewer slice. Topic→id mapping is held stable so the qa TCs (`TC-042.N`) line up.
>
> **ID-space disambiguation:** batch-28 story anchors are `HLR-038/039/040/041` and low-level `LLR-042.N`; the batch requirement is `R-TUI-042`. These are **distinct** from batch-27's `R-TUI-041` / `LLR-041.*` (different prefix — `HLR-041` here ≠ `R-TUI-041`/`LLR-041.*` there). Where this slice reuses batch-27 helpers it cites them by `file:line`.
>
> **Normative keyword discipline:** `shall` appears ONLY inside HLR/LLR statements; `should` never appears as a modal inside a statement (rationale/prose only).

---

## 3. High-level requirements (HLR)

### HLR-038.a — A2L Explorer default master/detail (list + record card)
- **Traceability:** US-038
- **Statement:** While an A2L artifact is loaded, the A2L Explorer shall present, as its default layout, a scannable tag list (master) beside a record card that renders all 16 A2L fields of the selected tag as labelled key/value lines, read from the same enriched tag dict the wide table consumes.
- **Rationale (informative):** the wide 16-column table is unreadable per-record; a card makes one record legible. Fields = Tag/Address/Length/Source/Raw/Physical/InMem/Region/Limits/Unit/Bits/Endian/Virt/Func/Access/Dtype (`s19_app/tui/app.py:3127-3143`).
- **Validation:** `test (pilot)` (black-box `AT` owned by qa) + `test` (white-box, LLR-042.1/.2).
- **Priority:** high
- **Acceptance (black-box):** observable outcome = the selected tag's 16 fields appear as labelled key/values in the card · shipped surface = A2L Explorer screen · deliverable = rendered card element · `AT-NNN` owned by qa.

### HLR-038.b — A2L layout-mode toggle (card ⇄ wide 16-col table)
- **Traceability:** US-038 (RESOLVED D1a — retain wide table behind a toggle)
- **Statement:** When the operator presses the A2L layout-toggle key, the A2L Explorer shall switch between the record-card layout and the pre-existing wide 16-column table layout, and the wide-table render path shall remain behaviourally unchanged from its current implementation.
- **Rationale (informative):** the wide table is retained (not deleted) so power users keep the dense cross-tag scan; both layouts are snapshot-tested.
- **Validation:** `test (pilot)` (qa `AT`) + `test` (LLR-042.3) + `inspection` (table path unchanged).
- **Priority:** high
- **Acceptance (black-box):** observable outcome = pressing the toggle key flips card↔table and back · shipped surface = A2L Explorer screen · `AT-NNN` owned by qa (drives the real key binding, not `.focus()` — C-16).

### HLR-039.a — Issues Report worklist (worst-first cards replace flat table)
- **Traceability:** US-039 (RESOLVED D1b — worklist replaces the flat 8-col table)
- **Statement:** While validation issues exist, the Issues Report shall present them as a severity-ordered (worst-first) list of cards, each card showing the issue severity, the artifacts involved, a plain-language message, and the issue address, in place of the prior flat 8-column table.
- **Rationale (informative):** the 8-col table (Severity/Code/Artifact/Related/Symbol/Address/Line/Message, `app.py:3112-3121`) buries the worst finding; a worklist surfaces triage order. Source data = `self._validation_issues: list[ValidationIssue]` (`app.py:764`).
- **Validation:** `test (pilot)` (qa `AT`) + `test` (LLR-042.4/.6).
- **Priority:** high
- **Acceptance (black-box):** observable outcome = the worst-severity issue renders first as a legible card · shipped surface = Issues Report screen · `AT-NNN` owned by qa.

### HLR-039.b — Issues card selection drives retained hex-peek + Open-in jump
- **Traceability:** US-039 (RESOLVED D1b — hex-peek pane STAYS)
- **Statement:** When the operator selects an issue card, the Issues Report shall update the retained hex-peek pane to show the bytes at that card's address, and shall offer per-card Open-in jump action(s) that focus the Workspace hex view on that address.
- **Rationale (informative):** the existing split `#issues_columns` = `#validation_issues_list` (2fr) | `#issues_hex_pane` (1fr) (`styles.tcss:723-738`) is reused; Open-in reuses `update_hex_view(focus_address=…)` + `action_show_screen("workspace")` (pattern at `app.py:7312-7314`).
- **Validation:** `test (pilot)` (qa `AT`) + `test` (LLR-042.5).
- **Priority:** high
- **Acceptance (black-box):** observable outcome = selecting a card repaints the hex-peek at its address; the Open-in action lands the Workspace hex view on that address · shipped surface = Issues Report + Workspace hex · `AT-NNN` owned by qa (real selection event, not `.focus()`).

### HLR-040.a — Workspace per-range coverage micro-bar
- **Traceability:** US-040 (sub-feature a)
- **Statement:** While a file is loaded, the Workspace ranges panel shall render, on each range row, a coverage micro-bar derived by display arithmetic on the already-parsed `ranges`/`range_validity`, without performing any new parse, coverage, or validation computation.
- **Rationale (informative):** `update_sections` already renders per-range rows from `current_file.ranges`/`range_validity` (`app.py:7194-7205`); the micro-bar is an in-row visual over the same numbers.
- **Validation:** `test` (LLR-042.8) + `demo` (visual).
- **Priority:** medium
- **Acceptance (black-box):** observable outcome = each range row carries a proportional coverage micro-bar · shipped surface = Workspace ranges panel · `AT-NNN` owned by qa.

### HLR-040.b — Workspace whole-image memory strip (single-row minimap)
- **Traceability:** US-040 (sub-feature b; RESOLVED D2 — Workspace-only; D3 — NO entropy)
- **Statement:** While a file is loaded, the Workspace shall render a single-row whole-image memory strip whose cells are coloured valid/invalid/gap from the already-computed `ranges`/`range_validity`, reusing the batch-27 cell-status logic, and this strip shall appear only on the Workspace screen.
- **Rationale (informative):** reuses `cell_status` (`s19_app/tui/screens_directionb.py:285`) + `MemoryMapPanel.render_ranges` (`screens_directionb.py:967`) as a rows=1 variant; no entropy sparkline (D3).
- **Validation:** `test` (LLR-042.9) + `demo` (visual).
- **Priority:** medium
- **Acceptance (black-box):** observable outcome = a one-row colour strip spans the image; absent on other screens · shipped surface = Workspace screen · `AT-NNN` owned by qa.

### HLR-040.c — Workspace stat pane (coverage % + range/error/warning counts)
- **Traceability:** US-040 (sub-feature c)
- **Statement:** While a file is loaded, the Workspace shall render a stat pane showing coverage percent and the range, error, and warning counts, all derived by display arithmetic on the already-parsed ranges and the already-computed `_validation_issues`, and shall show no entropy figure.
- **Rationale (informative):** coverage %/range counts reuse `coverage_stats` (`screens_directionb.py:538`, returns `CoverageStats`); error/warning counts are severity tallies over `_validation_issues` (`app.py:764`) — counting, not re-validation.
- **Validation:** `test` (LLR-042.10).
- **Priority:** medium
- **Acceptance (black-box):** observable outcome = coverage %, range/error/warning counts render and track the loaded file · shipped surface = Workspace screen · `AT-NNN` owned by qa.

### HLR-041 — MAC View leading per-row severity glyph
- **Traceability:** US-041
- **Statement:** While MAC records are displayed, the MAC View shall render a leading per-row status glyph (OK / warning / out-of-range) on each row of the existing 8-column MAC table, coloured exclusively through `color_policy.css_class_for_severity`, with no hard-coded severity colour.
- **Rationale (informative):** `update_mac_view` already builds severity-keyed `rich.text.Text` cells (`app.py:7521`); columns Tag/Address/InA2L/InMem/Status/SourceLine/ParseErr/A2LMatch (`app.py:3097-3106`). The glyph is a render-side prefix over the row severity already resolved for the Status column.
- **Validation:** `test` (LLR-042.7) + `inspection` (no severity hex).
- **Priority:** medium
- **Acceptance (black-box):** observable outcome = each MAC row leads with a severity glyph matching its status · shipped surface = MAC View screen · `AT-NNN` owned by qa.

---

## 4. Low-level requirements (LLR)

> Provisional-identifier note (V-5): every `TC-042.N` id, test file path, and `-k` selector below is **provisional-until-Phase-3**; NEW symbols are flagged `NEW — created in Phase 3`. Reconciled at Phase 4.

### LLR-042.1 — A2L record-card widget (16 labelled fields, render-only, markup-safe)
- **Traceability:** HLR-038.a
- **Statement:** The A2L record-card widget shall render, from the selected enriched tag dict, all 16 fields (Tag, Address, Length, Source, Raw, Physical, InMem, Region, Limits, Unit, Bits, Endian, Virt, Func, Access, Dtype) as labelled key/value lines, reading only the already-enriched dict and performing no parse or A2L re-read.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.1` (path/selector provisional)
- **Numeric pass threshold:** TC passes; all 16 field labels present for a representative tag; 0 failures
- **Acceptance criteria:** card shows each of the 16 fields keyed by the enriched dict; empty/absent field renders a neutral placeholder, not a crash.
- **Sources-verified:** column/field set `app.py:3127-3143`; enriched-dict producer `update_a2l_tags_view` `app.py:7827` (same dict the wide table consumes). Card widget symbol/id `NEW — created in Phase 3`.

### LLR-042.2 — A2L master selection → card update via the real selection event (C-16)
- **Traceability:** HLR-038.a
- **Statement:** When a master-list row is highlighted/selected through the actual DataTable row event (not a programmatic `.focus()`), the app shall update the record card to the corresponding enriched tag using the existing `#a2l_tags_list` row-key→tag map.
- **Validation:** `test (e2e)` (Textual Pilot)
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.2` (drives the real highlight/select event via Pilot key/click, asserts card content)
- **Numeric pass threshold:** TC passes; card content changes to the newly-selected tag; 0 failures
- **Acceptance criteria:** selecting a different row repaints the card; the AT drives the real mechanism (batch-27 lesson: arrow/select nav must be wired, not masked by `.focus()`).
- **Sources-verified:** row-key→tag map `self._a2l_row_key_to_tag` built in `update_a2l_tags_view` `app.py:7864`; table id `#a2l_tags_list` `app.py:3125`. Selection handler symbol `NEW — created in Phase 3`.

### LLR-042.3 — A2L layout-mode toggle key (card ⇄ wide 16-col table), table path preserved
- **Traceability:** HLR-038.b
- **Statement:** The A2L Explorer shall bind a key that toggles between the card layout and the pre-existing wide 16-column table layout, and the wide-table render path (`update_a2l_tags_view` producing the 16-cell rows) shall be invoked unchanged when the table layout is active.
- **Validation:** `test (e2e)` + `inspection`
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.3` (Pilot presses the real binding, asserts layout flips both ways); inspection = the wide-table call path is unmodified vs current `update_a2l_tags_view`
- **Numeric pass threshold:** TC passes; toggling flips card↔table and back; wide-table rows identical to pre-batch render; 0 failures
- **Acceptance criteria:** binding registered in the screen's `BINDINGS`; both layouts snapshot-tested (per D1a); no regression to the 16-col table.
- **Sources-verified:** wide-table renderer `update_a2l_tags_view` `app.py:7827`. Toggle binding + layout-state flag `NEW — created in Phase 3`.

### LLR-042.4 — Issues worklist widget (worst-first cards from `_validation_issues`)
- **Traceability:** HLR-039.a
- **Statement:** The Issues worklist widget shall render each `ValidationIssue` in `self._validation_issues` as a card carrying its severity, involved artifact(s), plain-language message, and address, replacing the flat `#validation_issues_list` table in the left slot of the existing `#issues_columns` split.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.4` (path/selector provisional)
- **Numeric pass threshold:** TC passes; one card per issue with severity+artifact+message+address; 0 failures
- **Acceptance criteria:** empty `_validation_issues` → neutral "no issues" state (see LLR-042.12); N issues → N cards.
- **Sources-verified:** `self._validation_issues` `app.py:764`; issue fields per column set `app.py:3112-3121`; existing split `#issues_columns` `styles.tcss:723-738`. Worklist widget symbol `NEW — created in Phase 3`.

### LLR-042.5 — Issues card selection → retained hex-peek + Open-in jump
- **Traceability:** HLR-039.b
- **Statement:** When an issue card is selected through the real selection event, the app shall repaint the retained `#issues_hex_pane` at the issue's address, and each card shall expose an Open-in action that invokes `update_hex_view(focus_address=…)` and `action_show_screen("workspace")`.
- **Validation:** `test (e2e)` (Textual Pilot)
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.5` (Pilot selects a card, asserts hex-peek address; triggers Open-in, asserts Workspace hex focus)
- **Numeric pass threshold:** TC passes; hex-peek address == selected card address; Workspace hex focus == that address; 0 failures
- **Acceptance criteria:** issues with no address route to a neutral hex-peek (no crash); Open-in reuses the established focus path, adds no new hex renderer.
- **Sources-verified:** `#issues_hex_pane` `styles.tcss:734`; Open-in pattern `action_show_screen("workspace")` + `update_hex_view(focus_address=…)` `app.py:7312-7314`; `update_hex_view` signature `app.py:7316`. Card-selection handler `NEW — created in Phase 3`.

### LLR-042.6 — Issues worst-first ordering rule (severity rank + stable secondary sort)
- **Traceability:** HLR-039.a
- **Statement:** The worklist shall order cards by descending severity rank derived from the `color_policy` severity vocabulary, with a deterministic stable secondary key (issue insertion order in `_validation_issues`) so equal-severity issues keep a repeatable order.
- **Validation:** `test (unit)`
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.6` (asserts a mixed-severity list renders worst-first; ties keep source order)
- **Numeric pass threshold:** TC passes; first card == highest severity; tie order == source order; 0 failures
- **Acceptance criteria:** ordering is a pure sort over the already-computed list (no re-validation); severity rank sourced from the frozen severity map, not a local literal table.
- **Sources-verified:** severity vocabulary via `color_policy` (`SEVERITY_CLASS_MAP` / `css_class_for_severity`, frozen — CLAUDE.md engine set). Ordering helper `NEW — created in Phase 3`.

### LLR-042.7 — MAC leading status glyph routed through `color_policy` (no hard-coded colour)
- **Traceability:** HLR-041
- **Statement:** `update_mac_view` shall prepend a leading status glyph to each MAC row whose glyph is chosen from the row's already-resolved severity and whose colour is applied via `css_class_for_severity`, with no severity hex literal introduced anywhere.
- **Validation:** `test (integration)` + `inspection`
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.7` (asserts glyph per row matches its status); inspection = grep the new render code for severity hex → none
- **Numeric pass threshold:** TC passes; glyph matches status for OK/warning/out-of-range rows; grep for hard-coded `#`-hex severity == 0 hits; 0 failures
- **Acceptance criteria:** glyph mapping is severity→glyph only; colour flows through the frozen policy; `tui/mac.py` stays a reader (unchanged).
- **Sources-verified:** `update_mac_view` `app.py:7500`; severity-keyed `Text` cells already built `app.py:7521`; MAC columns `app.py:3097-3106`. Glyph map `NEW — created in Phase 3`.

### LLR-042.8 — Workspace per-range coverage micro-bar (render-only arithmetic)
- **Traceability:** HLR-040.a
- **Statement:** `update_sections` shall render, per range row, a fixed-width coverage micro-bar computed by display arithmetic on that range's `(start, end)` and its `range_validity` flag, without invoking any parse/coverage/validation routine and without widening the row beyond the usable width of `#ws_left`.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.8` (asserts a micro-bar cell/line appears per range row; valid vs invalid render differently)
- **Numeric pass threshold:** TC passes; one micro-bar per range row; 0 failures; row fits `#ws_left` at 80 and 120 cols (geometry AT, §6.1)
- **Acceptance criteria:** bar is a pure function of already-parsed range data; no new sibling widget added to the row's horizontal budget (rendered as an added line OR a bounded inline bar — see §6.1 geometry risk).
- **Sources-verified:** `update_sections` per-range loop + two-line label `app.py:7194-7205`; `#ws_left` width 22 `styles.tcss:189`. Micro-bar helper `NEW — created in Phase 3`.

### LLR-042.9 — Workspace whole-image memory strip (single-row minimap, reuse batch-27 logic)
- **Traceability:** HLR-040.b
- **Statement:** The Workspace shall mount a single-row memory strip that colours cells valid/invalid/gap via the batch-27 `cell_status`/`status_to_css_class` path over the already-computed `ranges`/`range_validity`, rendered as a rows=1 variant of `MemoryMapPanel.render_ranges`, and shall not appear on any non-Workspace screen.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.9` (asserts a one-row strip mounts on Workspace with valid/invalid/gap cells; asserts it is absent on other screens)
- **Numeric pass threshold:** TC passes; strip present on Workspace, absent elsewhere; cell colours route through `css_class_for_severity`; 0 failures
- **Acceptance criteria:** empty ranges → neutral empty note (LLR-042.12); no re-derivation of ranges; single row (vertical band, §6.1 vertical budget).
- **Sources-verified:** `cell_status` `screens_directionb.py:285`; `status_to_css_class` `screens_directionb.py:333`; `render_ranges(ranges, range_validity, issues=())` `screens_directionb.py:967`; single-row geometry via `cell_count_for_geometry` `screens_directionb.py:211`. Strip container/id `NEW — created in Phase 3`.

### LLR-042.10 — Workspace stat pane (coverage % + range/error/warning counts, render-only)
- **Traceability:** HLR-040.c
- **Statement:** The Workspace stat pane shall display coverage percent and range count from `coverage_stats(ranges, range_validity, issues)`, and error/warning counts computed by tallying `_validation_issues` per severity, performing no new coverage/validation computation and displaying no entropy figure.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.10` (asserts coverage %, range count, error count, warning count against a fixture with known ranges+issues)
- **Numeric pass threshold:** TC passes; displayed coverage % == `coverage_stats.coverage_pct`; error/warning counts == severity tallies; no entropy label present; 0 failures
- **Acceptance criteria:** coverage %/range figures reuse the existing `CoverageStats`; severity tallies are counts over the already-computed issue list; empty file → zeroed/neutral pane (LLR-042.12).
- **Sources-verified:** `coverage_stats` `screens_directionb.py:538`; `CoverageStats` fields `screens_directionb.py:504-535`; `_validation_issues` `app.py:764`. Stat-pane host id `NEW — created in Phase 3` (candidate host `#ws_right` width 40 `styles.tcss:199`).

### LLR-042.11 — Markup-safe rendering of file-derived text (A2L card + Issues worklist) (C-17)
- **Traceability:** HLR-038.a, HLR-039.a
- **Statement:** Every file-derived string reaching the A2L record card or the Issues worklist — loaded A2L symbol/tag names, and `ValidationIssue.message`/`.symbol`/`.code` — shall be rendered by composing a `rich.text.Text` with explicit `style=` arguments treating the value as a literal, and shall never be interpolated into a markup-parsed string.
- **Validation:** `test (integration)` (hostile-input)
- **Executed verification:** `pytest tests/test_tui_app.py -k TC-042.11` (feeds a tag name and an issue symbol/message containing `[red]`/`[/]` markup tokens; asserts the literal brackets survive verbatim and no style is injected)
- **Numeric pass threshold:** TC passes; injected markup tokens render literally (present in output text, no colour applied); 0 failures
- **Acceptance criteria:** rendering is markup-safe on BOTH surfaces; the batch-27 `LLR-041.11` markup-safe `Text` composition is the pattern precedent.
- **Sources-verified:** `_scrub_issue_message` strips only ANSI CSI + control chars — NOT `[`/`]` — `validation/model.py:71-72`; it touches only `.message`, never `.symbol` `validation/model.py:137`; `_scrub_issue_message`/`model.py` are engine-frozen (CLAUDE.md), so the fix is panel-side. Precedent `render_ranges` "markup-safe `Text` (LLR-041.11)" `screens_directionb.py:981`; existing `safe_text(...)` usage `screens_directionb.py:753`.

### LLR-042.12 — Two-regime geometry + empty-state for all new surfaces (C-13)
- **Traceability:** HLR-038.a, HLR-038.b, HLR-039.a, HLR-039.b, HLR-040.a, HLR-040.b, HLR-040.c, HLR-041
- **Statement:** Each new surface (A2L card, Issues worklist, coverage micro-bar, memory strip, stat pane, MAC glyph column) shall render legibly at both the 80-column narrow regime and the 120-column wide regime without pushing any existing pane off-screen, and shall present a neutral no-data state when no file/A2L/issues are loaded.
- **Validation:** `test (e2e)` (Textual Pilot at fixed sizes)
- **Executed verification:** `pytest tests/test_tui_snapshot.py -k TC-042.12` via `App.run_test(size=(80,24))` and `App.run_test(size=(120,40))`; assert no horizontal overflow, all existing panes present, and each new surface renders
- **Numeric pass threshold:** TC passes at both sizes; 0 panes clipped/absent; empty-state note shown when no data; 0 failures
- **Acceptance criteria:** narrow regime uses the existing `width-narrow` breakpoint (<120, `app.py:4013`); no new fixed sibling exceeds the §6.1 budgets; empty states are neutral (no crash, no stale content).
- **Sources-verified:** breakpoint `_apply_width_regime` narrow `= width < 120` `app.py:4013`; rail 22→4 collapse `styles.tcss:1058,1096-1097`; workspace panes `styles.tcss:188-216`; batch-27 empty note `_EMPTY_TEXT` `screens_directionb.py:856`.

### LLR-042.13 — Engine-frozen + render-only invariant (batch-wide)
- **Traceability:** HLR-038.a, HLR-038.b, HLR-039.a, HLR-039.b, HLR-040.a, HLR-040.b, HLR-040.c, HLR-041
- **Statement:** The batch shall introduce all rendering changes only in `app.py`, new widget modules under `s19_app/tui/`, and `styles.tcss`; it shall NOT diff any engine-frozen path (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) vs `main`; and no new surface shall perform parse, coverage, or validation computation — all read the `LoadedFile` snapshot / enriched tags / `_validation_issues` / `ranges`+`range_validity` already computed on the worker thread.
- **Validation:** `test` + `inspection`
- **Executed verification:** `pytest tests/test_engine_unchanged.py` and `pytest tests/test_tui_directionb.py -k test_tc031` (engine-frozen guards); inspection = new render code contains no parse/coverage/validation call
- **Numeric pass threshold:** 0 frozen-path diffs vs `main`; guards green; 0 new parse/coverage/validation call-sites in render code
- **Acceptance criteria:** `tui/a2l.py` and `tui/mac.py` stay readers; renderers run on the UI thread and do not parse (matches the `models.py::LoadedFile` thread split).
- **Sources-verified:** engine-frozen set + guard files `tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py::test_tc031_*` (CLAUDE.md "Engine-frozen guard"); thread split `models.py::LoadedFile` (CLAUDE.md TUI layer).

---

## 6. Appendices

### 6.1 C-13 geometry budget — per new fixed sibling / surface

**Regime facts (verified):** narrow = terminal width `< 120` (`app.py:4013`); rail width = **22 cols wide / 4 cols narrow** (`styles.tcss:1058` wide, `1096-1097` collapse). `body_w = terminal_width − rail_width`.

- **Reference widths used below:**
  - 80-col terminal → narrow regime → rail 4 → **body_w = 76**.
  - 120-col terminal → wide regime → rail 22 → **body_w = 98**.

| # | New surface | Layout basis | 80-col (narrow, body 76) | 120-col (wide, body 98) | Verdict |
|---|-------------|--------------|--------------------------|--------------------------|---------|
| 1 | **A2L record card** (LLR-042.1) | reuses `#a2l_panes` proportional split `#a2l_tags_pane` 4fr / `#a2l_hex_pane` 3fr (`styles.tcss:254-262`) — NO new fixed sibling | card region ≈ 76×3/7 ≈ **33** (≈29 after round border+padding). 16 vertical key/value lines fit (one field per line; value truncates). | card region ≈ 98×3/7 ≈ **42** (≈38 usable). Comfortable. | **Clears by construction** (proportional). Placement of the card vs the existing `#a2l_hex_pane` region is a Phase-3 layout detail → **assumed — verify in Phase 3**. |
| 2 | **Issues worklist** (LLR-042.4) | reuses `#issues_columns` split cards 2fr / `#issues_hex_pane` 1fr (`styles.tcss:723-738`) — NO new fixed sibling | cards ≈ 76×2/3 ≈ **51**; hex-peek ≈ **25**. Card fits severity + artifacts + wrapped message. | cards ≈ 98×2/3 ≈ **65**; hex-peek ≈ **33**. | **Clears by construction** (proportional). |
| 3 | **Coverage micro-bar** (LLR-042.8) | in-row inside `#ws_left` (22 wide / 24% narrow, `styles.tcss:189,205`) | `#ws_left` usable ≈ 22 − border(2) − padding(2) = **~18**; range label already wraps to 2 lines (`app.py:7205`). Inline bar competes for the same ~18 cols → **pinch**. | wide `#ws_left` still 22 → same ~18 usable. | **RISK.** Mitigation: render the micro-bar as an ADDED LINE within the row (vertical, no horizontal steal) OR cap an inline bar ≤ ~8 cells. Exact cell count **assumed — measure in Phase 3** via `App.run_test(size=(80,24))` and `(120,40)`; assert `#ws_left` rows do not clip. |
| 4 | **Memory strip** (LLR-042.9) | single-row band spanning `#ws_center` (1fr, proportional) — horizontal is proportional; the cost is **vertical** | 1 cell-row + border/header ≈ **3 rows** of vertical budget subtracted from `#ws_center` hex height (~12% of a 24-row terminal). | same ~3 rows (~7% of 40-row terminal). | **Low-moderate (vertical).** Horizontal clears (proportional, auto-scaled cell count via `cell_count_for_geometry`). Vertical band height **assumed — measure in Phase 3** (assert hex view still renders ≥1 row at 80×24). |
| 5 | **Stat pane** (LLR-042.10) | candidate host `#ws_right` (40 wide / 30% narrow, `styles.tcss:199,208`) | narrow `#ws_right` ≈ 76×0.30 ≈ **22** → fits "Coverage: 98.7%" + 3 count lines. | wide `#ws_right` = **40** → ample. | **Clears.** Host pane `#ws_right` **assumed** — confirm it has vertical room in Phase 3 (may need its own sub-region). |
| 6 | **MAC glyph** (LLR-042.7) | +1 leading cell on existing 8-col MAC DataTable | +2–3 cols on an existing table already fitting 8 columns → marginal | ample | **Low.** DataTable auto-sizes; glyph is 1 char. |

**Summary geometry risk:** only **#3 (coverage micro-bar)** is a genuine pinch (the fixed 22-col `#ws_left`, the exact failure mode of batch-17). It is constrained in LLR-042.8 (no horizontal row widening) and gated by the LLR-042.12 two-size Pilot AT. #4/#5 carry a vertical-budget flag to measure in Phase 3. #1/#2 clear by construction because they reuse proportional (fr-based) splits with no new fixed sibling.

### 6.2 Increment-split hint for US-040 (structured for 2 increments)
- **Inc-A (in-place, low geometry risk):** LLR-042.8 (micro-bar) + LLR-042.10 (stat pane) — both reuse existing panes / existing arithmetic (`coverage_stats`), no new band.
- **Inc-B (new band, geometry-sensitive):** LLR-042.9 (memory strip) — the new single-row band consuming vertical budget; carries the Phase-3 vertical measurement.
- Rationale: isolates the one vertical-budget change so a geometry surprise in the strip does not block the micro-bar/stat-pane value.

### 6.3 Assumptions (numbered)
1. **Rail-width regime** is 22 (wide, ≥120) / 4 (narrow, <120) — VERIFIED (`styles.tcss:1058,1096-1097`; breakpoint `app.py:4013`). Not an assumption; recorded for the geometry arithmetic.
2. **A2L card placement** within `#a2l_panes` (card in the right/detail region, master list left) is **assumed**; whether the existing `#a2l_hex_pane` coexists with the card or is replaced by it in card-mode is a Phase-3 layout decision. Geometry clears either way (proportional). **verify in Phase 3.**
3. **Coverage micro-bar cell count / render form** (added line vs bounded inline bar ≤~8 cells) is **assumed — measure in Phase 3** against the ~18-col usable `#ws_left`.
4. **Memory-strip vertical band height** (~3 rows incl. border/header) is **assumed — measure in Phase 3**; assert the `#ws_center` hex view still renders at 80×24.
5. **Stat-pane host** = `#ws_right` (40 cols) is **assumed**; confirm vertical room in Phase 3 (may warrant a dedicated sub-region rather than sharing `#ws_right`).
6. **Error/warning severity tally** over `_validation_issues` assumes the `color_policy` severity vocabulary distinguishes error vs warning levels (it does — batch-26 MAC Orange warning + Red error flow through `SEVERITY_CLASS_MAP`). Counting is render-side, not re-validation.
7. **A2L toggle key** does not collide with an existing A2L-screen binding — **assumed — verify in Phase 3** (grep the screen `BINDINGS` before assigning).
8. **`_validation_issues` insertion order is stable** across a render (used as the LLR-042.6 secondary sort key) — assumed; it is a plain `list` (`app.py:764`), so order is preserved unless re-sorted upstream.
9. All new surfaces **read** the `LoadedFile` snapshot / enriched tags / `_validation_issues` populated on the worker thread; **no renderer parses** (LLR-042.13). Assumed to hold given the existing thread split (`models.py::LoadedFile`).

### 6.4 Phase-1 reconciliation log
*(No LLR threshold/statement changed after first draft; no promotion/removal. Empty at draft time — the orchestrator appends any reconciliation event during the merge/gate per the parent-HLR re-read rule.)*
