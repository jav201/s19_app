# 01b — QA validation catalog · batch-n8 (comprehensive per-view Legend)

Author: qa-reviewer (Phase 1). Surface under test: the `LegendScreen` modal
(`s19_app/tui/screens.py`) opened by `S19TuiApp.action_show_legend`
(`s19_app/tui/app.py`), scoped to `_active_screen_key` via
`_SCREEN_LEGEND_SECTIONS`. Black-box driver = Textual `run_test` Pilot: build
`S19TuiApp`, activate the rail screen with `action_show_screen(<key>)` (sets
`_active_screen_key`), open the legend with `action_show_legend()`, then observe
the rendered `LegendScreen`.

> **ID ownership.** The architect owns final AT/TC assignment. I **propose** the
> `AT-150…AT-156` and `TC-370…TC-375` blocks — chosen clear of the highest live
> ids (`AT-140`, `TC-361`). **If the architect assigns different ids, reconcile
> before Phase 3.** Every id below is a proposal.

---

## 0 · Layer-B observability findings (read before the ATs)

Three findings shape every AT here. They are the difference between a catalog
that can go RED pre-fix and one that is vacuously green.

### F-1 (BLOCKER for the fold-ins): `.render().plain` does NOT see truncation

In Textual, `Label` **subclasses** `Static`; both hold the full renderable.
`label.render().plain` returns the **complete** meaning string for a `Label`
**and** for a `Static` — truncation happens at *paint/layout* time (the widget's
region), not in `.render()`. Therefore the existing helper
`_modal_meanings()` (`tests/test_tui_legend.py:52`, reads `str(label.render())`)
**cannot** distinguish the pre-fix `Label` from the post-fix `Static`: an AT
built on it would be **green even on the un-fixed Label tree** — the counterfactual
would fail. **The two fold-in ATs must observe the PAINTED output**, via:

- **Primary (content):** join the widget's painted lines
  `"".join(row.render_line(y).text for y in range(row.size.height))` and assert
  the long-meaning **tail** substring is present. A `Label` at ~100 usable cols
  has `size.height == 1` and a single truncated strip → tail **absent** → RED.
  A `Static` wraps → `size.height >= 2`, joined strips contain the tail → GREEN.
- **Corroborating (mechanism):** assert `row.size.height >= 2` for the long row.

`_modal_meanings()` stays valid only for *short* rows that never wrap; do **not**
reuse it for AT-155 / AT-153.

### F-2: `Label` ⊂ `Static` breaks the naïve white-box type check

To assert the fold-in "rows are `Static`, not `Label`", `isinstance(row, Static)`
is **true for a `Label` too**. The white-box TC must use
`type(row) is Static` (or `not isinstance(row, Label)`). See TC-372.

### F-3: derive/guard element sets (C-31) — sources located

| Element set | Canonical source in code | Derive-oracle for the AT |
|---|---|---|
| 16 A2L columns | inline `a2l_table.add_columns(...)` at `app.py:5009-5026` (no shared const) | query the **live** `#a2l_tags_list` `DataTable.columns` labels; guard `len >= 16` |
| 4 entropy bands + cutoffs | `entropy_service.ENTROPY_BANDS` (`entropy_service.py:41`), glyphs via `entropy_style.band_style` | iterate `ENTROPY_BANDS`; guard `len == 4` |
| MAC / A2L / Issues colour meanings | `legend.LEGEND_TABLE[section]` | iterate the section dict; never hand-type a meaning |
| MAC warning-orange colour | `color_policy.MAC_ADDRESS_OVERLAY_STYLE` (frozen) → `#d9a35b` family | couple the expected colour to the constant, not the hex literal |

Because the 16 A2L columns are **inline literals** (not a reused constant), the
honest derived oracle is the **live DataTable columns** — this also couples the
legend to the table (a 17th column added without a legend line fails AT-151).

---

## 1 · Acceptance criteria (Given / When / Then) + black-box ATs

### AT-150 — Workspace legend is an example-only card (Story US-N8-1)

- **Given** a fresh `S19TuiApp` on the Workspace screen (`_active_screen_key == "workspace"`)
- **When** `action_show_legend()` opens the modal
- **Then** the modal body contains the Workspace **example** annotations — at
  minimum the memory-strip glyph gloss (assert the four band glyphs `·`, `░`,
  `▒`, `▓` **and** one anchor caption substring, e.g. `"one glyph per address cell"`
  or `"mapped bytes"`) **and** the Loaded-panel slot labels `S19` / `MAC` / `A2L`
- **And** it renders **no severity colour-key rows** — assert `0` widgets carry a
  `sev-*` class (`legend_body .sev-error, .sev-ok, .sev-warning, .sev-neutral`),
  i.e. Workspace is example-only.
- **Counterfactual (RED pre-impl):** today Workspace is **unmapped** in
  `_SCREEN_LEGEND_SECTIONS` → the `None` fallback renders the **full** table
  (all A2L/MAC/Issues/Hex `sev-*` rows). The `sev-*`-count-== 0 assertion is RED
  until Workspace gets an explicit example-only entry, and the example-glyph
  assertion is RED until the card content exists.
- *Type:* `test (pilot)`. C-10(a): drives Workspace and certifies its content
  differs from the colour-key views (asserts absence of the key rows).

### AT-151 — A2L legend explains all 16 columns + R/G/W/Grey (Story US-N8-2)

- **Given** the app on the A2L screen with the public `prg.s19` installed (so the
  A2L DataTable exists and its columns are initialised)
- **When** the legend opens
- **Then** for **every** column label **derived** from the live
  `#a2l_tags_list` `DataTable.columns` (Tag, Address, Length, Source, Raw,
  Physical, InMem, Region, Limits, Unit, Bits, Endian, Virt, Func, Access,
  Dtype — guard `len >= 16`), that label appears in the painted card text
- **And** each of the four `LEGEND_TABLE["A2L"]` meanings (Red / Green / White /
  Grey — **iterated**, not hand-listed) appears as a rendered key row
- **And (C-10(a) differential)** the A2L-only content is **absent** on a
  non-A2L view: re-open on `map` and assert the A2L column set is **not** all
  present (scope actually changed).
- **Counterfactual (RED):** the current modal shows only the 4 `LEGEND_TABLE["A2L"]`
  colour rows — none of the 16 column labels exist in the body → RED until the
  A2L example card is added.
- *Type:* `test (pilot)`. C-31: column set derived from the live table.

### AT-152 — Memory Map legend shows the 4 entropy bands + cutoffs (Story US-N8-3)

- **Given** the app on the Memory Map screen (`_active_screen_key == "map"`)
- **When** the legend opens
- **Then** for **every** `(label, lo, hi)` in `ENTROPY_BANDS` (iterated; guard
  `len == 4`) the band **label** (`constant/padding`, `low`, `medium`,
  `high/random`), its **glyph** (`band_style(label)` → `·ᐧ░▒▓`), and the numeric
  **cutoffs** `0`, `1`, `5`, `7.2`, `8` appear in the painted body
- **And** the "gap hatch" `╱` non-band marker appears
- **And** the closing note distinguishes the domains — assert a substring like
  `"NOT a"` / `"Bands ≠ severities"` / `"entropy"` is present (bands are an
  entropy domain, not a severity key)
- **And (C-10(a) differential)** re-open on `a2l` and assert the band glyph set
  is **not** all present there (scope changed).
- **Counterfactual (RED):** `_SCREEN_LEGEND_SECTIONS["map"]` maps to `("Hex",)`
  today → the Map legend shows the **Hex overlay** rows, **no** band labels or
  cutoffs → RED until the band key is rendered for `map`. **See testability
  concern TC-1 below — the map mapping must change.**
- *Type:* `test (pilot)`. C-31: bands derived from `ENTROPY_BANDS`.

### AT-153 — MAC reconciliation: pale-yellow key word AND orange sample row (Story US-N8-4, FOLD-IN 2)

- **Given** the app on the MAC screen
- **When** the legend opens
- **Then** the colour-key rows include the classification word **"Pale yellow"**
  (the cross-view severity name, from `LEGEND_TABLE["MAC"]`) rendered in the body
- **And** a **sample warning row** is present with an anchor substring
  (`"NOT_IN_A2L"` **and** a caption like `"what a warning row looks like"`)
- **And** that sample row is **painted orange** — inspect the sample row's painted
  segments (`render_line(0).segments` → a segment whose `style.color` is the
  `MAC_ADDRESS_OVERLAY_STYLE` orange family, `#d9a35b`; **couple the expected
  colour to the frozen constant, not to a hex literal**)
- **And** a "trust the glyph + Status column over hue" caption is present (C-10).
- **Counterfactual (RED):** the current modal has no reconciliation block — both
  the sample row **and** its orange paint are absent; asserting the orange
  segment is RED on the pre-fix tree. Because this checks the **painted colour**
  (not `.render().plain`), it also would not pass a version that merely prints
  the word "orange" in grey text (C-32).
- *Type:* `test (pilot)`. Requires a **stable hook** on the sample row — see the
  testability note; recommend the dev give it id `#legend_mac_warning_sample`.

### AT-154 — Issues legend: Errors/Warnings/Info meanings + code families (Story US-N8-5)

- **Given** the app on the Issues screen
- **When** the legend opens
- **Then** each of the three `LEGEND_TABLE["Issues"]` meanings (Errors /
  Warnings / Optional info — **iterated**) appears as a rendered key row, and the
  severity-strip vocabulary (`Errors`, `Warnings`, `Info`) appears in the card
- **And** the four issue-code **family** prefixes (`MAC_`, `A2L_`, `CROSS_`,
  `TRIPLE_`) each appear at least once (guard: if the impl inlines the 17-code
  census, derive the code set from the validation code source or guard
  `count >= 17`; if it folds to the one-line family summary per NOTES cut #1,
  assert the four prefixes only — do **not** hand-list 17 literals)
- **And (C-10(a) differential)** re-open on `mac` and assert the Issues-only
  "Optional info" / `Cyan` row is **not** present (scope changed).
- **Counterfactual (RED):** current modal shows the 3 Issues colour rows but
  **no** severity strip and **no** code families → RED until the Issues card is
  added.
- *Type:* `test (pilot)`. C-31: code families derived/guarded, not hand-listed.

### AT-155 — Label→Static: the 148-char "Errors" meaning tail survives (FOLD-IN 1)

- **Given** the app on the Issues screen at `run_test(size=(120, 30))`
- **When** the legend opens and the "Errors" key row is laid out (its meaning,
  `LEGEND_TABLE["Issues"]["Errors"][1]`, is ~148 chars — wider than the ~100-col
  usable card)
- **Then** the row's **painted** text (joined across `render_line(y)` for
  `y in range(row.size.height)`) **contains the tail** `"same-name mismatch"`
- **And** `row.size.height >= 2` (it wrapped rather than truncated).
- **Counterfactual (RED):** on the pre-fix `Label` tree the row has
  `size.height == 1` and one truncated strip ending near
  `"…broken GROUP/FUNCTION refere"` — the tail is **absent** → RED. This is the
  observability the F-1 finding requires; `_modal_meanings()` would (wrongly)
  pass here and must not be used.
- *Type:* `test (pilot)`. Locate the row by its rendered `Errors — ` prefix or a
  stable id.

### AT-156 — Cross-view scoping differential (C-10(a) certification)

- **Given** the app
- **When** the legend is opened on each of `workspace`, `a2l`, `map`, `mac`,
  `issues` in turn (popping between)
- **Then** the set of artifact/section headings (or a per-view fingerprint
  substring) is **distinct per view** — specifically: A2L-column labels appear
  only under `a2l`; band glyphs+cutoffs only under `map`; the MAC orange sample
  only under `mac`; the Issues code families only under `issues`; and `workspace`
  shows the example card with **no** `sev-*` rows.
- **Counterfactual (RED):** if scoping is not per-view (e.g. every view falls
  back to the full table, or `map` still shows Hex), the fingerprints collide →
  RED. Certifies the scoping is real, not the workspace default echoed everywhere.
- *Type:* `test (pilot)`. This is the umbrella C-10(a) guard; the per-story ATs
  carry their own local differential too.

---

## 2 · White-box test cases (per anticipated LLR)

| TC | Anticipated LLR | Assertion (white-box) | Method |
|---|---|---|---|
| TC-370 | Workspace mapped as example-only | `_SCREEN_LEGEND_SECTIONS` (or the new example map) has a `"workspace"` entry that resolves to **example-only** (no severity section); Workspace does **not** hit the `None`→full-table fallback | test |
| TC-371 | Per-view example completeness | the per-view example store (e.g. `LEGEND_EXAMPLES`) has an entry for **all 5** views (keys derived from the view set / guard `== {workspace, a2l, map, mac, issues}`); every entry is non-empty (no blank card) | test |
| TC-372 | Label→Static change (F-2) | every meaning/example content row is a `Static` and **not** a `Label` — assert `type(row) is Static` (NOT `isinstance`, since `Label ⊂ Static`); artifact **headers** may stay `Label` if intended, assert that split explicitly | test |
| TC-373 | Map band key derived from `ENTROPY_BANDS` | the Map band rows number `len(ENTROPY_BANDS)` and each carries the matching `band-*` class from `band_style` (anti-drift: a 5th band added to `ENTROPY_BANDS` without a legend row fails) | test |
| TC-374 | A2L column list coupled to the table | the A2L example lists **every** live `#a2l_tags_list` column label (a 17th column added to `add_columns` without a legend line fails) | test |
| TC-375 | MAC reconciliation colour coupled to source | the orange sample row's colour equals the `MAC_ADDRESS_OVERLAY_STYLE` orange family (`#d9a35b`), read from the frozen constant — a re-value of the constant must not silently pass a stale literal | test |

---

## 3 · Validation method table (requirement → method)

| Requirement | Story | AT (black-box, Layer B) | TC (white-box) | Method |
|---|---|---|---|---|
| Workspace example-only card | US-N8-1 | AT-150 | TC-370, TC-371, TC-372 | test (pilot) + test |
| A2L 16 columns + R/G/W/Grey | US-N8-2 | AT-151 | TC-374 | test (pilot) + test |
| Memory Map 4 bands + cutoffs (≠ severity) | US-N8-3 | AT-152 | TC-373 | test (pilot) + test |
| MAC reconciliation (pale-yellow word + orange row) | US-N8-4 | AT-153 | TC-375 | test (pilot) + test |
| Issues strip + families + 3 meanings | US-N8-5 | AT-154 | TC-371 | test (pilot) + test |
| Fold-in 1: Label→Static tail survives | (all views) | AT-155 | TC-372 | test (pilot) |
| Fold-in 2: MAC orange sample painted | US-N8-4 | AT-153 | TC-375 | test (pilot) |
| Per-view scoping is real | (all views) | AT-156 | TC-370 | test (pilot) |
| Density fits 80 & 120 cols (C-13) | (all views) | reuse AT-023e pattern (modal within terminal) | — | test (pilot) |
| Markup safety of sample tokens (C-17) | (all views) | — | assert sample rows render literal `Text`/escaped, `spans == []` on the caption where brackets appear | inspection + test |

Default: `test (pilot)` for the black-box layer, `test` for white-box. No
requirement here is validated by demo/analysis alone — every one is observable
through the shipped modal surface (with the F-1 caveat on how).

---

## 4 · Regression checklist

- [ ] **N1 scoping intact** — `test_legend_scope_and_logwidth.py::test_n1_legend_scoped_per_screen`
  still green for `a2l`→`A2L`, `mac`→`MAC`, `issues`→`Issues`. **Note:** if
  `map` is re-pointed from `Hex` to the band key, `test_n1_..._per_screen`'s
  `headings["map"] == ["Hex"]` assertion **will break** — this is an intended
  amendment; flag it (§6.5 Before/After) and update, don't silently edit.
- [ ] **N1 fallback** — `test_n1_unmapped_screen_shows_full_table`: Workspace no
  longer falls back to the full table (it becomes example-only), so this test
  **must be amended** to a different unmapped screen or updated for the new
  Workspace behaviour. Flag as an intended requirement change.
- [ ] **Frozen sev-class round-trip** — `test_n1_rows_keep_frozen_sev_class` still
  green (rows keep `sev-*` classes; the Label→Static swap must preserve classes).
- [ ] **Batch-18/36 legend anti-drift** — `test_tui_legend.py` TC-S1, TC-S2,
  TC-322, TC-023.1/.2, AT-023a–f, AT-059a all still green. `_modal_meanings`
  helper still works for the short rows those tests assert.
- [ ] **`_legend_lines` report parity** (TC-S2) — the report legend surface is
  unchanged by N8 (N8 touches the modal card, not the report legend).
- [ ] **Frozen files untouched** — `color_policy.py`, `a2l.py`, `mac.py` diff-clean
  vs `main` (`test_engine_unchanged.py`, `test_tui_directionb.py::test_tc031_*`).
- [ ] **Modal opens with no file loaded** (AT-023f pattern) — the new cards are
  static samples, not data-driven; legend must open empty-state on every view.
- [ ] **80×24 geometry** — the FULL-density card still fits / scrolls within the
  terminal on every view (C-13; extend AT-023e's `modal within terminal` check
  to all 5 views).

---

## 5 · Exit criteria

- AT-150 … AT-156 all PASS (each verified RED against its counterfactual first —
  fold-in ATs RED on the pre-fix Label/no-reconciliation tree).
- TC-370 … TC-375 all PASS.
- Regression checklist all green, with the N1 `map`/`workspace` amendments
  recorded via §6.5 Before/After (not silent edits).
- No frozen-file diff. Full suite `pytest -q` green except the known
  batch-58/59 `tc016s` snapshot advisories (19, pre-existing).
- Test-results columns in this catalog remain **blank** — filled by the Phase-4
  run, not pre-declared here.

---

## 6 · Testability concerns for the orchestrator (flag list)

1. **Memory Map mapping conflict (BLOCKS AT-152).** `_SCREEN_LEGEND_SECTIONS["map"]
   = ("Hex",)` today. N8 wants `map` to show the **entropy band key**. The
   architect must decide: band key **only**, or band key **+** Hex overlay (the
   Map inspector *does* show a hex peek, so Hex overlays are arguably relevant on
   Map too). Whichever — the shipped `map`→`Hex` mapping must change, and N1's
   `headings["map"] == ["Hex"]` test amends with it. **Needs an architect ruling
   before AT-152/TC-373 can be finalised.**

2. **Workspace fallback override (BLOCKS AT-150).** Workspace is *unmapped* → the
   `sections=None` path renders the **full** table (N1 AC-3). For example-only,
   Workspace needs an **explicit** entry that renders the card and suppresses the
   colour key — it must not reuse the `None`→full-table fallback. Confirm the
   mechanism (a distinct example-map vs a sentinel section) so TC-370 targets the
   right structure.

3. **`.render().plain` blindness to truncation (F-1).** The fold-in ATs (AT-155,
   AT-153-orange) **cannot** use `_modal_meanings()` / `.render().plain`; they must
   read the **painted** output (`render_line` join + `size.height`). If the dev
   prefers, expose a small test seam, but the painted-output method needs no
   production change. This is the single most important note — an AT built the
   easy way here is vacuously green.

4. **Stable hook for the orange sample row (AT-153/TC-375).** Asserting the
   *painted colour* needs a targetable widget. Recommend the dev give the MAC
   reconciliation sample row a stable id (e.g. `#legend_mac_warning_sample`) so
   the AT can read `render_line(0).segments[...].style.color`. Without a hook the
   colour assertion has to scan all segments (brittle). Flag to the dev.

5. **16 A2L columns are inline literals** (`app.py:5009`), not a shared const.
   The AT oracle derives from the **live DataTable columns** (couples legend↔table)
   — good C-31 outcome, but requires `prg.s19` installed so the columns exist.
   If a future refactor extracts a `A2L_COLUMNS` constant, retarget TC-374 to it.

6. **Not snapshot-captured.** The legend modal is not in the 19 `tc016s`
   baselines (PLAN risk). These black-box ATs + white-box TCs are the coverage;
   no canonical SVG regen is expected. Confirm at Phase 4.

---

## Evidence checklist (Phase-1 completeness)

- [x] Acceptance criteria use Given/When/Then — §1, AT-150…AT-156.
- [x] Test cases have explicit Expected (painted-content assertions), not vague "works".
- [x] Edge cases: empty (AT-023f reuse — no file), boundary (148-char meaning AT-155), invalid (markup-safety §3 row), error (none applicable — read-only modal, no failure path). Cut justified: no auth/concurrency (a static read-only modal, no roles, no shared state).
- [x] Regression checklist exists — §4 (incl. the two intended N1 amendments).
- [x] Exit criteria stated — §5.
- [x] No real PII / secrets — samples are synthetic (`VVT_ENABLE`, `RPM_LIMIT`, `prg.s19` public fixture).
- [x] Test-results columns left blank for the Phase-4 human/CI run.
- [x] Layer B: every story's deliverable observed through the SHIPPED modal via Pilot, with boundary (AT-155 148-char) + differential (AT-156) evidence — not only white-box on `LEGEND_TABLE`.
- [x] Bidirectional surface-reachability: inputs (each rail `screen_key` drives `_active_screen_key`) AND outputs (each per-view card/key rendered) exercised through `action_show_legend`, not the data module directly.
- [x] No unfilled template — every AT/TC has a concrete assertion + counterfactual; the two open architect rulings (§6.1, §6.2) are flagged, not left as silent placeholders.
- [x] C-31: A2L columns, entropy bands, colour meanings, code families all DERIVED or guarded (§0 F-3) — no silent hand-lists.
