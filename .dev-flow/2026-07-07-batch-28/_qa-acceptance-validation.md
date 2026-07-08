# QA — Acceptance blocks (§3) + Validation strategy (§5) · batch-28 · R-TUI-042

> **Authored by `qa-reviewer` in Phase 1, in parallel with the `architect`.** This file
> carries the **black-box acceptance blocks per story** and the **validation strategy**.
> The orchestrator MERGES it with the architect's HLR/LLR mechanism into `01-requirements.md`.
> This file does NOT author HLR/LLR mechanism and does NOT edit `01-requirements.md`/`state.json`.
>
> **V-5 provisional-identifier note (batch-09).** Every implementer-owned identifier below —
> the test FILE path (`tests/test_tui_directionb.py` + noted unit files), the `-k`/node-id
> selector, the `AT-NNN` id, the `TC-042.N` id, and every **NEW** widget id / key
> (`#a2l_master`, `#a2l_card`, toggle key, `#issues_worklist`, `#issues_hex`, coverage-bar /
> memory-strip / stat-pane ids) — is **provisional-until-Phase-3** and reconciled from the
> real tree at Phase 4. The architect's real HLR/LLR ids supersede the provisional
> `HLR-042.x` / `LLR-042.N` topic labels used here at merge; the binding is **by topic name**.

---

## 0. Grounding facts the ATs rely on (draft-time, verified)

- **Shipped surfaces (grep-verified `file:line`).** `#screen_a2l` (`app.py:2966`), `#screen_issues`
  (`app.py:1320`), `#screen_workspace` (`app.py:1255`), `#screen_mac` (`app.py:3039`); Workspace
  panes `#ws_left` (`app.py:1218`) / `#ws_right` (`app.py:1243`); existing `#hex_view` and
  `#a2l_view` Statics are constructed **`markup=False`** (`app.py:1231`, `app.py:1240`) — this is
  the **markup-safe render baseline** the new card/worklist/strip widgets must preserve.
- **Fixtures (existence probe 2026-07-07).** Full triple `examples/case_01_basic_valid/firmware.{s19,a2l,mac}`
  (S19+A2L+MAC) — reached by the existing `_load_case_01` helper (`test_tui_directionb.py:1197-1228`).
  Gaps/partial-coverage: `examples/case_02_gaps_and_patch_targets/`. Bad/error image:
  `examples/case_04_bad_checksums/`. Issue seeding: `_make_issues` + `_seed_issues_screen`
  (`test_tui_directionb.py:1785-1833`). All EXIST today (probed).
- **C-17 injection nuance (verified — `validation/model.py:19-137`).** `ValidationIssue.__post_init__`
  runs `_scrub_issue_message` on **`.message` only** — it strips ANSI CSI + ASCII control chars
  there, but **does NOT strip Rich markup brackets** (`[red]`, `[/]`, `[link=…]`) from `.message`,
  and does **NOT scrub `.symbol`/`.code` at all** (neither ANSI, control, nor brackets). A2L enriched
  tag/symbol names get **no** model scrub. **Therefore the render layer is the sole defense** for:
  (a) markup brackets in any of `.message`/`.symbol`/`.code`; (b) ANSI/control in `.symbol`/`.code`
  and in A2L symbol names. The mandatory C-17 ATs seed hostile content in exactly these unscrubbed
  positions so a `markup=True` regression is caught, not masked by the model scrub.
- **Severity → colour single source of truth:** `css_class_for_severity` / `SEVERITY_CLASS_MAP`
  (`tui/color_policy.py:5-19`, frozen). Glyph/bar/strip colour MUST round-trip through it.

---

## 3. Acceptance blocks (black-box) — one per story

> Each AT is `test (pilot)` (Layer B). Observation is through the **shipped screen surface** via
> `App.run_test()` Pilot; assertions reference the rendered element/content, never an internal-only
> symbol. Executed verification = a pytest node in `tests/test_tui_directionb.py` (unit files noted
> where a pure helper is also unit-tested). Numeric pass threshold is stated per AT.

### US-038 — A2L Explorer master/detail record card

- **Observable outcome:** On `#screen_a2l`, the operator sees a scannable **master tag list** and,
  for the selected tag, a **record card** showing **all 16 fields** as labelled key/value pairs
  (Tag/Address/Length/Source/Raw/Physical/InMem/Region/Limits/Unit/Bits/Endian/Virt/Func/Access/Dtype).
  The wide 16-col table is **retained behind a toggle key** (D1a).
- **Shipped surface:** `#screen_a2l` (rail key `3`) → master list `#a2l_master` (NEW) + record card
  `#a2l_card` (NEW) + retained table `#a2l_table`/existing (toggle key, NEW). Selection drives the
  real widget; card renders the SAME enriched-tag dict `update_a2l_tags_view` builds (`app.py:7827`).
- **Deliverable + observation:** rendered `#a2l_card` element carrying 16 labelled fields for the
  selected tag; toggle flips card⇄table visibility on the live screen.
- **C-16 real-mechanism:** every selection/toggle AT drives `pilot.press(...)`/`pilot.click(...)` on
  the actual master-list row / toggle key — **never `widget.focus()` or a direct setter** (batch-27
  arrow-nav lesson). **C-17 hostile-input AT is MANDATORY here (AT-038f).**

| AT | When `<input>`, the user observes `<outcome through the surface>` | Kind |
|----|--------------------------------------------------------------------|------|
| **AT-038a** | When case_01 (A2L present) is loaded and the A2L screen opened (`press "3"`) and the **first** tag selected via the real list, the user observes `#a2l_card` showing **all 16 field labels** + that tag's values. | golden · real-mech |
| **AT-038b** | When a **second/third** tag is then selected via the real mechanism (`press "down","down","enter"` or `pilot.click` the 3rd row), the card **content CHANGES** to the newly-selected tag's Address/Physical/InMem values (asserts changed content, not non-empty). | C-10a non-default · real-mech |
| **AT-038c** | When the toggle key is pressed on the default card view, the user observes the **wide 16-col table** replace the card; pressing again restores the card (visibility flip observed on-screen). | LLR .3 toggle · real-mech |
| **AT-038d** | When a tag whose `InMem`=hit is selected vs a tag that is unresolved/not-checked, the card's **InMem/Region fields differ** per branch (present-value vs not-checked value). | C-10b per-branch |
| **AT-038e** | When **no file** is loaded and the A2L screen is opened, the user observes the empty-state panel; the card is absent/placeholder; **no crash**. | boundary · empty |
| **AT-038f** | When a tag whose **symbol name** contains `MAP_Model[bold]`, `sensor[red]`, `x[/]`, `x[link=file:///etc]` **and a raw ANSI byte** (`\x1b[31m`) is selected through the surface, the card renders the brackets/ANSI as **LITERAL text** — **no `rich.errors.MarkupError`, no style/ANSI leak, no crash**. | **C-17 MANDATORY** · real-mech · invalid/error |
- **Boundary catalog (QC-3):** ☑ empty (AT-038e) · ☑ boundary (16-field max card + card⇄table toggle AT-038c; long-unicode symbol truncation folded into AT-038f) · ☑ invalid (unresolved-tag branch AT-038d; hostile symbol AT-038f) · ☑ error (would-be MarkupError under hostile input AT-038f).
- **Fixture note:** the hostile A2L symbol cannot come from a plain load through frozen `a2l.py`; seed it black-box by installing a synthetic **enriched-tag dict** on the app before `update_a2l_tags_view` (the `_seed_issues_screen` pattern applied to A2L) OR via a NEW hostile `.a2l` fixture (counts in the increment file budget). **Prefer the synthetic-tag seeding helper** so the AT stays black-box on the render surface with **zero** frozen-parser change. *(architect/dev action — see §Testability risks.)*

### US-039 — Issues Report worst-first worklist

- **Observable outcome:** On `#screen_issues`, the flat 8-col table is **replaced** by a **worst-first
  list of cards** (severity + artifact(s) + plain-language message + an Open-in affordance); the
  **live hex-peek pane STAYS beside it** and shows bytes at the selected card's address (D1b: cards | hex-peek).
- **Shipped surface:** `#screen_issues` → `#issues_worklist` (NEW cards) | `#issues_hex` (NEW/retained
  live hex-peek). Cards read the already-computed `S19TuiApp._validation_issues` (`app.py:764`). Open-in
  reuses `update_hex_view(focus_address=…)` + workspace switch (the Memory Map `OpenInHexRequested`
  pattern, `app.py:7287-7314`).
- **Deliverable + observation:** rendered `#issues_worklist` cards in worst-first order; `#issues_hex`
  content updates on card selection; Open-in focuses the Workspace `#hex_view` at the card's address.
- **C-16 real-mechanism:** card selection and Open-in drive `pilot.press`/`pilot.click` on the real
  card widget, never `.focus()`/setter. **C-12 output-then-consume:** Open-in AT drives the real card →
  the **handler** focuses the hex view → the AT asserts the **shipped `#hex_view`** shows the card's
  address, NOT a direct `update_hex_view` call. **C-17 hostile-input AT is MANDATORY here (AT-039f).**

| AT | When `<input>`, the user observes `<outcome through the surface>` | Kind |
|----|--------------------------------------------------------------------|------|
| **AT-039a** | When N mixed issues are seeded (`_seed_issues_screen`) and the Issues screen opened, the user observes **one card per issue**, each showing its **severity + artifact(s) + plain message + Open-in affordance**. | golden |
| **AT-039b** | When issues of mixed ERROR/WARNING/INFO severity are seeded, the rendered card order is **ERROR before WARNING before INFO** (worst-first — asserts observed order, not non-empty). | C-10b · LLR .4/.6 |
| **AT-039c** | When the **second** card (whose address differs) is selected via the real mechanism, `#issues_hex` **updates** to bytes at THAT card's address (content changed). **Boundary:** a card whose `address is None` → `#issues_hex` shows a neutral placeholder, **no crash** (address-None branch, per batch-27 `address None` exclusion). | C-10a non-default · real-mech |
| **AT-039d** | When the **Open-in** affordance is driven on a card (real `press`/`click`), the **handler** switches to Workspace and the shipped **`#hex_view`** shows that card's address — observed through the handler, **not** a direct `update_hex_view` call. | **C-12** · real-mech |
| **AT-039e** | When **0** issues are present, the user observes a "no issues" empty state and a neutral `#issues_hex`; **no crash**. (worst-first ordering exercised over 0 and 1 issue.) | boundary · empty |
| **AT-039f** | When a `ValidationIssue` is seeded with `.symbol="MAP_Model[bold]\x1b[31m"`, `.message="open[red]sensor[/] [link=file:///etc]"` and rendered+selected through the worklist, the cards render brackets/ANSI **LITERAL** — **no MarkupError, no ANSI/style leak, no crash**. (Covers both the model-scrubbed `.message`-bracket path AND the un-scrubbed `.symbol` ANSI+bracket path.) | **C-17 MANDATORY** · invalid/error |
- **Boundary catalog (QC-3):** ☑ empty (AT-039e) · ☑ boundary (single-issue ordering + address-None card AT-039c) · ☑ invalid (hostile symbol/message AT-039f) · ☑ error (would-be MarkupError AT-039f; Open-in on address-None yields no jump — folded into AT-039c/d).

### US-040 — Workspace inline coverage signal

- **Observable outcome:** On `#screen_workspace`, the operator sees, without opening the Memory Map:
  (a) a **per-range coverage micro-bar** per range row; (b) a **Workspace-only memory strip** colouring
  cells valid/invalid/gap; (c) a **stat pane** = coverage % + range count + error count + warning count.
  **No entropy sparkline** (D3).
- **Shipped surface:** `#screen_workspace` / `#ws_left` → coverage micro-bar (NEW), memory strip (NEW,
  single-row `MemoryMapPanel` cell-status variant, batch-27 `screens_directionb.py`), stat pane (NEW).
  All derive from already-parsed `current_file.ranges` / `range_validity` by the SAME arithmetic
  `render_ranges` / `update_sections` use (`app.py:7166`). Colour via frozen `css_class_for_severity`.
- **Deliverable + observation:** rendered micro-bar fill per range; strip cells with `sev-*`/valid/gap
  classes; stat-pane text showing the 4 counts matching the loaded image.
- **C-16 real-mechanism:** US-040 is render-on-load (additive signal); any *interactive* element added
  (e.g. strip cell select) MUST drive the real key/click if it exists. **No mandatory C-17 hostile AT**
  here — the panes render **numeric arithmetic on addresses + numeric range labels**, not arbitrary
  file free-text; markup-safety still applies (any range/region label composed into `Text` uses explicit
  `style=`, never a markup string), asserted structurally by TC-042.11's markup-safe inspection.

| AT | When `<input>`, the user observes `<outcome through the surface>` | Kind |
|----|--------------------------------------------------------------------|------|
| **AT-040a** | When case_02 (gaps → partial coverage) is loaded, each range row shows a **micro-bar whose fill reflects that range's covered fraction** — a fully-covered range shows a full-ish bar, a gappy range a partial bar (per-branch content). | golden · C-10b covered-vs-gap |
| **AT-040b** | When a file with a gap is loaded, the **memory strip** shows ≥1 valid-class cell and ≥1 gap-class cell reflecting the image (colour via `css_class_for_severity`). | LLR .9 · per-branch |
| **AT-040c** | When case_04 (errors) vs a clean file is loaded, the **stat pane** shows coverage % + range/error/warning counts **matching the loaded image's actual counts** — error count differs between the two (content, not non-empty). | LLR .10 · C-10b |
| **AT-040d** | When **no file** is loaded, the micro-bars/strip/stat pane show a neutral empty state (0 ranges, coverage `—`); **no crash**. | boundary · empty |
| **AT-040e** | When the Workspace is rendered with a file loaded, the panes contain **NO entropy sparkline element** (D3 dropped-feature scope guard, observable absence). | scope-negative |
- **Boundary catalog (QC-3):** ☑ empty (AT-040d) · ☑ boundary (single-range + 100%-vs-0% coverage folded into AT-040a; multi-range strip) · ☐ invalid — **N/A, reason:** panes are display arithmetic on the already-parsed range model; no new user-input surface to malform (render-only contract, PLAN R4). · ☐ error — **N/A, reason:** no new error path; renders the already-computed model on the UI thread. · ☑ scope-negative (AT-040e, entropy absent).

### US-041 — MAC View leading status glyphs

- **Observable outcome:** On `#screen_mac`, each row of the 8-col MAC table carries a **leading
  per-row status glyph** — OK / warning / out-of-range — so problem records are spotted at a glance,
  not by row colour alone.
- **Shipped surface:** `#screen_mac` (`app.py:3039`) → MAC table (`update_mac_view`, `app.py:7500`;
  columns Tag/Address/InA2L/InMem/Status/SourceLine/ParseErr/A2LMatch, `app.py:3097-3106`) decorated
  with a leading glyph. Glyph severity routes through `css_class_for_severity` / `color_policy`.
- **Deliverable + observation:** rendered MAC rows each showing the correct leading glyph + its
  `sev-*` class for that row's severity.
- **C-16 real-mechanism:** rows render on load; no navigation AT needed for the glyph itself. **C-17:**
  MAC TAG names are **file-derived** (the prototype seeded a `BAD=LINE` parse row) — a hostile-input AT
  is authored here (**AT-041d**) as a justified addition **beyond** the two task-mandatory (A2L+Issues)
  hostile ATs, because the MAC table renders file-derived TAG strings on the same markup surface.

| AT | When `<input>`, the user observes `<outcome through the surface>` | Kind |
|----|--------------------------------------------------------------------|------|
| **AT-041a** | When MAC records covering all three statuses are loaded (case_01 triple + a seeded oor/warn record), each row shows the **correct leading glyph** — OK glyph for in-range+in-A2L, warn glyph for overlap/alias/symbol-only, oor glyph for out-of-range (per-branch content, not non-empty). | golden · C-10b per-branch |
| **AT-041b** | For each row, the glyph's style/class equals `css_class_for_severity(row.severity)` (`sev-ok`/`sev-warning`/`sev-error`) — **no hard-coded hex** (single-source-of-truth round-trip, observed on the surface). | LLR .7 |
| **AT-041c** | When **no MAC file** (0 records) is present, the MAC screen shows its empty state; the glyph column does **not crash**. | boundary · empty |
| **AT-041d** | When a `.mac` line with a hostile TAG (`TAG[bold]=…`, ANSI byte) or a `BAD=LINE` parse-error row is loaded, the row (incl. glyph + TAG cell) renders **LITERAL** — **no MarkupError, no ANSI leak, no crash**. | C-17 recommended · invalid/error |
- **Boundary catalog (QC-3):** ☑ empty (AT-041c) · ☑ boundary (single record; long-unicode TAG folded into AT-041d) · ☑ invalid (hostile/`BAD=LINE` row AT-041d) · ☑ error (parse-error row glyph = warn/oor branch AT-041a/d).

---

## 5. Validation strategy

### 5.1 Methods

- **Layer B — black-box acceptance (`AT-NNN`, `test (pilot)`).** Every US above is validated through
  its shipped screen surface via `App.run_test()` Pilot in `tests/test_tui_directionb.py`, with
  representative + boundary + negative evidence and the actual rendered deliverable observed. This is
  the `test (pilot)` idiom, **not `demo`**. A story's AT FAILS if the deliverable (card / worklist card /
  micro-bar / glyph) is silently absent.
- **Layer A — white-box functional (`TC-042.N`, one per LLR topic).** Validates the architect's LLR
  mechanism. Method per topic below. `test (pilot)`/`test (unit)`/`test (integration)` are the executable
  forms; geometry/scope get `inspection`/`analysis` with a measured value + numeric threshold.

| LLR topic (provisional `LLR-042.N`) | Method | Executed verification (provisional node) | Numeric pass threshold |
|---|---|---|---|
| .1 A2L card renders 16 fields | test (pilot) | `pytest tests/test_tui_directionb.py -k TC_042_1` | 16/16 field labels present for the selected tag |
| .2 A2L master→card selection (real mech) | test (pilot) | `-k TC_042_2` | card content == selected tag's dict for ≥2 distinct tags |
| .3 A2L card⇄table toggle | test (pilot) | `-k TC_042_3` | both code paths reachable; visibility flips 2/2 presses |
| .4 Issues worklist cards worst-first | test (pilot) | `-k TC_042_4` | 1 card/issue; N cards for N issues |
| .5 Issues card→hex-peek + Open-in jump | test (pilot) | `-k TC_042_5` | peek address == selected card address; jump `#hex_view` shows same address |
| .6 Issues ordering rule | test (unit) + pilot | `pytest tests/test_tui_app.py -k TC_042_6` (pure order fn) + pilot render | order key monotonic ERROR≺WARNING≺INFO; 0 inversions |
| .7 MAC status glyph (color_policy-routed) | test (unit) + pilot | `-k TC_042_7` | glyph class == `css_class_for_severity(sev)` for ok/warn/oor; 0 hard-coded hex |
| .8 Workspace coverage micro-bar | test (pilot) | `-k TC_042_8` | bar fill == covered/total per range (±1 cell rounding) |
| .9 Workspace memory strip | test (pilot) | `-k TC_042_9` | ≥1 valid-class + ≥1 gap-class cell on a gapped image |
| .10 Workspace stat pane | test (pilot) | `-k TC_042_10` | 4 stats == actual range/error/warning counts + coverage % |
| .11 markup-safe file-derived text (C-17) | test (pilot) + inspection | `-k TC_042_11` + grep new widgets for `markup=False`/explicit-`Text` | 0 `MarkupError`; 0 raw file-text in a markup string (grep = 0) |
| .12 geometry / empty-state | test (pilot) + analysis | `-k TC_042_12` at `run_test(size=(80,24))` and `(120,30)` | new fixed siblings fit 80/120-col budget (C-13, measured); empty state renders, 0 crash |

- **Engine-frozen inspection (standing):** `pytest tests/test_engine_unchanged.py` +
  `tests/test_tui_directionb.py::test_tc031_*` → **0 diff** vs `main` on the frozen set
  (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`,
  `tui/color_policy.py`). Threshold: **0 frozen-path diffs**.

### 5.2 Dual-traceability tables

**Behavioral chain (black-box) — per user story.** `Observed?` filled at Phase 4.

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? (Phase 4) |
|----|--------------------|-----------------|----------------------------|---------------------|
| US-038 | Selected A2L tag → 16-field labelled record card; table behind toggle | `#screen_a2l` → `#a2l_master` \| `#a2l_card` (+ toggle) | AT-038a, AT-038b, AT-038c, AT-038d, AT-038e, **AT-038f** | ☐ |
| US-039 | Worst-first issue cards + live hex-peek + Open-in jump | `#screen_issues` → `#issues_worklist` \| `#issues_hex`; `#hex_view` | AT-039a, AT-039b, AT-039c, AT-039d, AT-039e, **AT-039f** | ☐ |
| US-040 | Per-range micro-bar + memory strip + stat pane; no entropy | `#screen_workspace` / `#ws_left` | AT-040a, AT-040b, AT-040c, AT-040d, AT-040e | ☐ |
| US-041 | Leading per-row OK/warn/oor glyph on MAC table | `#screen_mac` → MAC table (`update_mac_view`) | AT-041a, AT-041b, AT-041c, AT-041d | ☐ |

**Functional chain (white-box) — HLR/LLR → TC.** HLR ids are the architect's; bound **by topic** at
merge (provisional `HLR-042.a`=US-038, `.b`=US-039, `.c`=US-040, `.d`=US-041).

| Requirement (provisional) | Topic | Method | Test Case (`TC-042.N`) |
|---|---|---|---|
| HLR-042.a (US-038) | A2L master/detail | test (pilot) | TC-042.1, TC-042.2, TC-042.3 |
| HLR-042.b (US-039) | Issues worklist | test (pilot) | TC-042.4, TC-042.5, TC-042.6 |
| HLR-042.c (US-040) | Workspace signal | test (pilot) | TC-042.8, TC-042.9, TC-042.10 |
| HLR-042.d (US-041) | MAC glyphs | test (pilot) | TC-042.7 |
| LLR-042.1 | A2L card 16 fields | test (pilot) | TC-042.1 |
| LLR-042.2 | A2L master→card selection | test (pilot) | TC-042.2 |
| LLR-042.3 | A2L card⇄table toggle | test (pilot) | TC-042.3 |
| LLR-042.4 | Issues cards worst-first | test (pilot) | TC-042.4 |
| LLR-042.5 | Issues card→hex-peek + Open-in | test (pilot) | TC-042.5 |
| LLR-042.6 | Issues ordering rule | test (unit)+pilot | TC-042.6 |
| LLR-042.7 | MAC glyph color_policy-routed | test (unit)+pilot | TC-042.7 |
| LLR-042.8 | Workspace coverage micro-bar | test (pilot) | TC-042.8 |
| LLR-042.9 | Workspace memory strip | test (pilot) | TC-042.9 |
| LLR-042.10 | Workspace stat pane | test (pilot) | TC-042.10 |
| LLR-042.11 | markup-safe file-derived text (C-17) | test (pilot)+inspection | TC-042.11 |
| LLR-042.12 | geometry / empty-state | test (pilot)+analysis | TC-042.12 |

> Cross-layer: the C-17 topic (.11) is validated **both** white-box (TC-042.11: hostile render + grep
> for `markup=False`/explicit-`Text`) **and** black-box through the two mandatory hostile ATs (AT-038f,
> AT-039f) + the recommended AT-041d. The mechanism-only TC is **not** acceptance on its own.

### 5.3 Batch acceptance criteria

1. **Every LLR topic (.1–.12) has ≥1 `TC-042.N`** with a pass result (Layer A complete).
2. **Every user story (US-038…US-041) has ≥1 passing `AT-NNN`** observing its outcome **through the
   shipped surface**, each story's AT set carrying **boundary + negative** evidence (per the QC-3
   boundary catalogs above; any `N/A` class carries a one-line reason).
3. **C-16 real-mechanism:** every selection / navigation / toggle / Open-in AT (AT-038a/b/c/d/f,
   AT-039c, AT-039d) drives `pilot.press`/`pilot.click` on the real widget — **0** ATs use
   `widget.focus()` or a direct setter as a selection proxy.
4. **C-17 hostile-input:** AT-038f **and** AT-039f (mandatory) pass — brackets/ANSI render literal,
   **0 `rich.errors.MarkupError`**, 0 style/ANSI leak, 0 crash; AT-041d (recommended) same. TC-042.11
   grep finds **0** raw file-derived strings interpolated into a markup string in the new widgets.
5. **0 engine-frozen diffs** (`test_engine_unchanged.py` + `test_tc031_*` green).
6. **Snapshot cells** for the four changed views are added **xfail-until-baseline** (R1: local regen
   FORBIDDEN, textual pinned `8.2.8`; regen in canonical CI post-merge) — an xfail cell is not a fail.
7. **No requirement without an assigned validation method**; both traceability chains complete for
   every US (Layer A + Layer B).

---

## Testability risks to resolve with the architect / orchestrator (Phase-1)

1. **US-039 dual hex behavior (D1b + Open-in).** D1b keeps a **live hex-peek pane** beside the worklist
   (`#issues_hex`, updates on card selection) AND US-039 names an **Open-in jump** to the Workspace hex
   (`#hex_view`). These are **two distinct surfaces/behaviors**. AT-039c targets the peek; AT-039d
   targets the jump. **Need the architect to confirm both exist** and name their widget ids so the ATs
   bind cleanly. If only one is built, AT-039c/AT-039d must be reconciled at merge.
2. **A2L hostile-symbol seeding path (blocks AT-038f).** The enriched-tag dict is produced by frozen
   `a2l.py`. To keep AT-038f black-box on the render surface without touching a frozen parser, an LLR
   should expose a **synthetic enriched-tag seeding path** (mirroring `_seed_issues_screen`) OR add a
   NEW hostile `.a2l` fixture (counted in the increment budget). **Prefer the seeding helper.**
3. **MAC glyph severity source (affects AT-041b assertion).** Confirm whether the glyph's severity comes
   from the per-record MAC `Status` field or from a joined `ValidationIssue`. AT-041b asserts the
   `css_class_for_severity` round-trip; it needs to know **which** severity object drives the glyph.
4. **Per-range coverage fraction availability (affects AT-040a threshold).** AT-040a asserts micro-bar
   fill == covered/total per range. Confirm `range_validity`/`ranges` exposes a per-range covered
   fraction directly (batch-27 minimap worked in cells, not per-range fractions). If not directly
   available, LLR-042.8 must define the arithmetic and AT-040a's ±1-cell threshold re-checked.
5. **C-13 geometry budget for three new fixed siblings** (A2L record card, Workspace stat pane, memory
   strip row). TC-042.12 requires a **measured** fit at 80/120 cols before any fixed width is committed
   — measurement owed by the architect's LLR (`run_test(size=…)` probe cite), not asserted as fact.
