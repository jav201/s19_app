# 01 — Requirements · batch-28 · Prototype-approved view enhancements · R-TUI-042 (v2)

**BLUF:** Fold three operator-approved prototype treatments into the real s19tui TUI —
A2L table **polish** (US-038, dir A), Issues **grouped-by-severity dense** view (US-039,
dir B), Workspace **dense cockpit** inline signal (US-040, dir B). **3 HLR anchors (6 `shall`
clauses) · 12 LLR · 15 AT · 12 TC-topics.** TUI render-side only; 0 engine-frozen diffs. One C-17 mandatory hostile-input
AT (Issues code chips are the only new markup surface) and real-mechanism selection ATs (C-16)
carried. One genuine geometry risk (Workspace coverage micro-bar in the fixed 22-col
`#ws_left`); everything else clears by construction or carries a measured-in-Phase-3 flag.

> **v2 (Phase-1 iterate, 2026-07-07):** operator re-selected prototype directions at the P1
> gate. See §6.5 for the Before/After · Deleted/New amendment. v1 (A2L master/detail, Issues
> worklist, MAC glyphs) is superseded; MAC dropped. Re-derived inline; Phase-2 tri-agent
> cross-review is the independent check. Original derivation slices retained at
> `_arch-hlr-llr.md` / `_qa-acceptance-validation.md` (v1 — read with the §6.5 delta).

---

## 1. Purpose & scope

- **In scope (3 views):** A2L Explorer (table polish — dir A), Issues Report
  (grouped-by-severity + counts + chips — dir B), Workspace (coverage bars + memory strip +
  stat pane — dir B). TUI render-side only.
- **Out of scope:** MAC View (operator chose dir A = unchanged → dropped); A2L master/detail
  and Issues worklist (both descoped this iterate); Patch Editor, A2B Diff, Bookmarks; global
  persistent memory strip (D2); Workspace entropy sparkline (D3); any change to how enriched
  tags / issues / ranges are **computed** (engine).
- **New ids:** requirement **R-TUI-042**; stories **US-038, US-039, US-040** (US-041 dropped).

## 2. Context & verified facts (draft-time grounding)

Render-only; each reads an already-computed model on the UI thread (`models.py::LoadedFile`
thread split):

- **A2L table** — `update_a2l_tags_view` builds the 16-cell rows into DataTable
  `#a2l_tags_list` (`app.py:7827`; columns `app.py:3127-3144`); rows already carry sev styling
  via `_severity_style` (`app.py:7896`). Polish = density + fixed header; no change to the
  enrichment / paging / colouring logic. Density mechanism precedent: the workspace
  `density-comfortable`/`density-compact` classes (`styles.tcss:165-171`).
- **Issues** — `update_validation_issues_view` (`app.py:5556`) fills DataTable
  `#validation_issues_list` (8 cols `app.py:3112-3121`) from `_validation_issues:
  list[ValidationIssue]` (`app.py:764`); split `#issues_columns` = list (2fr) |
  `#issues_hex_pane` (1fr) (`styles.tcss:723-738`); the peek `#issues_hex_pane`
  (`Static(markup=False)`, `app.py:1310`) is repainted by `_update_issues_hex_pane(address)`
  (`app.py:5428`, from selection handler `app.py:5503`). Grouped-dense view groups these rows
  by severity with count headers + code chips; the peek + selection wiring are preserved.
- **Workspace** — `update_sections` renders per-range rows from `current_file.ranges` /
  `range_validity` (`app.py:7166-7205`); `#ws_left` (22) | `#ws_center` (1fr) | `#ws_right`
  (40) (`styles.tcss:188-201`). Coverage arithmetic reuses `coverage_stats`/`CoverageStats`
  (`screens_directionb.py:538` / `504-535`); memory strip reuses batch-27 `cell_status`
  (`screens_directionb.py:285`) / `status_to_css_class` / `render_ranges`.
- **Palette:** colour exclusively via frozen `color_policy.css_class_for_severity` /
  `SEVERITY_CLASS_MAP` (`tui/color_policy.py:5-19`). No hard-coded severity hex.
- **C-17 injection surface (verified):** `_scrub_issue_message` scrubs `.message` ANSI/control
  ONLY — not Rich brackets, never `.symbol`/`.code` (`validation/model.py:71-72,137`); it is
  engine-frozen → the render layer is the sole defense. The Issues **code chip** (styled
  `.code`) + any styled `.symbol`/`.message` on the grouped view are the new markup surface.

### 2.6 Source user stories (v2)

| ID | User Story | Dir | DoR |
|----|------------|-----|-----|
| US-038 | As an operator scanning A2L symbols, I want the symbol table polished — a column header that stays visible while I scroll and a more compact row density — so that I can read a long table without losing the column meanings, keeping the existing severity colouring. | A | READY |
| US-039 | As an operator triaging a loaded image, I want the Issues Report grouped by severity with a count per group and the issue code shown as a compact chip, keeping the live hex-peek beside it, so that I can scan how many problems of each kind exist and jump into any one. | B | READY |
| US-040 | As an operator, I want the Workspace to show inline coverage signal — a per-range coverage micro-bar, a whole-image memory strip, and an at-a-glance stat pane (coverage %, range/error/warning counts) — so that I can judge the image's health from the Workspace without opening the Memory Map. | B | READY |

**Decisions (DoR + P1 iterate, operator 2026-07-07):** A2L = table polish (compact density +
fixed header; NOT master/detail). MAC = unchanged → dropped. Issues = grouped-by-severity +
counts + code chips + retained hex-peek (NOT worklist). Workspace = dense cockpit,
Workspace-only strip (D2), no entropy (D3).

---

## 3. High-level requirements (HLR)

### HLR-038 — A2L Explorer table polish (fixed header + compact density) · US-038
While an A2L table is displayed, the A2L Explorer **shall** keep the column header row visible
while the operator scrolls the rows, and **shall** render rows at a compact density, without
altering the existing tag enrichment, paging, or per-row severity colouring. — *AT-038a/b/c/d +
TC-042.1/.2.*

### HLR-039.a — Issues Report grouped-by-severity with count headers + code chips · US-039
While validation issues exist, the Issues Report **shall** present them grouped by severity
(errors, then warnings, then info), each group led by a header carrying that group's issue
count, with each issue's code rendered as a compact chip, in place of the prior single flat
table. — *AT-039a/b + TC-042.3/.4.*

### HLR-039.b — Issues selection drives the retained hex-peek · US-039 (D1b)
When the operator selects an issue in the grouped view, the Issues Report **shall** repaint the
retained `#issues_hex_pane` at that issue's address, reusing `_update_issues_hex_pane`, with no
new hex renderer. — *AT-039c + TC-042.5.*

### HLR-040.a — Workspace per-range coverage micro-bar · US-040
While a file is loaded, the Workspace ranges panel **shall** render, on each range row, a
coverage micro-bar derived by display arithmetic on the already-parsed `ranges`/`range_validity`,
without any new parse/coverage/validation computation. *(Bar semantics per LLR-042.7: validity
colour + relative size.)* — *AT-040a + TC-042.7.*

### HLR-040.b — Workspace whole-image memory strip (single-row minimap) · US-040 (D2/D3)
While a file is loaded, the Workspace **shall** render a single-row whole-image memory strip
whose cells are coloured valid/invalid/gap from the already-computed `ranges`/`range_validity`
(reusing batch-27 cell-status logic), appearing only on the Workspace screen. — *AT-040b +
TC-042.8.*

### HLR-040.c — Workspace stat pane (coverage % + range/error/warning counts) · US-040 (D3)
While a file is loaded, the Workspace **shall** render a stat pane showing coverage percent and
the range, error, and warning counts, derived by display arithmetic on the already-parsed
ranges and the already-computed `_validation_issues`, and **shall** show no entropy figure. —
*AT-040c/e + TC-042.9.*

### Acceptance blocks (black-box) — one per story

**US-038 A2L polish.** Surface `#screen_a2l` → `#a2l_tags_list`. *(Rail keys — verified app.py:687-691:
Workspace=`1`, A2L=`2`, MAC=`3`, Map=`4`, Issues=`5`.)* **AT-038a** load case_01, open A2L
(`press "2"`), focus `#a2l_tags_list` and drive a REAL `pilot.press("pagedown")` → assert the
table actually scrolled (`scroll_offset.y > 0`) AND the header is still shown (`table.show_header`
with a column label rendered) — a real-scroll assertion that can fail, not a columns-always-present
tautology. **AT-038b** compact density applied — the A2L pane/table carries the queryable density
class (`.has_class("density-compact")`, mirroring the `#workspace_body` precedent). **AT-038c**
existing **sev-coloured rows preserved** — an error-severity tag row still carries its `sev-error`
style (regression guard). **AT-038d** no file → empty state, no crash. *(No C-17 hostile AT: no
new markup surface — the table already renders tag names via severity-styled `Text` (`app.py:7896`),
markup not parsed; TC-042.2 additionally asserts cells stay `Text` after the polish — batch-27 B-1
guard.)*

**US-039 Issues grouped-dense.** Surface `#screen_issues` → grouped list | retained
`#issues_hex_pane`. **AT-039a** seed N mixed issues (`_seed_issues_screen`) → one queryable
`.issue-group-header` per present severity, each asserting `count == len(group in the filtered
whole list)`, and ≥1 queryable `.issue-code-chip` node carrying the issue `.code` text.
**AT-039b** seed a set containing ≥1 ERROR, ≥1 WARNING and ≥1 INFO (extend `_make_issues`, which
today emits only ERROR+WARNING) → all three `.issue-group-header`s render in **errors → warnings
→ info** order (observed order, C-10b — the INFO branch is seeded, not assumed). **AT-039c**
select a **non-default** issue via the real mechanism (`pilot.click`/`pilot.press`) →
`#issues_hex_pane` repaints at THAT issue's address (content changed); an `address is None` issue
→ neutral peek, no crash (C-16, real mechanism). **AT-039d** 0 issues → "no issues" empty state,
neutral peek. **AT-039e (C-17 MANDATORY)** seed an issue with `.code`/`.symbol` =
`MAP_Model[bold]` + `\x1b[31m` and `.message = "open[red]sensor[/] [link=file:///etc]"` → the
group render + code chip show the brackets/ANSI as **LITERAL** text — no `rich.errors.MarkupError`,
no style/ANSI leak, **no OSC-8 hyperlink escape** from `[link=…]` (no clickable `file://` emitted),
no crash (covers the scrubbed-`.message` bracket path AND the unscrubbed `.code`/`.symbol` path).
**AT-039f (DoS bound)** seed a large-N issue list (≈5 000) → the grouped view mounts at most one
bounded paging window of rows (mounted `.issue-code-chip` count ≤ `page_size`), not O(N); no hang.

**US-040 Workspace signal.** Surface `#screen_workspace` / `#ws_left`. **AT-040a** case_02
(gaps) → each range row shows a micro-bar whose **colour = validity** (valid≠invalid class) and
whose **width ∝ range size** (a larger range → a wider-or-equal bar) — per-branch, C-10b.
**AT-040b** gapped image → memory strip has ≥1 valid-class + ≥1 gap-class cell (colour via
`css_class_for_severity`). **AT-040c** case_04 vs clean → stat pane error count differs;
coverage %/counts match the image (C-10b). **AT-040d** no file → neutral empty (0 ranges,
coverage `—`), no crash. **AT-040e** file loaded → NO entropy-sparkline element (D3
scope-negative). *(Invalid/error classes N/A — render-only arithmetic on the parsed model, no
new user-input surface.)*

---

## 4. Low-level requirements (LLR)

> V-5: every `TC-042.N` / test path / `-k` selector is provisional-until-Phase-3; NEW symbols
> flagged `NEW`. Workspace LLRs (.7/.8/.9) + geometry (.11) + the engine-frozen invariant (.12)
> are carried unchanged from v1; A2L (.1/.2) + Issues (.3/.4/.5/.6/.10) are re-derived. §6.5 maps old→new.

| LLR | Parent | Statement (summary) | Validation / TC | Sources / NEW |
|-----|--------|---------------------|-----------------|---------------|
| **042.1** | 038 | A2L rows scroll INSIDE the `#a2l_tags_list` DataTable (the DataTable — not an outer container — owns row scrolling), so its column header stays fixed. Verify-not-build (Textual DataTable default); the TC drives a REAL scroll and asserts it moved. | test (pilot) TC-042.1 | table `#a2l_tags_list` `app.py:3125`; DataTable owns scroll (NOT `#a2l_scroll`, the Workspace context pane); verify in Phase 3 |
| **042.2** | 038 | A2L rows render at a compact density via a queryable density class on the A2L pane/table (precedent `#workspace_body.density-compact`); the existing per-row `_severity_style` colouring + paging stay unchanged AND cells remain `rich.text.Text` (markup NOT flipped to True — batch-27 B-1 guard). | test (pilot)+inspection TC-042.2 | density precedent `styles.tcss:165-171`; sev styling `app.py:7896`; density class `NEW` |
| **042.3** | 039.a | Issues render grouped by severity, each group preceded by a header showing the group's issue count, over `_validation_issues`; groups in error→warning→info order. | test TC-042.3 | issues `app.py:764`; renderer `update_validation_issues_view` `app.py:5556`; group widget `NEW` |
| **042.4** | 039.a | Each issue's `.code` renders as a compact chip, composed markup-safe (see .10); no hard-coded severity hex — chip/severity colour via `css_class_for_severity`. | test+inspection TC-042.4 | `.code` field `app.py:3113`; `color_policy`; chip render `NEW` |
| **042.5** | 039.b | Selecting an issue via the real selection event repaints `#issues_hex_pane` via `_update_issues_hex_pane(address)`; `address is None` → neutral peek, no crash. | test (e2e) TC-042.5 | peek `app.py:1310`/`5428`/`5503`; handler adapts to grouped widget `NEW` |
| **042.6** | 039.a | The grouped view PRESERVES the existing issue paging window (`_get_window_bounds`/`page_size` `app.py:5605-5608`) so at most one bounded window of rows is mounted (a hostile large-N issue list cannot mount O(N) widgets); the existing severity filter (`issues_filter_all/error/warning`) is preserved and SCOPES which issues render; each group-header count = the whole (filtered) list count for that severity (not the windowed subset); a truncation note shows when issues exceed the window; the view exposes queryable `.issue-group-header` (severity label + integer count) and `.issue-code-chip` nodes. | test (pilot) TC-042.6 | paging `app.py:5605-5608`/`5695`/`5707`; filter `app.py:1298-1300`/`8282-8290`; nodes `NEW` |
| **042.7** | 040.a | **[R4]** Per range row, a fixed-width micro-bar whose **colour = validity** (`css_class_for_severity`: valid→ok, invalid→error) and whose **fill width ∝ range byte-size relative to the largest range** (relative-magnitude spark; a contiguous range is 100% covered by definition). No horizontal widening of the `#ws_left` row. | test (pilot) TC-042.7 | loop `app.py:7194-7205`; `#ws_left` 22 `styles.tcss:189`; helper `NEW` |
| **042.8** | 040.b | Single-row memory strip colours cells valid/invalid/gap via batch-27 `cell_status`/`status_to_css_class` over `ranges`/`range_validity` (rows=1 variant); absent on non-Workspace screens. | test TC-042.8 | `screens_directionb.py:285/333/211/967`; strip `NEW` |
| **042.9** | 040.c | Stat pane shows coverage % + range count from `coverage_stats(...)` + error/warning counts tallied from `_validation_issues` by severity; no entropy. | test TC-042.9 | `screens_directionb.py:538/504-535`; `app.py:764`; host `NEW` (cand. `#ws_right`) |
| **042.10** | 039.a | **[C-17]** Every file-derived string on the Issues grouped view (`.code` chip, `.symbol`, `.message`) rendered as `rich.text.Text` with explicit `style=`; never interpolated into a markup-parsed string. | test (hostile)+inspection TC-042.10 | scrub gap `model.py:71-72,137`; precedent `screens_directionb.py:981/753`; panel-side |
| **042.11** | all | Each new/changed surface (A2L density, Issues groups+chips, coverage bar, memory strip, stat pane) renders legibly at 80- and 120-col regimes without pushing existing panes off-screen (existing `width-narrow` <120 breakpoint), with a neutral no-data state. C-13 budgets §6.1. | test (e2e)+analysis TC-042.11 | breakpoint `app.py:4013`; panes `styles.tcss:188-216`; empty `screens_directionb.py:856` |
| **042.12** | all | Render changes only in `app.py` / new `tui/` widgets / `styles.tcss`; **0 diff** on any engine-frozen path; no new parse/coverage/validation call in render code. | test+inspection | guards `test_engine_unchanged.py`, `test_tc031_*` |

*(LLR set = .1–.12. Workspace LLRs .7/.8/.9 + geometry .11 + engine-frozen invariant .12 are
carried unchanged from v1 (were v1's .8/.9/.10/.12/.13); A2L .1/.2, Issues .3/.4/.5/.6/.10 are
the re-derived set. `.6` is the Phase-2 DoS/paging + filter-scope + structural-observable LLR.)*

---

## 5. Validation strategy

### 5.1 Methods
- **Layer B (black-box `AT`, `test (pilot)`):** 15 ATs (US-038: 4, US-039: 6, US-040: 5) through
  each shipped screen surface via `App.run_test()` Pilot in `tests/test_tui_directionb.py`,
  representative + boundary + negative, deliverable observed.
- **Layer A (white-box `TC-042.N`):** one per LLR topic; unit/integration/pilot per the LLR
  table; geometry/scope via inspection/analysis with a measured value + threshold.
- **Engine-frozen inspection (standing):** `test_engine_unchanged.py` + `test_tc031_*` → 0
  frozen-path diffs.

### 5.2 Dual traceability

**Behavioral (black-box):**

| US | Observable outcome | Shipped surface | AT | Observed? |
|----|--------------------|-----------------|----|-----------|
| US-038 | Header stays on scroll; compact rows; sev colour kept | `#screen_a2l` → `#a2l_tags_list` | AT-038a/b/c/d | Phase 4 |
| US-039 | Severity groups + counts + code chips; bounded paging; live hex-peek | `#screen_issues` → grouped list \| `#issues_hex_pane` | AT-039a/b/c/d/**e**/**f** | Phase 4 |
| US-040 | Per-range bar + memory strip + stat pane; no entropy | `#screen_workspace` / `#ws_left` | AT-040a/b/c/d/e | Phase 4 |

**Functional (white-box):** HLR-038→TC-042.1/.2; HLR-039.a→TC-042.3/.4/.6; HLR-039.b→TC-042.5;
HLR-040.a→TC-042.7; HLR-040.b→TC-042.8; HLR-040.c→TC-042.9; LLR-042.N→TC-042.N;
LLR-042.6→TC-042.6 **+** black-box AT-039f (DoS bound); LLR-042.10→TC-042.10 **+** black-box
AT-039e (mechanism-only TC is not acceptance on its own); LLR-042.12→`test_engine_unchanged`/`test_tc031_*`.

### 5.3 Batch acceptance criteria
1. Every LLR topic has ≥1 passing `TC-042.N`; every US ≥1 passing `AT` through the shipped
   surface with boundary + negative evidence.
2. **C-16:** every selection/scroll AT (AT-038a, AT-039c) drives real `pilot.press`/`pilot.click`/
   scroll — 0 use `.focus()` or a direct setter proxy.
3. **C-17:** AT-039e (mandatory) passes — literal brackets/ANSI, 0 `MarkupError`, 0 leak, 0
   crash; TC-042.10 grep = 0 raw file-text in a markup string in the Issues render.
4. **0 engine-frozen diffs**; 0 hard-coded severity hex in new render code.
5. Snapshot cells for the 3 changed views added **xfail-until-baseline** (local regen FORBIDDEN,
   textual `8.2.8`; canonical-CI regen post-merge — batch-25/27 pattern).
6. Full suite green (≥ current count; guards pass).

---

## 6. Appendices

### 6.1 C-13 geometry budget (per new/changed surface)
Regime: narrow = width `<120` (`app.py:4013`); rail 22 wide / 4 narrow (`styles.tcss:1058,1096`);
`body_w = terminal − rail`. 80→narrow→body 76; 120→wide→body 98.

| # | Surface | Basis | Verdict |
|---|---------|-------|---------|
| 1 | A2L density/header | in-place on `#a2l_tags_list` (no new sibling; density shrinks rows) | **Clears** — density reduces footprint; header-fixed is DataTable behaviour |
| 2 | Issues groups+chips | in-place on the `#issues_columns` 2fr list slot (proportional); group headers + chips are vertical/in-cell | **Clears by construction** (proportional); vertical group headers add rows, scroll absorbs |
| 3 | **Coverage micro-bar** | in-row in `#ws_left` 22 (usable ≈18; label already 2-line) | **RISK** (batch-17 mode): render as added line OR bounded inline; form `assumed — measure Phase 3` |
| 4 | Memory strip | 1-row band over `#ws_center` 1fr (vertical ~3 rows) | **Low-mod (vertical)**; height `assumed — measure Phase 3` (hex still ≥1 row @80×24) |
| 5 | Stat pane | host `#ws_right` 40/30% (≈22 @80) | **Clears**; vertical room `assumed — Phase 3` |

Only #3 is a genuine pinch (constrained in LLR-042.7 + gated by TC-042.11). #4/#5 carry vertical
flags. #1/#2 clear.

### 6.2 Increment-split hint
- **Inc-A (Issues dense):** LLR-042.3/.4/.5/.10 — grouped view + chips + selection + markup-safety.
- **Inc-B (Workspace in-place):** LLR-042.7 micro-bar + LLR-042.9 stat pane.
- **Inc-C (Workspace band):** LLR-042.8 memory strip (isolates the vertical-budget change).
- **Inc-D (A2L polish):** LLR-042.1/.2 — smallest; may fold into A or D as sizing allows.
- (Boundaries provisional; ≤5 files each; sequence Issues/Workspace before A2L.)

### 6.3 Assumptions (open — verify Phase 3)
1. A2L DataTable header is fixed-on-scroll by Textual default (LLR-042.1) — verify; if not,
   add a `fixed_rows`/header-pin. 2. A2L compact density via a class toggle (precedent
   `styles.tcss:165-171`). 3. Issues group render form (per-severity sub-sections vs group-header
   rows in one table) — Phase-3 layout detail; both keep `#issues_hex_pane`. 4. Coverage micro-bar
   render form (added-line vs inline ≤~8) — measure @80/120. 5. Memory-strip vertical height —
   assert `#ws_center` hex still renders @80×24. 6. Stat-pane host `#ws_right` vertical room.

### 6.4 Phase-1 reconciliation log
- R1–R5 (v1) resolved as recorded in the v1 slices; R4 (coverage-bar = validity+relative-size,
  not covered-fraction) carried into LLR-042.7. R3 (MAC glyph severity) is now moot (MAC dropped).

### 6.5 Requirement amendment (Phase-1 iterate, 2026-07-07) — Before/After · Deleted/New
Operator re-selected prototype directions at the P1 gate. Parent-US re-read: US-038/039/041
outcomes re-stated; US-040 unchanged.

**A2L (US-038): C → A.**
- **Before:** master/detail record card + wide-table toggle (HLR-038.a/.b; LLR-042.1 card /
  .2 selection / .3 toggle; AT-038a–f incl. hostile).
- **After:** table polish — fixed header + compact density, sev rows preserved (HLR-038; new
  LLR-042.1 header / .2 density; AT-038a–d, no hostile AT — no new markup surface).
- **Deleted:** old LLR-042.1/.2/.3 (card/selection/toggle); AT-038e/f (master-detail empty +
  hostile symbol). **New:** LLR-042.1 (fixed header), LLR-042.2 (compact density).

**MAC (US-041): B → A (unchanged) → DROPPED.**
- **Before:** leading status glyph (HLR-041; LLR-042.7 glyph; AT-041a–d).
- **After:** none — dir A is today's MAC; story removed from batch-28.
- **Deleted:** US-041, HLR-041, old LLR-042.7 (MAC glyph), AT-041a/b/c/d.

**Issues (US-039): C → B.**
- **Before:** worst-first worklist of cards + per-card Open-in jump (HLR-039.a worklist /
  .b hex-peek+Open-in; LLR-042.4 worklist / .5 selection+Open-in / .6 ordering).
- **After:** grouped-by-severity + count headers + code chips, retained hex-peek, no per-card
  Open-in (HLR-039.a grouped / .b hex-peek; LLR-042.3 grouping / .4 chips / .5 selection→peek).
- **Deleted:** old LLR-042.4 (worklist) / .6 (worklist ordering); AT-039d (Open-in C-12 jump).
  **New:** LLR-042.3 (group+counts), LLR-042.4 (code chips). **Retained:** hex-peek selection
  (LLR-042.5), C-17 hostile AT (now AT-039e over `.code` chip surface).

**Workspace (US-040): UNCHANGED** (HLR-040.a/.b/.c; LLR-042.7/.8/.9 [were .8/.9/.10]; AT-040a–e).

**Re-derived TC/AT:** LLR→TC one-to-one preserved; behavioral/functional traceability rebuilt in
§5.2. Net (v1→v2): 8→6 HLR clauses, 13→11 LLR, 21→14 AT.

### 6.6 Phase-2 amendment (v2.1, 2026-07-07) — cross-review majors folded
Phase-2 tri-agent review (0 blockers). Accepted majors folded (details in `02-review.md`):
- **New LLR-042.6** — Issues grouped view PRESERVES the existing paging window (bounds mounted
  widgets → no hostile-large-N DoS, security F1), the existing severity filter is PRESERVED and
  SCOPES the rendered set (architect A2), group-header count = whole (filtered) list count
  (architect A3), and the view exposes queryable `.issue-group-header`/`.issue-code-chip` nodes
  (qa F3). **New AT-039f** (large-N bounded mount).
- **LLR-042.1 + AT-038a reframed** — A2L fixed-header is verify-not-build; the AT drives a REAL
  `pagedown` and asserts `scroll_offset.y > 0` + header shown (was a tautology; wrong `#a2l_scroll`
  cite corrected — that is the Workspace context pane, not the tags DataTable) (qa F1 / architect F4).
- **AT-039b** seeds ≥1 INFO (the cited `_make_issues` emits only ERROR+WARNING) (qa F2).
- **AT-039e** adds a **no-OSC-8-hyperlink** assertion for `[link=…]` (security F2).
- **TC-042.2** asserts A2L cells remain `Text` (markup not flipped) after the density polish
  (batch-27 B-1 guard, security F3); **AT-038b** asserts the density **class** (qa F4).
- Minors: HLR tally (3 anchors / 6 clauses); per-range bar labelled **range-magnitude (not
  covered-fraction)**; §4 note label (.11 geometry / .12 frozen); `_validation_issues` anchor
  `app.py:766`. **Net v2→v2.1: +1 LLR (.6), +1 AT (039f) → 12 LLR / 15 AT / 12 TC.**
