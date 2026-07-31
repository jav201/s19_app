# Requirements Document — s19_app — Batch 2026-07-30-batch-72

> **Status: REVISION 3 — Phase-2 re-gate discharged, Phase 2 APPROVED, Phase 3 authorized.**
> Revision 1 was drafted by the prototyping session and approved at the Phase-1 gate
> (2026-07-30). Phase 2 returned **9 blockers / 12 majors / 7 minors**
> ([`02-review.md`](02-review.md)); this revision folds them, and every number the fold
> introduces was **executed** rather than reasoned — see [`00-measurements.md`](00-measurements.md).
> Two requirements did not survive the fold and are **withdrawn**, with their evidence recorded
> in §6.5 rather than silently dropped.

## 1. Introduction

### 1.1 Purpose
Implement the operator-decided redesigns for the 2026-07-28 P1 design defects:
**CRC Designer → prototype Variant B** (paired Reflection row + KAT demoted under Check)
and **Legend modal → prototype Variant B** (two-pane, colour key always visible).
Operator verdict 2026-07-30: *"Ok, CRC viewer vamos con (B). Leyenda, dos paneles. (B)"*.

### 1.2 Scope
- **IN:** `s19_app/tui/crc_designer_view.py` (compose + a module-level id tuple),
  `s19_app/tui/screens.py` (`LegendScreen.compose` + a width-regime hook),
  `s19_app/tui/styles.tcss` (layout rules only), `tests/`, `REQUIREMENTS.md`.
- **OUT:** engine-frozen files (all — no unfreeze needed); `legend.py` (reused untouched);
  any KAT *removal* (the operator chose **demote**); Flow Builder; prototype teardown (batch close).
- **OUT — added at revision 2 (S-4):** no edit to the `.sev-*`, `.band-*` or `.legend-card-*`
  blocks in `styles.tcss` (`:628-679`, `:1556-1568`). This batch adds **layout** rules only.
  Neither screen is snapshot-captured (P-2/P-3), so a hue drift here would be caught by nothing.
- **OUT — added at revision 2 (M-4):** CRC `Select` **height**. See §6.5 W-1 — measured and withdrawn.

### 1.3 Definitions
| Term | Binding definition (measured, not asserted) |
|---|---|
| **wide regime** | `width >= 120`. The breakpoint is `app.py:6202` (`narrow = width < 120`). Cited, not invented. |
| **floor** | `80x24` requested, which yields `screen.size == Size(78, 22)` under a modal. Coordinates are read from measured regions, never the requested tuple. |
| **focusable control** | `widget.focusable and widget.region.area > 0`, scoped to the named container. The area filter is not cosmetic: six zero-area `SelectOverlay` phantoms exist (M-1) and a naive walk pairs them nonsensically at `y=0`. |
| **vertically abutting** | `b.region.y == a.region.y + a.region.height` **and** the x-bands overlap (`a.x < b.x + b.width and b.x < a.x + a.width`). |

### 1.4 References
- `prototypes/p1_design_defects.HANDOFF-PLAN.md` · `p1_design_defects.NOTES.md` (verdict §7)
- PR [#164](https://github.com/jav201/s19_app/pull/164) (prototypes + frames + review page)
- [`.dev-flow/BACKLOG-CODE.md`](../BACKLOG-CODE.md) lines 149-156 (the four defect bullets)
- Batch-59 lineage (merged #113): the current bench layout and its ATs
- [`00-measurements.md`](00-measurements.md) — every geometry number in this document
- [`02-review.md`](02-review.md) + the three lane reviews

## 2. Overall description

### 2.1 Product perspective
Two independent surfaces of the shipped Textual TUI: the CRC Designer bench (a base-screen view,
reached by the `0` rail key) and the Legend modal (a `ModalScreen` pushed from any colour-coded
view). They share no code and are sequenced only by increment order.

### 2.2 Functions
Layout only. No new I/O, no network, no new dependency, no new external action surface, and no
change to any computation — the CRC bench stays preview-only and the legend data layer is untouched.

### 2.3 Users
The firmware engineer operating the CRC Designer bench, and any operator opening the Legend.

### 2.4 Constraints
- `_recompute` (`crc_designer_view.py:1115-1142`) queries **six** ids
  (`#crc_kat_verdict`, `#crc_custom_vector_result`, `#crc_json_preview`, `#crc_warnings`,
  `#crc_coverage_preview`, `#crc_coverage_window`) and aborts on the first `NoMatches` — every id
  MUST stay mounted. **Verified at Phase 2: `#crc_live_verify` is NOT among them** (it is the
  wrapper's id, not a queried surface), so retiring the hero tile removes no queried id *provided*
  `#crc_kat_verdict` is re-parented.
- AT-B59-03/08 (`tests/test_crc_designer_view.py:895-1312`) assert 3 pairwise-distinct bench-column
  ancestors; Variant B keeps `#crc_bench_c1/c2/c3`, so they survive unedited.
  **AT-B59-05 does NOT survive** — see §6.5 A-1.
- Legend data layer (`legend.py`) is reused **verbatim**; only `LegendScreen.compose` changes.
  Confirmed by measurement (M-6): `_render_key`/`_render_card` return flat `List[Widget]` with
  **0** containers, so the split needs no data-layer edit at all.
- **C-17 markup safety.** Every existing `markup=False` sink stays `markup=False`. At revision 1
  this was an *assertion*; **4 of the 6 CRC sinks were pinned by a test and 2 were not**
  (`#crc_custom_vector_result`, `#crc_coverage_preview`), in a batch that rewrites the very
  `compose` setting those kwargs. It is now an **enforced invariant** — HLR-072-8 / AT-219.
- **TC-N8-11 is a data-level guard**, not render coverage: it iterates `LEGEND_EXAMPLES` strings
  through `Content.from_markup` and never touches a widget (`test_legend_n8.py:247-272`). It stays
  green regardless of what `compose` does. The render-flag guard is new and owed (AT-218).

### 2.5 Assumptions and dependencies
- PR #164 merged (`31d87d0`); prototype files are reference-only inputs, not runtime dependencies.
- Parallel batch-65 may still be in flight — `state.json` is last-writer-wins; re-read before edit.
- The M-2/M-3 pane geometry assumes the implementation writes `height: 1fr` on the panes and
  `overflow: hidden` on `#legend_body`. **The requirement pins that CSS** (LLR-072-5.2 / 6.2)
  because different pane CSS moves the measured numbers.

### 2.6 Source user stories

**US-072-1 (CRC Designer, Variant B).** As a firmware engineer operating the CRC Designer bench,
I see the two reflection toggles as one labelled pair on a single row (each toggle individually
legible and separable), and the known-answer self-test as an annotation of the Check field it
validates — so no control reads as another control and the hero row spends its right column on
Warnings.

**US-072-2 (Legend modal, Variant B).** As an operator opening the Legend from any view, I see the
colour key beside the example card simultaneously (no scrolling past a ~29-line card to reach the
key); at the 80-col floor the modal still shows both, stacked with the key first.

**US-072-3 (markup-safety regression guard) — NEW at revision 2.** As the maintainer of a screen
that echoes user-typed text into six live surfaces, I need the `markup=False` flag on **every**
one of those surfaces enforced by a test that reads the live id set, so a `compose` rewrite cannot
silently drop a flag and let a typed `[` corrupt or crash the error message that exists to report a
bad parameter. *Origin: S-1. Reachable payload path — `_current_algorithm` raises `ValueError` on
non-hex input and `_recompute:1127-1135` writes `f"Invalid parameters: {exc}"`, echoing the user's
literal text, into all six sinks; `_recompute:1136-1142` has no `try/except` around the `.update()`
calls, so a `MarkupError` would propagate on the UI thread.*

#### Refinement log
- All three stories `READY`. INVEST holds: independent (different files), negotiable details
  resolved by the operator's variant pick, valuable (operator-flagged P1), estimable (prototyped +
  now measured), small (≤5 files each), testable through the pilot surface.
- Phase-0 already-shipped check (RC-1, re-executed by the executing session): `origin/main` tip
  `31d87d0`; no REQUIREMENTS.md row describes a paired reflection row or a two-pane legend.

### 2.7 Premise evaluation (C-43) — executed, not cited

| # | Premise | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| P-1 | Switch fusion = `.crc-field-switch {border:none;height:1}` + no row margin, two stacked `_switch_row`s | premise | ✅ TRUE | `styles.tcss:1952-1955`, `crc_designer_view.py:301-302`; re-measured M-1: `refin@y=32 h=1`, `refout@y=33 h=1`, borderless | fix via pair row (LLR-072-1.1) |
| P-2 | (Backlog line 153) "any change will drift the CRC snapshot cells" | premise | ❌ **FALSE** | `test_tui_snapshot.py:109-110` — CRC screen in neither screen list; 0 crc snapshots on disk. Re-probed independently at Phase 2 | **No snapshot-regen follow-up.** Backlog line 153 corrected at close |
| P-3 | Legend modal not snapshot-captured | premise | ✅ TRUE | same probe — 0 legend snapshots | zero baseline drift |
| P-4 | `_recompute` queries six ids; all must stay mounted | premise | ✅ TRUE | `crc_designer_view.py:1115-1121`; `except NoMatches: return` at `:1122-1124` | Variant B keeps all six. **Gap closed at rev 2:** 4 of the 6 were observed by no AT — now AT-219 |
| P-5 | AT-B59-03/08 survive Variant B | premise | ✅ TRUE **but incomplete** | teeth are a computed 3-column comparison (`test_crc_designer_view.py:928,1312`); Variant B keeps `#crc_bench_c1/c2/c3` | **The file's OTHER AT does not survive**: `AT-B59-05` (`:1003-1047`) hard-asserts `#crc_live_verify`. §6.5 A-1 |
| P-6 | Reverse census (C-26) | premise | ⚠️ **TRUE but imprecise** | re-executed at Phase 2 | CRC half exact (1 file). Legend half true only as a **union** — each legend symbol is single-pinned. **Three touched symbols are pinned NOWHERE**: `crc_algorithm_fields`, `crc-field-switch`, `_switch_row` — new obligations, not preserved ones |
| P-7 | Variant B renders + computes live on textual 8.2.8 | hypothesis | ✅ TRUE **for the wide case only** | PR #164 frames | **The floor case was never prototyped** — the B prototype has no narrow rule at all (P-8/A-2). Floor behaviour is measured here for the first time (M-3) |
| P-8 | Floor stacking order = key first | hypothesis | ✅ **RESOLVED at the Phase-1 gate** | operator, verbatim option label *"Stack, key first (Recommended)"* | Confirmed, not overridden. HLR-072-6. Remains a hypothesis until AT-217 passes — an operator decision fixes the requirement, it does not verify the implementation |
| P-9 | The switch-separability guard is encodable as an AT that fails on the old CSS | hypothesis | ❌ **FALSE as originally scoped** | Two reviewers independently measured **16** abutting pairs; Variant B fixes **1**. Under the "interleaved label" reading `_switch_row:465-469` already emits a `Label`, so the predicate is TRUE pre-batch and cannot go RED (C-40 limb 1) | **Re-scoped, not abandoned** — see P-11 |
| **P-10** *(new)* | The four geometry numbers (`Select height:3`, `3fr`/`2fr`, `96%`, floor stacking) hold on the shipped tree | premise | ❌ **FALSE for one of the four** | M-2/M-3 confirm the legend numbers and pin the pane widths (card 64 / key 43 cols). **M-4 refutes `Select height:3`**: `CRC-32/ISO-HDLC` renders `CRC-32/I` — 8 of 15 chars, no ellipsis — and 4 of 6 Selects lose their bottom border | HLR-072-4 **WITHDRAWN**, §6.5 W-1 |
| **P-11** *(new)* | A Switch-only abutment rule is FALSE pre-batch and satisfiable (0 violations) post-batch | hypothesis | ✅ TRUE | M-1: rule (c) = **1** violating pair pre → **0** post. Rule (b) *same-widget-class*, the fix qa proposed, = **7** pre → **6** post — **not satisfiable**, so it was rejected on measurement | G-1 adopts rule (c). Subject-set completeness: the whole app contains **2** `Switch` widgets from **1** construction site (`crc_designer_view.py:467`) |
| **P-12** *(new)* | `#legend_body` may be retired by the two-pane split | premise | ❌ **FALSE** | **9** descendant query sites across the 3 legend test files, plus `REQUIREMENTS.md:3352` and `R-LEGEND-GEOMETRY-001` name it | `#legend_body` is **preserved as the two-pane wrapper**; C-38 applies (a narrowed query that empties still *passes* many assertions) |

## 3. High-level requirements (HLR)

### HLR-072-1 — Paired reflection row · US-072-1
The CRC Designer Algorithm group **shall** render the `refin`/`refout` controls as ONE `Reflection`
row: the row label, then per-toggle sub-labels `in` and `out`, each immediately adjacent to its own
`Switch` (`#crc_field_refin` / `#crc_field_refout`, ids unchanged), with the two switches sharing a
single row band.

**Acceptance (black-box): AT-213** — pilot at 120x30, CRC screen reached through the shipped
surface (`pilot.press("0")`):
1. `#crc_field_refin.region.y == #crc_field_refout.region.y` (one row band);
2. a `Label` whose `region.x` lies strictly between the two switches' x-bands (they are separated
   by an interleaved label, not merely co-located);
3. **C-10 non-default drive, with measured values:** `#crc_field_refin` is seeded **`True`**
   (`SEED_ALGORITHM` = CRC-32/ISO-HDLC); drive it to **`False`** through the real `Switch` path and
   assert `#crc_custom_vector_result` transitions **`0xCBF43926` → `0x1898913F`** — the exact
   transition, not a `!=`.

*(Measured: the seed vector `#crc_custom_vector` is `"123456789"`, not empty, so the observable
genuinely moves. `0xCBF43926` is the externally published CRC-32 check value.)*

### HLR-072-2 — KAT demoted under Check · US-072-1
The known-answer verdict **shall** render as a `Self-test` row directly below the `Check` field
inside `#crc_algorithm_fields`, preserving the id `#crc_kat_verdict`, its `markup=False` flag, and
the tri-state glyph tokens (`✓ MATCH` / `✗ MISMATCH` / `○ NO-EXPECTED`); the row **shall** carry the
reference-vector naming `123456789` on screen; the wrapper `#crc_live_verify` **shall** no longer be
composed; and `#crc_top_right` **shall** contain the Warnings group only.

> **Retirement clause (A-1).** This requirement **retires** batch-59's verdict-hero requirement
> (US-L3 / HLR-L3 / LLR-L2.3+L3.1) and its acceptance test `AT-B59-05`
> (`tests/test_crc_designer_view.py:1003-1047`, `test_verdict_hero_center_aligned_in_hero_row`),
> whose five assertions are each falsified by Variant B by design. The retirement is recorded
> Before/After in §6.5 A-1 and budgeted in the test ledger as `D = 1`. **It is a deliberate
> retirement, not a weakening**: the test must be deleted, never edited into passing.

**Acceptance: AT-215** — pilot:
1. `#crc_kat_verdict` has ancestor `#crc_algorithm_fields`;
2. the on-screen text `123456789` is present within that row's subtree;
3. **drive the real `Input.Changed` path with the measured value:** set `#crc_field_check` to
   **`0x00000000`**; assert `#crc_kat_verdict` transitions from containing `MATCH` (and not
   `MISMATCH`) to containing `MISMATCH`. **Two near-misses are excluded explicitly** — clearing the
   field yields `○ NO-EXPECTED` (`check=None`) and a non-hex keystroke yields
   `"Invalid parameters: …"`; neither satisfies this clause;
4. `query("#crc_live_verify")` is empty (the discriminating negative).

### HLR-072-3 — Switch separability guard (G-1) · US-072-1
**No two `Switch` widgets shall render vertically abutting** — for every pair of `Switch` widgets in
the application, it is not the case that `b.region.y == a.region.y + a.region.height` with
overlapping x-bands.

> **Scope, stated openly (P-9 → P-11).** Revision 1 stated this over *every pair of
> vertically-adjacent focusable controls in the CRC form*. That rule is FALSE of **16** pairs on the
> shipped tree and Variant B fixes **one**; the remaining 15 abut **by design** — `styles.tcss:1941-1948`
> (`.crc-field-input { border: none; height: 1 }`) is batch-59's approved R9 compact-row decision.
> A same-widget-class rule was then proposed and also **rejected on measurement** (7 pre → 6 post).
> The Switch-only rule is the only one of the three that is FALSE before and satisfiable after.
> **Why this is a general guard and not special-pleading for one pair:** the subject set is
> **derived from the live DOM, never hand-listed** (C-31), and its completeness rests on a
> **static fact about the source**: every `Switch(` construction site in the package lives in
> `crc_designer_view.py`, reached only from the Algorithm group, so every `Switch` that can exist
> is on the CRC screen and inside the queried scope.
>
> ⚠️ **The property is single-module CONFINEMENT, not a site count — and this batch is why**
> (§6.5 **D-1**). Revisions 2 and 3 of this document said "exactly **one** construction site
> (`crc_designer_view.py:467`)". That was true of `origin/main` and **this batch falsified it**:
> LLR-072-1.2 deleted `_switch_row` — one `Switch(` call invoked twice — and LLR-072-1.1 inlined
> both toggles, so HEAD has **two** sites (`:325`, `:327`). Pinning the count would have shipped a
> RED test; re-pinning it to `2` would re-plant the same brittle constant against the next refactor.
> TC-514 therefore asserts what the count was standing in for: `Switch` is imported and constructed
> **only** in `crc_designer_view.py`.
> *Precision correction from the re-gate (N-4): `App.query` is **screen-scoped**
> (`app._get_dom_base() -> Screen`), so it does not by itself certify "anywhere in the app" — the
> **grep** carries that argument, not the query. The AT therefore queries the CRC screen and the
> completeness claim is anchored to the **owning module**, `crc_designer_view.py` — see the D-1
> note directly below for why it is the module and not a site count.*
> The guard coincides with HLR-072-1 *today* precisely because those two switches are the only ones
> that exist — stated plainly rather than dressed up.

**Acceptance: AT-214** —
1. the subject set is **derived**: `screen.query(Switch)` filtered `region.area > 0` (C-31);
2. the AT asserts the derived set is **non-empty** (`>= 2`), so a broken walk cannot pass vacuously;
3. zero abutting `Switch` pairs under the §1.3 relation;
4. **C-40 discharge — counterfactual artifact named, and it is the WHOLE FILE:** on a private copy,
   restore `crc_designer_view.py` from `origin/main` (`git checkout origin/main -- <file>`), run
   AT-214, paste the transcript showing an `assert` failure plus the restore hash.
   *Two wrong-reason failure modes are excluded by construction. (i) Reverting the CSS rule alone is
   **not** sufficient — the fusion is partly a `compose` fact (two stacked `Horizontal` rows), so a
   CSS-only revert may leave the AT GREEN. (ii) Reverting "just the pair row back to two
   `_switch_row` calls" would raise `NameError`, because LLR-072-1.2 **deletes** `_switch_row` — an
   error is not an assertion failure (`feedback_counterfactual_must_fail_on_its_assertion`). A
   whole-file revert is safe here **specifically because AT-214 references no `#id`**: it queries by
   widget type, so the set resolves in both trees.*

### HLR-072-4 — ~~Select chrome cap~~ **WITHDRAWN at revision 2**
See §6.5 **W-1**. Measured (M-4): `height: 3` renders `CRC-32/ISO-HDLC` as **`CRC-32/I`** — 8 of 15
characters with **no ellipsis and no overflow marker** — and clips the bottom border on 4 of the 6
Selects. The cap buys 3 rows on one control by silently lying about that control's value. The
affordance-density finding is real and is **carried to the backlog** with its measurement; the
measured lever is pane **width**, not height. `AT-219` is reallocated to HLR-072-8.

### HLR-072-5 — Legend two-pane layout · US-072-2
In the wide regime (§1.3) `LegendScreen` **shall** render the example card and the colour key
side-by-side — card left, key right — as two independently scrollable panes inside the preserved
`#legend_body` wrapper, with the key pane sized so its whole content fits without scrolling.

**Acceptance: AT-216** — pilot 120x30, **mac** view, opened through the real `k` binding:
1. **anchor on the widget, not the string** (Q-4): locate the key row by its
   `{legend-row, sev-warning}` classes inside `#legend_key_pane` and assert
   `LEGEND_TABLE["MAC"]["Pale yellow"][1] in row_text` — **containment, NOT equality**.
   *Measured: the row is built as `f"{classification} — {meaning}"` (`screens.py:1191`), so
   `text == meaning` is **False** and `meaning in text` is **True**; an `==` here would false-fail a
   correct implementation. Both anchors independently disambiguate the panes — executed: **0** card
   widgets carry `{legend-row, sev-warning}` and **0** contain the meaning string. The bare literal
   `Pale yellow` does not disambiguate: it also appears in a **card** caption (`legend.py:718`);*
2. **region containment, not rendered text** (Q-5 / project C-32):
   `#legend_key_pane.region.contains_region(row.region)` with `scroll_offset == (0, 0)` asserted;
   **and `#legend_body.region.contains_region(#legend_key_pane.region)`**.
   *Rationale for clause 2b (re-gate N-3): every other clause is relative to the pane, so all three
   pass with the key pane rendered entirely off-dialog — executed, a CSS-specificity slip put the
   pane at `x=113` outside a body spanning `[6,113)` and AT-216 stayed GREEN. `render().plain` is
   independently geometry-blind — proven on the shipped tree, where the row sits at
   `Region(x=22, y=27)` outside `body.region=Region(22,6,76,15)` and the harness still returns `True`;*
3. **assert the cause, not only the symptom:** `#legend_key_pane.max_scroll_y == 0`.
   *Measured: key content is **14** rows in a **15**-row pane for both mac and map — **one row of
   slack**. This clause fails on budget exhaustion before the symptom appears;*
4. **oracle mutation (C-32 discharge):** set the key pane `display: none` and confirm the AT goes
   RED; paste the transcript. *Note this mutation does **not** cover the off-dialog case — clause 2b
   does; the two are complementary, not redundant.*

*Measured geometry this requirement is pinned to: dialog `width: 96%` → 113 cols; modal chrome 6
cols (`styles.tcss:1504-1508`, verified `113 − 107`); card pane `3fr` → **64** cols; key pane `2fr`
→ **43** cols; body height 15 rows; `Pale yellow` at key content rows `[5, 8)`.*

### HLR-072-6 — Legend floor stacking, key first · US-072-2
At the floor (§1.3) the panes **shall** stack vertically with the colour key ABOVE the example card,
both panes at non-zero height, and the full key **reachable under scroll**.

> **Mechanism (A-2) — this HLR's LLR was unimplementable at revision 1.** `width-narrow` is applied
> only to `#workspace_shell` / `#workspace_body` (`app.py:6202-6208`), which live in the **base
> screen**; `LegendScreen` is a `ModalScreen` pushed on the stack (`screens.py:1030`,
> `app.py:5865`), a descendant of neither, and textual 8.2.8 has no CSS media queries. The modal
> therefore owns its own regime hook — LLR-072-6.1.

**Acceptance: AT-217** — pilot 80x24, mac view:
1. `#legend_key_pane.region.y < #legend_card_pane.region.y` (key precedes card);
2. **the non-vacuity tooth:** `#legend_card_pane.region.height >= 2`.
   *Rationale, measured: ordering alone is TRUE in all four candidate CSS regimes — including the
   degenerate `key: auto` regime, which starves the card to **1** row and overflows `#legend_body`.
   This clause is the only one that fails there;*
3. **reachable under scroll, NOT required visible:** `#legend_key_pane.max_scroll_y >= 1` and the
   last key row scrolls into a non-empty on-screen region via `scroll_visible()`.
   *Rationale, measured: the floor content budget is **9** rows and the key content is **10 (mac) /
   11 (map)** rows at the stacked width, so the key is never fully visible at 80x24 under any
   non-degenerate CSS. "Both panes visible" would either fail permanently or be weakened into
   vacuity — project C-29's measured trap.*

### HLR-072-7 — Data-pipeline preservation · US-072-2
The reorganized modal **shall** reuse the shipped data pipeline unmodified (`LEGEND_EXAMPLES` role
mapping, `_render_card`, `_render_key` incl. the map band-key branch) and **shall** preserve the ids
`#legend_dialog`, `#legend_body`, `#legend_close`, `#legend_mac_warning_sample` together with the
S-01 escaping behaviour and every existing `markup=` flag.

> `#legend_body` is preserved as the **two-pane wrapper** (P-12), so all 9 descendant query sites
> across the three legend test files keep resolving, as do `REQUIREMENTS.md`'s
> `R-LEGEND-MODAL-001` / `R-LEGEND-GEOMETRY-001` code lines.

**Acceptance: AT-218 — labelled a REGRESSION PIN, not a gate** (C-40 corollary: its declared subject
is the *unchanged* pipeline, so it is invariant under the change this batch makes; it is kept
because it is the only thing that would catch an accidental data-layer edit, and it is labelled so
nobody mistakes it for the gate):
1. mac view: `#legend_mac_warning_sample` present with its inline orange style read from
   **`render().spans`** — not `render_line(0)`, which reads the theme foreground `#e9e9e9`
   (project C-37);
2. map view: the band-key rows render in the **key** pane and still report
   `_render_markup is False` (S-2 — these flags are pinned by nothing today);
3. all 9 `#legend_body`-rooted query sites resolve **non-empty** after the change (C-38 — a
   narrowed query that quietly empties still passes `all(...)` and `assert not …`);
4. the three legend test files stay green.

### HLR-072-8 — CRC render-sink markup census · US-072-3 · NEW at revision 2
The six ids `_recompute` queries **shall** be declared as a module-level tuple in
`crc_designer_view.py`, `_recompute` **shall** consume that tuple, and every widget it names
**shall** report `_render_markup is False`.

**Acceptance: AT-219** — pilot, in two clauses that are deliberately different in kind:
1. **the PIN (labelled as such):** iterate the **live module-level tuple** (never a hand-list) and
   assert each resolved widget's `_render_markup is False`; assert `len(tuple) >= 6`.
   *Honest labelling per C-40's corollary: all six sinks are **already** `markup=False` today
   (`crc_designer_view.py:341,353,367,397,403,411`), so this clause is **invariant under this
   batch** — it is a regression pin protecting the `compose` rewrite, not a gate on new behaviour.
   It is exactly the guard S-1 asked for; it is simply not the thing that proves the hoist landed.*
2. **the GATE (re-gate N-5/N-3):** `len(tuple) >= 6` admits a tuple that is hoisted, asserted, and
   then **ignored** by a `_recompute` still carrying its hardcoded queries. So: monkeypatch the
   module tuple to contain one bogus id, drive one `Input.Changed` through the surface, and assert
   `_recompute` takes its `NoMatches` early return (`:1122-1124`) — i.e. the live surfaces do not
   update. **This is the only clause that is FALSE before the hoist**, which is what makes it the
   gate.

*C-31 live-oracle pattern, as used by `test_legend_n8.py:445-459`: a seventh surface added later is
covered by clause 1 automatically.*

## 4. Low-level requirements (LLR)

Each LLR carries a statement, a pass threshold, and its id inventory. Revision 1's one-line sketches
were an A-12 finding — every blocker in Phase 2 lived at LLR level.

| LLR | Parent | Statement | Pass threshold | Ids touched (C-26 declared) |
|---|---|---|---|---|
| **LLR-072-1.1** | HLR-072-1 | Replace the two `_switch_row` calls (`crc_designer_view.py:301-302`) with one `Reflection` row: `Label("Reflection", classes="crc-field-label")`, then `Label("in")` + `Switch(#crc_field_refin)` + `Label("out")` + `Switch(#crc_field_refout)` inside one `Horizontal(classes="crc-field-row")`. | `refin.region.y == refout.region.y`; a `Label.region.x` strictly between the two switches | `crc_field_refin`, `crc_field_refout`, `crc-field-row`, `crc-field-switch` |
| **LLR-072-1.2** | HLR-072-1 | `_switch_row` (`:453-469`) becomes orphaned; delete it. | `grep -rn "_switch_row" s19_app/ tests/` → 0 hits | `_switch_row` (pinned in **0** test files — P-6) |
| **LLR-072-2.1** | HLR-072-2 | **Re-parent, do not delete.** Move `Static(id="crc_kat_verdict", markup=False)` into `#crc_algorithm_fields` as a `Self-test` row after the Check row, carrying the reference-vector naming; drop the now-empty `#crc_live_verify` wrapper. | `#crc_kat_verdict` resolves under `#crc_algorithm_fields`; `123456789` on screen in that row; `query("#crc_live_verify")` empty | `crc_kat_verdict`, `crc_live_verify`, `crc_algorithm_fields` (pinned in **0** test files) |
| **LLR-072-2.2** | HLR-072-2 | Hero row becomes `Horizontal(#crc_coverage_window, Vertical(warnings_group, id="crc_top_right"))`. | `#crc_top_right` has exactly one child group | `crc_top_right`, `crc_hero_row`, `crc_warnings_group` |
| **LLR-072-2.3** | HLR-072-2 | `styles.tcss`: retire the `.crc-hero` (`:2005`) and `#crc_live_verify` rules. **No edit to `.crc-field-input` (`:1941-1948`) — batch-59's R9 decision stands.** | no `.crc-hero` / `#crc_live_verify` selector remains | `.crc-hero` |
| **LLR-072-2.4** | HLR-072-2 | **Delete** `test_verdict_hero_center_aligned_in_hero_row` (AT-B59-05, `tests/test_crc_designer_view.py:1003-1047`). Deletion, not edit. | the function is absent; ledger `D = 1` | `AT-B59-05` |
| **LLR-072-5.1** | HLR-072-5 | `LegendScreen.compose` (`screens.py:1194-1206`): replace `ScrollableContainer(*body, id="legend_body")` with `Horizontal(ScrollableContainer(*card, id="legend_card_pane"), ScrollableContainer(*key, id="legend_key_pane"), id="legend_body")` — **card first in compose, which is the WIDE order**; the floor order is produced at runtime by LLR-072-6.1's `move_child`, because textual 8.2.8 has no CSS ordering property. **`_render_card()` / `_render_key()` are called unchanged and their returned widgets are re-parented, never reconstructed.** | both panes resolve; card/key widget counts match M-6 (mac 17/6, map 20/7) | `legend_body`, `legend_card_pane`, `legend_key_pane` |
| **LLR-072-5.2** | HLR-072-5 | `styles.tcss`: `#legend_dialog { width: 96% }`; `#legend_card_pane { width: 3fr; height: 1fr; overflow-y: auto }`; `#legend_key_pane { width: 2fr; height: 1fr; overflow-y: auto }`; **`overflow-y: auto` moves OFF `#legend_body` (`:1543-1546`) to `overflow: hidden`** so there are not three nested scroll contexts. | measured: card 64 cols, key 43 cols, `key.max_scroll_y == 0` at 120x30 | `#legend_body`, `#legend_dialog` |
| **LLR-072-6.1** | HLR-072-6 | **The modal owns its own width regime, and it owns the ORDER.** `LegendScreen.on_mount` and `on_resize` read **`self.app.size.width`** against the same breakpoint as `app.py:6202` (`narrow = width < 120`), toggle a `legend-narrow` class on `#legend_dialog`, **and reorder the panes via `#legend_body.move_child(...)`** — key before card when narrow, card before key when wide. Idempotent: safe to call on every resize. **`self.app.size.width` — NOT `self.size.width`**, which is 118 under `run_test(size=(120,30))` because of `Screen { padding: 1 }` and would flip the wide case into the narrow regime. | class present at 80x24 / absent at 120x30 **and** `#legend_key_pane` precedes `#legend_card_pane` in `#legend_body.children` when narrow — both asserted by **TC-517** | `legend-narrow`, `legend_dialog`, `legend_body` |
| **LLR-072-6.2** | HLR-072-6 | `styles.tcss`, **every rule prefixed `#legend_dialog.legend-narrow`**: `… #legend_body { layout: vertical }`, `… #legend_key_pane { width: 100%; height: 1fr }`, `… #legend_card_pane { width: 100%; height: 1fr }`. **`height: auto` on the key pane is excluded by measurement** (it starves the card to 1 row and overflows `#legend_body`). | measured `1fr/1fr` at 80x24 → key h=4, card h=5, both non-zero, `key.max_scroll_y` 6 (mac) / 7 (map); **and the wide regime is unchanged** — card 64 / key 43 at 120x30 | `legend-narrow`, `legend_key_pane`, `legend_card_pane` |
| **LLR-072-7.1** | HLR-072-7 | **No `legend.py` edit.** A grouping helper in `screens.py` is permitted **only** to wrap the widget lists returned by `_render_card()` / `_render_key()` in containers; it **shall not** reconstruct rows from text or re-wrap `#legend_mac_warning_sample`'s markup (S-2b). | `git diff origin/main -- s19_app/tui/legend.py` empty | `legend_mac_warning_sample` |
| **LLR-072-8.1** | HLR-072-8 | Hoist `_recompute`'s six queried ids (`crc_designer_view.py:1115-1121`) into a module-level tuple and have `_recompute` consume it. **The six ids bind to six DISTINCT roles with three different error-path strings, so consumption shall be BY NAME (a mapping / named lookups), never a positional unpack** (re-gate N-5) — under an unpack the claimed "a 7th surface is covered automatically" becomes a `ValueError` raised on the UI thread, and AT-219 clause 1 cannot detect it. | `len(tuple) >= 6`; `_recompute` behaviour byte-identical on the happy path AND on the `Invalid parameters` error path; AT-219 clause 2 RED before the hoist | the six `_recompute` ids |

## 5. Validation strategy

### 5.1 Methods
All ATs: `test (pilot)` — `App.run_test()` driving the shipped surface, reached by the real binding
(`pilot.press("0")` for CRC, `k` for the Legend), never a `.focus()` proxy (C-16). TCs: unit /
structural. No `demo`.

### 5.2 Dual-traceability

| Story | HLR | LLR | AT (black-box) | TC (white-box) |
|---|---|---|---|---|
| US-072-1 | HLR-072-1 | 1.1, 1.2 | **AT-213** | TC-510 (pair-row structure), TC-511 (`_switch_row` orphan removal) |
| US-072-1 | HLR-072-2 | 2.1, 2.2, 2.3, 2.4 | **AT-215** | TC-512 (`#crc_top_right` single child), TC-513 (`.crc-hero` selector absent) |
| US-072-1 | HLR-072-3 | — *(guard over 1.1)* | **AT-214** | TC-514 (`Switch` is constructed only in `crc_designer_view.py` — the confinement property, §6.5 D-1) |
| US-072-2 | HLR-072-6 | 6.1 | *(covered by AT-217)* | **TC-520** (focus traversal — §6.5 D-2) |
| US-072-2 | HLR-072-5 | 5.1, 5.2 | **AT-216** | TC-515 (pane ids + widget counts vs M-6), TC-516 (`#legend_body` is the wrapper; 9 sites non-empty) |
| US-072-2 | HLR-072-6 | 6.1, 6.2 | **AT-217** | **TC-517 (the `legend-narrow` class flips at the 120 breakpoint)**, TC-518 (no `height: auto` on the key pane) |
| US-072-2 | HLR-072-7 | 7.1 | **AT-218** *(pin)* | TC-519 (`legend.py` diff vs `origin/main` empty) |
| US-072-3 | HLR-072-8 | 8.1 | **AT-219** | — *(AT-219 is itself the live-oracle census)* |

**Every AT maps to exactly one distinct on-disk node (C-18).** Revision 1's HLR-072-4 acceptance —
*"TC-level + a pilot height assertion inside AT-213's run"* — was a C-18 violation (an acceptance
realized in parts, smuggled into another AT's node); the requirement it belonged to is now withdrawn
and AT-213 carries **one** subject.

**ID allocation.** Census re-executed at Phase 2 excluding this batch's own directory (which
self-matches its reservation strings and reports a false collision): prior max **AT-212** / **TC-509**.
Allocated **AT-213..AT-219**, **TC-510..TC-519**. Re-run at Phase 3 — a parallel batch may consume ids.

### 5.3 Batch acceptance criteria
1. All seven ATs green through the pilot surface, with **AT-214's RED counterfactual transcript**
   (compose reverted on a private copy, failing on its own assertion line, restore hash confirmed)
   and **AT-216's oracle-mutation transcript** (`display: none` → RED).
2. Frozen guards BOTH arms green (C-27); `git diff origin/main -- <frozen set>` empty.
3. Test blast radius re-run green: `test_crc_designer_view.py`, `test_tui_legend.py`,
   `test_legend_n8.py`, `test_legend_scope_and_logwidth.py`.
4. `pytest -q -m "not slow"` green — the Phase-4 run is launched and collected by the **orchestrator**
   (C-25), not delegated.
5. **REQUIREMENTS.md** (A-8 — revision 1 pointed at a row that does not exist; `crc_live_verify`,
   `verdict hero`, `crc_bench` and `Designer` all return **0** hits, because the batch-59 bench
   layout was never registered):
   - **ADD `R-TUI-100`** — CRC Designer bench layout, post-batch-72 state (pair row, Self-test row,
     Warnings-only right column). This registers the CRC Designer view for the first time.
   - **AMEND `R-LEGEND-MODAL-001`** (`:3351-3352`) — two-pane body; `#legend_body` is the wrapper.
   - **AMEND `R-LEGEND-GEOMETRY-001`** — its Code line documents
     `#legend_body { height: 1fr; overflow-y: auto }`; the `overflow-y` moves to the panes
     (LLR-072-5.2), so the row needs a §6.5 Before/After.
6. **NO snapshot regen expected** (P-2/P-3). If any snapshot fails, **STOP** — a premise was wrong;
   do not regen casually.
7. **Test ledger** `post = base − D + A` with **base = 2379** (measured 2026-07-30 @ `b556e35`;
   the revision-1 figure of 2358 was stale by 21) and **D = 1** (LLR-072-2.4 retires AT-B59-05).

## 6. Appendices

### 6.2 Relevant design decisions (operator, verbatim)
> "Ok, CRC viewer vamos con (B). Leyenda, dos paneles. (B) Por favor deja el plan hecho, llama
> /dev-flow para ello y deja todo listo para que otra sesión tome desde ahí para llevarlo a término."

Gate-2 of the HANDOFF-PLAN (KAT demote-vs-remove) resolves to **demote** (Variant C was the removal
option). P-8 resolved at the Phase-1 gate: floor stacking **key first**.

### 6.3 Open risks
- **AT-216 has one row of slack.** Key content is 14 rows in a 15-row pane for both views. One extra
  key row, one reworded meaning that wraps, or a key pane narrower than 43 cols pushes the map key
  past the fold. Mitigated by AT-216's `max_scroll_y == 0` clause, which fails on the cause.
- **Three touched symbols are pinned by no test today** (`crc_algorithm_fields`, `crc-field-switch`,
  `_switch_row`) — new obligations, not preserved ones.
- **Focus traversal (C-16, A-10):** `ScrollableContainer.can_focus == True` on textual 8.2.8, so the
  modal goes from one focusable container to two, changing the tab cycle; `on_mount` focuses
  `#legend_close` and nothing re-specifies order after it. Flagged **`assumed — verify in target
  framework at Phase 3`**: each increment touching the modal re-checks the tab cycle. The CRC side
  is low risk (the pair row preserves refin→refout order and inserts a non-focusable `Static`).
- `state.json` last-writer-wins vs the parallel batch-65 — re-read before every edit.
- Prototype code is THROWAWAY: rewrite the compose per PROJECT_RULES.md conventions.

### 6.4 Design guards from the handoff plan — disposition of ALL four (A-10)
Revision 1 encoded G-1 and G-2 and let **G-3 and G-4 vanish with no disposition**. An unremarked
disappearance is not a decision (C-40 limb 2, instance ii). All four are now dispositioned:

| Guard | Source | Disposition at revision 2 |
|---|---|---|
| **G-1** — control separability | `HANDOFF-PLAN.md:120` | ✅ **ENCODED, re-scoped to `Switch` pairs** — HLR-072-3 / AT-214. The original scope was measured unsatisfiable (P-9/P-11) |
| **G-2** — state legible as glyph/word, not slider position alone | `HANDOFF-PLAN.md:121` | ❌ **RETIRED — see §6.5 R-1.** The rendered state word was **Variant A's** mechanism (`NOTES.md:66`); the operator chose **B**, which "steals nothing" (`:104`). Encoding A's guarantee against B's design is a category error, and revision 1's discharge (asserting the CRC vector changes) proved handler *wiring* — already covered at `test_crc_designer_view.py:414-415` — not legibility. **Carried to the backlog**, not dropped |
| **G-3** — hero extent / the 6:1 law | `HANDOFF-PLAN.md:122` | ⚪ **NOT ENCODED — and the first reason given for that was wrong.** *Rejected rationale (revision 2):* "the batch reduces the hero-tile count from 2 to 1, so it strictly decreases the quantity G-3 bounds." **Measured at the re-gate (N-6) and false:** `#crc_coverage_window` has area **305** while `#crc_live_verify` and `#crc_warnings_group` are identical `30x4` boxes of area **120** each — retiring one tile and giving its space to the other changes the bounded quantity by **zero**. Worse, G-3 is **already FALSE on `main`**: the measured ratio is **2.54:1** against a 6:1 law. *Actual reason it is not encoded:* it is a **pre-existing, unrelated violation** that this batch neither causes nor worsens; encoding it here would make batch-72's gate fail on batch-59's geometry. **Carried to the backlog with the measured 2.54:1**, which is the honest disposition |
| **G-4** — the colour key is reachable within ≤1 interaction at 120x30 **and** 80x24 | `HANDOFF-PLAN.md:123` | ✅ **ENCODED, split by regime** — at 120x30 into AT-216 (0 interactions: visible at `scroll_offset 0`, `max_scroll_y == 0`) and at 80x24 into AT-217 clause 3 (1 interaction: reachable under scroll). Measurement is why it splits — the floor cannot satisfy 0 |

### 6.5 Requirement amendments (Before/After · Deleted/New)

#### W-1 — HLR-072-4 (Select chrome cap) **WITHDRAWN**
- **Before:** *"`#crc_designer_panel Select` widgets **shall** render at height 3 (no multi-row value
  wrap at bench column widths). Rationale: shipped Selects wrapped to 5-6 rows at 120x30."*
- **After:** *(withdrawn — no requirement)*
- **Basis (executed, M-4):** at `height: 3`, `crc_preset_select` (12 cols wide, holding the 15-char
  `CRC-32/ISO-HDLC`) renders **`CRC-32/I`** — 8 of 15 characters, **no ellipsis, no overflow
  marker** — and 4 of the 6 Selects lose their bottom border. Minimum legible height at that width
  is **5** for the text and **6** for text + intact box, i.e. exactly what `height: auto` already
  produces. The rationale figure was also wrong: measured heights are `6/4/4/4/3/3`, so "5-6 rows"
  describes one control, not the set.
- **Why withdrawn rather than adjusted:** the measured lever is pane **width** (15 chars need ~19
  cols inside this Select's padding + arrow), which is a bench-column redesign — unscoped, and it
  would reverse batch-59 geometry. A cap that makes a control lie about its value is worse than the
  density it fixes.
- **Deleted tokens:** `HLR-072-4`. **Reallocated:** `AT-219` → HLR-072-8.
- **Carried to `BACKLOG-CODE.md`** with the measurement, so the affordance-density finding is not lost.
- *This is the C-39 rider in action — re-measure the fold's OWN new thresholds. The number came from
  a prototype pass and would have shipped a silently-truncated preset name.*

#### R-1 — G-2 (switch state legibility) **RETIRED**
- **Before:** *"G-2 — toggling a Switch changes at least one rendered glyph/word on screen (state
  legible without color/position)"*, discharged by an AT-213 clause asserting
  `#crc_custom_vector_result` text changes.
- **After:** *(retired — no requirement)*. The separability defect the operator reported is closed by
  HLR-072-1 / HLR-072-3.
- **Basis:** the discharge asserted a different proposition — the CRC value changes when *any*
  algorithm parameter changes, so it tested `on_switch_changed → _recompute` wiring, already covered
  at `test_crc_designer_view.py:414-415`. The rendered state word belongs to **Variant A**
  (`NOTES.md:66`); the operator chose **B**, whose verdict row records "Steals from: —" (`:104`).
- **Explicit retirement line (C-40 limb 2, instance ii):** what is dropped is *the guarantee that a
  `Switch`'s own state is readable without relying on slider position*. **Carried to the backlog.**

#### A-1 — batch-59 verdict-hero requirement **RETIRED**
- **Before (batch-59, US-L3 / HLR-L3 / LLR-L2.3+L3.1):** the KAT verdict renders as a
  centre-aligned hero tile `#crc_live_verify` inside `#crc_top_right`, carrying the `crc-hero`
  class, with `#crc_kat_verdict` as its descendant.
- **After (batch-72, HLR-072-2):** the KAT verdict renders as a `Self-test` row inside
  `#crc_algorithm_fields`; `#crc_live_verify` is not composed; `#crc_top_right` holds Warnings only.
- **Parent-HLR re-read:** batch-59's HLR-L3 exists to make the verdict *findable*. The operator's
  2026-07-28 report is that the tile does not earn hero placement; demoting it to an annotation of
  the field it validates preserves findability and improves attribution.
- **Deleted node:** `AT-B59-05` = `test_verdict_hero_center_aligned_in_hero_row`
  (`tests/test_crc_designer_view.py:1003-1047`). **Deleted, never edited into passing.** Ledger `D = 1`.
- **Re-derived acceptance:** AT-215 (clauses 1, 2, 4) covers the surviving obligation — the verdict
  remains present, correctly parented, and reachable.

#### D-1 — TC-514's completeness oracle **RE-DERIVED** (the batch falsified its own spec constant)
- **Before (revisions 2-3):** *"`Switch(` has exactly **one** construction site in the whole package
  (`crc_designer_view.py:467`)"* — asserted as present-tense fact in HLR-072-3 and in
  `00-measurements.md` M-1, and specified as TC-514's assertion.
- **After:** TC-514 asserts **single-module confinement** — `Switch` is imported and every
  `\bSwitch\(` site occurs **only** in `crc_designer_view.py` — plus a non-vacuity guard.
- **Basis (executed at Inc-4):** `origin/main` → 1 site (`:467`); **HEAD → 2 sites (`:325`, `:327`)**.
  The batch caused this itself: LLR-072-1.2 deleted `_switch_row` (one `Switch(` call invoked twice)
  and LLR-072-1.1 inlined both toggles into the pair row, converting one site into two.
- **Why re-derived rather than re-pinned:** asserting `== 1` ships a RED test; switching to `== 2`
  re-plants the identical brittle constant for the next refactor to break. The requirement's own
  stated purpose is that *every `Switch` that can exist is inside the queried scope* — that is a
  **confinement** property, and it survived the refactor untouched. The count was only ever a proxy
  for it.
- **The general lesson, and it is C-39's rider read backwards:** a measured constant is true *of the
  tree it was measured on*. When the batch **is** the thing that changes that tree, a spec constant
  measured pre-batch can be falsified **by the batch's own success**. Prefer the invariant the
  number stands for whenever the number is downstream of your own edit.
- **Deleted token:** the "exactly one construction site" claim, in HLR-072-3 and in M-1.

#### D-2 — TC-520 allocated **outside** the reserved block
- `TC-510..TC-519` were reserved at Phase 1; the focus-traversal pin the C-16 flag produced at
  Phase 3 is the eleventh TC. **`TC-520` is allocated** (census re-confirmed free) and now carries a
  §5.2 traceability row. Recorded rather than left as an untraced node.

#### A-8 — REQUIREMENTS.md registration target **CORRECTED**
- **Before (§5.3.5, revision 1):** *"new/amended rows for the bench layout (batch-59 lineage §6.5
  Before/After — the verdict-tile row changes)"*.
- **After:** see §5.3.5 — **ADD `R-TUI-100`** (registering the CRC Designer bench for the first
  time), **AMEND `R-LEGEND-MODAL-001`** and **AMEND `R-LEGEND-GEOMETRY-001`**.
- **Basis (executed greps over `REQUIREMENTS.md`):** `crc_live_verify` → 0 hits; `verdict hero` → 0;
  `crc_bench` → 0; `Designer` → 0. There is no verdict-tile row to amend — the obligation is to
  **add**. Next free id measured as `R-TUI-100` (max = `R-TUI-099`, batch-70).
