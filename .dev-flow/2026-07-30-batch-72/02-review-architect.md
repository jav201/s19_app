# Phase-2 Review — architect — batch 2026-07-30-batch-72

> Reviewer: `architect`. Artifact under review: `.dev-flow/2026-07-30-batch-72/01-requirements.md`
> (Phase-1 approved 2026-07-30). Every finding below cites a file:line or an executed
> probe. Probes were run in this worktree against textual 8.2.8 with
> `App.run_test(size=…)` — the C-23 method the spec itself never applied.

## BLUF

**ITERATE back to Phase 1 — 4 blockers.** The single most important finding is **A-3**:
the G-1 separability guard the batch exists to encode is **unsatisfiable by the planned
change**. An executed pilot at 120x30 finds **16 abutting focusable pairs** on the
shipped CRC form; Variant B fixes exactly **one** of them (refin/refout). AT-214 as
written stays RED after the batch lands, so its C-40 counterfactual proves nothing.
Close behind: **A-1** — HLR-072-2 deletes `#crc_live_verify`, which a live shipped test
(`AT-B59-05`) hard-asserts must exist, while §5.3.3 simultaneously requires that test
file green; and **A-2** — LLR-072-6.1's floor-stacking mechanism (`width-narrow`) is
structurally incapable of reaching a `ModalScreen`, so HLR-072-6 has no owning
mechanism at all.

Two axes came back **clean and are worth stating**: the `_recompute` six-id constraint
(§2.4) is exactly right and Variant B does keep all six mounted (**check 5 — no
blocker**), and `_render_key`'s map band-key branch emits a flat `List[Widget]` with no
container, so HLR-072-7's preservation claim on the data pipeline is **sound** (**check
7 — no blocker on that axis**; the gap there is `#legend_body`, see A-6).

---

## Findings

### A-1 HLR-072-2 contradicts a live shipped acceptance test, and §5.3.3 requires that test green — blocker

**Claim.** HLR-072-2 mandates that `#crc_live_verify` "**shall** no longer be composed"
and that `#crc_top_right` "**shall** contain the Warnings group only". A shipped,
currently-green test asserts the exact opposite on four separate arms. The requirements
document never names it, and §5.3.3 makes its greenness a batch acceptance criterion —
an internally unsatisfiable pair.

**Evidence.**
- `tests/test_crc_designer_view.py:1003-1047` — `test_verdict_hero_center_aligned_in_hero_row`
  (docstring names it **AT-B59-05**). It calls `app.query_one("#crc_live_verify")` at
  `:1020` (raises `NoMatches` the moment the tile is not composed), then asserts
  `:1041` `under_top_right`, `:1043` `#crc_kat_verdict` is inside `#crc_live_verify`,
  `:1044` `content_align == ("center","middle")`, `:1047` the `crc-hero` class.
- `.dev-flow/2026-07-30-batch-72/01-requirements.md:37-39` — §2.4 discusses only
  AT-B59-03/08 and concludes "these survive unedited". AT-B59-05 is absent from §2.4,
  §2.7 P-5, and §5.3.
- `01-requirements.md:192` — §5.3.3: "Test blast radius re-run: the 4 files from P-6 all
  green." `test_crc_designer_view.py` is one of those four.
- `PLAN.md:93-95` — test ledger: "deletions expected 0 unless `_switch_row`
  orphan-removal drops a TC". A retirement of AT-B59-05 is a deletion the ledger does
  not budget.
- §2.7 P-5 itself flags the debt honestly: *"file has 32 tests — full blast-radius
  re-read owed at Phase 2"*. This review is that re-read; the debt is now due.

**Impact.** Phase 3 hits a hard stop mid-increment (Inc-2). Worse, the cheapest way out
under a green-suite gate is to weaken AT-B59-05 rather than retire it deliberately —
silently discarding a batch-59 requirement the operator approved, with no Before/After
record. `feedback_requirement_amendment_before_after` exists for exactly this.

**Proposed disposition.** Add an explicit HLR (or an amendment clause on HLR-072-2)
stating that **batch-59's US-L3 / HLR-L3 / LLR-L2.3+L3.1 verdict-hero requirement is
RETIRED**, with AT-B59-05 retired alongside it and a §6.5-style Before/After record.
Correct §5.3.3 to "green **after** the AT-B59-05 retirement", and correct the test
ledger to `post = base − 1 + A`. Do not let Phase 3 discover this.

---

### A-2 HLR-072-6's floor-stacking has no mechanism that can reach a modal — blocker

**Claim.** LLR-072-6.1 prescribes "`styles.tcss` — width-narrow rule stacking the panes,
key first". The `width-narrow` class is applied **only** to two widgets that live in the
base screen; `LegendScreen` is a `ModalScreen` pushed onto the screen stack and is a
descendant of neither. No `#workspace_body.width-narrow …` selector can ever match
`#legend_dialog`. Textual 8.2.8 has no CSS media/width queries. **HLR-072-6 is therefore
unimplementable as specified, and the batch owns no substitute mechanism.**

**Evidence.**
- `s19_app/tui/app.py:6202-6208` — `_apply_width_regime`: `narrow = width < 120`, then
  `for widget_id in ("#workspace_shell", "#workspace_body"): widget.add_class("width-narrow")`.
  Those two ids only.
- `s19_app/tui/app.py:1901-1903` — `#workspace_body` / `#workspace_shell` are composed in
  the base screen's tree.
- `s19_app/tui/app.py:5865-5867` — `self.push_screen(LegendScreen(...))`; `screens.py:1030` —
  `class LegendScreen(ModalScreen[None])`. A pushed screen is a sibling on the stack, not
  a descendant of `#workspace_body`.
- Executed grep: every `width-narrow` rule in `styles.tcss` is prefixed by
  `#workspace_body` or `#workspace_shell` (34 occurrences; the non-prefixed hits are
  comments — verified).
- The prototype confirms the gap rather than closing it:
  `prototypes/legend_p1.inapp_prototype.py:96-103` — `VariantBLegend.DEFAULT_CSS` sets
  `#legend_dialog { width: 96%; }`, `width: 3fr; height: 100%`, `width: 2fr; height: 100%`
  and **no narrow rule whatsoever**. §2.7 P-8 says this out loud ("no narrow rule was
  written") and then treats the operator's *ordering* answer as if it discharged the
  *mechanism* question. It does not: an operator decision fixes the requirement, it
  supplies no implementation path.

**Impact.** The only HLR whose disposition the operator was asked to confirm is the one
that cannot be built from its own LLR. Phase 3 will improvise a mechanism (a
`LegendScreen.on_resize` toggling a class, a regime flag passed at construction, an
`app.size` read in `compose`) with no requirement governing it and no AT on the toggle
itself — and AT-217 drives `run_test(size=(80,24))`, which will pass or fail on whichever
improvisation lands.

**Proposed disposition.** Promote the mechanism to a first-class LLR under HLR-072-6:
name the trigger (e.g. `LegendScreen.on_resize` / `on_mount` reading `self.app.size.width`
against the **same 120-col breakpoint** `app.py:6202` uses), the class it toggles, and the
node it toggles it on. Add a TC that asserts the class flips at the breakpoint — AT-217's
geometry assertion alone cannot distinguish "stacked because the rule fired" from
"stacked because the panes happened to collapse".

---

### A-3 AT-214 / G-1 is unsatisfiable by the planned change — 16 abutting pairs measured, 1 fixed — blocker

**Claim.** HLR-072-3 encodes G-1 as *"for **every** pair of vertically-adjacent focusable
controls in the CRC form, their regions do not abut without a ≥1-row gap, border, or
interleaved label"*. On the shipped tree that predicate is FALSE for **16** pairs. The
batch changes exactly **one** of them. AT-214 therefore goes RED on the *fixed* tree, and
its mandated C-40 counterfactual (RED on old CSS) is uninformative because the assertion
is RED on both sides.

**Evidence — executed pilot** (`App.run_test(size=(120,30))`, press `0`, enumerate
`panel.query("*")` where `widget.focusable`, pair on `b.y == a.y + a.height` with x-overlap):

```
ABUT: Select crc_preset_select y=23 h=6 -> OsClipboardInput crc_field_width y=29 h=1
ABUT: OsClipboardInput crc_coverage_ranges y=23 h=1 -> Select crc_coverage_intra_gap y=24 h=3
ABUT: Select crc_custom_vector_mode y=23 h=3 -> OsClipboardInput crc_custom_vector y=26 h=1
ABUT: Select crc_coverage_intra_gap y=24 h=3 -> Select crc_coverage_join y=27 h=4
ABUT: Select crc_coverage_join y=27 h=4 -> OsClipboardInput crc_coverage_pad_byte y=31 h=1
ABUT: OsClipboardInput crc_field_width y=29 h=1 -> OsClipboardInput crc_field_poly y=30 h=1
ABUT: OsClipboardInput crc_field_poly y=30 h=1 -> OsClipboardInput crc_field_init y=31 h=1
ABUT: OsClipboardInput crc_field_init y=31 h=1 -> Switch crc_field_refin y=32 h=1
ABUT: OsClipboardInput crc_coverage_pad_byte y=31 h=1 -> Select crc_coverage_on_gap_conflict y=32 h=4
ABUT: Switch crc_field_refin y=32 h=1 -> Switch crc_field_refout y=33 h=1      <-- the ONLY pair the batch fixes
ABUT: OsClipboardInput crc_field_name y=32 h=1 -> OsClipboardInput crc_field_aliases y=33 h=1
ABUT: Switch crc_field_refout y=33 h=1 -> OsClipboardInput crc_field_xorout y=34 h=1
ABUT: OsClipboardInput crc_field_xorout y=34 h=1 -> OsClipboardInput crc_field_check y=35 h=1
ABUT: OsClipboardInput crc_load_path y=38 h=1 -> Button crc_load_btn y=39 h=1
ABUT: OsClipboardInput crc_field_output_address y=43 h=1 -> OsClipboardInput crc_field_store_width y=44 h=1
ABUT: OsClipboardInput crc_field_store_width y=44 h=1 -> Select crc_field_store_endianness y=45 h=4
total abutting pairs: 16
```

The abutment is **by design**, not a defect: `styles.tcss:1941-1948` `.crc-field-input
{ border: none; height: 1; }` is the deliberate batch-59 "R9 compact borderless 1-tall
inputs" decision, and `styles.tcss:1927-1930` `.crc-field-row { height: auto; }` sets no
margin. Labels sit **beside** their control on the same row
(`crc_designer_view.py:442-451`), never between two rows, so the "interleaved label"
escape hatch never applies vertically.

The probe also surfaced six `SelectOverlay` widgets with `focusable=True` and
`Region(0,0,0,0)` — a zero-area class the predicate must exclude or it will pair
nonsensically.

**Impact.** Phase 3 faces three bad options: (a) ship AT-214 RED, (b) quietly narrow the
sweep to the two Switches — at which point G-1 is a restatement of HLR-072-1 and encodes
no general guard, or (c) redesign every field row in the CRC form, which is unscoped,
un-costed, and reverses an approved batch-59 design decision.

**Proposed disposition.** Choose the scope **at Phase 1, in writing**. The defensible cut:
restate G-1 over a **named, closed subject set** — e.g. *"no two `Switch` widgets, and no
`Switch` and an adjacent `Input`, abut without a boundary"* — and pilot-measure the
resulting predicate against the shipped tree to confirm the "after" set is empty and the
"before" set is non-empty. Define `focusable control` as `widget.focusable and
widget.region.area > 0`, define *vertically adjacent* as the exact
`b.region.y == a.region.y + a.region.height` + x-overlap relation used above, and define
each of the three escape hatches operationally. If the operator's intent really is the
whole form, that is a different (much larger) batch and must be said so.

---

### A-4 G-2's acceptance test proves handler wiring, not state legibility — blocker

**Claim.** HLR-072-3 states G-2 as *"toggling a Switch changes at least one rendered
glyph/word on screen (**state legible without color/position**)"*. AT-213 discharges it by
asserting `#crc_custom_vector_result` **text changes**. That is a different proposition:
the custom-vector CRC changes when *any* algorithm parameter changes, so the assertion
tests that `on_switch_changed` → `_recompute` is wired — which is already covered — and
says nothing about whether the **switch's own state** is readable. Variant B does not add
a state word; the design record is explicit that **Variant A** was the variant carrying
that fix.

**Evidence.**
- `01-requirements.md:118-119` (G-2 statement) vs `:102-103` (AT-213's G-2 arm).
- `prototypes/p1_design_defects.NOTES.md:67` — Variant B's switch fix is *"adjacency
  eliminated horizontally: label between the two switches"*. `NOTES.md:66` — Variant **A**
  is the one with *"visible track tile + **on/off state word**"*. B was chosen; the state
  word came with A and was not stolen (§7 verdict table `NOTES.md:104` — "Steals from: —").
- `prototypes/p1_design_defects.NOTES.md:72-74` — G-2's design intent: *"a control's
  state must render as glyph/word, **not slider position alone**"*.
- Wiring is already proven independently: `tests/test_crc_designer_view.py:414-415` and
  `:432-433` read both switch values through the recompute path today.

**Impact.** The batch ships a green "design guard" that cannot fail on the axis it names.
This is the project's documented dominant defect class (`dev-flow-lessons`: *the dominant
defect class is the vacuous check, and it concentrates in SPECS, not code*), and here it
is baked into the HLR, not just the test — so a Phase-3 reviewer reading only the AT
against the HLR will find them consistent.

**Proposed disposition.** Decide which proposition G-2 asserts and make the HLR say only
that. If it is state legibility, the requirement must add a rendered state token beside
each switch (steal Variant A's on/off word) and the AT must read **that token** off the
row's painted content (`render().spans` per C-37 if colour-bearing, `region`-anchored
content per C-32), toggling via the real `Switch` path. If the intent is only "the toggle
is wired", delete G-2 — it duplicates existing coverage and adds no guard.

---

### A-5 Every numeric geometry commitment is inherited from the prototype, none measured on the shipped tree (C-13 / C-23 / C-29) — major

**Claim.** This is a layout batch, and C-23 is unambiguous: *"A spec claim about RENDERED
layout size … MUST be established by a PILOT MEASUREMENT … NEVER by CSS `fr`-fraction
arithmetic"*, and any illustrative value *"MUST be labelled non-normative"*. Four numeric
commitments appear in §3/§4 — `Select height: 3`, card `3fr` / key `2fr`, dialog
`width: 96%`, the "80-col floor" stacking — and **none** carries a measurement, a budget
arithmetic, or an `assumed — measure in Phase N` label. All four are lifted verbatim from
`prototypes/legend_p1.inapp_prototype.py:96-103` and `NOTES.md:50-52`.

**Evidence — executed pilots on the SHIPPED tree.**

*Legend, mac view:*
```
size (120,30)  dialog Region(w=82,h=25)  body Region(w=76,h=15)  virtual_size h=39  scroll needed: True
size (80,24)   dialog Region(w=54,h=19)  body Region(w=48,h=9)   virtual_size h=49  scroll needed: True
card widgets: 17   key widgets: 6
```
The defect the story names is real and now quantified: at 120x30 the key's first row sits
~29 rows into a **15-row** viewport. But the *fix's* budget is tight and unstated. Under
LLR-072-5.1, dialog 96% of 120 = ~115 cols; minus `border: round` (2) and
`.modal-dialog { padding: 1 2 }` (4, `styles.tcss:1503-1511`) = ~109 content cols; 3fr/2fr
→ card ≈65, **key ≈43**. At the measured 46-col width (the 80-col run) the six key
widgets already occupy ~18 rows because the MAC "Red" meaning wraps
(`legend.py:137-141`, 84 chars). The key pane's height budget is the same **15 rows** the
body has today. **≈18 rows of key content into a 15-row pane** — AT-216's
"`Pale yellow` visible without scrolling" is probably satisfiable (it is the 3rd key
widget) but it is *close*, and nobody measured it.

*At the floor it is worse.* Body height at 80x24 is **9 rows**. HLR-072-6 stacks both
panes into those 9 rows, and the prototype gives each pane `height: 100%`
(`legend_p1.inapp_prototype.py:100,103`) — two `height: 100%` siblings stacked in a 9-row
container is degenerate. The prototype never rendered this case (it has no narrow rule at
all, A-2), so the floor behaviour is **entirely un-prototyped and un-measured**.

*CRC Select:*
```
crc_preset_select  Region(x=39,y=23,width=12,height=6)  value 'CRC-32/ISO-HDLC'
crc_coverage_on_gap_conflict  Region(w=12,h=4)   crc_field_store_endianness Region(w=12,h=4)
crc_custom_vector_mode Region(w=13,h=3)          crc_coverage_intra_gap Region(w=12,h=3)
```
HLR-072-4's rationale ("shipped Selects wrapped to 5-6 rows at 120x30") is **TRUE** —
confirmed at h=6 for the preset. But the *cap* is the un-measured half: the preset Select
is **12 columns wide** holding a **15-character** value, and it is 6 rows tall *because it
is wrapping that value*. Forcing `height: 3` leaves one content row. Whether the preset
name then truncates or ellipsises at 120x30 is **UNVERIFIED** — I attempted a runtime CSS
injection probe and it did not re-apply, so I make no claim either way. That unverifiable
gap **is** the finding: C-23 requires Phase 1 to have measured it, and HLR-072-4 states a
chrome cap with no companion legibility clause.

**Impact.** C-29's origin case (batch-46) is this exact failure — a prototype's budget
inherited into an AT that was physically unachievable in the boxed production container,
caught only at Phase 3, forcing a mid-increment stop. The `2fr` key pane and the 9-row
floor body are the same shape of risk.

**Proposed disposition.** Before Phase 3, pilot-measure and record in §2 (a
`00-measurements.md` is the project's usual home): (i) key-pane rendered height and the
row index of `Pale yellow` at 120x30 for `mac` **and** `map` (the map band key has 8+
widgets, `screens.py:1160-1177`); (ii) the stacked-pane budget at 80x24 with explicit
heights for both panes — and relax AT-217 to reachable-under-scroll if 9 rows cannot hold
both (C-29's prescribed remedy); (iii) the preset Select's rendered value at `height: 3` /
width 12. Label anything still unmeasured `assumed — measure in Phase 3`.

---

### A-6 `#legend_body` is omitted from HLR-072-7's preserved-id list but 9 test sites and a shipped requirement row depend on it — major

**Claim.** HLR-072-7 preserves `#legend_dialog`, `#legend_close`,
`#legend_mac_warning_sample`. It does **not** name `#legend_body`, which is the single
`ScrollableContainer` the two-pane split replaces — and which nine test query sites use as
their selector root, plus a shipped `R-*` row and a live CSS rule.

**Evidence.**
- `s19_app/tui/screens.py:1194-1206` — `compose` yields
  `ScrollableContainer(*body, id="legend_body")` holding card + key in one flat list.
- Test sites rooted on it: `tests/test_legend_n8.py:284,387`;
  `tests/test_legend_scope_and_logwidth.py:34,88,89,121`;
  `tests/test_tui_legend.py:60,338,407`. All are descendant selectors
  (`#legend_body Static`, `#legend_body .legend-row`, `#legend_body Label`).
- `REQUIREMENTS.md:3352` — R-LEGEND-MODAL-001's Code line names
  ``styles.tcss `#legend_dialog`/`#legend_body` `` as the shipped surface.
- `s19_app/tui/styles.tcss:1543-1546` — `#legend_body { height: 1fr; overflow-y: auto; }`.
  If `#legend_body` becomes the two-pane `Horizontal` wrapper, `overflow-y: auto` on it
  plus `auto` on each pane creates three nested scroll contexts.
- `01-requirements.md:192` (§5.3.3) requires those three legend test files green.
- §2.7 P-6 *does* identify `legend_body` as pinned in 3 files — so the census found it and
  the HLR then dropped it. That is a traceability break between §2.7 and §3.

**Impact.** If Phase 3 names the panes `#legend_card_pane` / `#legend_key_pane` and retires
`#legend_body`, all nine query sites resolve to **zero widgets**. Per C-38, a narrowed
query that quietly empties still *passes* many assertions (`all(...)` over an empty set,
`assert not …`), so this can ship green — the batch-n8 origin case verbatim.

**Proposed disposition.** Add `#legend_body` to HLR-072-7's preserved-id list with an
explicit binding: keep `id="legend_body"` on the **two-pane wrapper** so every descendant
selector still resolves, and state in LLR-072-5.1 that the `overflow-y: auto` moves from
`#legend_body` to the two pane containers. Then re-verify each of the nine sites is
non-empty after the change (C-38 sweep), not merely green.

---

### A-7 LLR-072-2.1's "delete `verdict_group`" silently drops the only on-screen naming of the KAT reference vector — major

**Claim.** `verdict_group` has **two** children, not one. Deleting it as written removes
`Label("Known answer · 123456789")` — the only place in the app where the self-test's
reference vector is named on screen. No HLR says where that text goes, and HLR-072-2's
preservation clause covers only the id `#crc_kat_verdict` and the tri-state glyph tokens.

**Evidence.**
- `s19_app/tui/crc_designer_view.py:395-400`:
  `verdict_group = Vertical(Label("Known answer · 123456789", classes="crc-group-title"),
  Static("", id="crc_kat_verdict", …), id="crc_live_verify", classes="crc-field-group crc-hero")`.
- Executed grep: `"Known answer"` appears at **exactly one** site in the whole repo —
  `crc_designer_view.py:396`. There is no second surface carrying it.
- `01-requirements.md:157-158` — LLR-072-2.1: "`Self-test` row after the Check row; delete
  `verdict_group`". The re-parenting of `#crc_kat_verdict` is implied by HLR-072-2 but not
  stated in the LLR, so the LLR read literally deletes the queried id too.
- The semantics matter: `NOTES.md:20-24` and `HANDOFF-PLAN.md:53-56` both record that the
  operator's KAT framing under-states what `kat_ok` does — it validates the algorithm
  definition against the **published `123456789` check**. The label is what communicates
  that. `_save_template`'s warning text (`crc_designer_view.py:1204-1206`) also names
  `123456789`, but only after a Save.

**Impact.** A bare `Self-test  ✓ MATCH` row under `Check` does not tell the engineer *what*
was self-tested. The demote (over remove) was chosen precisely to keep the live
counterpart of that signal; dropping its caption erodes the reason for the choice.

**Proposed disposition.** Amend HLR-072-2 to state the `Self-test` row's rendered label
text explicitly (e.g. `Self-test` label + a `· 123456789` caption, or a tooltip/inline
suffix), and rewrite LLR-072-2.1 as "**re-parent** `#crc_kat_verdict` into
`#crc_algorithm_fields` and drop the now-empty `#crc_live_verify` wrapper" — "delete
`verdict_group`" is the wrong verb for an operation that must preserve a child.

---

### A-8 §5.3.5's REQUIREMENTS.md amendment target does not exist — major

**Claim.** §5.3.5 requires "new/amended rows for the bench layout (batch-59 lineage §6.5
Before/After — **the verdict-tile row changes**)". There is no verdict-tile row in
`REQUIREMENTS.md`. The batch-59 bench layout was never registered there at all, so the
obligation is to **add** rows for a two-batch-old design, and no HLR owns that work.

**Evidence.** Executed greps over `REQUIREMENTS.md`:
- `crc_live_verify` → **0 hits**
- `verdict hero` → **0 hits**
- `crc_bench` / `bench layout` / `hero row` → **0 hits**
- `Designer` / `designer` → **0 hits**

Every one of those tokens lives only in `.dev-flow/2026-07-21-batch-59/01-requirements.md`
(e.g. `:145`, `:242`, `:258`). The `§6.5 Amendment` convention rows that *do* exist in
`REQUIREMENTS.md` (`:439`, `:464`, `:4244`, `:4292`, `:4373`) are all for batches whose
requirement was registered first.

**Impact.** Two distinct problems. (1) The stated Phase-6 obligation is un-actionable as
written — an implementer looking for "the verdict-tile row" finds nothing and will either
skip it or invent a row with no lineage. (2) The repo's *"Requirements traceability"*
convention (`CLAUDE.md`, "When you add behavior covered by a requirement, update the
corresponding `R-*` entry") has a pre-existing hole for the whole CRC Designer view;
batch-72 is about to widen it by changing that unregistered layout again.

**Proposed disposition.** Restate §5.3.5 as: **add** `R-TUI-*` rows for the CRC Designer
bench layout (post-batch-72 state) and for the two-pane Legend, and **amend**
`R-LEGEND-MODAL-001` (`REQUIREMENTS.md:3351-3352`, which is real and does name
`#legend_body`). Give this an owning HLR or an explicit Inc-3 line item — §5.3 acceptance
criteria are a checklist, not a requirement, and nothing else in §3/§4 covers documentation.

---

### A-9 Derivation gaps: HLR-072-4 has no parent story; HLR-072-3 has no LLR and is a meta-requirement — major

**Claim.** Check 1 (US→HLR→LLR) does not close.

**Evidence.**
- **HLR-072-4 (Select chrome cap) traces to neither user story.** US-072-1
  (`01-requirements.md:51-59`) is about the reflection pair and the KAT demotion; it never
  mentions Selects, chrome density, or the fold. §5.2's table (`:179`) maps
  US-072-1 → "HLR 072-1..4" by range notation, which papers over the gap rather than
  showing the derivation. Its actual origin is a side observation in
  `HANDOFF-PLAN.md:38-41` ("A finding the shots surfaced, free of charge") — a legitimate
  finding, but it needs its own story or an explicit "adopted from the design pass" note.
- **HLR-072-3 has no LLR.** §4 lists LLR-072-1.1, 2.1, 2.2, 5.1, 6.1, 7.1 — none parents
  to HLR-072-3. §5.2 assigns US-072-1 the LLRs "1.1, 2.1, 2.2", confirming the omission.
- **HLR-072-3 is a requirement on the test suite, not on the system.** It reads "The batch
  **shall** encode: G-1 …, G-2 …". A `shall` whose subject is "the batch" is a process
  obligation. Every other HLR here has the product as its subject. This is why it has no
  LLR — there is no product change to decompose — and it is also why A-3 and A-4 were able
  to hide: a guard stated as "encode an AT" is never checked against the product.

**Impact.** The functional chain US→HLR→LLR→TC is broken at two points, which is the
evidence-checklist item that blocks the gate. Practically: HLR-072-4's CSS lands inside
LLR-072-2.2 (an HLR-072-2 child), so a Phase-4 reviewer tracing HLR-072-4 finds its
implementation under a different parent.

**Proposed disposition.** Either fold the Select cap into US-072-1's narrative (the fold /
affordance-density argument, with the measured 6-row evidence from A-5) or give it its own
one-line story. Give HLR-072-4 its own LLR rather than sharing LLR-072-2.2. Restate
HLR-072-3 as product requirements — *"no two `Switch` widgets shall abut…"* (already
HLR-072-1) and *"each `Switch`'s state shall render as a word/glyph adjacent to it"* — and
let AT-214/AT-213 be their acceptance, rather than making "encode an AT" the requirement.

---

### A-10 Keyboard / focus-traversal consequences are unowned (C-16) — major

**Claim.** Both stories re-lay-out a form and neither has a requirement covering focus
order or keyboard reachability, even though the design intent's own G-4 guard is about
reachability. C-16 is squarely on point: *"when a story's promise (esp. keyboard/pointer
interaction, focus traversal…) is demonstrated in a throwaway prototype … the requirement
MUST flag that interaction `assumed — verify in target framework at Phase 3`"*.

**Evidence.**
- **Measured:** `ScrollableContainer.can_focus == True` on textual 8.2.8 (executed:
  `python -c "from textual.containers import ScrollableContainer; print(ScrollableContainer.can_focus)"`
  → `True`; `Horizontal`/`Vertical` → `False`). The modal has **one** focusable container
  today (`#legend_body`, `screens.py:1198`); the two-pane split makes it **two**, changing
  the tab cycle. `LegendScreen.on_mount` (`screens.py:1208-1209`) focuses `#legend_close`
  and nothing re-specifies the order after it.
- **AT-217's "both reachable" is undefined** (`01-requirements.md:141-142`) — reachable by
  scrolling? by `Tab`? by `scroll_visible()`? Each is a different assertion, and per C-16
  the AT must exercise the **real** mechanism, not a `.focus()` proxy.
- **G-4 was dropped without disposition.** `HANDOFF-PLAN.md:123` defines G-4 (*"the colour
  key is reachable within ≤1 interaction from modal-open at 120x30 AND 80x24"*). §3
  encodes G-1 and G-2 only; §2.7 does not evaluate G-4 as a premise; §6.3 does not list its
  omission as a risk. Same for **G-3** (`HANDOFF-PLAN.md:122`, hero extent / the 6:1 law) —
  which is the guard for exactly the change HLR-072-2 makes (deleting the second
  majority-bright tile). Both simply vanish between the handoff plan and §3.
- CRC side: the pair row preserves refin→refout order and inserts a non-focusable `Static`,
  so the CRC tab-order risk is **low** — stated as a clean axis, not a finding.

**Impact.** The Legend story's entire value proposition ("the key stops living below the
fold") is a reachability claim, and reachability is the one property no HLR asserts. G-3's
omission is the sharper loss: the batch deletes a hero tile and has no requirement that
the remaining hero still reads as the hero.

**Proposed disposition.** Add an HLR for key-pane reachability that encodes G-4 with a
defined interaction budget, drive it through the real key path in the AT, and flag the
whole interaction axis `assumed — verify in target framework at Phase 3` per C-16. Either
encode G-3 against the post-batch hero row or record an explicit, reasoned decision to drop
it in §6.3 — an unremarked disappearance is not a decision.

---

### A-11 Under-specified terms that an implementer cannot decide without guessing — minor

**Claim.** Four phrases in §3 are not decidable as written. Two are benign today and one
is resolvable from disk; all four should be pinned before Phase 3.

**Evidence + disposition, per term.**

| Term (site) | Status | Evidence | Disposition |
|---|---|---|---|
| *"the app's wide regime"* (HLR-072-5, `:132`) | **Defined on disk, not cited** | `app.py:6202` — `narrow = width < 120`. So wide ⇔ `width >= 120`. | Cite the breakpoint and its source line. Note it is currently a *workspace* regime with no modal reach (A-2). |
| *"no two `Switch` widgets are vertically adjacent **anywhere on the screen**"* (HLR-072-1, `:98-99`) | **Benign today, unmeasurable as written** | Executed grep: `Switch(` appears at **exactly one** construction site app-wide — `crc_designer_view.py:467` — reached only by `_switch_row`, called twice (`:301-302`). So the CRC screen has exactly 2 Switches and no other screen has any. | Replace "anywhere on the screen" with the measurable relation (same as A-3's disposition) scoped to `#crc_designer_panel`. "Anywhere on the screen" implies a sweep no AT will actually perform. |
| *"focusable control"* (HLR-072-3 G-1, `:116-117`) | **Undefined** | The probe found 6 `SelectOverlay` widgets with `focusable=True` and `Region(0,0,0,0)`; including them makes the predicate incoherent. | Define as `widget.focusable and widget.region.area > 0`, scoped to `#crc_designer_panel` descendants. |
| *"a ≥1-row gap, border, or interleaved label"* (HLR-072-3, `:117-118`) | **Undefined disjuncts** | Labels are same-row siblings (`crc_designer_view.py:442-451`), never vertically interposed — so the third disjunct is unreachable on this form as built. | Operationalize each: gap = `b.region.y - (a.region.y + a.region.height) >= 1`; border = `styles.border` non-`none` on either widget or their shared row; interleaved label = a `Label` whose `region.y` lies strictly between. Or strike the unreachable disjunct. |

---

### A-12 §4 LLRs are one-line sketches and no TC exists — the functional traceability chain is a placeholder — minor

**Claim.** The evidence-checklist item requires **both** chains to exist: behavioral
US→AT→outcome and functional US→HLR→LLR→TC. The behavioral chain is genuinely present and
well-formed (six ATs, each with a stated observable). The functional chain terminates in
reservations.

**Evidence.**
- `01-requirements.md:154` — §4 is headed "**sketch** for Phase-2 refinement"; the six LLRs
  are single sentences with no Statement / Numeric pass threshold / Acceptance-criteria
  structure. Compare `.dev-flow/2026-07-21-batch-59/01-requirements.md:242-246`, which is
  the project's own baseline for what an LLR looks like (Statement, numeric threshold,
  acceptance criteria, id inventory).
- `01-requirements.md:179-180` — the TC column reads "TC-510..TC-514 (**reserved**)" /
  "TC-515..TC-519 (**reserved**)". No TC is authored; §5.1 describes the *method* only.

**Impact.** Phase 3 will author both the LLR detail and the TCs, i.e. the white-box design
is being deferred past the review that exists to check it. Given A-1/A-2/A-3/A-5 — every
one of which is an LLR-level defect — deferring is what let them through.

**Proposed disposition.** Promote §4 to real LLRs during the Phase-1 iterate this review
recommends: each with a statement, a numeric/structural pass threshold, and its id
inventory. At minimum, LLR-072-2.1 (A-7), LLR-072-5.1 and LLR-072-6.1 (A-2, A-6) must be
written out before Phase 3 — those three are where the blockers live.

---

### A-13 Template section numbering is incomplete — minor

**Claim.** §1 jumps 1.2 → 1.4 (no §1.3); §2 opens at 2.4 (no §2.1 Product perspective /
2.2 Functions / 2.3 Users). Not a defect in substance — the omitted sections carry little
for a two-story layout batch — but it makes the document hard to diff against the batch-59
and batch-63 requirements it inherits from.

**Evidence.** `01-requirements.md:10` (§1.1), `:16` (§1.2), `:23` (§1.4), `:30` (§2), `:32`
(§2.4). Contrast `.dev-flow/2026-07-21-batch-59/01-requirements.md`, which is contiguous.

**Proposed disposition.** Either renumber contiguously or add one-line "n/a — layout batch"
stubs. Lowest priority in this review; fix it while iterating for the blockers.

---

## Evidence checklist

| # | Item | ✓/✗ | Evidence (file:line / executed output) |
|---|---|---|---|
| 1 | **Derivation soundness** — each HLR traces to a US; each LLR to an HLR; no orphans | ✗ | **A-9.** HLR-072-4 (Select cap) has no parent story — US-072-1 `:51-59` never mentions Selects; origin is `HANDOFF-PLAN.md:38-41`. HLR-072-3 has **no LLR** (§4 `:156-167` lists 1.1/2.1/2.2/5.1/6.1/7.1; §5.2 `:179` confirms). HLR-072-1/2 → US-072-1 ✓; HLR-072-5/6/7 → US-072-2 ✓. |
| 2 | **Normative modal discipline** — `shall` only in HLR/LLR; no `should` as a modal | ✓ | Executed grep for `should\|must\|shall\|may ` over the whole doc: `should` → **0 hits**. `shall` appears only at `:95,106,109,110,116,125,132,139,145` — all inside HLR statements. `must` at `:36` (§2.4 constraint), `:121` (AT-214 discharge), `may` at `:46`,`:185` — all outside HLR/LLR statements. **No finding on this axis.** |
| 3 | **Ambiguity that will bite Phase 3** | ✗ | **A-11.** "wide regime" = `width >= 120`, defined at `app.py:6202` but uncited. "anywhere on the screen": measured — `Switch(` has **1** construction site app-wide (`crc_designer_view.py:467`), 2 instances, both in `#crc_algorithm_fields`; benign but unmeasurable as phrased. "focusable control": undefined — probe found 6 zero-area `SelectOverlay`s with `focusable=True`. "interleaved label": unreachable disjunct (labels are same-row siblings, `crc_designer_view.py:442-451`). |
| 4 | **Geometry controls (C-13 / C-13.1 / C-23 / C-29)** — numbers measured on the SHIPPED tree, not inherited | ✗ | **A-5.** All four numbers inherited from `legend_p1.inapp_prototype.py:96-103` / `NOTES.md:50-52`; none labelled `assumed — measure`. Measured shipped budget: legend body `h=15` @120x30 / `h=9` @80x24 vs key content ~18 rows at 46 cols; `crc_preset_select` `w=12 h=6` holding a 15-char value. `height: 3` consequence **UNVERIFIED** (runtime CSS injection probe did not re-apply). |
| 5 | **§2.4 constraint set** — the six `_recompute` ids are exactly right; Variant B keeps all six mounted | ✓ | `crc_designer_view.py:1115-1121` — the six are `#crc_kat_verdict`, `#crc_custom_vector_result`, `#crc_json_preview`, `#crc_warnings`, `#crc_coverage_preview`, `#crc_coverage_window`; `except NoMatches: return` at `:1122-1124`. **`#crc_live_verify` is NOT among them** (`crc_designer_view.py:398` — it is the wrapper's id, not a queried surface), so deleting the hero tile removes no queried id provided `#crc_kat_verdict` is re-parented. §2.4 is correct and Variant B is safe on this axis. **No blocker.** Also verified AT-B59-03's probes (`crc_field_width`/`crc_coverage_ranges`/`crc_custom_vector`, `tests/…:949`) stay in c1/c2/c3 under Variant B ✓. |
| 6 | **LLR-072-2.1 `delete verdict_group`** — what else does it contain? | ✗ | **A-7.** `crc_designer_view.py:395-400` — two children: `Label("Known answer · 123456789")` **and** `Static(id="crc_kat_verdict")`. Executed grep: `"Known answer"` → **1 hit repo-wide**, that line. The label is silently dropped and the LLR's verb ("delete") also contradicts HLR-072-2's id-preservation clause. |
| 7 | **HLR-072-7 preservation claim** — does the key move leave `_render_key` untouched? | ✓ (with A-6) | `screens.py:1132-1192` — `_render_key` returns a flat `List[Widget]` (`Label` + `Static`s) and emits **no container**; the map branch (`:1160-1177`) likewise appends into the flat list. Re-parenting the returned widgets into a pane cannot affect it. **HLR-072-7's claim on `_render_key` is SOUND — no blocker on this axis.** The gap is the *container*: `#legend_body` is omitted from the preserved-id list (**A-6**). |
| 8 | **Missing requirements** — esp. keyboard / focus traversal (C-16) | ✗ | **A-10.** `ScrollableContainer.can_focus == True` (executed, textual 8.2.8); one → two focusable containers; `screens.py:1208-1209` focuses `#legend_close` with no re-specified order. **G-3** (`HANDOFF-PLAN.md:122`) and **G-4** (`:123`) dropped between the handoff plan and §3 with no disposition in §2.7 or §6.3. AT-217's "both reachable" (`:141-142`) undefined. Also **A-8**: no HLR owns the REQUIREMENTS.md registration. CRC-side tab order: low risk, order preserved ✓. |

---

## Verdict

**4 blockers, 6 majors, 3 minors — ITERATE back to Phase 1.**

| Severity | Findings |
|---|---|
| **Blocker** | A-1 (AT-B59-05 contradiction) · A-2 (no floor-stacking mechanism) · A-3 (G-1 unsatisfiable — 16 pairs measured) · A-4 (G-2 proves the wrong proposition) |
| **Major** | A-5 (un-measured geometry) · A-6 (`#legend_body` unpreserved) · A-7 (`verdict_group` second child) · A-8 (non-existent REQUIREMENTS.md target) · A-9 (derivation gaps) · A-10 (focus/G-3/G-4 unowned) |
| **Minor** | A-11 (undefined terms) · A-12 (LLR/TC placeholders) · A-13 (section numbering) |

**Minimum to clear the gate.** A-1 and A-2 are cheap and mechanical: name the AT-B59-05
retirement, and name the modal's own width mechanism. A-3 and A-4 are the ones that need a
real decision, because both ask *what does this batch actually promise* — a general
separability guard the form cannot currently satisfy, or a narrow one; a legible switch
state, or just a wired handler. Answer those two and the batch is sound; leave them and it
ships two green guards that guard nothing, which is the failure mode this project has
already catalogued 38 times.

**What would change this verdict.** If the operator scopes G-1/G-2 to the two Switches
only and accepts that they restate HLR-072-1, A-3 and A-4 collapse to minors and the batch
clears with A-1/A-2 fixed. Conversely, if the intent is a form-wide separability standard,
this is a substantially larger batch that reverses batch-59's R9 compact-row decision, and
the increment cut in `PLAN.md:58-64` is wrong.
