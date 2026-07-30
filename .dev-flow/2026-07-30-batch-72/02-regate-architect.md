# Phase-2 RE-GATE — architect — batch 2026-07-30-batch-72

> Discharge review of `01-requirements.md` **revision 2** (`0a56ef6`) against the 13 findings in
> [`02-review-architect.md`](02-review-architect.md). Every ruling below was reached by **re-reading
> revision 2 and re-executing the claim**, never by trusting that the fold ran (C-44: a conditional
> verdict is not an authorisation). Probes ran in this worktree, Python 3.14.4 / textual **8.2.8**,
> as throwaway scripts in the session scratchpad. **No repo file other than this one was created or
> modified** — integrity proof at the end.

---

## BLUF

**ITERATE — 1 blocker, 6 majors, 3 minors. All 13 of my Phase-2 findings are CLOSED or
PARTIALLY CLOSED; the blocker is new and it was introduced by the fold.**

Revision 2 is a genuinely better document. The measurement pass did what it was supposed to do: it
caught a defect *inside* the review (qa's same-class re-scope measures 7→6, not 1→0), it killed a
requirement rather than shipping a control that lies about its value (HLR-072-4), and it turned four
inherited prototype numbers into executed ones. I independently reproduced M-2 end-to-end — dialog
113 cols, card **64**, key **43**, `key.max_scroll_y == 0`, `Pale yellow` at key content rows
`[5, 8)` — from a two-pane tree built on the real `_render_card`/`_render_key`. Those numbers are
real.

**The blocker (N-1) is an ordering contradiction the fold created while closing A-2.** LLR-072-5.1
pins the compose as `Horizontal(card_pane, key_pane)` — **card first**. HLR-072-6 / AT-217 clause 1
require the **key first** at the floor. Textual 8.2.8 has no CSS ordering property (the full
`StylesBase` property list contains `dock` and nothing else that reorders), so the `legend-narrow`
class the fold added *cannot* deliver clause 1. Executed at 80x24 with exactly the specified compose
and CSS: `key.region.y < card.region.y` → **False** (card `y=6 h=4`, key `y=10 h=5`) in both views.
The tell is in the requirement's own numbers: LLR-072-6.2's pass threshold reads *"key h=4, card
h=5"* — that is the **key-first** measurement. M-3 measured a tree the requirement does not specify.
The fix is cheap and I executed it (`Widget.move_child` inside the regime hook restores all three
AT-217 clauses *and* keeps 64/43 in the wide regime), but it is not in the document.

Two axes I want on the record as **clean**, because they are the ones that usually rot: the A-2
regime hook is real and the requirement got the one detail that would have broken it right — it
specifies `self.app.size.width` (120 at the floor of the wide regime), not `self.size.width`, which
is **118** at `run_test(size=(120,30))` and would have flipped AT-216 into the narrow regime. And the
Phase-3 increment cut has **zero orphans**: every AT-213..219, every LLR-072-*, and every
TC-510..519 has exactly one owning increment.

---

## Q1 — Discharge of A-1 … A-13

| # | Original finding | What revision 2 now says (quoted) | Ruling |
|---|---|---|---|
| **A-1** | HLR-072-2 contradicts live `AT-B59-05`; §5.3.3 requires it green | `:161-166` *"This requirement **retires** batch-59's verdict-hero requirement (US-L3 / HLR-L3 / LLR-L2.3+L3.1) and its acceptance test `AT-B59-05` … **It is a deliberate retirement, not a weakening**: the test must be deleted, never edited into passing."* · `:440-442` *"**Parent-HLR re-read:** batch-59's HLR-L3 exists to make the verdict *findable*. The operator's 2026-07-28 report is that the tile does not earn hero placement; demoting it to an annotation of the field it validates preserves findability and improves attribution."* · `:307` LLR-072-2.4 *"**Delete** … Deletion, not edit."* · `:364` ledger `D = 1` | **CLOSED.** The parent-HLR re-read is real (it names *what HLR-L3 was for* and argues the surviving obligation), not a formality. The edit-into-passing prohibition is stated **twice**, once in the HLR and once in the LLR, and the ledger budgets it. `:444` also re-derives the surviving acceptance onto AT-215 clauses 1/2/4. |
| **A-2** | Floor-stacking mechanism cannot reach a `ModalScreen` | `:310` LLR-072-6.1 *"**The modal owns its own width regime.** `LegendScreen.on_mount` and `on_resize` read `self.app.size.width` against the **same breakpoint as `app.py:6202`** … and toggle a `legend-narrow` class on `#legend_dialog`."* + TC-517 | **CLOSED — probed, not reasoned.** See "Executed probe A-2" below: `on_resize` **is** a real hook on `ModalScreen` (it fires once at mount and on every terminal resize, both directions, while the modal is on top of the stack), and `self.app.size` **is** readable and correct at `on_mount` time. Mechanism confirmed implementable. **But** it does not deliver HLR-072-6 clause 1 — that is **N-1**, below. |
| **A-3** | G-1 unsatisfiable — 16 pairs, 1 fixed | `:179-193` HLR-072-3 re-scoped to `Switch` pairs; *"the subject set is derived from the DOM (`app.query(Switch)`) and is **complete by construction** … It coincides with HLR-072-1 *today* precisely because those two switches are the only ones that exist."* | **CLOSED, honestly.** The artifact **does** say out loud that the guard coincides with HLR-072-1 today (`:192-193`) — that was the specific thing I asked for and it is not buried. The completeness argument is sound *as grounded*: it rests on the repo grep (`Switch(` → **1** construction site, `crc_designer_view.py:467`), not on `app.query`. **One clause is factually wrong** — "a future third `Switch` enters the guarded set automatically" — see **N-4**. The guard has not collapsed into a vacuous restatement: it is FALSE pre-batch (1 violation) and satisfiable post-batch (0), which rules (a) and (b) are not. |
| **A-4** | G-2's AT proves handler wiring, not legibility | `:432` *"**Explicit retirement line (C-40 limb 2, instance ii):** what is dropped is *the guarantee that a `Switch`'s own state is readable without relying on slider position*. **Carried to the backlog.**"* + `:428-430` basis | **CLOSED.** What was dropped is named at the level of the *property*, not the test — a later reader can recover the guarantee from that sentence alone without reading `NOTES.md`. The basis correctly identifies the discharge as a duplicate of `test_crc_designer_view.py:414-415`. |
| **A-5** | Geometry inherited from the prototype, unmeasured | `00-measurements.md` M-2/M-3/M-4; `:235-237` *"card pane `3fr` → **64** cols; key pane `2fr` → **43** cols; body height 15 rows; `Pale yellow` at key content rows `[5, 8)`"* | **CLOSED for geometry** — three spot-checks re-executed independently, all exact (table below). **PARTIALLY CLOSED overall:** AT-213's `0xCBF43926 → 0x1898913F` is presented as *"(Measured: …)"* (`:152`) but `grep 'CBF43926\|1898913F\|123456789' 00-measurements.md` → **0 hits**. I executed it: `SEED_ALGORITHM.compute(b"123456789")` = `0xCBF43926`; `replace(refin=False).compute(...)` = `0x1898913F`. **Both values are correct** — the gap is documentation, not correctness. |
| **A-6** | `#legend_body` unpreserved; 9 query sites | `:131` P-12 *"`#legend_body` is **preserved as the two-pane wrapper**"* · `:262-270` HLR-072-7 preserves it · `:281` AT-218 clause 3 *"all 9 `#legend_body`-rooted query sites resolve **non-empty** after the change (C-38…)"* | **CLOSED.** Re-verified the 9 sites (`test_tui_legend.py:60,338,407`; `test_legend_n8.py:284,387`; `test_legend_scope_and_logwidth.py:34,88,89,121`) — **all nine are descendant selectors** (`#legend_body Static` / `Label` / `.legend-row` / `.legend-artifact` / `.legend-card-sub`), so a `Horizontal` wrapper keeps every one resolving. C-38 sweep correctly demanded as *non-empty*, not merely green. |
| **A-7** | `verdict_group`'s second child (`Known answer · 123456789`) silently dropped | `:157-158` *"the row **shall** carry the reference-vector naming `123456789` on screen"* · `:170` AT-215 clause 2 · `:304` LLR-072-2.1 *"**Re-parent, do not delete.**"* | **CLOSED.** The verb is fixed and the caption is promoted from an implementation detail to a normative clause with its own AT arm. |
| **A-8** | §5.3.5's amendment target does not exist | `:352-360` *"**ADD `R-TUI-100`** … This registers the CRC Designer view for the first time"* + two AMENDs · `:448-455` §6.5 A-8 with the executed 0-hit greps | **CLOSED**, and it has an owning increment — `PLAN.md:92-93` Inc-4 carries *"`R-TUI-100` + the two legend row amendments"*. |
| **A-9** | HLR-072-4 orphan story; HLR-072-3 has no LLR and is a process `shall` | HLR-072-4 **withdrawn** (`:206`) · `:179-180` HLR-072-3 restated with the **system** as subject: *"**No two `Switch` widgets shall render vertically abutting**"* · `:328` §5.2 *"— *(guard over 1.1)*"* | **CLOSED.** The orphan HLR is gone with the withdrawal, and the process-`shall` is now a product-`shall`. HLR-072-3 still has no LLR, but that is now *annotated as a decision* ("guard over 1.1") rather than an omission — which was the actual complaint. |
| **A-10** | Focus traversal unowned; G-3 and G-4 vanished | `:389-398` §6.4 dispositions **all four** guards · `:381-385` §6.3 focus risk flagged *"`assumed — verify in target framework at Phase 3`"* · G-4 split by regime into AT-216 (0 interactions) / AT-217 clause 3 (1 interaction) | **PARTIALLY CLOSED.** G-4's regime split is correct and measurement-driven; the C-16 flag is present and per-increment. **G-3's stated reason does not hold** — see **N-6**. It remains correctly *not encoded*; it is the *argument* that is wrong. |
| **A-11** | Four undefined terms | `:30-36` §1.3 defines *wide regime* (`width >= 120`, cited to `app.py:6202`), *floor*, *focusable control*, *vertically abutting* | **CLOSED**, with one orphan: after the G-1 re-scope, **no normative statement uses "focusable control"** — AT-214 clause 1 filters on `region.area > 0` only (`:196-197`). See **N-9** (minor; retaining it as M-1 provenance is defensible, it just needs to say so). |
| **A-12** | LLRs are sketches; TCs are bare reservations | `:300-313` — every LLR now carries Statement / Pass threshold / declared id inventory; `:324-332` — every TC now carries a named subject (e.g. TC-517 *"the `legend-narrow` class flips at the 120 breakpoint"*) | **CLOSED.** Both traceability chains close: behavioral US→AT→outcome (7 ATs, each with an observable) and functional US→HLR→LLR→TC. |
| **A-13** | Section numbering incomplete | §1.3 added; §2.1 Product perspective / 2.2 Functions / 2.3 Users added (`:48-58`) | **CLOSED.** |

### A-5 spot-checks — three geometry numbers, re-executed

Built from the **real** `LegendScreen._render_card()` / `._render_key()`, hosted in
`Horizontal(ScrollableContainer, ScrollableContainer)`, with LLR-072-5.2's CSS **appended to a copy
of the shipped `styles.tcss`** loaded as `CSS_PATH` (this matters — a `DEFAULT_CSS` override is
outranked by the app stylesheet and silently leaves `.modal-dialog { width: 70% }` in force; my
first attempt made exactly that mistake and produced 45/31, not 64/43).

| Requirement claim | Site | My executed value | Match |
|---|---|---|---|
| dialog @ `width: 96%` → 113 cols, content 107 | `01-requirements.md:235-236` | `dialog region=Region(x=3, y=2, width=113, height=25) container=Size(width=107, height=21)` | ✅ exact |
| card pane `3fr` → **64** cols; key pane `2fr` → **43** cols | `:236-237` / LLR-072-5.2 threshold `:309` | `card region=…width=64…` · `key region=Region(x=70, y=6, width=43, height=15)` | ✅ exact |
| `key.max_scroll_y == 0` and `Pale yellow` at key content rows `[5, 8)` | `:229`, `:237` | `key … max_scroll_y=0` · `sev-warning row region=Region(x=70, y=11, width=43, height=3)` → offset from pane `y=6` = rows **[5,8)**, `contained_in_key=True`, `scroll_offset=Offset(0,0)` | ✅ exact |

### Executed probe A-2 — is the regime hook real on textual 8.2.8?

```
--- ModalScreen pushed at 120x30 ---
   ('on_mount',  'app.size=Size(width=120, height=30)', 'self.size=Size(width=120, height=30)')
   ('on_resize', 'event.size=Size(width=120, height=30)', 'app.size=Size(width=120, height=30)')
   classes now: []
--- resize to 80x24 while the modal is on the stack ---
   ('on_resize', 'event.size=Size(width=80, height=24)', 'app.size=Size(width=80, height=24)')
   classes now: ['legend-narrow']
--- resize back to 120x30 ---
   ('on_resize', 'event.size=Size(width=120, height=30)', 'app.size=Size(width=120, height=30)')
   classes now: []
--- fresh app started AT 80x24, modal pushed after ---
   ('on_mount',  'app.size=Size(width=80, height=24)', ...)  classes now: ['legend-narrow']
```

Both halves of the question answer **yes**: `on_resize` is a genuine hook on a `ModalScreen`
(`Resize.handler_name == 'on_resize'`, `Resize.bubble is False` — it is delivered *directly* to the
screen, so no ancestry problem), and `self.app.size` is populated and correct at `on_mount`. The
class toggles in both directions.

**And the requirement got the subtle part right.** `LLR-072-6.1` says `self.app.size.width`. Under
`run_test(size=(120,30))` the real app's `screen.size` is `Size(118, 28)` (`Screen { padding: 1 }`,
`styles.tcss:33-38`) while `app.size` is `Size(120, 30)`. Had the LLR said `self.size.width`, the
modal would compute `118 < 120` → **narrow at AT-216's own 120x30 pilot size**, and AT-216 would
fail for a reason unrelated to the layout. `app.py:6212` reads the App-level `event.size.width`, so
`app.size` is also the *same* quantity the base-screen regime uses. Clean axis, and a near-miss
worth naming.

---

## Q2 — Did the fold introduce new defects?

### N-1 — HLR-072-6's key-first ordering is unreachable from LLR-072-5.1's compose — **BLOCKER**

**Claim.** LLR-072-5.1 pins the compose order as **card, then key**. HLR-072-6 and AT-217 clause 1
require **key above card** at the floor. The only mechanism the batch owns is a CSS class, and
textual 8.2.8 has no CSS property that reorders children. The two requirements are jointly
unsatisfiable as specified.

**Evidence — executed.** Real `LegendScreen` subclass, compose exactly as LLR-072-5.1 writes it,
CSS exactly as LLR-072-5.2 + LLR-072-6.2 write it (narrow-prefixed), regime hook exactly as
LLR-072-6.1 writes it:

```
### compose=card_first requested=(80, 24) view=mac
  dialog classes=['legend-narrow', 'modal-dialog']
  card  region=Region(x=6, y=6,  width=68, height=4)
  key   region=Region(x=6, y=10, width=68, height=5)
  AT-217.1 key.y < card.y   : False        <-- clause 1 FAILS
  AT-217.2 card.h >= 2      : True (h=4)
  AT-217.3 key.max_scroll_y>=1: True (5)
### compose=card_first requested=(80, 24) view=map   -> AT-217.1 : False   (card h=4, key h=5)
```

- No ordering primitive exists: enumerating `textual.css.styles.StylesBase` public properties and
  filtering for `order|direction|reverse|dock` returns **`dock`, `is_docked`** and nothing else.
- The contradiction is visible inside the requirement itself. `01-requirements.md:311`
  (LLR-072-6.2 pass threshold) reads *"measured `1fr/1fr` at 80x24 → **key h=4, card h=5**"*. That
  is the **key-first** tree — I reproduce `key h=4, card h=5` only when the compose puts the key
  first. With LLR-072-5.1's card-first compose the same CSS yields `card h=4, key h=5`. **M-3
  measured a tree the requirement does not specify.**
- Composing key-first instead does not rescue it — it breaks HLR-072-5. Executed at 120x30 with
  `compose=key_first`: `key region=Region(x=6, …)`, `card region=Region(x=48, …)` — the key renders
  **left** of the card, violating *"card left, key right"* (`:216`).

**Impact.** Phase 3 hits this inside Inc-2 with AT-217 already authored and RED on clause 1. The
cheapest way out under a green-suite gate is to weaken clause 1 (drop it, or swap it to
`card.y < key.y`) — which discards the operator's **explicitly confirmed** P-8 decision
(*"Stack, key first (Recommended)"*, `:127`) with no Before/After record. That is the A-1 failure
mode replayed on the one clause the operator personally chose.

**Disposition — and it is cheap; I executed the remedy.** Add the reordering to LLR-072-6.1's hook
(it is a *behaviour*, which is why Inc-2 already exists as a separate increment) and state it in
HLR-072-6's mechanism note. `Widget.move_child(child, *, before=None, after=None)` exists on 8.2.8.
With `body.move_child(key, before=card)` on entering narrow and the inverse on leaving:

```
### movechild + card_first  (120,30) mac : card w=64 x=6  | key w=43 x=70   <- HLR-072-5 ✅, AT-216 numbers ✅
### movechild + card_first  (80,24)  mac : key y=6 h=4    | card y=10 h=5
     AT-217.1 True | AT-217.2 True (h=5) | AT-217.3 True (6)               <- all three clauses ✅
### movechild + card_first  (80,24)  map : AT-217.1 True | AT-217.2 True (h=5) | AT-217.3 True (7)
```

Note this also makes LLR-072-6.2's pinned `key h=4, card h=5` correct as written. Whatever mechanism
is chosen, **TC-517 must assert the resulting child order, not just the class** — the class flipping
is now provably insufficient to produce clause 1.

---

### N-2 — LLR-072-6.2's pane rules are written unprefixed and override the wide regime — **major**

**Claim.** `01-requirements.md:311` reads: *"`#legend_dialog.legend-narrow #legend_body { layout:
vertical }` with the key pane **first in document order**, `#legend_key_pane { width: 100%; height:
1fr }`, `#legend_card_pane { width: 100%; height: 1fr }`."* The second and third selectors carry no
`.legend-narrow` prefix. They have the same specificity as LLR-072-5.2's `#legend_card_pane { width:
3fr }` / `#legend_key_pane { width: 2fr }` and appear later in source order, so on the literal
reading they win **in both regimes**.

**Evidence — executed** (same probe, rules transcribed literally):

```
### compose=card_first requested=(120, 30) view=mac
  card  region=Region(x=6,   y=6, width=107, height=15)
  key   region=Region(x=113, y=6, width=107, height=15)
```
`#legend_body` is `Region(x=6, width=107)` → `[6, 113)`. The key pane starts at **x=113** — entirely
outside the body **and** partly outside the 113-col dialog `[3, 116)`. LLR-072-5.2's own pass
threshold ("card 64 cols, key 43 cols") fails.

**Impact.** An implementer will probably infer the missing prefix — but "probably" is what an LLR
exists to remove, and the failure it permits is invisible to the batch's own gate (**N-3**).

**Disposition.** Write the two narrow pane rules with their `#legend_dialog.legend-narrow` prefix,
exactly as the first one is written.

---

### N-3 — AT-216 passes on a layout with the key pane rendered off-dialog — **major**

**Claim.** AT-216's three assertions are (1) locate the key row by class inside `#legend_key_pane`,
(2) `#legend_key_pane.region.contains_region(row.region)` with `scroll_offset == (0,0)`,
(3) `#legend_key_pane.max_scroll_y == 0`. Every one of them is **relative to the key pane**. None
asserts the key pane is inside `#legend_body`, inside the dialog, or on screen at all.

**Evidence — executed.** On the N-2 layout (key pane at `x=113`, outside the body):

```
  AT-216.2 sev-warning row region=Region(x=113, y=9, width=107, height=1)
           contained_in_key=True   key.scroll_offset=Offset(x=0, y=0)
  AT-216.3 key.max_scroll_y==0: True
```

All three clauses **green** on a legend where the colour key is not visible to the operator. The
`display: none` oracle mutation in clause 4 does not cover this — `display: none` zeroes the region
and breaks clause 1/2; an off-dialog pane does not.

**Impact.** This is the project's catalogued dominant defect class, and it survived a fold that was
specifically hardening AT-216 against vacuity (Q-4/Q-5). The batch's headline story is *"the key
stops living below the fold"*, and its gate cannot fail when the key lives off the side instead.

**Disposition.** Add one clause: `#legend_body.region.contains_region(#legend_key_pane.region)`
(and the same for the card pane). Executed, that clause is `True` on the correct layout and `False`
on the N-2 layout, so it discriminates. It also subsumes the "side-by-side" property AT-216
currently asserts nowhere.

---

### N-4 — HLR-072-3's "a future third `Switch` enters the guarded set automatically" is false — **major**

**Claim.** `01-requirements.md:190-193` grounds the whole not-special-pleading argument on that
sentence. `App.query` is **screen-scoped**, so a `Switch` added to any other screen or modal never
enters AT-214's derived set.

**Evidence — executed.** `inspect.getsource(App.query)` → `node = self._get_dom_base()`; measured on
the running app while on the CRC screen: `app._get_dom_base() -> Screen`, `app.query(Switch) -> 2`.
The *static* half of the argument is sound and is what actually carries it: `grep -rn "Switch(" s19_app/
--include=*.py` → **1** hit (`crc_designer_view.py:467`).

**Impact.** Low today (2 Switches, 1 site) — but the sentence is load-bearing for why a
1-pair guard is a guard, and it names the wrong mechanism. Left as-is, a future batch adding a
`Switch` to a settings modal will believe it inherited coverage it does not have.

**Disposition.** One-line correction: either scope the claim ("*any `Switch` **on the CRC Designer
screen*** enters the set automatically; app-wide completeness rests on the single construction site
`crc_designer_view.py:467`, re-grepped per C-26"), or have AT-214 sweep the screens it cares about.

---

### N-5 — LLR-072-8.1's "`_recompute` consumes the tuple" is order-fragile, and AT-219 cannot detect it — **major**

**Claim.** The six ids are **not interchangeable**. `crc_designer_view.py:1116-1121` binds them to
six distinct locals, and the error path at `:1127-1135` writes **three different strings** to them
(`verdict/preview/coverage/window` ← `f"Invalid parameters: {exc}"`, `custom_result` ← `"—"`,
`warnings` ← `""`), then the success path at `:1136-1142` calls six *different* text producers. The
natural reading of "hoist the six ids into a module-level tuple; `_recompute` consumes it" is a
positional unpack — which makes correctness depend on tuple **order**, a property AT-219 does not
assert.

**Evidence.**
- `01-requirements.md:313` LLR-072-8.1 pass threshold: *"`len(tuple) >= 6`; `_recompute` behaviour
  unchanged"* — the second half has no owning test.
- `:290-292` AT-219 asserts only *"each resolved widget's `_render_markup is False`"* + *"the
  tuple's length `>= 6`"*. Reordering the tuple keeps both green while `_recompute` writes
  `"Invalid parameters: …"` into `#crc_warnings` and `""` into `#crc_kat_verdict`.
- `:293` claims *"a seventh surface added later is covered automatically"*. Under a positional
  unpack that is **false in the opposite direction** — a seventh entry raises `ValueError: too many
  values to unpack` at every keystroke on the UI thread.

**Impact.** The batch adds a guard whose stated benefit (extensibility) is negated by its stated
mechanism (consumption), on a method that runs on every `Input.Changed` / `Switch.Changed` /
`Select.Changed`. Verified the census itself has teeth: `Static("x")._render_markup` is `True` by
default and `False` only when `markup=False` is passed — so the flag assertion is not vacuous. The
defect is the hoist, not the census.

**Disposition.** Make LLR-072-8.1 prescribe the id→role binding explicitly (a dict comprehension
keyed by id, or six `query_one` calls whose ids are *read from* the tuple by name) and **forbid
positional unpacking** in the statement. Then either keep the "7th surface" claim (true under a
by-name binding) or drop it.

---

### N-6 — G-3's non-encoding rationale is a rationalisation; measured, G-3 is already FALSE — **major**

**Claim.** `01-requirements.md:397` justifies not encoding G-3 as: *"The guard bounds *excess* hero
extent; this batch reduces the hero-tile count from 2 to 1 (`#crc_live_verify` retired), so the
change strictly *decreases* the quantity G-3 bounds and cannot violate it."* G-3 (`HANDOFF-PLAN.md:122`)
has **two** clauses: *"the coverage window's rendered extent ≥ 6x any other single bright element on
the CRC screen (6:1 law); exactly one majority-bright tile."*

**Evidence — executed pilot at 120x30, `pilot.press("0")`, shipped tree** (extent proxied by
`region.area`; G-3 defines neither "extent" nor "bright", which is itself part of the problem):

```
#crc_hero_row          region=Region(x=24, y=10, width=92, height=10) area=920
#crc_coverage_window   region=Region(x=24, y=10, width=61, height=5)  area=305
#crc_top_right         region=Region(x=85, y=10, width=31, height=10) area=310
#crc_live_verify       region=Region(x=86, y=10, width=30, height=4)  area=120   <- retired by this batch
#crc_warnings_group    region=Region(x=86, y=15, width=30, height=4)  area=120   <- survives, IDENTICAL box
```

- **Ratio clause:** the largest "other" tile is `120` **before** (`#crc_live_verify`) and `120`
  **after** (`#crc_warnings_group`) — the two boxes are the same `30x4`. The batch changes the
  bounded quantity by **exactly zero**. And the shipped ratio is `305 : 120` = **2.54 : 1**, i.e.
  **G-3 is already violated on `main`**, which no artifact says.
- **Count clause:** 2 → 1 majority-bright tiles. This half of the argument *is* valid.

So "cannot violate it" happens to be true, but the reason given ("strictly decreases") is false, and
the far more relevant fact — the guard is RED pre-batch and this batch neither fixes nor worsens it
— is absent. Both `#crc_top_right` and `.crc-field-group` are `height: auto` (`styles.tcss:1997-2001`,
`.crc-hero { min-height: 3 }` at `:2005` applies only to the retired tile), so nothing grows into the
freed space; the "after" figure is a substitution, not a shrink.

**Impact.** Not a correctness risk — G-3 is correctly *not encoded* either way. It is a
premise-integrity defect: `§6.4` exists precisely to stop guards disappearing behind arguments, and
this row is an argument that does not hold.

**Disposition.** Restate the G-3 row the way G-2's was restated: *"FALSE on the shipped tree
(measured `305 : 120` = 2.54:1 at 120x30); this batch changes the ratio by zero (both competitor
tiles are `30x4`) and improves the count clause 2→1. **Carried to the backlog** with the
measurement."* One sentence, and it is then honest.

---

### N-7 — `PLAN.md` is stale in three places against revision 2 — **major**

`PLAN.md` is what Phase 3 executes from, and three of its lines still describe revision 1:

| `PLAN.md` | Says | Revision 2 says |
|---|---|---|
| `:28` Objective | *"…Warnings owns the hero right column, **Select height capped**"* | HLR-072-4 **WITHDRAWN** (`01-requirements.md:206`) |
| `:55` kickoff step 5 | *"AT-213..**218**, TC-510..519 reserved"* | **AT-213..219** (`:341`) |
| `:121-124` Test ledger | *"Base at prep: **2358**… deletions expected **0** unless `_switch_row` orphan-removal drops a TC"* | *"**base = 2379** … and **`D = 1`**"* (`:364`) |

The ledger row is the one that bites: §5.3.7 makes `post = base − D + A` a batch acceptance
criterion, and the two artifacts disagree on both operands. `PLAN.md:58-84` already carries the
correct narrative (it explains the withdrawal and quotes 2379), so this is pure section drift.

---

### N-8 — §1.2's scope line under-describes LLR-072-8.1 — **minor**

`:20` IN: *"`s19_app/tui/crc_designer_view.py` (**compose + a module-level id tuple**)"*. LLR-072-8.1
(`:313`) also edits **`_recompute`** — a method that is neither compose nor the tuple. Given N-5,
that edit is the risky part of the change and the scope line should name it.

### N-9 — §1.3's "focusable control" is defined but unused — **minor**

After the G-1 re-scope, no normative statement uses the term (`grep focusable` over the artifact →
`:35` the definition, `:184` a historical reference, `:382`/`:385` §6.3 prose). AT-214 clause 1
(`:196-197`) filters `region.area > 0` only. Either mark the definition as M-1 provenance or drop
it — a live definition nothing consumes reads as a leftover from the superseded scope.

### N-10 — AT-218 is labelled a regression pin; AT-219 has the same shape and is not — **minor**

`:272-275` labels AT-218 *"a REGRESSION PIN, not a gate"* with an explicit reason (its subject is
invariant under the change). AT-219's subject is invariant for at least 4 of its 6 sinks
(`#crc_custom_vector_result`, `#crc_json_preview`, `#crc_coverage_preview`, `#crc_coverage_window`
are untouched by this batch's compose edit). It does have real teeth on `#crc_kat_verdict`, which is
re-parented — so it is legitimately a gate. Worth one clause saying *which* of its subjects carries
the teeth, so a Phase-4 reader does not mistake breadth for strength.

---

### Axes checked and **clean** — stated explicitly

| Axis | Result | Evidence |
|---|---|---|
| **Increment cut (C-21) — orphans** | **None.** Every AT-213..219, every LLR (1.1, 1.2, 2.1-2.4, 5.1, 5.2, 6.1, 6.2, 7.1, 8.1) and every TC-510..519 has **exactly one** owning increment | `PLAN.md:86-93` cross-checked against `01-requirements.md:300-313` and `:324-332`. Inc-1 {5.1,5.2,7.1 / 216,218 / 515,516,519} · Inc-2 {6.1,6.2 / 217 / 517,518} · Inc-3 {1.1,1.2,2.1-2.4,8.1 / 213,215,219 / 510-513} · Inc-4 {214 / 514 / docs} |
| **`overflow-y` move vs `R-LEGEND-GEOMETRY-001`'s shipped guarantee** | **Not broken.** *"the opened modal fits within the terminal"* holds under `width: 96%` + `#legend_body { overflow: hidden }` | Executed all four runs: `screen.region.contains_region(dialog.region)` → `True`. At the floor `dialog=Region(x=3, width=74)` → right **77** ≤ screen **78**, and `test_at023e_c13_geometry_at_80_cols` (`test_tui_legend.py:278-293`) asserts `dlg.region.right <= app.size.width` (80) — satisfied with 3 cols of margin. `#legend_body.max_scroll_y == 0` in every run, so `overflow: hidden` clips nothing (floor budget 9 rows = card 4 + key 5, exact). §5.3.5 correctly requires the Before/After on that row's Code line |
| **The 9 `#legend_body` descendant sites** | **All survive** the wrapper change — every one is a descendant selector, none queries `#legend_body` as a leaf or asserts its scroll state | `test_tui_legend.py:60,338,407`; `test_legend_n8.py:284,387`; `test_legend_scope_and_logwidth.py:34,88,89,121` |
| **LLR-072-6.2's pinned `1fr/1fr` vs M-3** | Numbers are **internally consistent with M-3** and reproduce exactly — but only for the **key-first** tree. This is the tell that led to N-1 | `key h=4, card h=5, key.max_scroll_y 6 (mac) / 7 (map)` reproduced verbatim under `compose=key_first` and under `card_first + move_child` |
| **AT-213's CRC transition** | **Arithmetically correct** | `SEED_ALGORITHM.compute(b"123456789")` = `0xCBF43926`; `dataclasses.replace(SEED_ALGORITHM, refin=False).compute(...)` = `0x1898913F`. (The near-miss `refout=False` → `0x649C2FD3`, so the AT is driving the right toggle.) Not recorded in `00-measurements.md` — see A-5 |
| **AT-219's census is not vacuous** | Confirmed | `Static("x")._render_markup` → `True` (default); `Static("x", markup=False)._render_markup` → `False`. All six sinks currently pass `markup=False` in source (`crc_designer_view.py:341, 352-354, 367, 397, 403, 411`) |
| **§1.3 definitions used consistently** | 3 of 4 clean | *wide regime* → HLR-072-5 `:214`; *floor* → HLR-072-6 `:239`; *vertically abutting* → HLR-072-3 `:180` + AT-214 clause 3 `:198`. *focusable control* → **orphaned**, N-9. The *floor* definition (`screen.size == Size(78,22)`) and LLR-072-6.1's `app.size` read are **not** in conflict — 78 and 80 are both `< 120` |

---

## Q3 — Verdict

**`iterate` — the named gap is on the CERTAINTY axis.**

| Axis | Status |
|---|---|
| **Coverage** | ✅ All four blockers and all six majors from `02-review-architect.md` are dispositioned; §6.4 disposes all four design guards; §6.5 records every withdrawal Before/After; every AT/LLR/TC has an owning increment |
| **Evidence** | ⚠️ Strong but not complete. Every geometry number I spot-checked reproduces exactly. Two gaps: AT-213's CRC values are labelled "Measured" and are absent from `00-measurements.md` (A-5, values verified correct here), and §6.4's G-3 rationale asserts a quantity relation that measurement contradicts (**N-6**) |
| **Certainty** | ❌ **The gap.** HLR-072-6 clause 1 and LLR-072-5.1 are jointly unsatisfiable under the mechanism the batch owns (**N-1**), and the requirement's own pinned floor numbers come from a tree it does not specify. Compounding: LLR-072-6.2's CSS is ambiguous in a way that breaks the wide regime (**N-2**) and AT-216 cannot fail on that breakage (**N-3**) |

**Minimum to clear.** Three edits, all confined to §3/§4, and none needs a new measurement pass —
I executed all three outcomes above:

1. **N-1** — give LLR-072-6.1's hook the child-reorder responsibility (`move_child`, verified on
   8.2.8) and extend TC-517 to assert the resulting order, not only the class. Then LLR-072-6.2's
   `key h=4, card h=5` becomes true as written.
2. **N-2** — prefix LLR-072-6.2's two pane rules with `#legend_dialog.legend-narrow`.
3. **N-3** — add `#legend_body.region.contains_region(<pane>.region)` to AT-216.

N-4 through N-7 are one-sentence corrections (N-7 is a `PLAN.md` sync, and the ledger operands must
match §5.3.7 before Phase 4 reconciles them). N-5 needs a real decision about how `_recompute`
consumes the tuple — by name, not by position.

**What would change this verdict.** If LLR-072-5.1 is amended to compose **key-first** and HLR-072-5
is renegotiated to key-left / card-right at 120x30, N-1 evaporates without any runtime mechanism
(executed: `compose=key_first` gives `key x=6 w=42` / `card x=48 w=65` wide, and all three AT-217
clauses green at the floor). That is an operator-facing design change, not an architect's call — the
two-pane variant B mockup put the card on the left. I do **not** recommend it; the `move_child` route
preserves the operator's chosen visual and costs ~6 lines in the hook Inc-2 already owns.

**Explicitly not re-litigated.** The G-1 re-scope to `Switch`-only pairs, the HLR-072-4 withdrawal,
and the G-2 retirement were all settled on executed measurement. I found no counterexample and no
incompleteness in any of the three; my N-4 and N-6 findings are about *stated claims surrounding*
those decisions, not the decisions themselves.

---

## Integrity

```
$ git rev-parse --abbrev-ref HEAD ; git rev-parse --short HEAD
claude/batch-72-design-defect-634a67
0a56ef6
$ git status --porcelain
?? .dev-flow/2026-07-30-batch-72/02-regate-architect.md
```

All probes were throwaway scripts under the session scratchpad
(`probe_a2.py`, `probe_order2.py`, `probe_literal_6_2.py`, `probe_movechild.py`, `probe_g3.py`) and
a **copy** of `styles.tcss` written to the scratchpad; `s19_app/tui/styles.tcss` was never opened for
write. No repo file other than this review was created or modified.
