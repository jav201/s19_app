# batch-77 — Phase-1 QA lane: validation method + black-box acceptance design

**Batch:** `2026-08-01-batch-77` · **Branch:** `claude/batch-77-memmap-variant-a` @ `065bb95`
**Base:** `origin/main` @ `f8747b8` (code identical — Phase 0 commit is docs-only)
**Lane:** QA (the WHAT, observed through the shipped surface) · **Language:** English
**Controls applied:** C-10 · C-12 · C-16 · C-18 · C-22 · C-26 · C-28 · C-29 · C-31 · C-32 · C-34 · C-37 · C-40 · C-42 · C-43 · C-46
**Every verdict below was EXECUTED** against the pre-change tree. Transcripts are inline.
Probes were run with `PYTHONDONTWRITEBYTECODE=1` (C-46) and mutated nothing.

---

## BLUF

**Six blockers. Three stories cannot have an acceptance authored as they are currently worded —
not because the acceptance is hard, but because the stated outcome is unreachable, unsatisfiable,
or already true.**

| # | Sev | Story | Finding (all measured) |
|---|---|---|---|
| **B-1** | 🔴 **HIGH** | US-77-1 | **The story's outcome is unreachable at 120×30 by the fix as scoped.** `.map-band-bar` measures **21 columns** at 120×30 while `_BAND_BAR_WIDTH = 60` is budgeted. **2 of the 5 mapped regions are painted entirely OFF the bar and are invisible TODAY.** A predicate `total ≤ 60` is fully satisfiable while the operator still sees nothing. Fixing it collides head-on with a live PIN test that instructs its own deletion. **Needs an operator scope ruling before <AT-a>/<AT-c> can be finalised.** |
| **B-2** | 🔴 **HIGH** | US-77-2 | **The story is self-contradictory and its acceptance is unsatisfiable as worded.** "every ruler label names a mapped address" ∧ "labels at region starts **+ span end**" cannot both hold: `span_end` is **exclusive**. Measured `span_end = 0x07FFFF3E`, last mapped byte `0x07FFFF3D`. **Executed: 4 of 5 ticks name an unmapped address — not Phase-0's 3 of 5.** |
| **B-3** | 🔴 **HIGH** | US-77-5 | **All three proposed keys are already claimed.** `o`→`open_workarea`, `j`→`dump_a2l_json`, `k`→`show_legend`, every one `priority=False`. `o` and `j` are frozen into the `_PRE_BATCH_BINDINGS` literal guarded by **live `TC-011`**. Binding-resolution policy is undecided → the acceptance cannot state its own expected outcome. |
| **B-4** | 🟠 **MED** | US-77-4 | **Half the story is already true.** `k → "Legend"` is **already a `show=True` App binding rendered in the map screen's Footer today** (executed). Any acceptance worded "a footer hint points to the `k` LegendScreen" is **vacuous — C-40 limb 1**, exactly the charter-draft-#1 failure repeating one story over. |
| **B-5** | 🟠 **MED** | US-77-1 | **The proposed dense byte-golden fixture is itself vacuous unless its runs are UNEQUAL.** Executed: equal 512/512 runs → widths `[30, 30]` — invariant under *any* monotone re-weighting, so the golden cannot fail. Unequal 768/256 → `[45, 15]`, which moves. |
| **B-6** | 🟠 **MED** | US-77-5 | **"Focus a row" has no stated ENTRY mechanism.** Executed: `down`×3 and `tab` never move focus off `RailItem`; `RegionRow.can_focus == False` on all 5 rows; `RegionRow.BINDINGS == []`. `can_focus = True` alone does not give the operator a way *in*. **UNDECIDABLE** as specified (C-43). |

**Plus three Phase-0 premise corrections, all executed:**

- **P-7 is wrong in the count.** 3 of 5 → **4 of 5** ticks name an unmapped address under a membership oracle.
- **"Both regimes byte-identical, so a narrow-vs-wide split buys nothing here" is FALSE.** True at the *content* layer, false at the *painted* layer. Phase 0 read `render()` — a pre-layout proxy (**C-32**). The two regimes differ by **4 clipped segments**. The wide regime is the broken one.
- **P-4 needs re-pointing, not discarding.** Charter draft #1 ("every region ≥ 1 visible bar column") is vacuous **at the content layer** and **RED today at the painted layer**. It is not a wrong acceptance — it was read at the wrong layer. Constructive re-litigation per C-43: the disposition **enlarges** the requirement (keep it, re-point it, *and* add monotonicity), it does not delete it.

**AT/TC registry — the true next free (`AT-TC-REGISTRY.jsonl` line 1 `_meta`):**

```
"high_water": {"AT": 281, "TC": 612},  "next_free": {"AT": 282, "TC": 613}
```

**No ids are minted in this document.** Placeholders `<AT-a>…<AT-l>`, `<TC-a>…<TC-d>` are used
throughout; reservation is its own small PR merged to `main` **before** the work
(`docs/engineering-rules.md` §"AT/TC id allocation"). **12 AT + 4 TC** would be requested —
see §9 for the reservation request sheet.

---

## §1 · Executed baseline — the transcripts every predicate below is discharged against

Fixture re-derived (not copied): 5 regions at `0x00000000 / 0x01000000 / 0x02000000 /
0x04000000 / 0x07FFFF00`, sizes `256/256/256/200/62` B, alternating constant-`0xFF` /
seeded-pseudo-random. Driven through the shipped surface only:
`App.run_test(size=…)` → `action_show_screen("map")` → `update_memory_map()`.

### 1.1 Content layer (what Phase 0 measured — reproduces exactly)

```
SPARSE ranges=[(0, 256), (16777216, 16777472), (33554432, 33554688), (67108864, 67109064), (134217472, 134217534)]
  mapped=1030 span=[0x00000000,0x07ffff3e) = 134217534 B   _BAND_BAR_WIDTH=60

=== SPARSE size=(80, 24) ===            === SPARSE size=(120, 30) ===
  segs=9 BandSegment=5 gaps=4             segs=9 BandSegment=5 gaps=4
  RegionRow=5 focusable=0                 RegionRow=5 focusable=0
  app.focused=RailItem                    app.focused=RailItem
  run_cols = {0x00000000:1, 0x01000000:1, 0x02000000:1, 0x04000000:1, 0x07ffff00:1}
  gap_cols=59  TOTAL=64  budget=60        gap_cols=59  TOTAL=64  budget=60
  ticks=['00000000','01FFFFCF','03FFFF9F','05FFFF6E','07FFFF3E']
  legend_rows=4  .map-band-legend containers=1
  row_classes=[['band-constant','map-region-row'], ['band-medium','map-region-row'], …]
  #map_stats_body='Coverage: 0.00%  Bytes covered: 1030\nValid ranges: 5  Invalid ranges: 0\nGaps: 4  Largest gap: 67108408 bytes\nTotal issues: 0'
  #map_detail_body='Click a region to inspect it - double-click to open in hex.'
```

### 1.2 Painted layer — **the finding Phase 0 could not see** (C-32)

`region.width` clipped to `.map-band-bar.region`, per segment, role-labelled:

```
--- size=(80, 24): .map-band-bar x=[8,74) width=66  (_BAND_BAR_WIDTH=60) ---
    RUN 0x00000000   width=  1 x=[8,9)     visible
    gap              width=  7 x=[9,16)    visible
    RUN 0x01000000   width=  1 x=[16,17)   visible
    gap              width=  7 x=[17,24)   visible
    RUN 0x02000000   width=  1 x=[24,25)   visible
    gap              width= 15 x=[25,40)   visible
    RUN 0x04000000   width=  1 x=[40,41)   visible
    gap              width= 30 x=[41,71)   visible
    RUN 0x07FFFF00   width=  1 x=[71,72)   visible
    => 0 INVISIBLE, 0 truncated; MAPPED REGIONS entirely invisible = 0 of 5

--- size=(120, 30): .map-band-bar x=[26,47) width=21  (_BAND_BAR_WIDTH=60) ---
    RUN 0x00000000   width=  1 x=[26,27)   visible
    gap              width=  7 x=[27,34)   visible
    RUN 0x01000000   width=  1 x=[34,35)   visible
    gap              width=  7 x=[35,42)   visible
    RUN 0x02000000   width=  1 x=[42,43)   visible
    gap              width= 15 x=[43,58)   TRUNCATED 4/15
    RUN 0x04000000   width=  1 x=[58,59)   INVISIBLE
    gap              width= 30 x=[59,89)   INVISIBLE
    RUN 0x07FFFF00   width=  1 x=[89,90)   INVISIBLE
    => 3 INVISIBLE, 1 truncated; MAPPED REGIONS entirely invisible = 2 of 5
```

**Read this against Phase-0 §3.** Phase 0 concluded *"Both regimes are byte-identical — the
defect is width-independent, so a narrow-vs-wide split buys nothing here."* At the content
layer that is true and reproduces. At the painted layer it is **false**: at 120×30 the operator
cannot see regions `0x04000000` and `0x07FFFF00` **at all, today**, and the widest gap is gone
too. `_BAND_BAR_WIDTH = 60` vs a **21-column** container is a **39-column** disagreement, and
the container is the thing the operator looks at.

### 1.3 The container measurement, both fixtures, both regimes

```
  SPARSE (80, 24): .map-band-bar width = 66   #map_grid = 66   .map-ruler = 66   (_BAND_BAR_WIDTH = 60)
  SPARSE (120,30): .map-band-bar width = 21   #map_grid = 50   .map-ruler = 50
  DENSE  (80, 24): .map-band-bar width = 66   #map_grid = 66   .map-ruler = 66
  DENSE  (120,30): .map-band-bar width = 21   #map_grid = 50   .map-ruler = 50
```

The wide regime is *narrower* for the bar because the "At a glance" panel docks beside it
(`width-narrow` reflow, `test_at0xx_glance_reflow`). This is the C-29 two-axis trap in its
purest form: the constant was proven against a 66-column container and is applied unchanged
inside a 21-column one.

### 1.4 The keybinding namespace, and the mechanism absence

```
### (2) US-77-5 keybinding namespace — App-level claims TODAY
  'j' -> ('dump_a2l_json', 'show=False', 'priority=False')
  'k' -> ('show_legend',   'show=True',  'priority=False')
  'o' -> ('open_workarea', 'show=False', 'priority=False')

### (4) C-16 — does a real arrow key reach a RegionRow today?
  focus trace = [('start','RailItem'), ('down','RailItem'), ('down','RailItem'),
                 ('tab','RailItem'), ('down','RailItem')]
  RegionRow.can_focus per row = [False, False, False, False, False]
  RegionRow.BINDINGS = []

map-screen footer show=True bindings:
  {'ctrl+k':'Palette','ctrl+d':'Density','ctrl+l':'Load','ctrl+s':'Save','slash':'Find',
   'g':'Go-to','q':'Quit','x':'Operations','k':'Legend','question_mark':'Help',
   'plus':'Page+','minus':'Page-','comma':'Hex-','period':'Hex+'}
Footer region w,h = 78 1
US-77-4 'footer hint points to k LegendScreen' ALREADY TRUE?  True
```

### 1.5 Which render layer holds which fact (C-32 / C-37, executed — not reasoned)

`RegionRow`, at 120×30:

```
{'classes': ('band-constant','map-region-row'), 'background': 'Color(0, 0, 0, a=0)',
 'color': 'Color(107, 114, 128)', 'text_style': 'none', 'region': (50, 1), 'spans': []}
{'classes': ('band-medium','map-region-row'),   'background': 'Color(0, 0, 0, a=0)',
 'color': 'Color(217, 163, 91)', 'text_style': 'none', 'region': (50, 1), 'spans': []}
```

| Fact | Holding layer, **measured** | Do **not** read |
|---|---|---|
| segment / row **geometry** | `widget.region` (`.width`, `.x`, clipped against `bar.region`) | `len(str(widget.render()))` — the pre-layout proxy that hides all clipping |
| band / selection **colour** on a `RegionRow` | **`widget.styles.color` / `.background` / `.text_style`** — the resolved CSS. Executed: `color` **differs per band** (`107,114,128` vs `217,163,91`), `background` is transparent on every row, so a selection style that paints a background produces a clean measurable delta | `render().spans` — **executed as `[]`** on these rows (they are plain `Text`, no inline markup), so C-37's span route is **inapplicable here**; `render_line` returns the base theme colour |
| stats / inspector **text** | `#map_stats_body` / `#map_detail_body` | `#map_stats` / `#map_detail` — **containers**, they render `Blank` (Phase-0 §4) |
| footer chip set | `app.active_bindings` filtered on `.show and .enabled` | a substring grep of the Footer render (C-42 mechanic 4) |

---

## §2 · Validation method per requirement

`demo` is **never** used for acceptance — it is perceptual and unfalsifiable. Where a
mechanism cannot yet be verified it is marked `assumed — verify in target framework at Phase 3`
(C-16), and the *outcome* still gets a `test (pilot)` method.

| Story | Deliverable observed | Method | Node kind | Notes |
|---|---|---|---|---|
| US-77-1 widths | region bar widths order with mapped size | **test (pilot)** | `<AT-a>` | painted layer, both sizes |
| US-77-1 no-op control | dense image renders unchanged | **test (pilot) + byte-golden** | `<AT-b>` + `<TC-a>` | C-12: golden captured from the shipped producer in its **own prior commit** |
| US-77-1 budget (P-15) | bar fits what the operator sees | **test (pilot)** | `<AT-c>` | **blocked on B-1** — two candidate subjects |
| US-77-1 fold marker | gap marker width is bounded and fixed | **test (pilot)** | `<TC-b>` | white-box companion to `<AT-a>` |
| US-77-1 invariant | fold markers are not `RegionRow`s | **test (pilot)** — *regression PIN, not a gate* | existing `test_ac6_band_segments_do_not_widen_region_row_queries` | C-40 corollary: invariant under the change → label it a PIN |
| US-77-2 ruler | every tick label is admissible | **test (pilot)** | `<AT-d>` | **blocked on B-2**; re-derives live `AT-072b` |
| US-77-3 stats | dual mapped/span readout + humanized gap | **test (pilot)** | `<AT-e>` | |
| US-77-3 empty state | no-file strip stays neutral | **test (pilot)** | `<TC-d>` | re-derivation of `test_tc041_9`, which goes **vacuous** after the change |
| US-77-4 legend | legend block absent from the map body | **test (pilot)** | `<AT-f>` | the footer half is **B-4 / vacuous** — see §3.6 |
| US-77-4 non-regression | `k` LegendScreen unaffected | **test (pilot)** — *regression PIN* | `<AT-f>` second node, or reuse existing | |
| US-77-5 keyboard | real keys move focus and act | **test (pilot), real `pilot.press` only** | `<AT-g>` | **mechanism `assumed — verify in target framework at Phase 3` (C-16)**; **never `.focus()`** |
| US-77-5 non-regression | `o`/`j`/`k` still do their App jobs when no row is focused | **test (pilot)** | `<AT-h>` | **blocked on B-3**; this is the *discriminating negative* |
| US-77-5 mouse | N4a single=inspect / double=hex preserved | **test (pilot)** — *regression PIN* | `<AT-i>` | |
| US-77-5 discoverability | the new keys are reachable/announced | **test (pilot)** + **analysis** for footer capacity | `<AT-l>` | analysis: the footer already renders **14** chips in **78** columns at 80×24 (C-13/C-29) |
| US-77-6 auto-select | inspector populated with zero clicks | **test (pilot)** | `<AT-j>` | |
| US-77-7 selection | selected row visually distinguishable | **test (pilot)** | `<AT-k>` | reads the resolved-CSS layer per §1.5 |
| Cross-cutting | dangling `LLR-072.3` citation corrected | **inspection** | — | `tests/test_tui_map_big.py:118`; not a runtime property |
| Cross-cutting | snapshot drift is as predicted | **test (snapshot)** | — | §7, per-cell |

---

## §3 · Acceptance design, with the C-40 discharge executed for every predicate

**Reading key.** *Declared subject* = what the predicate says it certifies (C-40 limb 1).
*Quantified set* = where the "every/all" comes from (C-40 limb 2 — must come from the RULE).
*Discharge* = the executed verdict on the **pre-change** tree plus the named mutation.

---

### 3.1 `<AT-a>` — US-77-1 · bar widths order with mapped size, **and every region is visible**

> **Given** the sparse 5-region fixture (`256/256/256/200/62` B over a 128 MiB span)
> **When** the map screen renders at 80×24 **and** at 120×30
> **Then** for every ordered pair of mapped regions `a, b` drawn from the fixture's own
> ranges, `bytes(a) > bytes(b) ⇒ visible_cols(a) ≥ visible_cols(b)`; **at least one** such
> pair is a **strict** inequality; **and** `visible_cols(r) ≥ 1` for every mapped region `r`.

`visible_cols(seg) = max(0, min(seg.region.right, bar.region.right) − max(seg.region.x, bar.region.x))`
— the painted, clipped width, exactly as computed in §1.2. **Not** `len(str(seg.render()))`.

**Completeness guard (C-31, mandatory).** Before evaluating the universal, assert
`{s.region_start for s in query(BandSegment)} == {start for start, _end in loaded.ranges}`.
Without it, a fold implementation that *drops* a region shrinks the quantified set and the
monotonicity clause passes vacuously over the survivors. The set comes from the **fixture's
ranges** (the rule), never from what the renderer emitted.

| C-40 limb | Discharge |
|---|---|
| 1 — declared subject in the expression | Subject = *the width the operator sees for each mapped region.* `visible_cols` is a function of `BandSegment.region` clipped to `bar.region` — both are the subject. ✅ |
| 2 — quantified set from the RULE | Pairs enumerated over `loaded.ranges` (the fixture), gated by the completeness guard above. ✅ |

**Executed on the pre-change tree:**

```
[charter#1  every region >=1 col (CONTENT layer) ] -> True   GREEN (VACUOUS)
[AT-a  monotone=True  strict=False]              -> RED  (conjunction is the gate)   @ (80,24)
[AT-a  monotone=True  strict=False]              -> RED  (conjunction is the gate)   @ (120,30)
painted layer, (120,30): MAPPED REGIONS entirely invisible = 2 of 5  ->  RED
painted layer, (80,24) : MAPPED REGIONS entirely invisible = 0 of 5  ->  GREEN
```

**Three things this transcript settles.**

1. **The charter's draft #1 is vacuous at the content layer and RED at the painted layer.** It
   is not a wrong acceptance — it was read at the wrong layer. **Keep it, re-point it.** This is
   the constructive re-litigation C-43 requires: the requirement comes out **larger**, not smaller.
   *This amends Phase-0 decision D-3 from "replace" to "re-point and enlarge".*
2. **The monotonicity limb ALONE is GREEN today** (`monotone=True`, trivially, because all five
   widths are equal). It is **vacuous on its own**. All the falsifying power is in the **strict**
   limb. Do not let the conjunction be split across two nodes, and do not let a later
   "simplification" drop the strict clause.
3. **`visible_cols ≥ 1` and the strict clause fail at different sizes.** `visible_cols ≥ 1` is
   GREEN at 80×24 and RED at 120×30; the strict clause is RED at both. Parametrising over both
   sizes is load-bearing, **not** boilerplate — a single-size AT at 80×24 would ship B-1 green.

**Mutation that reddens it (name + expected):** in `_build_band_widgets`, restore
`seg_width = max(1, round(_BAND_BAR_WIDTH * run_bytes / total_span))` — i.e. substitute the new
denominator back to `total_span`. Record the **substituted VALUE**, not "drop the fold". Expected:
`strict` → `False` at both sizes.

**Feasibility (C-29, both axes, measured).** At 120×30 the bar is **21** columns. Four fold
markers at 1–2 columns consume 4–8, leaving **13–17** for 1030 mapped bytes → `256 B ≈ 3 cols`,
`200 B ≈ 2–3`, `62 B ≈ 1`. Monotone with ≥1 strict inequality **is** achievable at 21 columns.
The acceptance is not physically impossible — **but only if the implementation budgets against
the container**, which is exactly B-1.

> 🔴 **B-1 BLOCKS the final wording of the `visible_cols ≥ 1` clause.** If the operator rules
> that US-77-1 budgets against `_BAND_BAR_WIDTH` and leaves the container disagreement alone,
> then `visible_cols ≥ 1` **cannot be satisfied at 120×30** and must be relaxed to the 80×24
> regime — which means the story's own promise ("the operator sees each region's bar width
> order with its mapped size") is not delivered in the wide regime. **I will not author an
> acceptance that is physically unachievable (C-29), and I will not silently relax the one
> clause that carries the operator's outcome.** This goes back to the operator.

---

### 3.2 `<AT-b>` + `<TC-a>` — US-77-1 · the dense no-gap byte-golden control (C-12)

The charter's draft #2 is **the strongest thing in the drafted set** and is kept. It is also
where B-5 lives.

**`<TC-a>` — capture, in its own commit, BEFORE any production change.**

1. Add `<TC-a>` as a **test-only commit on the branch, ahead of every US-77-1 edit** (PLAN §4
   Inc-0). It drives the **shipped** producer — `App.run_test` → `action_show_screen("map")` →
   `update_memory_map()` — over the dense fixture at both sizes.
2. It writes the observed payload to an on-disk golden under
   `tests/_artifacts/` (the existing convention; **`.gitattributes` `-text`** if any byte-exact
   file is stored — `reference_evidence_bytes_need_gitattributes_text`).
3. **`<AT-b>` re-reads that file from disk** and compares it to a fresh live render (C-12:
   producer → on-disk artifact → unmodified consumer). No shim across the seam.

**Golden payload = a list of `(sorted(classes), rendered_text)` per `.map-band-seg`.** Classes
are included so a band-token regression (`band-medium` → `band-low`) reddens it; text is
included so a width or glyph regression reddens it.

**B-5 — executed proof that the obvious fixture is vacuous:**

```
### (1) DENSE byte-golden fixture — is it discriminating?
  EQUAL 512/512      (80, 24): widths=[30, 30] TOTAL=60 budget=60
  EQUAL 512/512      (120,30): widths=[30, 30] TOTAL=60 budget=60
  UNEQUAL 768/256    (80, 24): widths=[45, 15] TOTAL=60 budget=60
  UNEQUAL 768/256    (120,30): widths=[45, 15] TOTAL=60 budget=60

  UNEQUAL golden payload =
    [(('band-constant','map-band-seg'), '·············································'),   # 45
     (('band-medium',  'map-band-seg'), '▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒')]                                  # 15
```

Two equal-size runs render `[30, 30]` under **any** proportional or monotone scheme — the
golden is invariant under the redistribution it exists to detect. This is the catalog's
palindrome-fixture pattern with a different mask. **The dense fixture MUST use unequal runs**
(768/256 measured above). *Cut cases only with a justification: none applies here.*

| C-40 limb | Discharge |
|---|---|
| 1 | Subject = *the dense-image band strip is unchanged.* The predicate compares the strip's own classes+text before and after. ✅ |
| 2 | Set = every `.map-band-seg` in the dense render, derived from the query, ordered by mount order. ✅ |

**Discharge, honestly stated:** `<AT-b>` is **GREEN on the pre-change tree by construction** —
that is its purpose. It is a **no-op control**, and per C-40's corollary it is a **regression
PIN, not a gate**, and is labelled so. Its falsifiability is discharged the other way: after
Inc-1 lands, **substitute the new fold denominator into the dense path** (a 1-token change) and
confirm `<AT-b>` goes RED. **That mutation must be executed and its transcript pasted at the
Inc-1 gate — a golden never mutation-tested is a file, not a control.**

---

### 3.3 `<AT-c>` — US-77-1 / P-15 · the bar fits its budget

Two candidate subjects. They are **not** equivalent and the choice is B-1.

| Option | Predicate | Executed today | Verdict |
|---|---|---|---|
| **C-1 constant** | `Σ len(str(seg.render())) ≤ _BAND_BAR_WIDTH` | `64 ≤ 60` → **RED** (both sizes) | ✅ falsifiable ⚠️ **certifies a constant, not the operator's view.** Satisfiable at 60 while 2 of 5 regions stay invisible at 120×30 |
| **C-2 container** | every `.map-band-seg` satisfies `bar.region.contains_region(seg.region)` | 80×24 → **GREEN** (0 outside) · 120×30 → **RED** (4 not contained) | ✅ falsifiable ✅ **certifies what the operator sees** ❌ **collides with a live PIN test** |

**The collision, verbatim from the live test's own docstring**
(`tests/test_map_click_chain.py::test_ac6_clipped_segments_are_a_known_layout_limitation`):

```python
assert bar_width < _BAND_BAR_WIDTH, (
    "... If the constant and the container were reconciled, DELETE this test — "
    "it exists only to pin the disagreement.")
assert outside_count > 0, (
    "... The clipping this test pins is gone; delete it and drop the limitation "
    "note from the two AC-6 pointer tests.")
```

That test is **live and passing today** (`16 passed in 20.99s`, §6). Option **C-2 makes it RED**,
and the correct disposition is a **deliberate deletion** plus removal of the limitation note
from two sibling tests — a documented geometry-purity decision that batch-67 explicitly deferred
to the operator. Option **C-1 leaves it green** and leaves the operator's actual problem unfixed.

> 🔴 **B-1: I recommend C-2, and I cannot author it unilaterally.** C-1 is the predicate that
> passes while the story fails — the exact "correct, exact, complete, and never mentions the
> thing under test" shape C-40 was written for. But C-2 expands US-77-1's blast radius into a
> deferred design decision and deletes a test another batch deliberately wrote. **Operator ruling
> required.** A third path exists and should be on the option table: **ship C-1 as the gate and
> register the container reconciliation as a carry**, with `<AT-c>` explicitly documenting that
> it certifies the constant only. That is honest, and it is worse for the operator.

---

### 3.4 `<AT-d>` — US-77-2 · every ruler label is admissible (and the `AT-072b` re-derivation)

**B-2, executed.** With the tick set read from the live tree and the membership oracle taken
from the **independent** `range_index` engine (the same oracle `AT-073` uses — never the map's
own arithmetic):

```
[AT-b  strict 'address_in_sorted_ranges' oracle] unmapped ticks = 4/5
   [('00000000', True), ('01FFFFCF', False), ('03FFFF9F', False),
    ('05FFFF6E', False), ('07FFFF3E', False)]
[span_end 07FFFF3E in ranges? False]   last mapped byte = 07FFFF3D
[ticks ⊆ region-starts        ] -> RED
[ticks ⊆ starts ∪ {span_end}  ] -> RED
[AT-072b  len(ticks) == 5     ] -> GREEN   (the live shipped assertion)
```

**`span_end` is EXCLUSIVE.** `0x07FFFF3E` is one past the last mapped byte. So:

- Phase-0 **P-7 is wrong**: 4 of 5, not 3 of 5.
- The charter's draft acceptance **#3 ("No ruler label names an unmapped address") is
  UNSATISFIABLE** while the story simultaneously mandates a span-end tick. The story and its
  acceptance contradict each other. This is not a wording nit — it decides whether the last
  tick reads `07FFFF3E` (the exclusive bound, matching the shipped `AT-072b` contract and
  `derive_image_span`) or `07FFFF3D` (the last mapped byte, matching the story's promise).

**The acceptance I can author once B-2 is decided** — worded against an **admissible-label set**,
not against "mapped":

> **Given** the sparse fixture
> **When** the map renders at both sizes
> **Then** `{tick labels} ⊆ ADMISSIBLE`, where
> `ADMISSIBLE = {f"{s:08X}" for s, _e in loaded.ranges} ∪ {END_LABEL}` and `END_LABEL` is the
> single, explicitly-decided span-end spelling; **and** `{tick labels} ⊇ {f"{s:08X}" for the
> first and last region start}` (a non-empty lower bound, so an implementation that renders
> **zero** ticks cannot pass a subset-only predicate).

**The `⊇` clause is not optional.** A pure `⊆` predicate is GREEN on an empty tick set — the
"absence assertion is green on a widget that painted nothing" trap named in C-32. Executed
confirmation of the hazard: `set() <= admissible` is `True` in Python.

| C-40 limb | Discharge |
|---|---|
| 1 | Subject = *the tick labels the ruler renders.* Both clauses quantify over the live `.map-ruler-tick` query. ✅ |
| 2 | `ADMISSIBLE` derived from `loaded.ranges` + one declared constant — **from the rule**, never from what `MapRuler.compose` currently emits. ✅ |

**C-31 — how "mapped" is enumerated, since you asked explicitly.** *It is not.* Deriving a
"mapped address set" by enumeration is a 128 MiB membership problem and the wrong shape. Two
independent, guarded sources instead: (a) the **admissible-label set** is `loaded.ranges` — the
loader's own range list, an interval set, not a hand list; (b) where membership genuinely must
be tested, use `build_sorted_range_index(loaded.ranges)` + `address_in_sorted_ranges` — the
**frozen** `range_index` engine, i.e. an oracle outside the code under test (reader-as-oracle).
The completeness guard on (a) is `len(ADMISSIBLE) == len(loaded.ranges) + 1` — it fails loudly
if two region starts collide into one label.

**Re-derived `AT-072b` (`tests/test_tui_map_big.py::test_at072b_ruler`).**

| | Before (live, passing) | After (re-derived) |
|---|---|---|
| Cardinality | `len(ticks) == 5` — an **exact count fixed by `_TICK_COUNT`** | **`1 ≤ len(ticks) ≤ _TICK_COUNT_MAX`** and `len(ticks) == len(set(ticks))` (overlap collapse is *the feature*, so duplicate labels are the defect) |
| Endpoints | `ticks[0] == span_start`, `ticks[-1] == span_end` | `ticks[0] == f"{min(region starts):08X}"`; `ticks[-1] == END_LABEL` (B-2's decision) |
| **New invariant** | — | **`ticks` is strictly ascending as integers**, and `{ticks} ⊆ ADMISSIBLE` |

**Why strict ascent is the right replacement invariant:** it is what "5 evenly-spaced ticks"
was really protecting (a ruler is monotone), it survives overlap collapse, and it is
**falsifiable** — a collapse implementation that emits a duplicate or an out-of-order label
reddens it, whereas `len(ticks) == 5` would go red on the *correct* new behaviour and green on
a broken collapse that happened to emit 5.

**`R-TUI-072` needs a §6.5 Before/After amendment** (Phase-0 P-6). The dangling `LLR-072.3`
citation at `tests/test_tui_map_big.py:118` and in `MapRuler`'s docstring (`:1239`, `:1273`,
`:1300`) is corrected in the same edit — **four sites, not one**.

---

### 3.5 `<AT-e>` / `<TC-d>` — US-77-3 · stats

> **Given** the sparse fixture (mapped `1030 B`, span `128.0 MiB`, true coverage `0.000767 %`)
> **When** the map renders
> **Then** `#map_stats_body` contains a **dual** readout naming both the mapped total and the
> span total in humanized form, a coverage figure that is **not** `0.00%`, and a largest-gap
> figure rendered by `human_bytes` and **not** as a raw byte count.

**Executed today:**

```
#map_stats_body = 'Coverage: 0.00%  Bytes covered: 1030\nValid ranges: 5  Invalid ranges: 0\n
                   Gaps: 4  Largest gap: 67108408 bytes\nTotal issues: 0'
[AT-e  dual mapped/span readout] -> RED;  raw-byte gap present = True
```

**C-42 discipline — assert the EMITTED form.** Do **not** predicate on `"1.0 KiB"` guessed by
hand. `human_bytes` is the producer; write the expected strings as
`human_bytes(1030)` and `human_bytes(span_end - span_start)` **computed in the test from the
fixture**, and assert those exact substrings. Executed producer output must be pasted into the
Inc-3 gate before the predicate is trusted. Symmetrically, assert the **discriminating
negatives**: `"Largest gap: 67108408 bytes"` is **absent**, and `"Coverage: 0.00%"` is absent.

**Boundary + invalid cases (coverage default):**

| Case | Input | Expected |
|---|---|---|
| empty | no file loaded | strip neutral, **no crash, no divide-by-zero** — `<TC-d>` |
| boundary — single full range | one range, 0 gaps | coverage `100.00%`, `Gaps: 0`, largest gap `0` (guard the `human_bytes(0)` spelling — assert `human_bytes(0)`, not `"0 B"`) |
| boundary — sub-0.01 % coverage | the sparse fixture | the readout must **not** flatten to `0.00%`; this is the defect |
| boundary — 1-byte image | one range of 1 B | no `ZeroDivisionError`; `human_bytes(1)` |

> ⚠️ **`test_tc041_9_empty_state_stats_neutral_no_exception` goes VACUOUS after this change.**
> Its whole runtime assertion is `assert "Coverage:" not in strip`. Once `build_stats_text` no
> longer emits the word "Coverage:" **anywhere**, that assertion can never fail — it is a check
> that passes on correct code, on broken code, and on no code. **`<TC-d>` re-derives it** to
> assert the *new* strip's neutral form positively (and that the new mapped/span tokens are
> absent). Not doing so leaves a vacuous check on `main`, which is precisely how batch-76
> accumulated 14 of them.

---

### 3.6 `<AT-f>` — US-77-4 · legend demotion

> **Given** any loaded image
> **When** the map renders
> **Then** `len(query(".map-legend-row")) == 0` **and** `len(query(".map-band-legend")) == 0`
> **and** pressing `k` still pushes `LegendScreen`, whose own body still lists all four band
> labels.

**Executed today:** `legend_rows = 4`, `.map-band-legend containers = 1` → **RED**. ✅

| C-40 limb | Discharge |
|---|---|
| 1 | Subject = *the legend block is not in the map body.* Both queries name the block. ✅ |
| 2 | Band-label completeness inside `LegendScreen` derived from `ENTROPY_BAND_LABELS`, **not** hand-listed as `("constant/padding","low","medium","high/random")` — which is exactly what the live `test_at075` does today, and is a C-31 hand-listed domain. ✅ |

> 🟠 **B-4 — do NOT write "a footer hint points to the `k` LegendScreen".** Executed:
> `k → "Legend"` is **already** a `show=True` App binding present in the map screen's footer
> chip set today. That clause is **GREEN on the pre-change tree** — vacuous, C-40 limb 1, and
> the same failure as charter draft #1 one story over. Either (a) drop the clause and let the
> existing footer chip satisfy the discoverability need (my recommendation — it costs nothing
> and adds no C-28 drift), or (b) if a *new in-body* hint widget is genuinely wanted, the
> acceptance must name **that widget** and assert its presence and its text, not the footer.

**Blast radius:** `test_at075_e_key_opens_no_modal_map_has_legend`
(`tests/test_tui_directionb.py:4574`) asserts all four band names appear in
`query(".map-legend-row")`. This story makes it **RED**. Its *first* purpose — "pressing `e`
opens no modal" — is unrelated and must be **preserved by porting the assertion**, never by
deleting the test wholesale (catalog §5: *never delete a test in the same increment that
changes the behavior it guards; port the assertions first*).

---

### 3.7 `<AT-g>` / `<AT-h>` / `<AT-i>` / `<AT-l>` — US-77-5 · the keyboard path

**`<AT-g>` — the golden path, real keys only.**

> **Given** the sparse fixture, map screen shown, **no prior `.focus()` call**
> **When** the operator presses the documented **entry key**, then `down`, then `j`, then
> `up`, then `k`, then `Enter`, then `o` — **all through `await pilot.press(...)`**
> **Then** after the entry key `isinstance(app.focused, RegionRow)` is `True`; after
> `down`/`j` the focused row's `region_start` has advanced to the next region **in rendered
> order derived from the tree**; after `up`/`k` it has moved back; `Enter` populates
> `#map_detail_body` with that region's start address; `o` posts exactly one
> `MemoryMapPanel.OpenInHexRequested` at that region's start.

**C-16 is mandatory and non-negotiable here.** Executed on the pre-change tree:

```
focus trace = [('start','RailItem'), ('down','RailItem'), ('down','RailItem'),
               ('tab','RailItem'), ('down','RailItem')]
RegionRow.can_focus per row = [False, False, False, False, False]
RegionRow.BINDINGS = []
```

Textual moves focus **nowhere near** the map on `down` **or on `tab`**. The AT must
**press real keys** and must **never** call `.focus()` — batch-27 shipped exactly that gap
GREEN. The mechanism (`can_focus` + widget `BINDINGS` + an entry action) is marked
**`assumed — verify in target framework at Phase 3`**.

> 🟠 **B-6 — the story does not say how the operator GETS focus.** `tab` does not reach the
> map (measured). `can_focus = True` alone is not an entry path. The story is **UNDECIDABLE**
> until an entry mechanism is named (a screen-scoped binding? auto-focus on `render_ranges`,
> which US-77-6 already implies? the rail's `tab` chain extended?). **I will not fabricate an
> expected outcome** — `<AT-g>`'s first Given/When cannot be written without it.

**`<AT-h>` — the discriminating negative, and B-3's gate.**

> **Given** the map screen, **focus NOT on a `RegionRow`** (the pre-existing state)
> **When** the operator presses `k`, then `j`, then `o`
> **Then** `k` pushes `LegendScreen`, `j` invokes `dump_a2l_json`, `o` invokes
> `open_workarea` — **exactly as they do today** — and none of them moves the map selection.

**This is the single most important node in US-77-5.** Executed App-binding census:
`o`→`open_workarea`, `j`→`dump_a2l_json`, `k`→`show_legend`, all `priority=False`. Textual
resolves a focused widget's `BINDINGS` **ahead of** a non-priority App binding, so the design is
*mechanically feasible* — but "feasible" is not "specified", and the two directions must both
be asserted or the batch ships a silent global-keybinding regression.

`o` and `j` are additionally frozen into `_PRE_BATCH_BINDINGS`
(`tests/test_tui_directionb.py:5463,5466`), guarded by live
`test_tc011_every_pre_batch_action_keeps_a_keyboard_path`. **If US-77-5 rebinds them at the App
level, TC-011 goes RED and a deliberate supersession record is owed.** If it binds them only on
the focused widget, TC-011 stays green — and `<AT-h>` becomes the *only* thing standing between
the batch and a shadowing regression.

> 🔴 **B-3 — the binding-resolution policy is undecided, so `<AT-h>`'s "Then" cannot be
> finalised.** Operator ruling required: widget-scoped shadowing (TC-011 survives) vs App-level
> rebinding (TC-011 needs a supersession amendment). Recommendation: **widget-scoped**, and
> reconsider `j`/`k` entirely — `up`/`down` alone are unambiguous and vi-keys here buy a
> three-way collision.

**`<AT-i>` — N4a mouse split preserved.** *Regression PIN, not a gate* (C-40 corollary): it is
invariant under US-77-5's change **by design**, which is the point. Real `pilot.click` /
`pilot.double_click` on a scrolled-into-view row; single ⇒ `#map_detail_body` populated **and
zero** `OpenInHexRequested`; double ⇒ **exactly one**. Labelled PIN in the ledger. Note the
existing `test_map_click_chain.py` nodes already cover this — **check for duplication before
minting `<AT-i>`; a reused existing node is better than a new one** (C-18 asks for exactly one
node per AT, not for a new file).

**`<AT-l>` — discoverability.** Assert against `app.active_bindings` filtered on
`.show and .enabled` (the layer that *holds* the fact — never a Footer substring grep, C-42
mechanic 4), plus the `?` help-panel content.

> ⚠️ **C-13/C-29 analysis, measured:** the map footer already renders **14** chips into a
> **78**-column Footer at 80×24. Adding `show=True` bindings risks truncating existing chips —
> and a truncated chip is a *silent* loss. If any `show=True` binding is added, `<AT-l>` must
> also assert that the **pre-existing** `_GLOBAL_FOOTER_KEYS` set is still fully rendered at
> 80×24, not merely present in `active_bindings`.

---

### 3.8 `<AT-j>` — US-77-6 · auto-select, zero clicks

> **Given** a loaded file **When** the map screen renders — **with no click, no key press, no
> message posted by the test** **Then** `#map_detail_body` contains `0x{first_region_start:08X}`
> and does **not** contain the neutral hint.

**Executed today:** `#map_detail_body = 'Click a region to inspect it - double-click to open in hex.'` → **RED**. ✅

**C-10 note.** "First region" is the *default*. A green AT on the default alone would verify the
default, not the wiring. So `<AT-j>` carries a second arm: after the operator moves the
selection to a **non-first** region, a **re-render** (`update_memory_map()`) must return the
inspector to a **defined** state — and the spec must say which (reset-to-first, or preserve).
Currently unstated. **Flagged: `<AT-j>` arm 2 blocked on that decision.**

Additional case: **auto-select must not fire when no file is loaded** (`test_tc025` guards the
`EmptyStatePanel`); assert the hint/empty state is preserved there — the discriminating negative.

---

### 3.9 `<AT-k>` — US-77-7 · selection is visually distinguishable

> **Given** a loaded file with ≥ 2 regions **When** exactly one row is selected
> **Then** the selected row's **resolved style triple** `(styles.background, styles.color,
> styles.text_style)` differs from that of **every** unselected row, and **exactly one** row
> carries the selection marker class.

**Written mechanism-agnostically on purpose.** Reading only `"…-selected" in row.classes` binds
the acceptance to one implementation choice and certifies a *class*, not *distinguishability*.
The style triple certifies the outcome regardless of whether the implementer reaches for
`background`, `color`, or `text-style`.

**Which layer holds the fact (§1.5, executed):** `widget.styles.*` — the resolved CSS.
`render().spans` is **`[]`** on these rows (measured) so C-37's span route does not apply;
`render_line` returns the base theme colour (C-37). `background` is currently
`Color(0,0,0,a=0)` on every row and `color` already differs per band — so the predicate must
compare the **triple**, and must compare **selected vs unselected**, never against a hex literal.

**Executed today:** `[AT-k  a selection marker class exists] -> RED  markers=[]`;
`row_classes = [['band-constant','map-region-row'], ['band-medium','map-region-row'], …]` — band
+ base only. ✅

| C-40 limb | Discharge |
|---|---|
| 1 | Subject = *the selected row looks different from the others.* The predicate compares the selected row's painted style against every other row's. ✅ |
| 2 | The "every unselected row" set is `query(RegionRow)` minus the selected one — derived from the tree, with the **exactly-one** cardinality clause as the completeness guard. ✅ |

**Mutation that reddens it:** remove the selection class assignment (record the substituted
value: `classes=f"map-region-row {token} {SELECTED}"` → `classes=f"map-region-row {token}"`) →
all triples equal → RED. Must be executed at the Inc-4 gate.

**Boundary:** a single-region image — "exactly one selected, zero unselected" makes the
"differs from every unselected row" clause **vacuously true**. The AT's fixture must have ≥ 2
regions, and that requirement must be asserted in the test body (`assert len(rows) >= 2`), not
assumed from the fixture's name.

---

## §4 · Coverage default — what is covered, and what is cut with a reason

| Case class | Covered by | Notes |
|---|---|---|
| golden path | `<AT-a>` `<AT-d>` `<AT-e>` `<AT-f>` `<AT-g>` `<AT-j>` `<AT-k>` | one per story |
| alternative valid path | `<AT-b>` (dense/no-gap) · `<AT-i>` (mouse vs keyboard) | |
| empty / null / zero input | `<TC-d>` (no file) · `<AT-j>` negative (no file ⇒ no auto-select) | |
| boundary | `<AT-a>` @ **21-column** container · `<AT-c>` at exactly 60 · single-range 100 % coverage · `human_bytes(0)` · 1-byte image · single-region `<AT-k>` | the 21-column regime is the real boundary and it is where the batch breaks |
| invalid / malformed input | **CUT, with reason.** The map consumes `loaded.ranges` from the **frozen** loader; there is no new parse surface and B3 holds (no file-derived text reaches the bar or rows — verified: every new label is a count, an address or a constant). C-17 markup safety is re-checked at Phase 2 and is already covered live by `AT-074`'s `sensor[red]` payload. | |
| unauthenticated / wrong role | **CUT, with reason.** Single-user local TUI; no auth surface exists. | |
| network / error state | **CUT, with reason.** No network surface. The analogous failure — a render exception — is covered by the full-suite gate and by `<TC-d>`'s no-crash clause. | |
| concurrency | **CUT, with reason.** The map render is synchronous on the UI thread. *(The adjacent hazard — a heavy call on the UI thread — is batch-68's territory and nothing here adds one.)* | |
| regression on adjacent feature | §6 census: **7 named live assertions** across **3 files** | |

---

## §5 · Bidirectional surface-reachability matrix (C-12 · C-18)

Every named **input dimension** must be *driven* through the shipped handler, and every named
**output / deliverable** must be *observed* through the shipped surface. A row with a driven
input and no observed output is an unrealized story; a row with an observed output that was
never driven through the handler is a white-box test wearing an AT's badge.

| Dimension | Driven through the handler? | Observed through the shipped surface? | Node |
|---|---|---|---|
| **INPUTS** | | | |
| sparse multi-region image | ✅ `build_loaded_s19` → `app.current_file` → `update_memory_map()` | — | `<AT-a><AT-c><AT-d><AT-e>` |
| dense contiguous image (no gaps) | ✅ same path | — | `<AT-b>` |
| single range / 100 % coverage | ✅ same path | — | `<AT-e>` boundary |
| **no file loaded** | ✅ `update_memory_map()` with `current_file is None` | — | `<TC-d>` `<AT-j>`-neg |
| terminal regime 80×24 | ✅ `run_test(size=(80,24))` | — | all |
| terminal regime **120×30** | ✅ `run_test(size=(120,30))` | — | all — **this is where the batch breaks** |
| real key press | ✅ `await pilot.press(...)` — **never `.focus()`** (C-16) | — | `<AT-g><AT-h>` |
| real mouse click / double-click | ✅ `pilot.click` / `pilot.double_click` after `scroll_visible` | — | `<AT-i>` |
| A2L tags present | ✅ `app._a2l_enriched_tags` | — | existing `AT-073` (PIN) |
| **OUTPUTS** | | | |
| band-segment **painted width** | — | ✅ `seg.region` clipped to `bar.region` | `<AT-a>` |
| band-segment **content + classes** | — | ✅ `str(seg.render())`, `sorted(seg.classes)` | `<AT-b>` `<TC-a>` |
| bar total vs budget | — | ✅ Σ widths vs `_BAND_BAR_WIDTH` **and** vs `bar.region.width` | `<AT-c>` |
| gap fold marker | — | ✅ `query(".map-band-gap")` width + count | `<TC-b>` |
| ruler tick labels | — | ✅ `[str(t.render()) for t in query(".map-ruler-tick")]` | `<AT-d>` |
| stats strip text | — | ✅ `str(query_one("#map_stats_body").render())` — **body, not the `#map_stats` container** | `<AT-e>` `<TC-d>` |
| legend absence | — | ✅ `query(".map-legend-row")` **and** `query(".map-band-legend")`, both `== 0` | `<AT-f>` |
| `k` LegendScreen unaffected | — | ✅ `pilot.press("k")` → `isinstance(app.screen, LegendScreen)` + its body | `<AT-f>` PIN |
| focused widget identity | — | ✅ `isinstance(app.focused, RegionRow)` + `.region_start` | `<AT-g>` |
| `OpenInHexRequested` message | — | ✅ captured on the panel, count **and** payload address | `<AT-g>` `<AT-i>` |
| inspector text | — | ✅ `str(query_one("#map_detail_body").render())` | `<AT-j>` `<AT-i>` |
| selection style | — | ✅ `row.styles.(background, color, text_style)` — resolved CSS (§1.5) | `<AT-k>` |
| footer chip set | — | ✅ `app.active_bindings` filtered `.show and .enabled` | `<AT-l>` |
| App-level `o`/`j`/`k` behaviour | — | ✅ screen stack / action side-effect, focus NOT on a row | `<AT-h>` |

**Gap check:** every input row above appears in at least one output row's node, and every output
row is driven by at least one input row. **No orphan on either side.** The two rows I cannot
close are `<AT-g>`'s entry key (**B-6**) and `<AT-h>`'s expected outcome (**B-3**).

---

## §6 · C-26 reverse-grep census — every touched symbol across the WHOLE `tests/` tree

Executed: `grep -rln <symbol> tests/` for each symbol (`__pycache__` hits elided).

| Symbol | Files | Named live assertions this batch puts at risk |
|---|---|---|
| `RegionRow` | `test_map_click_chain.py`, `test_tui_directionb.py`, `test_tui_map_big.py` | `test_ac6_band_segments_do_not_widen_region_row_queries` (counts + `isinstance` overlap == 0) · `test_at073_sym_count` (iterates `query(RegionRow)`) · `test_at074_inspector` (`next(r … r.region_start == …)`) · `directionb:3461,4241` row lookups |
| `.map-band-seg` | `test_tui_directionb.py`, `test_tui_map_big.py` | `test_at035_map_shows_band_bar_and_summary_header` (`bar.query(".map-band-seg")`, ≥2 `band-*` tokens) · `test_at072a_bands` (`_strip_text` joins **all** segment renders; ≥2 band glyphs **and** ≥1 `╱`) |
| `.map-ruler-tick` | `test_tui_map_big.py` | **`test_at072b_ruler` — `len(ticks) == 5`. US-77-2 makes this RED.** Re-derivation in §3.4 |
| `.map-legend-row` | `test_tui_directionb.py` | **`test_at075_e_key_opens_no_modal_map_has_legend` — asserts all 4 band names are in the map body. US-77-4 makes this RED.** Port the `e`-key clause |
| `#map_stats_body` | `test_tui_directionb.py` | **`test_at037_stats_strip_matches_case_02_coverage` — asserts all 7 labels incl. `"Coverage:"` and `"Largest gap: N bytes"`. US-77-3 makes this RED (two clauses).** · **`test_tc041_9_…` — `assert "Coverage:" not in strip` goes VACUOUS** (§3.5) · `_ws_stats_text` at `:7274` mirrors the read convention only (not at risk) |
| `#map_detail_body` | all three files | `test_at074_inspector` · `test_map_click_chain` single/double · `directionb:4329`. **US-77-6 auto-select changes the pre-click baseline** — any test asserting the neutral hint *before* a click flips |
| `.map-band-gap` | `test_map_click_chain.py` | `test_ac6_gap_hatch_segments_are_not_clickable` — double-clicks **every** gap, asserts 0 navigations. **Fold markers must stay inert `Static`s** (Phase-0 P-13/P-14) |
| `.map-band-legend` | **— none —** | Removing the container breaks no query of the container itself. Only `.map-legend-row` matters |
| `.map-band-bar` | `test_map_click_chain.py`, `test_tui_directionb.py` | **`test_ac6_clipped_segments_are_a_known_layout_limitation` — asserts `bar_width < _BAND_BAR_WIDTH` AND `outside_count > 0`. Option C-2 in §3.3 makes this RED and requires DELIBERATE DELETION.** · `test_at035…` |
| `_BAND_BAR_WIDTH` | `test_map_click_chain.py` | same node |
| `BandSegment` | `test_map_click_chain.py` | AC-6 sibling-not-subclass pin |
| `.map-region-row` | `test_tui_directionb.py`, `test_tui_map_big.py` | `_region_rows` helper at `:3890`; `directionb:3967,3996,4037` |
| `.map-ruler` | `test_tui_map_big.py` | via `_ruler_ticks` |
| `.map-region-list` | **— none —** | |

**Blast radius: 3 test files, 7 live assertions at risk, of which 4 go RED by design and 1 goes
VACUOUS.** `tests/test_map_click_chain.py` is the **third** file — Phase 0 §5.4 named only
`test_tui_map_big.py`, and `test_map_click_chain.py` is where the `_BAND_BAR_WIDTH` /
container-disagreement pin actually lives. **That omission is why B-1 was not found at Phase 0.**

**Baseline, executed just now (form: full file, not `-k`):**

```
$ python -m pytest tests/test_tui_map_big.py tests/test_map_click_chain.py -q
................                                                         [100%]
16 passed in 20.99s
```

---

## §7 · Snapshot-drift expectation, reasoned PER CELL (C-22) + shared-chrome census (C-28)

**Map cells in the matrix:** `map` is a `_SCAFFOLD_SCREENS` / `_TWO_SIZE_SCAFFOLDS` screen —
**exactly 2 cells**, `comfortable × {80×24, 120×30}`. Total matrix = 29 cells.

| Cell | Increment | Drifts? | Reason (per-cell, not a count) |
|---|---|---|---|
| `map · comfortable · 80×24` | Inc-1 (US-77-1) | ✅ **YES** | The bar body repaints: run widths change from `[1,1,1,1,1]` and gaps fold from `[7,7,15,30]`. Fully inside the 66-column container, so the change is fully rendered → **certain drift** |
| `map · comfortable · 120×30` | Inc-1 | ⚠️ **YES, but the delta is partly INVISIBLE** | The bar container is **21** columns; today 3 segments render entirely outside it. The SVG captures only what is painted, so the drift here is the *visible prefix* only. **If the operator rules C-1 (constant-only), this cell may drift LESS than expected — do not read a small diff as "the fix didn't apply"** |
| both map cells | Inc-2 (ruler) | ✅ YES | tick label text and count change |
| both map cells | Inc-3 (stats + legend) | ✅ YES | 4 legend rows removed → **the map body reflows vertically**; content below shifts |
| both map cells | Inc-4 (keyboard/auto-select/selection) | ✅ YES | auto-select paints the inspector, which was the neutral hint at capture time; the selection style repaints one row |
| all 27 non-map cells | Inc-1…Inc-4 | ❌ **NO — conditional on C-28** | **No other screen renders the map body.** ✅ **Provided US-77-5 adds NO `show=True` App-level binding.** |

> 🔴 **C-28 trigger, stated as a rule not a hope.** If US-77-5 adds **any** App-level
> `Binding(..., show=True)`, the Footer renders on **every** screen and **all 29 cells** drift.
> Executed measurement of the exposure: the map footer already carries **14** chips in a
> **78**-column Footer at 80×24, so a 15th chip may also *truncate* existing chips at the narrow
> regime while leaving wide cells clean — i.e. the drift would be **width-dependent**, and a flat
> "all 29" mark would be wrong in the other direction.
>
> **C-30 sequencing consequence:** any shared-chrome change **must be sequenced LAST**. Applying
> it in Inc-1 would blanket-`xfail` the whole matrix and suppress snapshot regression coverage
> for the remaining three increments.
>
> **Recommended and cheapest:** **add no `show=True` binding at all.** `k → Legend` and
> `? → Help` are already in the footer (measured). US-77-5's discoverability is then satisfied by
> the `?` help panel, C-28 drift is **zero**, and the census stays 2 cells.

**Marking discipline:** mark the 2 map cells `xfail(strict=False)` as an **upper bound** per
C-22, following the existing `_batch45_map_drift_marks` / `_batch47_map_drift_marks` convention.
**Regenerate baselines ONLY in canonical CI** (textual 8.2.8 pin) — local regen corrupts
unrelated baselines.

---

## §8 · Validation strategy — how each gate is run

1. **C-34 — every increment in this batch touches `screens_directionb.py` and/or `styles.tcss`,
   both TUI render modules. Every increment gate therefore runs the FULL
   `tests/test_tui_directionb.py`, not a `-k` subset.** That file is the cross-cutting guard
   host: the `from_markup` source scans (`test_tc_042_10`), the rail census, the footer binding
   census (`TC-030`), the `_PRE_BATCH_BINDINGS` reachability guard (`TC-011` — directly
   implicated by B-3), and the legend/stats assertions all live there and none is reachable
   from a story-scoped selector. A `-k`-only gate is a C-19 partial-run violation.
2. **Plus, at every gate:** `tests/test_tui_map_big.py` + `tests/test_map_click_chain.py`
   (the other two census files) and the frozen dual guard (source **and** `_ENGINE_TEST_FILES`,
   C-27).
3. **C-25 — one complete run, owned by the orchestrator, read from its own output.** No
   assembling a verdict from fragments; the validating agent does not exit before the run ends.
4. **Gate suite form is stated with every ledger figure.** `tui-ci` runs `-m "not slow"` on PRs
   and the **FULL** suite on pushes; **21 slow tests**. **The FULL form runs before merge.**
5. **Mutation discharge is executed, not described.** For each gate predicate: name the
   mutation, record the **substituted VALUE** (not the deleted operator — `max(a,b)` has two
   one-token mutations and "drop the clamp" names neither), execute it in an **isolated tree**
   with `PYTHONDONTWRITEBYTECODE=1` (**C-46**), restore, and **prove the restore with a green
   run — not with a hash** (a same-size mutation plus a sub-second restore is invisible to both
   `git status` and md5).
6. **Per-arm verdicts (CC-1).** Every AT here is parametrized over `[(80,24),(120,30)]`. An exit
   code over parametrized tests hid **4 surviving arms** in batch-76. **Report the RED/GREEN
   verdict per resolved node id, per size arm** — `<AT-a>`'s two arms are measurably different
   (GREEN@80×24 / RED@120×30 on the visibility clause) and a single aggregate verdict would
   destroy exactly the information B-1 depends on.
7. **No test file is deleted in the same increment that changes the behaviour it guards.** The
   two RED-by-design nodes (`test_at072b_ruler`, `test_at075_…`) are **re-derived in place**;
   `test_ac6_clipped_segments_…` is deleted **only** on an explicit operator ruling for §3.3
   option C-2, with the deletion recorded as a supersession.
8. **Test results in this document are BLANK.** §10's table is for the human running the gates.
   The only results asserted anywhere above are pre-change probe transcripts, and each carries
   its command.

---

## §9 · AT/TC reservation request sheet (for the pre-work registry PR)

**Do not mint from this table.** Take `next_free` from `AT-TC-REGISTRY.jsonl` line 1 at the
moment the reservation PR is written (**currently `AT: 282`, `TC: 613`**), append `RESERVED`
rows with `reserved_by` and the one-sentence `statement` below, and **merge that PR to `main`
before any batch work**. A reservation on an unmerged branch prevented nothing in batch-64/65.

> **Consider batch-scoped ids (`AT-B77-01`…) instead.** `docs/engineering-rules.md` prefers
> them; they cannot collide by construction and the global pool never carries them. Given B-1/
> B-2/B-3 may reshape three of these stories, **batch-scoped is the lower-risk choice here** and
> is my recommendation. Two of the twelve below (`<AT-i>`, and possibly `<AT-f>`'s PIN arm) may
> resolve to **existing** nodes rather than new ids — check before reserving.

| Placeholder | Statement (one sentence) | Gate or PIN | Blocked |
|---|---|---|---|
| `<AT-a>` | Region bar widths order with mapped size and every mapped region is visible, at both regimes. | **GATE** | 🔴 B-1 |
| `<AT-b>` | A dense contiguous image renders a byte-identical band strip vs the pre-change golden. | **PIN** (gate via post-fix mutation) | 🟠 B-5 (fixture) |
| `<AT-c>` | The band bar fits its column budget. | **GATE** | 🔴 B-1 (which budget) |
| `<AT-d>` | Every ruler tick label is drawn from the admissible label set, strictly ascending, no duplicates. | **GATE** (re-derives live `AT-072b`) | 🔴 B-2 |
| `<AT-e>` | The stats strip shows a dual mapped/span readout with a real percentage and a humanized largest gap. | **GATE** | — |
| `<AT-f>` | The legend block is absent from the map body and the `k` LegendScreen is unaffected. | **GATE** + PIN arm | 🟠 B-4 (drop the footer clause) |
| `<AT-g>` | Real key presses focus a region row, move the selection, inspect and open-in-hex. | **GATE**, mechanism `assumed — verify at Phase 3` | 🔴 B-6 |
| `<AT-h>` | With focus off the region list, `o`/`j`/`k` still perform their App actions. | **GATE** (discriminating negative) | 🔴 B-3 |
| `<AT-i>` | The N4a mouse split (single=inspect, double=hex) is preserved. | **PIN** | check for an existing node first |
| `<AT-j>` | With a file loaded the inspector is populated with zero interactions. | **GATE** | ⚠️ arm 2 (re-render policy) unstated |
| `<AT-k>` | The selected row's resolved style differs from every unselected row, and exactly one row is selected. | **GATE** | — |
| `<AT-l>` | The keyboard path is surfaced in the footer/`?` without displacing the pre-existing global footer set. | **GATE** | — |
| `<TC-a>` | Capture the dense band-strip golden from the shipped producer (own commit, pre-change). | harness | 🟠 B-5 |
| `<TC-b>` | A folded gap marker's width is bounded and independent of the gap's byte size. | **GATE** | — |
| `<TC-c>` | Fold markers are not `RegionRow`s. | **PIN** — likely reuse `test_ac6_band_segments_do_not_widen_region_row_queries` | — |
| `<TC-d>` | With no file loaded the stats strip stays neutral and raises nothing. | **GATE** (re-derives `test_tc041_9`) | — |

---

## §10 · Test results — **left blank for the human / the Phase-4 run**

Per the evidence checklist: this section is not filled by me. The only executed results in this
document are the **pre-change probe transcripts** in §1 and §3, each of which states its command.

| Node | Size arm | Expected pre-change | Observed | Pass/Fail | Notes |
|---|---|---|---|---|---|
| `<AT-a>` | 80×24 | RED (strict) | | | |
| `<AT-a>` | 120×30 | RED (strict **and** visibility) | | | |
| `<AT-b>` | both | GREEN (no-op control) | | | post-fix mutation must go RED |
| `<AT-c>` | 80×24 | C-1 RED / C-2 GREEN | | | depends on B-1 ruling |
| `<AT-c>` | 120×30 | C-1 RED / C-2 RED | | | |
| `<AT-d>` | both | RED | | | |
| `<AT-e>` | both | RED | | | |
| `<AT-f>` | both | RED | | | |
| `<AT-g>` | both | RED | | | mechanism verified at Phase 3? |
| `<AT-h>` | both | GREEN (pin) | | | must stay GREEN after Inc-4 |
| `<AT-i>` | both | GREEN (pin) | | | |
| `<AT-j>` | both | RED | | | |
| `<AT-k>` | both | RED | | | |
| `<AT-l>` | both | RED | | | |
| `<TC-b>` `<TC-d>` | both | RED | | | |
| `test_at072b_ruler` | both | GREEN → RED by design | | | re-derived, not deleted |
| `test_at075_…legend` | 120×30 | GREEN → RED by design | | | `e`-key clause ported |
| `test_at037_stats_…` | 120×30 | GREEN → RED by design | | | two clauses |
| `test_tc041_9_…` | 120×30 | GREEN → **VACUOUS** | | | re-derive as `<TC-d>` |
| `test_ac6_clipped_segments_…` | 120×30 | GREEN → RED **iff** C-2 | | | deliberate deletion, operator ruling |
| FULL `test_tui_directionb.py` | — | 2514 passed baseline (batch-76 close, FULL form) | | | C-34, every gate |

---

## §11 · Self-caught defects in my own probes (recorded, not hidden — C-43)

1. **Probe 3 printed a variable named `fully-outside-bar` that actually counted
   *not-fully-contained*.** Read at face value it would have over-stated the 120×30 damage for
   the dense fixture ("2 of 2 segments outside" when both were merely *crossing the edge*).
   Caught by re-running with the three cases separated and role-labelled (probe 4), which is
   where the real, sharper finding came from: **2 of 5 mapped regions are entirely invisible**.
   *A count is not a finding until its predicate name matches its expression* — C-40 limb 1
   landing in my own probe.
2. **My key-press probe pressed `k` (which pushed `LegendScreen`), then pressed `j` and `o`
   while that modal was still up** — `escape` did not dismiss it. The `j`/`o` rows of that trace
   are therefore **not evidence** and are not used anywhere above. The B-3 finding rests solely
   on the **`S19TuiApp.BINDINGS` census**, which is direct and unambiguous. Recorded because a
   plausible-looking trace that I had *not* invalidated would have been the vacuous input here.
3. **Probe 1 crashed on `UnicodeEncodeError` (cp1252) when printing the golden payload.** All
   the numeric findings had already printed; the fix was `sys.stdout.reconfigure(encoding="utf-8")`
   in probes 2–4. Noted because it is the same family as C-42 mechanic 4 — *the emitted form is
   not the readable form* — and because a probe that dies **after** printing partial results is
   exactly the shape that gets misread as complete.

---

## §12 · Evidence checklist (C-45 artifact requirement)

| # | Item | ✓/✗ | Evidence |
|---|---|---|---|
| 1 | Acceptance criteria use Given/When/Then | ✅ | §3.1–3.9, every `<AT-*>` |
| 2 | Test cases have explicit **Expected**, not vague "works" | ✅ | §3 predicates are executable expressions; §10 states an expected pre-change verdict per arm |
| 3 | Edge cases include empty, boundary, invalid, error | ✅ | §4 — with **written justifications** for the 4 cut classes, none cut silently |
| 4 | Regression checklist exists | ✅ | §6 — 3 files, 7 named live assertions, baseline `16 passed in 20.99s` executed |
| 5 | Exit criteria stated | ✅ | §8 — FULL `test_tui_directionb.py` per gate (C-34), FULL suite before merge, per-arm verdicts (CC-1), executed mutation per gate predicate |
| 6 | No real PII / secrets | ✅ | fixtures are in-test builders + the public `examples/` triple; no client data, no credentials, no host paths |
| 7 | Test-results section left **blank** | ✅ | §10 — Observed/Pass-Fail columns empty. Only pre-change probe transcripts are asserted, each with its command |
| 8 | **Layer B (black-box)** — every output-producing story observed through the SHIPPED surface with boundary + negative evidence | ✅ | §5 output half: all 13 outputs observed post-`update_memory_map()`; boundary = the 21-column regime; negatives = `<AT-h>`, `<AT-j>`-neg, `<TC-d>`, the `human_bytes`/`Coverage:` absence clauses |
| 9 | **Bidirectional surface-reachability** | ✅ | §5 — 10 inputs driven, 13 outputs observed, no orphan either side; the 2 unclosable rows are named as blockers (B-3, B-6), not papered over |
| 10 | **No unfilled template** | ⚠️ **PARTIAL, deliberately** | No `<...>` placeholder remains *unexplained*: `<AT-a>`…`<TC-d>` are the mandated id placeholders (§9 gives the true `next_free`), and every empty cell in §10 is the human's to fill. **Three "Then" clauses are genuinely undecided (B-1 `<AT-c>`, B-2 `<AT-d>`, B-3/B-6 `<AT-g>`/`<AT-h>`) and are flagged as blockers rather than invented.** Per the failure mode: *if you cannot determine the expected behaviour, stop and ask — do not fabricate an "expected" outcome.* |
| 11 | C-40 discharged per predicate | ✅ | §3 — both limbs named per AT, mutation named, **verdict executed and transcript pasted** |
| 12 | C-46 — mutation/probe hygiene | ✅ | all probes read-only, run with `PYTHONDONTWRITEBYTECODE=1`; no source file mutated in this lane |
