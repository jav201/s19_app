# batch-77 — Phase-2 QA review: adversarial testability + vacuous-acceptance audit

**Batch:** `2026-08-01-batch-77` · **Branch:** `claude/batch-77-memmap-variant-a` @ `37a83e1`
**Under review:** `.dev-flow/2026-08-01-batch-77/01-requirements.md` (578 lines)
**Context audited, not deferred to:** `01b-qa-validation.md` (a different agent's Phase-1 QA lane) · `00-measurements.md` · `docs/engineering-rules.md` · `tests/test_tui_map_big.py` · `tests/test_map_click_chain.py` · `tests/test_tui_directionb.py` · `tests/test_tui_snapshot.py` · `AT-TC-REGISTRY.jsonl`
**Method:** every finding below was **executed**. Mutations ran in an isolated copy of `s19_app/` under `PYTHONDONTWRITEBYTECODE=1` (C-46); the working tree was never written. Integrity proven by hash **before and after**: `s19_app/tui/screens_directionb.py` = `b11fdfcd25c52bf2fdd4d1e40272d9fa` at both ends, `git status` clean of source changes.

**Scope note:** the six operator rulings R1–R6 are settled and are **not** re-litigated. Findings B-1, B-2 and B-4 concern *incorrect or inconsistent implementation* of R1/R2/R6 in the requirement text, which is in scope.

---

## BLUF

**4 blockers · 5 majors · 8 minors. Something blocks.**

The document is unusually strong — its N-1, P-42, R-2 and snapshot analyses all reproduced exactly under independent execution, and its R-6 mutation prediction is **correct** on the clause that carries it. The four blockers are all the same shape the batch was warned about: **a predicate that was genuinely executed, against the wrong corpus or the wrong state, returning a plausible number.**

| # | Sev | Finding | Executed evidence |
|---|---|---|---|
| **B-1** | 🔴 | `AT-B77-01`'s C-31 completeness guard is **FALSE on the unmodified shipped producer**; its monotonicity clause is un-authorable as worded | 1 `loaded.ranges` entry → **4** `BandSegment`s |
| **B-2** | 🔴 | **Inc-1a's gate is arithmetically unsatisfiable** — both ATs it names are still RED after Inc-1a, and 80×24 gets *worse* | `AT-B77-01` RED both arms; `AT-B77-03` 2-of-9 outside (was 0 at 80×24) |
| **B-3** | 🔴 | `LLR-116.5` / `AT-B77-13`'s focus clause is **GREEN on a detached widget** | `focused.is_attached=False`, `parent=None`, not in `query(RegionRow)` — threshold reads `True` |
| **B-4** | 🔴 | `AT-B77-09` tests the **one state in which the shadowing it gates cannot occur** | its `Given` is "focus NOT on a row"; after Inc-5 focus **is** on a row by default |
| **M-1** | 🟠 | The R-6 mutation table is a **prediction marked ✓ as discharged**. I executed it: correct on the detail clause, **collapses as specced** | `mutB` ≡ `correct` (R,G,R) once the focus clause is conjoined |
| **M-2** | 🟠 | `LLR-111.4`'s golden payload `[45,15]` is on the **retired** `_BAND_BAR_WIDTH=60` basis, labelled "container 66" | 45+15=**60**; at 66 → `[50,16]`, at 21 → `[16,5]` |
| **M-3** | 🟠 | The `test_tc041_9` vacuity claim is **UNDECIDABLE**, and both lanes mislocate its power | no-file strip is `''`; `build_stats_text` is **never called** on that path |
| **M-4** | 🟠 | Blast radius undercounts `test_at037` — a `.6f` absence clause reddens if precision isn't pinned | `LLR-113.1` says "at least four", pinning nothing |
| **M-5** | 🟠 | `AT-B77-10` is a **two-node** claim (C-18 "covered in parts" = unrealized) | maps to `test_ac3_…` + `test_ac4_…` |

**Independently reproduced, no action needed:** N-1 (exactly) · P-42 · the R-2 fixture discrimination · 29 snapshot cells / 2 map cells · 14 footer chips in 78 columns · `AT-072b` RED on its real fixture · the registry/id claims · baseline `16 passed`.

---

## BLOCKERS

### B-1 🔴 `AT-B77-01`'s completeness guard is FALSE on correct code, and its universal has no well-defined subject

**What the document claims.** §3 HLR-111, Deliverable + observation:

> **Completeness guard (C-31):** before evaluating any universal, assert `{s.region_start for s in query(BandSegment)} == {start for start,_ in loaded.ranges}` … **The set comes from the fixture's ranges, never from what the renderer emitted.**

**Executed — the guard is `False` on the shipped, unmutated producer.** A single contiguous range whose first half is `0xFF` and second half pseudo-random:

```
loaded.ranges  = [('0x10000', '0x11000')]
n_ranges       = 1

=== size=(80, 24)  bar width=66 ===
  n BandSegment = 4
    0x00010000..0x00010800  ('band-constant', 'map-band-seg')  content_cols=30
    0x00010800..0x00010B00  ('band-medium',   'map-band-seg')  content_cols=11
    0x00010B00..0x00010D00  ('band-high',     'map-band-seg')  content_cols=8
    0x00010D00..0x00011000  ('band-medium',   'map-band-seg')  content_cols=11
  n RegionRow   = 4
  C-31 GUARD  {seg starts} == {range starts}  -> False
     seg starts   = ['0x10000', '0x10800', '0x10b00', '0x10d00']
     range starts = ['0x10000']
```

Identical at 120×30.

**Why it is wrong, and why the document already knows.** A `BandSegment` is a **run**, not a range — the document's own §1.3 defines it that way ("A merged same-band region from `_merge_band_runs`"), and the shipped docstring is explicit that runs split on *band change* **or** address discontinuity (`screens_directionb.py`, `_merge_band_runs`). `LLR-116.4`'s rationale states the consequence outright:

> matching is by **address**, never by index — a re-merge can change how many runs precede the selected one (`_merge_band_runs` splits on band change *or* address discontinuity)

So the same document reasons correctly about runs-vs-ranges in §4 and writes a range-keyed guard in §3. The guard holds **only** because the sparse 5-region fixture happens to be entropy-homogeneous per range. That is a **fixture coincidence dressed as a rule** — C-40 limb 2 exactly, and the claim "the set comes from the rule, never from what the renderer emitted" is false: the set that must match is the renderer's *entropy* decomposition.

**The consequence is worse than a bad guard.** `AT-B77-01`'s Then clause reads:

> for every ordered pair of mapped regions `a, b` **drawn from the fixture's own ranges**, `bytes(a) > bytes(b) ⇒ visible_cols(a) ≥ visible_cols(b)`

`visible_cols` is defined on a **segment**. With 1 range → 4 segments there is no `visible_cols(range)`. **The "Then" clause cannot be authored for the general case.** It is only meaningful under an unstated 1:1 precondition.

**What its "Then" clause cannot be:** it cannot quantify over `loaded.ranges` while measuring per-segment geometry.

**Fix (cheap, and strictly stronger).**
1. Quantify over **runs**, not ranges — the run list is the rule's own decomposition and is what the operator sees.
2. Replace the guard with an **interval-union** equality, which *is* rule-derived and still detects a dropped region:
   `⋃ [seg.region_start, seg.region_end) == ⋃ loaded.ranges` (verified: holds for both the sparse and the mixed-band fixture; breaks if any region is dropped).
3. State the 1:1 precondition explicitly wherever a fixture relies on it, and assert it (`TC-B77-03`'s "more runs than container columns" fixture in particular).

---

### B-2 🔴 Inc-1a's gate is unsatisfiable — both ATs it names are still RED after Inc-1a, and 80×24 regresses

**What the document claims.** §7: Inc-1a content is "`LLR-111.1` + `LLR-111.6` — width basis → measured container; the settling helper. **`AT-B77-01`, `AT-B77-03`.**" `LLR-111.1`'s numeric pass threshold: "**`AT-B77-01` GREEN on both arms**". The gap fold (`LLR-111.2`) is deferred to **Inc-2**.

**Executed.** I applied exactly the change `LLR-111.1`'s Symbols line prescribes — replace the `_BAND_BAR_WIDTH` basis at the gap expression (`:2058`) and the run expression (`:2066`) with the measured container width — and nothing else:

```
### Inc-1a ONLY (container width basis, NO gap fold) ###

=== size=(80, 24)  bar.region.width=66 ===
  content widths (all segs) = [1, 8, 1, 8, 1, 16, 1, 33, 1]  SUM=70  container=66  OVERFLOW=True
  visible_cols = {0x00000000:1, 0x01000000:1, 0x02000000:1, 0x04000000:1, 0x07FFFF00:0}
  AT-B77-01  visible>=1=False monotone=True strict=True  -> RED
  AT-B77-03  segments outside container = 2 of 9  -> RED

=== size=(120, 30)  bar.region.width=21 ===
  content widths (all segs) = [1, 3, 1, 3, 1, 5, 1, 10, 1]  SUM=26  container=21  OVERFLOW=True
  visible_cols = {0x00000000:1, 0x01000000:1, 0x02000000:1, 0x04000000:1, 0x07FFFF00:0}
  AT-B77-01  visible>=1=False monotone=True strict=True  -> RED
  AT-B77-03  segments outside container = 2 of 9  -> RED
```

**Note the regression:** `AT-B77-03` at 80×24 is **GREEN today** (0 segments outside, per the document's own threshold line) and Inc-1a alone turns it **RED** (2 outside).

**This is not an implementation-choice artifact — it is arithmetic.** Unfolded, proportional gaps consume **65 of 66** columns at 80×24 and **21 of 21** at 120×30. Five runs need ≥1 column each. `65 + 5 = 70 > 66`; `21 + 5 = 26 > 21`. **No Inc-1a-only implementation can satisfy `visible≥1`** — the fold is a *precondition* of `AT-B77-01`, not a follow-on.

**Where the wrong corpus entered.** P-38 is the feasibility premise attached to R1/HLR-111, and every row of its evidence includes a fold:

```
bar= 66 fold=1 ... fits mono strict allvisible
bar= 66 fold=2 ... fits mono strict allvisible
bar= 21 fold=1 ... fits mono strict allvisible
bar= 21 fold=2 ... fits mono strict allvisible
```

**The unfolded case is never evaluated.** P-38 proves "R1 + a fold is achievable" and is cited as proving "R1 is achievable" (P-38's own wording: *"R1 is achievable inside the real container at both regimes"*). Plausible number, wrong corpus.

**Second-order defect.** Inc-1a *also* deletes the containment PIN (`test_ac6_clipped_segments_…`, Amendment C) whose replacement observable is `AT-B77-03`. Since `AT-B77-03` is RED until Inc-2, **containment is unguarded in both directions between Inc-1a and Inc-2** — the exact "a consolidation must not silently drop observables" hazard Amendment C believes it discharged.

**Fix.** Either (a) merge Inc-1a and Inc-2 (both are `screens_directionb.py` + `styles.tcss` + one test file — still ≤5 files), or (b) move `AT-B77-01`/`AT-B77-03` to **Inc-2's** gate, give Inc-1a an inspection-only gate (`no width derives from _BAND_BAR_WIDTH`) plus a no-regression full ×3 run, and **defer the Amendment-C deletion to Inc-2** so the containment observable is never unguarded. Correct `LLR-111.1`'s threshold accordingly, and re-scope P-38 to say what it measured.

---

### B-3 🔴 `LLR-116.5` / `AT-B77-13`'s focus clause is GREEN on a fully detached widget

**What the document claims.** `LLR-116.5` threshold: "`app.focused.region_start == resolved_selection`". HLR-116 threshold: "`app.focused.region_start` equals it". `AT-B77-13`: "`app.focused` is the row whose `region_start` equals it."

**Executed.** Against a minimal reference implementation of `LLR-116.2/.4/.5`, after selecting `0x02000000` and re-rendering the same image:

```
app.focused                       = RegionRow id=1384659156368
app.focused.region_start          = 0x02000000
LLR-116.5 threshold as worded     = True
live RegionRow ids                = [1384659662352, 1384659661392, 1384659656912, 1384659660112, 1384659663312]
focused widget IS in live query   = False
focused.is_attached               = False
focused.parent                    = NoneType
n live RegionRow                  = 5
live starts                       = ['0x0', '0x1000000', '0x2000000', '0x4000000', '0x7ffff00']
```

**The threshold reads `True` while the focused widget is detached from the tree** — `is_attached=False`, `parent is None`, and it is not among the five live `RegionRow`s. The operator's arrow keys would resume from a widget that no longer exists.

**Root cause is the document's own §2.2 constraint.** "Remount discipline — classes, never ids (`DuplicateIds`)" cites `screens_directionb.py:2094-2097`, whose comment says removal after `grid.remove_children()` **is deferred**. So during the resolution window both the stale and the fresh row sets are queryable, and `app.focused` can legitimately hold the stale one. `LLR-116.5`'s acceptance note flags a *different* hazard (re-entrancy) and never this one.

**What its "Then" clause cannot be:** `app.focused.region_start == X` alone cannot certify "focus follows selection", because it is satisfied by a detached row.

**Fix.** Conjoin liveness in both `AT-B77-13` and `AT-B77-14` and in the `LLR-116.5` threshold:
`assert app.focused in set(app.query(RegionRow))` (or `assert app.focused.is_attached`) **and** `app.focused.region_start == resolved`. Add the corresponding note to `LLR-116.2` that "after the rows are mounted" is not a synchronous point in `render_ranges` — `grid.mount()` is deferred, so the resolution must run on a post-refresh hook. This is currently unstated and is the mechanism that produced the defect.

---

### B-4 🔴 `AT-B77-09` exercises the one state in which the shadowing it gates cannot occur

**What the document claims.** `AT-B77-09` *(the discriminating negative)* — "with focus **not** on a region row, `k`/`j`/`o` still perform their App actions and none moves the map selection." HLR-115's threshold repeats it: "**with focus off the region list**, `k` pushes the legend screen, `j` invokes `dump_a2l_json`, `o` invokes `open_workarea`." `LLR-115.4` declares this AT "the discharge of R3".

**The declared subject is shadowing.** `LLR-115.4`'s Statement: "`RegionRow.BINDINGS` **shall not** bind `j`, `k` or `o`." A widget-scoped binding can only shadow an App binding **when that widget has focus**. With focus off the row, no widget-scoped binding is in the resolution chain at all — so the predicate is invariant under the change it gates. **C-40 limb 1: a regression PIN, not a gate.**

**And R-6 makes the excluded state the default.** After Inc-5, `LLR-116.5` puts focus **on** a region row on every render, with no operator input. So the post-batch default state is precisely the one `AT-B77-09` declines to test, and the pre-batch state it *does* test becomes hard to reach through the shipped surface.

**How it got here.** The wording is inherited verbatim from the Phase-1 QA lane's `<AT-h>` ("**focus NOT on a `RegionRow`** (the pre-existing state)") — written *before* R-6 existed. §6.4's reconciliation log records R-6 as touching HLR-116, `LLR-116.4/.5`, §5.2 and §8, and **not** HLR-115. The fold changed the default focus state and no one re-read the acceptance that depends on it. (Corroborating symptom: §5.2 still says `AT-B77-09` "must stay green after **Inc-4**", while §7 places HLR-115 in **Inc-6** — a stale reference from the QA lane's 4-increment plan.)

**Fix.** Make `AT-B77-09` two arms and keep both:
- **arm A (the gate, new):** with focus **ON** a region row — the post-Inc-5 default — `k` pushes the legend screen, `j` invokes `dump_a2l_json`, `o` invokes `open_workarea`, and none moves the map selection.
- **arm B (the PIN, existing):** with focus off the region list, unchanged.

Arm A is the only one that can redden if someone adds `Binding("k", …)` to `RegionRow.BINDINGS`. Note this makes `AT-B77-09` genuinely RED-able **only after Inc-5**, which is consistent with §7's ordering (Inc-5 precedes Inc-6).

---

## MAJORS

### M-1 🟠 The R-6 mutation table is a prediction marked as discharged — executed, it holds on the detail clause and collapses as specced

§9's evidence checklist marks **C-40 both limbs per predicate ✓** citing "the HLR-116 **per-arm mutation table** (each mutation reddens exactly one of `AT-B77-13`/`14`)". Those mutations are on **code that does not exist yet**, so they cannot have been executed at Phase 1. Per the meta-rule (*3-of-5 and 4-of-7 agent RED-predictions were wrong when finally run*), I executed them: a minimal reference implementation of `LLR-116.2/.4/.5` in an isolated tree, then the two substituted values from the document's table.

```
######## VARIANT = correct ########
AT-B77-11 fresh   : DETAIL=GREEN  FOCUS=RED   CONJUNCTION=RED
AT-B77-13 preserve: DETAIL=GREEN  FOCUS=GREEN (focused-row-is-STALE=True)  CONJUNCTION=GREEN
AT-B77-14 fallback: DETAIL=GREEN  FOCUS=RED   CONJUNCTION=RED

######## VARIANT = mutA  (selected = ordered[0], always reset) ########
AT-B77-13 preserve: DETAIL=RED    ...
AT-B77-14 fallback: DETAIL=GREEN  ...

######## VARIANT = mutB  (selected = _selected_cell_start unconditionally) ########
AT-B77-11 fresh   : DETAIL=RED    ...
AT-B77-13 preserve: DETAIL=GREEN  ...
AT-B77-14 fallback: DETAIL=RED    ...

   DETAIL-ONLY clause : correct 11=G 13=G 14=G | mutA 13=R 14=G | mutB 11=R 13=G 14=R
   AS SPECCED (detail AND focus): correct=R,G,R | mutA=R,R,R | mutB=R,G,R
```

**Verdict on the split: the document is RIGHT.** On the selection-resolution clause, `mutA` reddens **`AT-B77-13` only** and `mutB` reddens **`AT-B77-14` only`** — exactly as tabulated. Each mutation reddens exactly one arm; neither arm alone is a gate. **The two-arm split is sound and should be kept.** (Bonus coverage the table does not claim: `mutB` also reddens `AT-B77-11`.)

**But as specced it collapses.** With the focus clause conjoined per B-3, `mutB` produces `R,G,R` — **byte-identical to `correct`**. `AT-B77-13` + `AT-B77-14` together then cannot distinguish the correct implementation from "never re-resolve, keep the stale address". This is a *consequence* of B-3, not an independent defect: fixing B-3 (liveness assertion) and the deferred-mount hook restores discrimination. Recorded so the fix order is explicit — **B-3 must land before the R-6 arms are trusted.**

**Action:** re-mark §9's C-40 row as *predicted at Phase 1, executed at Phase 2 (this document), verified on the resolution clause, conditional on B-3*.

### M-2 🟠 `LLR-111.4`'s golden payload is measured on the retired width basis

`LLR-111.4` publishes, under the heading "**Measured payload @80×24, container 66**":

```
('band-constant','map-band-seg')  len= 45
('band-medium',  'map-band-seg')  len= 15
```

**Executed:** `45 + 15 = 60` — that is `_BAND_BAR_WIDTH`, the basis **R1 retires**. The container is 66.

```
### UNEQUAL 768/256   loaded.ranges=[('0x0', '0x400')]
   size=(80, 24) bar.region.width= 66  n_seg=2 gaps=0  content widths=[45, 15]  SUM=60
   size=(120,30) bar.region.width= 21  n_seg=2 gaps=0  content widths=[45, 15]  SUM=60

### Is the published payload on the SHIPPED basis or the post-R1 basis?
   basis= 60 -> 768/256 renders [45, 15]  sum=60
   basis= 66 -> 768/256 renders [50, 16]  sum=66
   basis= 21 -> 768/256 renders [16,  5]  sum=21
```

The golden is captured in **Inc-1b, after Inc-1a re-bases the width** — so the real golden will be `[50,16]` at 80×24, not `[45,15]`. The literal is illustrative, but it is labelled "container 66" and sits next to the capture instruction, which invites Inc-1b to reject a correct capture.

This also **falsifies an evidence-checklist row**: "*No transcript carried from the old width basis or a fold=2 assumption ✓ — Every figure re-executed post-ruling.*"

**Fix:** mark the payload "pre-R1 basis, illustrative only — the Inc-1b capture supersedes it", or restate it at the post-R1 basis; and correct the checklist row.

**Related (minor, listed below as m-2):** §5.1 standing rule 4 says *every* AT is parametrized over both sizes, while `LLR-111.4` requires capture "at a **FIXED** container width". The container is 66 at 80×24 and 21 at 120×30, so one golden cannot serve both. Two goldens (one per size arm) satisfies both rules; the document should say so.

### M-3 🟠 The `test_tc041_9` vacuity claim is UNDECIDABLE, and both lanes mislocate where its power lives

Both documents assert the node goes vacuous — the requirements doc in a ⚠️ callout under HLR-113, the QA lane in §3.5 — and bind `TC-B77-10` + Inc-4 work to that claim.

**Executed, the shipped node:**

```python
def test_tc041_9_empty_state_stats_neutral_no_exception(tmp_path):
    stats = coverage_stats([], [], [])
    assert stats.image_span == 0
    assert stats.coverage_pct == 0.0
    assert stats.covered_bytes == 0
    assert stats.gap_count == 0
    ...
    assert "Coverage:" not in strip
```

**Five** assertions, not one. The first four call `coverage_stats` directly — HLR-113 re-formats `build_stats_text` only, so they remain fully discriminating. The QA lane's "its **whole runtime** assertion" is defensible; the requirements doc's Inc-4 line "**`TC-B77-10` re-derives `test_tc041_9`**" is not, unless read with §5.1 rule 8 ("re-derived **in place**").

**Executed, where the runtime clause actually points:**

```
no-file #map_stats_body  = ''   len=0
  'Coverage:' not in strip -> True  (on an EMPTY string)
```

`_render_stats(..., empty=True)` does `body.update(safe_text(""))` and **returns without ever calling `build_stats_text`**. So the clause tests the empty-branch early return — not the stats format. It is discriminating **today** (deleting the `if empty:` guard would render `"Coverage: 0.00%…"` and redden it).

**It goes vacuous if and only if the new format drops the literal token `"Coverage:"` — and no requirement decides that.** HLR-113's Statement never mentions the label. `AT-B77-05` forbids only the exact string `"Coverage: 0.00%"`, which is satisfied by `"Coverage: 0.0008%"`. So the claim is **❓ UNDECIDABLE (C-43)**, recorded as ✅.

**Fix:** either add a normative clause to HLR-113 stating the strip no longer emits `"Coverage:"` (which *makes* the claim true and justifies `TC-B77-10`), or drop the vacuity claim. Whichever way, `TC-B77-10` must **preserve the four `coverage_stats` assertions and the node's name** (see m-6).

### M-4 🟠 The blast radius undercounts `test_at037`, and `LLR-113.1` pins no precision

The document says `test_at037_stats_strip_matches_case_02_coverage` goes "RED by design (**two clauses**)". Executed, the node has **four** clauses this batch can move:

| Line | Clause | Status under HLR-113 |
|---|---|---|
| `:26` | `"Coverage:"` in the seven-label loop | **conditional** — red only if the label is dropped (the same undecided decision as M-3) |
| `:39` | `f"Coverage: {PCT:.2f}%" in strip` | **certain RED** |
| `:42` | `assert f"{PCT:.6f}%" not in strip` | **conditional** — red if the implementer picks 6 fractional digits |
| `:49` | `f"Largest gap: {N} bytes" in strip` | **certain RED** |

`LLR-113.1` requires "the coverage percentage with **at least four** fractional digits" — an open lower bound. Choose 4 and `:42` survives; choose 6 and it reddens unannounced.

**Fix:** pin the precision to an exact value in `LLR-113.1` (the threshold `0.0008%` implies 4), and list all four clauses in the blast radius.

### M-5 🟠 `AT-B77-10` is a two-node claim (C-18)

`AT-B77-10` *(PIN)*: "single click ⇒ inspector populated **and zero** `OpenInHexRequested`; double ⇒ **exactly one**." The document then says "**Reuse the existing node if it suffices** — C-18 asks for one node per AT". The existing coverage is **two** nodes:

- `tests/test_map_click_chain.py::test_ac3_single_click_inspects_and_does_not_navigate`
- `tests/test_map_click_chain.py::test_ac4_double_click_navigates_to_the_region_start`

"Covered by X + Y combined" is **UNREALIZED** per C-18. **Fix:** split into `AT-B77-10a`/`10b` bound to the two existing nodes (preferred — no new code), or mint one new node driving both gestures.

---

## MINORS

| # | Finding | Evidence / fix |
|---|---|---|
| **m-1** | `AT-B77-02` is owned by **two** increments — Inc-1b captures the golden, Inc-2 gates it. C-21 wants one owner. | Name **Inc-2** the owning increment; Inc-1b is a harness step. |
| **m-2** | §5.1 rule 4 ("every AT parametrized over both sizes") contradicts `LLR-111.4` ("capture at a **FIXED** container width"). | Two goldens, one per size arm (66 and 21). See M-2. |
| **m-3** | Stale increment references inherited from the QA lane's 4-increment plan: §5.2 says `AT-B77-09` "must stay green after **Inc-4**" (§7 puts HLR-115 in **Inc-6**); the QA lane's `<AT-k>` mutation says "Inc-4 gate" (now **Inc-5**). | Re-point to the 8-increment plan. |
| **m-4** | "**3 files, 7 live assertions**" (R-1) does not decompose — I count **11** named at-risk nodes across the two lanes' tables. The **3-file** count is correct: `MapRuler`'s hit in `tests/test_tui_snapshot.py:669` is a **comment**, not an assertion (verified). | Re-derive the assertion count or drop the figure. |
| **m-5** | `LLR-112.3` cites `tests/test_tui_snapshot.py:670`; the actual `MapRuler` mention is `:669`. | Off-by-one; correct the citation. |
| **m-6** | Inc-4 says "`TC-B77-10` **re-derives** `test_tc041_9`". That node **is** registry-registered. If re-derivation renames or replaces it, guard **G2** fires. | State explicitly that the node **name is preserved** and `TC-B77-10` is a documentation alias. (Verified safe the other way: `test_ac6_clipped_segments_…` is **not** in the registry — **0 rows** — so Amendment C's deletion fires no guard.) |
| **m-7** | The document calls `RegionRow.render()` output "plain `Text`" (P-42, `LLR-117.2`). Executed: it is a `Content` object. The substance (`spans == []`) is correct. | Cosmetic; correct the type name. |
| **m-8** | `test_ac3`/`test_ac4` stay discriminating after auto-select **only because** they click `"high/random"` (region 2) while auto-select takes region 1. That is a fixture coincidence, not a designed property. | Add a one-line note to Inc-5's gate: re-verify both nodes' discrimination after auto-select lands. |

---

## What I verified independently and found CORRECT

These were the document's load-bearing claims. All reproduced.

### N-1 — the two regimes redden on different limbs ✅ EXACTLY as stated

```
ranges = [(0, 256), (16777216, 16777472), (33554432, 33554688), (67108864, 67109064), (134217472, 134217534)]
bytes  = {0: 256, 16777216: 256, 33554432: 256, 67108864: 200, 134217472: 62}

=== size=(80, 24)  bar.region.width=66 ===
  visible_cols = {0x00000000:1, 0x01000000:1, 0x02000000:1, 0x04000000:1, 0x07FFFF00:1}
  LIMB visible>=1 = True    LIMB monotone = True    LIMB strict = False   -> RED
  [content layer] visible>=1=True monotone=True strict=False

=== size=(120, 30)  bar.region.width=21 ===
  visible_cols = {0x00000000:1, 0x01000000:1, 0x02000000:1, 0x04000000:0, 0x07FFFF00:0}
  LIMB visible>=1 = False   LIMB monotone = True    LIMB strict = True    -> RED
  [content layer] visible>=1=True monotone=True strict=False
```

`strict=True` at 120×30 arises exactly as N-1 says: two runs clip to `0` and `1 > 0` satisfies strictness. The QA lane's "strict is RED at both" is true on **content** widths (both rows show `strict=False`) and false on **painted** widths. **The correction is right, and `AT-B77-01` must stay a single three-way conjunction.**

One calibration on the callout's wording, not its conclusion: "*Splitting the conjunction across nodes … ships one regime green*" is loose — split into three parametrized nodes, every limb still has a RED arm somewhere. The **real** hazard, which the conclusion correctly guards, is that a split `test_strict[120×30]` would read **GREEN pre-change for a spurious reason** (clipping), and a reviewer would read that as "strictness works at the wide regime". Keep the conjunction; consider sharpening the justification.

### P-42 — the selection fact lives in `widget.styles`, not `render().spans` ✅

```
('band-constant','map-region-row') type=Content spans=[]
   bg=Color(0, 0, 0, a=0)  color=Color(107, 114, 128)  text_style=none
('band-medium','map-region-row')   type=Content spans=[]
   bg=Color(0, 0, 0, a=0)  color=Color(217, 163, 91)  text_style=none
span lengths = [0, 0, 0, 0, 0]
distinct (bg,color,ts) triples = 2 over 5 rows
```

C-37's span route is indeed inapplicable; `background` is transparent on every row and `color` already differs per band, so the **triple**, compared selected-vs-unselected, is the right predicate. `AT-B77-12`'s design and `TC-B77-25`'s `len(rows) >= 2` guard are both correct.

### R-2 — the dense fixture is genuinely discriminating and the equal one genuinely vacuous ✅

```
### EQUAL   512/512   -> content widths=[30, 30] at BOTH regimes   (invariant, vacuous)
### UNEQUAL 768/256   -> content widths=[45, 15] at BOTH regimes   (moves)
   both fixtures: n_seg=2  gaps=0   (genuinely gapless, as R-2 requires)
```

The B-5 finding the golden rests on is correct. See **M-2** for the basis-label defect in the published payload.

### `AT-072b` — RED on its own fixture, not just on the sparse one ✅

The document's "4 of 5" is measured on the sparse fixture, but the node under re-derivation (`test_at072b_ruler`) drives **`case_02`**. I measured `case_02` directly:

```
case_02 ranges = [('0x0','0xb'), ('0x80010000','0x80010022'), ('0x80010080','0x80010090'), ('0x80010120','0x80010140')]
span_end=0x80010140  last mapped byte=0x8001013F
  span_end mapped? False   se-1 mapped? True

 ticks = ['00000000', '20004050', '400080A0', '6000C0F0', '80010140']   (identical at both sizes)
 membership = [('00000000',True), ('20004050',False), ('400080A0',False), ('6000C0F0',False), ('80010140',False)]
 UNMAPPED ticks = 4 of 5
 ADMISSIBLE = ['00000000','80010000','80010080','80010120','8001013F']
 {ticks} subset ADMISSIBLE -> False
```

**4 of 5 on `case_02` too**, and R4's `span_end - 1` construction verifies on `case_02` against the frozen oracle. The re-derivation is sound on the fixture it will actually run against — a coincidence worth recording, since the document did not check it.

### Snapshot drift (C-22/C-28) — 29 cells, 2 map cells, add no `show=True` binding ✅

```
$ pytest tests/test_tui_snapshot.py --collect-only -q
32 tests collected
  minus 3 non-cell nodes (tc016s_setup, cv04_breakpoint ×2)  ->  29 snapshot cells
map cells = 2:
  test_tc016s_density_layout_snapshot[map-comfortable-80x24]
  test_tc016s_density_layout_snapshot[map-comfortable-120x30]
```

Footer capacity, executed:

```
size=(80,24)  show=True chips = 14   Footer region(w,h) = (78, 1)
   rendered width needed (key+desc+pad) approx = 181
size=(120,30) show=True chips = 14   Footer region(w,h) = (118, 1)
```

**The recommendation to add NO new `show=True` binding is confirmed and, if anything, understated.** Fourteen chips already need ~181 columns of content in a **78**-column footer at 80×24 — they are heavily compressed *before* a 15th is added. Keeping the count at 14 holds drift at **2 cells instead of 29**, and Inc-7-last is the right sequencing.

### Baseline and process claims ✅

```
$ python -m pytest tests/test_tui_map_big.py tests/test_map_click_chain.py -q
................                                                         [100%]
16 passed in 23.54s
```

Registry claims verified against `AT-TC-REGISTRY.jsonl` line 1: `governed` = "a token whose body starts with a digit; **letter-initial bodies … outside this authority**" → `AT-B77-*`/`TC-B77-*` need **no reservation PR**, collision-free by construction, and `docs/engineering-rules.md` prefers exactly that. `next_free` = `AT-282 / TC-613` matches. `AT-072b` is `LIVE` with node `tests/test_tui_map_big.py::test_at072b_ruler` — re-deriving **in place** keeps G2 green.

**Id hygiene, independently recounted:** `AT-B77-01…14` — all 14 defined, no gap, no duplicate. `TC-B77-01…29` — HLR-111:01-05 · HLR-112:06-09 · HLR-113:10-13 · HLR-114:14-15 · HLR-115:16-20 · HLR-116:21-24+29 · HLR-117:25-28 = **29, each used exactly once**. Every increment is ≤5 files.

---

## Mandatory-check disposition

| # | Check | Result |
|---|---|---|
| 1 | C-40 limb 1 — declared subject in the expression, per arm | **2 failures: B-4** (`AT-B77-09`, subject is shadowing, state excluded) and **B-3** (`LLR-116.5`, satisfied by a detached widget). All other predicates carry their subject. Per-arm verdicts reported throughout; no aggregate exit code used. |
| 2 | C-40 limb 2 / C-31 — quantified set from the RULE | **1 failure: B-1** (`AT-B77-01`'s guard is range-keyed against a run-keyed renderer; false on unmutated code). `AT-072b`'s `ADMISSIBLE`, `AT-B77-06`'s `ENTROPY_BAND_LABELS` derivation and `AT-B77-12`'s "every unselected row" are all correctly rule-derived. |
| 3 | C-32/C-37 — reading the layer that holds the fact | **P-42 verified independently** (`spans==[]`, `Content` not `Text`; triple differs per band). `#map_stats_body`/`#map_detail_body` vs the `Blank` containers verified. Geometry read at `widget.region` clipped to the container throughout. **One layer error found: B-3**, at the focus layer. |
| 4 | **Verify N-1 independently** | ✅ **The document is correct.** Both regimes executed; they redden on different limbs exactly as stated. Keep the single three-way conjunction. Wording of the justification calibrated above. |
| 5 | **Verify the R-6 two-arm split** | ✅ **The split is correct** on the selection-resolution clause — `mutA` reddens 13 only, `mutB` reddens 14 only, both executed. ⚠️ **collapses as specced** once the focus clause is conjoined (**M-1**, consequence of B-3). |
| 6 | **The re-based dense golden (R-2)** | Fixture discrimination ✅ verified (equal `[30,30]` vacuous, unequal `[45,15]` moves, both gapless). Capture-from-shipped-producer-in-own-commit (C-12) is correctly specified. ⚠️ **published payload is on the retired basis (M-2)**; ⚠️ fixed-width vs both-sizes contradiction (m-2). |
| 7 | C-18 / C-21 — one AT ↔ one node ↔ one increment | **2 failures: M-5** (`AT-B77-10` = two nodes) and **m-1** (`AT-B77-02` = two increments). Also: the document names only `-k` patterns (11) for 15 ATs — the AT→node-id map must be recorded at each increment gate. |
| 8 | **C-26 reverse-grep, whole `tests/` tree** | Re-run for all 13 symbols. **The Phase-1 lane's 3-file conclusion is CORRECT** — the apparent 4th file (`MapRuler` → `tests/test_tui_snapshot.py`) is a **comment** at `:669`, not an assertion. `.map-band-legend` → **0** files, confirmed. The "**7 live assertions**" figure does not decompose (I count 11 named nodes) — **m-4**. The `test_tc041_9` vacuity claim is **corrected: M-3**. |
| 9 | C-22/C-28 snapshot drift per cell | ✅ **29 cells / 2 map cells confirmed by collection.** The no-new-`show=True`-binding recommendation is **confirmed and understated** — 14 chips already overflow a 78-column footer. Inc-7-last sequencing correct. |

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Acceptance criteria use Given/When/Then | ✓ | Findings restate each predicate's Given/When/Then before attacking it; B-1/B-3 name what the "Then" clause **cannot** be. |
| Test cases have explicit Expected, not vague "works" | ✓ | Every verdict is an executed expression with a pasted transcript. |
| Edge cases include empty, boundary, invalid, error | ✓ | Empty (no-file strip = `''`, M-3) · boundary (21-column regime, B-2; 1 range → 4 segments, B-1) · invalid (detached widget, B-3) · error (Inc-1a overflow, B-2). |
| Regression checklist exists | ✓ | C-26 census re-run over 13 symbols; baseline `16 passed in 23.54s`; blast-radius corrections in M-4/m-4. |
| Exit criteria stated | ✓ | The four blockers are the exit criteria; each carries a named, cheap fix. |
| No real PII / secrets | ✓ | Fixtures are in-test builders + the public `examples/case_02` triple. No credentials, no client data, no host paths beyond the repo root. |
| Test-results section left blank | ✓ | **This review adds no results table.** `01b-qa-validation.md` §10 remains the human's to fill; nothing in it was filled by me. Every result above is a Phase-2 probe transcript with its command. |
| Layer B (black-box) through the shipped surface | ✓ | Every probe drives `App.run_test(size=…)` → `action_show_screen("map")` → `update_memory_map()` and observes `widget.region` / `widget.styles` / `#*_body` / `app.focused` / `app.active_bindings`. No shim. |
| Bidirectional surface-reachability | ✓ | Inputs driven: sparse 5-region · mixed-band single range · unequal & equal dense · disjoint file switch · both regimes · real `Activated` message. Outputs observed: painted width, containment, segment classes+text, ruler ticks, stats body, detail body, focus identity + attachment, footer chips, snapshot cell ids. |
| No unfilled template | ✓ | No `<…>` placeholder, no `TC-NNN`, no empty required row. |
| Mutation hygiene (C-46) | ✓ | All mutations in an isolated copy under `PYTHONDONTWRITEBYTECODE=1`; isolated tree deleted at close; working tree proven unchanged by hash `b11fdfcd25c52bf2fdd4d1e40272d9fa` **before and after**, `git status` clean of source changes. |

---

## Recommendation

**BLOCK at the Phase-2 gate.** Four blockers, all cheap to fix and none requiring a ruling:

1. **B-1** — re-key `AT-B77-01` to **runs**; replace the guard with the interval-union form.
2. **B-2** — merge Inc-1a+Inc-2 (or move `AT-B77-01`/`03` to Inc-2's gate and defer the Amendment-C deletion with them); re-scope P-38 to state it measured the *folded* case.
3. **B-3** — conjoin widget liveness to the focus clause in `LLR-116.5`, `AT-B77-13`, `AT-B77-14`; state in `LLR-116.2` that `grid.mount()` is deferred so the resolution needs a post-refresh hook.
4. **B-4** — add the focus-**on**-row arm to `AT-B77-09`; it is the only arm that can detect shadowing.

Then re-run the R-6 mutation battery (M-1) — the split itself is sound and verified, but its discrimination is hostage to B-3.

**The rest of the document is in good shape.** N-1, P-42, R-2, the snapshot census, the footer analysis, the registry hygiene and the AT/TC id allocation all survived independent execution unchanged.
