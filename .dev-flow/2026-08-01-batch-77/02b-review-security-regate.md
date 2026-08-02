# Security Re-Gate — batch-77 revision 2 (Phase 2)

**Reviewer:** security lane · **Date:** 2026-08-01
**Subject:** `.dev-flow/2026-08-01-batch-77/01-requirements.md` **revision 2** (548 lines) @ `d33b2ab`
**Supersedes:** `02-review-security.md` (rev-1 review: 1 blocker, 2 major, 2 minor)
**Probes:** read-only, `PYTHONDONTWRITEBYTECODE=1` (C-46). No repo file modified by this review.

---

## BLUF

**All four rev-1 findings are substantively addressed. One new blocker, one new major, and a correction
to a claim of my own that revision 2 adopted verbatim.**

| # | Finding | Class |
|---|---|---|
| **B-1r** | **`AT-B77-15`'s control-byte limb is mis-verdicted AND cannot go green in this batch.** Claimed RED today — executed, it is **GREEN, vacuously**. After Inc-7 lands auto-select it becomes genuinely RED, and `C-77-h` defers the fix out of the batch, so **Inc-7 introduces a red gate it cannot pass**. The recorded mutation is **inert on that limb**. | **BLOCKER** |
| **M-3r** | **`LLR-111.8` as worded specifies an O(n²) loop on the UI thread** over attacker-controlled cardinality. Measured **840 ms at n=5000**, uncapped. | **MAJOR** |
| **X-1** | ⚠️ **Correction of my own rev-1 claim, now load-bearing in rev 2.** `:261-262`'s *"distorting the very layout arithmetic R-7 exists to reconcile"* is **FALSE** — executed, the bar is structurally isolated from the detail pane. **Withdraw the rationale; the finding stands on other grounds.** | **correction** |
| m-2r | Census is **9+**, not 8 — a sibling file in the same directory as site 8 was missed | minor |
| **rev-1 B-1** | → addressed; residual is **B-1r** | partly closed |
| **rev-1 M-1** | → **fully closed, both halves** (vacuous predicate rewritten; ruler now *bounded* by R-7 aggregation) | **CLOSED** |
| **rev-1 M-2** | → `legend.py` is site 7 with an owning increment (Inc-4) | **CLOSED** |
| **rev-1 m-1** | → closed by `LLR-117.2`'s strengthening | **CLOSED** |
| C-27 dual guard | re-verified on the re-cut plan — **0 intersections across all 9 increments** | **CLEAN** |

Revision 2 is a large improvement. The remaining blocker is **one node's verdict and its increment
routing** — no requirement needs rewriting, and no new attack surface was introduced by R-7/R-8/R-9.

---

## Findings

### B-1r — `AT-B77-15`'s control-byte limb: wrong verdict today, unreachable verdict at close  [BLOCKER]

**What.** Three coupled defects in the node that closes my rev-1 blocker.

**(a) The claimed pre-change verdict is FALSE.** `LLR-116.6` (`:398`), §5.2 (`:437`) and the C-40 register
(`:347`) all record the control-byte limb as **RED today**. Executed through the shipped surface with
**zero clicks and zero keys**, exactly as `AT-B77-15` specifies (`:263-266`):

```
  size=(80, 24)  detail_body = 'Click a region to inspect it - double-click to open in hex'
     limb1 payload-verbatim : False -> RED
     limb2 spans == []      : True  -> GREEN
     limb3 no ESC in strip  : True  -> GREEN   <== doc claims RED today
  size=(120, 30)  detail_body = 'Click a region to inspect it - double-click to open in hex'
     limb1 payload-verbatim : False -> RED
     limb2 spans == []      : True  -> GREEN
     limb3 no ESC in strip  : True  -> GREEN   <== doc claims RED today
```

Limb 3 is **green because nothing rendered** — with zero clicks the inspector still shows `_DETAIL_HINT`
(`screens_directionb.py:1723`), which contains no file-derived text at all. This is **C-40 limb 1**, the
exact pattern the document's own standing rule 3 names (`:411`, *"every absence assertion carries a
presence co-assertion"*). The node aggregates to RED off limb 1, which is what hid it.

**(b) The limb becomes RED only after Inc-7, and the fix is carried out of the batch.** Once
`LLR-116.1`/`.2` land auto-select, `build_detail_text` fires on load and limb 3 goes genuinely RED.
But `C-77-h` (`:267-268`, `:453`) explicitly defers the scrub: *"The scrub itself is NOT fixed here."*
So at batch close:

- `LLR-116.6` is **normative** — *"**shall not** emit any C0 or C1 control byte into the painted strip"* (`:398`)
- `AT-B77-15` is listed a **GATE** — *"✅ **GATE — RED, executed**"* (`:347`)
- Inc-7's gate requires it — *"`AT-B77-11/12/13/14/15`"* (`:509`)
- and nothing in the batch can turn it green.

**Inc-7 would introduce a red gate.** This is the same class as the architect's Inc-1 indivisibility
finding, landed on my finding instead.

**(c) The recorded mutation does not discharge the limb.** `:347` records *"remove `safe_text` from the
A2L path"*. Executed:

```
  SHIPPED  safe_text(p)          limb1_literal=True  limb2_nospans=True  limb3_noESC=False
  MUTATED  Text.from_markup(p)   limb1_literal=False limb2_nospans=False limb3_noESC=False
  safe_text(P).plain == P  -> True
  => the recorded mutation flips limbs 1-2 and is INERT on limb 3.
```

`safe_text` is a **no-op on ESC** (P-51 already establishes this), so removing it cannot change limb 3's
verdict. Limbs 1-2 have a real mutation; **the limb the entire finding is about has none.**

**Where.** `01-requirements.md:398` (`LLR-116.6` threshold), `:437` (§5.2 row), `:347` (C-40 register),
`:252-268` (the `AT-B77-15` block), `:509` (Inc-7 gate), `:453` (carry C-77-h).

**Why it matters.** A gate whose pre-change verdict is wrong is not a gate — it is a node that will be
read as discharged. And a normative `shall not` whose only verifier stays RED at close means the batch
ships a requirement it does not meet, in the C-17 domain.

**Recommendation — pick one, both close it:**

| Option | Expected result | Consequences |
|---|---|---|
| **A — land the control-char filter in Inc-7** | ✅ `AT-B77-15` green at close; `LLR-116.6` genuinely met | ⚠️ `safe_text:688` is **not frozen** (verified), so this is in-scope; drifts snapshot baselines, but **Inc-9 already regenerates them**; ⚠️ Inc-7 is at **exactly 5 files** — needs the operator's call on the cap |
| **B — split the node** | ✅ green at close, honestly | `AT-B77-15a` **GATE** = limbs 1-2 (markup literal ∧ `spans == []`) with the recorded mutation, which does discharge them; `AT-B77-15b` **PIN** = limb 3, `xfail(strict=True)` naming `C-77-h`, converting to a gate when the carry lands |
| C — leave as written | ❌ Inc-7 ships a RED gate | violates §5.3's *"0 blocker findings at the merge gate"* |

**Independently of A or B, three corrections are mandatory:**
1. **Correct the pre-change verdict** at `:398`, `:437`, `:347`: limb 3 is **GREEN today (vacuously — nothing rendered)**, becoming RED after Inc-7. Do not leave "RED today" on the page.
2. **Add the C-40 co-assertion to limb 3 explicitly:** it may be evaluated *only* in a run where limb 1 has already established the payload is present. State it in the AT body, not just in standing rule 3.
3. **Record a mutation that reddens limb 3** — e.g. *substitute the C0-filtered value with the raw value* once the filter exists (option A), or mark limb 3 mutation-undischargeable-until-`C-77-h` (option B).

---

### M-3r — `LLR-111.8` as worded specifies an O(n²) loop on the UI thread over attacker-controlled cardinality  [MAJOR]

**What.** `LLR-111.8`'s Statement (`:312`) reads: *"**shall** merge the smallest adjacent runs into
aggregate segments **until the allocation fits**."* Read literally — and it will be, it is the normative
sentence — that is a repeat-until-fits loop with a min-scan per iteration: **O(n²)**. Run count is
attacker-controlled and uncapped (rev-1 measured 5000 scattered ranges → 5000 runs; no cap exists in
this project). `render_ranges` runs on the UI thread, on every render.

**Measured, both new allocation clauses:**

```
=== LLR-111.7 largest-remainder allocation (fits, no aggregation) ===
  n=   100  alloc      0.05 ms
  n=  1000  alloc      0.30 ms
  n=  5000  alloc      1.25 ms          <- O(n log n), FINE

=== LLR-111.8 'merge smallest adjacent until it fits', bar=50 (as worded) ===
  n=   100  merges=   75  final= 25       0.45 ms
  n=   500  merges=  475  final= 25       8.47 ms
  n=  1000  merges=  975  final= 25      31.10 ms
  n=  2000  merges= 1975  final= 25     128.60 ms
  n=  5000  merges= 4975  final= 25     840.34 ms   <- UI THREAD, per render
```

Textbook quadratic: 500→1000 is 3.7×, 1000→2000 is 4.1×, 2000→5000 is 6.5× for 2.5× the input.

**Where.** `01-requirements.md:312` (`LLR-111.8` Statement), `:315` (threshold — states the *onset*
`2·n_runs − 1 > bar_w`, never the *cost*), `:305-309` (`LLR-111.7`, which is fine), §9 `:540` — the
evidence checklist records *"column budgets are the cost axis"*, so **time is not a stated axis anywhere
in the document**.

**Why it matters.** This is a genuinely new surface created by R-7/2 — it did not exist in revision 1.
Batch-68 already moved report composition off the UI thread because *a total freeze* was the symptom;
a hostile `.s19` with a few thousand scattered ranges reproduces that class here, on the load path, with
no cap to stop it. It is major rather than a blocker because the cost is a **freeze, not a corruption or
an escape**, and the fix is cheap.

**Recommendation.**
- **Add a complexity bound to `LLR-111.7`/`.8`:** *"the allocation and any aggregation **shall** complete
  in `O(n log n)` in the number of runs."* A heap, or a single-pass selection of the `k` smallest
  adjacent pairs where `k = n − (bar_w+1)//2`, is O(n log n) and needs no loop at all — the target count
  is known in closed form from the onset formula the document already derives (`:315`).
- **Add a boundary TC** under HLR-111 asserting a wall-clock or operation-count ceiling at
  **n ≥ 2000 runs**, both regimes. `TC-B77-03` (`:142`) covers *"more runs than container columns"*
  functionally but asserts nothing about cost.
- The `+N more` count is **clean** — `:316` derives it as `len(oracle) − non_aggregate_segments`, both
  O(1) given the lists, **no enumeration**. `R-TUI-098`'s *"the count is exact even when the enumeration
  is bounded"* is carried correctly (`:314`). No finding.

---

### X-1 — Correction: my rev-1 width-perturbation claim is FALSE, and revision 2 built on it  [correction, not a finding]

Revision 2 `:261-262` states, as the reason `AT-B77-15` belongs to *this* batch:

> *"a hostile A2L symbol inflates rendered width by invisible bytes, distorting the very layout arithmetic R-7 exists to reconcile."*

**That sentence is mine, from `02-review-security.md`, adopted verbatim. Executed, it is false.**

```
  BENIGN    size=(80, 24) | bar= 66 grid= 66 #map_detail= 66 body= 66 len(plain)=  277 ESC=False
  HOSTILE   size=(80, 24) | bar= 66 grid= 66 #map_detail= 66 body= 66 len(plain)=  708 ESC=True
  -> perturbed? False   ((66, 66, 66) vs (66, 66, 66))

  BENIGN    size=(120, 30) | bar= 21 grid= 50 #map_detail= 36 body= 36 len(plain)=  277 ESC=False
  HOSTILE   size=(120, 30) | bar= 21 grid= 50 #map_detail= 36 body= 36 len(plain)=  708 ESC=True
  -> perturbed? False   ((21, 50, 36) vs (21, 50, 36))
```

The payload inflated the body's plain length **277 → 708** with the ESC present, and `.map-band-bar`,
`#map_grid` and `#map_detail` were **byte-identical** at both regimes. The reason is structural:
`#map_detail { width: 36; }` (`styles.tcss:861`) is a **fixed** column, `#map_detail_body { width: 100%; }`
of that fixed parent (`:873`), and under `width-narrow` the pane is `width: 100%` (`:867`) — **never
content-sized**. `#map_grid` takes `1fr` of the remainder and is unaffected.

**An attacker cannot perturb the bar's geometry through a symbol name.** The width inflation is real but
confined inside a fixed-width box and reaches nothing. This also answers the re-gate's question 2
directly: the allocation's inputs are run byte-counts from `_merge_band_runs` — pure address arithmetic —
and **no file-derived string is an input to `LLR-111.7`**.

**Recommendation.** Delete `:261-262`'s width-perturbation clause and replace it with the true reason,
which is sufficient on its own: *"Why it lands on this batch: `HLR-116` converts this sink from
click-gated to fired-by-loading-a-file, on the untrusted-firmware path."* A wrong rationale inside a
requirement is precisely how revision 1's premises failed (P-38, P-44, P-45, P-51) — I am not going to
let one of mine become the next one.

---

### m-2r — the census is 9+, not 8; the missed site is a sibling of site 8  [minor]

`LLR-112.3` (`:364-376`) raises the census 6 → 8. A prose sweep — reading for the *claim*, not the id,
which is what my rev-1 M-2 asked for — finds a **ninth** in the same directory as site 8:

```
./.dev-flow/2026-07-15-batch-47/06-docs/functionality.md:173:
  | **Address ruler** | A NEW widget beneath the strip: exactly 5 tick labels at
    0/25/50/75/100 % of the address span; tick 0 % == span start, tick 100 % == span end. |
```

Site 8 is `.../06-docs/traceability-matrix.md:54`. Its sibling in the same folder was not read. The
batch-47 artifact set carries **~14** further restatements (`01b-qa-strategy-and-verification.md:65/132/
203/277/293/301`, `03-increments/increment-05.md:131`, `increment-06.md:24/106/143`,
`04-validation.md:53/106/144`).

**This is minor, not major, because `LLR-112.3`'s Statement is already normatively correct** — `:365`
says *"every surviving statement of the retired 5-tick contract in shipped source, tests,
`REQUIREMENTS.md`, **and the batch-47 artifact set**."* The Statement covers them; only the count "8" and
the census table are short. The site that actually mattered — `legend.py`, operator-facing — is now
site 7 with an owning increment.

**Recommendation.** Replace the threshold *"8 sites reconciled"* with a **derived** one:
*"0 surviving statements of the retired contract under `s19_app/`, `tests/`, `REQUIREMENTS.md` and
`.dev-flow/2026-07-15-batch-47/`, verified by reading each file the sweep returns."* A fixed integer will
be wrong again — this is the second revision in a row where it was a lower bound. Note also
`prototypes/legend_n8.*` (3 files) and `prototypes/screen_upgrades.HANDOFF-PLAN.md` carry it; those are
KEPT-by-operator-decision prototypes, **out of scope** — flagged only so their exclusion is deliberate.

---

## Rev-1 findings: disposition

**rev-1 M-1 — CLOSED, both halves. This is the strongest repair in revision 2.**

*Vacuous predicate:* `LLR-112.2` (`:362`) is re-authored to *"shall not emit a tick whose rendered width
is less than the length of the label it carries"*. That is falsifiable on exactly the case the overlap
predicate could not see. Correct.

*Unbounded widget count:* R-7's aggregation now **bounds the ruler**, which revision 1 could not do.
`LLR-112.1` ticks one per **emitted** run, and `LLR-111.8` caps emitted runs at `(bar_w+1)//2`:

```
  80x24    emitted runs <= 33  ->  ruler ticks <= 34  (was unbounded)
  120x30   emitted runs <= 25  ->  ruler ticks <= 26  (was unbounded)
```

**And the two mechanisms are genuinely distinct — neither acceptance can be satisfied by the other's
behaviour**, which the re-gate asked me to check:

```
  80x24                  bar= 66 | aggregation onset at  34 runs | ruler must DROP from  8 runs
      -> at the aggregation cap (33 runs) the ruler needs 34 ticks in 66 cols = 1.9 cols each -> ALL elided
  120x30 (R-7 widened)   bar= 50 | aggregation onset at  26 runs | ruler must DROP from  6 runs
      -> at the aggregation cap (25 runs) the ruler needs 26 ticks in 50 cols = 1.9 cols each -> ALL elided
```

The ruler's threshold is **~5× lower** than the bar's, so aggregation never rescues the ruler and the
elision path is always exercised. Useful corollary: **`prg.s19` (14 runs) already trips the ruler at both
regimes**, so `TC-B77-08` is reachable on a shipping fixture — no synthetic needed there, unlike
`AT-B77-17`, whose synthetic fixture *is* correctly justified (`:146-148`).

**rev-1 M-2 — CLOSED.** `legend.py:606-614` is site 7 (`:372`) with the correct diagnosis (*"matches no
`LLR-072` grep… C-42 in its purest form"*, `:375`) and an owning increment — Inc-4 (`:506`). The
`AT-B77-07`-passes-green-while-the-screen-lies consequence is stated. Residual is m-2r above.

**rev-1 m-1 — CLOSED.** `LLR-117.2` (`:402`) now forbids *"a text style that inverts foreground and
background"* alongside the foreground-colour clause. That is exactly the `text-style: reverse` hole.

**rev-1 B-1 — addressed in substance.** `LLR-116.6` + `AT-B77-15` exist; all three payload classes are
named (`:263-264`); the **painted-strip** layer is named normatively (`:398`, and standing rule 1 at
`:409` now lists *"Control bytes → the painted strip"*); routing to a non-frozen file is stated. The
false docstring is correctly recorded as P-51 and carried as `C-77-h`. Residual is **B-1r**.

---

## C-27 dual guard — re-verified on the re-cut plan  [CLEAN]

Every file across the re-cut Inc-1…Inc-9, checked against the live `_ENGINE_PATHS`
(`tests/test_engine_unchanged.py:120-130`) and `_ENGINE_TEST_FILES`
(`tests/test_tui_directionb.py:5494-5504`):

```
  Inc-1: 4 files, frozen intersections = NONE
  Inc-2: 3 files, frozen intersections = NONE
  Inc-3: 3 files, frozen intersections = NONE
  Inc-4: 4 files, frozen intersections = NONE
  Inc-5: 5 files, frozen intersections = NONE
  Inc-6: 4 files, frozen intersections = NONE
  Inc-7: 5 files, frozen intersections = NONE
  Inc-8: 3 files, frozen intersections = NONE
  Inc-9: 1 files, frozen intersections = NONE

  TOTAL frozen intersections across the re-cut plan: 0
  tests/test_tui_hostile_map.py in _ENGINE_TEST_FILES: False
```

`s19_app/tui/legend.py` (newly entering at Inc-4) is **not** in `_ENGINE_PATHS` — in scope.
`tests/test_tui_hostile_map.py` is new and non-frozen — `AT-B77-15` is correctly routed.
⚠️ **Inc-5 and Inc-7 sit at exactly 5 files**, the cap. B-1r resolution **option A** adds a file to
Inc-7 and needs the operator's call.

---

## Also clean

The four **new label surfaces** remain free of file-derived text — rev-1's execution stands and R-7/R-8/R-9
add no new label sink: the aggregate disclosure carries a **count** on the region list (`:313`, correctly
reasoned as the same class as R-TUI-073's `N sym` integer), and the CSS widen adds no text. `LLR-111.9`
is a stacking change only. **No secret, credential, token, network call, dependency, external integration,
destructive command, auth flow or deploy surface is touched by revision 2.** No client data leaves the
system; fixtures remain the public `examples/` triple plus in-test builders.

---

## Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Each finding has what · where · why · recommendation | ✓ | B-1r, M-3r, X-1, m-2r |
| Each finding has a severity rating | ✓ | 1 blocker · 1 major · 1 correction · 1 minor |
| No secret values in this output | ✓ | none in scope |
| Verdict explicit | ✓ | §Verdict |
| New tool/integration scope + blast radius | ✓ | **N/A, stated** — none added; blast radius assessed for R-7's new allocation instead (M-3r) |
| `AT-B77-15` verified by execution, not read | ✓ | shipped surface, zero clicks, both regimes — limb 3 GREEN, contradicting the doc |
| Mutation discharge checked per limb | ✓ | recorded mutation executed; inert on limb 3 |
| Width/geometry perturbation measured, not assumed | ✓ | benign vs hostile at both regimes — bar/grid/detail identical |
| Complexity measured at attacker cardinality | ✓ | n=100…5000, both allocation clauses |
| Ruler/aggregation mechanism separation verified | ✓ | thresholds ~5× apart; ruler bound derived |
| Ninth census site found by reading, not grepping | ✓ | `batch-47/06-docs/functionality.md:173` |
| C-27 dual guard re-verified on the re-cut plan | ✓ | 0 intersections, all 9 increments |
| My own prior claim re-tested and corrected | ✓ | X-1 |

---

## Verdict

- [ ] OK to ship
- [x] **OK to proceed to Phase 3 once B-1r is resolved** — one node, no requirement rewrite
- [ ] Block

**Revision 2 is materially better than revision 1** and I want to say so plainly: rev-1 M-1 is closed on
both halves, M-2 and m-1 are closed, and the C-27 boundary is clean across a fully re-cut plan. The
document's own premise table now carries P-51/P-52/P-53 with executed transcripts, which is how the
`legend.py` and elision defects got found at all.

**B-1r must be resolved before Phase 3 opens** — pick option A or B, correct the three verdict/mutation
statements, and it is closed. It is a routing-and-verdict defect on one node, not a design flaw.

**M-3r should land in Phase 1** — one complexity clause on `LLR-111.7`/`.8` and one boundary TC. It is
cheapest here and it is the only genuinely *new* attack surface R-7 creates.

**X-1 must be applied regardless of B-1r's resolution.** It is my error propagating into a normative
document, and it should not survive into Phase 3.

**m-2r is a recommendation.**

**On re-review:** send only the diff to `LLR-116.6`, `AT-B77-15`'s block (`:252-268`), the C-40 register
row `:347`, §5.2's `AT-B77-15` row, `LLR-111.7`/`.8`, and `LLR-112.3`'s threshold. I do not need to
re-read the document.
