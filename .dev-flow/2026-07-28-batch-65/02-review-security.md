# batch-64 — Phase-2 review: SECURITY lane

**Reviewer:** independent security lane (the lane that filed batch-63's `02-review-rescoped-security.md`
and `02-regate-security.md`).
**Base:** `claude/batch-64-addendum-producer-bound` @ `082ada9` == `origin/main`.
**Under review:** `.dev-flow/2026-07-28-batch-65/01-requirements.md` (1213 lines), with `PLAN.md`,
`01-requirements-architect.md`, `01b-qa-catalog.md` as supporting inputs.
**Constraint honoured:** review only. `git status --porcelain` shows `M .dev-flow/state.json`,
`?? .dev-flow/2026-07-26-batch-63/state-at-close.json`, `?? .dev-flow/2026-07-28-batch-65/` and nothing
else; `git diff --numstat origin/main -- s19_app/ tests/` is empty. **Every counterfactual ran in a
`git archive HEAD s19_app tests` export** at
`…/scratchpad/b64sec`, never in this worktree (batch-62's lesson).
Probes bounded: max `R = 512`, max `E = 400`, max `N = 300`; no fixture above 400 candidates was built;
peak allocation negligible (< 2 MB).

---

## 1. BLUF — verdict: **BLOCK**

**One blocker, and it is exactly the failure the review was asked to hunt: `R-TUI-098` over-claims.**
Not on the memory axis — the F2 non-claim is honest, complete, and I clear it without hedging — but on
the **traversal-cost** axis, in the requirement's own first clause. The `R` multiplier the batch exists
to remove is not removed; it **moves** from the candidate loop into `LLR-103.2`'s attribution walk,
where **no acceptance in this document looks**, and where the two geometries `TC-488` / `TC-489`
deliberately pin are the only two that hide it. Executed: **153 600 region comparisons for 300
candidates producing 300 hits** at `R = 512`, and **19 200 at `R = 64`** — bit-for-bit the number §7 T-2
prints as the *defect being removed* (`19200 → 300`).

The blocker is spec-level and fixable inside the current scope: either narrow the requirement text to
what `LLR-103.1` actually delivers and disclose the work-axis residual with the number below, or
re-specify the attribution structure. No new files, no new increments.

| # | finding | class | risk |
|---|---|---|---|
| **S1** | **`R-TUI-098` claims "a single pass whose cost is independent of the declared-region count"; §14's diagram claims `O(V×E·log R + R×3K)`. Both are false** under one broad region + `R−1` narrow ones — a natural operator declaration. Executed `R×N` comparisons. Non-claim (c) disclaims only the *resident* axis. `AT-195`/`TC-488`/`TC-489` count candidate consumption, which stays flat at `N`, so the gate is **GREEN throughout**. | **blocker** | **HIGH** |
| **S2** | `R-TUI-098` and `HLR-103` both say the notice names "**the** affected variants"; `LLR-103.5` caps the list at `ADDENDUM_NOTICE_VARIANTS_MAX = 8` + `+N more`. Above 8, "contributed nothing" and "evidence dropped" stay indistinguishable — the exact confusion US-B64-2 exists to remove. | major | MED |
| **S3** | `AT-197` ("exactly 1 notice line") and `AT-198` arm 1 ("**0** notice lines **anywhere in the report**") are **not decidable by counting `> TRUNCATED:`** — the report already carries three such emitters, and one of them fires on §7 T-5's own `flood = 400` transcript row. Executed. | major | MED |
| **S4** | **§10.5's consumer carry is copied from a stale docstring, not censused.** The two consumers it names are the two that are provably **NOT** at risk; the one that **is** at risk is absent, and so is the in-repo coalescing precedent. Executed. | major | MED |
| **S5** | §10.4 **overstates** the residual (the addendum is not the report's sole evidence sink — executed) and §8.3's alternatives analysis is **incomplete**: it rejects the only alternative it considered on cost, while a **severity-priority admission at the same `O(R × 3K)`** is never considered. Severity is available at the admission point. | major | MED |
| **S6** | §10.3's disclosed `≈ 11.6 kB/region` was measured on a fixture where **no cap fires**, so it carries none of the notice term the fix introduces — up to `≈ 8.3 kB/region` more. A carried number that does not cover the state it is carried into. | minor | LOW |

**Explicitly cleared, by execution, with no finding** — §5:
`LLR-103.2`'s workaround is **SOUND** (0 mismatches over ~150 k swept addresses, 9 adversarial suites +
200 randomised region sets) · the notice **cannot be forged** from document-derived text · the notice
**leaks nothing** the report does not already contain · the **F2 non-claim holds** in full.

---

## 2. S1 — the requirement over-claims on the traversal-cost axis `[blocker · HIGH]`

**What.** `R-TUI-098`'s Statement (§3, `01-requirements.md:243-245`) reads:

> "The declared-region report addendum shall consume the candidate set in **a single pass whose cost is
> independent of the declared-region count**…"

and §14's diagram (`:1155`) formalises it as `O(V x E x log R + R x 3K)`. Under `LLR-103.2`'s adopted
attribution structure — coalesced cover as reject pre-filter, then a **caller-local `bisect` +
prefix-max-of-ends walk** to recover region identity — the per-candidate attribution cost is `O(R)` in
the worst case, so the total is `O(V×E×R)`. The `R` multiplier is not removed; it is **relocated**.

**Where.** `01-requirements.md:243-245` (Statement) · `:251-262` (the four non-claims) · `:400-438`
(`LLR-103.2`) · `:1155-1168` (the diagram) · the acceptance that would have caught it,
`LLR-103.1` `:372-398` and `TC-488` / `TC-489` `:954-964`.

**Why it matters.** Three compounding reasons.

1. **Non-claim (c) does not cover it.** `:259-260` reads *"it does not claim the addendum's resident
   cost is independent of `R` — it is `O(R × 3K)` by construction"*. That disclaims the **resident**
   axis only. The **work** axis is claimed, in the Statement, unqualified.
2. **The gate cannot see it.** `AT-195` / `TC-488` / `TC-489` assert `consumed == N`, where `consumed`
   counts **candidate leaves**. Candidate consumption is flat at `N` in every geometry below, including
   the pathological one. This is `AT-165` again in a new costume: *a predicate that tests something
   adjacent to what its label claims.*
3. **The two pinned geometries are precisely the two that hide it.** `TC-488` pins *all `R` regions
   cover one span* (every region matches → `R` comparisons produce `R` output lines, which is legitimate
   and unavoidable). `TC-489` pins *disjoint, each covers `1/R`* (the prefix-max prunes immediately).
   Neither pins **nested-with-one-broad-region**, which is the natural operator pattern: one
   `whole-cal-area` declaration plus named sub-regions inside it.

**Executed** (`pB_llr1032.py`, LLR-103.2 implemented verbatim, `COMPARISONS` counted at the walk):

```
    geometry pinned by TC-488 (all R regions cover ONE span):
      R=  1  candidates consumed=300  region comparisons=    300  emitted hits=300
      R=  8  candidates consumed=300  region comparisons=   2400  emitted hits=2400
      R= 64  candidates consumed=300  region comparisons=  19200  emitted hits=19200

    geometry pinned by TC-489 (disjoint, each covers 1/R):
      R=  1  candidates consumed=300  region comparisons=    300  emitted hits=300
      R=  8  candidates consumed=300  region comparisons=    562  emitted hits=300
      R= 64  candidates consumed=300  region comparisons=    595  emitted hits=300

    geometry NEITHER TC pins - ONE broad region + R-1 narrow ones below it
    (the natural operator pattern: a whole calibration area + named sub-regions)
      R=   1  candidates consumed=300  region comparisons=    300  emitted hits= 300   comparisons/candidate=1
      R=   8  candidates consumed=300  region comparisons=   2400  emitted hits= 300   comparisons/candidate=8
      R=  64  candidates consumed=300  region comparisons=  19200  emitted hits= 300   comparisons/candidate=64
      R= 512  candidates consumed=300  region comparisons= 153600  emitted hits= 300   comparisons/candidate=512
```

Read the third block against §7 T-2 (`:717-728`), whose headline RED is `300 / 2400 / 19200` at
`R = 1/8/64` and whose GREEN is `300 / 300 / 300`. **The adopted design reproduces the RED figures
exactly, on 300 candidates yielding 300 output lines.** `19200 → 300` is one of the four numbers
`TC-497` (`:266-268`) inspects verbatim in `REQUIREMENTS.md` and the PR body — so the batch would ship
a residual-disclosure gate that asserts the presence of a number the shipped code does not honour on the
work axis.

**Why prefix-max cannot prune here.** `prefix_max[i] = max(ends[0..i])` is non-decreasing, so the walk
stops only when `prefix_max[j] ≤ addr`. One region with a large `end` and a small `start` pins
`prefix_max` above every address for the whole vector, and the walk visits all `R` entries for every
candidate that clears the reject pre-filter. This is inherent to prefix-max attribution, not an
implementation slip.

**Attacker model, stated precisely.** `R` is **operator**-supplied (§2.4 A-2, and §10.3 `:1033`), so the
attacker does not choose the geometry. The attacker chooses the **addresses** — `V×E` of them, all three
classes document-derived (`changes/apply.py:363`, `changes/check.py:399`). The operator needs to declare
exactly **one** enclosing region for the attacker to pay `R` comparisons per candidate. This is not a
privilege escalation and not a memory regression (the resident bound `O(R×3K)` still holds and I confirm
it) — it is **the requirement asserting a bound the implementation does not provide, with a gate
structurally unable to falsify it.**

**Recommendation (spec-level, in scope, choose one).**

- **(a) — narrow the claim, minimum fix.** Amend `R-TUI-098`'s first clause to
  *"…shall consume the candidate set in a single pass whose **candidate consumption** is independent of
  the declared-region count…"*, correct §14's diagram to `O(V×E·(log R + A) + R×3K)` where `A` is the
  attribution walk length, and **add non-claim (e)**: *"it does not claim the addendum's total work is
  independent of `R` — recovering region identity for a candidate inside an enclosing region costs
  `O(R)` in the worst case; executed **153 600 region comparisons for 300 candidates at `R = 512`**,
  and **19 200 at `R = 64`**, i.e. §7 T-2's RED figures on the work axis."* Carry it to
  `BACKLOG-CODE.md` as its own named axis, and add the number to `TC-497`'s verbatim set.
- **(b) — keep the claim, fix the structure.** Replace prefix-max attribution with an
  output-sensitive interval structure (`O(log R + matches)`), and add a **third geometry** to `TC-488`'s
  family — one enclosing region plus `R−1` narrow ones — with an assertion on **region comparisons**,
  not candidate consumption. `AT-195`'s counting iterable cannot express this; it needs a second counter
  at the attribution call.

**Either way, one fold is mandatory:** the geometry above must become a pinned fixture. A residual that
no fixture exercises is how it comes back.

---

## 3. Major findings

### S3 — the notice predicates are not decidable as written `[major · MED]`

**What.** `AT-197` (`:775-776`) requires *"exactly **1** notice line for the `change-file issue` class"*;
`AT-198` arm 1 (`:777`) requires *"class **total** `≤ K` → **0** notice lines **anywhere in the
report**"*. The report already emits `> TRUNCATED:` lines from three unrelated sites.

**Where.** `report_service.py:1134` (`_declaration_error_lines`, per-variant issue cap) · `:1383`
(modified-region cap) · `:1403` (hexdump byte-budget). Executed census:

```
    report_service.py:1134: f"> TRUNCATED: {omitted} of {omitted + MAX_REPORT_ISSUES_PER_VARIANT} "
    report_service.py:1383: put([f"> TRUNCATED: {text}.", ""])
    report_service.py:1403: out.extend([f"> TRUNCATED: {text}.", ""])
```

and their firing conditions against the spec's **own** §7 T-5 fixture (`pC_notice.py` / follow-up):

```
  :1134  fires when ONE variant carries > 200 change+check issues
  :1383  fires when ONE variant has > 128 modified regions
  :1403  fires when a hexdump block does not fit REPORT_MAX_TOTAL_BYTES=2097152

  flood=199  addendum class total=201  v1 issues=199  :1134 fires=False  pre-existing "> TRUNCATED:" lines=0
  flood=200  addendum class total=202  v1 issues=200  :1134 fires=False  pre-existing "> TRUNCATED:" lines=0
  flood=201  addendum class total=203  v1 issues=201  :1134 fires=True   pre-existing "> TRUNCATED:" lines=1
  flood=400  addendum class total=402  v1 issues=400  :1134 fires=True   pre-existing "> TRUNCATED:" lines=1
```

**Why it matters.** §7 T-5's third transcript row is `syntax= 400`. At that row a correct implementation
produces **two** `> TRUNCATED:` lines, one of which is not the addendum's. `:1383` and `:1403` fire on
axes the AT fixture does not control at all, so the "0 anywhere" arm is not merely fragile — it is
**not a function of the addendum**. This is the control that discharges US-B64-2 and F1's residual;
it must not be decidable by grep.

**Recommendation.** Amend `AT-197` / `AT-198` to bind the predicate to
`ADDENDUM_TRUNCATION_NOTICE_FMT`'s **rendered shape**, matched **within the `## Addendum: declared
regions` section only** — e.g. count lines matching
`^> TRUNCATED: (?:modification|change-file issue|check-file issue) hits in this region were capped at`
between the addendum heading and the next `^## `. Record in §12 that three pre-existing `> TRUNCATED:`
emitters exist at `:1134` / `:1383` / `:1403` so the next reader does not re-derive it. Add a positive
control: a fixture that fires `:1134` **and** no addendum cap must still read **0** addendum notices.

### S2 — "the affected variants" vs a cap of 8 `[major · MED]`

`R-TUI-098` (`:248-249`) and `HLR-103` (`:277-278`) both promise the notice names *"the affected
variants"*. `LLR-103.5` (`:516-518`) truncates at `ADDENDUM_NOTICE_VARIANTS_MAX`; §8.1 sets it to 8;
`TC-490` (`:359-360`) accepts `+N more`. Executed:

```
    affected= 8  notice variants field -> v1, v2, v3, v4, v5, v6, v7, v8
    affected= 9  notice variants field -> v1, v2, v3, v4, v5, v6, v7, v8, +1 more
    affected=20  notice variants field -> v1, v2, v3, v4, v5, v6, v7, v8, +12 more
```

**The cap itself is sound** and I endorse it — §8.2 (`:846-848`) is right that an uncapped list
reintroduces a `V` term into the very bound `LLR-103.3` establishes, and 8 is a reasonable value. The
defect is the **statement**, which promises more than the LLR delivers, in the requirement text that
ships to `REQUIREMENTS.md`. For `v9…vN` the operator is left with exactly the ambiguity US-B64-2
(`:174`) exists to remove.

**Recommendation.** Amend both Statements to *"…and **up to `ADDENDUM_NOTICE_VARIANTS_MAX` of** the
affected variants, with an explicit count of the remainder"*, and record the residual in
`R-TUI-098`'s "does NOT claim" paragraph as **(f)**: *above `ADDENDUM_NOTICE_VARIANTS_MAX` affected
variants the notice states how many were not named but not which.* One clause each; no fixture change —
`TC-490` already covers the behaviour, only the claim is wrong. Also pin the **selection order** of the
named 8 (first-in-traversal-order is fine, but it must be stated, or the list is non-deterministic
across a re-ordered manifest).

### S4 — §10.5's consumer carry is copied, not censused `[major · MED]`

**What.** §10.5 (`:1047-1056`) states the overlap defect's blast radius as:

> "the same latent defect exists for **every other consumer** — `validation/engine.py` and
> `tui/hexview.py`, named in `range_index.py`'s own `Used by` docstrings (`:59-60`) — and whether
> *their* range sets can overlap is **unverified by this batch**… **This is the highest-value thing
> batch-64 found that batch-64 is not fixing.**"

The list is the `Used by:` block of a docstring. It is neither complete nor correct. Executed census
(`rg` over `s19_app/`, 10 modules import or re-export the primitives) plus per-consumer provenance:

| consumer | range set | overlap possible? | evidence |
|---|---|---|---|
| `validation/engine.py:60` | `s19_ranges = primary_file.ranges` | **NO — sound** | provenance `load_service.py:60` → `core.py:496-514 get_memory_ranges`, which closes a range at the first non-consecutive key of a sorted unique-key dict ⇒ strictly increasing, non-adjacent, disjoint **by construction** |
| `tui/hexview.py:84/113/141` | — | **N/A — not a consumer** | pure re-export facade; `_build_sorted_range_index(` appears **1** time, inside the wrapper. It builds no range set |
| `tui/app.py` ×6, `compare_service.py:297`, `diff_report_service.py:856` | `LoadedFile.ranges` / one range | NO | same invariant |
| `operations/crc.py:1165` | `working_ranges`, mutated in the loop | NO | `_extend_ranges` (`crc.py:1033-1060`) merges on insert and documents the invariant |
| `screens_directionb.py:1889` | merged band runs | NO | runs are documented and constructed disjoint |
| `services/report_filter.py:737` | a2l+mac `(addr, addr+extent)` — **overlaps freely** | **already handled** | `build_sorted_range_index(_merge_ranges(ranges))` — **the in-repo coalescing precedent `LLR-103.2` reinvents and does not cite** |
| **`changes/apply.py:465` `_linkage_index`** (also `check.py:293-294`) | A2L tag ranges `(addr, addr+length)` | **YES — live** | see below |

Executed, real functions, real overlap:

```
E1  apply.py::_linkage_index over A2L tag ranges - CAN the set overlap?
    linkage source triples: [(4096, 36864, 'BIG_ARRAY'), (8192, 8208, 'INNER')]
    addr=0x5000  probe=(False, None)  truth=['BIG_ARRAY']  WRONG
    addr=0x2008  probe=(True, 'INNER')  truth=['BIG_ARRAY', 'INNER']  ok

E2  report_filter.py:737 - the in-repo COALESCE precedent the spec does not cite
    _merge_ranges( [(4096, 36864), (8192, 8208)] ) -> [(4096, 36864)]
```

and the disjointness proof for `validation/engine.py`, over real fixtures including the one named for
this exact hazard:

```
  parsed 9 real .s19 fixtures | range sets with an overlap or out-of-order pair: 0
  case_03_OVERLAPPING_RECORDS: 3 ranges, overlapping pairs=0, sorted=True
  case_08_heavy_fragmentation: 801 ranges, overlapping pairs=0, sorted=True
  synthetic through the real function: keys [0,1,2,10,11,500] -> [(0,3),(10,12),(500,501)]
    disjoint=True sorted=True
```

(`case_03_overlapping_records` yields disjoint **ranges** because `get_memory_map()` is a dict —
overlapping S-records collapse onto unique address keys.)

**Why it matters (security, not bookkeeping).** §10.5 is the batch's own escalation of the highest-value
thing it found. As written it points a future batch at two places where there is nothing to fix and away
from the one place where there is. `apply.py::_first_intersecting_symbol` (`:470-519`) is a **second,
local copy of the primitive's one-candidate shape**, so an unfreeze-and-fix of `range_index.py` would
**not** repair it. Its docstring (`:491-496`) already concedes *"overlapping declared ranges may resolve
to the nearest-start match only — acceptable for an informative-only annotation"*, which is a defensible
call for `linkage_symbol`; the point is that §10.5 does not know it exists.

**Recommendation.** Replace §10.5's consumer sentence with the executed census above. State plainly:
`validation/engine.py` and `tui/hexview.py` are **cleared** (with the `get_memory_ranges` structural
argument and the facade fact); the live item is `changes/apply.py::_linkage_index` /
`_first_intersecting_symbol` over A2L tag ranges, which carries its **own** copy of the defect and is
therefore **not** covered by a `range_index.py` unfreeze; and cite `report_filter.py:737` as the
existing in-repo precedent for `LLR-103.2`'s coalescing step. Carry the `apply.py` item to
`BACKLOG-CODE.md` at **MED**, not as an unverified blanket.

### S5 — §10.4 overstates the residual; §8.3 never considers the cheap prevention `[major · MED]`

**What (part 1 — the overstatement).** §10.4 (`:1038-1045`) says the attacker's 200
`CHG-ADDRESS-SYNTAX` warnings evict the ERROR-severity `CHG-COLLISION` from **both** `v2` and `v3`, and
that *"the control is disclosure, not prevention"*. That is true **of the addendum** and materially
incomplete **of the report**: `_declaration_error_lines` (`report_service.py:1053-1140`) renders every
change-file and check-file issue per variant, capped at `MAX_REPORT_ISSUES_PER_VARIANT = 200`
**per variant**. Executed against the spec's own §7 T-5 fixture, through the **shipped** functions:

```
   flood=199  addendum class total=201
      SHIPPED addendum (uncapped)            : CHG-COLLISION lines = 2/2
      batch-64 capped addendum (first K)     : CHG-COLLISION lines = 1/2   <-- the eviction S10.4 describes
      'Declaration errors' sections, all v   : CHG-COLLISION lines = 2/2   pre-existing '> TRUNCATED:' lines = 0

   flood=200  addendum class total=202
      batch-64 capped addendum (first K)     : CHG-COLLISION lines = 0/2
      'Declaration errors' sections, all v   : CHG-COLLISION lines = 2/2   pre-existing '> TRUNCATED:' lines = 0

   flood=400  addendum class total=402
      batch-64 capped addendum (first K)     : CHG-COLLISION lines = 0/2
      'Declaration errors' sections, all v   : CHG-COLLISION lines = 2/2   pre-existing '> TRUNCATED:' lines = 1
```

**In every row of §7 T-5's own transcript the "evicted" collision is still in the report.** The addendum
is a cross-reference view, not the sole evidence sink. That is a genuine mitigation and it belongs in
the residual — and it is directly relevant to the question this lane was asked, *is disclosure
sufficient here*.

**What (part 2 — the case where it is not).** The genuinely-lost case is flood and collision **in the
same variant**, past that variant's own 200-cap:

```
D2  one variant, 400 syntax warnings then 1 CHG-COLLISION (index 400):
      Declaration errors: CHG-COLLISION rendered = 0   '> TRUNCATED:' lines = 1
      capped addendum   : CHG-COLLISION rendered = 0
```

Both sinks drop it, two notices fire, and **neither names a severity** — the operator learns "evidence
was cut" but not "an ERROR was cut". *That* is what the attacker still achieves after this change:
suppression of the **severity signal**, not of the evidence's existence.

**What (part 3 — §8.3's incomplete alternatives).** §8.3 (`:853-859`) justifies "bound + disclose" by
rejecting exactly one alternative: a per-`(region, class, **variant**)` budget, at `R × 3K × V`. A
cheaper one exists and is not considered:

```
D3  ValidationIssue.severity = <ValidationSeverity.ERROR: 'error'>  -> .value = 'error'
```

Severity is on the object at the admission point. Admitting the `K` **highest-severity** candidates per
`(region, class)` and emitting them in document order is still `O(R × 3K)` resident, still a
**subsequence** of the shipped sequence — so `LLR-103.4`'s byte identity below the bound is untouched,
because below the bound nothing is evicted at all. This is **prevention at the specced cost**, and the
document rejects prevention without having priced it.

**Recommendation (three folds, all spec-level).**
1. Amend §10.4 to state the executed mitigation: the addendum's eviction does **not** remove an issue
   from the report while that variant stays under `MAX_REPORT_ISSUES_PER_VARIANT`; the joint-loss case
   is flood + collision in one variant, and both notices fire there.
2. Add the **dropped-severity histogram** to `ADDENDUM_TRUNCATION_NOTICE_FMT` — one extra counter per
   `(region, class, severity)`, three ints per region, **no new resident term** — so the notice reads
   `… 2 more not listed (1 error, 1 warning; variants affected: v2, v3)`. This is the smallest change
   that converts "evidence was cut" into "an ERROR was cut" and it is the honest minimum for an
   evidentiary document. Extend `AT-197`'s triple to a quadruple.
3. Record severity-priority admission in §8.2's alternatives matrix with its real cost (`R × 3K`,
   subsequence-preserving), and state why it is or is not chosen. Rejecting it is fine; rejecting it
   silently is not.

### S6 — §10.3's per-region figure does not cover the state the fix creates `[minor · LOW]`

§10.3 (`:1031`) discloses `≈ 11.6 kB/region` at `K = 200`, sourced from §7 T-3 (architect §7.6c), a
fixture on which **no cap fires** and therefore **no notice is built**. The notice term
`LLR-103.3` counts (`:448`) is `R × 3 × ADDENDUM_NOTICE_VARIANTS_MAX` variant identifiers, each
`md_safe`'d at `REPORT_CELL_CHARS`. Executed:

```
    REPORT_CELL_CHARS=512  worst-case escaped id len=1024
    worst-case notice line  ~    8329 chars
      R=    1 -> notice text alone ~     0.02 MB   (hit lines at K=200, ~90 B/hit:     0.05 MB)
      R=  128 -> notice text alone ~     3.20 MB   (hit lines at K=200, ~90 B/hit:     6.91 MB)
      R= 5000 -> notice text alone ~   124.94 MB   (hit lines at K=200, ~90 B/hit:   270.00 MB)
```

The notice is **not** the dominant term — the hit lines are — so this is LOW and I do not press it. But
the disclosed number understates the capped-and-noticed case by roughly `+8.3 kB/region`, and §10.3 is a
residual the batch is carrying forward as a *number*. **Recommendation:** state the figure as
`≈ 11.6 kB/region with no cap firing, ≈ 20 kB/region with all three caps firing at
ADDENDUM_NOTICE_VARIANTS_MAX`, or re-derive at Inc-2. One line.

---

## 4. The F2 non-claim — answered plainly, no hedge

**The F2 non-claim holds. It is honest and it is complete on the axis it addresses. F2 has nothing to
attach to.** I looked for a closure claim in five places and found none:

| where I looked | what it says | verdict |
|---|---|---|
| `R-TUI-098` Statement (`:243-249`) | bounds *"its own resident allocation"*, scoped to the addendum | no whole-report claim |
| `R-TUI-098` non-claim (a) (`:252-256`) | explicitly *"does not claim the project report's resident-memory exhaustion axis is closed"*, with `988 B/entry`, `×1.68`/`×1.81`, `×1.94` and their lane provenance | **an explicit disclaimer, with numbers** |
| `HLR-103` threshold (`:286-289`) | keys on the marginal-delta doubling ratio and `consumed`, never on whole-report peak | satisfiable |
| §6.2 behavioral row for `AT-194` (`:632`) | *"additional memory **attributable to the addendum**"* | correctly labelled |
| §5.2 (`:609`) | *"Any acceptance keyed to `generate_project_report`'s **whole-report** peak — Unsatisfiable"*, retired **in writing** | the trap is closed |
| §7 T-1 label discipline (`:704-708`) | *"It must **not** be labelled 'report generation is bounded'"*, and retires the per-hit-constant phrasing | explicitly self-policing |
| §10.2 (`:1011-1025`) | restates with both lanes' figures, not averaged, and ends *"batch-64 must not pull it in"* | correct |

This is a materially better document than batch-63's on this axis, and I say so without qualification.
The discipline is exemplary in one place: §7 T-1's *"What the adopted number does NOT establish"*
paragraph pre-empts the exact mislabelling my F2 was filed about.

**The reason S1 is still a blocker** is that the same discipline was applied to the **memory** axis and
not to the **work** axis. The document disclaims resident cost in `R` (non-claim (c)) and asserts work
cost independent of `R` in the same breath (the Statement's first clause), with no fixture able to tell
the difference. F2 was *"a gate that cannot pass is the same defect class as one that cannot fail"*.
S1 is the second half of that sentence.

---

## 5. Cleared by execution — no finding

**V1 — `LLR-103.2`'s workaround is SOUND. A lost hit was the thing to fear and it does not happen.**
The spec's construction was implemented verbatim (coalesce `(start, end+1)` → `build_sorted_range_index`
as reject pre-filter → caller-local `bisect` + prefix-max-of-ends → caller-order indices) and swept
against `DeclaredRegion.contains` ground truth:

```
B1  SOUNDNESS sweep - adopted structure vs DeclaredRegion.contains
   spec-2.6 nested            swept  4097 addrs  mismatches=0
   equal-start nest           swept  4103 addrs  mismatches=0
   byte-identical dup         swept  4102 addrs  mismatches=0
   caller order reversed      swept  4097 addrs  mismatches=0
   1-byte + enclosing         swept  4097 addrs  mismatches=0
   touching (end+1==start)    swept   518 addrs  mismatches=0
   adjacent inclusive edge    swept   519 addrs  mismatches=0
   disjoint                   swept  4227 addrs  mismatches=0
   zero-width at 0            swept     7 addrs  mismatches=0
   randomised 200 sets        swept  124k addrs  mismatches=0
   TOTAL MISMATCHES ACROSS ALL SUITES: 0
```

The `+1` inclusive→half-open conversion is correct at both edges, the coalesced cover rejects only
genuine non-members, the prefix-max walk **enumerates every** matching region (not just the nearest),
and sorting the recovered indices restores the caller's region order that `LLR-103.4` requires. The
`TC-486` / `TC-487` fixtures the spec names are the right ones. **No finding.** The cost of this
soundness is S1.

**V2 — the notice cannot be forged from document-derived text.** §2.4 A-3's claim verified rather than
accepted:

```
C1  '>' in MD_ESCAPE : True      '#' in MD_ESCAPE : True
    variant id that IS a notice line
       escaped -> '\\> TRUNCATED: check-file issue hits in this region were capped at 200; 0 more '
       lines produced=1  notice-shaped lines=1  (1 == no forgery)
    id with CR/LF then a notice
       escaped -> 'v1  \\> TRUNCATED: modification hits'
       lines produced=1  notice-shaped lines=1
    id with linkify+strike
       escaped -> 'v\\*\\_\\[x\\](http:\\/\\/e\\.example)\\~\\~z\\~\\~'
    id with a tab
       escaped -> 'v1 more'
    benign id 'variant_A-1' -> 'variant\\_A-1'   escape artefacts=1
```

`markdown_safety._normalise` (`:111-125`) collapses `\r\n\t` to a space **before** any mode-specific
step, so no file-derived value reaches column 0; `MD_ESCAPE` contains `>` and `#`, so a hostile id
renders `\>` and cannot open a blockquote. `AT-199` / `TC-495` are correctly specified and `A-5`'s
elevation of escaping from a review note to an acceptance is the right call — §2.7's executed
demonstration that a *reference* notice implementation emitted the id **unescaped** is exactly the
evidence that justifies it. **No finding.** (One note for `TC-495`: the benign direction acquires
**1** escape artefact on `variant_A-1` because `_` is in `MD_ESCAPE`. §7's *"a benign variant id renders
with **0** escape artefacts"* is only true for ids with no markdown-significant characters; pick the
fixture id accordingly or the arm false-fails.)

**V3 — the notice leaks nothing the report does not already contain.** Field census of
`ADDENDUM_TRUNCATION_NOTICE_FMT` (§8.1 `:822-826`): `{label}` from a module constant; `{cap}` from a
module constant; `{dropped}` an int; `{variants}` the variant ids. Variant ids **already appear in every
addendum hit line** (`report_service.py:1565/1571/1579`, `(variant {md_safe(result.variant_id, …)})`)
and in every `notes` entry at `:1384` / `:1405`. **No host path, no symbol name, no file path, no
credential** enters the notice — and this is the module where §10.2's sibling posture matters:
`report_service.py:1048` records the deliberate operator ruling that issue *messages* are **not**
path-redacted, and the notice adds **no** new emission site for a message. The `{dropped}` count reveals
a cardinality the attacker authored and the operator's own change document already states. **Not an
amplification vector either:** the variant list is `O(1)` at 8, and the `3R` notice-line multiplier is
the `R` term §10.3 already discloses. **No finding.**

**V4 — no new external surface.** The batch adds four module constants, a coalescing helper, and a
rewritten private producer, all inside `s19_app/tui/services/report_service.py`. It opens no file, no
socket, no subprocess; it adds one **import** of an engine-frozen module. §11's guard census
(`:1080-1088`) is correct: `report_service.py` is absent from `_ENGINE_PATHS`
(`tests/test_engine_unchanged.py:120`) and no report test is in `_ENGINE_TEST_FILES`
(`tests/test_tui_directionb.py:5458-5468`), and the guards diff by `git diff --name-only`, so consuming
a frozen module does not trip them. `range_index.py` is **read-only** in this review and in the plan.
**No finding.**

**V5 — probe discipline.** Every counterfactual ran in a `git archive HEAD s19_app tests` export at
`…/scratchpad/b64sec`. `git diff --numstat origin/main -- s19_app/ tests/` in the worktree is **empty**;
`git status --porcelain` shows only `.dev-flow/` paths. Max `R = 512`, max `E = 400`, max `N = 300`;
the declared-domain large fixture was never built; no `tracemalloc` grid above 400 candidates was run.

---

## 6. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Each finding has what · where · why · recommendation | ✓ | §2 S1, §3 S2–S6 — all four elements each, every `where` a `file:line` |
| 2 | Each finding has a severity rating | ✓ | §1 table — blocker/major/minor × HIGH/MED/LOW |
| 3 | **No secret value appears in this output** | ✓ | no `.env`, key, token or credential read or quoted; the only file contents cited are `s19_app/` source lines, `.dev-flow/` spec lines and synthetic in-memory fixtures |
| 4 | Verdict is explicit and **unconditional** | ✓ | §1 — **BLOCK**. Not conditional on any signature; S1's fold is spec-level and in scope |
| 5 | Q1 — does the F2 non-claim hold? answered plainly | ✓ | §4 — **it holds**, seven locations checked, none over-claims on the memory axis; the over-claim is on the **work** axis (S1) |
| 6 | Q2 — notice as a disclosure surface: leak / amplification / cap / escaping / forgery | ✓ | §5 V2 (forgery **cleared**, executed), §5 V3 (leak + amplification **cleared**, field census), §3 S2 (the cap is sound; the **claim** about it is not) |
| 7 | Q3 — is disclosure sufficient for the eviction residual? | ✓ | §3 S5 — **sufficient for the addendum, and §10.4 overstates the harm** (executed: the collision survives in `_declaration_error_lines` in all three §7 T-5 rows); **insufficient on severity** in the joint-loss case, with the concrete fold |
| 8 | Q4a — `LLR-103.2` workaround audited for soundness | ✓ | §5 V1 — **SOUND**, 0 mismatches over ~150 k swept addresses, 9 adversarial suites + 200 randomised sets, implemented verbatim from the spec |
| 9 | Q4b — does the overlap defect reach `validation/engine.py` / `tui/hexview.py`? | ✓ | §3 S4 — **NO to both**, with the `core.py:496-514` structural argument, 9 real fixtures parsed (0 overlaps, incl. `case_03_overlapping_records`), and the facade fact. The live consumer is `changes/apply.py:465` — executed WRONG result |
| 10 | Q5 — attacker model after the change | ✓ | §2 (attacker owns addresses, operator owns `R`; one enclosing region suffices for `O(R)` per candidate) · §3 S5 (what suppression survives) · §1 |
| 11 | Executed probes paste their **real** output | ✓ | §2 (pB), §3 S3 (pC + follow-up), §3 S4 (pA + E1/E2), §3 S5 (pD), §3 S6 (pC C4), §5 V1/V2 — every block is copied from a run, none reconstructed |
| 12 | Counterfactuals ran in an **export**, never the worktree | ✓ | §5 V5 — `git archive HEAD s19_app tests` → `…/scratchpad/b64sec`; worktree `git diff --numstat origin/main -- s19_app/ tests/` empty |
| 13 | New tool/integration scope + blast radius | ✓ | §5 V4 — none; four constants + one helper + one private producer + one import of a frozen module. No file/socket/subprocess opened |
| 14 | Frozen set untouched | ✓ | §5 V4/V5 — `range_index.py` read only; no production source edited |
| 15 | Prior-lane findings carried, not re-derived | ✓ | F1's residual → §3 S5; F2 → §4 (**cleared**); the intra-class/cross-variant residual → §3 S5 with new executed evidence |
| 16 | Claims corrected where the code contradicted a prior review | ✓ | §3 S5 — my batch-63 framing of the addendum as *the* evidence sink was too narrow: `_declaration_error_lines` renders the same issues. Stated loudly because it **weakens** my own prior finding |

---

## 7. Verdict

- [ ] OK to ship
- [ ] OK to ship with the listed mitigations applied first
- [x] **BLOCK — S1 must be folded into Phase 1 before Phase 3 opens.**

**Unconditional.** No operator signature is requested and none would change this: S1 is a requirement
asserting a bound the design does not provide, which is a Phase-1 defect with a Phase-1 fix, not a risk
to accept.

### Gate conditions

| # | fold | discharges | scope |
|---|---|---|---|
| **G-1** | **`R-TUI-098`'s first clause → "candidate consumption"**, §14's diagram corrected, **non-claim (e)** added with `153 600 comparisons / 300 candidates at R = 512` and `19 200 at R = 64`, carried to `BACKLOG-CODE.md` as its own **work-axis** line, and added to `TC-497`'s verbatim set. **OR** re-specify `LLR-103.2`'s attribution as output-sensitive. | **S1** | spec-level |
| **G-2** | **Add the third geometry** — one enclosing region + `R−1` narrow ones — as a pinned fixture beside `TC-488`/`TC-489`, asserting on **region comparisons**, not candidate consumption. Mandatory under either arm of G-1. | **S1** | spec-level |
| **G-3** | `AT-197`/`AT-198` bind to `ADDENDUM_TRUNCATION_NOTICE_FMT`'s rendered shape **scoped to the addendum section**; record the three pre-existing `> TRUNCATED:` emitters (`:1134`/`:1383`/`:1403`) in §12; add the positive control. | S3 | spec-level |
| **G-4** | `R-TUI-098` + `HLR-103` → *"up to `ADDENDUM_NOTICE_VARIANTS_MAX` of the affected variants"*; add non-claim **(f)**; pin the selection order of the named 8. | S2 | spec-level |
| **G-5** | Replace §10.5's consumer sentence with the executed census of §3 S4: `validation/engine.py` and `tui/hexview.py` **cleared**; `changes/apply.py::_linkage_index` carried at MED with the note that it holds its **own** copy of the defect; cite `report_filter.py:737` as the coalescing precedent. | S4 | spec-level |
| **G-6** | Amend §10.4 with the executed mitigation; add the **dropped-severity histogram** to the notice format and to `AT-197`'s tuple; price severity-priority admission in §8.2's matrix. | S5 | spec-level |

**Non-gating:** S6 (re-derive §10.3's per-region figure with caps firing, or state both) · `TC-495`'s
benign-direction fixture must use an id with no `MD_ESCAPE` character, or the *"0 escape artefacts"* arm
false-fails on `variant_A-1` (executed, §5 V2).
