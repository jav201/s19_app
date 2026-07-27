# batch-64 — Phase 1, QA lane: validation strategy + observable catalog

**Lane:** qa-reviewer, Phase 1. **Base:** `claude/batch-64-addendum-producer-bound` @ `082ada9` ==
`origin/main`. **Artifact language:** English.
**Under design:** US-B64-1 (bound the `_addendum_lines` producer) · US-B64-2 (a truncation notice that
names the cut hit classes and variants).

**Identifier policy for this batch:** this lane allocates **NO** `AT-NNN` / `TC-NNN`. Every observable
below carries a **slug**. The architect lane owns the binding; §9 is the hand-off table.

**Where the numbers come from.** Every transcript in this file was executed against a pristine
`git archive` export of `082ada9` at `C:/Users/jjgh8/AppData/Local/Temp/claude/b64` (batch-62 sec F5:
never take gate evidence from a tree another session is editing). Probe scripts live in the session
scratchpad (`p1_rangeindex.py`, `p2_measure.py`, `p3_marginal.py`, `p4_predicates.py`,
`p5_followups.py`, `p6_edges.py`) and are re-runnable with `python <probe>.py` from that export root.
Ceiling actually used: ≤ 4 000 synthetic entries, peak < 3 MB, four temp report files ≤ 170 kB.
No `examples/` image was read; every fixture is a synthetic in-memory object.

---

## 1. BLUF

**The approved single-pass design is validatable — but not as written.** Four executed findings change
the acceptance set before a line of code exists:

1. **`range_index`'s primitives are UNSOUND as the membership oracle for `DeclaredRegion` as specified.**
   `address_in_sorted_ranges` inspects **one** candidate interval (`bisect_right(starts, addr) - 1`),
   which is correct only over **disjoint** ranges. `options.declared_regions` carries no non-overlap
   constraint, and **overlapping declared regions silently lose hits**. Executed, and the lost hits
   named. The design needs a **merge-then-resolve** step (executed sound over a swept domain, 0
   mismatches); the primitive also returns `bool`, so it can never name *which* region — it can only
   ever be a pre-filter. **This is a design correction, not a test.**
2. **Emission order is pinned by NOTHING today** — not "indirectly via whole-document byte-identity"
   as the brief's own reading proposed. `grep -c "Addendum" tests/goldens/batch35/at055b-project-report.md`
   → **0**. The one whole-document golden contains no addendum section at all. Combined with the
   verified `_addendum_lines` census (**0** direct test references), a structural rewrite has **zero**
   guard. The byte-identity arm must ship a **new** golden that actually contains an addendum.
3. **batch-63's traversal bound `consumed ≤ R × 3K + ε` is NOT re-usable for Option 2 and would
   false-fail a correct fix** — the same C-39 / BLK-4 shape one batch later. A single pass consumes
   `E_total` **once**; the R multiplier disappears, which is the honest property. A *stronger*
   early-exit bound is achievable (executed: `consumed = 200` of `E=4000`) but **only with a
   per-class break**; the naive "break when every bucket is full" never fires, because a class with
   no producers never reaches its cap (executed: `consumed = 4000` of `E = 4000`). The requirement
   must **decide** whether early exit is mandated. If it asserts the bound without mandating the
   design, it false-fails a conforming implementation.
4. **The marginal-cost isolation proposal is SOUND as a doubling ratio between two LARGE `E` points,
   and UNSOUND as a per-hit constant.** Executed both arms — see §8.

Everything else the brief asked for is achievable, and every proposed predicate below was executed
against the shipped tree **and** against seven implementation arms (one correct, six defective) to
confirm it can go RED for the right reason.

---

## 2. Verifications of the brief's own readings (asked for, not assumed)

| brief's statement | verdict | evidence |
|---|---|---|
| "the existing addendum assertions at `tests/test_report_service.py:908,:942-943` and `tests/test_tui_report_seam.py:372` are MEMBERSHIP assertions, not ordering ones" | **CONFIRMED** | `:908` `assert "modification @ 0x1000" in text`; `:942-943` `assert "modification @ 0x2000" in addendum` / `"0x2011" not in addendum`; seam `:372` `assert "modification @ 0x1000" in text`. All `in`/`not in`. |
| "so order is pinned only indirectly via whole-document byte-identity" | **FALSE** | `grep -c "Addendum" tests/goldens/batch35/at055b-project-report.md` → **0**. The AT-055b golden carries no addendum. Order is pinned by **nothing**. |
| emission order = `for result → for summary → (that summary's entry hits, then its issue hits) → then, after every summary, the check-result issue hits` | **CONFIRMED, and it is per-RESULT not per-region-global** | `report_service.py:1561-1583` — `for result:` (col 8) → `for summary:` (col 12) → entries (16) then issues (16) → **then** `for check in result.check_results:` (col 12), still inside `for result`. Executed dump in §3.2. |
| "`_addendum_lines` has 0 direct tests today" | **CONFIRMED** | `grep -rn "_addendum_lines" tests/` → 0 hits. Only `report_service.py:1514/1657/1720` and two docstring references in `report_addendum.py`. |
| "The in-domain maximum is 2 hits per region … a cap of 200 means every in-domain test is green" | **CONFIRMED at the boundary** | executed: at `E = CAP−1 = 199` and `E = CAP = 200` the **shipped** function is GREEN on the bound predicate; it only goes RED at `E = 201`. §5, `OBS-hits-bounded-per-region-class`. |

---

## 3. Executed findings that change the design

### 3.1 F-QA-1 (HIGH) — `address_in_sorted_ranges` loses hits on overlapping declared regions

`s19_app/range_index.py:65-68` takes the **single** interval whose `start` is the greatest `≤ addr`
and tests only that one. Over disjoint ranges that is complete; over overlapping ranges it is a
**silent false negative**.

```
=== P1b: OVERLAPPING declared regions (no non-overlap constraint exists) ===
  addr 0x1000: truth(regions containing)=['outer']            address_in_sorted_ranges(union)=True
  addr 0x1550: truth(regions containing)=['outer', 'inner']   address_in_sorted_ranges(union)=True
  addr 0x1800: truth(regions containing)=['outer']            address_in_sorted_ranges(union)=False   <-- LOST
  addr 0x2000: truth(regions containing)=['outer']            address_in_sorted_ranges(union)=False   <-- LOST

=== P1c: NESTED / equal-start declared regions ===
  addr 0x1050: truth=['wide', 'narrow']   address_in_sorted_ranges(union)=True
  addr 0x1900: truth=['wide']             address_in_sorted_ranges(union)=False                       <-- LOST

=== P1d: can the primitive name WHICH region? ===
  address_in_sorted_ranges returns: bool
  -> no region identity is carried; the addendum needs per-region buckets.
```

The correction, executed sound: **merge** the declared spans into disjoint intervals first, index
those, and use the index only as a **reject filter**; resolve identity separately.

```
=== P1e: MERGED union as a pre-filter (sound?) ===
  merged half-open: [('0x1000', '0x2001')]
  mismatches over swept domain: 0        (swept 0x0F00..0x2100 step 7 against DeclaredRegion.contains)
```

Also executed, the inclusive→half-open conversion the design must carry (`end + 1`):

```
=== P1a: half-open vs inclusive ===
  addr 0x2000: contains=True  naive(start,end)=True  (start,end+1)=True
  addr 0x2010: contains=True  naive(start,end)=False (start,end+1)=True    <-- naive drops the end byte
  addr 0x2011: contains=False naive(start,end)=False (start,end+1)=False
```

**Exposure today: total.** All **33** `DeclaredRegion(...)` constructions in `tests/` are disjoint;
**no test uses overlapping or nested regions**. A `FIX-E`-shaped implementation ships green.

### 3.2 F-QA-2 (MAJOR) — emission order, executed, and unprotected

```
=== P2e: EMISSION ORDER on the shipped producer ===
    '## Addendum: declared regions'
    ''
    '### ord (0x1000-0x2000)'
    '- modification @ 0x1001 (variant v0)'      <- summary 1 entries
    '- modification @ 0x1002 (variant v0)'
    '- issue [S1I] @ 0x1003 (variant v0)'       <- summary 1 issues (INTERLEAVED, per summary)
    '- modification @ 0x1004 (variant v0)'      <- summary 2 entries
    '- issue [S2I] @ 0x1005 (variant v0)'       <- summary 2 issues
    '- issue [CHK] @ 0x1006 (variant v0)'       <- check results, after ALL of that result's summaries
    ''
```

The order is **interleaved per summary**, not class-grouped. A single pass that buckets by class and
concatenates produces `1001,1002,1004 | 1003,1005 | 1006` — a different document. Executed as arm
`FIX-B` in §5.

### 3.3 F-QA-3 (MAJOR) — the traversal bound must be re-derived, not carried

Shipped tree, re-iterable counting fixture (`E = 500`):

```
=== P2c: TRAVERSAL - re-iterable counting fixture, SHIPPED tree ===
  R=1 V=1 E=500: entries consumed = 500   (== R*V*E = 500)
  R=2 V=1 E=500: entries consumed = 1000  (== R*V*E = 1000)
  R=4 V=1 E=500: entries consumed = 2000  (== R*V*E = 2000)
  R=8 V=1 E=500: entries consumed = 4000  (== R*V*E = 4000)
```

Inherited finding 5 re-executed (a one-shot generator is not usable):

```
=== P2d: one-shot generator breaks at R>=2 ===
  one-shot generator, R=2 E=3 -> hit lines rendered = 3 (expected 6)
```

The naive "break when every (region, class) bucket is full" **never fires**, because a class with no
producers never reaches its cap — so a correct-by-memory single pass still walks everything:

```
OBS-traversal-bounded : consumed <= 3*CAP once every bucket is full   (E=4000, R=1)
  SHIP   consumed=4000 -> RED
  FIX-A  consumed=4000 -> RED        <- FIX-A is the memory-correct arm; the bound false-fails it
  FIX-D  consumed=4000 -> RED
```

A **per-class** break is achievable and does bound traversal, measured exactly at `R × CAP`:

```
C. PER-CLASS early exit - is traversal bounded below E?          (E=4000, CAP=200)
  overlapping regions (all cover the same span):
    R=1: consumed=200  of E=4000   (R*CAP+1 = 201)
    R=2: consumed=200  of E=4000   (R*CAP+1 = 401)
    R=8: consumed=200  of E=4000   (R*CAP+1 = 1601)
  DISJOINT regions (each entry lands in exactly one):
    R=1: consumed=200  of E=4000
    R=2: consumed=400  of E=4000
    R=8: consumed=1600 of E=4000
  byte-identity of fix_a2 below the bound: True
```

**Two consequences the requirement owes a decision on.**
(a) `consumed ≤ R × 3K + ε` (batch-63's `TC-441` bound) **false-fails** the memory-correct
Option-2 fix at any `E > 3K` unless per-class early exit is mandated. Do not carry it.
(b) "consumed is independent of R" is true only for **overlapping** geometry (200/200/200) and false
for **disjoint** geometry (200/400/1600). A test asserting R-independence must **fix the geometry in
its fixture** or it false-fails a conforming implementation. This is C-39's failure mode keyed to a
*fixture* rather than to a number, which is why it is easy to miss.

### 3.4 F-QA-4 (MAJOR) — the NEW notice line is an unescaped markdown sink

`md_safe` is applied to `result.variant_id` at every existing hit line. A notice that names variants
is a **new** emission of file-derived text. Executed against a reference notice implementation:

```
=== P6a: a hostile variant_id reaching the NEW notice line ===
  shipped-shape hit line  : '- modification @ 0x1000 (variant v\\*\\_\\[x\\](http:\\/\\/e\\.example)\\~\\~z\\~\\~)'
  NEW notice line         : '- _Truncated at 200 per class: modification (variants v*_[x](http://e.example)~~z~~)._'
  hit line escaped?       : True
  notice escaped?         : False
```

Same class as the hole batch-60 closed (linkify + `~~strike~~` in an audit record). It is an
**acceptance**, not a review note, because the notice is the batch's only new emitted string.

---

## 4. Acceptances KILLED before they were written

| killed candidate | why |
|---|---|
| **"every producing hit class is represented in the rendered region"** (batch-63 `AT-165`) | Tests the concatenation SHAPE, not the evidence. batch-63 measured it GREEN through all three attacks while `CHG-COLLISION` was evicted. Replaced by `OBS-notice-names-cut-classes` + `OBS-notice-names-cut-variants`, whose RED arms are executed in §5. |
| **peak memory or wall time to separate cap-and-break from cap-and-continue** | Measured indistinguishable (19019/19019, 1.00 vs 1.04) in batch-63, re-confirmed here: `FIX-A` and `FIX-D` have identical peaks (21021/21021) and identical bounded output. Only the counting iterable separates them. |
| **any acceptance keyed to `generate_project_report`'s WHOLE-report peak** | Unsatisfiable — the neighbouring tables dominate. Executed: with **no addendum at all**, whole-report peak is 344 231 B at `E=1000` and 669 247 B at `E=2000` (ratio 1.94), for a 48 kB / 94 kB document. D1 cannot make that flat, and R-1 forbids claiming it. |
| **`consumed ≤ R × 3K + ε`** carried from batch-63 `TC-441` | Executed: false-fails the memory-correct single pass (4000 consumed at `E=4000`). §3.3. |
| **`< 1.5` peak-ratio on the R axis**, and its "fix" by widening to 2.0 | Inherited finding 6; not re-proposed. No memory acceptance in this catalog touches the R axis. |
| **a `tracemalloc` acceptance whose fixture is built inside the traced window** | Every memory observable below states the traced window explicitly; every probe here builds its fixture before `tracemalloc.start()`. |
| **"the addendum's marginal cost is ~89 B/hit at the shipped surface"** | Executed and refuted: the shipped-surface delta per hit reads **150.3 / 238.3 / 237.3 / 269.2 B** across the grid — it contains the addendum's *output* and the join/encode terms, not the producer alone. §8. |
| **"a rewrite that keeps the tests green is order-preserving"** | The whole-document golden has **0** addendum bytes (§2). Green proves nothing about order today. |

---

## 5. Observable catalog

`CAP` below means the **constant** the implementation defines (candidate name
`MAX_ADDENDUM_HITS_PER_REGION_CLASS`), never the literal `200`. Every test **imports** it (C-39).
The executed matrix ran with `CAP = 200`.

**Implementation arms used for every RED/GREEN result in this section** (all defined in
`p4_predicates.py` / `p5_followups.py`, all with `_addendum_lines`'s signature):

| arm | what it is |
|---|---|
| `SHIP` | the shipped `_addendum_lines` @ `082ada9` |
| `FIX-A` | correct single-pass, merged-index membership, per-(region, class) bounded buckets, order preserved |
| `FIX-A2` | `FIX-A` + per-class early exit |
| `FIX-B` | single pass, class buckets concatenated → **order changes** |
| `FIX-C` | cap the **output** only (`hits[:CAP]`) — producer still materialises everything |
| `FIX-D` | cap **and continue** — bounded materialisation, unbounded traversal |
| `FIX-E` | `FIX-A` but membership via **raw** `address_in_sorted_ranges` on the unmerged region list |
| `FIX-F` | `FIX-A` but the notice omits the variant names |
| `FIX-G` | `FIX-A` but the notice always names all three classes |

---

### 5.1 `OBS-below-bound-byte-identity` — **mandatory** (US-B64-1 regression arm)

- **Observed:** for inputs at or below `CAP` in every class, the addendum block of the written report
  is **byte-identical** to `082ada9`'s. **Surface:** black-box — drive `generate_project_report`,
  read the file, compare through `tests/conftest.py::canonical_report_bytes` against a committed
  golden.
- **RED mutation:** any change to region ordering, hit ordering, membership semantics, or line
  formatting. Category: **CODE (C-10)**, and it is the only observable that catches a *silent*
  rewrite drift.
- **Executed** (hostile below-bound fixture: overlapping + nested + empty + inclusive-edge regions,
  2 variants, 2 summaries, check results):

```
  SHIP   -> GREEN
  FIX-A  -> GREEN
  FIX-B  -> RED  (first diff at index 3)        <- order
  FIX-C  -> GREEN
  FIX-D  -> GREEN
  FIX-E  -> RED  (first diff at index 5)        <- overlap membership
  FIX-F  -> GREEN
  FIX-G  -> RED  (first diff at index 10)       <- spurious notice below the bound
```

- **Boundary/negative:** the golden fixture is deliberately `E ≤ CAP` in every class, so this
  observable is silent about the cap and loud about everything else. Its negatives (`empty` region →
  `None.`; `issue.address is None` → not a hit; 1-byte-wide region) are executed in §7.
- **Sequencing hazard:** the golden must be **captured on `082ada9` and committed in the first
  increment, before the producer is touched.** A golden regenerated after the fix certifies the fix
  against itself.

### 5.2 `OBS-emission-order-interleaved`

- **Observed:** within one region, hits appear as `for result → for summary → (that summary's entry
  hits, then that summary's issue hits) → after all of that result's summaries, that result's
  check-result issue hits`. **Surface:** white-box over `_addendum_lines` (an explicit expected
  sequence), because the assertion is about order and a golden diff reports it as an opaque byte
  mismatch.
- **RED mutation:** class-bucket concatenation. Category: **CODE (C-10)**.
- **Executed:** `FIX-B` RED at index 3; `SHIP`/`FIX-A` GREEN. Full shipped sequence in §3.2.
- Fold candidate: the architect may bind this and 5.1 to one AT with two TCs. They are listed
  separately because their fixtures and failure reports differ.

### 5.3 `OBS-overlap-membership-preserved`

- **Observed:** an address inside **two** declared regions renders under **both**; an address inside
  a wide region but past a nested region's end still renders. **Surface:** black-box through the file
  (it is an output-content property).
- **RED mutation:** membership via the raw `range_index` primitive over the unmerged region list.
  Category: **CODE (C-10)**, and specifically the code the approved design *names*.
- **Executed** — the exact hits `FIX-E` drops:

```
B. FIX-E (raw address_in_sorted_ranges) - WHICH hit is dropped
  present in SHIPPED, absent from FIX-E:
    - '- issue [S1I] @ 0x1800 (variant v0)'
    - '- issue [S3I] @ 0x2000 (variant v1)'
  present in FIX-E, absent from SHIPPED:      (none)
```

- **Boundary/negative:** equal-start nesting (`wide` and `narrow` both start `0x1000`); an address at
  exactly `region.end` (inclusive) in the **outer** of two overlapping regions; an address one past
  `end` in **both** (must appear in neither).

### 5.4 `OBS-hits-bounded-per-region-class`

- **Observed:** rendered hit lines of one class under one region never exceed `CAP`.
  **Surface:** black-box — count matching lines in the addendum block of the written file.
- **RED mutation:** **INPUT SET (C-31)** — the predicate is green on the shipped code for every
  in-domain input; only `E = CAP + 1` turns it red. This is the single most important C-31 case in
  the batch.
- **Executed:**

```
  --- E=199 ---   SHIP hits=199 notice=False -> GREEN
  --- E=200 ---   SHIP hits=200 notice=False -> GREEN
  --- E=201 ---   SHIP hits=201 notice=False -> RED
  --- E=4000 --   SHIP hits=4000 notice=False -> RED
```

- **Boundary fixtures are mandatory: `CAP−1`, `CAP`, `CAP+1`, and one far-above (`4000`).** The
  `CAP−1` and `CAP` rows are the proof that an in-domain-only test set is vacuous here.

### 5.5 `OBS-interior-no-marker` — the `E == CAP` interior case

- **Observed:** at `E == CAP` exactly, the rendered count is `CAP` **and** no truncation notice is
  present. **Surface:** black-box, same block.
- **RED mutation:** an off-by-one cap check (`>=` vs `>`), i.e. a notice that fires at the boundary.
  Category: **THRESHOLD (C-39)**.
- **Executed:**

```
OBS-interior-no-marker : at E == CAP the count is CAP *and* no notice
  SHIP   hits=200 notice=False -> GREEN
  FIX-A  hits=200 notice=False -> GREEN
  FIX-G  hits=200 notice=True  -> RED
```

- Note the asymmetry that makes this worth its own row: `FIX-G` is **GREEN** on
  `OBS-hits-bounded-per-region-class` at every `E`, including `CAP−1`. Only the conjunction
  *count AND marker-absence* sees it.

### 5.6 `OBS-traversal-R-multiplier-gone` — the B-3(b) closure

- **Observed:** the number of `change_summaries[].entries` elements **consumed** does not grow with
  the declared-region count. **Surface:** white-box TC over `_addendum_lines`, injecting a
  **re-iterable** counting sequence as `ChangeSummary.entries`.
- **RED mutation:** none needed — **the shipped tree is the RED arm**, executed. The category is
  **WRITER/producer**: the observable is a property of the traversal itself, not of any expression
  relating two pure functions.
- **Executed** (`E = 500`, overlapping geometry):

```
OBS-traversal-R-independent : entries consumed does not grow with R
  SHIP   consumed R=1/2/8 -> [500, 1000, 4000]  -> RED
  FIX-A  consumed R=1/2/8 -> [500, 500, 500]    -> GREEN
  FIX-C  consumed R=1/2/8 -> [500, 1000, 4000]  -> RED
  FIX-D  consumed R=1/2/8 -> [500, 500, 500]    -> GREEN
```

- **Fixture constraint (mandatory, or the test false-fails):** the regions must be **overlapping**.
  With disjoint regions a conforming implementation consumes `R × CAP` (executed 200/400/1600), so
  R-independence is false by construction. State the geometry in the test docstring.
- **Does not separate `FIX-D`.** That is 5.7's job, and 5.7 is conditional — so if the requirement
  declines early exit, cap-and-continue is **admitted by design** and the requirement must say so.

### 5.7 `OBS-traversal-early-exit` — **CONDITIONAL on a requirement decision**

- **Observed:** once every region's bucket for a class is full, the walk producing that class stops:
  `consumed_entries ≤ R × CAP + ε`. **Surface:** white-box, same counting instrument.
- **RED mutation:** cap-and-continue (`FIX-D`) and the naive saturation gate (`FIX-A`).
  Category: **WRITER/producer**.
- **Executed:** `FIX-A2` → `consumed = 200` of `E = 4000` (overlapping, any `R`); `200/400/1600` for
  `R=1/2/8` disjoint — exactly `R × CAP`. `SHIP` / `FIX-A` / `FIX-D` → `4000`.
- **The decision the requirement owes:** mandate per-class early exit (then this observable is
  binding and `ε = 1`), or decline it (then **delete this row** — asserting it against a design that
  does not mandate it is precisely batch-63's BLK-4 defect). Do **not** state it as an aspiration.

### 5.8 `OBS-addendum-peak-flat-in-E` — the producer bound, keyed to `_addendum_lines` alone

- **Observed:** `tracemalloc` peak of a `_addendum_lines(regions, results)` call stops tracking
  `V × E`. **Surface:** white-box TC. **Traced window, stated explicitly: `tracemalloc.start()` is
  called AFTER the fixture is fully constructed and the only statement inside the window is the
  `_addendum_lines` call** (inherited finding 7).
- **RED mutation:** bounding the output without bounding the producer (`FIX-C`).
  Category: **CODE (C-10)**.
- **Executed** (`E` doubling 1000 → 2000, `R = V = 1`):

```
OBS-marginal-flat (white-box) : peak(_addendum_lines) stops tracking V x E
  SHIP   peak E=1000 93940  E=2000 186300  ratio 1.98
  FIX-C  peak E=1000 87529  E=2000 171857  ratio 1.96      <- output-only cap: still RED
  FIX-A  peak E=1000 21021  E=2000 21021   ratio 1.00
  FIX-D  peak E=1000 21021  E=2000 21021   ratio 1.00
```

- **Threshold, derived by execution, not chosen:** the two populations are `{1.96, 1.98}` and
  `{1.00}`. A `< 1.30` threshold sits 0.30 above the conforming population and 0.66 below the
  offending one. Supporting product law and the per-hit constant, with inputs printed:

```
=== P2a: product law, fixture built OUTSIDE the traced window ===
axis                      lo        hi   ratio
E 500->1000 (R1V1)     46916     94000    2.00
V 1->2  @E500 (R1)     46804     93944    2.01
R 1->2  @E500 (V1)     46804     89403    1.91

=== P2b: B/hit constant ===
  R=1 V=1 E=1000  hits=1000 peak=93944  B/hit=93.9
  R=1 V=1 E=4000  hits=4000 peak=373136 B/hit=93.3
  R=2 V=2 E=1000  hits=4000 peak=356371 B/hit=89.1
```

- **The R axis is deliberately absent** (inherited finding 6): a per-region bucket set materialises
  `R × CAP` by construction, so peak is linear in R for any conforming fix.

### 5.9 `OBS-marginal-cost-flat` — the shipped-surface (Layer B) corroboration

- **Observed:** at the shipped surface, the **difference** in whole-report `tracemalloc` peak between
  an identical fixture with `options.declared_regions` non-empty and empty stops doubling when `E`
  doubles. **Surface:** black-box — two `generate_project_report` calls, delta of peaks.
- **RED mutation:** none needed — the shipped tree is RED. Category: **WRITER/producer**.
- **Executed, both arms** (see §8 for the full grid and the caveat):

```
  SHIPPED producer :  delta(E=2000)=474535 -> delta(E=4000)=1076391   ratio 2.27   RED
  BOUNDED producer :  delta(E=2000)= 52631 -> delta(E=4000)=  52759   ratio 1.002  GREEN
```

- **Threshold derived by execution: `< 1.30` on the `E: 2000 → 4000` delta ratio.** Do **not** key it
  to `E = 500` (§8) and do **not** express it as B/hit (§4, killed).
- **Label discipline (R-1):** this observable's label is *"the addendum's marginal cost stops tracking
  V×E"*. It must **not** be labelled *"report generation is bounded"* — with no addendum at all the
  whole-report peak still doubles (344 231 → 669 247, ratio 1.94).

### 5.10 `OBS-cap-constant-quoted`

- **Observed:** every test names the constant, never `200`. **Surface:** inspection + the tests'
  own imports.
- **RED mutation:** **THRESHOLD (C-39)** — change the constant's value in the module; a test carrying
  the literal goes red for the wrong reason, a test importing it stays green.
- **Validation method:** inspection at the review gate + one executed check that the suite is green
  after the constant is temporarily re-valued (`CAP = 37`) with fixtures derived from it.

### 5.11 `OBS-notice-names-cut-classes` (US-B64-2)

- **Observed:** when a class is truncated under a region, the rendered notice **names that class**.
  **Surface:** black-box, the notice line in the written file.
- **RED mutation:** the shipped tree (no notice at all) and `FIX-C` (a notice that cannot name what
  it cut, because it sliced a merged list). Category: **CODE (C-10)** and **WRITER/producer**.
- **Executed** on the batch-63 attack fixture (`v1` floods modifications *and* change-issues; `v2`
  contributes one `CHG-COLLISION`; `v3` contributes one check-issue that is **not** cut):

```
  SHIP   -> RED   (no notice)
  FIX-C  -> RED   - _Truncated at 200 per class: modification (variants ?)._
  FIX-A  -> GREEN - _Truncated at 200 per class: modification (variants v1,v2); change-issue (variants v1,v2)._
```

### 5.12 `OBS-notice-names-cut-variants` (US-B64-2)

- **Observed:** the notice names the **variant ids** whose hits were dropped — the control that
  inherited finding 2 says is the real one, because per-class capping only moves the selectability
  to the intra-class / cross-variant axis.
- **RED mutation:** a notice that names classes only. Category: **CODE (C-10)**.
- **Executed:** `FIX-F -> RED  - _Truncated at 200 per class: change-issue; modification._`
- **Boundary:** exactly one variant cut (the notice must not render a spurious list separator); a
  variant that contributed hits **and** was cut (must appear); a variant that contributed hits and was
  **not** cut (must not appear).

### 5.13 `OBS-notice-absent-for-uncut-class` — the **P-6 positive control**

- **Observed:** a class that produced hits and was **not** truncated does **not** appear in the
  notice; and no notice is rendered at all when nothing was cut.
- **Why this row exists:** batch-63's `AT-193b` was built only from cases its detector already
  caught, so it certified a completeness the detector lacked. This row is shaped to the **RULE**
  ("the notice names exactly the classes that were cut"), so it carries the **false-positive**
  direction that every other notice row is blind to.
- **RED mutation:** a notice that always names all three classes. Category: **CODE (C-10)**.
- **Executed:** `FIX-G` — RED on this row and on `OBS-interior-no-marker`, while **GREEN** on
  `OBS-notice-names-cut-classes`, `OBS-notice-names-cut-variants`, `OBS-hits-bounded-per-region-class`
  (at every `E` including `CAP−1`), `OBS-traversal-R-multiplier-gone` and `OBS-addendum-peak-flat-in-E`.
  Six of nine other observables do not see it.

```
  FIX-G  -> RED   - _Truncated at 200 per class: modification (variants v1,v2); change-issue (variants v1,v2); check-issue (vari…
                                                                                                              ^ never cut
```

### 5.14 `OBS-notice-escapes-file-derived-text`

- **Observed:** variant ids (and any other file-derived text) reaching the notice are escaped through
  `md_safe` with an explicit `limit`, exactly as the hit lines are.
- **RED mutation:** a raw f-string in the notice. Category: **WRITER/producer**.
- **Executed:** §3.4 — the reference notice emits
  `v*_[x](http://e.example)~~z~~` unescaped while the neighbouring hit line on the same fixture emits
  `v\*\_\[x\]\(http:\/\/e\.example\)\~\~z\~\~`.
- **Negative direction:** a benign variant id must render **without** escape artefacts (otherwise the
  test passes for the wrong reason on any input).

### 5.15 `OBS-notice-reaches-the-file` — Layer B for US-B64-2

- **Observed:** the notice is present in the report **on disk**, and in the report generated by
  driving the shipped TUI report dialog with a declared region.
- **RED mutation:** **INPUT SET (C-31)** — a notice produced by `_addendum_lines` but dropped by the
  `emit()` byte-budget path in `generate_project_report` (`report_service.py:1720`) would be invisible
  to every white-box row above.
- **Validation method:** test. The seam precedent already exists — `tests/test_tui_report_seam.py`
  drives `ReportViewerScreen` with `"calzone,0x1000,0x10FF"` and reads the written file.

### 5.16 `OBS-residual-stated-with-numbers` — inspection, not a test (R-1)

- **Observed:** `REQUIREMENTS.md`, the requirement text, and the PR body state that batch-64 does
  **not** close the report memory-exhaustion path, and carry the measured residual: the neighbouring
  `_modifications_lines` / `_checklist_lines` at **988 B/entry**, and the whole-report peak measured
  here at 344 231 B (`E=1000`) → 669 247 B (`E=2000`), **ratio 1.94, with no addendum present at all**.
- **Validation method:** inspection at the merge gate. If the requirement never asserts closure, the
  security lane's F2 has nothing to attach to.

---

## 6. Test-file homes

`_ENGINE_TEST_FILES` (frozen, from `tests/test_tui_directionb.py:5458-5468`) is
`test_core_srecord_validation.py`, `test_hexfile.py`, `test_range_index.py`, `test_validation_a2l.py`,
`test_validation_engine.py`, `test_validation_mac.py`, `test_tui_a2l.py`, `test_tui_mac.py`,
`test_color_policy_round_trip.py`. **None is a report test — this batch routes around the freeze with
no exception needed.** `s19_app/range_index.py` is engine-frozen too; the design **consumes** it and
must not edit it (the merge helper lives in `report_service.py` / a new module, never in
`range_index.py`).

| what | home | why |
|---|---|---|
| golden bytes for 5.1 | **new** `tests/goldens/batch64/addendum-below-bound.md` | mirrors `tests/goldens/batch35/`; `at055b-project-report.md` carries **0** addendum bytes and must not be re-baselined for this |
| 5.1, 5.3, 5.4, 5.5, 5.11–5.14 (black-box, through the file) | **new** `tests/test_report_addendum_bound.py` | keeps a ~90-test, 1000+-line `test_report_service.py` unperturbed and makes the batch diff reviewable; `tests/test_report_addendum.py` is the `DeclaredRegion` dataclass's own file and stays that |
| 5.2, 5.6, 5.7, 5.8, 5.10 (white-box over `_addendum_lines`) | same new file, in a clearly separated `# --- white-box` section | the counting instrument and the traced window are mechanism tests; keeping them beside their black-box twins preserves AT/TC adjacency |
| 5.9 (marginal delta at the shipped surface) | same new file, marked `@pytest.mark.slow` | four `generate_project_report` runs at `E ≤ 4000`; measured ~2 s, but it is a resource measurement and `-m "not slow"` must stay usable |
| 5.15 (TUI seam) | **extend** `tests/test_tui_report_seam.py` beside the existing declared-region drive at `:355-372` | that is where the shipped surface already is; adding a second file that boots the app costs a Textual pilot for nothing |
| the four existing addendum tests (`test_report_service.py:896-960`) | **unchanged** | they are the pre-existing regression net; if the rewrite breaks one, that is signal, not maintenance |

---

## 7. Fixture plan

### 7.1 `FIX-GOLD` — the below-bound hostile fixture (drives 5.1, 5.2, 5.3)

Deliberately shaped so a naive rewrite fails on it. Executed shipped rendering (this **is** the
golden's addendum block):

```
   0 '## Addendum: declared regions'
   1 ''
   2 '### outer (0x1000-0x2000)'
   3 '- modification @ 0x1001 (variant v0)'
   4 '- modification @ 0x1550 (variant v0)'
   5 '- issue [S1I] @ 0x1800 (variant v0)'
   6 '- issue [S2I] @ 0x1555 (variant v0)'
   7 '- issue [CHK] @ 0x1560 (variant v0)'
   8 '- issue [S3I] @ 0x2000 (variant v1)'
   9 '- issue [CHK2] @ 0x1000 (variant v1)'
  10 ''
  11 '### inner (0x1500-0x1600)'
  12 '- modification @ 0x1550 (variant v0)'
  13 '- issue [S2I] @ 0x1555 (variant v0)'
  14 '- issue [CHK] @ 0x1560 (variant v0)'
  15 ''
  16 '### empty (0x9000-0x9010)'
  17 'None.'
  18 ''
  19 '### edge (0x3000-0x3010)'
  20 '- modification @ 0x3010 (variant v0)'
  21 '- modification @ 0x3000 (variant v1)'
  22 ''
```

Properties it carries: **overlapping** (`outer` ⊃ `inner`) · **empty** region (`None.`) ·
**inclusive end** (`0x3010` in `edge`) · **two variants** in one region · **two summaries** in one
variant (the interleaving at indices 3-6) · **check results** (indices 7, 9, 14) · a hit that is in
**both** regions (`0x1550`, `0x1555`, `0x1560`) · a hit past the nested region's end but inside the
outer (`0x1800`, `0x2000` — the two `FIX-E` drops).

### 7.2 Boundary fixtures (drive 5.4, 5.5)

`E ∈ {CAP−1, CAP, CAP+1, 4000}`, all entries in one region, `R = V = 1`. `E` is **derived** from the
imported constant (`CAP - 1`, `CAP`, `CAP + 1`), never written as `199 / 200 / 201`.

### 7.3 `FIX-FLOOD` — the hostile eviction fixture (drives 5.11, 5.12, 5.13)

`v1` mints `CAP + 100` modifications and `CAP + 50` `CHG-ADDRESS-SYNTAX` change-issues; `v2`
contributes exactly one modification and one ERROR-severity `CHG-COLLISION`; `v3` contributes one
check-issue that is **never** cut. This is inherited finding 2's executed attack, rebuilt.
Expected notice on a conforming fix: names `modification` and `change-issue`, names `v1` and `v2`,
and **does not name** `check-issue`.

### 7.4 Traversal fixtures (drive 5.6, 5.7)

A **re-iterable** counting sequence (`__iter__` re-yields from a stored list and increments a counter;
`__len__` delegates) substituted for `ChangeSummary.entries`. A one-shot generator is executed-broken
(§3.3). Two geometries, both required and both named in the test:
**overlapping** (all `R` regions cover one span) and **disjoint** (each region covers `1/R` of the
address space).

### 7.5 Memory fixtures (drive 5.8, 5.9)

`E ∈ {1000, 2000}` for 5.8 and `E ∈ {2000, 4000}` for 5.9, `R = V = 1`, all entries in-region.
**Constructed before `tracemalloc.start()` in every case.** For 5.9, each of the four
`generate_project_report` runs uses its **own freshly built** `variant_results` (a `Counting`-free
plain list) so no arm inherits another's allocations.

### 7.6 Negative / empty domain (executed against the shipped function; the fix must match)

```
  no regions at all        shipped=['## Addendum: declared regions', '']
  regions, no variants     shipped=[..., '### z (0x1000-0x1FFF)', 'None.', '']
  issue.address is None    shipped=[..., '### z (0x1000-0x1FFF)', 'None.', '']
  region is 1 byte wide    shipped=[..., '- modification @ 0x1000 (variant v0)', '']
```

`FIX-A` reproduces all four exactly (`fix_a == shipped -> True` in each). A hostile-name region
(`DECLARED_REGION_NAME_MAX` truncation) is already covered by
`tests/test_report_addendum.py` and `tests/test_report_field_census.py:187` — not re-created here.

---

## 8. Verdict on the marginal-cost isolation proposal

**Proposal (from the brief):** *measure the addendum's MARGINAL cost by difference — identical fixture
with `options.declared_regions` non-empty vs empty — and assert the delta stops tracking `V×E`.*

**Verdict: ADOPT, but only as a doubling ratio between two LARGE `E` points, and only as a
corroborating Layer-B arm. REJECT the per-hit-constant reading of it.**

Executed grid, shipped producer:

```
  V=1 E=500   no_reg=240996   with_reg=316602   delta=75606
  V=1 E=1000  no_reg=376203   with_reg=613538   delta=237335
  V=1 E=2000  no_reg=733131   with_reg=1207666  delta=474535
  V=1 E=4000  no_reg=1447147  with_reg=2523538  delta=1076391
  delta growth vs E=500 : {E=500: 1.0, E=1000: 3.14, E=2000: 6.28, E=4000: 14.24}
```

Executed grid, bounded producer (`FIX-A2` monkeypatched into `generate_project_report`):

```
  V=1 E=500   no_reg=212757   with_reg=236810   delta=24053
  V=1 E=1000  no_reg=344087   with_reg=397538   delta=53451
  V=1 E=2000  no_reg=669387   with_reg=722018   delta=52631
  V=1 E=4000  no_reg=1447147  with_reg=1499906  delta=52759
  delta growth vs E=500 : {E=500: 1.0, E=1000: 2.22, E=2000: 2.19, E=4000: 2.19}
```

**Three things this shows.**

1. **It separates the arms cleanly at large `E`.** `2.27` vs `1.002` on the `E: 2000 → 4000`
   doubling. That is a wider margin than the white-box ratio and it is observed entirely through the
   shipped entry point.
2. **It is NOT a clean isolation of the producer.** The delta contains the addendum's own *output*
   plus its share of the join/encode, so it reads **150.3 / 238.3 / 237.3 / 269.2 B per hit** across
   the grid against the 89–94 B/hit the producer actually costs. Any acceptance phrased as a per-hit
   constant is chasing a number that is not there.
3. **The `E = 500` point is an outlier in BOTH arms** (`24053` where the bounded plateau is ~`53000`;
   growth `1.0 → 2.22` for a fix that renders an *identical* addendum at every `E ≥ 201`). `peak` is a
   max over the whole run, so the addendum's live set only shows above the baseline when it coincides
   with the run's peak moment. **Anchoring the ratio at `E = 500` would false-fail a correct fix at
   2.22** — the batch-63 `<1.5` mistake, reproduced from the other side. Anchor at `E = 2000`.

**Replacement, if the orchestrator prefers a single arm:** `OBS-addendum-peak-flat-in-E` (§5.8,
white-box, `1.98 → 1.00`) is the cleaner oracle and is not confounded. Keep 5.9 as the black-box
corroboration required by the Layer-B rule, not as the primary node.

---

## 9. Hand-off table for the architect lane (slug → binding)

| slug | US | surface | RED-mutation category | executed RED |
|---|---|---|---|---|
| `OBS-below-bound-byte-identity` | B64-1 | black-box, file + `canonical_report_bytes` | CODE | `FIX-B` / `FIX-E` / `FIX-G` |
| `OBS-emission-order-interleaved` | B64-1 | white-box, `_addendum_lines` | CODE | `FIX-B` (idx 3) |
| `OBS-overlap-membership-preserved` | B64-1 | black-box, file | CODE | `FIX-E` (2 hits lost) |
| `OBS-hits-bounded-per-region-class` | B64-1 | black-box, file | INPUT SET (C-31) | `SHIP` at `E=CAP+1` |
| `OBS-interior-no-marker` | B64-1 | black-box, file | THRESHOLD (C-39) | `FIX-G` |
| `OBS-traversal-R-multiplier-gone` | B64-1 | white-box, counting iterable | WRITER/producer | `SHIP` 500/1000/4000 |
| `OBS-traversal-early-exit` **(conditional)** | B64-1 | white-box, counting iterable | WRITER/producer | `SHIP` / `FIX-A` / `FIX-D` = 4000 |
| `OBS-addendum-peak-flat-in-E` | B64-1 | white-box, traced window stated | CODE | `SHIP` 1.98 · `FIX-C` 1.96 |
| `OBS-marginal-cost-flat` | B64-1 | black-box, two `generate_project_report` runs | WRITER/producer | `SHIP` 2.27 |
| `OBS-cap-constant-quoted` | B64-1 | inspection + imports | THRESHOLD (C-39) | re-value the constant |
| `OBS-notice-names-cut-classes` | B64-2 | black-box, file | CODE | `SHIP` (none) · `FIX-C` (`?`) |
| `OBS-notice-names-cut-variants` | B64-2 | black-box, file | CODE | `FIX-F` |
| `OBS-notice-absent-for-uncut-class` | B64-2 | black-box, file | CODE | `FIX-G` |
| `OBS-notice-escapes-file-derived-text` | B64-2 | black-box, file | WRITER/producer | executed §3.4 |
| `OBS-notice-reaches-the-file` | B64-2 | black-box, file + TUI seam | INPUT SET (C-31) | budget-drop scenario |
| `OBS-residual-stated-with-numbers` | both | inspection | — | n/a (inspection) |

**Requirement decisions this lane cannot make and will not fabricate:**
(a) the notice's **exact wording and granularity** — one line per region, or one per (region, class)?
This lane's reference form is one line per region naming each cut class with its variant list; the
observables are wording-agnostic (they assert what the notice *names*, not its prose).
(b) whether **per-class early exit** is mandated (§5.7).
(c) whether the merge-then-resolve membership correction (§3.1) is folded into this batch's design or
raised as a blocker to the design as approved. **This lane's position: it must be folded in, because
the approved design names the primitive that is unsound.**

---

## 10. Regression checklist

- [ ] `pytest -q tests/test_report_service.py tests/test_report_addendum.py` — baseline **44 passed**
      on `082ada9` (executed). The four addendum tests at `:896-960` must stay green **unmodified**.
- [ ] `pytest -q tests/test_tui_report_seam.py` — the declared-region drive at `:355-372`.
- [ ] `pytest -q tests/test_tui_report_filter_surface.py tests/test_before_after_report.py` — the
      three other `canonical_report_bytes` consumers; a change to report bytes shows up here first.
- [ ] `pytest -q tests/test_report_field_census.py` — carries the `DeclaredRegion` payload census at
      `:187` and the AST column-0 escape guard the notice line must not trip.
- [ ] `pytest -q tests/test_manifest_writer.py` — `declared_regions` round-trip (`:463`, `:520`).
- [ ] `pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py -k tc031 or tc032` —
      the frozen-source and frozen-test guards; **`range_index.py` must show a zero diff vs `main`**.
- [ ] `pytest -q` full suite, non-slow — compare against the batch-63 close figure recorded in
      `PLAN.md`'s test ledger.
- [ ] `tests/goldens/batch35/at055b-project-report.md` — **must not change**. If it does, the
      addendum change leaked into a document that has no addendum, which is a defect.

## 11. Exit criteria

1. Every slug in §9 has a bound id, a test, and a **pasted pre-fix RED transcript** from CI or the
   packet — not from this file.
2. `OBS-below-bound-byte-identity`'s golden was captured on `082ada9` **before** the producer changed,
   and its capture commit precedes the fix commit.
3. `OBS-traversal-early-exit` is either bound **or** explicitly retired with the requirement's reason
   recorded (§5.7).
4. §3.1's membership correction is folded into the design **or** the design is returned.
5. No acceptance in the batch is keyed to `generate_project_report`'s whole-report peak (R-1), and the
   residual is stated with its numbers (§5.16).
6. Test results sections in `04-validation.md` are filled by execution, never by this file's numbers.

---

## 12. Evidence checklist

| # | item | ✓/✗ | evidence (re-runnable) |
|---|---|---|---|
| 1 | Acceptance criteria use an observable / RED-mutation / boundary triple | ✓ | §5 — every row carries all three, plus the mutation **category** |
| 2 | Test cases have an explicit Expected, not "works" | ✓ | §5 rows quote the exact predicate; §7.1 pastes the exact expected 23-line block |
| 3 | Edge cases include empty, boundary, invalid, error | ✓ | §7.6 empty/`None`-address/1-byte region (executed) · §7.2 `CAP−1/CAP/CAP+1/4000` (executed) · §3.1 overlapping/nested (executed) · §3.4 hostile markdown (executed) |
| 4 | Regression checklist exists | ✓ | §10, eight entries, each a runnable `pytest` invocation; baseline **44 passed** executed |
| 5 | Exit criteria stated | ✓ | §11 |
| 6 | No real PII / secrets / operator firmware | ✓ | every fixture is a synthetic in-memory dataclass; no `examples/` image opened; four temp report files under `tempfile.TemporaryDirectory`, auto-removed |
| 7 | Test-results section left **blank** unless actually run | ✓ | this file states no Phase-4 result; every transcript is labelled with the probe and the export that produced it |
| 8 | **Layer B (black-box):** the shipped surface observed, with boundary + negative evidence | ✓ | §5.1/5.3/5.4/5.5/5.9/5.11–5.15 all key on `generate_project_report` and the file on disk; §5.15 additionally on the TUI seam; §8 executed at the shipped entry point in both arms |
| 9 | **Bidirectional surface-reachability** | ✓ | **inputs** exercised through the handler: region count, region geometry (overlapping / nested / disjoint / empty / 1-byte / inclusive-end), variant count, summary count, entry count, issue class, `issue.address is None`, hostile variant id. **outputs** observed through the handler: rendered hit lines, `None.`, the notice line, the file bytes, whole-report peak delta. **Mechanism-only** observables (consumed count, `_addendum_lines` peak) are labelled white-box, never counted as Layer B |
| 10 | **No unfilled template** | ✓ | no `<…>`, no `TC-NNN`, no empty required cell; every RED result in §5 and §9 is an executed number |
| 11 | **P-5: every observable's RED mutation was EXECUTED on the current tree** | ✓ | §5 — 15 of 15 testable observables have a pasted transcript. `OBS-cap-constant-quoted` (§5.10) is the one whose mutation is *described* rather than run, because the constant does not exist yet; flagged as such rather than claimed |
| 12 | **P-6: the positive control is shaped to the RULE, not the implementation** | ✓ | §5.13 — built from the false-positive direction (`FIX-G`), executed GREEN on six of the nine other observables, which is the measurement that shows the rule needed its own row |
| 13 | **C-39: every threshold derived by execution, transcript pasted** | ✓ | `< 1.30` for §5.8 derived from `{1.96, 1.98}` vs `{1.00}`; `< 1.30` for §5.9 derived from `2.27` vs `1.002`; the `E = 500` anchor executed-rejected at `2.22` |
| 14 | **A carried number is re-derived, not copied** | ✓ | the 87–94 B/hit constant re-measured here (93.9 / 93.3 / 89.1); the product law re-measured (2.00 / 2.01 / 1.91); the traversal counter re-executed (500/1000/2000/4000); the one-shot-generator break re-executed |
| 15 | **A predicate tests what its LABEL claims** | ✓ | applied to this catalog: §5.9's label is narrowed to the addendum's *marginal* cost and §5.16 forbids the closure claim; §5.7 is marked conditional rather than asserted; §5.4's label says *per region-class*, which is what its fixture isolates |
| 16 | **An AT quotes the CONSTANT, never its value** | ✓ | §5.10 + §7.2 (`E` derived as `CAP − 1` / `CAP` / `CAP + 1`); the literal `200` appears in this file only inside executed transcripts |
| 17 | Frozen-set safety | ✓ | `_ENGINE_TEST_FILES` read at `tests/test_tui_directionb.py:5458-5468`; no report test is in it; §6 routes the merge helper away from the frozen `range_index.py` |
| 18 | Probe safety: bounded, temp trees removed, pristine export | ✓ | ≤ 4 000 synthetic entries, peak < 3 MB, four temp reports ≤ 170 kB under `TemporaryDirectory`; all execution in the `git archive` export at `…/Temp/claude/b64`, the worktree never mutated (`git status` clean apart from this file) |
