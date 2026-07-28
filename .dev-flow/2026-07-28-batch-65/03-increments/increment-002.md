# batch-64 — Increment 2 — Review Packet

> **Scope: THE PRODUCER.** `_addendum_lines` is now the single-pass, region-indexed, bounded,
> self-disclosing producer `R-TUI-098` / `HLR-103` / `LLR-103.1…103.6` specify. **28 of 28 nodes in
> `tests/test_report_addendum_bound.py` are GREEN**, all four `xfail(strict=True)` markers are removed,
> and **every named mutant arm has been driven RED against the IMPLEMENTED producer** — including
> `FIX-NONE` and `FIX-SCOPE`, the batch's one knowingly-open item, which are executed here for the first
> time.
>
> **Three findings are reported rather than worked around** (§5). Two are Inc-1 fixture defects that made
> a gate condition unreachable and were fixed in the fixture without touching any predicate; one is a
> spec mis-assignment (`FIX-E` → `TC-487`) that is **left in place and reported**, with the arm that
> actually bites executed beside it.

## 1. What changed

**The producer.** `_addendum_lines` no longer nests `for region → for variant → for entry/issue` and no
longer appends one fully formatted string per matching triple into a local list before any output
exists. It now:

1. **Coalesces** the declared regions once per call into a disjoint **half-open** cover —
   `_merge_ranges([(r.start, r.end + 1) for r in regions])`, **reusing** `report_filter._merge_ranges`
   rather than inventing a third coalescer (the in-repo precedent `LLR-103.2` names). The `+ 1` converts
   `DeclaredRegion`'s inclusive `[start, end]` to `range_index`'s half-open convention; without it the
   end address of every declared region is a false negative.
2. Uses `range_index.address_in_sorted_ranges` as a **sound reject pre-filter only**. It is boolean, it
   inspects a single `bisect_right(starts, addr) - 1` candidate, and it is therefore unsound over
   overlapping ranges and can never name a region. **`range_index.py` is consumed, never modified.**
3. Resolves region **identity** from a caller-local `bisect` + **prefix-max-of-ends `List[int]`** inside
   `report_service.py`, walking `i` downward from `bisect_right(starts, addr) - 1` while
   `pmax[i] >= addr` and collecting every `i` whose `ends[i] >= addr`. The array is the structure
   `LLR-103.2` pins; a segment tree is §15 item 7's named reversal trigger, not this batch.
4. Keeps **ONE ordered hit list per region + three admission counters** — not three per-class buckets.
   The shipped emission order interleaves `mod, issue, mod, issue` per summary, so per-class
   concatenation emits `mod, mod, issue, issue` and breaks byte identity. With counters the admitted
   sequence is a **subsequence** of the shipped one by construction. Executed: `FIX-B` is RED on
   `AT-196` **and** `TC-494`, first difference at position 1.
5. Emits, inside each region's own sub-section, one `ADDENDUM_TRUNCATION_NOTICE_FMT` line per hit class
   whose cap fired, naming the class, the cap, the dropped count and the affected variants — capped at
   `ADDENDUM_NOTICE_VARIANTS_MAX` with a `+N more` remainder counted through an **`O(1)` last-seen
   sentinel**, which is `O(1)` only because `variant_results` stayed the outermost loop.

**Traversal is not terminated on saturation**, deliberately: a run that stopped looking could not report
the dropped count or the affected-variant set, which is the entire content of the notice.

**Escaping.** `md_safe(result.variant_id, limit=REPORT_CELL_CHARS)` is evaluated **once per variant at
the recording site** and shared by the hit lines and the notice — which is both why a given id renders
byte-identically in both (`TC-495`) and why the AST census adds **no new key**
(`("md_safe", "result.variant_id")` already exists at `test_report_field_census.py:344`;
`LLR-103.5` pins that spelling). Executed: `test_census_covers_every_escaped_expression_in_the_source`
is GREEN with **no `_ESCAPED_EXPRESSIONS` edit** — case (i) of §11's census obligation did **not**
obtain, and this increment records that rather than editing the entry anyway.

**The seam (operator ruling, review finding M3).** The region-op counter is an **optional keyword-only
`ops_counter: Optional[List[int]]` parameter**, not the module-level
`report_service._LAST_ADDENDUM_REGION_OPS` Inc-1 pinned. `report_service` carries no module-level
mutable state today and `_addendum_lines` is shared by the TUI report worker and the CLI, so a module
global would be a cross-call race dressed as an instrument. `TC-498` was edited to match. Recorded as
**amendment A-41** below.

**The census (§10.10, unconditional).** `PLANTED` gains `("notice_variant", "MKNOTICE", "A")`, and both
`_hostile_report` and `_benign_report` now fire the addendum cap symmetrically, so the batch's one new
markdown sink is rendered through markdown-it by `test_at157` / `test_at158` /
`test_census_every_planted_field_renders_verbatim`. Verified non-vacuous — the hostile document's notice
line is:

```
> TRUNCATED: change-file issue hits in this region were capped at 200; 1 more not listed (variants
affected: MKNOTICE\~\~s\~\~\*\*b\*\*\[l\](http:\/\/evil\.com)\|\&vert;\`c\`).
```

and the benign reference's is `(variants affected: b)`. **Symmetry is load-bearing**: the notice is a
blockquote, and a hostile-only blockquote would make `AT-157` fire on a fixture asymmetry instead of on
an injection. The flood is split across two variants (`K/2` and `K/2 + 1`) so neither trips
`MAX_REPORT_ISSUES_PER_VARIANT` — a second cap firing at the same time would make it ambiguous which one
produced the document's blockquote.

## 2. Files modified

Three files — the §11.1 Inc-2 allocation plus the bound-test file the operator ruling and two fixture
defects required. Under the ≤ 5 cap.

- `s19_app/tui/services/report_service.py` — the four `LLR-103.6` constants; `_AddendumRegionIndex`,
  `_build_addendum_region_index`, `_addendum_regions_for`, `_AddendumRegionHits`,
  `_addendum_truncation_notice`, `_render_addendum` (all new); `_addendum_lines` rewritten. New imports:
  `bisect`, `range_index.{RangeIndex, address_in_sorted_ranges, build_sorted_range_index}`,
  `report_filter._merge_ranges`.
- `tests/test_report_addendum_bound.py` — the Inc-1 constant helper and its four fallbacks **deleted**;
  four `xfail(strict=True)` markers removed; `TC-498` re-pointed at the `ops_counter` seam; `AT-194`'s
  warm-up and `TC-488`'s leaf size corrected (§5 findings 1 and 2). **No predicate was weakened.**
- `tests/test_report_field_census.py` — the `PLANTED` entry, `_flood_issues`, and the symmetric
  cap-firing extension of both fixtures.

`tests/test_tui_report_seam.py` needed **no** edit: it imports `_addendum_notices` and `_cap`, not the
deleted helper. Inc-1's pending item 3 is discharged by inspection — `grep -rn "_const(" tests/…` over
**both** files → **0 hits**.

## 3. How to test

```bash
python -m pytest tests/test_report_addendum_bound.py -v --tb=short

# regression subsets — per subset, NOT merged
python -m pytest -q tests/test_report_service.py tests/test_tui_report_seam.py \
                   tests/test_report_field_census.py tests/test_manifest_writer.py \
                   tests/test_capped_text_area.py
python -m pytest -q tests/test_report_service.py tests/test_report_addendum.py
python -m pytest -q tests/test_tui_report_filter_surface.py tests/test_before_after_report.py

# BOTH frozen guards
python -m pytest -q tests/test_engine_unchanged.py
python -m pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"

python -m ruff check s19_app/tui/services/report_service.py \
                     tests/test_report_addendum_bound.py tests/test_report_field_census.py
grep -rn "_const(" tests/test_report_addendum_bound.py tests/test_tui_report_seam.py   # 0 hits
git status --porcelain tests/goldens/                                                  # empty
```

**Mutant arms.** `scratchpad/mutant_plugin.py` applies one arm per run from the `MUTANT` env var at
`pytest_configure`; nothing in it edits the repo:

```bash
export PYTHONPATH=<scratchpad>
MUTANT=FIX-B python -m pytest -q -p mutant_plugin --tb=line \
    tests/test_report_addendum_bound.py -k "at196 or tc494"
```

## 4. Test results

### 4.1 Observed vs §11.1 expected — every node, both gates

From **one** complete run: `python -m pytest tests/test_report_addendum_bound.py -v --tb=short`
→ tail **`28 passed in 1.34s`**, **exit code 0**.

| node | §11.1 expected @ Inc-1 | observed @ Inc-1 | §11.1 expected @ Inc-2 | **observed @ Inc-2** | evidence |
|---|---|---|---|---|---|
| `AT-194` | RED | RED | GREEN | **GREEN** | ratio `1.00` on the corrected warm-up; steady-state `delta(2000)=52296 delta(4000)=52247` |
| `AT-196` | GREEN — regression guard | GREEN | GREEN | **GREEN** | 6/6 shapes byte-identical to the Inc-1 golden |
| `AT-197` | RED | RED | GREEN | **GREEN** | notice: class `change-file issue`, dropped `2`, variants `{v2, v3}` (set equality) |
| `AT-198[le_K]` | GREEN by vacuity | GREEN | GREEN | **GREEN** | class total 199 → 0 notices |
| `AT-198[interior]` | GREEN by vacuity | GREEN | GREEN | **GREEN** | class total 200 → 0 notices, 200 hit lines |
| `AT-198[K_plus_1]` | RED | RED | GREEN | **GREEN** | class total 201 → exactly 1 notice |
| `AT-199` | RED | RED | GREEN | **GREEN** | 1 notice not 2; injected `>` escaped; `\r\n\t` collapsed |
| `AT-200` | RED | RED | GREEN | **GREEN** | notice present in the written file **and** the `ReportViewerScreen` seam |
| `AT-201` | RED | RED | GREEN | **GREEN** | named classes == cut classes |
| `AT-202` | RED | RED | GREEN | **GREEN** | named variants == variants with ≥ 1 dropped hit |
| `AT-203` | RED | RED | GREEN | **GREEN** | notice under the flooded `### ` sub-section, absent from the quiet one |
| `TC-480` | RED | RED | GREEN | **GREEN** | heading + sub-headings + ≤ K hits + ≥ 1 notice |
| `TC-481` | GREEN by vacuity | GREEN | GREEN | **GREEN** | 199 hits rendered, 0 notices |
| `TC-482` | GREEN by vacuity | GREEN | GREEN | **GREEN** | 200 hits rendered, 0 notices |
| `TC-483` | RED | RED | GREEN | **GREEN** | ≤ K at `K+1` and at 3000; addendum 208 lines ≤ bound 607 |
| `TC-484` | GREEN by construction | GREEN | GREEN | **GREEN** | `None.` on all three empty sub-cases; 1-byte region → 1 hit |
| `TC-485` | GREEN by construction | GREEN | GREEN | **GREEN** | `R = 0` guard on unchanged code |
| `TC-486` | GREEN by construction | GREEN | GREEN | **GREEN** | 0x5000 beyond the inner end → 1 hit; 0x2000 emitted twice |
| `TC-487` | GREEN by construction | GREEN | GREEN | **GREEN** | duplicate ×3 → 3 hits; equal-start-nested → 2 hits |
| `TC-488` | RED | RED | GREEN | **GREEN** | overlapping, `consumed/N` = `900/900` at R = 1/8/64 |
| `TC-489` | RED | RED | GREEN | **GREEN** | disjoint, `consumed/N` = `300/300` at R = 1/8/64 |
| `TC-490` | `xfail(strict=True)` | XFAIL | GREEN, marker removed | **GREEN, marker removed** | 8 named + `+32 more` over 40 distinct affected variants |
| `TC-491` | GREEN — regression guard | GREEN | GREEN | **GREEN** | two run roots → identical, and equal to the golden |
| `TC-492` | `xfail(strict=True)` | XFAIL | GREEN, marker removed | **GREEN, marker removed** | four constants present; no bare `200` in the body; `K → 37` green over the K-derived nodes |
| `TC-493` | RED | RED | GREEN | **GREEN** | `peak(E=1000)=19801 peak(E=2000)=19802 ratio=1.0001 ≤ 1.25` |
| `TC-494` | GREEN by construction | GREEN | GREEN | **GREEN** | order `['modification','issue','modification','issue','issue']`, `S = 2` |
| `TC-495` | `xfail(strict=True)` | XFAIL | GREEN, marker removed | **GREEN, marker removed** | notice rendering == hit-line rendering over 5 ids incl. the hostile string |
| `TC-498` | `xfail(strict=True)` | XFAIL | GREEN, marker removed | **GREEN, marker removed** | `A == R × N`: `300 / 2400 / 19200 / 76800` at `R = 1/8/64/256`, `N = 300` |
| `TC-499` | GREEN by vacuity | GREEN | GREEN | **GREEN** | report-wide `> TRUNCATED:` fires outside the addendum; 0 addendum notices |
| `TC-497` | n/a — Inc-3 | not authored | n/a | **not authored** | Inc-3 owns it |

**Observed tally at Inc-2: 28 GREEN · 0 RED · 0 xfail · 1 n/a.** Every §11.1 Inc-2 expectation matched;
**no divergence**. The 13 Inc-1 REDs all flipped GREEN, the 12 Inc-1 GREEN guards all stayed GREEN, and
all four `xfail(strict=True)` nodes now pass with their markers removed — an XPASS would have failed
under `strict=True`, so their passing is a genuine verdict, not a suppressed one.

**`TC-498` records the §10.7 residual with a value.** `A` counts **only** `ends[i] >= addr` comparisons
in the downward walk; the `pmax` guard, the attribution `bisect`, and the reject pre-filter's bisect are
excluded. `A = R × N` exactly, at every `R`, on the pinned `huge+tiny` geometry — the disclosure, not a
bound. (The spec's `128000` figure is at `N = 500`; this node's fixture is `N = 300`, hence `76800` at
`R = 256`.)

### 4.2 Mutant arms — every one reproduced RED against the IMPLEMENTED producer

A GREEN guard nobody has driven to RED is indistinguishable from one that cannot fail. Every arm below
was executed **after** the rewrite landed, against the real function.

| arm | mutation | node(s) it must kill | **observed** |
|---|---|---|---|
| `FIX-B` | per-class bucket concatenation instead of one ordered list | `AT-196`, `TC-494` | **RED both.** `TC-494`: expected `['modification','issue','modification','issue','issue']`, observed `['modification','modification','issue','issue','issue']`, first difference at position 1. `AT-196`: shape `R3V2E5` drifted at an unchanged 8625 bytes |
| `FIX-E` | raw `range_index` membership, coalescing removed | `AT-196`, `TC-486` | **RED both.** `TC-486`: the 0x5000 candidate inside the outer region beyond the inner end is reported `[]`. `AT-196`: `FIXGOLD` 5064 vs golden 5260 bytes |
| `FIX-E(b)` *(Inc-2 addition — see §5 finding 3)* | coalescing used for **attribution**, not only as a reject pre-filter | `TC-487`, `TC-486`, `AT-196` | **RED all three.** `TC-487`: three identical regions collapse to one |
| `FIX-G` | a notice for every class, cut or not | `AT-196`, `AT-198` ×3, `AT-201`, `TC-481`, `TC-482` | **RED all 7.** `AT-201` names `['change-file issue','check-file issue','modification']` where only `['change-file issue']` was cut |
| `FIX-H` | name every variant that CONTRIBUTED to the cut class | `AT-202`, `AT-197` | **RED both.** Names `['v1','v2','v3']`; only `['v2','v3']` lost a hit — `v1` is the flooder whose every hit was admitted |
| `FIX-I` | every notice re-emitted under the FIRST region | `AT-203` | **RED.** The quiet region carries `> TRUNCATED: … 1 more not listed (variants affected: v1)` |
| `FIX-A2` | a real per-class early exit on saturation | `TC-488`, `AT-197` | **RED both.** `TC-488`: `603/900` at every `R`. `AT-197`: 0 notices — a traversal that stopped cannot count what it did not look at |
| `FIX-C` | `hits[:CAP]` — bound the OUTPUT, not the producer | `TC-493`, `AT-197`, `TC-481` | **RED all three.** `TC-493`: `peak(E=1000)=89282 peak(E=2000)=172611 ratio=1.933 > 1.25`. `AT-197`: names `['?']`. `TC-481`: 197 of 199 hits rendered |
| **`FIX-NONE`** *(first execution ever)* | drops the `None.` branch and stops skipping `issue.address is None` | `TC-484` | **RED.** `TC-484 [no variants]: an empty region must render an explicit 'None.'` |
| **`FIX-SCOPE`** *(first execution ever)* | counts `> TRUNCATED:` report-wide instead of addendum-scoped | `TC-499` | **RED.** Counts `> TRUNCATED: 1 of 201 declaration errors omitted (cap: 200 issues per variant).` — the pre-existing `:1134` emitter — as an addendum notice |

**Every one of the 12 Inc-1 GREEN regression guards has now been driven RED**, which is the gate
condition §6.3 and §11.1 note 1 impose — the one exception being `TC-485`, which §11.1 states **in
writing** is a pure guard over unchanged code with no arm, rather than inventing one for it:

| Inc-1 GREEN guard | arm(s) that drove it RED |
|---|---|
| `AT-196` | `FIX-B`, `FIX-E`, `FIX-E(b)`, `FIX-G` |
| `AT-198[le_K]`, `AT-198[interior]` | `FIX-G` |
| `TC-481` | `FIX-C`, `FIX-G` |
| `TC-482` | `FIX-G` |
| `TC-484` | **`FIX-NONE`** |
| `TC-485` | *none — pure guard on unchanged code, per §11.1* |
| `TC-486` | `FIX-E`, `FIX-E(b)` |
| `TC-487` | **`FIX-E(b)`** (`FIX-E` is GREEN — §5 finding 3) |
| `TC-491` | `FIX-B` (`R3V2E5`), `FIX-E` (`FIXGOLD`), `FIX-G` (`R1V1E1`) |
| `TC-494` | `FIX-B` |
| `TC-499` | **`FIX-SCOPE`** |

`FIX-NONE` and `FIX-SCOPE` were the batch's one knowingly-open item (§11.1 note 1, C-39): specified,
never executed, because they mutate a producer that did not exist. **They are executed here and both are
RED.** The item is closed.

> **`FIX-SCOPE` needed a correction to be a real arm.** A first build mutated the predicate to a
> report-wide scan using the *notice prefix regex*, and read GREEN — because the `:1134` emitter's line
> (`> TRUNCATED: 1 of 201 declaration errors omitted…`) does not match the addendum notice's prefix. The
> arm §11.1 specifies is the coarser one — count any line starting with `> TRUNCATED:` — and that one is
> RED. Recorded because a mutant that reads GREEN for the wrong reason is the same defect class as a
> vacuous check, and a first-build GREEN that goes unexamined would have certified `TC-499` as
> falsifiable when it had not been falsified.

### 4.3 Byte identity below the bound

`AT-196` compares six documents — the architect lane's five `(R,V,E)` shapes plus the qa lane's hostile
`FIXGOLD` — against **Inc-1's golden, captured from the SHIPPED producer on `082ada9`** before any
production code was touched (C-12). **6/6 byte-identical, 0 differing bytes.** `TC-491` additionally
confirms the harness is deterministic across two run roots.

`git status --porcelain tests/goldens/` → **empty**: neither `tests/goldens/batch64/` nor
`tests/goldens/batch35/at055b-project-report.md` changed. The golden was **not** re-baselined.

### 4.4 Regression sets (§6.3) — per subset, not merged

| subset | baseline | observed | verdict |
|---|---|---|---|
| `test_report_service` + `test_tui_report_seam` + `test_report_field_census` + `test_manifest_writer` + `test_capped_text_area` | **123** pre-batch (Inc-1: `1 failed, 123 passed`) | **`125 passed in 118.01s`** | 123 preserved + `AT-200` (Inc-1) + the new census `notice_variant` arm (Inc-2); **0 failures** |
| `test_report_service` + `test_report_addendum` | **44** | **`44 passed in 1.76s`** | unchanged; the four addendum tests at `test_report_service.py:896-960` stay green **unmodified** |
| `test_tui_report_filter_surface` + `test_before_after_report` | 29 | **`29 passed in 103.27s`** | unchanged |
| `tests/goldens/` | must not change | `git status --porcelain` → empty | unchanged |

**The full non-slow suite is NOT claimed here.** `pytest -q -m "not slow"` was started and had reached
**83 %** with **0 failures and 1 xfail** when this packet was written; the tail is the Textual snapshot
block, which runs at a few tests per minute on this host. It is **Inc-3's** gate cell, not Inc-2's, and
Inc-2's gate is the three per-subset regression sets above — all three complete, all three green. Stating
a partial run as a pass would be the exact failure mode §6.3 forbids, so the row reads *in flight* rather
than *passed*.

### 4.5 BOTH frozen guards

| guard | command | result |
|---|---|---|
| engine-freeze **path** guard | `pytest -q tests/test_engine_unchanged.py` | **`1 passed in 0.08s`** |
| engine-freeze **test-file** guard (TC-031/TC-032) | `pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"` | **`6 passed, 168 deselected in 0.54s`** |

`range_index.py` shows a **zero diff** vs `main`. The new `range_index` import is a frozen-module
**consume**: the guards test by `git diff --name-only`, not by import graph, and
`git diff --stat 082ada9 -- s19_app/` touches `report_service.py` only.

### 4.6 Lint

```
python -m ruff check s19_app/tui/services/report_service.py \
                     tests/test_report_addendum_bound.py tests/test_report_field_census.py
   -> All checks passed!
```

No type checker is configured in this repo.

## 5. Risks

### Finding 1 — `AT-194`'s Inc-1 warm-up made its own precondition unreachable (FIXED in the fixture)

`AT-194` warmed with a 64-entry fixture, regions only. Against the implemented producer that leaves
**~124 kB** of one-time allocation charged to whichever window runs first — the `E = 2000` no-regions
sample — which is **larger than the whole marginal delta the node measures**. Executed:

```
trial=0 E=2000 without=793238 with=721753 delta=-71485     <-- precondition `delta > 0` FAILS
trial=0 E=4000 without=1447350 with=1499597 delta=52247
trial=1 E=2000 without=669413 with=721709 delta=52296
trial=1 E=4000 without=1447350 with=1499597 delta=52247
trial=2 E=2000 without=669462 with=721709 delta=52247
```

The property itself is unambiguous — with-regions costs a **flat** +52 kB at both `E = 2000` and
`E = 4000`. Only the measurement was wrong. **Fix: warm at full scale in BOTH configurations.** After it,
four consecutive trials read ratios `0.9973 / 1.0000 / 1.0000 / 1.0020`. The threshold, the
positive-delta precondition and the ratio predicate are Inc-1's, untouched. This was invisible at Inc-1
because the shipped producer's delta was `408661` — the artifact was noise against it and is decisive
against a bounded producer.

### Finding 2 — `TC-488`'s Inc-1 fixture cannot fire the arm the gate assigns it (FIXED in the fixture)

§6.2 and §11.1 both credit `TC-488` with the stealth-early-exit control and the Inc-2 gate names
`FIX-A2 RED on TC-488`. Inc-1 built the fixture with **100 candidates per leaf**, i.e. 100 per class
against a cap of 200 — **a per-class early exit cannot fire below the cap at all.** Executed against the
implemented producer:

```
geometry=overlapping, arm=FIX-A2, predicate = TC-488 consumed == N
  per_leaf=100 N= 300  consumed R=1/8/64 -> [300, 300, 300]  -> TC-488 GREEN (exit cannot fire)
  per_leaf=300 N= 900  consumed R=1/8/64 -> [603, 603, 603]  -> TC-488 RED
```

**Fix: the leaf size is now `_cap() + 100`, derived from the constant, with an explicit fixture
precondition asserting `per_leaf > cap` and naming why.** The predicate `consumed == N` is unchanged and
is strictly stronger at `N = 900`. Without this the gate condition was unsatisfiable — not because the
arm is unreal, but because the fixture never reached the boundary its own docstring claims.

### Finding 3 — SPEC DEFECT, reported and NOT worked around: `FIX-E` has no detection power on `TC-487`

§11.1 assigns `TC-487` the mutant arm `FIX-E` (raw `range_index` membership, no coalescing). **Executed:
`FIX-E` is GREEN on `TC-487`.** Both of its sub-fixtures survive an uncoalesced bisect *by accident*:

- duplicated `[(0x1000, 0x2000)] × 3` → `bisect_right(starts, 0x1500) - 1 = 2`, `0x1500 < ends[2]` → True;
- equal-start nested → `sorted()` orders by `(start, end)`, so the last candidate is the **widest** and
  still contains the probe.

The hazard `TC-487` actually guards is the **converse**, and its own docstring says so: *"a coalescing
step used for anything other than a reject pre-filter would silently collapse these"*. I have **not**
changed `TC-487`, and **not** changed the spec. Instead I built and executed the arm that does bite —
`FIX-E(b)`, coalescing used for attribution — and it is **RED on `TC-487`, `TC-486` and `AT-196`**. The
node therefore has demonstrated detection power; **the spec's arm assignment is wrong and needs an
Inc-3 amendment.** `TC-486`'s assignment to `FIX-E` is correct and was reproduced.

### Other risks

4. **`_merge_ranges` is imported across modules and is private.** `report_service` now imports
   `report_filter._merge_ranges`. `LLR-103.2` explicitly sanctions *"reuses or mirrors"* and forbids a
   third coalescer, so reuse is the specified choice — but it couples two service modules through a
   private name. If `report_filter` ever changes `_merge_ranges`' convention, the addendum's correctness
   precondition moves with it silently. `TC-486` is the guard that fires.
5. **`A = R × N` is a residual this batch discloses, not closes.** Region resolution costs `O(R)` per
   *surviving* candidate under the `huge+tiny` geometry. §10.7 owns it; §15 item 7 names both reversal
   triggers; `TC-498` fails **loudly** if a later batch swaps in an output-sensitive structure, which is
   by design.
6. **The notice is outside one of the two static guards.** `test_no_escaped_field_is_emitted_at_the_head_of_its_line`
   walks `ast.JoinedStr` only and the notice is `CONST.format(...)`-built, so it is structurally
   invisible there. What defuses column 0 is the **literal `> ` prefix** in
   `ADDENDUM_TRUNCATION_NOTICE_FMT`, plus `_normalise`'s `\r\n\t` collapse. Both facts are recorded in
   the constant's own docstring so an edit that drops the prefix knows it is removing the only guard.
   The `PLANTED` entry is what proves the sink inert **at the reader** rather than merely escaped at the
   writer.
7. **`ADDENDUM_CLASS_LABELS` is consumed positionally** by `_addendum_truncation_notice` and by the
   acceptance suite. Defining it as a `dict` in a later batch breaks both. Recorded, not defended
   against.
8. **The census fixtures grew by ~200 issues each.** Subset 1 went from ~124 s to 118 s, so no material
   cost, but both hostile and benign documents are now materially larger and must stay **symmetric** —
   an asymmetric edit will surface as an `AT-157` failure that looks like an injection and is not.
9. **An uncommitted `.dev-flow/state.json` change is in the working tree.** Pre-existing; this
   increment did not write it. Flagged, as Inc-1 flagged it.

## 6. Pending items

1. **Inc-3 must carry three amendments** (see §7's table): **A-41** the seam form change, **A-42**
   `AT-194`'s warm-up + `TC-488`'s leaf size, **A-43** the `FIX-E` → `TC-487` mis-assignment corrected to
   `FIX-E(b)`. A-43 is a **spec** correction, not a code one.
2. **Inc-1's own §11.1 tally defect is still open** — *"11 GREEN … = 29 rows"* should read *"12 GREEN …
   = 30 rows"*. Inc-1 reported it; Inc-3's amendment log owns it.
3. **`TC-497` is not authored** — Inc-3 owns it, authored *and* gated there, including the 7-string grep
   list and the flagged judgement half.
4. **§10.10's census case (i) did not obtain and is recorded as such.** No `_ESCAPED_EXPRESSIONS` entry
   was added because the pinned `md_safe(result.variant_id, …)` spelling introduced no new key. The
   increment records which case obtained, as §11 requires.
5. **`AT-194` and `TC-493` remain the only nodes reading `tracemalloc`.** Both are now far inside their
   thresholds (`1.00` vs `1.30`, `1.0001` vs `1.25`), i.e. the margin moved from the RED side to the
   GREEN side, but they are still the two nodes that could flake on a different interpreter.

## 7. Suggested next task

**Inc-3 — documentation and closure (3 files):** `REQUIREMENTS.md` (the `R-TUI-098` entry **including
non-claims (e) and (f)**, traceability rows, the §6.5 amendment log of §9/§9b **plus A-41…A-43**),
`.dev-flow/BACKLOG-CODE.md` (the §10.3 / §10.5 / §10.7 / §10.8 / §10.9 / §12 X-8 carries, each **with its
number**), and `.dev-flow/2026-07-28-batch-65/PLAN.md`. `TC-497` is authored and gated there. Its gate:
the full non-slow suite, no requirement without a validation method, the 7-string grep list passing, and
the judgement half signed by a named reviewer.

**Amendments this increment introduces, for Inc-3's log:**

| id | Before | After |
|---|---|---|
| **A-41** | `LLR-103.1`'s seam: Inc-1 pinned `report_service._LAST_ADDENDUM_REGION_OPS`, a module-level `int` | the keyword-only `_addendum_lines(..., ops_counter: Optional[List[int]])` — the other form the same LLR offers. Operator ruling: `report_service` has no module-level mutable state and the function is shared by the TUI worker and the CLI, so a module global is a cross-call race dressed as an instrument. The equality gate is unchanged |
| **A-42** | `AT-194` warmed at `E = 64`, regions only; `TC-488` used 100 candidates per leaf | `AT-194` warms at full scale in **both** configurations (a ~124 kB one-time allocation otherwise drove `delta(2000)` negative); `TC-488`'s leaf size is `cap + 100`, derived from the constant, so the early-exit arm the gate assigns it can fire. **No predicate changed** |
| **A-43** | §11.1 assigns `TC-487` the RED arm `FIX-E` | `FIX-E` is **executed-GREEN** on `TC-487` — duplicate and equal-start-nested regions survive an uncoalesced bisect by accident. The arm that bites is the converse, **`FIX-E(b)`** (coalescing used for attribution), executed RED on `TC-487`, `TC-486` and `AT-196`. `TC-486`'s assignment to `FIX-E` is correct and stands |

---

## Evidence checklist

- [x] **Tests/type checks/lint pass (or why skipped).** `28 passed` on the acceptance file, exit code 0;
      `125` / `44` / `29` per regression subset, 0 failures; both frozen guards pass;
      `ruff check` → `All checks passed!`. No type checker is configured in this repo. Nothing skipped.
- [x] **No secrets in code or output.** Every fixture is a synthetic in-memory object graph under
      `tmp_path`. No golden was regenerated (`git status --porcelain tests/goldens/` → empty), so the
      Inc-1 host-path scan still holds over the committed bytes. This module performs no logging.
- [x] **No destructive commands run without approval.** No `rm -rf`, no force push, no rename, no
      deploy, no commit. Writes are confined to the three tracked files plus the scratchpad.
- [x] **File count within cap.** 3 files, under the ≤ 5 cap.
- [x] **Review packet attached.** This document.
- [x] **Every mutant arm executed against the IMPLEMENTED producer, not asserted.** Ten arms, ten pasted
      REDs, including the two that had never been executed by any lane.
