# batch-64 — Phase-2 review, ARCHITECT lane (independent)

> **Reviewing:** `.dev-flow/2026-07-28-batch-65/01-requirements.md` (1213 lines, consolidated spec).
> **Tree:** `claude/batch-64-addendum-producer-bound` @ `082ada9`. Every figure below was executed on
> **this** tree by **this** lane (C-39). Nothing is inherited from the Phase-1 lanes or from batch-63.
> **Probe scripts:** `…/scratchpad/p1_prefixmax.py`, `p2_cost.py`, `p3_subseq.py`, `p4_census.py`,
> `p5_x2.py` (paths in §7).

---

## 0. Verdict

**BLOCKED — 3 blockers, 6 majors, 3 minors.** None of them is the design. The single-pass /
one-ordered-list-per-region / three-counters shape is **correct**, and I verified its two load-bearing
claims by execution rather than accepting them:

- the **subsequence property holds** — 72/72 configurations across 6 geometries, **0 violations** (§2);
- the **prefix-max resolver is sound** — **375 064** address checks including 3 000 random geometries,
  **0 mismatches** against `DeclaredRegion.contains` (§3).

I also **closed the spec's own open obligation X-2** by measurement: `AT-194`'s GREEN on the shape the
spec actually adopts (no early exit) is **1.018**, 3/3 reps, deterministic, against a threshold of 1.30
(§4). It does not need to go to Inc-2.

What blocks is narrower and sharper: **the requirement claims R-independence that the adopted structure
does not deliver, and the acceptance that guards it measures a proxy that cannot see the difference**
(B-1) — the exact defect class this batch exists to stop repeating. Plus two mechanical gate defects
that make the increment cut unrunnable as written (B-2, B-3).

| # | severity | one line |
|---|---|---|
| **B-1** | **blocker** | `R-TUI-098`'s "cost independent of the declared-region count" and §10.1's `R×V×E → V×E` are **false** under a constructible geometry; `AT-195`/`TC-488`/`TC-489` count leaves consumed, not region comparisons, and stay GREEN at `R = 256` while work grows ×256. |
| **B-2** | **blocker** | Inc-2's ONE-file cut is infeasible: `tests/test_report_field_census.py::test_census_covers_every_escaped_expression_in_the_source` is a **source-AST** census that fires on the notice's new `md_safe` site. No increment owns that file. Executed. |
| **B-3** | **blocker** | `AT-196` is **GREEN at Inc-1 by construction** (byte identity vs a golden captured from the shipped producer). Inc-1's gate "every AT fails" and §6.3's "every AT shown RED before the fix lands" are unsatisfiable for it. |
| **M-1** | major | `TC-492`'s "suite stays green at `K = 37`" contradicts `LLR-103.4`'s committed golden shape `(1,1,200 == K)`. One of the two must change. |
| **M-2** | major | `LLR-103.5`'s `+N more` distinct-variant count is achievable in `O(1)` **only** under a variant-major traversal invariant the spec never states — and `LLR-103.3`'s "independent of the variant count" bound is true only under it. |
| **M-3** | major | `TC-497` is owned by Inc-1 (created) **and** Inc-3 (passes); Inc-2's gate "Inc-1 tests GREEN" cannot hold with it. C-18/C-21 ownership violation. |
| **M-4** | major | §7 T-1's RED **2.27** is fixture-specific — I measure **2.000** on mine. Inc-1's gate demands "the recorded RED figures of §7 reproduced"; a test with its own fixture cannot reproduce them. |
| **M-5** | major | The notice **breaks the module's own truncation convention**: both other `> TRUNCATED:` sites pair with `notes.append(...)` feeding the Truncation appendix; `_addendum_lines` has no notes channel and §8.2 never considered it. Directly affects US-B64-2's outcome. |
| **M-6** | major | X-2 was carried to Inc-2 as an open obligation when it was closable at Phase 1. Closed here (§4); fold the number and strike the row. |
| **m-1** | minor | §0 item 2 / §9 A-1 say the shipped order "interleaves `mod, issue, mod, issue`". True only for `S ≥ 2` or `V ≥ 2`; at `S = V = 1` it is class-grouped. `TC-494`'s fixture must pin `S ≥ 2` in the requirement, not only in qa §3.2. |
| **m-2** | minor | §8.2 cites `report_service.py:1381, :1401` for the blockquote convention; the actual emissions are `:1383` and `:1403` (and there is a **third** at `:1134`). |
| **m-3** | minor | `LLR-103.2`'s "prefix-max-of-ends structure" is under-specified — a prefix-max **array** and a max-**segment-tree** have the same correctness and different asymptotics, and B-1 turns on which one is built. |

**Clean, and worth saying so:** `shall`/`should` discipline (executed: 2 `should` hits, both meta),
dual traceability (0 gaps, `AT-194…199` / `TC-480…497` contiguous), the four "does NOT claim" clauses
sitting in the **shipped requirement text** and not merely in prose, §12's refusal to average X-5, the
golden-in-Inc-1 sequencing, and the boundary plan actually reaching the behaviour (see §6).

---

## 1. What I did not find

Stated plainly, because a manufactured finding is worse than none.

- **The design is not wrong.** One ordered hit list per region + three admission counters is the right
  shape and the spec's correction of batch-63's per-class-bucket shape is correct and executed.
- **`LLR-103.2`'s coalesce + reject-prefilter + local attribution is not unsound.** I tried hard to
  break it (§3) and could not.
- **The boundary plan is not vacuous.** Despite the in-domain max of 2 hits/region, `TC-481/482/483` +
  `AT-198` derive `E` from the imported `K` and key on the class **total**, which does reach the
  behaviour (§6).
- **The `> TRUNCATED:` notice does not collide with an existing assertion.** Reverse-grepped: no test
  counts `> TRUNCATED:` occurrences in a project report (§5).

---

## 2. Item 1 — the core claim: is the admitted sequence really a subsequence? **YES, verified.**

I implemented the spec's adopted shape (one ordered list per region + three counters + the `LLR-103.2`
resolver) and compared it to the **shipped** `_addendum_lines` on this tree, over 6 geometries × 6
`(V,S,E)` shapes × `K ∈ {200, 3}`.

`…/scratchpad/p3_subseq.py`, abridged (72 rows total, full output in the script's run):

```
geometry              V  S     E     K  identical?  subseq(all regions)?   shipped/adm hits
single                1  1     1   200        True                  True        3/3
single                1  1   200   200        True                  True      600/600       <- exactly at K
single                1  1   200     3       False                  True      600/9
single                2  1   201   200       False                  True     1206/600       <- K+1, cap fires
3 identical           1  1   200   200        True                  True     1800/1800      <- duplicate regions
3 identical           2  1   201     3       False                  True     3618/27
nested                1  1   200   200        True                  True      861/861       <- overlapping
nested                2  1   201   200       False                  True     1728/1122
staggered overlap     2  1   201   200       False                  True     1296/720
disjoint+empty        1  1     0   200        True                  True        0/0
edge inclusive        1  1   200   200        True                  True       12/12        <- inclusive bound

subsequence violations = 0
```

**Findings:** the exactly-at-`K` shape is byte-identical (`identical? True` at `E = 200, K = 200`), the
cap first fires at `K+1`, and the admitted sequence is a subsequence of the shipped one in every
overlapping geometry including three byte-identical duplicate regions. §0 item 2, §9 A-1 and
`LLR-103.3`'s "subsequence by construction" are **confirmed by execution**, not merely argued.

→ **m-1** falls out of the same run: at `S = 1, V = 1` the shipped order is *not* interleaved (all
`E` modifications, then all `E` change-file issues). The interleaving §0 item 2 relies on requires
`S ≥ 2` or `V ≥ 2` — qa §3.2's dump uses `S = 2`. **Fold:** `LLR-103.4`'s `TC-494` row must state
`S ≥ 2` as a fixture precondition; a `TC-494` written on an `S = 1` fixture is GREEN on `FIX-B` (the
per-class-bucket mutant) and therefore vacuous.

---

## 3. Item 2 — is the prefix-max structure correct for arbitrary overlapping regions? **YES.**

**Answer: correct, and I could not break it.** Reference: sort by `start`; `j = bisect_right(starts, a) - 1`;
walk `i` down from `j` **while `pmax[i] >= a`**, collecting `i` where `ends[i] >= a`. Because `pmax` is a
running max it is non-decreasing, so `pmax[i] >= a` is monotone in `i` — the scan window `[i0, j]`
provably contains every match (`ends[k] >= a ⟹ pmax[k] >= a ⟹ k >= i0`; `starts[k] <= a ⟹ k <= j`).
Nothing is lost and nothing is duplicated.

Executed against `DeclaredRegion.contains` as oracle (`…/scratchpad/p1_prefixmax.py`):

```
OK  nested (3 deep)            probes= 20012 mismatches=0
OK  staggered overlap          probes=  8203 mismatches=0
OK  identical duplicates       probes=   266 mismatches=0
OK  equal-start nested         probes=  4107 mismatches=0
OK  equal-end nested           probes=  4107 mismatches=0
OK  zero-width (start==end)    probes=    13 mismatches=0
OK  adjacent (touching)        probes=   522 mismatches=0
OK  1-apart (gap of 1)         probes=   522 mismatches=0
OK  single point far           probes= 20007 mismatches=0
OK  huge + tiny (B-3b geo)     probes= 20007 mismatches=0
OK  disjoint control           probes= 12298 mismatches=0

fuzz: 3000 random geometries x 95 addresses -> mismatches=0
TOTAL address checks=375064  geometry failures=0  fuzz failures=0
```

The coalesced-cover reject never false-rejects (coalescing only widens the cover), and the `+1`
inclusive→half-open conversion is exercised by the `edge inclusive` and `zero-width` rows.

### B-1 (BLOCKER) — but the structure does not deliver the R-independence the requirement claims

Correctness is not the problem. **Cost is.** The scan window `[i0, j]` is `O(R)` whenever a wide region
sits low in the sorted order — and that is a geometry an operator can declare by accident and an
attacker cannot even be blamed for.

`…/scratchpad/p2_cost.py`, `E = 500` candidate leaves, all at one address:

```
geometry                   R  consumed(leaves)   region ops  ops/leaf  matches
all-nested                 1               500          500      1.00        1
all-nested                 8               500         4000      8.00        8
all-nested                64               500        32000     64.00       64
all-nested               256               500       128000    256.00      256

huge+tiny                  1               500          500      1.00        1
huge+tiny                  8               500         4000      8.00        1
huge+tiny                 64               500        32000     64.00        1
huge+tiny                256               500       128000    256.00        1

disjoint                   8               500          500      1.00        1
disjoint                 256               500          500      1.00        1

huge+tiny: ground-truth matching regions at 0x100000 == [0] for R in 1/8/64/256  (1 hit, R-independent output)
```

Read the **`huge+tiny`** block. One region matches at every `R` — the **output is R-independent** — yet
region comparisons are `500 / 4000 / 32000 / 128000`, i.e. **exactly `R × N`**. That is the `R×V×E`
product the batch exists to remove, moved from leaf consumption to region resolution. Geometry: one
declared region spanning the image plus `R-1` narrow regions below the hit addresses. Nothing hostile
is required — "whole calibration area" + a set of named sub-blocks is the *normal* way an operator
declares regions.

**And the acceptance cannot see it.** `consumed` — what `AT-195` / `TC-488` / `TC-489` / §7 T-2 measure
via the injected counting iterable — reads **500 at every `R` in every geometry**. `T-2`'s threshold
`consumed == N` is GREEN at `R = 256` while the work is 256×. This is precisely the batch-63 rule the
PLAN quotes back at itself: *a predicate must test what its LABEL claims*. `AT-195`'s label is "the
addendum stops re-reading the whole candidate set once per declared region"; the predicate tests leaf
re-reads only.

**What is actually false, in the shipped requirement text:**

- `R-TUI-098`: *"shall consume the candidate set in a single pass **whose cost is independent of the
  declared-region count**"* — false under `huge+tiny`.
- `R-TUI-098` non-claim (b): *"the **`R` multiplier is removed**, the `V×E` pass is not"* — false; the
  multiplier is relocated, not removed.
- §10.1: *"B-3(b) reduced `R×V×E → V×E`, executed `19200 → 300` at `R = 64`"* — that `19200 → 300` was
  measured on a geometry where it holds. On `huge+tiny` at `R = 256` it is `500 → 128000`.
- §14's diagram: `O(V x E x log R + R x 3K)` — the `log R` term is `O(R)` in the worst case.

Note the `all-nested` block is a *different* case and is **not** a defect: there `R` regions genuinely
match, so `R` work per candidate is output-proportional and irreducible given `LLR-103.5`'s
per-(region, class) dropped counts. That irreducibility is itself worth stating — it is the same trade
as X-1, on the region axis, and the spec has not noticed it.

**Recommended fold (cheap, and it does not change the design):**

1. `LLR-103.2` — replace "prefix-max-of-ends structure" with a structure whose enumeration is
   **output-proportional** (a max-segment-tree over `ends`, descending, `O((1 + k) log R)` for `k`
   matches), **or** keep the prefix-max array and accept the residual. Pick one in writing; today the
   phrase admits both and they differ exactly on B-1 (**m-3**).
2. `LLR-103.1` / `T-2` — add a second, **non-proxy** arm: an operation counter on the region resolver,
   asserted `≤ c × (N + total_hits)` at `R ∈ {1, 8, 64, 256}` **under `huge+tiny` geometry**. Without
   it there is no falsifiable oracle for the R-independence claim at all, and `TC-489`'s disjoint
   control does not supply one (it reads `500` at every `R` for both a correct and an `O(R)`
   implementation — see the `disjoint` block above).
3. If the prefix-max array is kept: narrow `R-TUI-098` to *"consumes each candidate exactly once
   regardless of the declared-region count"* (which is true and is what the acceptance measures),
   move the region-comparison term into a new **§10.7 residual** carrying `500 → 128000 at R = 256`,
   and correct non-claim (b) and §10.1 to say **relocated**, not removed.
4. Either way, add to §10 the `all-nested` irreducibility: `Θ(R)` region-counter updates per matching
   candidate are forced by `LLR-103.5`'s per-(region, class) `{dropped}` obligation.

---

## 4. Item 3 — X-2: judged, and **closed here by measurement**

**Judgement: it should not have been carried to Inc-2, because it is closable at Phase 1 — and I closed
it.** Carrying an unmeasured GREEN into Phase 3 means the first honest measurement happens at a gate
where the only remaining moves are "widen" or "return to Phase 1", which is the failure mode the spec
itself names two paragraphs earlier.

I built `FIX-A` — the spec's adopted shape, **no early exit** — monkeypatched it over
`report_service._addendum_lines`, and measured `AT-194`'s exact form at the shipped surface: marginal
delta `peak(with declared_regions) − peak(declared_regions=())`, `V = 1`, ratio `delta(4000)/delta(2000)`.
Fixtures built **before** `tracemalloc.start()` (inherited finding #7). `…/scratchpad/p5_x2.py`:

```
threshold: <= 1.30 (s7 T-1). RED recorded 2.27 (SHIP). GREEN recorded 1.002 on FIX-A2 (WITH early exit).

--- rep 1 ---
  SHIP     E= 2000  peak_with=   2462022  peak_none=    843548  delta=   1618474
  SHIP     E= 4000  peak_with=   4730022  peak_none=   1493532  delta=   3236490
  SHIP     RATIO delta(4000)/delta(2000) = 2.000   -> RED vs threshold 1.30

  FIX-A    E= 2000  peak_with=   1005894  peak_none=    843548  delta=    162346
  FIX-A    E= 4000  peak_with=   1658822  peak_none=   1493532  delta=    165290
  FIX-A    RATIO delta(4000)/delta(2000) = 1.018   -> GREEN vs threshold 1.30

--- rep 2 ---   SHIP 2.000 | FIX-A 1.018
--- rep 3 ---   SHIP 2.000 | FIX-A 1.018
```

**GREEN on the implemented shape = 1.018**, 3/3 reps, byte-deterministic, **22 % below the 1.30
threshold**. The adopted threshold survives without the early exit. `FIX-A2`'s `1.002` and my `1.018`
differ by fixture, not by shape.

- **Fold (M-6):** paste these figures into §7 T-1 as *"GREEN re-derived on the implemented `FIX-A` shape
  by the Phase-2 architect lane: 1.018, 3/3 reps"*, strike X-2's open obligation from §12, and delete
  the Inc-2 gate clause *"`AT-194`'s GREEN re-derived on the implemented arm"*. Keep the anti-widening
  rule.

### M-4 (major) — the RED figure is fixture-specific and the Inc-1 gate demands it verbatim

My `SHIP` RED is **2.000**, not §7 T-1's **2.27**. Same side, same order of magnitude, different
fixture. §11's Inc-1 gate reads *"the recorded RED figures of §7 reproduced and **pasted from this
run**"* — an Inc-1 test with its own fixture **cannot** reproduce `2.27`, and an author who tries will
either tune the fixture to hit a number or record a false pass.

- **Fold:** restate the Inc-1 gate as *"each AT RED with a pasted transcript from this run, and each
  measured ratio on the failing side of its threshold by ≥ 50 %"*, and re-label §7's RED figures as
  *observed on the lane's fixture*, not as reproduction targets. Same correction applies to T-3's
  1.98/1.96 and T-2's 300/2400/19200.

---

## 5. Item 7 — touched-symbol reverse census (C-26). **Two findings, one of them a blocker.**

The spec's §11 census checked the engine-freeze guards and stopped. C-26 asks for the whole `tests/`
tree, independent of which requirement owns the symbol. Executed sweep:

```
$ grep -rn "_addendum_lines" tests/                 -> 0 hits            (spec correct)
$ grep -c "Addendum" tests/goldens/batch35/at055b-project-report.md -> 0  (spec correct)
$ grep -rc "DeclaredRegion(" tests/ | grep -v ":0"
tests/test_manifest_writer.py:3
tests/test_report_addendum.py:7
tests/test_report_field_census.py:1
tests/test_report_service.py:4
tests/test_tui_report_seam.py:18                    -> 33 total          (spec correct)
$ grep -rn "TRUNCATED" tests/*.py                   -> no project-report `> TRUNCATED:` COUNT assertion
$ sed -n '115,130p' tests/test_engine_unchanged.py  -> report_service.py absent from _ENGINE_PATHS
$ sed -n '5457,5468p' tests/test_tui_directionb.py  -> no report test in _ENGINE_TEST_FILES
$ grep -c "range_index" s19_app/tui/services/report_service.py -> 0      (spec correct)
```

So far the spec holds. Then the sweep hits `tests/test_report_field_census.py` — a file the spec **puts
in its own regression set (§6.3) and leaves out of its structural census (§11)**.

### B-2 (BLOCKER) — Inc-2's ONE-file cut is infeasible

`tests/test_report_field_census.py:353` `test_census_covers_every_escaped_expression_in_the_source`
parses `report_service.py` with `ast` and asserts the set of `md_safe`/`md_code` call sites **exactly**
equals a hand-maintained `_ESCAPED_EXPRESSIONS` dict at `:327`. Its own failure message: *"a NEW escaper
call site exists with no census entry — plant it in `PLANTED` or record why it cannot be"*.

`…/scratchpad/p4_census.py` — baseline, then the same extraction after appending the minimal plausible
Inc-2 notice builder:

```
== BASELINE (082ada9, untouched) ==
  escaper call sites in report_service.py : 18
  _ESCAPED_EXPRESSIONS entries in the test: 18
  new  = []
  gone = []
  head-of-line offenders = []

== AFTER a minimal Inc-2 notice builder that md_safe()s the variant ids ==
  new  = [('md_safe', 'vid')]   <-- assert not new  FAILS
  gone = []
  head-of-line offenders = []
```

Baseline confirmed green independently:

```
$ python -m pytest -q tests/test_report_field_census.py -k "census_covers or no_escaped_field"
..                                                                       [100%]
2 passed, 30 deselected in 0.27s
```

`LLR-103.5` mandates *"the **`md_safe`-escaped** identifiers of the variants"*, so Inc-2 adds an escaper
call site — and Inc-2's file budget is **one file**, `report_service.py`. Inc-2's own gate requires the
§6.3 regression set (which **includes** `test_report_field_census.py`, "123 passed") to be green. It
cannot be. **No increment in §11 owns `tests/test_report_field_census.py`.**

Second half of the same finding: the notice is built by `.format()` on a module constant, not by an
f-string, so `test_no_escaped_field_is_emitted_at_the_head_of_its_line` (`:860`, the A-23 column-0
static guard, which only walks `ast.JoinedStr`) is **structurally blind to the new sink** — see the
`head-of-line offenders = []` line above, unchanged after the patch. The batch's only new markdown sink
lands outside one of the two static guards that protect every other sink in the module.

- **Fold:** add `tests/test_report_field_census.py` to Inc-2 (2 files, still ≤ 5) with an explicit
  obligation: (i) a `_ESCAPED_EXPRESSIONS` entry for the notice's variant expression, (ii) a `PLANTED`
  entry so the notice's variant field joins the hostile corpus that `test_at157` / `test_at158` /
  `test_census_every_planted_field_renders_verbatim` render through markdown-it — otherwise the new sink
  is escaped but never *proven* inert at the reader, which is exactly what §2.7 says this batch must not
  repeat. Note in `LLR-103.5` that the `.format()` construction is outside the column-0 guard and that
  the literal `> ` prefix is what defuses it.
- **Alternative fold** (also acceptable, must be chosen explicitly): build the notice from the
  **already-escaped** variant strings so no new escaper site exists. That keeps Inc-2 at one file but
  leaves the new file-derived sink unplanted — I do **not** recommend it silently; if chosen, `TC-495`
  must carry the planted-corpus obligation instead.

---

## 6. Item 6 — the increment cut

**Correct and worth keeping:** the golden is captured in **Inc-1 from the SHIPPED producer on `082ada9`**
with the C-12 rationale stated in §11 — it cannot certify the rewrite against itself. The file-count
budget (3 / 1 / 3) is inside the ≤ 5 rule. `TC-496` correctly extends the existing seam drive at
`tests/test_tui_report_seam.py:355-372` (verified: that drive types `"calzone,0x1000,0x10FF"` into
`#report_declared_regions` and asserts `"modification @ 0x1000" in text`).

**And the boundary plan does reach the behaviour**, which the brief asked me to judge specifically.
The in-domain max of 2 hits/region would make every in-domain fixture vacuous, but `TC-481/482/483` and
`AT-198` derive `E` from the **imported** `K` and `AT-198` keys on the class **total** (§9 A-6's
executed trap: `flood = K-1` still notices, because `199 + 1 = K` admitted and `v3`'s collision is the
`K+1`-th). My §2 run confirms the discriminating point empirically: at `E = 200, K = 200` the output is
byte-identical; at `E = 201` the cap fires. The plan is adequate.

### B-3 (BLOCKER) — `AT-196` cannot be RED at Inc-1

Inc-1's gate: *"**All ATs RED** … every AT fails"*. §6.3: *"**Every** `AT` shown RED against the pre-fix
tree before the fix lands (Inc-1 gate)"*.

`AT-196` is byte identity + emission order, compared *"against a golden captured at **Inc-1** from the
**SHIPPED** producer"* (`LLR-103.4` Executed verification, §11 Inc-1). At Inc-1 the tree still carries
the shipped producer. **A byte-identity test against a golden captured from the code under test is GREEN
by construction.** The gate as written is unsatisfiable, and an author meeting it literally would have to
manufacture a RED — e.g. by capturing the golden from something other than `082ada9`, which destroys the
whole point of putting it in Inc-1.

`AT-198` has the same shape at reduced severity: arms 1–2 assert *absence* of a notice, and the shipped
producer emits no notice at all, so those two arms are **GREEN by vacuity** on the pre-fix tree. Only the
`K+1 → exactly 1` arm is genuinely RED.

- **Fold:** re-state Inc-1's gate as *"every AT whose observable the pre-fix producer can exhibit is RED
  with a pasted transcript; `AT-196` and `AT-198` arms 1–2 are **regression guards**, GREEN at Inc-1 by
  construction, and their falsifiability is carried by the mutant arms (`FIX-B`@3, `FIX-E`@5, `FIX-G`@10,
  qa §5.1) which Inc-2 must reproduce against the implemented producer."* Without that last clause
  `AT-196` has no demonstrated detection power on this tree at all — only on a Phase-1 prototype.

### M-3 (major) — `TC-497` is double-owned and breaks Inc-2's gate

§11 Inc-1 content is *"`AT-194…199` + **`TC-480…497`**"*; §11 Inc-3's gate is *"`TC-497` inspection
passes"*; `TC-497` inspects `REQUIREMENTS.md` + the PR body, which only exist after **Inc-3**. Inc-2's
gate is *"Inc-1 tests GREEN"* — impossible while `TC-497` is an Inc-1 artefact. C-18/C-21: one AT/TC,
one increment.

- **Fold:** state Inc-1's content as `AT-194…199` + `TC-480…496`, and assign `TC-497` to Inc-3.

### M-1 (major) — `TC-492`'s mutation contradicts `LLR-103.4`'s golden

`TC-492`/§7 T-6 threshold: *"the suite stays green when the constant is temporarily re-valued to `37`
with fixtures derived from it"*. `LLR-103.4`'s threshold names the shape `(1,1,200 == K)`, described as
*"sits **exactly at** `K`"* — i.e. `E` derived from `K`. If `E = K` and the golden was captured at
`K = 200`, then at `K = 37` the fixture emits a different document and `TC-491` goes **RED**. The
mutation and the golden cannot both be satisfied.

- **Fold:** pin the golden's fixture to **literal** `E` values independent of `K` (the other four shapes
  already are), state in `LLR-103.4` that `(1,1,200)` is a *literal* 200 chosen to coincide with the
  default `K`, and scope `TC-492`'s mutation to the boundary TCs (`TC-481/482/483`, `AT-198`) — the ones
  that *should* track the constant — rather than to "the suite".

### M-2 (major) — `+N more` vs the `V`-independent resident bound

`LLR-103.3` claims resident cost *"independent of … the variant count"* while allowing
`R × 3 × ADDENDUM_NOTICE_VARIANTS_MAX` identifiers. `LLR-103.5` requires *"truncated at
`ADDENDUM_NOTICE_VARIANTS_MAX` identifiers with an explicit **`+N more`** remainder"*. If `N` is the
count of **distinct** affected variants, computing it needs membership against all variants seen —
`O(V)` per (region, class) — which reintroduces `V` into the very bound.

It **is** achievable in `O(1)`, but only because the traversal is **variant-major** (`for result` is the
outermost loop), so a per-(region, class) `last_cut_variant` sentinel suffices. That invariant is
load-bearing and the spec never states it — and it is exactly the kind of thing an implementer breaks by
reordering loops for the B-1 fix.

- **Fold:** state in `LLR-103.3` or `LLR-103.5` that `{dropped}`'s variant remainder is counted with an
  `O(1)` last-seen sentinel, valid **because** `LLR-103.1` fixes `variant_results` as the outer loop; and
  add the invariant to `TC-490`'s assertion (`+N` equals the distinct affected-variant count, on a fixture
  where a variant contributes cut hits **non-contiguously** — the case the sentinel would get wrong if the
  loop order changed).

### M-5 (major) — the notice bypasses the module's Truncation appendix

Executed (`grep -n "> TRUNCATED" s19_app/tui/services/report_service.py`): three sites — `:1134`, `:1383`,
`:1403`. Both `:1383` and `:1403` pair the in-document marker with `notes.append(...)`, and `notes` feeds
the report's **`## Truncation appendix`** — the reader's single index of everything the report cut.

`_addendum_lines` returns `List[str]` and has no notes channel, so the addendum's cuts would appear in the
body and **nowhere in the appendix**. An operator who scans the appendix — the documented place to look —
sees no sign the addendum was truncated. That is a direct dent in US-B64-2's outcome ("I can see WHICH hit
classes were cut"), and §8.2's four-candidate matrix never evaluated it.

- **Fold:** either extend `_addendum_lines` to `(lines, notes)` and thread it into the existing `notes`
  list at `generate_project_report:1720` (one file, matches the module's convention, `LLR-103.5` gains one
  clause), **or** record it explicitly in §10 as a disclosed inconsistency with a stated reason. Do not
  leave it unstated — §10.6's M-2 disclaimer covers *marker completeness*, not *appendix consistency*.

---

## 7. Item 4 — the three "does NOT do" claims: accuracy check

| claim | in requirement text? | accurate? |
|---|---|---|
| B-3(b) **reduced** `R×V×E → V×E`, not eliminated (§10.1) | ✓ `R-TUI-098` non-claim (b) | **✗ — see B-1.** The `R` multiplier is *relocated* from leaf consumption to region resolution, not removed. `500 → 128000` at `R = 256`, executed. |
| memory-exhaustion DoS **not** closed (§10.2) | ✓ non-claim (a), with `988 B/entry`, `×1.68`/`×1.81`, `×1.94` | ✓ accurate, and my own baseline corroborates the direction: `peak_none` `843548 → 1493532` at `E: 2000→4000` = **×1.77** on my fixture (§4) — a third independent figure, consistent with both lanes' spread. |
| intra-class / cross-variant eviction **disclosed, not prevented** (§10.4) | ✓ non-claim (d) | ✓ accurate, with §8.3's rejected per-variant budget and its `R × 3K × V` cost stated. |
| `R` uncapped, resident `O(R × 3K)` (§10.3) | ✓ non-claim (c) | ✓ accurate. |

Three of four are in the **shipped requirement text** with numbers and are correct — that is good
discipline and the reason `TC-497` exists. The fourth is B-1.

---

## 8. Item 5 — the §12 contradictions, judged

| # | left open? | my judgement |
|---|---|---|
| **X-1** (is one pass irreducible?) | **resolved** | **Correctly resolved.** The architect lane's "not removable" was over-stated and the correction — removable, but *forbidden* by `LLR-103.5`'s dropped-count obligation — is right and executed on both sides (`FIX-A2` consumed 200 of 4000). §15 item 2 correctly records it as reversible by requirement amendment, not implementation choice. **No change.** Add only the region-axis mirror image (B-1 fold 4): the same obligation makes `Θ(R)` counter updates irreducible under all-nested geometry. |
| **X-2** (GREEN measured on a retired arm) | **open obligation → Inc-2** | **Should have been resolved now, and is (§4): 1.018.** Carrying an unmeasured GREEN to a gate whose only moves are "widen" or "return to Phase 1" is the failure this batch exists to avoid. **Fold M-6.** |
| **X-3** (`TC-489`'s disjoint arm) | flagged **strikeable** | **Do not strike — but do not overrate it either.** It is the only control against a stealth early exit, and a stealth early exit silently corrupts `LLR-103.5`'s counts, so keep it. But the spec implies it also guards R-independence, and my `disjoint` block shows it reads `500` at every `R` for a correct **and** an `O(R)` implementation — it has **zero** detection power for B-1. Resolve the row as **KEEP, scoped to early-exit detection only**, and add the separate `huge+tiny` ops arm from the B-1 fold. |
| **X-4** (golden location) | resolved | Correct; repo convention wins. No change. |
| **X-5** (two per-hit constants, two baseline growth rates) | **left open, not averaged** | **Correctly left open.** No acceptance keys on either, both carry provenance, and the spread is honest uncertainty. My independent `×1.77` baseline growth (§7) is a third point in the same spread and confirms that averaging would have manufactured false precision. **No change.** |
| **X-6 / X-7** | resolved | Cosmetic. No change. |

---

## 9. Evidence checklist (this review)

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Constraints re-verified, not accepted | ✓ | `_ENGINE_PATHS` `tests/test_engine_unchanged.py:120-130`, `_ENGINE_TEST_FILES` `tests/test_tui_directionb.py:5457-5468`, `canonical_report_bytes` `tests/conftest.py:970`, `MAX_REPORT_ISSUES_PER_VARIANT` `report_service.py:90`, addendum guard `:1719-1720` — all read on this tree |
| 2 | ≥ 2 alternatives considered for each fold | ✓ | B-1 fold offers segment-tree **vs** narrow-the-claim; B-2 fold offers add-the-file **vs** reuse-escaped-strings; M-5 fold offers thread-notes **vs** disclose |
| 3 | Every threshold executed on THIS tree (C-39) | ✓ | §2 (72 configs), §3 (375 064 checks), §4 (3 reps × 2 arms), §5 (AST census + pytest) — all pasted |
| 4 | Set-derived, not hand-listed (C-31) | ✓ | §3's oracle is `DeclaredRegion.contains` itself; §5's census set is extracted from the source AST and from the test module's own `_ESCAPED_EXPRESSIONS`, not retyped |
| 5 | Runtime identity probed (C-15/C-15.1/C-35) | ✓ | §2 and §4 monkeypatch `report_service._addendum_lines` and drive the **real** `generate_project_report`; §5 runs the real pytest |
| 6 | Increment ownership audited (C-18/C-21) | ✓ | B-3, M-3 |
| 7 | Reverse census across the whole `tests/` tree (C-26) | ✓ | §5 — 8 sweeps; found the guard §11's census missed |
| 8 | Risks / residuals of my own recommendations stated | ✓ | §10 |
| 9 | Nothing predicted or inherited | ✓ | no figure in this document comes from a Phase-1 artefact or from batch-63 |

---

## 10. Risks of my own recommendations

- **B-1 fold 1 (segment tree) adds real complexity** to a function whose whole point is to get simpler.
  If the operator prefers "boring", **fold 3 (narrow the claim + record the residual) is the right call**
  — it is honest, it is one paragraph, and it costs nothing. What is *not* acceptable is leaving the
  requirement claiming R-independence it does not have. My recommendation, stated: **take fold 3 + fold 2
  + fold 4**, not fold 1.
- **B-2 fold widens Inc-2 to 2 files.** Still inside the ≤ 5 budget, but it puts a test edit in the same
  increment as the source rewrite. Mitigation: the `_ESCAPED_EXPRESSIONS`/`PLANTED` edit is mechanical
  and reviewable in isolation.
- **M-5 fold changes `_addendum_lines`'s signature**, which touches `generate_project_report:1720`. That
  is inside Inc-2's one file and inside the batch's scope, but it is a second structural change to an
  untested function in the same increment. If the operator prefers, take the disclose-only option.
- **I did not measure** the notice's own resident cost, the `FIX-B…FIX-G` mutants (they are Phase-1
  artefacts I did not reconstruct), or the full §6.3 regression baselines (`123 passed` / `44 passed`).
  Those remain unverified by this lane and I am not asserting them.
- **The probe scripts live in the scratchpad**, not the repo. They are reproduction aids, not deliverables:
  `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-OneDrive-Documents-Github-s19-app--claude-worktrees-backlog-revision-s19-app-a6e12c\9f2a68ff-2369-4781-a9fe-714a18959601\scratchpad\{p1_prefixmax,p2_cost,p3_subseq,p4_census,p5_x2}.py`

---

## 11. Gate recommendation

**Return to Phase 1 for a bounded re-consolidation.** The work is small and none of it re-opens the
design:

1. **B-1** — pick fold 3 (+2, +4): narrow `R-TUI-098`'s R-independence clause and §10.1 to what the
   acceptance actually measures, add §10.7 with `500 → 128000 @ R = 256`, add the `huge+tiny` ops arm to
   `TC-488`/`TC-489`, resolve `LLR-103.2`'s structure ambiguity (**m-3**) in writing.
2. **B-2** — add `tests/test_report_field_census.py` to Inc-2 with the census + planted-corpus obligation.
3. **B-3** — re-state the Inc-1 gate; name `AT-196` / `AT-198` arms 1–2 as regression guards and bind
   their falsifiability to the mutant arms Inc-2 must reproduce.
4. **M-1…M-6** — the folds above; **M-6 is a paste, not a re-derivation** (§4's numbers are ready).
5. **m-1…m-3** — one line each.

After those, I would sign off. The spec is unusually strong — it caught its own design shape being wrong,
refused to average two lanes' constants, and put its non-claims in the shipped requirement text. B-1 is
the one place where it did to itself exactly what it was written to prevent, and it is fixable in a
paragraph.
