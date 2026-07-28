# batch-64 — Phase-2 RE-GATE, ARCHITECT lane (narrow)

> **Reviewing:** `.dev-flow/2026-07-28-batch-65/01-requirements.md` **revision 2** (2620 lines).
> **Tree:** `claude/batch-64-addendum-producer-bound` @ `b09ae9a`. Every figure below was executed on
> **this** tree by **this** lane (C-39). Nothing is inherited from revision 1, from the other Phase-2
> lanes, or from my own first-pass review except where a row explicitly says so.
> **New probes:** `…/scratchpad/p6_tc498.py`, `…/scratchpad/p7_inc1_verdicts.py`.
> **Scope:** discharge of my twelve findings + a new-defect check on what revision 2 CHANGED. I did
> **not** re-litigate the prefix-max correctness sweep (375 064 checks, 0 mismatches) or the subsequence
> claim (72/72) — both already verified and unchanged by revision 2.

---

## 0. Verdict

**STILL BLOCKED — one new blocker, one new major, three new minors. Nine of my twelve findings are
CLOSED; three are PARTIALLY CLOSED.** The revision is a large, honest improvement: it corrected two of
my findings on the evidence rather than accommodating them, it put the relocated `R` multiplier into the
**shipped requirement text** as non-claim (e) carrying my `500 / 4000 / 32000 / 128000`, and it pinned
the prefix-max array in `LLR-103.2`'s Statement so the residual is a decision instead of an accident.

**What still blocks is one thing, and it is the fold of my own B-3.** §11.1's per-node
expected-verdict table — the artefact created to replace *"every AT fails"* — is itself wrong on
**at least 9 of its 28 rows**. Revision 2 applied the "GREEN by construction / by vacuity" analysis to
the two nodes I happened to name (`AT-196`, `AT-198` arms 1–2) and did not apply it to the rest of the
catalog. Inc-1's gate demands the table be *"reproduced exactly"*, so it is unsatisfiable for the same
reason revision 1's gate was. Executed, on the shipped producer:

```
node     11.1 says   ACTUAL on 082ada9
TC-484   RED         GREEN    a/b/c render 'None.'=(True,True,True)  1-byte hits=1
TC-486   RED         GREEN    shipped emits 1 hit line (the >=1 the node requires)
TC-487   RED         GREEN    3 identical regions, 1 entry -> 3 hit lines
TC-481   RED         GREEN    class total K-1: hit lines=199 (<=K)  addendum notices=0
TC-482   RED         GREEN    class total K  : hit lines=200 (<=K)  addendum notices=0
TC-483   RED         RED      class total K+1: hit lines=201 (>K)          <- correct
TC-494   RED         GREEN    shipped order = ['mod','issue','mod','issue']
TC-499   RED         GREEN    addendum notices=0 (shipped _addendum_lines emits no '> TRUNCATED:')
```

plus `TC-485` (a guard asserted on shipped code at `:1719`, trivially GREEN) and `TC-498` (§3 below).

| # | severity | one line |
|---|---|---|
| **N-1** | **blocker** | §11.1 mis-states the Inc-1 verdict for ≥ 9 of 28 nodes; Inc-1's gate *"the table reproduced exactly"* is unsatisfiable. **Executed above.** This is B-3's defect class, surviving B-3's fold. |
| **N-2** | major | `TC-498`'s instrument is undefined, and `A == R × N` holds under only **one** of three defensible counting conventions (executed: `128000` / `256000` / `257000` at `R = 256`). `LLR-103.2`'s own reversible design note flips two of them. An exact-equality gate on an unpinned counter invites tuning the counter to the number — the **M-4 defect class, re-created**. |
| **N-3** | minor | `HLR-103`'s *Numeric pass threshold* bullet states the region-ops arm as `A ≤ c × (N + total_hits)` — a bound the document itself says is expected RED and does **not** adopt. The adopted form appears only in the prose after it. |
| **N-4** | minor | §6.3's *"RED by ≥ 50 % margin"* rule is undefined for the 7 boolean expected-RED nodes, and for `AT-194` the tightest observed RED clears it by **3.8 percentage points** (executed: `2.000 / 1.30 = 53.8 %`). |
| **N-5** | minor | §12's preamble still reads *"X-2 and X-5 carry an open obligation"* while the X-2 row reads **CLOSED** — stale residue of the M-6 fold. |

**If N-1 and N-2 are folded, revision 2 is implementable as written.** Everything else in this document
is confirmation, not objection.

---

## 1. Discharge table — my twelve findings, ruled strictly

| # | verdict | evidence, and what remains |
|---|---|---|
| **B-1** | **PARTIALLY CLOSED** | **Closed:** the claim is narrowed to *candidate consumption* in `R-TUI-098`'s Statement (`:331-333`) and `HLR-103`'s (`:391-393`); non-claim (e) (`:356-363`) carries my `500 / 4000 / 32000 / 128000` verbatim and the word **relocated**; §10.7 exists with both lanes' tables and the `all-nested` irreducibility paragraph (my fold 4); §14's diagram now labels `A` on the hot path and its dashed edge says *"region ops STILL `R × N` under huge+tiny"*. All three moves I recommended (fold 3 + fold 2 + fold 4) landed. **Remains:** my fold 2 asked for a *non-proxy oracle*. `TC-498` is that oracle in name only — see N-1 (its Inc-1 verdict is wrong) and N-2 (its instrument is undefined). The claim is now true; the guard on it is not yet sound. |
| **B-2** | **CLOSED — and the correction is right** | Verified on disk: the census key is built at `tests/test_report_field_census.py:363-364`, `("md_safe", "result.variant_id")` **is** an entry at `:344`, and `result.variant_id` is the live spelling the shipped `_addendum_lines` already escapes three times (`report_service.py:1567`, `:1574`, `:1582`). So escaping **in place** genuinely adds no census key and my *"infeasible"* was conditional on my probe's local rebinding. **The correction is factually correct and I accept it.** Revision 2 nonetheless pins the spelling (`LLR-103.5`, `:880-889`) **and** gives Inc-2 the file (`:2273`) with an **unconditional** `PLANTED` obligation — which is the right call for the reason stated: a spec must not leave a guard's verdict to an implementer's incidental choice. The second half (the `.format()` notice being invisible to the column-0 `JoinedStr` guard at `:860`) is recorded at §10.10 and `LLR-103.5:890-897`. Inc-2 = 2 files, inside budget. |
| **B-3** | **PARTIALLY CLOSED** | **Closed:** §6.3's *"every AT"* is qualified (`:1084-1093`), the mutant-arm clause landed **verbatim including my mandatory last sentence**, §11.1 exists, and §6.2 gains a pre-fix executability ledger. `AT-196` and `AT-198` arms 1–2 are correctly re-labelled regression guards. **Remains: N-1.** The analysis was applied to the two nodes I named and to no others; ≥ 9 rows are wrong and Inc-1's gate is still unsatisfiable. |
| **M-1** | **CLOSED** | `LLR-103.4:784-793` pins all five golden shapes to **literal** `E`, states why `200` was chosen, and `LLR-103.6:918-922` scopes the `K → 37` mutation to the `K`-derived nodes (`TC-481/482/483`, `AT-197/198/201/202`), explicitly excluding `TC-491`/`AT-196`. Both sides of the contradiction resolved. |
| **M-2** | **CLOSED** | The variant-major invariant is in `LLR-103.1`'s **Statement** (`:588`, *"shall keep `variant_results` as the outermost loop"*), justified at `LLR-103.1:630-635` and `LLR-103.3:742-748`, asserted by `TC-490` on a **non-contiguous-contributor** fixture (§6.2 `:1059`), and drawn into §14. Exactly the fold I asked for. |
| **M-3** | **CLOSED** | Inc-1's content is now `AT-194`, `AT-196…203` + `TC-480…495`, `TC-498`, `TC-499`, with *"`TC-497` is NOT here"* stated inline (`:2272`); `TC-497` is authored **and** gated at Inc-3 (`:2274`, `:2301`). One node, one authoring increment, one gating increment. |
| **M-4** | **PARTIALLY CLOSED** | **Closed:** §7 T-1 re-labels `2.27` fixture-specific, states *"the acceptance uses neither number"*, and §6.3 + Inc-1's gate now read *failing side, named fixture, pasted transcript* — the substance of my fold. **Remains: N-4.** The `≥ 50 %` quantifier was generalised over **all** expected-RED nodes; it is undefined for the boolean ones and has 3.8 pp of headroom for `AT-194`. |
| **M-5** | **CLOSED (narrowed) — and the correction is right** | Verified on disk: three `> TRUNCATED:` emitters at `report_service.py:1134`, `:1383`, `:1403`; `:1383` and `:1403` each pair with `notes.append(...)` (read at `:1383-1387` and `:1403-1407`); **`:1134` sits inside `_declaration_error_lines`, declared `-> List[str]` at `:1053`, with no `notes` channel at all.** **The convention is 2 of 3 and my "breaks the module's own convention" framing was wrong.** Ruling on the choice: **disclose is now adequately justified** — see §4. |
| **M-6** | **CLOSED** | §7 T-1 carries both Phase-2 transcripts including my 3-rep `1.018`, the agreement table, and *"the Inc-2 re-derivation obligation is STRUCK"*; Inc-2's gate (`:2273`) no longer carries it; §12 X-2 records the judgement. Only N-5 (a stale preamble line) remains, and it is cosmetic. |
| **m-1** | **CLOSED** | `LLR-103.4:794-801` pins `S ≥ 2` as a fixture precondition **in the requirement**, with the `S = V = 1` class-grouping re-verified against `report_service.py:1554-1583` and the vacuity consequence (`TC-494` GREEN on `FIX-B`) stated. |
| **m-2** | **CLOSED** | Corrected to `:1134` / `:1383` / `:1403` in §8.2, §2.3, §10.8 — and re-verified by this lane, above. |
| **m-3** | **CLOSED** | `LLR-103.2`'s **Statement** (`:650-652`) now says *"a prefix-maximum-of-ends **ARRAY** (`pmax[i] = max(ends[0..i])`, a plain `List[int]` built once per call in `O(R)`)"*, with a STRUCTURE PINNED bullet (`:684-700`) arguing array vs segment tree and naming §15 item 7 as the reversal trigger. The ambiguity B-1 turned on is gone. |

**Tally: 9 CLOSED · 3 PARTIALLY CLOSED · 0 NOT CLOSED.**

---

## 2. Ruling on the three B-1 moves

### Move 1 — the narrowed claim. **Sound. It is now true.**

*"consume the candidate set in a single pass whose candidate consumption is independent of the
declared-region count"* is exactly what `TC-488`/`TC-489` measure and exactly what the adopted design
delivers. `HLR-103`'s Rationale states the reason in the right words — *"A statement must claim what its
oracle tests"* — and non-claim (e) says **relocated**, not removed, with the numbers. This is the fold I
recommended (fold 3) and it is correctly executed. Independent confirmation from my own probe: under
`huge+tiny` at `R = 256` the fixed attribution produces **500 hits** — output R-independent — while
paying `128 000` region comparisons. The claim and the residual are both true simultaneously, which is
the whole point.

### Move 2 — the residual. **Honestly stated. Better than I asked for.**

§10.7 carries both lanes' fixtures side by side, states the law `A = R × N`, states the attacker model
precisely (*the operator declares the geometry; the attacker chooses the addresses; ONE enclosing region
suffices*), states that it is **not** a memory regression, and adds the paragraph I asked for warning an
implementer not to "optimise" the `all-nested` case. `TC-497`'s 7-string grep list forces
`500 → 128000` into `REQUIREMENTS.md` and the PR body. Nothing is smoothed.

### Move 3 — a pinned equality as the instrument. **Right in principle, defective in execution.**

The argument *"a bound like `A ≤ c × (N + hits)` cannot pass against the adopted array, and a gate that
cannot pass is the same defect class as one that cannot fail"* is **correct, and it is a better answer
than my fold 2 as I wrote it.** My fold assumed the segment tree; once the array is pinned, my bound
becomes a permanent RED, which is not a gate. A pinned equality is falsifiable in **both** directions —
it fails if the cost grows and it fails if a later batch improves it — which is precisely the property
§15 item 7 wants. **I accept the instrument choice.**

**What is defective is the instrument's definition, and its expected verdict.** Two executed problems:

**(a) `A == R × N` is GREEN on the SHIPPED producer** under any generic region-comparison counter,
because the shipped `_addendum_lines` (`:1554-1583`) loops `for region: for candidate:` and calls
`DeclaredRegion.contains` exactly `R × N` times. Executed (`p6_tc498.py`, huge+tiny, `N = 500`):

```
== Q1. SHIPPED _addendum_lines, region ops = DeclaredRegion.contains calls ==
   R   consumed(N)   region ops A   A == R x N ?   matches
    1          500            500          GREEN   1
    8          500           4000          GREEN   1
   64          500           32000         GREEN   1
  256          500          128000         GREEN   1
```

So §11.1's *"`TC-498` … expected @ Inc-1: **RED** (`SHIP` has no attribution walk to count)"* is false
under that instrument. Under the *other* instrument — a counter inside the new attribution walk — the
subject does not exist on `082ada9` at all, which makes `TC-498` **NOT EXECUTABLE PRE-FIX**, belonging
in the `xfail(strict=True)` row with `TC-490`/`TC-492`/`TC-495`. **Neither reading yields "RED".**
This is part of N-1.

**(b) The equality is instrument-dependent.** `LLR-103.1`'s only definition is *"counts region
comparisons at the attribution call"*. Executed against `LLR-103.2` implemented verbatim:

```
== Q2. LLR-103.2 verbatim (prefix-max ARRAY): what does 'region ops' count? ==
   R   A(ends only)   A(pmax+ends)   A(+bisect)   R x N     which one is 'A == R x N'?
    1            500           1000         2000       500     ends-only
    8           4000           8000         9000      4000     ends-only
   64          32000          64000        65000     32000     ends-only
  256         128000         256000       257000     128000    ends-only
```

Only the **`ends[i] >= addr` comparisons** satisfy the equality. Counting the `pmax[i] >= addr` guard as
well — an equally natural reading of "region comparison" — gives `2R × N`. And `LLR-103.2`'s own
*"Design note (informative, reversible)"* explicitly **authorises Phase 3 to drop the coalesced-cover
reject**, which changes `A` by `N` under the third convention. An exact-equality gate whose value moves
with a spec-sanctioned implementation choice will be satisfied by tuning the counter until it prints
`R × N` — which is the defect M-4 removed from the ratio gates, re-created on the new one.

**Fold (N-2), one paragraph in `LLR-103.1` + §7 T-9:** define `A` as *"the number of `ends[i] >= addr`
comparisons performed by the attribution walk"*, state that the bisects and the reject pre-filter are
**excluded** so the counter is invariant under the design note's sanctioned removal, and state the
fixture precondition the equality rests on — *every declared region's `start` lies below the probe
address, so the downward walk visits all `R` entries*. Without that precondition `A == R × N` is fixture
luck, not a law.

---

## 3. Ruling on N-1 — the increment cut and its gates

**Is every AT/TC owned by exactly one increment?** **Yes.** 9 live `AT`s + 19 live `TC`s = 28 nodes;
§11.1 lists all 28 with an *authored* and a *gated* increment, and the two retired ids appear in neither
table. `TC-497`'s double ownership (my M-3) is gone. **Clean.**

**Is every file that must change owned?** **Yes, as far as I can census.** Inc-1 owns the new test file,
the new golden and the seam-test extension; Inc-2 owns `report_service.py` **and**
`tests/test_report_field_census.py` (my B-2); Inc-3 owns the three document files. The structural census
at `:2315-2337` now extends past the engine-freeze guards to the escaper census, the column-0 guard, the
planted corpus and the batch-35 whole-document golden, and marks itself *"best-effort, gate-confirmed at
Inc-2"* rather than "VERIFIED COMPLETE". `tests/test_report_service.py`'s four addendum tests are
explicitly required to stay green **unmodified**, so they need no owner.

**Is each increment's gate satisfiable?** **Inc-2 and Inc-3: yes. Inc-1: NO — N-1.**

Inc-1's gate is *"the per-node expected-verdict table below is reproduced exactly"*. The table asserts
**RED at Inc-1** for a block of nodes that are GREEN on `082ada9` by construction, by vacuity, or
because the thing they guard is a hazard of the **new** implementation rather than a defect of the
shipped one. Executed (`p7_inc1_verdicts.py`, shipped `_addendum_lines` driven directly):

```
node     11.1 says   ACTUAL on 082ada9   predicate / evidence
TC-484   RED         GREEN    N=0 -> 'None.'; no variants; address None; 1-byte region
                              a/b/c render 'None.'=(True, True, True)  1-byte hits=1
TC-486   RED         GREEN    hit at 0x5000 inside outer, beyond inner's end -> >=1 hit
                              shipped emits 1 hit line(s)
TC-487   RED         GREEN    3 identical regions, 1 entry -> emitted 3 times
                              shipped emits 3 hit line(s)
TC-481   RED         GREEN    class total K-1=199: hit lines <= K and 0 notices
                              hit lines=199  addendum notices=0
TC-482   RED         GREEN    class total K=200: hit lines <= K and 0 notices
                              hit lines=200  addendum notices=0
TC-483   RED         RED      class total K+1=201: hit lines <= K
                              hit lines=201  addendum notices=0
TC-494   RED         GREEN    S=2 expected sequence mod,issue,mod,issue
                              shipped order=['mod', 'issue', 'mod', 'issue']
TC-499   RED         GREEN    addendum-scoped notices == 0 while the :1134 emitter fires
                              addendum notices=0
```

Three distinct causes, and the spec's own text already contains the proof for two of them:

1. **GREEN by construction on shipped behaviour.** `TC-484`'s four sub-cases are described at
   `:450-451` as *"All four executed against the **shipped** function (qa §7.6) and `FIX-A` reproduces
   all four exactly"* — a node whose expectation the shipped code already satisfies cannot be RED
   against it. Same for `TC-487` (shipped emits `M` times, which is the behaviour `LLR-103.2` promises
   to **reproduce**), `TC-494` (the "expected sequence" **is** the shipped sequence — that is why the
   golden exists), and `TC-485` (a guard asserted on `report_service.py:1719`, unchanged code).
2. **GREEN by vacuity, exactly like `AT-198` arms 1–2.** `TC-481`, `TC-482` and `TC-499` assert
   *absence* — `≤ K` hit lines, or **0** addendum notices — and the shipped producer emits no notice at
   all and does not exceed `K` below the boundary. `TC-499` is the sharpest case: it is the **positive
   control for addendum-scoped counting**, and its predicate reads 0 on a producer with no notice
   concept whatsoever.
3. **The RED belongs to a different subject.** `TC-486`'s threshold at `LLR-103.2:658-661` records the
   pre-state as *"`address_in_sorted_ranges(0x5000, …) = False` while ground truth is `True`"* — that is
   **`range_index`'s primitive** being wrong, not the addendum. The shipped addendum uses
   `DeclaredRegion.contains` and is **correct** on overlapping regions. `TC-486` guards a hazard the
   **new** implementation introduces (the coalescing precondition); it has nothing to fail against on
   `082ada9`.

There is a defensible counter-reading for `TC-481`/`TC-482`: `LLR-103.5:865` requires boundary fixtures
to *"derive `E` as `K-1`/`K`/`K+1` from the **imported constant**"*, which does not exist pre-fix — so
those nodes would raise at import. But an import error is a **collection error, not a RED on a
threshold**, and §6.2's ledger already created the correct category for exactly that case
(`NOT EXECUTABLE PRE-FIX → xfail(strict=True)`). Under either reading the table's "RED" is wrong.

**Fold (N-1), mechanical and small.** Re-derive the Inc-1 column per node into the three categories the
document already has, rather than by block:

- **RED (genuinely falsifiable pre-fix):** `AT-194`, `AT-197`, `AT-198` arm 1b, `AT-199`, `AT-200`,
  `AT-201`, `AT-202`, `AT-203`, `TC-480`, `TC-483`, `TC-488`, `TC-489`, `TC-493`.
- **GREEN — regression guard / by vacuity, falsifiability carried by a named mutant arm:** `AT-196`,
  `AT-198` arms 1–2, `TC-481`, `TC-482`, `TC-484`, `TC-485`, `TC-486`, `TC-487`, `TC-491`, `TC-494`,
  `TC-499`.
- **NOT EXECUTABLE PRE-FIX (`xfail(strict=True)`):** `TC-490`, `TC-492`, `TC-495`, and — per §2(a) —
  `TC-498`.

Then apply §11.1's own rule to the newly-GREEN rows: **each needs a named mutant arm reproduced at
Inc-2**, or it has no demonstrated detection power. Most already have one (`FIX-B` for `TC-494`,
`FIX-E` for `TC-486`, `FIX-G` for `TC-482`). `TC-484`, `TC-485`, `TC-487` and `TC-499` do not, and the
spec should either name one or state in the row that they are pure regression guards over unchanged
behaviour. **That is the honest version of the table, and it costs one editing pass — no design change,
no re-measurement.**

---

## 4. Ruling on M-5 — is *disclose* adequately justified?

**Yes, and the correction to my framing is right.** Verified on this tree:

```
$ grep -n "TRUNCATED" s19_app/tui/services/report_service.py
1134:            f"> TRUNCATED: {omitted} of {omitted + MAX_REPORT_ISSUES_PER_VARIANT} "
1383:        put([f"> TRUNCATED: {text}.", ""])
1403:        out.extend([f"> TRUNCATED: {text}.", ""])

:1383 -> followed immediately by notes.append(f"Variant '{md_safe(result.variant_id, …)}': {text}.")
:1403 -> followed immediately by notes.append(f"Variant '{md_safe(result.variant_id, …)}': {text}.")
:1134 -> inside `def _declaration_error_lines(result: VariantExecutionResult) -> List[str]:` (:1053)
         no `notes` parameter, no `notes` return, no notes.append anywhere in the function
```

**2 of 3, confirmed. My "breaks the module's own convention" was an overstatement**, and the addendum
follows the `_declaration_error_lines` precedent rather than diverging from a universal rule. §10.8's
three reasons are sound in that light: (1) the precedent exists; (2) threading `(lines, notes)` puts a
**second** structural change on an untested function inside the rewrite increment, against a batch whose
whole risk posture is "one structural change protected by a byte-identity arm"; (3) US-B64-2's outcome
is met where the operator is actually looking. The residual is stated plainly, it carries at LOW, and
§15 item 8 names the module-wide unification as the reversal. My own fold offered *"record it
explicitly in §10 with a stated reason"* as an acceptable option; they took it and stated the reason.
**No further action.**

---

## 5. Ruling on `AT-194`'s layer: **keep it as an `AT`. The exception is principled, not a loophole.**

The grey zone is real, but `AT-194` and the retired `AT-195` are on **opposite sides of it**, and the
distinction is not "reads the file" — it is **whether the object under observation is the shipped one**:

- `AT-195` **substituted** a counting `list` subclass for a leaf sequence. The thing measured was a
  test double wired into a private call path; the predicate was unreadable from any operator-visible
  artefact; and `TC-488` already asserted the identical predicate on the identical instrument.
  Retiring it was correct.
- `AT-194` substitutes **nothing**. `tracemalloc` is an external observer of the *unmodified* shipped
  call, it references no private symbol, and the quantity — additional resident memory attributable to
  the addendum — is the operator-facing quantity US-B64-1 is written about. The report file **is**
  produced by the same call and §3's Deliverable clause makes it a mandatory co-assertion
  (*"An AT that produced no file fails"*).

There is also a structural reason not to demote it. US-B64-1's other Layer-B node, `AT-196`, is a
regression guard that is **GREEN at Inc-1 by construction** and whose falsifiability is carried entirely
by mutant arms. Demote `AT-194` and US-B64-1 has **zero** black-box nodes capable of going RED against
the pre-fix tree — the story's behavioural chain would be certified only by white-box `TC`s and by
mutants of a producer that does not exist yet. That is a worse spec, not a purer one.

**Conditions I would attach, both already satisfied in the text — keep them:** the co-assertion must be
a real assertion in the test body (file exists, non-empty, still carries `## Addendum: declared regions`
and its per-region sub-headings — `:434-437`), and the delta must be taken across the *same* call that
wrote the file (`:436`). If a future edit weakens either, the exception lapses and `AT-194` becomes an
`AT-195`.

---

## 6. New findings in detail

### N-3 (minor) — `HLR-103` states a threshold it does not adopt

`:416-420` reads: *"**region ops `A ≤ c × (N + total_hits)`** at `R ∈ {1, 8, 64, 256}` under `huge+tiny`
geometry … This arm is **expected RED** against the adopted prefix-max array and is therefore specified
as a **disclosure counter** … see §7 T-9 for the exact form"*. The bound that appears **in the
requirement's Numeric pass threshold list** is the one the system is designed to fail; the adopted form
(`A == R × N`) appears only in the following sentence and in §7. A Phase-3 implementer skimming the
bullet list — or the transcriber copying `HLR-103` into `REQUIREMENTS.md` — writes the failing assertion.
**Fold:** state the bullet as `A == R × N` (disclosure counter, §7 T-9, §10.7) and move
`A ≤ c × (N + hits)` into the explanatory clause as the **rejected** form.

### N-4 (minor) — the `≥ 50 %` RED margin is over-generalised, and thin where it applies

Executed on this tree:

```
node                        observed  threshold  margin over threshold  >= 50% ?
AT-194 RED (arch P2)          2.000       1.30                 53.8%  YES
AT-194 RED (qa P2)            2.265       1.30                 74.2%  YES
AT-194 RED (qa P1)            2.270       1.30                 74.6%  YES
TC-493 RED (arch P1)          1.980       1.25                 58.4%  YES
TC-493 RED (qa P2)            1.982       1.25                 58.6%  YES
TC-488 RED R=1 consumed/N     1.000       1.00                  0.0%  NO
TC-488 RED R=8 consumed/N     8.000       1.00                700.0%  YES
```

Two problems. **(a)** Seven of the expected-RED nodes are **boolean** (`AT-197`, `AT-199`, `AT-200`,
`AT-201`, `AT-202`, `AT-203`, `TC-480`): *"failing side of its threshold by ≥ 50 %"* has no meaning for
"0 notices where 1 is required", yet Inc-1's gate quantifies over **every** expected-RED node.
**(b)** The mechanism drives `AT-194`'s RED toward exactly **2.0** (the delta doubles when `E` doubles),
and `2.000 / 1.30 = 53.8 %` — the rule has **3.8 percentage points** of headroom against the value the
mechanism actually produces. An Inc-1 fixture reading `1.94` is a *correct* RED that **fails the gate**.
**Fold:** scope the margin rule to *ratio-valued* thresholds and lower it to `≥ 25 %`, and state the
boolean nodes' RED condition as *"the asserted predicate is false, with the observed value pasted"*.

### N-5 (minor) — §12's preamble contradicts its own X-2 row

`:2343` still reads *"X-2 and X-5 carry an **open obligation**"*; the X-2 row reads *"**CLOSED at
Phase 2 — no obligation carried**"*. One line, but §12 is the section a later batch greps for open
obligations. **Fold:** *"X-5 carries an open obligation; X-2 was closed at Phase 2."*

---

## 7. What I checked and did **not** find

Stated because a manufactured finding is worse than none.

- **No claim in `R-TUI-098` is now false.** I re-read all six non-claims against the executed evidence;
  (a)–(f) are each supported by a number in §10 with a lane attribution, and (e) is mine.
- **The new nodes are not redundant.** `AT-201` (class axis) and `AT-202` (variant axis) are genuinely
  independent — the spec's own executed transcript shows `FIX-G` GREEN on the variant axis and `FIX-H`
  GREEN on the class axis. `AT-203`'s region axis is covered by neither.
- **The `AT-195` retirement does not lose an observable.** `TC-488`/`TC-489` carry it, and `TC-498` adds
  to it. §5.2's refusal to re-point either retired id is the right rule.
- **`LLR-103.5`'s pinned spelling is implementable.** `result.variant_id` is in scope at the recording
  site — the shipped traversal already escapes it three times inside the same loop nest.
- **The diagram is honest.** §14's dashed edge names the axis that improved **and** the axis that
  relocated, in the same annotation.
- **Nothing in §17 quietly dropped a finding.** All twelve of mine appear with a disposition and a
  "lands in" pointer, and every pointer I sampled resolves to text that exists.

---

## 8. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Every threshold I assert executed on THIS tree (C-39) | ✓ | `p6_tc498.py` (SHIP region ops + 3 counting conventions), `p7_inc1_verdicts.py` (8 nodes vs shipped), the margin arithmetic in §6 — all pasted |
| 2 | Each of my 12 findings ruled with evidence, not narrative | ✓ | §1, every row cites a line on this tree |
| 3 | Both corrections to my findings independently re-verified | ✓ | B-2: `test_report_field_census.py:344`/`:363-364` + `report_service.py:1567/1574/1582`. M-5: `:1053`, `:1134`, `:1383-1387`, `:1403-1407` |
| 4 | New defects found on what revision 2 CHANGED, not on what I already verified | ✓ | N-1 (§11.1, new), N-2 (`TC-498`, new), N-3 (`HLR-103` threshold, new), N-4 (§6.3 gate form, new), N-5 (§12, new) |
| 5 | ≥ 2 options offered for each fold | ✓ | N-1 (re-derive per node vs demote the gate to "per the table, categories included"); N-2 (pin the counter vs drop the equality for a recorded-value-only assertion) |
| 6 | Set-derived, not hand-listed (C-31) | ✓ | §3's verdicts come from driving the shipped function per node, not from reading the table |
| 7 | Runtime identity probed (C-15) | ✓ | both probes import and call the **real** `report_service._addendum_lines` and the **real** `DeclaredRegion` |
| 8 | No counterfactual written into the worktree | ✓ | both probes are read-only importers; no file in the repo was created or edited by this lane except this document |
| 9 | Risks of my own recommendations stated | ✓ | §9 |
| 10 | Nothing predicted or inherited | ✓ | every number here was produced by a command run in this session |

---

## 9. Risks of my own recommendations

- **N-1's fold makes ~11 nodes GREEN at Inc-1.** That is a real loss of pre-fix falsification pressure,
  and the honest mitigation — a named mutant arm per newly-GREEN node — is work. But the alternative is
  a gate that cannot be met truthfully, and an author who meets it literally will manufacture REDs. I
  would rather the spec say "11 of 28 are regression guards" out loud than have Inc-1 record 11 false
  REDs.
- **N-2's fold pins `A` to `ends[i] >= addr` comparisons only**, which makes `TC-498` blind to a change
  that doubles the `pmax` guard work. That is acceptable: `TC-498` is a *disclosure* counter for §10.7,
  not a performance gate, and pinning it to the one quantity §10.7 actually reasons about is what makes
  the equality meaningful.
- **N-4's fold lowers a threshold** (50 % → 25 %), which is the move this batch is otherwise right to be
  suspicious of. The difference: it is lowered **before** any measurement, on a stated mechanism
  (RED → 2.0 asymptotically), not widened at a gate to make a failing run pass.
- **I did not verify** the `FIX-B…FIX-I` mutant arms, the qa/security lanes' Phase-2 transcripts, the
  `123 passed` / `44 passed` regression baselines, or the notice's own resident cost. Those remain
  unverified by this lane and I am not asserting them.
- **Probe scripts live in the scratchpad**, not the repo:
  `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-OneDrive-Documents-Github-s19-app--claude-worktrees-backlog-revision-s19-app-a6e12c\9f2a68ff-2369-4781-a9fe-714a18959601\scratchpad\{p6_tc498,p7_inc1_verdicts}.py`

---

## 10. Gate recommendation

**One more bounded editing pass — no re-measurement, no design change, no return to the drawing board.**

1. **N-1 (blocker)** — re-derive §11.1's Inc-1 column per node into the three categories the document
   already defines, and attach a mutant arm (or an explicit "pure regression guard" note) to each
   newly-GREEN row. ~30 lines of table.
2. **N-2 (major)** — define `A` as the count of `ends[i] >= addr` comparisons, exclude the bisects and
   the reject pre-filter, and state the fixture precondition the `A == R × N` equality rests on. One
   paragraph in `LLR-103.1` + one in §7 T-9. Fix `TC-498`'s Inc-1 verdict in the same edit.
3. **N-3 / N-4 / N-5** — one line each.

**After those, I sign off.** Revision 2 did the hard part: it made the requirement true, put the
residual it had been denying into the shipped requirement text with executed numbers, chose the data
structure in writing, named the reversal trigger, and corrected two of my findings on the evidence
rather than accommodating them. What remains is that the fold of B-3 was applied to the two nodes I
named and not to the catalog it belongs to — which is precisely the "partially closed" pattern batch-63
paid for, caught here instead of at Phase 3.
