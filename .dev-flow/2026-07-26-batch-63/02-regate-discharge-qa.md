# batch-63 (RE-SCOPED) — Phase-2 RE-GATE: independent discharge audit

**Auditor:** independent qa lane, discharge audit only. **Base:** `claude/batch-63-report-table-caps`
@ `031ca8d` == `origin/main`. **Artifact language:** English.
**Under audit:** `01-requirements-rescoped-consolidated.md` (revision 3, normative) and its §6 claim
that A-01..A-14 discharge all 10 Phase-2 blockers.
**Ground truth:** `02-review-rescoped-architect.md` · `02-review-rescoped-qa.md` ·
`02-review-rescoped-security.md`. Every verdict below was reached by reading the SOURCE review's own
text and recommendation, then checking the consolidated document against it — **never against the
amendment table**.
**Constraint honoured: zero production-source edits, zero edits to any existing `.dev-flow` artifact.**
This file is the only file written. All counterfactuals ran in a `git archive` export of `031ca8d` at
the short root `C:/Users/jjgh8/AppData/Local/Temp/claude/b63/g1`, removed at close;
`/b63/{a,b,qa,arch,archb,r1,r2,r3,g2}` never touched. Probe script written to a file and invoked by
path. **Ceiling actually used: 4 000 synthetic hits, one 400 kB temp file, peak < 2 MB** — three
orders below the 200 000-hit / 50 MB cap. The declared-domain D1 fixture was never built.

---

## 1. BLUF — verdict: **NOT-DISCHARGED**

**4 of the 10 blockers are genuinely closed. 6 are partially closed, and the partiality is
concentrated in one place: the fold resolved the id collision by picking a list, which is exactly what
all three source reviews forbade.**

Every source review conditioned its discharge on the same clause, in three different wordings:

- security F5 — *"keep the **union** of observables (expand past AT-175 as needed) … **Do not resolve
  by picking one lane's list.**"*
- qa BLK-2 — *"**Nothing from either lane's unique ATs may be dropped silently.**"*
- architect B-4 — *"with the architect's `AT-172` (monkeypatch-the-encoder) **added** rather than
  substituted — the two `AT-172` forms are complementary, not duplicative."*

The consolidated registry carries **11 live ATs against a union of ~18 distinct observables**. Eight
union observables have **no node at all**, including the ONE both lanes independently agreed on
(`AT-167` = byte-identity / golden neutrality below the cap, now re-purposed) and the one the qa
review's own §6 called *"the D3 gate CI can actually run"* (the AST structural census). Separately,
the document supersedes `01b-qa-catalog-rescoped.md` — **40 fully-specified TC rows with asserts and
RED counterfactuals** — and replaces the whole TC layer with three id-range rows plus one named
`TC-441`. Dual traceability (AT = WHAT, TC = HOW) does not survive that.

Two discharges are **claimed but not real**:

| claim | reality |
|---|---|
| **A-14 discharges sec F6** ("narrowed to what the predicate tests") | The narrowing was **not performed**. `AT-170` reads *"On abort"* and `LLR-101.4` asserts *"a single terminal write, so an abort leaves no file"* — **executed FALSE**: a mid-write `OSError` leaves a 200 000-byte file matching `REPORT_FILENAME_REGEX`. F6's mandatory option (a) was *"narrow the label to **a composition failure** leaves no file"*. The document restates the overbroad label in new words and annotates it "Covers F6's residue". |
| **A-01 discharges arch B-4 · qa BLK-2 · sec F5** | The *collision* is closed. The *condition all three reviews attached* — keep the union, drop nothing silently — is violated at 8 observables + the entire TC layer. |

Three **new defects** the fold introduces are in §4, one of them executed unsatisfiable
(`AT-171` on the constructible negative domain).

**Recommended disposition: `iterate`**, scoped to restoring the dropped union members, re-narrowing
the fail-closed label, and re-instating three dropped obligations (`OB-SEC-1`, the resident-memory
BACKLOG carry, the low-match traversal carry). No new measurement is required — every number in the
consolidated document survives this audit.

---

## 2. Per-blocker discharge table

| # | blocker | what the **SOURCE review** actually required | claimed | **verdict** | evidence |
|---|---|---|---|---|---|
| 1 | **arch B-1** | `02-review-rescoped-architect.md:103-114`: add a clause that `_line_bytes` *"shall retain its per-line `+1` convention and shall be partition-invariant … shall not be redefined in terms of the encoder"*; re-key `AT-174` to `== len(report_bytes(l)) + 1`; adopt qa's composability AT; strike §5.2's phrasing. | A-02 | **closed** (one residual) | `LLR-102.2` now says *"byte-identical to `031ca8d`"* + partition invariance + *"Redefining it in terms of the encoder is **prohibited**"* — the refuted design is excluded by name. `AT-174` carries **both** halves, and both are needed: executed — `+1→+2` **is still partition-invariant** (566→602, invariant across 1/3/12-way partitions), so the invariance clause alone would not catch it; `len(join)` breaks invariance (565, not invariant). Residual: B-1 fix item 2 asked for the *encoder-relating* `== +1` form; `HLR-102`'s *"shall remain an upper bound of the encoder's output"* therefore has **no AT** (see §4 N-5). |
| 2 | **arch B-2** | `:158-165`: *"Add an AT that observes traversal directly and can only be satisfied by a break — instrument the per-region candidate iterator (a counting wrapper) and assert `visited <= MAX_ADDENDUM_HITS_PER_REGION + <bounded slack>`."* | A-08 | **closed** | `LLR-100.2` + `TC-441`. **Executed against both arms** on the shipped traversal shape: `cap+break` consumed **201**, `cap+NO-break` consumed **2000** at `E=2000, K=200` → the counter goes RED. This is the separation the resource ratio could not make (identical peaks 19019/19019). One spec-precision defect on the bound itself → §4 N-4. |
| 3 | **arch B-3** | `:200-207`: two parts — (a) narrow `HLR-100`'s traversal clause to *"bounded **once a region reaches the cap**"*; (b) *"carry the residual — a region matching fewer than `MAX_ADDENDUM_HITS_PER_REGION` entries still traverses O(V×E) — into §9 as a stated risk and into `.dev-flow/BACKLOG.md`. `range_index.py::build_sorted_range_index` is the existing primitive that would close it; **naming it makes the carry actionable**."* | A-05 | **partially closed** | (a) ✓ — `HLR-100` now reads *"shall stop traversing a class **once that class's bound is reached**"* and *"**once every class is at its bound**"*. (b) ✗ — `grep -c "range_index" 01-requirements-rescoped-consolidated.md` → **0**; §3.2's "what this does NOT claim" names `_modifications_lines` / `_checklist_lines` and the R-cardinality, and is **silent on the low-/zero-match O(V×E) traversal residual**; §8 carries no obligation for it. The attacker-selectable case B-3 identified (declare R narrow regions matching nothing, feed V×E entries) is now neither claimed nor carried. |
| 4 | **arch B-4** | `:248-253`: one merged allocation, both artifacts re-emitted against it, *"Recommended basis: the qa catalog's assignment …, with the architect's `AT-172` (monkeypatch-the-encoder) **added rather than substituted** — the two forms are complementary, not duplicative: the census is structural and the monkeypatch is behavioural, **and both are RED pre-fix on CI**."* | A-01 | **partially closed** | The merged registry exists (§2) and every id binds to one observable — the collision itself is closed. But the instruction was violated in the exact direction B-4 warned about: the **monkeypatch was substituted for the census, not added to it**. Consolidated `AT-172`/`AT-173` are the mutation form only; the AST structural census (qa `AT-172`) appears nowhere as an acceptance node. Full drop list in §3. |
| 5 | **qa BLK-1** | `02-review-rescoped-qa.md:104-109`: *"Keep the ruled identity, **re-label it** … and it is **not** the D3 gate. **State in the requirement that the D3 gate is the pair {structural census, encoder-mutation}**, both of which were shown RED against a wrong fix here."* | A-04 | **partially closed** | The re-label is done and done well: §2 marks `AT-174` **"PIN, not a D3 gate"**, §5.4 repeats it, and A-04 credits the ruling to the orchestrator rather than burying it. The **pair** is not stated — only the mutation half survives. The pin's counterfactual is real and worth keeping (C-26: `_line_bytes` has **0** test references, so `+1→+2` is a green-suite change today; executed above). |
| 6 | **qa BLK-2** | `:391-392`: one merged registry, *"**Nothing from either lane's unique ATs may be dropped silently.**"* Named casualties if resolved by picking: *"qa's `AT-171` (honest Length cell) and `AT-174` (composability) have **no counterpart** in the architect registry and would be lost."* | A-01 | **partially closed** | The two casualties BLK-2 named by name **were** rescued (consolidated `AT-171` honest cell, `AT-174` composability). But eight other union observables were dropped, six of them silently — §3. The named-casualty test passes; the general instruction fails. |
| 7 | **qa BLK-3** | `:171-174`: *"Verify traversal with a **counting instrument**, not with a resource ratio … assert the consumed count is `O(CAP)`, not `O(E)`. That predicate is RED against `cap,NObreak` by construction. **Bind it to `LLR-100.2` and give it its own TC.**"* | A-08 | **closed** | `LLR-100.2` states it normatively (*"shall be observable to a test through an injected counting iterable"*) and `TC-441` is named as its node. Executed RED-capability above. |
| 8 | **qa BLK-4** | `:195-197`: three parts — drop the R axis from the `<1.5` ratio; *"**replace with the honest property — `peak(R=2)/peak(R=1) ≈ 2` and `peak/region` is flat and bounded by `CAP`**"*; *"record R as an open axis **carried to batch-64**"*. Plus a warning: do not silence by widening to 2.0. | A-09 | **partially closed** | Drop ✓ (A-09, with the measured 1.89 quoted). Warning honoured ✓ (no widened threshold anywhere). **Replacement property ✗** — `AT-166` reads *"flat across V and E"*; R is simply absent, so the honest R behaviour is asserted by nothing and a fix that is *super*-linear in R is now unobservable. **Carry ✗** — §3.2 states R is unbounded in prose; §8 carries no obligation, and `grep "17.8"` → 0, so security's post-fix per-region figure did not survive either. |
| 9 | **sec F1** | `02-review-rescoped-security.md:77-90`: *"Make the cap **per hit-class**, not per region — three independently bounded, independently traversal-bounded lists … Then extend the AT: **the rendered region contains at least one hit of every class that produced one.**"* | A-07 | **closed as recommended** (residual, §4 N-1) | Adopted verbatim; `AT-165` is the recommended clause word-for-word. **Executed against the shipped producer order (`report_service.py:1518/:1524/:1532`):** per-REGION reproduces F1 exactly (`mods=200, cap=200` → **0/5** issues survive); per-CLASS → **5/5** survive and `AT-165`'s predicate is GREEN. F1's executed scenario is closed. |
| 10 | **sec F2** | `:148-160`: **three** recommendations — (1) re-key `AT-164` to `_addendum_lines`, *"Keep the shipped-surface observation as `AT-165`'s **count** assertion (`TC-453`), which is satisfiable"*; (2) *"**Extend OB-1** … Both numbers, **with their inputs, in the PR body**"*; (3) *"**Carry to `.dev-flow/BACKLOG.md`** as a named axis: `_modifications_lines` / `_checklist_lines` uncapped in E — 988 B/entry marginal, 6.3 GB at 8 documents × 8 variants … **This is a peer of the twelve document axes, not a subset of them.**"* | A-05 + A-06 | **partially closed (1 of 3, and half of that one)** | (1a) ✓ — the re-key happened under a new id: `AT-166` keys on the addendum only, and §3.4 says so explicitly. A-06's "withdrawal" of `AT-164` is therefore a rename, not a loss — see §5 attack 6. (1b) ✗ — consolidated `AT-165` is the F1 class-representation clause, **not** a count assertion; the shipped-surface hit-count observable has no node (§3, drop D-1). (2) ✗ — §8 OB-1 requires the PR to *state* the axis is not closed but **does not require the numbers**; `grep "17.8"` → 0. (3) ✗ — §8 has OB-1/OB-2/OB-3 and **none of them is the resident-memory axis**; §3.2's *"are batch-64's subject"* is prose, not an obligation. The original charter of batch-63 was to cap those two tables; the fold now carries no obligation to remember them. |

**Score: 4 closed · 6 partially closed · 0 not closed.** Two of the six partials rest on a discharge
that is *claimed* but not real (A-01's union condition; and see A-14 below, which the amendment table
lists against a major rather than a blocker but claims closure it does not have).

---

## 3. Coverage loss during id reconciliation — the load-bearing finding

The two superseded lanes carried ~18 distinct observables in 12 ids (security F5 counted "~17"). The
union is reconstructed here from the **source reviews' own comparison tables** — architect B-4's
12-row table, qa BLK-2's 12-row table, security F5's 9-row table — not from the superseded artifacts,
so the count is auditable against ground truth.

| # | union observable | source | consolidated node | status |
|---|---|---|---|---|
| 1 | hit lines ≤ cap constant, per region | arch `AT-165` / qa `AT-164` | — | **DROPPED (D-1)** |
| 2 | honest `≥K` notice, no total | arch `AT-166` / qa `AT-165` | `AT-167` | kept |
| 3 | addendum resident cost flat | arch `AT-164` / qa `AT-166` | `AT-166` | kept |
| 4 | byte-identity / golden neutrality **below the cap** | arch `AT-167` **=** qa `AT-167` (the only id both lanes agreed on) | — | **DROPPED (D-2)** |
| 5 | wide address → a report exists | arch `AT-168` = qa `AT-168` | `AT-168` | kept |
| 6 | `W−1` renders the exact decimal cell | arch `AT-169` | `AT-169` | kept |
| 7 | the **checklist twin** (`:1171`) is fixed too | arch `AT-170` / qa `AT-169` | — | **DROPPED (D-3)** |
| 8 | fail-closed | arch `AT-171` / qa `AT-170` | `AT-170` | kept (mislabelled — §4 N-2) |
| 9 | the wide `Length` cell is honest | qa `AT-171` | `AT-171` | kept + strengthened |
| 10 | the **address cell** is intact at width `W` | qa `AT-171` 2nd clause; qa review §5 flags it *"**GAP** — no LLR; **no architect AT at all**"* | — | **DROPPED (D-4)** |
| 11 | `W+100` negative — *"the fix must not be a one-width special case"* | qa `AT-168`; arch MAJ-3 `:348-349` says **"Adopt it."** | — | **DROPPED (D-5)** |
| 12 | encoder mutation, report writer | arch `AT-172` | `AT-172` | kept |
| 13 | encoder mutation, flow writer | arch `AT-173` | `AT-173` | kept |
| 14 | **AST structural census — no text-mode writer in the derived set** | qa `AT-172`; qa review §6: *"This is the D3 gate CI can actually run, and the claim survives"*; arch B-4: *"added rather than substituted"* | — | **DROPPED (D-6)** |
| 15 | encoder identity / `_line_bytes` is an upper bound of the encoder | qa `AT-173` (`== −1`) / arch `AT-174` (`>=`); sec F7 `:282-283`: *"F5's reconciliation should keep **both** … and record why"* | — | **DROPPED (D-7)** |
| 16 | batch-composability | qa `AT-174` | `AT-174` | kept |
| 17 | on-disk size `== used − 1` (platform-independent) | qa `AT-175` 1st clause; qa MIN-5 asks `AT-172` to assert **size**, not just "bytes changed" | — | **DROPPED (D-8)** |
| 18 | no `\r` on disk (Windows-only) | arch `AT-175` = qa `AT-175` 2nd clause | `AT-175` | kept |

**8 of 18 dropped. Six of the eight are dropped silently** — the document's §6 amendment log records
only one deliberate removal (A-06 / `AT-164`, which is in fact a rename, not a removal). D-2 is the
sharpest: it is the single observable the two independent lanes converged on without coordination, and
`LLR-100.4` ("For inputs at or below the bound in every class, the rendered addendum **shall** be
byte-identical to `031ca8d`") is now a normative clause with **no acceptance node in §3.4**.

**The TC layer is gone entirely.** `01b-qa-catalog-rescoped.md` carried 40 rows, each with an explicit
`Asserts` predicate and a RED counterfactual (`TC-440`…`TC-479`, e.g. `TC-479`, the *positive control*
proving the `\r` detector itself can fire — *"a broken detector would make TC-475/477 pass for the
wrong reason on **every** platform"*). The consolidated document declares itself normative over that
artifact and replaces the layer with three range rows in §2 plus one named `TC-441`. Under this
project's dual-traceability control an `AT` is the behavioural contract and a `TC` is the mechanism;
Phase 3 now receives 11 ATs and 40 unallocated ids. Note also that consolidated `TC-441` (the
consumption counter) **re-binds** an id the superseded catalog used for "095 (a) below the bound" —
harmless while `01b` is non-normative, but the collision class OB-2 exists to fix.

---

## 4. New defects the fold introduces

**N-1 (major) — `AT-165` cannot see the eviction that survives the per-class fold.**
Per-class closes F1's *executed* scenario (proved in §2 row 9), but it moves the selectability one
level down rather than removing it. Within the summary-issue class the producer order is
`for result → for summary → for issue`, so an attacker who owns **one** variant's change document
floods that class and evicts every other variant's findings. Executed (`pq1.py` P1c, K=200):

```
   attacker mints 400 CHG-ADDRESS-SYNTAX in v1; v2 and v3 each carry one CHG-COLLISION
   rendered summary-issue hits: 200
   CHG-ADDRESS-SYNTAX (attacker-minted): 200
   CHG-COLLISION      (tool finding)   : 0
   variants represented in output      : ['v1']
   AT-165 'every producing class is represented' -> GREEN
```

This is F1's own defect shape one axis in, and `AT-165`'s predicate is structurally blind to it
(it quantifies over **classes**, and the surviving class *is* represented). Not a reason to reject
A-07 — it is the fold security asked for — but the document should say what the per-class cap does
**not** close, exactly as §3.2 does for the neighbouring tables. Minimum fold: extend `LLR-100.3`'s
notice so a cut names the **variant(s)** it stopped at, or state the residual in §3.2's
"deliberately does NOT claim" list.

**N-2 (major) — A-14's narrowing was not performed, and `LLR-101.4` asserts a refuted implication.**
Security F6 executed that neither writer is atomic and gave option (a) as **mandatory**: *"Narrow the
label to **'a composition failure leaves no file'** so the predicate matches the claim."* The
consolidated text instead reads, in three places: §2 *"no report file is left behind when generation
**aborts**"*, §4.4 `AT-170` *"**On abort**, no file matching `REPORT_FILENAME_REGEX` remains"*, and
`LLR-101.4` *"…in **a single terminal write, so an abort leaves no file**."* "Abort" is the broad
label; only *composition* abort is what the predicate can test. Re-executed:

```
   mid-write OSError raised: No space left on device
   file exists after abort: True  size=200000
   name matches REPORT_FILENAME_REGEX: True
```

A single terminal `write_text`/`write_bytes` call is **not** atomic — the file is created and
truncated at open, and a mid-write `OSError` leaves a partial report the shipped viewer lists as
legitimate. `LLR-101.4`'s stated causal chain is therefore false as written, and §4.4's annotation
*"Covers F6's residue; the label is narrowed to what the predicate tests"* is a claim the text does
not support. This is the project's own named rule — *a predicate must test what its LABEL claims* —
failing inside the document that quotes it.

**N-3 (major) — `AT-171` is unsatisfiable on a constructible input domain.**
A-11 mandates *"The guarded cell **starts with `0x`** and is not `-`."* Security F8 (unaddressed by
the fold; `grep -c negative` → **0**) showed a negative `Length` is constructible. Confirmed against
the shipped dataclass:

```
   ChangeSummaryEntry(address_start=0x2000, address_end=0x1000) -> length = -4096   (constructs OK)
```

`_ADDRESS_RE = ^0x[0-9A-Fa-f]+$` (`changes/io.py:235`) admits unbounded width, so a *hugely* negative
length is reachable by the same route F3's forgery uses. Executed at that width:

```
   decimal raises on the negative too: Exceeds the limit (4300 digits)
   candidate '-99999999999'...  startswith0x=False
   candidate '-0x999999999'...  startswith0x=False   <- the readable form FAILS AT-171
   candidate '0x-999999999'...  startswith0x=True    <- satisfies AT-171, unreadable
```

`AT-171` as written forces the implementation to choose between failing its own acceptance and
emitting `0x-…`. F8's one-line fold (*"a negative length past the digit limit renders with a leading
sign"*) closes it; the fold dropped F8 entirely.

**N-4 (minor) — `TC-441`'s stated bound contradicts `LLR-100.1`.**
§3.4 says the counter *"asserts `consumed ≤ 3K + ε`"*; `LLR-100.1` says worst case is `O(R × 3K)`.
The region loop is **outer**, so a re-iterable counting fixture (required — a one-shot generator
breaks at `R ≥ 2`) accumulates across regions. Executed: `R=1 → 201`, `R=2 → 402`. At any `R ≥ 2`
with a small ε the stated assertion false-fails a correct fix — the C-39 / BLK-4 failure mode
re-entering through the amendment that fixed BLK-4's twin. Fix: `consumed ≤ R × 3K + ε`.

**N-5 (minor) — `HLR-102`'s upper-bound clause has no verifier.**
*"`_line_bytes` … **shall** remain an upper bound of the encoder's output"* is normative in §5.2 and
is asserted by none of `AT-172/173/174/175`. Security F7 asked the reconciliation to *"keep **both**
(the `==` as the pin, the `>=` as the safety property) and record why"*; only the `+1`/partition pin
survives. `>=` is the direction that protects `flow_report_service.py:310`'s emission gate.

**N-6 (minor) — `OB-SEC-1` was dropped.**
The security review filed a Phase-3 obligation in its §4 V2 block: *"paste
`git diff --numstat -- s19_app/tui/services/flow_report_service.py` in the review packet. Anything
other than the import line and the writer line is out of the sanctioned diff."* `grep -c "OB-SEC-1"`
and `grep -c "numstat"` on the consolidated document both return **0**. §8 carries OB-1/OB-2/OB-3
only. This is the only mechanical guard on the batch's one cross-module edit.

**N-7 (minor) — `AT-173`'s mutation site is unstated and the obvious reading is vacuous.**
`AT-173` says *"Monkeypatch `document_bytes`; the same for `write_flow_report`."* But
`flow_report_service.py:69-74` uses `from .report_service import (…)`, binding names at import time —
patching `report_service.document_bytes` is a **no-op** for the flow writer. The AT must name
`flow_report_service.document_bytes` as the patch target, or a Phase-3 implementation writes a green
`AT-173` that proves nothing. (`LLR-102.1` mandates the same `from`-import shape, so this is not
hypothetical.)

---

## 5. Direct answers to the seven attack items in the brief

**1 — A-07 / `LLR-100.1` per-hit-class cap vs security F1.** It **does** close F1's executed case, on
the shipped producer order: per-region `0/5`, per-class `5/5` (§2 row 9). It **does not** remove
selectability — it moves it from the class axis to the intra-class / cross-variant axis, where
`AT-165` is blind to it (**N-1**, executed). The single-class-flooded region is real and cheap to
build.

**2 — A-08 / `TC-441` counting iterable.** Yes, it separates the arms, and the counter can go RED:
`cap+break` **201** vs `cap+NO-break` **2000** at `E=2000, K=200`. This is a genuine repair of the
node that the resource ratio could not provide (19019/19019). One arithmetic defect in the stated
bound → **N-4**.

**3 — A-02 / `LLR-102.2`.** The wording **does** exclude the refuted non-composable design.
*"byte-identical to `031ca8d`"* plus the explicit prohibition leaves no reading under which
`_line_bytes := len(encoder(...))` conforms, and `AT-174` carries a counterfactual that names it.
Executed check that both halves of the pin are needed: `+1→+2` is partition-invariant (so invariance
alone would not catch it) and `len(join)` is not (so the `+1` clause alone would not catch it either).
The document states both. Residual is at the AT layer only (**N-5**).

**4 — A-11 / `AT-171`'s `0x` prefix vs F3.** The `'9'×3572` forgery is **closed**: `0x999…` has
`isdigit() == False` and `startswith("0x") == True`. I could not forge past it on the positive domain
— any hex rendering carries the prefix, and the prefix cannot be produced by a decimal numeral. It is
**broken on the negative domain** (**N-3**).

**5 — A-04 / `AT-174` as a pin.** Worth keeping, and the counterfactual is real: C-26's census found
`_line_bytes` has **zero** test references, so `+1→+2` ships green today, and I confirmed the pin's
two clauses are independently load-bearing. It is correctly labelled *"PIN, not a D3 gate"* and
correctly excluded from the gate set. The half-discharge is that BLK-1 also required the requirement
to **name the gate pair**, and only one member of the pair still exists (**D-6**).

**6 — A-06 / `AT-164` withdrawal: correct or convenient?** **Correct, and the satisfiable
formulation was not lost** — it is `AT-166`, keyed to `_addendum_lines` under a traced window, which
is precisely what security F2 rec-1 asked for and what the qa lane had already written. The
"withdrawal" is really a rename plus a re-key. Two caveats: the document does not say the observable
survives elsewhere (a reader of §2 sees only "WITHDRAWN"), and the *convenient* part rode along with
it — F2 rec-1's second sentence, the shipped-surface **count** assertion, was dropped with no note
(**D-1**). Also unclosed: qa MIN-2's requirement that the AT state *"fixture construction precedes
`tracemalloc.start()`"*, without which `AT-166` can never go green for any implementation.

**7 — Coverage loss during id reconciliation.** Enumerated in §3: 8 of ~18 union observables dropped,
6 of them silently, plus the entire 40-row TC layer. This is the reason for the NOT-DISCHARGED
verdict.

---

## 6. What is sound (recorded so `iterate` does not re-litigate it)

- **A-02 / `LLR-102.2`** — the strongest amendment in the set; the refuted design is excluded by
  name and the pin's counterfactual bites (executed).
- **A-07** — adopted security's recommendation verbatim, including the AT clause, and it closes the
  executed attack.
- **A-08** — a genuine repair of a node that had no failing mode.
- **A-03** — the retracted phrase is gone; `grep "share ONE encoder"` → 0. §5.2's heading is now
  *"One place bytes are made; accounting is an unchanged upper bound."*
- **A-10** — the "crashes" claim is correctly replaced by *denial* + the `app.py:4034`
  misclassification, and §4.1 credits C-35 against the orchestrator's own measurement. Honest.
- **A-12 / `LLR-101.3`** — the literal is gone and the derivation is mandated. `grep "3571"` /
  `grep "3572"` appear only inside quoted Phase-2 findings, never in a normative clause.
- **A-13 / `LLR-102.1`** — `document_bytes(text: str)` correctly resolves qa MAJ-2 without touching
  `compose_flow_report`'s `-> str` (39 tests untouched).
- **A-05's honesty section** (§3.2 "What this requirement deliberately does NOT claim") is the right
  instrument; it is under-populated, not wrong.
- **§1's self-falsification** — the document withdraws its own Phase-1 gate-packet claim that the
  REV-4 collision was "removed by construction". That is the behaviour this batch exists to teach.

---

## 7. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|---|---|
| 1 | Every blocker audited against the SOURCE review, not the amendment table | ✓ | §2 — each row quotes the source review with a file:line citation before stating a verdict; the amendment table is cited only as the *claim* column |
| 2 | Acceptance criteria use an observable/counterfactual triple | ✓ | consolidated §3.4/§4.4/§5.4 all do; audited, not assumed |
| 3 | Verdicts have explicit Expected, not vague "works" | ✓ | §2 verdict column is closed / partially closed with the specific missing clause named in each partial |
| 4 | Edge cases: empty, boundary, invalid, error | ✓ | executed — boundary `E=CAP` traversal (P2), invalid negative `Length` (P4/N-3), error mid-write `OSError` (P5/N-2), forgery `'9'×3572` (P4) |
| 5 | Regression/coverage checklist exists | ✓ | §3 — the 18-row union table, drops D-1..D-8 named |
| 6 | Exit criteria stated | ✓ | §1 — `iterate`, scoped to restoring D-1..D-8, re-narrowing the fail-closed label, re-instating `OB-SEC-1` + two BACKLOG carries |
| 7 | No real PII / secrets / operator firmware | ✓ | all fixtures synthetic in-memory objects; no `examples/` image read; no `.env`, key or token touched |
| 8 | Test-results section left blank unless actually run | ✓ | every transcript in this file is labelled with the probe that produced it and the tree it ran against (`…/b63/g1`, export of `031ca8d`) |
| 9 | **Layer B (black-box):** the shipped surface observed, with boundary + negative evidence | ✓ | producer order read at `report_service.py:1513-1537` and re-implemented in both cap shapes; writer abort executed at file level; `ChangeSummaryEntry` constructed from the shipped module (`s19_app/tui/changes/model.py:321`) |
| 10 | **Bidirectional surface-reachability** — inputs and outputs both exercised | ✓ | inputs: hit class, variant, `E`, `R`, address width, sign, partition. outputs: rendered hit set, consumed count, `_line_bytes` totals, the rendered cell, the file on disk |
| 11 | **No unfilled template** — no placeholder survives in this artifact | ✓ | no `<…>`, no `TC-NNN`, no empty required row; every verdict cell filled |
| 12 | **C-39: every threshold executed, transcript pasted** | ✓ | `0/5` vs `5/5` (F1 fold), `201` vs `2000` (traversal counter), `566/602/565` + invariance (pin), `isdigit`/`startswith` (forgery), `size=200000` (abort). All pasted verbatim |
| 13 | **A predicate tests what its LABEL claims** — applied to the fold itself | ✓ | **N-2** ("On abort" vs composition abort) and **N-1** (`AT-165` labelled anti-eviction, tests class presence) are both instances found by applying this rule to the consolidated document |
| 14 | **An AT quotes the CONSTANT, never its value** — checked in the fold | ✓ | `LLR-101.3` mandates derivation from `sys.get_int_max_str_digits()`; no literal `3571`/`3572` survives in a normative clause. `MAX_ADDENDUM_HITS_PER_REGION` is quoted, flagged `NEW — created in Phase 3` (C-36) |
| 15 | **A carried number is re-derived, not copied** | ✗ (finding, not failure) | `AT-166`'s `×3.99/×4.01` counterfactual is copied from the **superseded** `01-requirements-rescoped-architect.md:489-490`, not from `00b`. The arm is still the right one (unbounded producer), so this is a provenance note, not a defect — but the consolidated document is the only normative artifact and it now cites a non-normative one for a number |
| 16 | No production source edited, no `.dev-flow` artifact edited | ✓ | `git status --porcelain` shows only this file added under `.dev-flow/2026-07-26-batch-63/`; all execution in the deleted export |
| 17 | Probe safety: bounded, temp trees deleted, forbidden fixture never built, short root | ✓ | max 4 000 synthetic hits, one 400 kB temp file, peak < 2 MB (ceiling 200 000 hits / 50 MB); `tempfile.mkdtemp` + `shutil.rmtree` in a `finally`, `temp tree removed: True`; export root `…/Temp/claude/b63/g1`, removed at close; `/b63/{a,b,qa,arch,archb,r1,r2,r3,g2}` untouched; the declared-domain D1 fixture was never constructed |

---

## 8. Verdict

- [ ] DISCHARGED
- [ ] DISCHARGED-with-folds
- [x] **NOT-DISCHARGED**

**Release condition — all spec-level, no new scope, no new increments:**

1. **Restore the union.** Re-instate D-1..D-8 as `AT-176…AT-183` (the ids are free — architect §6
   verified the highest tracked outside `.dev-flow` is `AT-163`/`TC-398`). D-2 (byte identity below
   the cap) and D-6 (the AST structural census) are mandatory; the rest are cheap.
2. **Restore the TC layer**, or state explicitly that `01b-qa-catalog-rescoped.md`'s §4 table remains
   normative for `TC-440..479` under the consolidated id semantics. A range reservation is not a
   catalog.
3. **N-2** — narrow the fail-closed label to *"a **composition** failure leaves no file"* in all three
   places, and delete `LLR-101.4`'s false causal clause (*"in a single terminal write, so"*).
4. **N-3** — adopt security F8's negative-domain clause so `AT-171` is satisfiable.
5. **N-4** — `TC-441`'s bound becomes `R × 3K + ε`.
6. **N-6** — re-instate `OB-SEC-1`.
7. **arch B-3 (b)** and **sec F2 (2)(3)** — add the two dropped BACKLOG carries (low-/zero-match
   O(V×E) traversal, naming `range_index.py`; and the `_modifications_lines`/`_checklist_lines`
   resident-memory axis with its measured constants), and put security's numbers in OB-1's PR text.
8. **N-1, N-5, N-7** and qa MIN-2's tracemalloc-window clause — fold or record as accepted residuals,
   with a reason.
