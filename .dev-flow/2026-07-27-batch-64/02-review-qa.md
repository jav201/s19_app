# batch-64 — Phase-2 QA review (independent reviewer)

> **Reviewing:** `.dev-flow/2026-07-27-batch-64/01-requirements-consolidated.md` (normative).
> Supporting, read but not defended: `PLAN.md`, `01-requirements.md`,
> `01-requirements-architect.md`, `01b-qa-catalog.md`, `01c-arms-measurement.md`.
> **I am not the author of any of them.** Every number below was re-derived in this session with
> harnesses I wrote (`rq_corpus.py`, `rq_arms.py`, plus inline probes). `c40_arms.py` and
> `c40_variants.py` were **not** reused, imported, or read for their results.

---

## 0. BLUF

**VERDICT: BLOCKED. 2 blockers, 4 major, 5 minor.**

**Every headline number reproduces.** 6/6, 0/6, 4/6, 2.07×, 0/29-vs-29/29, C-29-unregistered,
`C-10…C-39` — all confirmed independently (§1). The prior lanes' arithmetic is sound and their
self-reported harness defect (run-1 never opened the C-40 text) was correctly diagnosed and correctly
repaired. **The arithmetic is not where this batch is weak.**

**The corpus is.** Per C-31 and C-40's own limb 2, *a predicate that quantifies over a set is only as
strong as the set* — and this set was hand-assembled. I attacked it and it did not hold:

- **The positive corpus is incomplete by at least three members, all executable, all found in under
  an hour** (§2.1). One of them — `tests/test_flow_report_service.py:496` — is the **same round-trip
  tautology as `V-6`, sitting one line above the predicate the catalog harvests as sound negative
  control `S-3`.** The lane had it on screen and cited its neighbour.
- **A second is `tests/test_report_document_bytes.py:221`,** whose consequence is sharper than the
  batch records: **`test_at172b` has no clause that can go RED on the merge-gate host at all** — the
  claim "the test is not wholly inert, only its named clause is" is false on `ubuntu-latest` (§2.3).
- **A third is at the validation-record layer:** `04-validation-rescoped.md:34` records a pre-fix
  **RED** for an observable I measure GREEN in all four cells (§2.1). batch-63's *gate record* carries
  a false counterfactual, and no lane looked there.

**Layer A is NOT N/A, and I refuted it by execution rather than by argument** (§4). A white-box
placement layer is constructible: my predicate is RED pre-batch, GREEN on a correct insert, and RED on
a mis-placed insert — while `AT-B64-08` and `AT-B64-09` return **identical** values on the correct and
the mis-placed insert. Four LLR `shall` clauses state within-file placement and **nothing observes
them.**

**One open item I closed rather than carried:** `~/.claude/skills/tui-design/SKILL.md`, unread by all
three prior lanes (architect §10.5, `01c` B-6). Read. **No overlap** — `AT-B64-09`'s leg is not
redundant (§3.9).

---

## 1. CHARGE 1 — headline measurements, re-derived

Harnesses: `rq_corpus.py` (executes each code-backed predicate under the real
text-mode→byte-mode writer change, on an LF and a CRLF host) and `rq_arms.py` (reads C-40's actual
bytes from `01-requirements-consolidated.md` §3.1 and parses it by its **own structural markers**
`**LIMB 1` / `**LIMB 2` / `**DISCHARGE`, not by fixed anchor strings).

### 1.1 Invariance under the change — executed, no C-40 text involved

```
id            LF host      CRLF host   invariant?   cite
V-1        True->True     True->True   INVARIANT    00b-measurements-rescoped.md:149
V-2        True->True     True->True   INVARIANT    00b-measurements-rescoped.md:150
V-3        True->True     True->True   INVARIANT    00b-measurements-rescoped.md:181-182
V-6        True->True     True->True   INVARIANT    tests/test_report_document_bytes.py:217
V-7        True->True     True->True   INVARIANT    tests/test_flow_report_service.py:496  << NOT IN PRIOR CORPUS
S-1       False->True    False->True   moves        tests/test_report_document_bytes.py:187-206
S-2       False->True    False->True   moves        tests/test_flow_report_service.py:448-480
S-3        True->True    False->True   CRLF-only    tests/test_flow_report_service.py:497
S-4       False->True    False->True   moves        tests/test_report_document_bytes.py:274-298
S-6        True->True     True->True   INVARIANT    tests/test_report_document_bytes.py:241-266
V-6cmp     True->True    False->True   CRLF-only    tests/test_report_document_bytes.py:221
```

### 1.2 The arms, C-40 as encoded in §3.1

```
C-40 text read from disk: 5015 B, sha-prefix acc170a02537fb1e
limb1=present keying=DECLARED pin=True | limb2_general=True

POSITIVE ARM  6/6   GREEN          NEGATIVE ARM  false positives 0/6   GREEN
   V-1  FLAG  L1(declared subject absent)
   V-2  FLAG  L1(declared subject absent)
   V-3  FLAG  L1(declared subject absent)
   V-4  FLAG  L2(set drawn from implementation)
   V-5  FLAG  L2(set drawn from implementation)
   V-6  FLAG  L1(declared subject absent)
```

### 1.3 Reddening mutations, each applied to the TEXT and re-parsed

```
[M-A] delete LIMB 2 span (1001 chars removed)  -> POSITIVE 4/6 RED   (V-4, V-5 lost)
[M-B] delete LIMB 1 span  (766 chars removed)  -> POSITIVE 2/6 RED   (V-1,2,3,6 lost)
[M-C] re-key LIMB 1 on "the component under test" (pre-A-3 draft)
                                               -> NEGATIVE false positives RED
[M-D] corrupt the "**LIMB n" markers           -> POSITIVE 0/6 RED   (parser reads the bytes)
```

`M-D` is my integrity discharge: the harness's verdict is a function of the variant's bytes, so this
harness is not run-1's inert one.

### 1.4 Scoreboard — did my numbers differ?

| claim | prior lane | **my derivation** | |
|---|---|---|---|
| positive arm, C-40 as specified | 6/6 | **6/6** | MATCH |
| negative arm | 0/6 | **0/6** | MATCH |
| one-limb mutant | 4/6, losing `AT-165`+`AT-193b` | **4/6, losing V-4 + V-5** | MATCH |
| `V-6` is a tautology | 0 RED over {pre,post}×{LF,CRLF} | **0 RED, all four cells** | MATCH |
| limb-1-on-the-change mutant | 1/6 (S-6) | **1/6 full domain** · 2/6 CI-only | MATCH, see §2.2 |
| C-40 block | 5 015 B | **5 015 B** | MATCH |
| C-39 block | 2 427 B | **2 427 B** | MATCH |
| ratio | 2.07× | **2.066×** | MATCH |
| rider whole / body | 1 325 / 889 B | **1 325 / 889 B** | MATCH (spec §3.2 still reads "~890 B" — M-4) |
| snapshot counterexample | 0/29 · 29/29 | **0/29 · 29/29** | MATCH |
| `VERIFY.md` extension | 1 540 B | **1 540 B** | MATCH |
| C-42 mechanics | 5 in 6 bullets | **5 distinct in 6 bullets** | MATCH |
| `AT-B64-05` body scan | 0 hits | **0 hits / 23 terms**, mutation bites | MATCH |
| `AT-B64-08` | 0 hits | **0 hits**, both mutations bite, non-emptiness guard holds | MATCH |
| R-2 `C-29` encoded, unregistered | yes | **confirmed**, `docs/engineering-rules.md:64` | MATCH |
| R-3 encoded space `C-10…C-39` | contiguous | **confirmed contiguous, 32 ids** | MATCH, see M-1 |
| `AT-B64-10` pre-RED carriers | 1/3 (C-29) | **1/3 (C-29)** | MATCH |

**Conclusion of Charge 1: no number is wrong. Ship the arithmetic; the defect is one level up.**

---

## 2. CHARGE 2 — attacking the corpus

### 2.1 (a) The positive corpus is INCOMPLETE — 3 further members, executed

#### **`V-7` — `tests/test_flow_report_service.py:496`. BLOCKER-grade.**

```python
    assert raw == frs.document_bytes(raw.decode("utf-8"))          # :496   <-- tautology
    assert raw == frs.document_bytes(compose_flow_report(_state(), _AT))   # :497 = the catalog's S-3
```

Byte-for-byte the same round-trip identity as `V-6`. Executed: `True->True` on **both** hosts (§1.1).
`01b-qa-catalog.md:180-185` quotes **line 497** as the sound contrast and writes *"rather than against
its own decode"* — the lane was looking directly at line 496, named its defect, and did not add it to
the corpus. Adding it, C-40 as encoded flags it:

```
>>> corpus=7 (V-7 added)
POSITIVE ARM  7/7   GREEN
   V-7  FLAG  L1(declared subject absent)   tests/test_flow_report_service.py:487-489 / assert :496
```

**The control gets stronger; the acceptance's stated number `6/6` becomes wrong.**

#### **`V-8` — `tests/test_report_document_bytes.py:221`.**

```python
    assert CR.encode() not in raw or os.linesep == LF
```

On `ubuntu-latest` the right disjunct is a constant `True`. It is `AT-175`'s predicate with the
`skipif` inlined into the expression instead of the decorator — so it rides inside an unskipped,
unlabelled test. Consequence at §2.3.

#### **`V-9` — `.dev-flow/2026-07-26-batch-63/04-validation-rescoped.md:34`.**

```
| `AT-172` | `test_at172b_...` | the written bytes equal `document_bytes` of their own text | RED | GREEN |
```

The stated observable is GREEN in all four cells (§1.1). **The recorded pre-fix RED cannot have been
produced by it.** The adjacent rows show the authors qualified where they knew — `:37` reads *"RED **on
every platform incl. CI**"*, `:40` reads *"**skipped on CI**"* — and `:34`/`:36` carry no qualifier at
all. This is a false counterfactual in batch-63's **gate record**, which is squarely inside C-40's
scope (*"any measurement probe whose number a gate is keyed on"*). No batch-64 lane examined the
validation layer.

#### Also: `S-6`'s second assert is dead by construction

`tests/test_report_document_bytes.py:266`, `assert totals.pop() == rs._line_bytes(doc)`. Since
`partitions[0] == [24]` and `len(doc) == 24`, the first iteration inserts `_line_bytes(doc)` into
`totals`, and `:265` has already pinned `len(totals) == 1`. Executed:

```
variant                              line265   line266
as shipped (+1 per line)                True      True
MUTANT +1 -> +2                         True      True
MUTANT redefined as len(join)          False     False
```

Line 266 is GREEN wherever 265 is GREEN and unreachable where 265 is RED — **it can never fire
independently.** Worse, the docstring at `:250-252` justifies it with *"neither implies the other:
`+1 -> +2` IS partition-invariant, so invariance alone would miss it."* **Measured above: under
`+1 -> +2`, line 266 is GREEN too.** Nothing in the test catches that mutation; the stated
justification is false.

### 2.2 (b) Are the negative controls genuinely SOUND?

| id | verdict | evidence |
|---|---|---|
| **S-1** | **SOUND** | `False->True` both hosts (§1.1) |
| **S-2** | **SOUND** | `False->True` both hosts |
| **S-3** | **SOUND but CI-DEAD** | `True->True` on LF, `False->True` on CRLF. **Cannot go RED on the merge-gate host.** |
| **S-4** | **SOUND**, one caveat | `False->True` both hosts. But the cited span `:274-298` includes `:292`, whose expected set `{"report_service.py","flow_report_service.py"}` is drawn from the **implementation** — limb-2 shaped. Defensible as an anti-vacuity guard, not as the gate; the citation should narrow to `:294-298`. |
| **S-5** | **NOT A SHIPPED TEST** | `grep -rn "TC-441" tests/` → 0 hits. A spec-transcript predicate (D1 was returned to the backlog) presented in a control group as evidence. The catalog discloses this at §9.9; the *consolidated spec* does not. |
| **S-6** | **SOUND at `:265`**, dead at `:266` | see §2.1 |

**The S-3 finding is the sharp one.** Its RED window is platform-gated, and batch-63's own test-file
header lists exactly that property among the three **REFUTED** vacuous acceptances
(`tests/test_report_document_bytes.py:17-20`: *"'The written file contains no CR' is GREEN pre-fix on
`ubuntu-latest`, which is where the merge gate runs"*). The corpus applies one standard to a positive
member and the opposite standard to a negative member.

**Does this flip 0/6?** No. Under the **amended** (declared-subject) keying S-3 is correctly not
flagged, because its declared subject — the encoder's output vs the file — *is* in its expression.
**0/6 stands.** But the *mutant* number is domain-sensitive:

```
                          FULL domain {LF,CRLF}   CI-ONLY domain {LF}
S-3                                       False                  True
S-6                                        True                  True
false positives                             1/6                   2/6
```

The prior lanes' `1/6` is **correct under the full-domain reading** and I confirm it. The divergence
exposes a real ambiguity in the encoded text: limb 1 states a **semantic** test (*"invariant under the
change it gates"*) and a **syntactic** one (*"that subject appears in the predicate's own
expression"*) as if equivalent. **S-3 is the counterexample where they disagree.** See M-2.

### 2.3 (c) `V-6`'s second assert — the load-bearing write-up claim

```
                                     line217      line221      WHOLE TEST
LF   (ubuntu-latest = merge gate)  True->True   True->True   True->True   INERT
CRLF (Windows dev host)            True->True   False->True  False->True  moves
```

**The companion clause IS sound — on a CRLF host only.** So the claim *"the test is not wholly inert,
only its named clause is"* is **true on a developer's Windows box and false on the merge gate**, where
the entire test is invariant under the defect it names. `01b-qa-catalog.md:174-178` gets the mechanism
right (*"only on a CRLF host — i.e. never on CI"*) but states the conclusion in a form the spec then
inherits without the platform qualifier. The backlog carry at `01-requirements-consolidated.md:300-305`
should say **"inert on the merge-gate platform in both clauses"**, which is a materially stronger
reason to fix it.

---

## 3. CHARGE 3 — judging the acceptances

| AT | spec's label | **my verdict** |
|---|---|---|
| **AT-B64-01** | LOAD-BEARING, expected 6/6 | **LOAD-BEARING, but the expected value is WRONG.** B-1 |
| **AT-B64-02** | LOAD-BEARING | **CONFIRMED.** 0/6, mutant bites. Sound. |
| **AT-B64-03** | LOAD-BEARING | **CONFIRMED.** The honest C-35 row is correct and creditable. |
| **AT-B64-04** | re-scoped to 8 occurrences | **ACCEPT.** Enumeration-not-total (A-12) is right; three registers do disagree. |
| **AT-B64-05** | WEAK — boundary complement | **CONFIRM WEAK.** Executed: 0/23 terms, mutation bites, `chk.json` correctly inside the excluded citation. Correctly labelled. |
| **AT-B64-06** | LOAD-BEARING | **CONFIRMED.** 5 distinct mechanics in 6 bullets; mechanic 4 reproduced live. |
| **AT-B64-07** | WEAK, vacuous pre-encoding | **CONFIRM WEAK**, and the disclosure is honest. |
| **AT-B64-08** | WEAK — constraint check | **CONFIRM WEAK.** Executed GREEN with a non-emptiness guard, which is the right shape. |
| **AT-B64-09** | LOAD-BEARING — carries US-B64-4 | **CONFIRMED satisfiable and NOT a restatement — but over-argued.** §3.9 |
| **AT-B64-10** | strongest mechanical AT | **CONFIRMED**, two defects. §3.10 |
| **AT-B64-11** | BOOKKEEPING | **AGREE.** Correct demotion. |

### 3.9 `AT-B64-09` — the hardest one, re-run

Counterexample reproduced from scratch:

```
total SVG snapshots: 29
literal 'Edit Tool'      (rendered form) hits: 0 / 29
emitted 'Edit&#160;Tool' (emitted  form) hits: 29 / 29
raw emitted context: '40" y="27">Hex&#160;Edit&#160;Tool</text>\n'
```

**Does `VERIFY.md`'s pre-existing text already catch it?** The section is 5 lines (`:34-38`). Judging
the catalog's three separation tests independently:

- **Test 1 — "its criterion classifies the bad predicate as GOOD": CONTESTABLE, and the catalog
  over-claims it.** Line 37 says *"never on the presence of a label or docstring"*, and the 0/29
  predicate is literally a search for a label. The catalog's rebuttal — that pairing *label* with
  *docstring* fixes the referent as source-side prose — is reasonable but not decisive. A reviewer
  holding only the old text can arrive at either reading. **This test is a draw, not a win.** The
  catalog does raise the counter-argument (`01b:570-577`), which is creditable, and then still
  presents test 1 as passing.
- **Test 2 — the direction: DECISIVE.** Line 36 (*"a green check that only goes red when you delete
  prose"*) and line 38 (*"a test that can't fail"*) both describe a **false pass**. The 0/29 predicate
  is a **false fail**. Nothing in `:34-38` addresses a predicate that is red for the wrong reason.
  **Genuine gap, and the extension fills exactly it** (`§3.4`: *"Note the direction: this is a false
  FAIL, not a false pass."*).
- **Test 3 — the neighbouring section: DECISIVE.** `VERIFY.md:40-49` prescribes inject → confirm red →
  verify applied → restore. Every step presumes the assert is currently GREEN. A predicate already red
  passes trivially. **Structurally blind.** Confirmed by reading the section.

**Verdict: the leg SURVIVES on tests 2 and 3. It is not a restatement.** Re-weight the write-up so it
does not rest on test 1 (M-3).

**Plus, the open item nobody discharged.** `SKILL.md` scan:

```
  SKILL.md  emitted=0  &#160;=0  entity=0  escap=0  producer=0  snapshot=0  export=0   (SVG=2)
```

The two `SVG` hits and `PROTOTYPE.md`'s SVG passages concern *capturing* an artifact and version
pinning, not the *form a predicate should assert against*. `INTAKE.md:65`'s "escaping rules" is an
intake question, not a predicate rule. **No overlap. `01c` B-6 / architect §10.5 is DISCHARGED —
close it rather than carry it.**

### 3.10 `AT-B64-10` — two defects in the strongest AT

Re-derived: PRE = RED (carrier `C-29`), POST = GREEN. Green-by-construction audit reproduces `1/3`.

**(i) The `encoded()` predicate is narrower than its label.** `01c` §8 defines it as *"a `## C-NN — …`
heading, or a bullet whose bolded lead contains `(C-NN)`"*. Measured, three declaration shapes are in
use:

```
  S1 '## C-NN --'              11 ids
  S2 bullet bold lead (C-NN)   20 ids
  S3 bold lead '**C-NN --'      1 ids: C-33      <- dev-flow.md:117
  detects 31/32 declarations; FALSE NEGATIVES: ['C-33']
```

Harmless for the `{C-29, C-40, C-42}` subject set; **unsound the moment the set is widened.** I hit
this false negative with my own first regex, which is fair evidence that the shape is easy to miss.

**(ii) The normative spec does not record that `C-29` is load-bearing.** `01c` B-5 raised it at 15:11;
`01-requirements-consolidated.md` is 14:58 and therefore cannot contain it. Grepping the spec for
`C-29` returns registration *requirements* only — nothing warns that dropping `C-29` from the subject
set returns the AT to green-by-construction. **Unfolded finding.**

---

## 4. CHARGE 4 — the Layer-A declaration is WRONG

Both lanes argued: *for a documentation deliverable the artifact IS the observable, so there is no
internal mechanism a TC could verify.* **I tested that by trying to build the layer they say cannot
exist. It builds.**

`LLR-B64-4.1` requires the `VERIFY.md` extension to land **inside** `## Pin the truth, not a string
[travels]`, before `## Mutation-test every assert`, adding no new `##`. That is a structural property
of the document — the "mechanism" by which a future reader encounters the rule in context — and it is
distinct from "the text is present":

```
  PRE-BATCH (nothing inserted):
     inside_section=False  no_new_h2=True  -> RED     <- correctly RED
  SIM A — inserted CORRECTLY (end of the section, before the next '##'):
     inside_section=True   no_new_h2=True  -> GREEN   <- correctly GREEN
  SIM B — MIS-PLACED: same bytes appended after 'Mutation-test every assert':
     inside_section=False  no_new_h2=True  -> RED     <- correctly RED

  CONTROL: do the batch's EXISTING acceptances separate SIM A from SIM B?
     SIM A (correct)      AT-B64-08 identifiers=0 (GREEN)   AT-B64-09 content-present=True (GREEN)
     SIM B (mis-placed)   AT-B64-08 identifiers=0 (GREEN)   AT-B64-09 content-present=True (GREEN)
```

**Both existing ATs are identical on a correct and a mis-placed insert. The placement predicate
separates them.** So the layer is constructible, falsifiable, RED pre-batch, and **uncovered**.

**Four `shall` clauses have no observer:** `LLR-B64-1.1` (C-40 after the C-39 bullet, before the
UI-geometry pointer), `LLR-B64-2.1` (rider inside the C-35 bullet, before its `(Origin: …)`),
`LLR-B64-3.1` (C-42 after `## C-38`, before `## C-34`), `LLR-B64-4.1` (above).

**Why the traceability table did not catch this.** `§4.1` claims *"Zero orphans. Every LLR traces to an
HLR; every HLR to ≥1 US; every US to ≥1 load-bearing AT."* — the **LLR→AT edge is absent from the
claim**. So it is not a false statement; it is a claim shaped to what holds. With Layer A declared N/A
*and* Layer B not reaching the LLRs, the LLR clauses have **no verification layer at all**. §4's
assurance that the `TC` leg is *"declared N/A with its reason in the artifact, not silently dropped"*
is true about the declaration and untrue about the consequence.

**I am not asking for `TC-NNN` ids to be minted to fill a matrix** — both lanes are right that that
would be template-filling. I am asking for **four placement predicates** (whatever they are called),
which are ~10 lines each and which I have already demonstrated run.

---

## 5. Findings

### BLOCKERS

**B-1 — the positive corpus is under-drawn; `AT-B64-01`'s normative expected value is wrong.**
`01-requirements-consolidated.md:224` (`expected 6/6`), `:53` (A-2), `:146` (the encoded Origin's
*"both limbs flag 6 of 6"*).
At least three further members exist, all executed: `tests/test_flow_report_service.py:496`;
`tests/test_report_document_bytes.py:221`; `.dev-flow/2026-07-26-batch-63/04-validation-rescoped.md:34`.
C-40 as written flags the first (`7/7`, executed §2.1) — **the control is fine; the acceptance's set is
not.** Shipping `6/6` makes the batch's flagship acceptance certify a completeness its corpus does not
have, which is verbatim the limb-2 defect C-40 exists to name, and it is already forbidden by the
encoded **C-31**.
**Fix:** add the members, re-run, restate the expected. Cheap — the harness exists.
**Note the encoded text is affected:** §3.1's Origin asserts *"6 of 6 … over six sound controls —
measured, not argued"*, which becomes false on a corpus of 8+. `01c` §5 already observed that an
encoded claim about a measurement is a maintenance liability; this is that liability firing before the
batch even lands. Consider dropping the count from the Origin and citing the artifact.

**B-2 — Layer A is declared N/A on an argument I refuted by execution; four `shall` clauses are
unverified.** `01-requirements-consolidated.md:236-239` (§4), `:70` (*"Layer A N/A (both lanes
concurred)"*), `:116`, `:121`, `:124`, `:127` (the four unobserved LLRs), `01b-qa-catalog.md:702-719`.
A placement predicate is RED pre-batch, GREEN on a correct insert, RED on a mis-placed insert; both
existing ATs are blind to the difference (§4).
**Fix:** either add the four placement predicates, or re-state the N/A honestly as *"Layer A is N/A
**and** LLR-level placement clauses are accepted unverified"* — and let the operator rule on that
knowingly.

### MAJOR

**M-1 — `S-3` is a CI-dead negative control, and the corpus applies two standards.**
`01b-qa-catalog.md:201`, predicate at `tests/test_flow_report_service.py:497`. Invariant on
`ubuntu-latest` (§1.1). batch-63's own header lists that property among the **refuted** vacuous
acceptances (`tests/test_report_document_bytes.py:17-20`). `0/6` is unaffected under the amended
keying, but the control's citation must be qualified *"RED only on a CRLF host"* or the negative arm
overstates its headroom.

**M-2 — C-40's limb 1 conflates a semantic and a syntactic test, and they disagree on a live
predicate.** `01-requirements-consolidated.md:146`: *"a predicate whose value is **invariant under the
change it gates** cannot gate it"* (semantic) alongside *"confirm that subject appears in the
predicate's own expression"* (syntactic). `S-3` passes the syntactic test and fails the semantic one on
the merge-gate host (§2.2). The block should say which governs when they diverge, or state that the
domain includes the platform.

**M-3 — `AT-B64-09`'s separation argument rests partly on a test that does not hold.**
`01b-qa-catalog.md:549-555` (test 1). Line 37's *"never on the presence of a label"* plainly covers a
label search; the *label*/*docstring* pairing argument is reasonable but not decisive. **The leg
survives on tests 2 and 3** (§3.9) — re-weight rather than withdraw.

**M-4 — `S-6`'s second assert is dead by construction and its stated justification is false.**
`tests/test_report_document_bytes.py:266`, docstring `:250-252`. Executed §2.1. `S-6` is the corpus's
"sharpest control"; its citation should narrow to `:265`, and `:266` belongs on the backlog beside
`AT-172b`.

### MINOR

**m-1 — `AT-B64-10`'s `encoded()` misses a third declaration shape.** `01c-arms-measurement.md:424-427`
vs `dev-flow.md:117` (`C-33`). Harmless at the current subject set; latent (§3.10 i).

**m-2 — the spec does not record that `AT-B64-10`'s pre-batch RED rests entirely on `C-29`.**
`01c` B-5 (`:519`) postdates the spec. Fold it into `§4`'s AT-B64-10 row (§3.10 ii).

**m-3 — `S-5` is not a shipped test.** `grep -rn "TC-441" tests/` → 0 hits. Disclosed at
`01b:826-827`, **not** disclosed in the normative spec, which presents "six sound controls" without
noting one is a spec transcript. Say so in `§4`.

**m-4 — stale figure.** `01-requirements-consolidated.md:155` reads *"~890 B"*; measured **889 B**
(`01c` §0 already corrected it). Trivial, but this batch's own rule is that a stated number is
measured.

**m-5 — `§10` carries two items that are now closed.** Item 5 (`SKILL.md` unread) is discharged by
§3.9. Item 7 (the R-c length ruling) is resolved by operator ruling **D-9** (ships V-FULL). Leaving
them open misrepresents the gate's remaining surface.

### Carried, not blocking

- **`AT-172b` on `main`** — unchanged as a backlog item, **but restate the severity**: on the merge-gate
  platform *both* clauses are inert (§2.3), not just the named one. Add `tests/test_flow_report_service.py:496`
  and `tests/test_report_document_bytes.py:266` to the same carry. **D-5 forbids touching `tests/` this batch.**
- **`04-validation-rescoped.md:34`/`:36`** — a false counterfactual in batch-63's validation record. New carry.
- **The `2201 passed` baseline** is now carried by four lanes and re-derived by none. Phase-3 gate item.
- **`01c` B-2** (the R-c cap is not like-for-like) — agreed, and it is the reviewer-correct call for its author to make.

---

## 6. Regression checklist for Phase 3

- [ ] `pytest -q` still reports the **re-derived** baseline (not `2201` copied from `PLAN.md:162`); `A=0`, `D=0`.
- [ ] `AT-B64-01/02/03` re-run against the **final pasted bytes** in `dev-flow.md`, not against `§3.1`'s fence.
- [ ] `AT-B64-10` re-run **after** the lineage edit, with `encoded()` widened to all three declaration shapes.
- [ ] `AT-B64-05` re-run over the pasted rider body (the architect's §10.2 self-report is correctly discharged by `01c` §6; re-confirm post-paste).
- [ ] Placement predicates (B-2) run against the four edited regions.
- [ ] `.dev-flow/BACKLOG.md` re-read before reconciling — the one real collision point with parallel work.
- [ ] `VERIFY.md`'s `[travels]` tag retained and `AT-B64-08` = 0 post-edit.

## 7. Exit criteria for this gate

1. **B-1 discharged** — corpus restated, arms re-run, the encoded Origin's count reconciled or removed.
2. **B-2 discharged** — placement predicates added, **or** the N/A restated to disclose that LLR
   placement clauses ship unverified, with an operator ruling.
3. M-1…M-4 folded (all are wording/citation changes; none requires new measurement).
4. m-1…m-5 folded or explicitly declined.
5. No AT presented as acceptance that this review marks blind to its subject (`AT-B64-08`, `AT-B64-11`).

---

## 8. Evidence checklist

| item | ✓/✗ | evidence |
|---|---|---|
| Acceptance criteria use Given/When/Then | **N/A, declared** | this is a review of an existing AT catalog, not new AT authoring; the reviewed artifacts use *observable + reddening mutation + executed result*, which is the right shape for "does this rule discriminate over a corpus" |
| Test cases have explicit Expected, not vague "works" | ✓ | every arm states its expected before the transcript (§1.2–1.4) |
| Edge cases include empty, boundary, invalid, error | ✓ | boundary = `S-3`/`V-6cmp`, the CRLF-only pair (§2.2); invalid = M-D anchor corruption; error = the entailed-dead assert at `:266`; empty = `no_new_h2` on the pre-batch tree (§4) |
| Regression checklist exists | ✓ | §6 |
| Exit criteria stated | ✓ | §7 |
| No real PII / secrets | ✓ | inputs are repo docs, `~/.claude` command/skill text, and git blobs; no credentials read or printed |
| Results left blank unless actually run | ✓ | **every transcript is command output from this session**; §1.4 tabulates which prior figures I confirm |
| Layer B observed through the SHIPPED surface | ✓ | the shipped surface of a control is the file a future agent reads: `rq_arms.py` reads C-40's bytes (M-D proves it); the snapshot counterexample reads the 29 exported SVGs; the census reads the destination files |
| Bidirectional surface-reachability | ✓ | inputs: C-40 text + 4 mutants, 13 corpus members, 3 declaration shapes, 2 hosts, 2 writers. outputs: positive arm, negative arm, invariance, byte counts, census PRE/POST, placement verdict — each observed |
| No unfilled template | ✓ | no `<…>`, no `TC-NNN` placeholders, no empty required rows |
| C-40 applied to this review's own predicates | ✓ | §1.3 M-D: my harness's verdict is a function of the variant's bytes (6/6 → 0/6 under marker corruption). My own first census regex produced a false negative on `C-33` and I report it as mine (§3.10 i) rather than quietly widening it |
