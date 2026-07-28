# batch-64 — arms measurement per C-40 variant (Phase 1, qa lane, run 2)

> **BLUF — four findings, in descending order of what they change.**
>
> **(1) The corpus arms CANNOT price the trims. All three variants measure 6/6 positive and 0/6
> false positives.** The discrimination table the operator asked for is flat. That is itself the
> answer: the excess bytes buy relations, absorbed content and provenance — not detection.
>
> **(2) The §9.7 first arm is REACHABLE, so "accept 2.07× or lose a member" is a false dilemma.**
> The minimal text that still measures 6/6 is **1 936 B = 0.80× C-39** — *under* the cap. But it
> deletes two clauses the operator's own LLRs require (LLR-B64-1.3, -1.4), so it is not a legal
> deliverable. Its value is as a **measurement**: it decomposes the 5 015 B into 39 % discrimination
> and 61 % non-discrimination, and prices each part.
>
> **(3) V-TRIM-2 is disqualified on executed grounds that are not byte counts.** The named-instances
> span scans **0 hits across 14 stack terms** — it is stack-free. The project's placement rule sends
> stack-*specific* content to `docs/engineering-rules.md`. V-TRIM-2 moves stack-free content into the
> stack-specific file, inverting the rule, and additionally reverses the A-4 absorption ruling. It is
> also the only variant that loses a corpus member under either model (**V-5, under the assisted
> model**).
>
> **(4) My own run-1 harness was VACUOUS under C-40 and I am reporting it as a defect of mine.**
> `c40_arms.py` never opens the C-40 text. Its `6/6` is invariant under every possible wording of
> C-40 — the declared subject is absent from the expression. It measured the CORPUS correctly and
> **could not have measured a VARIANT at all.** This run's harness reads each variant's bytes and the
> anchor-corruption mutation (M-4) reddens it 6/6 → 2/6, proving it does.
>
> **Recommendation: V-TRIM-1, second arm accepted at 1.70×**, with one named consequence the operator
> should assent to explicitly (§5).

---

## §0 — Provenance discipline

Every number in this document was derived **in this process**. Nothing is copied from
`01b-qa-catalog.md`, from `01-requirements-consolidated.md`, or from the architect lane — including
numbers that turn out to agree. Where a figure matches a previously-stated one, that is an
independent confirmation and is labelled as such.

| figure | previously stated by | my independent derivation | agrees? |
|---|---|---|---|
| C-39 block | architect §9.1: 2 427 B | `dev-flow.md:147`, `len(line)` = **2 427 B** | ✓ |
| C-40 V-FULL | architect §9.1: 5 015 B | §3.1 fence extracted, `len(utf-8)` = **5 015 B** | ✓ |
| C-35 rider, whole | architect §9.1: 1 325 B | §3.2 fence = **1 325 B** | ✓ |
| C-35 rider, body | architect §9.1: 890 B | body before `(Measured:` = **889 B** | ✗ **off by 1** |
| V-TRIM-1 saving | architect §9.1: −~1 400 B | measured **−888 B** | ✗ **off by 1.58×** |

**Two corrections to the architect's §9.1.** The rider body is **889 B**, not 890 (a one-byte
rounding, recorded only because this batch's rule is that a stated number is measured). More
materially, **trim (a) saves 888 B, not ~1 400 B** — the architect priced the *whole* Origin
(1 386 B) while their own trim specifies *keeping its first two sentences* (497 B). That is the
**third** estimate in §9.1 to miss, after the 16 % and the 2.3 ×.

Harnesses, all in the session scratchpad:
`c40_variants.py` (three-variant arms) · `at_b64_08.py` (de-identification) ·
`at_b64_10.py` (bidirectional census). Variant texts written to `b64-variants/`.

---

## §1 — The three-variant discrimination table

### §1.1 How a variant is evaluated (and why this differs from run 1)

Run 1's `c40_arms.py` hard-coded one clause set. This harness **reads each variant's bytes**, detects
which normative clauses survive by verbatim anchor phrase, and only then applies the surviving
clauses to the corpus. **A trim loses a corpus member iff it deletes the clause that was catching
it** — which is the question the operator actually asked.

Clause anchors detected (verbatim substrings of the drafted text):

| clause | anchor | bytes |
|---|---|---|
| `CL1-DECLARED` | `the subject *the predicate itself declares*` | (within L1) |
| `CL1-STATIC` | `which symbol in it the implementation could move` | (within L1) |
| `CL1-PIN` | `regression PIN, not a gate` | (within L1) |
| `CL2-GENERAL` | `drawn from the rule the predicate states, never from the implementation` | 353 |
| `CL2-INST-I` | `a positive control shaped to the implementation` | 654 (with II) |
| `CL2-INST-II` | `a consolidation that drops observables` | ” |
| `DISCHARGE` | `execute it, and paste the transcript` | 353 |
| `RELATIONS` | `DISTINCT from C-10` | 1 039 |
| `ORIGIN-V6` / `-INST` / `-ARMS` | Origin sentences S3 / S4-S5 / S6 | 1 386 total |

Two models are run, because one judgment is genuinely open and I will not assert it:

- **LITERAL** — an implementation-shaped set is caught by `CL2-GENERAL` alone.
- **ASSISTED** — a *detector-catchlist* set is only caught when its **named instance (i)** is present,
  because without it the tuple reads as rule-shaped and the reader never asks the provenance question.

### §1.2 The table

| variant | bytes | ×C-39 | Δ vs V-FULL | positive arm (literal) | positive arm (assisted) | false positives | **member lost** |
|---|---|---|---|---|---|---|---|
| **V-FULL** | **5 015 B** | **2.07×** | — | **6/6 GREEN** | **6/6 GREEN** | **0/6 GREEN** | **none** |
| **V-TRIM-1** *(Origin → first 2 sentences)* | **4 127 B** | **1.70×** | **−888 B** | **6/6 GREEN** | **6/6 GREEN** | **0/6 GREEN** | **none** |
| **V-TRIM-2** *(instances (i)/(ii) moved out)* | **3 989 B** | **1.64×** | **−1 026 B** | **6/6 GREEN** | **5/6 RED** | **0/6 GREEN** | **V-5 (`AT-193b`), assisted model only** |
| *V-CORE (reference, not offered)* | *1 936 B* | *0.80×* | *−3 079 B* | *6/6 GREEN* | *5/6 RED* | *0/6 GREEN* | *V-5, assisted* |

**The load-bearing column, spelled out.**

- **V-TRIM-1 loses nothing, under either model.** It deletes only Origin sentences S3–S6 — provenance,
  not rule. Every clause that flags a corpus member (`CL1-DECLARED`, `CL2-GENERAL`) survives intact.
  **A trim that holds 6/6 at 82 % of the bytes is strictly better on the discrimination axis, and I
  say so plainly.**
- **V-TRIM-2 loses `V-5` (`AT-193b`, the offending-list-shaped-to-the-detector) under the assisted
  model, and nothing under the literal model.** Why V-5 specifically: it is the only corpus member
  whose set is a *detector catch-list*. `V-4` (`AT-165`) is a renderer-output set, which
  `CL2-GENERAL` catches on its face; `V-5`'s tuple looks rule-shaped, and instance (i) is what makes
  its provenance the question.

### §1.3 Resolving the V-5 model question against disk, not by argument

The two models disagree only on V-5. I settled it against **V-5's own on-disk fix comment** —
`tests/test_report_document_bytes.py`, the shipped replacement's self-diagnosis:

```
    # Shaped to the RULE ("shall not encode or newline-translate on its own"),
    # not to the detector. The first version of this list was shaped to the
    # detector and therefore certified a completeness the detector did not have:
```

against `CL2-GENERAL`'s text:

```
  ... that set MUST be drawn from the rule the predicate states, never from the implementation it
  certifies; a set derived from what the code currently handles makes the check a tautology that
  certifies a completeness the code does not have.
```

Executed overlap:

```
  GENERAL contains 'certifies a completeness the code does not have'          -> True
  GENERAL contains 'never from the implementation it certifies'               -> True
  GENERAL contains 'drawn from the rule the predicate states'                 -> True
  CL2-GENERAL  shared-with-V5 diagnostic words: ['completeness', 'rule']
  CL2-INST-I   shared-with-V5 diagnostic words: ['detector', 'rule', 'shaped']
```

**Reading, and its limit.** The author who fixed V-5 reasoned in `CL2-GENERAL`'s exact sentence frame
— *shaped to the RULE, not to the detector* ≡ *drawn from the rule, never from the implementation* —
one noun apart (`detector` ← `code`), and a detector *is* an implementation. That is real evidence
for the LITERAL model. **But it does not close the question**: the shared words show
`CL2-INST-I` is the clause carrying `detector` and `shaped`, the two words the fix actually used.
The honest statement is that **the literal model is better evidenced and the assisted model is not
refuted**, so V-TRIM-2 carries a measured risk to V-5 that V-TRIM-1 does not carry at all.

### §1.4 Reddening mutations — executed, each confirmed to bite

```
M-1  key limb 1 on THE CHANGE'S subject (the writer) instead of the DECLARED subject
     applied to V-FULL's clause set -> false positives 1/6 -> RED (mutation bit)
       S-6 AT-174b   _line_bytes partition-invariance PIN  flagged by CL1-DECLARED

M-2  delete limb 2 entirely -> positive arm 4/6 -> RED (mutation bit)
       V-4 AT-165    every producing class is represented  LOST
       V-5 AT-193b   offending list (pre-reshape)  LOST

M-3  delete limb 1 entirely -> positive arm 2/6 -> RED (mutation bit)
       V-1 qa lane   len(join)==_line_bytes-1  [N>=1]  LOST
       V-2 arch lane _line_bytes>=len(join)    [all N]  LOST
       V-3 M-7       _line_bytes==len(report_bytes)+1  LOST
       V-6 AT-172b   raw == document_bytes(raw.decode())  LOST

M-4  ANCHOR-INTEGRITY: corrupt every anchor, confirm detection actually reads the text
     clauses now: CL1-PIN CL1-STATIC CL2-INST-I CL2-INST-II DISCHARGE ORIGIN-ARMS ORIGIN-INST ORIGIN-V6 RELATIONS
     positive arm 2/6 -> RED (detector reads the bytes)
```

**M-1 independently re-confirms A-3.** The architect's original limb-1 wording produces exactly
`1/6` — the S-6 false positive. The amended wording produces `0/6`. Re-derived here, not carried.

**M-2 independently re-confirms A-4.** One-limb C-40 flags `4/6`, missing exactly `AT-165` and
`AT-193b`. Same result as run 1, reached by a harness that reads the text rather than a table.

**M-4 is the mutation run 1 could not have run**, and is the discharge for this harness's own C-40
compliance (§4).

---

## §2 — Where the 5 015 B actually go

The flat discrimination table means the ruling has to be made on *what the excess buys*. Measured,
clause by clause:

| clause | bytes | % of block | % of a C-39 block | bought by the arms? | required by an LLR? |
|---|---|---|---|---|---|
| header + scope | 460 | 9.2 % | 19.0 % | **yes** | — |
| LIMB 1 + PIN corollary | 770 | 15.4 % | 31.7 % | **yes** (catches V-1,2,3,6) | LLR-B64-1.2 |
| LIMB 2 general | 353 | 7.0 % | 14.5 % | **yes** (catches V-4,5) | LLR-B64-1.3 |
| DISCHARGE | 353 | 7.0 % | 14.5 % | **yes** (the executed-transcript rule) | HLR-B64-1 |
| **subtotal — discrimination floor** | **1 936** | **38.6 %** | **0.80×** | | |
| LIMB 2 named instances (i)/(ii) | 654 | 13.0 % | 26.9 % | **no** (literal) / yes (assisted) | **LLR-B64-1.3** |
| RELATIONS (C-10/C-31/C-39/C-35/Certainty) | 1 039 | 20.7 % | 42.8 % | **no** | **LLR-B64-1.4** |
| ORIGIN narrative | 1 386 | 27.6 % | 57.1 % | **no** | house convention only |
| **subtotal — not priced by the arms** | **3 079** | **61.4 %** | **1.27×** | | |

**This reframes the ruling.** The gate breach is not caused by the control's detection content — that
fits inside the cap at 0.80×. It is caused by **1 693 B of operator-mandated relations and absorbed
instances (LLR-B64-1.3 + -1.4) plus 1 386 B of discretionary provenance.** The only genuinely
discretionary component is the Origin, and that is exactly what V-TRIM-1 targets.

**A finding about the gate itself, offered as a backlog carry, not a batch-64 change.** §9.7's R-c
check caps a control block at the length of *one other control block*. C-40 absorbs **three**
candidates (P-5 + P-6 + P-7 by operator ruling) and states **five** relations; C-39 absorbs one and
states two. A 1× cap prices a 3-candidate absorbing control against a 1-candidate one, so it is not a
like-for-like comparison. **I wrote that check in run 1 and it is mine to correct: the cap should be
per-absorbed-candidate, or it should exclude the Origin block, or both.** As written it will fire on
every future absorbing control regardless of density.

---

## §3 — V-TRIM-2's disqualification, executed

The architect flagged that trim (b) "would reverse the absorption ruling and should not be done
without one." That is deference. Here is the executed version.

**AT-B64-05-style scan of the span V-TRIM-2 proposes to move**, word-boundary:

```
--- STACK-FREE scan of the LIMB-2 NAMED INSTANCES span ---
    markdown-it      0        s19              0        report_service   0
    &#160;           0        s19_app          0        _line_bytes      0
    Rich             0        a2l              0        AT-193b          0
    Textual          0        mac              0        AT-165           0
    SVG              0        chk.json         0
                              pytest           0
```

**14 terms, 0 hits. The named instances are stack-free.** They state general defect shapes — *a
positive control shaped to its own detector*; *a consolidation that drops observables* — with no
identifier from this project in them.

Three consequences, in order of force:

1. **The destination is wrong by the project's own placement rule.** Global `/dev-flow` text stays
   project-agnostic; **stack-specific** controls go to `docs/engineering-rules.md`. Moving *stack-free*
   content into the stack-specific file inverts the rule. This holds independent of any byte count.
2. **It reverses A-4 and breaks three approved clauses.** A-4 promoted (i)/(ii) from illustrations to
   **limb 2 of the rule**. LLR-B64-1.3 requires limb 2 "as a normative clause with its two named
   instances"; HLR-B64-1(ii) states limb 2 with them; LLR-B64-5.2 records P-6/P-7 as **ABSORBED into
   C-40**. Executing trim (b) makes all three false.
3. **It is the only variant with a measured discrimination risk** (V-5, assisted model), and it buys
   only **138 B** more than V-TRIM-1 for that risk.

**V-TRIM-2 costs 138 B less than V-TRIM-1 and costs three approved clauses plus a corpus member to
get there. It should be rejected.**

---

## §4 — C-40 applied to this document's own new predicates

Required by the batch's own rule. My new predicate is *"variant `V` flags corpus member `M`."*

- **Declared subject:** the **variant's text** — the bytes whose discrimination is being reported.
- **Is it in the expression?** Yes. `clauses(text)` opens each variant file and tests verbatim anchor
  substrings; the corpus verdict is a function of the detected clause set.
- **Reddening mutation, executed (M-4):** corrupt the `CL1-DECLARED` and `CL2-GENERAL` anchors in the
  variant text. Result **6/6 → 2/6**. The mutation applied (clause set visibly loses both anchors) and
  the predicate reddened. **Not inert.**

### §4.1 Self-report — my run-1 harness was vacuous under the control it was measuring

```
  c40_arms.py  (batch-64 run 1)    reads any C-40 text? False
  c40_variants.py (this run)       reads any C-40 text? True
```

`c40_arms.py` never opens any C-40 text. Its `6/6` and `0/6` are **invariant under every possible
wording of C-40** — the declared subject is absent from the expression. There is no place to apply
the reddening mutation, because the text is not an input, and a predicate with nowhere to apply the
mutation is the definition of inert.

**What this does and does not invalidate.** Run 1's `6/6` / `0/6` / `4/6` remain **correct as
measurements of the CORPUS** — that is what the harness's expression actually ranged over, and the
corpus labels are each traced to a `file:line`. What run 1 could **not** do is measure a *variant*,
which is why this task needed a new harness rather than a re-run. **Both facts are stated because
reporting only the first would be the same defect one level up.** This is a fourth in-batch instance
of C-40 catching its own author, after the architect's limb-1 wording (A-3), the orchestrator's id
census (A-8), and V-6 itself.

---

## §5 — Recommendation

**Adopt V-TRIM-1. Accept the §9.7 second arm at 1.70× C-39.** Reasoning, in order:

1. **It is free on the only axis QA can measure.** 6/6 positive, 0/6 false positives, under both
   models. Zero corpus members lost. Measured, not argued (§1.2).
2. **It is the largest legal saving.** V-TRIM-2 saves 138 B more and is disqualified on three
   independent grounds, one of them executed (§3). No other trim of the offered two exists.
3. **It cuts the breach by 36 %** — 2.07× → 1.70× — and takes it from *"more than twice the reference
   block"* to *"under twice"*, which is the rhetorically different number even though the gate is
   arithmetically still breached.
4. **The residual excess is not discretionary.** After V-TRIM-1, 1 936 B is discrimination and
   1 693 B is LLR-B64-1.3 + -1.4, which the operator already approved. Cutting further means
   reopening an approved requirement, not editing prose.

**One consequence the operator should assent to explicitly, because I will not bury it.** V-TRIM-1
deletes Origin sentence **S3 (361 B)** — the `AT-172b` worked example. That is **the block's only
demonstration of the defect it exists to catch, and the only live-on-`main` instance in the batch**.
It also carries the encoded statement that V-6 is *"missed by C-10, C-31 and C-39"*, which is
AT-B64-03's evidence in the encoded text (AT-B64-03's *artifact* evidence survives in
`01b-qa-catalog.md` §3.5, so this is a provenance loss, not an acceptance loss). Every other encoded
control in this repo carries a worked instance in its Origin — C-35 carries `ASAP2_Demo_V161.a2l`,
C-39 carries the batch-62 measured drift set. C-40 under V-TRIM-1 would be the first without one.

**If the operator wants S3 kept, I costed the variant the architect did not:** drop only Origin
sentences **S4 + S5** (132 + 238 B, the instance evidence — now redundant, since A-4 promoted the
instances into limb 2's normative body) and **S6** (152 B, the arms measurement — which lives in this
document and will live in the lineage record). **Result: 4 491 B = 1.85× C-39, −524 B, 6/6, 0/6.**
That is 364 B more expensive than V-TRIM-1 and keeps the worked example. **It is a straight
trade of 364 B for the block's only self-demonstration, and that is a judgment the arms cannot make
for the operator.**

**Ranked:** V-TRIM-1 (1.70×) > hybrid-keep-S3 (1.85×) > V-FULL (2.07×) >> V-TRIM-2 (rejected).

**One incidental point in V-TRIM-1's favour.** S6 states *"both limbs flag 6 of 6 with 0 false
positives over six sound controls — measured, not argued."* This run **confirms that sentence is
true** as of today. But an encoded claim about a measurement is a claim that can go stale as the
corpus grows; dropping it removes a maintenance obligation from a global command file.

---

## §6 — Discharge 1: AT-B64-05, stack-free scan of the C-35 rider's normative body

**Scope** (LLR-B64-2.2 as amended by A-5): the rider's **normative body only** — rule sentence,
discharge, placement clause — excluding the `(Measured: …)` citation. `AST` is **not** in the term
list. Word boundaries throughout.

```
rider WHOLE     = 1325 B
rider BODY      =  889 B   <- the scan subject (LLR-B64-2.2)
(Measured: ...) =  435 B   <- EXCLUDED per A-5 / house precedent

AT-B64-05 — WORD-BOUNDARY scan of the NORMATIVE BODY
    markdown-it      0        s19_app          0        report_service   0
    &#160;           0        a2l              0        document_bytes   0
    Rich             0        mac              0        _line_bytes      0
    Textual          0        hexfile          0        chk.json         0
    SVG              0        core             0        pytest           0
    s19              0        range_index      0        textual          0
                              ASAP2            0        S19File          0
                                                        IntelHexFile     0

  AST (dropped from the list by A-5): body count = 0  -- informational only

  TOTAL forbidden hits in the normative body: 0  -> GREEN

  REDDENING MUTATION (the scan must be able to go RED):
    inject "Textual" into the body -> hits 1 -> RED (scan bites)
    confirm the mutation applied: body != mutant -> True
```

**Result: GREEN, 21 terms, 0 hits.** This is an independent scan by the gate lane, discharging the
architect's §10.2 self-report that their own scan was *"P-6 committed inside the batch encoding P-6."*

**Two honest notes.**

1. **`AST` = 0 in the body anyway.** A-5 dropped it from the list because `dev-flow.md:57` uses it
   inside C-31 as a legitimate stack-free technique. That ruling stands on its own merits, but for
   *this* text it changed nothing — the rider never used the term. Reported so the amendment is not
   credited with a save it did not make.
2. **Word boundaries did not matter for this text.** Naive case-insensitive substring counts over the
   *whole* rider for `Rich` / `mac` / `core` returned **0 / 0 / 0**, identical to the bounded counts.
   The phantom hits in my run-1 harness came from scanning a longer body. Boundaries are used here
   because they are correct, **not** because they rescued this result — claiming otherwise would be
   exactly the kind of unearned credit this batch is about.

**The `chk.json` scoping is sound.** It appears only in the excluded `(Measured: …)` citation.
Precedent verified on disk: `dev-flow.md:145`'s own C-35 `(Origin: …)` carries
`ASAP2_Demo_V161.a2l`, a project fixture name, inside its citation.

---

## §7 — Discharge 2: AT-B64-08, de-identification of the `VERIFY.md` extension

Subject: the final extension text, §3.4 of the consolidated spec, **1 540 B / 19 lines**.

```
AT-B64-08 — de-identification, WORD-BOUNDARY, over the FULL extension text
    CRC Designer   0      s19tool        0      ASAP2          0
    CRC            0      s19tui         0
    s19            0      a2l            0
    s19_app        0      mac            0

  repo-path identifiers (regex sweep):
    dev-flow path      0   (\.dev-flow)          .py file           0   (\.py\b)
    tests/ path        0   (tests/)              fixture ext        0   (\.s19\b|\.a2l\b|...)
    package path       0   (s19_app/)            examples path      0   (examples/)
    windows abs path   0   ([A-Za-z]:[\\/]{1,2}Users)   repo host path 0   (\bGithub\b)
                                                 test runner        0   (\bpytest\b)

  TOTAL identifiers: 0  -> GREEN

  REDDENING MUTATION (the scan must be able to go RED):
    inject 's19tui' -> hits 1 -> RED (scan bites)
    mutation actually applied (text changed): True
    inject 'tests/...' path -> hits 1 -> RED; applied: True

  Generic terms PRESENT (confirms the scan ran over non-empty, on-topic text):
    snapshot export    1      render spans       1      false FAIL         1
    rail label         1      &#160;             1      impossible         1
    menu entry         1      producer           2
```

**Result: GREEN.** Zero `CRC Designer`, `s19`, `a2l`, `mac`, or repo-path identifiers, across 9 term
checks and 9 path regexes, with **two** reddening mutations both confirmed to bite.

**Non-emptiness guard included deliberately.** A de-identification scan over an empty or truncated
string is trivially green — the same class of defect as the corpus arms this batch exists to fix. The
generic-term counts prove the scan ran over the real, on-topic extension: `&#160;` ×1 and
`false FAIL` ×1 are the two clauses that carry the extension's actual contribution.

**Note on `&#160;`.** It is present and it is **correct** to be present: it is a
generic HTML/XML entity, not a project identifier, and it is the mechanism the extension teaches. It
appears on the AT-B64-05 forbidden list (for the *global command's rider*) and not on AT-B64-08's
list (for the *skill's* `VERIFY.md`) — the two scans have different scopes by design, and I confirmed
the lists are not accidentally swapped.

---

## §8 — Discharge 3: AT-B64-10, the re-scoped census, PRE-RED / POST-GREEN verified

**Predicate.** For each id in `{C-29, C-40, C-42}`: `encoded(id) == registered(id)`, where
`encoded` requires an id-bearing **declaration** (`## C-NN — …` heading, or a bullet whose bolded
lead contains `(C-NN)`) in a destination file, and `registered` is a word-boundary hit in the
canonical lineage record. **`.dev-flow/**` excluded from both directions** (A-6).

```
============================================================================================
PRE-BATCH — tree as it stands (nothing applied)
============================================================================================
  id     encoded?   where                        registered?  consistent
  C-29   True       docs/engineering-rules.md    False        MISMATCH
  C-40   False      —                            False        ok
  C-42   False      —                            False        ok

  CENSUS -> RED
     C-29: ENCODED but NOT REGISTERED

============================================================================================
POST-BATCH — simulated with §3.1 + §3.3 applied + lineage entries
============================================================================================
  id     encoded?   where                        registered?  consistent
  C-29   True       docs/engineering-rules.md    True         ok
  C-40   True       dev-flow.md                  True         ok
  C-42   True       docs/engineering-rules.md    True         ok

  CENSUS -> GREEN

AT-B64-10 VERDICT   PRE = RED   POST = GREEN
  required: PRE RED, POST GREEN  -> SATISFIED
```

**Result: the re-scope works. PRE = RED, POST = GREEN, verified rather than assumed.**

### §8.1 But the re-scope fixed it only partially, and the operator should know how

```
  GREEN-BY-CONSTRUCTION AUDIT (the thing F-2 flagged and the re-scope had to fix):
    C-29: encoded=True registered=False -> carries the RED
    C-40: encoded=False registered=False -> consistent-by-absence — contributes NO pre-batch signal
    C-42: encoded=False registered=False -> consistent-by-absence — contributes NO pre-batch signal
    ids supplying the pre-batch RED: 1/3
```

**The entire pre-batch RED rests on `C-29`.** `C-40` and `C-42` are consistent-by-absence pre-batch —
they are unencoded *and* unregistered, which the predicate correctly reads as consistent. So the
re-scope defeats green-by-construction **because A-14 added C-29 to the subject set**, not because
the set was narrowed. **Drop C-29 and the AT is green-by-construction again.** This does not block —
the AT is satisfied as scoped — but the mechanism is narrower than "the re-scope fixed it" implies,
and `C-29` is load-bearing for AT-B64-10 in a way nothing in the spec currently records.

Post-batch the AT is meaningful for all three ids in the direction that matters: a batch that encodes
a control and forgets to register it goes RED. Both directions executed:

```
M-1  encode C-40 but FORGET to register it   -> C-40 ENCODED but NOT REGISTERED  -> RED as required
M-2  register C-40 but FORGET to encode it   -> C-40 REGISTERED but NOT ENCODED  -> RED as required
```

### §8.2 The two integrity mutations that make this census non-vacuous

**M-3 — declaration vs mention.** A-8 recorded the orchestrator's own instance of this batch's defect
class: *the RC-1 census counted mentions, not encodings*. My predicate must not repeat it.

```
    C-10: declarations=1  mentions=5   (a mention-counting census would over-report)
    C-29: declarations=1  mentions=1
    C-40: declarations=1  mentions=3   (a mention-counting census would over-report)
```

`C-40` is mentioned 3× across destinations (once as its own declaration, plus cross-references inside
its own block and in C-42's text) but declared **once**. The two predicates give different answers on
the same tree, so the declaration predicate is doing real work.

**M-4 — the exclusion is load-bearing, measured.**

```
    C-29: 212 mentions under .dev-flow/**
    C-40: 146 mentions under .dev-flow/**
    C-42:  65 mentions under .dev-flow/**
```

Without the `.dev-flow/**` exclusion, `registered` would be TRUE for all three ids pre-batch and the
census would read GREEN before the batch did anything. **A-6's exclusion is what makes the AT
capable of going RED at all**, and the numbers show by how much.

---

## §9 — Blockers and open items

| # | item | severity | disposition |
|---|---|---|---|
| **B-1** | **The §9.7 R-c gate is BREACHED under every legal variant.** Floor with all LLR-required clauses = 4 127 B = 1.70×; cap = 1×. No trim that satisfies LLR-B64-1.3 + -1.4 can clear the first arm. | **OPERATOR RULING REQUIRED** | §5 recommends accepting the second arm at V-TRIM-1's 1.70×. **This is the one item that changes the deliverable's text.** |
| **B-2** | **The R-c check as I wrote it in run 1 is not like-for-like** — it caps a 3-candidate absorbing control against a 1-candidate one, and prices narrative identically with discrimination. | MEDIUM | My defect to carry. Proposed for `.dev-flow/BACKLOG.md`: make the cap per-absorbed-candidate or exclude the Origin block. **Not a batch-64 change.** |
| **B-3** | **`AT-172b` is still a live tautology on `main`** (V-6). Out of batch-64's scope; carried at `01b-qa-catalog.md` §9.6. Re-confirmed present this run. | MEDIUM | Backlog carry, unchanged. |
| **B-4** | **The assisted/literal model question for V-5 is evidenced, not closed.** §1.3 favours literal; it does not refute assisted. | LOW | Only affects V-TRIM-2, which is rejected on other grounds. Moot if the recommendation is taken. |
| **B-5** | **AT-B64-10's pre-batch RED depends entirely on `C-29`** (§8.1). Nothing in the spec records that C-29 is load-bearing for the AT rather than an incidental backlog fix. | LOW | Recommend §4 of the consolidated spec note it, so a future re-scope does not drop C-29 and silently re-vacuate the AT. |
| **B-6** | **`~/.claude/skills/tui-design/SKILL.md` still unread by any lane** (architect §10.5). If it states an overlapping rule the `VERIFY.md` extension may be partly redundant. I did not read it either — out of the scope I was given. | LOW | Carried, unchanged. Names a real gap in AT-B64-09's coverage. |
| **B-7** | **The `2201 passed` baseline remains carried by all three lanes and re-measured by none** (architect §10.4). Not in my scope this run; flagged so it is not lost. | LOW | Must be re-derived at the Phase-3 gate per this batch's own rule. |

**Files written by this lane:** `.dev-flow/2026-07-27-batch-64/01c-arms-measurement.md` (this file)
only. No destination file (`dev-flow.md`, `VERIFY.md`, `docs/engineering-rules.md`, the lineage
memory) was read-modified — all were opened read-only.

---

## §10 — Evidence checklist

| item | ✓/✗ | evidence |
|---|---|---|
| Acceptance criteria use Given/When/Then | **N/A** | this run produces measurements against an existing AT catalog (`01b-qa-catalog.md` §5), not new ATs |
| Test cases have explicit Expected, not vague "works" | ✓ | every arm states expected (6/6, 0/6, PRE-RED/POST-GREEN) before the transcript |
| Edge cases include empty, boundary, invalid, error | ✓ | non-emptiness guard (§7 generic-term counts); boundary = V-CORE floor at 0.80× (§2); invalid = anchor corruption M-4; error direction = both M-1/M-2 census directions |
| Regression checklist exists | ✓ | §9 B-2…B-7 carry every item this run could break or leaves open |
| Exit criteria stated | ✓ | §5 ranked recommendation + §9 B-1 as the single blocking ruling |
| No real PII / secrets | ✓ | all inputs are repo docs and `~/.claude` command/skill text; no credentials read or printed |
| Test results left blank unless actually run | ✓ | **every number in this document was executed in this session**; §0 tabulates which previously-stated figures I confirmed and which two I corrected |
| Layer B (black-box) | ✓ | the variants are measured through their **shipped surface** — the literal bytes that would be pasted into `dev-flow.md` — not through a model of them. M-4 proves the harness reads those bytes |
| Bidirectional surface-reachability | ✓ | inputs: 3 variants + V-CORE, all read from disk. outputs: positive arm, negative arm, bytes, ratio, lost-member — each observed per variant, §1.2 |
| No unfilled template | ✓ | no `<…>` placeholders, no `TC-NNN`, no empty required rows |
| C-40 applied to this document's own predicates | ✓ | §4, with the reddening mutation executed (6/6 → 2/6) and the run-1 self-report at §4.1 |
