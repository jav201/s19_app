# batch-64 — Phase 2, ARCHITECT REVIEW (independent)

> **VERDICT: BLOCKED. 6 blockers, 10 majors, 8 minors.**
>
> **The headline is the union audit, and it found the thing it was sent to find.** Of **163** union
> items enumerated from `01-requirements-architect.md` and `01b-qa-catalog.md`, **136 are carried**,
> **7 are explicitly retired with a stated reason**, and **20 are dropped with no retirement line**.
> Six of those twenty are blocker-grade. **The document that encodes *"a consolidation that drops
> observables"* as instance (ii) of its own control dropped twenty observables while doing it** — and,
> worse than batch-63, it printed a false *preservation* line twice (§3.3 and §3.4 both say
> "Unchanged"; both are changed).
>
> **Two further blockers are not about the fold at all.** `AT-B64-04` — the **sole** load-bearing
> acceptance for `US-B64-2` — had its subject replaced wholesale (C-41's clauses → the C-35 rider's
> clauses) and **has never been executed against any text**, and §10 does not disclose it as un-run.
> And the document is **stale against `01c-arms-measurement.md` and against operator ruling D-9**,
> which is recorded in **no** batch artifact.
>
> **`shall`/`should` discipline: CLEAN.** Verified mechanically — this is the one axis with nothing to report.
>
> **Controls earning their place: C-42 YES (unqualified) · the C-35 rider YES · C-40 YES as a control,
> but V-FULL's 5 015 B is earned only on the relations axis, not the detection axis** — 61.4 % of the
> block does no detection work (`01c` §2), and the operator's D-9 acceptance of the second arm must be
> written into the spec rather than left as an open question in §9.1/§10.7.

**Reviewer standing.** I did not author the artifact. Every claim below is the output of a command run
in this session; nothing is predicted.

---

## §0 — Baseline integrity (required by the brief)

The three out-of-VCS destinations are **UNMODIFIED**. Verified this session:

```
44660d7cfede148746ac27dcbb8cccabd11c9a420de94b6351b2c7e7ad10b883 *.claude/commands/dev-flow.md
23cf75e6ae8d0a2c04489f99954ab7d6e976ae3eb93846cba9c8fb25ca9588ed *.claude/skills/tui-design/VERIFY.md
  275 59259 .claude/commands/dev-flow.md
  182 10142 .claude/skills/tui-design/VERIFY.md
```

Both match the spec's §6 PRE table exactly (`01-requirements-consolidated.md:282-283`). **Nothing has
been encoded yet**, which is correct for Phase 2. Anchors re-verified on disk: `dev-flow.md:99` is the
*Certainty* clause verbatim; `:145` is C-35; `:147` is C-39; `:177` is C-19; `VERIFY.md:34` is
`## Pin the truth, not a string  [travels]` with `## Mutation-test every assert` at `:40`. Every
placement LLR points at a real anchor.

**`shall`/`should` discipline — executed, CLEAN.**

```
'shall' at lines: 76 83 84 85 86 87 88 116…137 337
'should' at lines: 76 (convention) 372 383
```

`shall` occurs only inside HLR statements (`:83-88`), LLR statements (`:116-137`), and two meta-mentions
of the convention itself (`:76`, `:337`). `should` occurs only in informative text (`:372` the length
ruling, `:383` the recommended next action). **No finding.**

---

## §1 — THE UNION AUDIT (SPECIFIC-1)

**Method, stated because it is the point.** I did **not** review §1's amendment table. I enumerated
every observable, acceptance clause, finding, executed measurement, and constraint present in the two
source lanes, then tested each for presence in the consolidated document. batch-63's revision-3 fold
was caught only because an auditor went to the sources; the amendment table is the fold's own account
of itself and cannot detect what the fold forgot it changed.

### §1.1 — Tally

| disposition | count |
|---|---|
| union items enumerated (architect 77 + QA 94, less 8 cross-lane duplicates) | **163** |
| **carried** into the consolidated (verbatim, amended, or by explicit citation) | **136** |
| **explicitly retired with a stated reason** | **7** |
| **DROPPED — in neither category** | **20** |

The seven legitimate retirements, for the record — this is what the discipline looks like when it
works: C-41 as a control (A-1, operator ruling) · `AST` from the forbidden term list (A-5) · the sixth
C-42 mechanic (A-9, "presentation split, not a sixth") · `AT-B64-11` as acceptance (A-10) · `US-B64-5`
(operator ruling, §4.1) · any P-3 *total* in encoded text (A-12) · the `TC` layer (§4, N/A with reason).

### §1.2 — The twenty drops

Numbered `D-*` for reference. Severity assigned in §2.

| # | dropped item | source | present in consolidated? |
|---|---|---|---|
| D-01 | C-41's **`EXTENDS C-36`** relation, and §C.2's working that C-41 catches cases C-36 provably does not | `01-requirements-architect.md:141`, `:260-266` | **No.** `grep -c "C-36"` → architect **10**, consolidated **2**, and both survivors are incidental (`:121` house-form reference, `:134` the stale-footer string) |
| D-02 | C-41's **`startswith`/prefix-guard** clause — 1 of the "three spellings of the same mistake" | `:141` | **No.** `grep "prefix guard"` → consolidated **0**. `startswith` survives once, inside C-42's `(Origin: …)` only |
| D-03 | C-41's **"the failure is quiet and symmetric … reads as a measurement rather than as a bug"** normative clause | `:141` | **No.** `grep "quiet and symmetric"` → consolidated **0** |
| D-04 | C-41's **"an *impossible* value is luck, not detection"** corollary — demoted from normative clause to a parenthetical inside `(Measured: …)` | `:141` vs consolidated `:152` | **Demoted, not carried** |
| D-05 | §C.1's finding that the idea also pre-exists at **`dev-flow.md:177` (C-19, "the RED counterfactual")** and at **`VERIFY.md:40-49`** | `:220-227` | **No.** `grep -c "C-19"` → architect 2, consolidated **0**. C-40 now claims to EXTEND the Certainty clause alone |
| D-06 | §C.1's **recommendation** to apply LLR-B64-1.4 plus its drift argument (*"the flow states the same requirement twice … and they will drift"*) | `:245-250` | **No.** LLR-B64-1.5 survives as a bare `*(OPTIONAL — operator call)*` row with no rationale |
| D-07 | §C.3's **working** that C-42 is distinct from C-32/C-37 (*"C-32 has no purchase; the case is untouched"*) | `:287-295` | **No.** Only C-42's own self-declaration survives |
| D-08 | §G's alternative: **C-40 as an amendment to the Certainty clause + the one new static sentence, "roughly one third the bytes"** | `:452-456` | **No.** §9.1 offers only trims (a) and (b) |
| D-09 | §G's alternative F-1 ruling and its consequence: *if a global control may cite no project identifier, **C-35's `(Origin: …)` is already in violation** and that is a separate cleanup item* | `:460-463` | **No** |
| D-10 | §E's expected deltas for **`VERIFY.md`** and the **lineage memory** (the bounded-delta check's "state the expected magnitude before the edit") | `:424` | **No.** §6 states the expected delta for `dev-flow.md` only |
| D-11 | §E's obligation to **cross-reference the pasted text from the evidence artifact** so a reviewer can diff it against the POST file — *"the only external reviewer these legs get"* | `:431-433` | **No** |
| D-12 | **QA §4 — the validation-method table** (6 rows: Test / Demo / Inspection / Analysis per story, each with justification) | `01b-qa-catalog.md:307-317` | **No.** `grep -c` → consolidated: `Inspection` **0**, `Analysis` **0** |
| D-13 | **QA §8 — the evidence checklist** (10 rows), including *no unfilled template*, *edge cases: empty/boundary/invalid/error*, *Layer B through the SHIPPED surface*, *bidirectional surface-reachability*, and the **declared G/W/T deviation** | `:723-737` | **No.** Silently replaced by the architect-role 8-row checklist at §9 |
| D-14 | **QA §9.7 regression checklist — 4 of 6 rows**: the `[travels]` fallback (*"if it cannot be met, the tag is dropped rather than the constraint"*); the **`.dev-flow/BACKLOG.md` collision check** (*"re-read before reconciling; do not re-apply"*); the **lineage-census re-run-AFTER-the-edit** check; and R-d's "SHA taken immediately before and after" | `:787-802` | **No.** `grep -c "collision"` → consolidated **0** |
| D-15 | QA §9.6's traceability link **`R-TUI-097` / `REQUIREMENTS.md:4849` cites `AT-172` as covering this** | `:782` | **No.** `grep` → consolidated **0** for both tokens |
| D-16 | `AT-B64-01`'s **second** reddening mutation (move S-6 into the positive corpus → `6/7` → RED) | `:333-334` | **No** |
| D-17 | `AT-B64-05`'s **"Note against myself"** — the word-boundary harness defect QA reproduced and recorded rather than quietly fixing | `:442-444` | **No** |
| D-18 | §9.9's caveat that **S-5 / `TC-441` was never shipped** — *"a valid negative-control predicate; it is not a running test"* | `:825-827` | **No** |
| D-19 | LLR-B64-2.2's forbidden-identifier class silently loses **"or fixture"** (architect: *"module, function, class, or **fixture** identifier"*) | `:103` vs consolidated `:122` | **Narrowed without an amendment row** |
| D-20 | E-5's record that **`dev-flow.md:202`'s `Textual` is NORMATIVE**, not an Origin example | `:35`; QA `:435-437` | **No.** A-5 carries only the count |

---

## §2 — BLOCKERS

### BLOCKER-1 — `AT-B64-04` is the sole load-bearing acceptance for `US-B64-2`, its subject was replaced wholesale, and it has never been executed. The spec does not disclose this.

`01-requirements-consolidated.md:227` states the re-scope in its own words:

> `| **AT-B64-04** | … | **8 occurrences across batches 60-63** (was ~9 across 61-63) — A-7. Subject is now **the C-35 rider's clauses**, not C-41's | re-scoped |`

`:246` makes it load-bearing and alone: `| US-B64-2 | HLR-B64-2 | 2.1 – 2.3 | 04, 05 | **04** (05 is weak) |`.

Three facts compose into the blocker:

1. **The subject changed, not merely the count.** A-7 (`:58`) amends only the occurrence set. But C-41
   (≈2 000 B, four normative clause groups) was replaced by an 889-byte rider that **dropped three of
   those clauses** (D-02, D-03, D-04). An arm that flags 8 occurrences against C-41's clauses is not
   evidence about the rider's clauses.
2. **It has never been run.** `grep "AT-B64-04"` returns **0 hits** in `01c-arms-measurement.md`. QA's
   own verdict was *"UNSATISFIABLE AS WRITTEN. Blocker, §9.3"* (`01b-qa-catalog.md:406`), and QA's
   reddening mutation was executed **on the corpus**, not against any control text.
3. **§10 conceals it.** `:378-383` lists only `AT-B64-01/02/03` as un-runnable, and calls the limb-1
   re-run *"the single highest-value remaining check"*. `AT-B64-04` is absent from §10 entirely, so a
   gate reader is told three arms are pending when four are.

Concretely: **D-02's removal is the live risk.** Occurrence #? in QA's enumeration is the
`startswith("| 0x00001")` row counter that reported 4 rows where 400 were emitted. C-41 flagged it by
a dedicated named clause; the rider must now flag it via *"prefer a predicate over the producer's own
structured output … to a substring search over serialized text."* That may hold — but it is **exactly
the kind of claim this batch exists to say must be executed, not argued.**

**Required fold.** Execute `AT-B64-04` against §3.2's pasted rider bytes over the 8 enumerated
occurrences, paste the transcript, and add the reddening mutation (delete the "structured output"
clause and confirm the arm loses the `startswith` occurrence). Until then §10 must list `AT-B64-04`
alongside 01/02/03.

---

### BLOCKER-2 — Two false preservation claims. §3.3 and §3.4 both assert "Unchanged"; both are changed, and one changed a normative requirement.

This is the batch's own defect class inverted. C-40 instance (ii) (`:146`) requires a merge to *"carry
every observable forward **or print an explicit retirement line**."* The fold instead printed a
**preservation** line that is false — a failure mode instance (ii) does not even name.

**(a) §3.3 — C-42.** `:165-166` reads *"(Unchanged from the architect lane. Reproduced here because
this document is normative.)"* Executed word-diff, architect `:150-160` vs consolidated `:169-179`:

```
< 19**.
---
> 29**  across  the  snapshot  set  while  the  emitted  form  matched  **29  of  29**.
...
< grep
---
> grep,  reproduced  live  in  this  repo
```

The measurement changed from **0 of 19** (batch-62's cited figure) to **0 of 29** (a live in-repo
reproduction), in both mechanic 4 and the `(Origin: …)`. The change is an **improvement** — and that
is not the point. It is an undeclared substitution of one measured number for another inside text
labelled unchanged, in a batch whose §0 rule is *"a carried number is re-derived, not copied."*

**(b) §3.4 — `VERIFY.md`, and this one moved a requirement.** `:184-185` reads *"(Unchanged.)"*
Executed diff, architect `:169-183` vs consolidated `:188-206`:

```
9a10,13
> Note the direction: this is a **false FAIL**, not a false pass. Everything above is about a check that
> cannot go red; this one goes red against a correct implementation, which is worse, because it looks
> like a real defect and invites "fixing" something that was never broken.
```

A whole paragraph was **added**. And LLR-B64-4.3 was rewritten to require it — architect `:110`
(*"read a genuine runtime value and therefore satisfied the pre-existing rule in full"*) became
consolidated `:129` (*"read a genuine runtime value **and a false fail**, the direction the section
does not cover"*). **A normative LLR changed with no amendment row**, under a heading asserting
nothing changed. §3.4 then compounds it at `:211-212` by claiming *"The added false-fail-direction
paragraph is what earns the tag"* — the document simultaneously calls the paragraph "unchanged" and
credits it as the `[travels]` justification.

**Required fold.** Delete both "Unchanged" labels. Add amendment rows: `0/19 → 0/29 (live
reproduction)` and `+false-FAIL-direction paragraph, LLR-B64-4.3 rewritten to require it`.

---

### BLOCKER-3 — Four normative clauses were deleted in the C-41 → rider conversion with no retirement line.

D-01 through D-04. A-1 (`:52`) records only the **form** change (*"a new global control C-41 … → a
rider … ~700 B"*) and its byte cost. It does not record that the conversion **deleted rule content**:

- the **`EXTENDS C-36`** relation, whose supporting working (`01-requirements-architect.md:262-266`)
  was the measured demonstration that C-41 catches a case C-36 satisfies in full — *"the label is a
  defined constant on disk, C-36 is satisfied, and the predicate still false-failed a correct
  implementation."* The rider now relates to C-35 only;
- the **prefix-guard** spelling (D-02) — see BLOCKER-1;
- the **quiet-and-symmetric** clause (D-03) — the explanation of *why* the defect is expensive;
- the **impossible-value** corollary (D-04), demoted into `(Measured: …)`, where by the document's own
  F-1 ruling (`:157-161`) the citation is explicitly **out of normative scope**. A rule moved into a
  region the spec has ruled non-normative has been retired, not relocated.

The rider's length is a legitimate operator ruling (D-7). **Which clauses paid for it is a design
decision the operator never saw**, because the amendment table prices the change in bytes and not in
rules.

**Required fold.** One amendment row enumerating the four deleted clauses, each marked RETIRED (with
the reason) or RE-HOMED (with the destination). If the prefix-guard clause is retired, `AT-B64-04`
must show the rider still flags that occurrence — which is BLOCKER-1.

---

### BLOCKER-4 — The normative document is stale against `01c-arms-measurement.md` and against operator ruling D-9, which is recorded nowhere.

The consolidated (14:58) predates `01c` (15:11). `01c` is not a supporting note — it is the executed
measurement of the spec's own central open question, and it **corrects and refutes** the spec on five
points:

| consolidated says | `01c` measured | cite |
|---|---|---|
| §10.7: the R-c ruling is **open**; *"the one open item that can change the deliverable's text"* | Operator ruled **D-9: ship V-FULL, 5 015 B**, accepting the second arm | brief; **recorded in no artifact** |
| §9.1: trim (a) saves **−~1 400 B** | **−888 B**. The spec priced the whole Origin (1 386 B) while its own trim keeps the first two sentences (497 B) — *"the **third** estimate in §9.1 to miss"* | `01c:46`, `:50-52` |
| §6/§9.1: rider body **890 B** | **889 B** | `01c:45`, `01c:331-333` |
| §10.1: `AT-B64-01/02/03` un-run; the limb-1 amendment *"has not been run through `c40_arms.py`"* | **Run.** M-1 confirms V-FULL yields `0/6` where the pre-amendment wording yields `1/6`; M-2 confirms `4/6` one-limb; M-3 `2/6`; M-4 anchor-integrity `6/6→2/6` | `01c:150-176` |
| §0: cites QA's `6/6`/`0/6`/`4/6` as measurements | **`c40_arms.py` never opens any C-40 text.** Its results are *"invariant under every possible wording of C-40"* — valid as **corpus** measurements, incapable of measuring a variant | `01c:261-279` |

That last row is the sharpest. §10.3 states *"If any of those five is wrong, this document inherits
the error."* One is now known to be a measurement of something other than what the spec cites it for.

**Separately: D-9 is recorded in no batch artifact.** `grep -rn "D-9" *.md` → **0 hits**. `PLAN.md`'s
decision log ends at D-8 (`PLAN.md:189-196`). This violates the batch's own authorization commitment
(`PLAN.md:43-45`): *"every normative ruling is surfaced in-conversation as it is made … All un-asked
decisions land in this PLAN's decision log, `state.json.decisions_log`, `05-postmortem.md`, and the
vault at sync."*

**Required fold.** Record D-9 in `PLAN.md` §10 and `state.json`. Close §10.7 and rewrite §9.1's
*"I am not choosing"* to record the ruling and its accepted justification. Correct 890→889 and
−1 400→−888. Amend §0's citation of `6/6`/`0/6`/`4/6` to state what the run-1 harness ranged over, and
replace §10.1 with `01c`'s executed results.

---

### BLOCKER-5 — QA's validation-method table (§4) and evidence checklist (§8) — 16 rows — dropped with no retirement.

D-12 and D-13. The consolidated declares itself normative and says it *supersedes* both lanes
(`:3-5`). Superseding means the normative document must carry the union or retire the remainder.

- **§4 (6 rows)** assigned a verification method per story with justification — `Test` where a
  reproduction exists, `Demo` for prose walkthroughs, `Inspection` for limb 2 (*"cannot be
  mechanised"*), `Analysis` for `AT-B64-09` (*"labelled honestly rather than dressed as a test"*).
  Executed: `Inspection` and `Analysis` return **0** in the consolidated. The normative spec now
  assigns **no verification method to any requirement** — a required IEEE-830 element, and the very
  distinction that keeps `AT-B64-09` from being over-claimed as a test.
- **§8 (10 rows)** carried discharges the architect's 8-row checklist does not cover: *no unfilled
  template*; *edge cases include empty, boundary, invalid, error*; *Layer B observed through the
  SHIPPED surface*; *bidirectional surface-reachability*; *no real PII/secrets*; and the **declared
  G/W/T deviation** (`⚠ partial`, *"deviation declared, not silent"*). A declared deviation that
  disappears at the fold becomes an undeclared one.

**Required fold.** Carry §4 as a table and merge §8's rows into §9, or retire each with a reason.

---

### BLOCKER-6 — Four of six regression-checklist rows dropped, including the only check that closes `AT-B64-10`'s loop and the only check on the batch's declared collision point.

D-14. `01b-qa-catalog.md:787-802`. Two of the four are load-bearing:

- ***"The lineage memory is read by `/dev-flow-sync`. Check: the bidirectional census (AT-B64-10) is
  re-run AFTER the edit, not only before."*** `AT-B64-10` is the spec's *"strongest mechanical AT"*
  (`:233`). Executed pre-batch it is RED; executed post-batch it must be GREEN. **The consolidated
  states no post-edit re-run obligation anywhere.** Without it the strongest AT is a pre-batch
  observation, not an acceptance. (`01c` §8 simulated POST — a simulation over proposed text is not
  the post-edit run.)
- ***"`.dev-flow/BACKLOG.md` is the one real collision point with parallel work. Check: re-read before
  reconciling; do not re-apply."*** `grep -c "collision"` → consolidated **0**, while `PLAN.md:217`
  marks it **"the one real collision point"** and `LLR-B64-5.4` (`:134`) edits exactly that file in
  Inc-4. A stated concurrency hazard with a stated mitigation vanished from the document that governs
  the increment.

**Required fold.** Restore all four rows into a §-level regression checklist.

---

## §3 — C-40 APPLIED TO THE SPEC'S OWN ACCEPTANCES (SPECIFIC-2)

Both limbs, on each `AT-B64-*`. **Bottom line: the three re-scopes are not equivalent — one genuinely
fixed the defect, one relocated it, one is disclosed-weak.**

| AT | limb 1 — declared subject in the expression? | limb 2 — set drawn from the RULE? | verdict |
|---|---|---|---|
| 01 | ✓ subject = C-40's encoded text; `01c` M-4 proves the run-2 harness reads those bytes | ✓ corpus fixed before C-40 existed; V-6 found after | sound |
| 02 | ✓ same | ✓ S-6 shaped to trap a lazy C-40 | sound |
| 03 | ✓ | n/a | sound |
| **04** | ✓ *in principle* — **but never evaluated against any text** | ✓ 8 enumerated from primary records | **BLOCKER-1** |
| **05** | ⚠ weak (disclosed at `:228`) | **✗ the 21-term list is hand-shaped**, and unlike `AT-B64-08` it carries **no non-emptiness guard** | minor, disclosed |
| 06 | ✓ keyed on which mechanics C-42 names | ✓ five from the record | sound |
| 07 | ⚠ weak (disclosed) | n/a | disclosed |
| 08 | ✗ blind to whether the extension teaches anything (disclosed) | ✓ `01c` §7 added a non-emptiness guard | disclosed |
| 09 | ✓ separated two candidate drafts | n/a | sound |
| **10** | ✓ | **✗ the set `{C-29, C-40, C-42}` is drawn from what the batch touches — the implementation — not from the rule *"every encoded control id"*** | **MAJOR-1** |
| 11 | ✗ (retired to bookkeeping, A-10) | n/a | correctly retired |

### §3.1 — `AT-B64-04`, `-05`, `-10`: did the re-scopes fix or relocate?

- **`AT-B64-05` — fixed, and the fix is verified by an independent party.** `01c` §6 scanned the
  rider's actual 889-byte body over 21 terms: **0 hits, GREEN**, with an executed reddening mutation
  (inject `Textual` → 1 hit → RED, mutation confirmed applied). This discharges §10.2's honest
  self-report that the architect's own scan was *"P-6 committed inside the batch encoding P-6."* The
  residual weakness (hand-shaped term list, no non-emptiness guard) is real but the spec labels the AT
  **WEAK** at `:228`, so it is disclosed, not hidden. **Minor.**

- **`AT-B64-10` — RELOCATED, and the brief's suspicion is confirmed by execution.** The pre-batch RED
  rests **entirely on `C-29`**. `01c:459-472`, executed:

  ```
  C-29: encoded=True registered=False -> carries the RED
  C-40: encoded=False registered=False -> consistent-by-absence — contributes NO pre-batch signal
  C-42: encoded=False registered=False -> consistent-by-absence — contributes NO pre-batch signal
  ids supplying the pre-batch RED: 1/3
  ```

  `01c` states the consequence plainly: *"the re-scope defeats green-by-construction **because A-14
  added C-29 to the subject set**, not because the set was narrowed. **Drop C-29 and the AT is
  green-by-construction again.**"* That is F-2 returning one amendment away from closing —
  the precise pattern the brief flagged.

  **Is it adequately recorded? No.** A-6 (`:57`) reads *"My F-2 (green by construction) + QA §9.4
  (RED pre-batch on 9 ids). `C-29` closed here"*, and §7.2 files C-29 as a cheap backlog closure. **No
  line in the spec says C-29 is load-bearing for `AT-B64-10`.** `01c` B-5 (`:519`) recommends exactly
  this addition. A future re-scope that drops C-29 as "already done" silently re-vacuates the batch's
  strongest AT.

  **Required fold (MAJOR-1).** State in §4 that `C-29` is the sole supplier of the pre-batch RED and
  must not be removed from the subject set. Then strengthen limb 2 by drawing the set from the rule:
  **all encoded ids in the union**, with `C-1…C-9` carried as a *named known-RED exception* rather
  than excluded by narrowing the quantifier.

### §3.2 — Did the limb-1 amendment fix `AT-B64-02`, or relocate it?

**It fixed it — and I can say so from an execution I did not perform, which is the right standard
here.** `01c:150-152`, M-1:

```
M-1  key limb 1 on THE CHANGE'S subject (the writer) instead of the DECLARED subject
     applied to V-FULL's clause set -> false positives 1/6 -> RED (mutation bit)
       S-6 AT-174b   _line_bytes partition-invariance PIN  flagged by CL1-DECLARED
```

`01c:169-170`: *"The architect's original limb-1 wording produces exactly `1/6` … The amended wording
produces `0/6`. Re-derived here, not carried."* Independent of QA run 1's refuted harness. **The
re-scope is real, not relocated.**

**Two residual observations, both minor.**

- **The refuted wording is still in the text, twice, unqualified.** Limb 1 (`:146`) reads
  *"…; a predicate whose value is **invariant under the change it gates** cannot gate it"*, and the
  DISTINCT clause repeats *"…and still be invariant under the change it gates."* Applied to S-6 in
  isolation, both flag it; only the PIN corollary later in the same limb rescues it. `01c`'s harness
  keys on the `CL1-DECLARED` anchor, so **no arm ever evaluates that sentence in isolation.** The text
  is internally coherent — a reader who reaches the corollary gets the right answer — but the
  cheapest hardening is a four-word bridge: *"…cannot gate it — **see the corollary below**."*
- **QA §3.1's own formal statement carries the same defect the amendment repairs.** `01b:218-220`
  defines *"`subject(D)` = the artifact or symbol `D` modifies"*, which is the writer — i.e. the M-1
  mutant. A-3 (`:54`) attributes the defect to the architect draft only. Since the QA catalog remains
  on disk as the harness's specification, this should be noted so a future re-run against §3.1's
  definition does not reproduce the S-6 false positive.

### §3.3 — A traceability gap the fold created (MAJOR-2)

`§4.1` claims *"Zero orphans"* (`:252`). True for `US→HLR→LLR`. **Not true in the other direction:**
`LLR-B64-5.2` (`:132`) requires the lineage record to state ***"`C-41` as NOT CONSUMED — the id
remains free"***, and `AT-B64-10`'s subject set explicitly **excludes** C-41 (`:233`: *"`C-41` is NOT
in the set (not consumed)"*). So **operator ruling D-7's headline outcome has zero acceptance
coverage**, in a batch whose subject is acceptances that verify nothing. The same holds for
LLR-B64-5.1's *"and the C-35 rider"* clause — the rider has no id, so the census cannot see it.

**Required fold.** Add `C-41` to `AT-B64-10`'s set with the expectation `encoded == False` **and**
`registered-as-consumed == False`, and state its reddening mutation (mint a `C-41` declaration in any
destination → RED). Cost: one row. It converts a headline ruling from asserted to verified.

---

## §4 — DO THE CONTROLS EARN THEIR PLACE? (SPECIFIC-3)

### §4.1 — C-40: the "partial restatement" claim is CORRECT. I re-tested it independently.

The previous architect's assessment (`01-requirements-architect.md:216-243`) holds. I read the three
prior statements on disk rather than trusting the citation:

- **`dev-flow.md:99`** — *"every acceptance is non-vacuous … with the counterfactual shown (the AT RED
  on the pre-fix tree) … **No pass that cannot fail.**"*
- **`dev-flow.md:177`** — C-19, gate evidence includes *"the RED counterfactual"*.
- **`VERIFY.md:40-49`** — the complete mutation loop: inject → confirm red → **verify the mutation
  actually applied (a typo'd mutation also "fails," for the wrong reason)** → restore, closing with
  *"An assert that survives its own mutation is decoration."*

**The idea is stated three times already, and batch-63 produced six vacuous predicates anyway.** C-40's
`(Origin: …)` even reuses `VERIFY.md:47`'s parenthetical nearly verbatim. So the restatement finding
is not a quibble — it is measured.

**The novelty is the binding, and the drafted text does state it.** Verified in `:146`: authoring-time
rather than gate-exit ✓; per-predicate ✓; extended from `AT-NNN` to `LLR` clauses, `TC`s **and
probes** ✓; from "shown" to "executed, with the transcript pasted" ✓; and the static subject-naming
test (*"read the expression and ask which symbol in it the implementation could move"*) ✓ — which is
the one genuinely new sentence and the only clause that catches V-1..V-3 before a probe is written.

**The empirical case is strong and is the deciding factor.** `V-6` (`AT-172b`) is live on `main`, was
found by applying C-40, and is missed by C-10, C-31 **and** C-39 (QA §3.5; `01c` M-3 shows deleting
limb 1 drops the arm to `2/6`, losing V-6). A control that finds a real shipped defect no existing
control catches earns its id.

**"NOT orthogonal to C-35" — VERIFIED PRESENT, and the honesty is intact.** `:146` reads: *"**NOT
orthogonal to C-35**, and say so honestly: running the producer over a real input *does* catch the
round-trip-identity form of this defect; C-40's contribution over C-35 is that it applies where there
is no product transform to run."* This is A-11 discharged and it matches QA's instruction at
`01b:364-368` (*"do not claim C-40 is orthogonal to C-35 when it is not"*). **Good — keep it.**

**Where it does NOT earn its length.** `01c` §2 decomposed the 5 015 B:

| clause group | bytes | % | bought by the arms? |
|---|---|---|---|
| discrimination floor (header + limb 1 + PIN + limb 2 general + discharge) | **1 936** | 38.6 % | **yes** — and `0.80× C-39`, *inside* the R-c cap |
| named instances (i)/(ii) | 654 | 13.0 % | no (literal model) / yes (assisted) |
| RELATIONS | 1 039 | 20.7 % | **no** |
| ORIGIN narrative | 1 386 | 27.6 % | **no** |

**Verdict: C-40 earns its place as a control. V-FULL earns its length only on the relations +
worked-example axis, and the operator ruled that acceptable (D-9).** That ruling is defensible — the
1 693 B of relations are LLR-B64-1.3/-1.4, already approved, and `01c:298-305` shows V-TRIM-1's saving
costs the block its only self-demonstration (Origin S3, the `AT-172b` worked example), making C-40 the
**first** control in the repo without a worked instance. **But the spec must stop presenting the
question as open** (BLOCKER-4), and it should carry `01c` B-2's finding that the R-c check itself is
not like-for-like — it prices a 3-candidate absorbing control against a 1-candidate one and *"will
fire on every future absorbing control regardless of density."*

### §4.2 — C-42: earns its place, unqualified.

- **Distinct on the producer axis, verified.** C-32/C-37 govern the widget render path (geometry at
  `render_line`, colour at `render().spans`); C-42 governs document/export/source producers. The
  architect's working — *"apply C-32 to `"](" not in note`: the report has no painted surface and no
  compositor; C-32 has no purchase"* — is sound. **It was dropped from the normative doc (D-07),
  which is a documentation defect, not a novelty defect.**
- **It carries a live in-repo reproduction** (0/29 vs 29/29), which no other leg has.
- **Its cost lands in the right file.** `docs/engineering-rules.md` is 125 lines and in VCS; the R-c
  bloat risk is about the 59 KB global command, which C-42 does not touch. It is also the only leg a
  PR, CI, and diff review can see — which is why Inc-1 banks it first (`:263`), a sequencing call I
  endorse.
- **One gap:** C-42's novelty claim (*"extends C-32/C-37"*) has **no acceptance**. `AT-B64-06` tests
  mechanic-naming; `AT-B64-07` tests placement. Neither tests distinctness. Given `AT-B64-03` exists
  for exactly this purpose on C-40, the asymmetry should be named. **Major (MAJOR-3), not blocker** —
  the claim is true, it is merely unverified.

### §4.3 — The C-35 rider: earns its place; cancelling C-41 was right.

The ~70 % overlap finding (`01-requirements-architect.md:276`) is sound and the operator's D-7 ruling
against a *stated* alternative is exactly the decision hygiene this practice wants. Placement inside
C-35 at `:145` is correct — I verified C-35's bullet is the draft-time execution probe, and the rider's
delta (*execute the producer **and write the predicate against its pasted output***) is a genuine one
sentence wide. **The rider is the right shape.** What blocks is not the rider but what the conversion
silently deleted (BLOCKER-3) and the fact that its only load-bearing AT has never run (BLOCKER-1).

### §4.4 — The `VERIFY.md` extension: the strongest leg, and I would ship it first.

`AT-B64-09`'s three-test separation (`01b:548-577`) is the sharpest argument in the batch: the
pre-existing rule's own dichotomy classifies the 0/29 predicate as **GOOD**, its stated failure mode is
the **opposite direction** (false pass vs false fail), and the neighbouring mutation-test section is
structurally blind to a predicate that is red for the wrong reason. I read `VERIFY.md:34-49` directly
and confirm all three. `01c` §7 executed de-identification over the final 1 540 B text: **0
identifiers across 9 terms + 9 path regexes, two reddening mutations both confirmed to bite**, with a
non-emptiness guard. `[travels]` is earned. **No finding against this leg** beyond BLOCKER-2(b)'s
mislabel.

---

## §5 — MAJOR findings

| # | finding | cite |
|---|---|---|
| **MAJOR-1** | `AT-B64-10`'s subject set is implementation-shaped (limb 2); pre-batch RED rests **1/3** on `C-29`; the spec nowhere records C-29 as load-bearing | `:57`, `:233`; `01c:459-472`, B-5 |
| **MAJOR-2** | D-7's headline outcome (*`C-41` stays free*) and LLR-B64-5.1's rider clause have **zero acceptance coverage** | `:132`, `:233`, `:249` |
| **MAJOR-3** | C-42's `extends C-32/C-37` claim has no AT, and §C.3's supporting working was dropped (D-07) | `:169`, `:229-230` |
| **MAJOR-4** | The C-36 relation and its working dropped (D-01) — the rider now claims only a C-35 extension, and the C-36 delta is unstated | `:152` vs architect `:141`, `:260-266` |
| **MAJOR-5** | §G's *"one third the bytes"* alternative (D-08) dropped **at exactly §9.1**, where the operator must rule on length. D-9 was made against **two** stated trims, not three | `:370-372` vs architect `:452-456` |
| **MAJOR-6** | §G's alternative F-1 ruling and the consequent *"C-35's `(Origin: …)` is already in violation"* cleanup item dropped (D-09) | architect `:460-463` |
| **MAJOR-7** | §C.1's finding that the idea also pre-exists at `dev-flow.md:177` and `VERIFY.md:40-49` dropped (D-05); C-40 now claims to EXTEND the Certainty clause **alone**, understating the restatement it makes | `:146` |
| **MAJOR-8** | LLR-B64-1.5 kept OPTIONAL but the recommendation + drift argument dropped (D-06); the operator is asked to rule with the reasoning removed | `:120` |
| **MAJOR-9** | LLR-B64-2.2 silently narrows the forbidden class by dropping **"fixture"** (D-19) — material, since `chk.json` is precisely a `tests/` fixture name (§0 R-4) | `:122` vs architect `:103` |
| **MAJOR-10** | §6 drops the expected deltas for `VERIFY.md` and the lineage memory (D-10); 2 of 3 bounded-delta checks are unarmed, and §6 claims bounded-delta as one of *"three properties that make this a check rather than a log"* | `:287-291` |

---

## §6 — MINOR findings

1. **`59 259` vs `59 260`.** §6 records the measured baseline as `59 259 B` (`:282`); §9.1 computes
   *"6 340 B into **59 260 B** → +10.7 %"* (`:358`). The percentage is right; the base is off by one,
   in a batch whose rule is that a stated number is measured.
2. **Limb 1's unqualified invariance sentence** restates the refuted wording twice and is rescued only
   by the corollary; no arm evaluates it in isolation (§3.2). Suggested: *"…cannot gate it — see the
   corollary below."*
3. **QA §3.1's `subject(D)` definition is the M-1 mutant** and remains on disk as the harness spec;
   A-3 attributes the defect to the architect draft only (§3.2).
4. **`AT-B64-05` has no non-emptiness guard**, asymmetric with `AT-B64-08`, which `01c` §7 gave one.
5. **§4.1's traceability row** shows `*(cross-cutting)*` in the US column (`:250`) rather than naming
   `US-B64-1/-2/-4/-6`; the architect's note explaining the four-parent edge (`:86-89`) was dropped.
6. **D-15** — `R-TUI-097` / `REQUIREMENTS.md:4849` dropped from the §7.1 backlog carry; a future fixer
   of `AT-172b` needs the requirement that falsely claims coverage.
7. **D-16, D-17, D-18** — three executed QA discharges dropped: `AT-B64-01`'s second reddening
   mutation, `AT-B64-05`'s self-caught word-boundary defect, and the S-5/`TC-441` *"never shipped"*
   caveat (which matters: S-5 is 1 of 6 negative controls and is not a running test).
8. **D-11, D-20** — the *"reviewer can diff the pasted text against the POST file"* obligation, and the
   record that `dev-flow.md:202`'s `Textual` is normative rather than an Origin example.

---

## §7 — What would change this verdict

- **BLOCKER-1 falls** if `AT-B64-04` is executed against §3.2's rider bytes over the 8 occurrences with
  a reddening mutation pasted — or if the arm is honestly demoted to WEAK and `US-B64-2` is given a
  different load-bearing acceptance.
- **BLOCKER-2, -3, -5, -6 fall** on one revision: delete the two false "Unchanged" labels, and add
  amendment rows or retirement lines for D-01…D-20. This is bookkeeping, not redesign — perhaps two
  hours. **It is also the batch demonstrating the control it is encoding**, which is worth more than
  the rows.
- **BLOCKER-4 falls** when D-9 is recorded in `PLAN.md`/`state.json`, §9.1/§10.7 are closed against it,
  and `01c`'s corrections (889 B, −888 B, the run-1 harness scope, the executed arms) are folded in.
- **My C-40 length verdict would change** if the operator re-opened D-9. On the discrimination axis
  alone `01c` measured V-TRIM-1 at 6/6 · 0/6 · 1.70× with **zero** corpus members lost, and the hybrid
  keeping Origin S3 at 1.85×. I am not re-litigating a made ruling; I am recording that the arms
  price V-FULL's excess at **zero detection value**, and that this is what the spec must say.
- **My "C-42 earns its place" verdict would change** only if `~/.claude/skills/tui-design/SKILL.md`
  (unread by **all three** lanes — architect §10.5, `01c` B-6) turned out to state an overlapping rule.
  That is 5 minutes of reading and it is still not done.

---

## §8 — Evidence checklist (architect gate obligation)

| item | ✓/✗ | evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | zero-code surface honored — this review wrote one file; baselines re-verified §0; `shall`/`should` verified mechanically |
| ≥2 alternatives considered | ✓ | for each blocker a fold is specified **and** an alternative discharge (BLOCKER-1: execute **or** demote + re-assign the load-bearing AT; §7 records what would reverse the C-40 length verdict) |
| Recommendation tied to constraints | ✓ | severity assigned by whether the drop changes encoded text or disarms a gate, not by size |
| Risks listed | ✓ | §2 (6), §5 (10), §6 (8); §3.1 names the re-vacuation risk if C-29 is later removed |
| Cost / latency estimated where relevant | ✓ | reader cost measured, not estimated: 5 015 B / 2.07× C-39, decomposed 38.6 % detection vs 61.4 % relations+provenance (`01c` §2) |
| Diagram included when flow is non-trivial | ✗ | deliberate. This is a document audit; the union tally (§1.1) and the drop table (§1.2) carry the structure a diagram would |
| What would change the recommendation | ✓ | §7 |
| Two-layer requirements | ✓ **with declared N/A** | behavioral chain audited row-by-row in §3; the `TC` leg's N/A argument (`01b` §7, architect §A.0) reviewed and **accepted** — I looked for a white-box layer independently and agree none exists. **But §3.3 records that the reverse direction is not clean:** two LLR clauses have no acceptance, so "zero orphans" at `:252` is true only downward |

**Reviewer's own C-40 self-application.** My new predicate is *"union item `X` is absent from the
consolidated document."* Declared subject = the consolidated document's bytes; it is in the expression
— every row of §1.2 is a `grep` over that file, and the counts are reported per-lane so a false zero
is visible against a non-zero source count. Reddening mutation, executed: the same harness returns
**non-zero** for `C-36` (2), `startswith` (1), `fixture` (3) and `SKILL.md` (1) in the consolidated,
so the scan is not uniformly blind — it distinguishes present from absent on the same file. Not inert.

---

## §9 — Verdict

**BLOCKED — 6 blockers, 10 majors, 8 minors.**

None of the blockers challenges the batch's design. The controls are the right controls, the operator's
rulings are sound, the `VERIFY.md` leg is excellent, and C-40 found a live defect on `main` that three
existing controls miss. **What blocks is that the fold did to itself exactly what instance (ii) of
C-40 forbids — and then said it hadn't.** Fix the record and this is ready.

The batch's own thesis survives the audit intact, and one datum makes the case better than any
argument in the spec: **C-40 has now caught its own author five times** — the architect's limb-1
wording (A-3), the orchestrator's id census (A-8), V-6 itself, QA's run-1 harness (`01c` §4.1), and
this fold's twenty dropped observables. A control with that hit rate inside a single batch is not a
restatement, whatever its overlap with `dev-flow.md:99`.
