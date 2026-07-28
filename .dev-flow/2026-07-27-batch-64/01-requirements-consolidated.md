# batch-64 — Requirements, CONSOLIDATED (Phase 1, fold iteration 3 — §3 FROZEN)

> **NORMATIVE.** This document supersedes `01-requirements-architect.md` and `01b-qa-catalog.md` as
> the batch spec. Both remain on disk so the reversal stays traceable; their executed transcripts are
> **cited, not re-run**, except where §0 re-derives a number this fold changes.

> **BLUF — three things moved, and one of them is a reversal of my own recommendation.**
> **(1) `C-41` is CANCELLED as a control.** P-3 leg 1 becomes a **rider on the existing C-35**, per
> operator ruling against the alternative I surfaced. **The id `C-41` is NOT consumed — it stays
> free.** Encoded controls this batch are exactly **{C-40, C-42} + the C-35 rider**.
> **(2) The corpus is SIX, not five.** QA found `V-6` — a tautology live on `main` — by *executing*
> the candidate control rather than reading batch-63's summaries. I re-derived it independently (§0).
> **(3) My own C-40 limb-1 wording FAILS QA's executed negative arm and is amended here.** I wrote
> *"name the component under test"*; applied to `AT-174b` that reads as the writer, which is absent,
> producing the exact false positive QA's S-6 trap was built to catch. Corrected to *"the subject the
> predicate itself declares"*, plus a PIN corollary that turns the near-miss into a useful ruling.
>
> Fourteen amendments in §1. **Nothing in this fold is carried: every number it changes was
> re-derived from disk (§0), because batch-63's most expensive lesson is that the fold reintroduces
> the defect class.** Two items could not be discharged (§10).

> ## FOLD 2 (Phase-2 discharge) — read this first
>
> **Phase 2 came back BLOCKED in two of three lanes, and the headline is that fold 1 did to itself
> exactly what C-40 instance (ii) forbids: it dropped 20 of 163 union observables and printed a
> preservation line it had not earned.** Sixteen further amendments (§1.1), all discharged, plus the
> structural fix: **`01d-union-ledger.md`** now dispositions every union item three ways with no
> fourth category. **The cause was that fold 1 REWROTE where it should have AMENDED; from here this
> document is amended in place.**
>
> **What the reviews changed that fold 1 got wrong, in order of consequence.** (1) **Layer A `N/A` is
> WITHDRAWN** — three parties declared it and the QA reviewer refuted it by *building the layer*; four
> `shall` clauses had no observer, and four placement predicates now discriminate a correct insert
> from a mis-placed one where both existing ATs are blind (§4.5). (2) **The positive corpus was
> under-drawn by three**, one of them one line above a predicate a lane had quoted — arms restated
> **8/9 full-domain · 9/9 CI-only** (§4.2). (3) **`AT-B64-04` had never been executed** and is the
> sole load-bearing acceptance for US-B64-2; now **8/8 · 9/9** with two mutations biting at 6/9 (§4.3)
> — and running it found the *enumeration itself* under-drawn by one. (4) **`AT-B64-10`'s set was
> implementation-shaped** — C-40 limb 2 violated by the fold closing limb-2 defects — re-derived from
> the rule, now with two independent RED carriers (§4.4). (5) **C-40's mandated mutation was
> unbounded**; the source draft's fourth step, `restore`, was lost in transcription and is restored
> with a blast-radius bound.
>
> **Honest residue: D-9 was ruled at 2.07× and the review-mandated discharges took C-40 to 2.56×.**
> Every byte is decomposed at §9.1 and none is elective, but re-affirming the ruling at the new figure
> is the operator's call. **And this control has now caught its own authors six times inside one
> batch** — the sixth being this fold's own `re.MULTILINE` census defect (§4.4), found because the
> result was *implausible*, which is the corollary the same fold was restoring.

> ## FOLD 3 (the soft cap) — FREEZE, then measure. Read this before any figure in this document.
>
> **The root cause of three failed iterations is that the acceptance layer has been measuring a
> moving target.** Every fold changed the normative text; every arm figure was measured against that
> text; each fold silently invalidated the prior measurements. `02c-discharge-audit.md` proved it
> mechanically: `AT-B64-04`'s discharge (§4.3) was executed against the rider's **fold-1 890 B body**
> while the shipping body is **1 975 B**, and its two mutation clauses — the prefix guard (block
> offset 1241) and the character-list clause (offset 245) — are **distinct spans ~1 000 B apart**, so
> the claimed *"delete the character-list clause → 6/9, losing #5/#7/#9"* is **impossible against the
> shipping bytes**. That is `C-40` limb 1 committed by the discharge of `C-40` limb 1's own blocker.
>
> **So this fold measures NOTHING. It freezes the text.** §3 now opens with **§3.0 — FROZEN PASTE
> MANIFEST**: per destination file, the paste block's byte count and its SHA256, plus one hash over
> the concatenation. **§3 is FROZEN** — any later edit to a paste block invalidates every measurement
> keyed to that block's hash and requires re-measurement. A separate measurement pass runs **after**
> this fold, against these frozen bytes, and **not concurrently with it** — which is the structural
> fix for the read/write race `01d` §M-1 disclosed and that produced `U-1`/`U-2`/`U-3`(b).
>
> **Every arm figure now in this document is therefore marked `STALE — pending re-measure against the
> frozen manifest` (A-40).** They are neither deleted nor restated as current. Twelve amendments in
> §1.2, of which four correct numbers this document asserted wrongly: §6's expected delta did not sum
> to its own total, and the gap is exactly the **phantom 889 B fold-1 rider that is not on disk**;
> §3.2's prose still priced the rider body at *"~890 B"* against **1 975 B**; the negative arm was
> reported with no domain named, and under the CI-inclusive domain **`A-23` itself makes normative**
> it is **`1/6`, not `0/6`**; and §3 carried paste text for **four of the six edited files**, leaving
> `D-11`'s just-restored cross-reference obligation undischargeable for the two legs that get no PR,
> no CI and no diff review.

---

## §0 — Numbers this fold CHANGES, re-derived (C-39 · C-40 applied to the fold itself)

The coordinator verified three of QA's claims. I re-derived the four that this document's normative
content depends on. **A carried number is re-derived, not copied** — including from a lane I trust.

| # | claim being changed | my independent derivation | verdict |
|---|---|---|---|
| **R-1** | `V-6` (`AT-172b`) is a tautology | `tests/test_report_document_bytes.py:217` asserts `raw == rs.document_bytes(raw.decode("utf-8"))`; `report_service.py:406` defines `document_bytes(text) -> text.encode("utf-8")`. Executed the predicate over three writer states: `LF pre-fix (text mode) -> True` · `CRLF pre-fix (text mode) -> True` · `LF post-fix (byte mode) -> True`. **RED cases over the writer mutation: 0.** | **CONFIRMED.** Independent of QA's harness. |
| **R-2** | `C-29` is encoded but unregistered | `docs/engineering-rules.md:64` = `## C-29 — two-axis geometry-budget measurement (Phase 1, extends C-23)`. Word-boundary count of `C-29` in the lineage memory: **0**. | **CONFIRMED. 1 encoded / 0 registered.** |
| **R-3** | the encoded id space is `C-10 … C-39`, not `C-1 … C-39` | Declaration-shaped grep per destination. `dev-flow.md`: `C-10 11 12 14 15 15.1 16 17 18 19 20 21 24 25 26 27 31 33 35 36 39`. `docs/engineering-rules.md` (`##` headings): `C-13 13.1 22 23 28 29 30 32 34 37 38`. `VERIFY.md`: **0**. Union = **`C-10 … C-39` contiguous**, plus `C-13.1`/`C-15.1`. | **CONFIRMED. `PLAN.md:73-74` is REFUTED** — see A-8. |
| **R-4** | `chk.json` is/is not a project identifier (decides the rider's stack-free scope) | `grep -rn "chk.json" s19_app/ tests/` → **0 hits in `s19_app/`, 4 in `tests/`** as a fixture filename. | **Borderline.** Resolved by construction, not by argument — see A-5 / §3.2. |

**C-40 applied to this table.** Subject = *the numbers this fold asserts*; each row's expression is an
executed command over the current tree, so the subject is in the expression. Reddening mutation for
R-1: run the predicate against a writer that does not round-trip — the only such input is invalid
UTF-8, which is why it is a tautology; the mutation exists and confirms the classification.

**Numbers I did NOT re-derive, and am therefore citing rather than asserting:** the `0/29 vs 29/29`
snapshot reproduction and the P-3 occurrence enumeration. **They are not re-stated as my
measurements.**

**RE-ATTRIBUTION (A-29) — fold 1 cited three figures as measurements of C-40, and they are not.**
Run 1's `c40_arms.py` **never opens any C-40 text**: its `6/6` · `0/6` · `4/6` are *"invariant under
every possible wording of C-40"*, valid as **corpus** measurements and structurally incapable of
measuring a variant. The variant-sensitive figures come from `01c`'s second harness (M-1…M-4, which
`M-4` proves reads the bytes: anchor corruption takes it `6/6 → 2/6`) and from the Phase-2 QA
reviewer's independent `rq_arms.py` (`M-D`: corrupting the `**LIMB n` markers takes it `6/6 → 0/6`).
**Fold 1's §10.3 said *"if any of those five is wrong, this document inherits the error"*; one was
wrong in exactly that way** — it measured something other than what it was cited for. The arm figures
that stand in this document are §4.2's, re-executed here.

---

## §1 — Amendment table (Before → After)

| # | item | BEFORE | AFTER | source / evidence |
|---|---|---|---|---|
| **A-1** | **P-3 leg 1's form** | a new global control **C-41**, drafted at ~2 000 B | a **rider appended to the existing C-35 block** in `~/.claude/commands/dev-flow.md`, ~700 B. **`C-41` is NOT consumed and stays free.** | Operator ruling, taken against the alternative I stated in `01-requirements-architect.md` §C.2 (*"~70 % C-35 … the cheaper form"*) |
| **A-2** | **the vacuous corpus** | five (batch-63's postmortem count) | **six** — `V-6` = `AT-172b`, `tests/test_report_document_bytes.py:208-221`, live on `main` | QA §1.6; re-derived at §0 R-1. Positive arm expected **6/6**, negative arm **0/6** |
| **A-3** | **C-40 limb 1's key** | *"name the **component under test** and confirm that component appears in the predicate's own expression"* (my draft) | *"name the subject **the predicate itself declares** …"* **+ a PIN corollary** | **My draft failed QA's executed negative arm.** Working at §2.1 |
| **A-4** | **P-6/P-7's structural role in C-40** | "named examples inside C-40" | **LIMB 2 of the rule, with those two as its named instances.** The absorption is unchanged; its *status* is promoted from illustration to normative clause | QA §3.3: one-limb C-40 flags **4/6**, missing exactly `AT-165` and `AT-193b` |
| **A-5** | **AT-B64-05's scope + term list** | *"the encoded global text contains no `markdown-it`, `&#160;`, `Rich`, `Textual`, `SVG`, `AST`"* | scoped to **the added rider block's normative body**, excluding its `(Measured: …)` citation; **`AST` REMOVED** from the term list | My F-1 (`Textual` ×3, `AST` ×1 pre-existing) + QA §9.5 (`dev-flow.md:57` uses `AST` as a stack-free technique) |
| **A-6** | **AT-B64-10's subject set** | "every encoded control id" | **{C-29, C-40, C-42}**, with `.dev-flow/**` **excluded** from both directions | My F-2 (green by construction) + QA §9.4 (RED pre-batch on 9 ids). `C-29` closed here; `C-1…C-9` carried |
| **A-7** | **the P-3 occurrence set** | *"~9 occurrences across batches 61-63"* | **8 occurrences across batches 60-63**, enumerated | QA §AT-B64-04 table. The brief's own number was wrong |
| **A-8** | **`PLAN.md:73-74`'s id census** | *"`C-1 … C-39` contiguous across the union"* | **REFUTED. The encoded space is `C-10 … C-39`.** `C-2 … C-9` have no id-bearing text anywhere; the apparent hits are architecture-diagram node labels and a ruff rule code | QA §AT-B64-10; re-derived at §0 R-3. **Recorded as the orchestrator's own instance of this batch's defect class: the RC-1 census counted mentions, not encodings** |
| **A-9** | **C-42's mechanic count** | my draft: **six** bullets · `01-requirements.md:92`: *"four instances"* · `BACKLOG.md:37` + QA: **five** | **FIVE mechanics** is normative. My draft renders mechanic 1 as two bullets (token-types, then entity-spoofing) — a **presentation split inside one mechanic, not a sixth**. Stated so AT-B64-06's 5-row table does not false-fail on a bullet count | QA §AT-B64-06 |
| **A-10** | **AT-B64-11's status** | an acceptance test | **bookkeeping, not acceptance.** Labelled as such in the traceability table; **not counted toward any story** | QA §5: *"a hash proves a change, never the right one"* |
| **A-11** | **C-40's discrimination claim** | drafted as DISTINCT from C-10/C-31/C-39 | unchanged for those three, **plus an explicit statement that C-40 is NOT orthogonal to C-35** — C-35 does catch `V-6` | QA §AT-B64-03: the C-35 row went RED, which is the arm working |
| **A-12** | **P-3 totals in encoded text** | — | the encoded text carries **no occurrence total**; it enumerates | my §H.1 finding: three registers disagree (`~7th` / `~9` / `8+`) |
| **A-13** | **encoded-control list + increment plan** | 3 controls, 5 increments | **2 controls + 1 rider**, 5 increments; `dev-flow.md` now takes **C-40 + the C-35 rider** in one atomic write | consequence of A-1 |
| **A-14** | **US-B64-6's scope** | register C-40/C-41/C-42 | register **C-40, C-42**, the C-35 rider, **and C-29** (cheap, in-scope reverse-direction miss) | §0 R-2 |

### §1.1 — Fold iteration 2 (Phase-2 discharge). Sixteen further amendments.

> **The structural finding, stated first because it indicts this document.** The architect review
> audited fold 1 against the SOURCE lanes rather than against §1's table and found **163 union items ·
> 136 carried · 7 retired with reason · 20 DROPPED with no retirement line**, and **two false
> "Unchanged" labels** (§3.3 and §3.4, both changed, one of them changing a normative LLR).
> **The document encoding *"a consolidation that drops observables … an id-range table is a container,
> not evidence of preservation"* dropped twenty observables and printed a preservation line it had not
> earned.** The cause was structural — fold 1 **rewrote** where it should have **amended** — so the
> repair is structural: **`01d-union-ledger.md` now carries one row per union item with a
> three-way disposition and no fourth category.** From this fold on, this document is amended in
> place; nothing is regenerated.

| # | item | BEFORE | AFTER | source |
|---|---|---|---|---|
| **A-15** | the 20 dropped observables | dropped silently | **every one dispositioned** in `01d-union-ledger.md` as `CARRIED` / `RETIRED` / `RESTORED-THIS-FOLD`; D-01…D-04 restored into the rider's normative body, D-12/D-13/D-14 restored as §4.0/§9/§9.2, the rest restored as prose | arch §1.2, BLOCKER-3/-5/-6 |
| **A-16** | §3.3 and §3.4's *"Unchanged"* labels | asserted | **DELETED.** Executed diffs prove both changed: C-42's mechanic 4 moved `0 of 19` → **`0 of 29`** (live in-repo reproduction), and §3.4 **added a paragraph** that rewrote LLR-B64-4.3. Both now carry amendment rows | arch BLOCKER-2 |
| **A-17** | `AT-B64-04` | never executed against any text; not disclosed as un-run | **EXECUTED** against the rider's 890 B — **8/8 GREEN** as specified, **9/9** over the corrected enumeration, with **two** reddening mutations biting at **6/9** each (§4.3) | arch BLOCKER-1 |
| **A-18** | the P-3 enumeration | 8 occurrences | **9.** Executing AT-B64-04 found the enumeration under-drawn: the `startswith("| 0x00001")` prefix guard (4 rows where 400 were emitted) is absent from QA's 8 — the reviewer flagged it as *"occurrence #?"*, unable to place it. **The 8 was itself a hand-shaped set** | §4.3, arch BLOCKER-1 |
| **A-19** | `AT-B64-10`'s subject set | `{C-29, C-40, C-42}` — implementation-shaped, C-40 limb 2 violated by the fold closing limb-2 defects; pre-batch RED rested **1/3** on C-29 | **RE-DERIVED FROM THE RULE**: *every encoded control id* = **32** ids (union of **three** declaration shapes) ∪ `{C-40, C-42}` ∪ `{C-41: expected absent}`. Pre-batch RED now has **two independent carriers** (`C-29` encoded-unregistered **and** `C-1` registered-unencoded), so dropping C-29 no longer returns it green (§4.4) | arch MAJOR-1, qa m-1/m-2 |
| **A-20** | `C-41`-stays-free (D-7's headline) | **zero acceptance coverage** — explicitly excluded from the census | **covered**: `C-41` enters the subject set with expectation `encoded == False ∧ registered-as-consumed == False`; reddening mutation stated and confirmed | arch MAJOR-2 |
| **A-21** | the positive corpus | 6 members, arm `6/6` | **9 members.** `V-7` (`test_flow_report_service.py:496`) is the same round-trip tautology as V-6 **one line above** the predicate harvested as sound control S-3; `V-8` (`:221`); `V-9` (a false counterfactual in batch-63's **validation record**). Arms re-executed: **8/9 full-domain, 9/9 CI-only** (§4.2). **The control got stronger; the acceptance's number was wrong** | qa B-1 |
| **A-22** | the negative controls | *"six sound controls"* | **5/6 sound, disclosed.** `S-3` is **CI-dead** (invariant on `ubuntu-latest` — the property batch-63's own test header lists among its *refuted* vacuous acceptances); `S-5` is **not a shipped test**; `S-6`'s second assert is dead by entailment behind a false docstring. `0/6` survives under the amended keying | qa M-1, m-3, M-4 |
| **A-23** | C-40 limb 1 | semantic (*invariant under the change*) and syntactic (*subject appears in the expression*) stated as equivalent | **the divergence is ruled**: they disagree on a live predicate (`S-3`), so the block now states that **the semantic test governs and its domain includes the platform**, plus a *"see the corollary below"* bridge so the invariance sentence is never read in isolation | qa M-2, arch §3.2/MINOR-2 |
| **A-24** | **Layer A `N/A`** | declared N/A by both lanes and accepted by the reviewer | **REFUTED BY EXECUTION.** Four **placement predicates** built and run: each is **RED pre-batch, GREEN on a correct insert, RED on a mis-placed insert**, while `AT-B64-08`/`AT-B64-09` return **identical** values on both (§4.5). Four `shall` clauses had no observer. **Added; explicitly NOT minted as `TC` ids** | qa B-2 |
| **A-25** | C-40's DISCHARGE | mandates mutation *execution* with **no blast-radius bound** — zero `restore`/`revert`/`scratch`/`worktree` across all four paste blocks | **bounded.** `BACKLOG.md:40`'s source draft states the loop in **four** steps ending in `restore`; fold 1 encoded **three** — transcription loss. The fourth is restored, with the where-it-runs bound (~200 B) | sec F1 |
| **A-26** | POST-hash rows | all in Inc-4, three increments after the first out-of-VCS write | **moved into the increment that edits each file**, so LLR-B64-6.3's blocking predicate fires at its own boundary | sec F3 |
| **A-27** | operator ruling **D-9** | presented as **open** (*"the one open item that can change the deliverable's text"*) | **SETTLED and recorded: C-40 ships as V-FULL at 2.07×, R-c breach accepted on arm 2.** §9.1/§10.7 closed against it | arch BLOCKER-4 |
| **A-28** | three stale numbers | rider body *"~890 B"*; trim (a) *"−~1 400 B"*; base *"59 260 B"* | **889 B · −888 B · 59 259 B.** Trim (a) was mispriced **1.58×** — it charged the whole Origin (1 386 B) while the trim keeps its first two sentences (497 B). **The third estimate in §9.1 to miss** | `01c`, arch BLOCKER-4, qa m-4, arch MINOR-1 |
| **A-29** | §0's citation of `6/6`/`0/6`/`4/6` | cited as measurements **of C-40** | **re-attributed.** Run-1's `c40_arms.py` **never opens any C-40 text** — its results are invariant under every wording, valid as **corpus** measurements only. The variant-sensitive figures come from `01c`'s second harness and the QA reviewer's independent `rq_arms.py` | arch BLOCKER-4 |
| **A-30** | `SKILL.md` unread (carried by all three lanes) | open | **CLOSED.** The QA reviewer read it: `emitted=0 &#160;=0 entity=0 escap=0 producer=0 snapshot=0 export=0`; the two `SVG` hits concern capturing an artifact, not the form a predicate asserts against. **No overlap; the `VERIFY.md` leg is not redundant** | qa §3.9 |

**Not amended — surviving unchanged, and this claim is now backed by executed diffs (A-16's lesson):**
C-42's five mechanics and their discharges; the `VERIFY.md` extension's text with `[travels]`
**retained**; the Inc-1-first ordering; the R-d argument. **`Layer A N/A` is NO LONGER in this list —
it was in fold 1's and it was wrong (A-24).**

### §1.2 — Fold iteration 3 (the soft cap). Twelve amendments, and the fold measures nothing.

> **The operator's ruling for this fold is `freeze-then-measure`.** Fold 3's deliverable is **§3.0**,
> the frozen paste manifest. It does **not** re-execute an arm, re-derive the corpus, or touch a
> destination file. Every measurement in this document is keyed to a paste block whose bytes were
> changing under it; the manifest is what converts *"measured against the shipping bytes"* from an
> assertion into a **provable** claim, which is the structural fix for the defect that cost three
> iterations. Source: `02c-discharge-audit.md`, verdict `DISCHARGED-WITH-FOLDS` — 38 source findings,
> 31 genuinely closed, 4 properly carried, **3 not closed**, plus 3 new blocker-grade findings.

| # | item | BEFORE | AFTER | source |
|---|---|---|---|---|
| **A-31** | **§3's status** | mutable prose; four folds edited it and every arm figure silently re-keyed | **FROZEN.** New **§3.0** records, per destination file, the paste block's byte count and SHA256 plus a concatenation hash. Normative clause: *any later edit to a paste block invalidates every measurement keyed to its hash and requires re-measurement* | audit §3.4 / §10 — *"the fold's discharge of `AT-B64-04` against bytes that no longer exist"* |
| **A-32** | **§3 coverage** | paste text for **4 of the 6** edited files | **§3.5 added — the lineage-memory entry** (`LLR-B64-5.1/5.2/5.3`). Without it `D-11`'s obligation is undischargeable for the out-of-VCS leg with no PR, no CI and no diff | audit §5.2 (F-4) |
| **A-33** | **§3 coverage** | `.dev-flow/BACKLOG.md` had no paste text | **§3.6 added — the reconciliation text**: footer replacement (`LLR-B64-5.4`), items-shipped lines, new carries, header refresh. Segmented with explicit `⟪REPLACES …⟫` anchors because this destination takes **four spot edits, not one contiguous insert** | audit §5.2 (F-4) |
| **A-34** | §6's `dev-flow.md` expected delta | *"**+8 630** — C-40 **6 219 B** … plus **+1 522 B** lengthening `:145` in place (rider 2 411 B less the 889 B fold-1 body it replaces)"* — `6 219 + 1 522 = 7 741 ≠ 8 630` | **corrected to `6 219 + 2 411`.** There is no *"889 B fold-1 body"* on disk: `dev-flow.md:145` is 1 774 B and contains no rider. The subtraction was against fold 1's **plan**, not against the file. **The line terminator is now named as its own term** — see A-35 | audit §5.3 (**FINDING C**, F-1) |
| **A-35** | §6's expected-delta table | 3 rows (`dev-flow.md`, `VERIFY.md`, lineage), two of them `~`-estimates, none traceable to a block | **6 rows — one per edited file — every Δbytes re-derived from §3.0's frozen block sizes, with line-terminator/framing bytes named as separate terms rather than absorbed.** Nothing in the table is carried | audit §5.3 + §5.2; `C-39` |
| **A-36** | §3.2's prose | *"Rider normative body length: **~890 B**"* — wrong by **2.2×** against its own fenced block twelve lines above | **1 975 B** (**1 976 B** if the single space before `(Measured:` is counted; the ±1 is that space and nothing else). Derived from §3.0's frozen §3.2 block by splitting at `(Measured:` — `1 975 + 1 + 435 = 2 411` | audit §3.4 / §6 `qa m-4` **regressed** (F-2) |
| **A-37** | the negative arm | reported **`0/6`** with no domain named, in three places | **stated WITH its domain, because the domain is what makes it correct.** Under the CI-inclusive domain `A-23` makes normative: **`1/6`** (`S-3` flagged, a **true** positive — `S-3` is inert on `ubuntu-latest`). Under the full `{LF, CRLF}` domain: `0/6`. Reclassifying `S-3` out of the control group gives **`0/5`**, a figure that appeared **zero times** in this document. **All three marked STALE per A-40** | `02b-trimc-measurement.md` §0(4)/§7; audit §3.3 (**FINDING A**, F-3) |
| **A-38** | **`LLR-B64-5.4`** | **no observer** — `AT-B64-10` excludes `.dev-flow/**` from both directions by `A-6`, so nothing observed the `BACKLOG.md` footer clause | **observer added: `PP-5`** (§4.5), a footer-id-range predicate over `.dev-flow/BACKLOG.md:143-144`. ⚠ **SPECIFIED, NOT YET EXECUTED — an open `C-40` debt**, discharged by the measurement pass / Inc-4 and stated as a debt rather than presented as run | audit §5.1 |
| **A-39** | **operator ruling `D-10`** | absent. §9.1 asked the operator to re-affirm `D-9` at 2.56× and §10 item 1 carried it as *"the one open item that can still change shipped text"* | **SETTLED and recorded, the way `D-9` was (A-27): C-40 ships as V-FULL at 2.56×**, re-affirmed on `02b-trimc-measurement.md`'s evidence. §10 item 1 closes. ⚠ **Id collision disclosed:** operator ruling **`D-10`** is a different register from union-ledger restoration **`D-10`** (*expected deltas, all three*) | operator ruling `D-10`, 2026-07-27; `02b` §3/§3.1/§5 |
| **A-40** | every arm figure in this document | printed as current | **marked `STALE — pending re-measure against the frozen manifest`** — normatively at the head of §4 and per-row in §4's AT table. Not deleted, not restated as current. The measurement pass replaces them | audit §3.4; the moving-target root cause |
| **A-41** | **`01d` §U-3** | *"two lane observations dropped and in no restoration set"* — both presented as standing | **`U-3`(b) is DISCHARGED**, not open: §10.2's first bullet quotes `subject(D)`, cites `01b-qa-catalog.md:218-220`, and states the defect was in **both** lanes. **Only `U-3`(a) stands** (`grep "can it go RED"` → 0; `grep "naive"` → 0). `U-3`(b) was closed by the same +32 063 B that closed `U-2`; the read/write-race correction was applied to `U-2`/`U-1` and not to `U-3`, which was snapshotted under the identical condition | audit §1.4 |
| **A-42** | document hygiene, four items | line 1 read *"fold iteration **1**"* while §1.1 was fold 2; §9 opened with an **empty table header + separator** rendering as a blank table; §4.1.1's HLR-B64-6 row printed `*(cross-cutting)*` beside the four named parents **which the same paragraph says it no longer does**; and that row's LLR range read `6.1 – 6.3` while `LLR-B64-6.4` exists in §2.3 | **title → fold iteration 3**; empty §9 header removed; the `*(cross-cutting)*` gloss deleted; range corrected to **`6.1 – 6.4`**. **§9's section ordering (9.1 after 9.2/9.3) is NOT reordered** — a reader note is added instead, because moving a section breaks every `§9.x` cross-reference across five artifacts for a cosmetic gain | audit §1.3, §5.4 |

**Not amended, and the diff was executed before this sentence was written** (fold 1 printed two false
*"Unchanged"* labels — A-16): the four pre-existing paste blocks **§3.1, §3.2, §3.3, §3.4** are
**byte-identical to their fold-2 state** — confirmed by extracting each fence by byte offset and
hashing it before and after this fold's edits, and the four hashes in §3.0 are that output. **A-36
changes §3.2's surrounding *prose*, not its fenced block.**

---

## §2 — Requirements register (corrected)

**Convention.** IEEE 830 + EARS. `shall` only inside an HLR/LLR statement; `should` only in
informative text.

### §2.1 — HLR register

| HLR | parent US | statement | Δ |
|---|---|---|---|
| **HLR-B64-1** | US-B64-1 | The global `/dev-flow` command **shall** carry a Phase-1 control, identified `C-40`, requiring every acceptance-bearing predicate to (i) name the subject **the predicate itself declares** and confirm that subject appears in the predicate's expression, and (ii) draw any set it quantifies over from the **rule** it states rather than from the implementation it certifies — and **shall** require the reddening mutation for both limbs to be executed and its transcript recorded. | limb 1 re-keyed (A-3); limb 2 promoted (A-4) |
| **HLR-B64-2** | US-B64-2 | The existing `C-35` block in the global `/dev-flow` command **shall** carry a rider stating that executing the producer is not sufficient unless the predicate is then written against the producer's actual emitted output, and the rider's normative body **shall** be free of stack-specific identifiers. | **rewritten** — no new control (A-1) |
| **HLR-B64-3** | US-B64-3 | `docs/engineering-rules.md` **shall** carry a control, identified `C-42`, declaring itself an extension of C-32 and C-37 and naming five emitted-form mechanics of this project's markup, export, and source-inspection stack. | count fixed to five (A-9) |
| **HLR-B64-4** | US-B64-4 | The `tui-design` skill's `VERIFY.md` **shall** state, within its existing `## Pin the truth, not a string  [travels]` section, that pinning a runtime value is necessary but not sufficient and that the value **shall** be pinned in the form its producer emits — in terms that hold for any terminal-UI project. | unchanged |
| **HLR-B64-5** | US-B64-6 | The canonical control-lineage record **shall** register `C-40`, `C-42`, the `C-35` rider, **and `C-29`**, and **shall** record P-6 and P-7 as ABSORBED into C-40 and P-3 as DECOMPOSED with `C-41` explicitly noted as **not consumed**. | +C-29, +the free-id note (A-14, A-1) |
| **HLR-B64-6** | US-B64-1, -2, -4, -6 (cross-cutting) | **When** this batch modifies a file that is not under version control, the batch artifacts **shall** record that file's line count, byte count, and SHA256 before and after, plus the path of a pre-edit backup. | unchanged; status demoted to bookkeeping (A-10) |

### §2.2 — The limb-1 amendment, with the working (A-3)

**This is the fold catching its own author, so the working is shown rather than asserted.**

Apply each wording to QA's negative-control S-6 — `AT-174b`,
`sum(_line_bytes(b) for b in partition) == _line_bytes(whole)`
(`tests/test_report_document_bytes.py:241-266`) — which is **sound** despite the writer being absent:

| wording | what it resolves "the subject" to for S-6 | in the expression? | verdict |
|---|---|---|---|
| **my draft:** *"the component under test"* | the batch's change → **the writer** | ✗ | **FLAG → false positive.** Matches QA's executed mutant exactly: `false positives 1/6 -> RED` (§3.4) |
| **amended:** *"the subject the predicate itself declares"* | S-6 declares `_line_bytes`'s `+1` convention | ✓ | no flag → **correct** |
| **amended, on V-3** (`_line_bytes == len(report_bytes)+1`) | declares *"the writer emits bytes, not translated text"* | ✗ | **FLAG → correct** |

**The PIN corollary, and why it is worth its line.** The amended wording alone merely *exempts* S-6.
The useful ruling is the one batch-63 actually reached: when a predicate's declared subject is **not**
the subject of the change it is offered as the gate for, it is a **regression pin, not a gate**, and
must be labelled so. Precedent on disk:
`.dev-flow/2026-07-26-batch-63/01-requirements-rescoped-consolidated.md:285` —
*"`AT-174` | **PIN, not a gate.**"* The corollary converts a would-be false positive into a
classification the reviewer can act on.

### §2.3 — LLR register

| LLR | parent | statement | lands in |
|---|---|---|---|
| **LLR-B64-1.1** | HLR-B64-1 | The C-40 block **shall** be inserted as one bullet in `### Phase 1 — Requirements engineering`, after the C-39 bullet and before the `Project-specific UI-geometry gates` pointer. | `~/.claude/commands/dev-flow.md` (between the bullets at `:147` and `:148` pre-edit) |
| **LLR-B64-1.2** | HLR-B64-1 | C-40 **shall** state limb 1 keyed on the predicate's **declared** subject, and **shall** carry the corollary that a declared subject differing from the change's subject makes the predicate a labelled PIN. | same block |
| **LLR-B64-1.3** | HLR-B64-1 | C-40 **shall** state limb 2 as a normative clause with its two named instances (positive-control-shaped-to-the-implementation; consolidation-that-drops-observables). | same block |
| **LLR-B64-1.4** | HLR-B64-1 | C-40 **shall** state its DISTINCT-from relation to C-10, C-31, C-39, its EXTENDS relation to the `## Objective exit criteria` *Certainty* clause, **and** that it is **not orthogonal to C-35**. | same block |
| **LLR-B64-1.5** | HLR-B64-1 | *(OPTIONAL — operator call)* The *Certainty* clause **shall** gain a parenthetical cross-reference to C-40. | `~/.claude/commands/dev-flow.md:99` |
| **LLR-B64-2.1** | HLR-B64-2 | The rider **shall** be inserted **inside the existing C-35 bullet**, immediately before its `(Origin: …)` parenthetical, in the house `**Rider — …:**` form used by C-36 and C-39. | `~/.claude/commands/dev-flow.md:145` |
| **LLR-B64-2.2** | HLR-B64-2 | The rider's **normative body** — its rule sentence, discharge, and placement clause, i.e. the rider excluding its `(Measured: …)` citation — **shall** contain none of `markdown-it`, `&#160;`, `Rich`, `Textual`, `SVG`, or any s19_app module, function, class, **or fixture** identifier. **`AST` is not a forbidden term** (`dev-flow.md:57` already uses it as a stack-free technique inside C-31). | same |
| **LLR-B64-2.3** | HLR-B64-2 | The rider **shall** state that stack-specific emitted-form traps belong in the project's `docs/engineering-rules.md`. | same |
| **LLR-B64-3.1** | HLR-B64-3 | The C-42 control **shall** be added as a new `## C-42 — …` section after the `## C-38` section and before the `## C-34` section. | `docs/engineering-rules.md` (after `:122`, before `:124`) |
| **LLR-B64-3.2** | HLR-B64-3 | C-42 **shall** name **five** mechanics, each with its own discharge: (1) markup token TYPES over substring presence, including entity spoofing of a structural delimiter; (2) the escaped form of a character is not the character; (3) a heading emitted inside a code-span wrapper; (4) entity-bearing snapshot export text; (5) a language-aware source parse over a line regex. | same section |
| **LLR-B64-3.3** | HLR-B64-3 | C-42 **shall** open by declaring itself an extension of C-32/C-37 and naming the axis on which it differs (the producer under test). | same section |
| **LLR-B64-4.1** | HLR-B64-4 | The extension **shall** be appended inside the existing `## Pin the truth, not a string  [travels]` section, after its final paragraph and before the `## Mutation-test every assert` heading, and **shall not** introduce a new `##` heading. | `~/.claude/skills/tui-design/VERIFY.md`, between `:38` and `:40` |
| **LLR-B64-4.2** | HLR-B64-4 | The extension **shall** contain no occurrence of `CRC Designer`, `s19`, `a2l`, `mac`, or any repository path, and its illustrating example **shall** be a generic terminal-UI element. | same |
| **LLR-B64-4.3** | HLR-B64-4 | The extension **shall** state the counterexample so that it separates from the section's pre-existing rule — namely that the failing predicate read a genuine runtime value and a **false fail**, the direction the section does not cover. | same |
| **LLR-B64-4.4** | HLR-B64-4 | The `[travels]` tag **shall** be retained and the justifying test recorded in the batch artifact. | same + §3.4 |
| **LLR-B64-5.1** | HLR-B64-5 | The lineage record **shall** gain one entry in its existing `**NEW C-NN (batch, date, operator-approved → destination):**` form covering **C-40** and **C-42** and the **C-35 rider**, each with destination, one-sentence rule, and origin. | `project_devflow_control_lineage.md` |
| **LLR-B64-5.2** | HLR-B64-5 | The lineage record **shall** record P-6/P-7 as ABSORBED into C-40, P-3 as DECOMPOSED, and **`C-41` as NOT CONSUMED — the id remains free**. | same |
| **LLR-B64-5.3** | HLR-B64-5 | The lineage record **shall** register **`C-29`** (encoded at `docs/engineering-rules.md:64`, previously unregistered). | same |
| **LLR-B64-5.4** | HLR-B64-5 | The `## Controls encoded` footer **shall** be corrected from `C-1..C-36` to the measured encoded space plus this batch's additions, and its stack-specific list **shall** be corrected to include C-32, C-34, C-37, C-38. | `.dev-flow/BACKLOG.md:143-144` |
| **LLR-B64-6.1** | HLR-B64-6 | Before the first write to any out-of-VCS file, a byte-identical copy **shall** be taken to a recorded path. | `03-out-of-vcs-evidence.md` |
| **LLR-B64-6.2** | HLR-B64-6 | For each out-of-VCS file the record **shall** carry PRE and POST rows (lines, bytes, SHA256) plus the deltas, and the POST row for a file **shall** be taken **in the increment that edits that file**, not deferred to the final increment. | same (A-26) |
| **LLR-B64-6.4** | HLR-B64-6 | The record **shall** state each file's expected line/byte delta **before** its edit, and **shall** cite §3 as the diffable source of the inserted text. | same (D-10, D-11) |
| **LLR-B64-7.1** | HLR-B64-1…4 | Each LLR clause stating a within-file insertion position **shall** be observed by a placement predicate that is RED on the pre-batch tree, GREEN on a correct insert, and RED on a mis-placed insert. | §4.5 (A-24) |
| **LLR-B64-6.3** | HLR-B64-6 | **If** a POST SHA256 equals its PRE SHA256 for a file the batch claims to have edited, **then** the batch **shall** treat that as a failed increment and block the gate. | same |

---

## §3 — The normative text, ready to paste

### §3.0 — FROZEN PASTE MANIFEST (A-31) — **§3 IS FROZEN**

> **NORMATIVE, and it is the deliverable of fold 3.**
>
> 1. **§3 is FROZEN.** The six blocks below are the batch's shipped text. **Any later edit to a paste
>    block invalidates every measurement keyed to that block's hash and requires re-measurement.** A
>    fold that changes a block and leaves a figure standing has committed the defect this manifest
>    exists to prevent.
> 2. **A figure is admissible only if it names the block hash it was taken against.** *"Measured
>    against the shipping bytes"* is a **provable** claim under this rule and an unfalsifiable one
>    without it. This is the structural fix for the defect that cost three iterations: `AT-B64-04` was
>    discharged against a rider body that the same fold had already superseded, and nothing in the
>    document could detect that, because no figure was bound to a subject.
> 3. **Before each paste, re-verify the block's SHA256 against this table.** A moved hash means
>    **stop and re-measure — do not paste** (§9.2).
> 4. **`§3.6`'s five `⟪…⟫` anchor lines are hashed with the block and are NOT pasted.** They exist
>    because `.dev-flow/BACKLOG.md` takes four spot edits, not one contiguous insert. A reviewer
>    diffing §3.6 against the POST file strips anchor lines first; a POST file containing `⟪` is an
>    immediate Inc-4 failure.

**Extraction rule, stated so any party can reproduce these hashes rather than trust them.** A block is
the bytes **between the LF that terminates its opening ` ```markdown ` fence and the LF that precedes
its closing fence, exclusive of that final LF** — i.e. the paste payload with no fence and no trailing
newline. Measured as UTF-8 bytes.

| # | block | destination file | insert point | bytes | lines | SHA256 |
|---|---|---|---|---|---|---|
| 1 | **§3.1** — C-40 | `~/.claude/commands/dev-flow.md` | new bullet between `:147` and `:148` | **6 219** | 1 | `5cb146e980deb639a65fe7e494c356e666086c0c743f810fbd4294149945c9ed` |
| 2 | **§3.2** — the C-35 rider | `~/.claude/commands/dev-flow.md` | **in place inside `:145`**, before its `(Origin: …)` | **2 411** | 1 | `4b4e3bad391c0962c3a8ab0fb8aa59115e3dc85d95882640de3573a6943fbdae` |
| 3 | **§3.3** — C-42 | `docs/engineering-rules.md` *(in VCS)* | new `##` section after `:122`, before `:124` | **4 306** | 11 | `db1fa905083ec96a2ecad5bc65ae9fdcd49df3ba14fd4e30a3443c1cb0b923d9` |
| 4 | **§3.4** — the `VERIFY.md` extension | `~/.claude/skills/tui-design/VERIFY.md` | inside `## Pin the truth…`, between `:38` and `:40`; **no new `##`** | **1 540** | 19 | `b1cdc97013f792d22e3bca494cf0bd6d96592583b2403421c7eee2da0a4c9e99` |
| 5 | **§3.5** — the lineage entry ⟵ NEW | `…/memory/project_devflow_control_lineage.md` | appended after the file's final entry | **5 962** | 6 | `059b7badc4fd9ed9f47e87c489b4d5419af65e0eb7e89ca699c261e59896bbed` |
| 6 | **§3.6** — the `BACKLOG.md` reconciliation ⟵ NEW | `.dev-flow/BACKLOG.md` *(in VCS)* | **4 spot edits**, per its `⟪…⟫` anchors | **7 265** *(of which **515 B** are 5 anchor lines that are **not pasted**; payload **6 751 B** / 13 lines)* | 18 | `3a6c737458870a35961e4117521a3aa7d0405bdae34669a4ff7eb7db9e852262` |
| — | **CONCATENATION** of blocks 1–6 in this order, no separator | — | — | **27 703** | — | `92029b6fe10377e8976401fc5d7e5a4ace32eda39aa32537b24bd5a8a11dce88` |

**Sum check, so the concatenation hash is not an unaudited byte bag:**
`6 219 + 2 411 + 4 306 + 1 540 + 5 962 + 7 265 = 27 703` ✓ — it matches the concatenation's measured
length, so no block was dropped or double-counted when the digest was taken.

**Coverage check — six blocks, six destination files, and that is the whole edit surface.** Fold 2
carried paste text for **four**; the two missing were the **lineage memory** and **`.dev-flow/
BACKLOG.md`** (A-32/A-33), and the lineage memory is one of the legs with **no PR, no CI and no diff
review**, i.e. exactly the destination for which `D-11` says *"§3 is the only external reviewer they
get."* The obligation was undischargeable where it mattered most.

**Blocks 1–4 are byte-identical to their fold-2 state, and that claim was verified by execution, not
asserted** (fold 1 printed two false *"Unchanged"* labels — A-16). Each fence was extracted by byte
offset and hashed **before** this fold's edits and again **after** them; all four hashes are unchanged,
and they also reproduce the independent audit's `5cb146e980de` / `4b4e3bad391c` / `db1fa905083e` /
`b1cdc97013f7` prefixes. **A-36 changed §3.2's surrounding *prose*, not its block.**

### §3.1 — C-40 (amended limb 1 + PIN corollary), `~/.claude/commands/dev-flow.md`, Phase-1 section

```markdown
- **Falsifiability-before-correctness (C-40) — "can this predicate go RED?" is a SEPARATE gate question from "is this predicate correct?", and it is answered at AUTHORING time, by EXECUTION:** every acceptance-bearing predicate — a black-box `AT`, an `LLR` acceptance clause, a `TC`, **and any measurement probe whose number a gate is keyed on** — MUST, in the artifact that introduces it, satisfy BOTH limbs and record the executed transcript for each. **LIMB 1 — the declared subject must be IN the expression.** Name the subject *the predicate itself declares* it certifies, then confirm that subject appears in the predicate's own expression; a predicate whose value is **invariant under the change it gates** cannot gate it, however exact its arithmetic — **see the corollary below before applying that sentence on its own.** **When the syntactic test (is the subject in the expression?) and the semantic test (does the predicate's value move?) DISAGREE, the semantic one governs, and its domain includes the platform** — a predicate whose subject is plainly in its expression can still be invariant on the host the merge gate runs on, which makes it inert exactly where it is relied upon. **The static half is free: read the expression and ask which symbol in it the implementation could move.** A predicate relating two pure functions of the same input certifies arithmetic, not the implementation. **Corollary, and it is the useful half:** when the declared subject is NOT the subject of the change being gated, the predicate is a **regression PIN, not a gate** — keep it and **label it so**; do not delete it and do not let it stand as the gate. **LIMB 2 — the set must come from the RULE, not from the implementation.** If the predicate quantifies over a set, that set MUST be drawn from the rule the predicate states, never from the implementation it certifies; a set derived from what the code currently handles makes the check a tautology that certifies a completeness the code does not have. **Two named instances:** *(i)* **a positive control shaped to the implementation** — deriving a detector's cases from the cases the detector already catches; shape them from the rule's own statement and establish each case's status independently of the detector. *(ii)* **a consolidation that drops observables** — when N artifacts merge, the **union of their observables** is the subject, so the merge MUST carry every observable forward or print an explicit retirement line naming what was dropped and why; an id-range table is a container, not evidence of preservation, and a green traceability count over the survivors cannot see the casualties. **DISCHARGE for both limbs:** name the mutation that reddens the predicate, **execute it, and paste the transcript**, including confirmation that the mutation actually applied (a typo'd mutation also "fails", for the wrong reason). Run the mutation where **no other session is reading** — your own increment tree or a `git archive`/worktree export, never a tree a concurrent review or a parallel batch is measuring — and **RESTORE it before the next gate**, confirming the restore in the same transcript (`git status` clean, or the file's hash back at its pre-mutation value). A mutation left applied contaminates every later measurement in that tree and is indistinguishable, to anyone else reading it, from a real defect. A predicate that stays GREEN under a mutation of what it claims to certify is **inert: rewrite it, do not re-argue it.** **DISTINCT from C-10** (mutates the CODE at the AT surface), **C-31** (mutates the INPUT SET) and **C-39** (executes the THRESHOLD the gate is keyed on) — a predicate can satisfy all three, be arithmetically exact, quantify over a derived complete set, carry a measured number, **and still be invariant under the change it gates**. **NOT orthogonal to C-35**, and say so honestly: running the producer over a real input *does* catch the round-trip-identity form of this defect; C-40's contribution over C-35 is that it applies where there is no product transform to run — a spec-layer algebraic predicate, a consolidation table, a hand-shaped case list. EXTENDS the §Objective-exit-criteria *Certainty* clause ("the counterfactual shown — the AT RED on the pre-fix tree") on three axes: from a **gate-exit** obligation to a **per-predicate authoring-time** one; from `AT-NNN` alone to **every acceptance-bearing predicate**, including `LLR` clauses, `TC`s and probes; and from "shown" to "**executed, with the transcript pasted**". (Origin: batch-63 — a corpus of vacuous acceptances for one defect that has grown every time someone looked for more, three of them authored *after* vacuity was already that batch's identified theme and three the orchestrator's (`05-postmortem.md:59-65`). Five related an accounting helper to a string join — both pure functions of the same input — while the writer, the declared subject, never appeared in the expression (`00b-measurements-rescoped.md:211-216`); the executed counterfactual read `RED cases against the WRONG implementation: 0` (`:206`). The **sixth was found by applying this control** and is live on `main`: `AT-172b` asserts `raw == document_bytes(raw.decode("utf-8"))`, an identity for every valid UTF-8 string, while its docstring claims to be *"the clause that fails on a text-mode writer"* — 0 RED cases across {pre-fix, post-fix} × {LF, CRLF}, and it is missed by C-10, C-31 **and** C-39. Instance (i) is `AT-193b`, built only from cases its own detector already caught, which omitted this repo's own `p.open("w")` idiom. Instance (ii) is the revision-3 fold, which replaced a 40-row TC layer with three id ranges and dropped **8 of ~18** union observables, including the only structural check the merge gate could run (`02-regate-discharge-qa.md:66`, `:102`). **Dropping one limb measurably loses members of that corpus while the other limb keeps them — the arms, their domains and their exact figures are recorded in the batch artifact rather than in this block, because a count encoded in a control becomes wrong the moment the corpus grows, and that is exactly what happened while this control was being written.**)
```

### §3.2 — The C-35 rider (replaces the cancelled C-41), inserted INSIDE the C-35 bullet at `dev-flow.md:145`, immediately before its `(Origin: …)`

```markdown
**Rider — executing the producer is not enough if the predicate is then written against the RENDERED form:** the run MUST end with the producer's **actual emitted output pasted into the artifact**, and the predicate written against that paste — never against a character list, the human-readable rendering, or the spec's own vocabulary for the thing. Producers escape, encode, wrap and substitute, so confirming that a named output *exists* passes while the predicate that searches for its readable form **false-fails a CORRECT implementation**; prefer a predicate over the producer's own structured output (its parser's token stream, a language-aware parse of the source) to a substring search over serialized text, because a substring search cannot tell a value from its own encoding. **The failure is quiet and symmetric, and that is what makes it expensive:** it returns a *plausible* number, so a predicate that under-counts by two orders of magnitude reads as a measurement rather than as a bug — and when a probe instead returns an **impossible** value (zero matches for something plainly present, a negative index for something that exists), that is luck, not detection. **Three spellings, each of which looks like careful work:** a `startswith`/prefix guard over a formatted line — widths, separators and padding are the producer's choice, not the predicate author's; a hand-listed character class standing in for *"this field is inert"*; and a predicate written from the requirement's wording instead of from the output. **Also EXTENDS C-36** — which reconciles an acceptance literal to a constant DEFINED on disk — from the *source-side definition* to the *output-side encoding of that same constant*: a literal can satisfy C-36 in full, being a defined constant, and still be unfindable in the emitted output, so C-36 and this rider fail independently. Stack-specific emitted-form traps belong in the project's `docs/engineering-rules.md`, never here. (Measured: a report heading emitted as `` #### Checklist: `chk.json` `` is unfindable by its bare form — the probe returned an impossible `-1`, which is the only reason it was caught; `.dev-flow/2026-07-26-batch-63/00-measurements.md:96-98`. Same family, 8 occurrences enumerated across batches 60-63 in `.dev-flow/2026-07-27-batch-64/01b-qa-catalog.md` §AT-B64-04 — cite the enumeration, never a total: three registers disagree.)
```

**Rider normative body length: 1 975 B** (**1 976 B** if the single space separating the body from
`(Measured:` is counted — the ±1 is that space and nothing else). **CORRECTED, A-36:** this sentence
read *"~890 B"* through fold 2, wrong by **2.2×** against its own fenced block twelve lines above,
and it is the number `A-17` cited when it discharged `AT-B64-04` (§4.3) — which is why that discharge
is not accepted (§4.3's staleness banner). Derived from §3.0's frozen §3.2 block by splitting at
`(Measured:`: **1 975 + 1 + 435 = 2 411 B**, the whole block. I scoped the body at ~600 B and fold 1
measured 889 B; `D-01…D-04` then restored four clauses into it, which is where the rest came from.
**Stack-free scan of the normative body**, i.e. excluding the `(Measured: …)` citation, executed in
§4 — **STALE per A-40, re-run against §3.0's frozen bytes:** all terms **0**.
The concrete `chk.json` example lives inside the citation **by construction, not by convenience** —
§0 R-4 measured it as a `tests/` fixture name with 0 hits in `s19_app/`, and the F-1 ruling the
operator upheld scopes the constraint to the normative body exactly as C-35's own `(Origin: …)`
carries `ASAP2_Demo_V161.a2l`.

### §3.3 — C-42, `docs/engineering-rules.md`, new `##` section after C-38

*(**CHANGED from the architect lane — fold 1 labelled this "Unchanged" and that was false (A-16).**
Executed word-diff, architect `:150-160` vs this block: mechanic 4 and the `(Origin: …)` both moved
**`0 of 19` → `0 of 29`**, substituting a live in-repo reproduction for batch-62's cited figure, and
`grep` → `grep, reproduced live in this repo`. The change is an improvement and that is not the point:
it is an undeclared substitution of one measured number for another inside text labelled unchanged, in
a batch whose §0 rule is that a carried number is re-derived. **Five mechanics**; mechanic 1 is
rendered as two bullets — a presentation split, not a sixth.)*

```markdown
## C-42 — assert against the EMITTED form of this stack's producers (Phase 1/3, extends C-32/C-37, markup + export + source-inspection paths)
C-32 and C-37 answer *which render layer holds the fact* for a **widget** — geometry at `render_line`, colour at `render().spans`. C-42 is the same discipline one producer over: for the **document, export and source-scan** paths, the question is *which encoding holds the fact*, and the answer is almost never the readable one. The global C-35 rider states the principle; this section is the list of ways this project's producers actually spell things, and every entry cost a real predicate.

- **Mechanic 1 — assert markup token TYPES, not substring presence.** The report's markdown is consumed by `markdown-it-py`; a payload's inertness is the claim that *every token the field produces is `text`* (`{t.type for t in toks} <= {"text", "softbreak"}`), not that some hostile substring is absent. Subtracting a benign token baseline is blind by construction — an injected `# PWNED` heading reports "no change" under subtraction, because the benign report already emits `heading_open`. Pair the token-type clause with a content clause: `{t.type} <= {"text"}` alone is also satisfied by an escaper that simply **deletes** the payload.
- **Mechanic 1, second face — `&`-entity spoofing: the tokens can all be `text` and the table still be forged.** `SYM_A&vert;PASSED&vert;0x0` renders as `SYM_A|PASSED|0x0`, a forged verdict fragment, while every token stays `text`. Escaping `&` is what closes it; the *predicate* lesson is that a token-type assertion is necessary and not sufficient when the renderer resolves entities after tokenisation.
- **Mechanic 2 — the escaped form of a character is not the character.** `"](" not in note` **failed against a correct implementation**: the emitted form is `\](`, because `]` is escaped and `(` needs no escape once the bracket pair is dead. Write the predicate against the escaped spelling, or against the parsed token, never against the character pair you were defending.
- **Mechanic 3 — Mode-B code spans make a heading unfindable by its bare form.** A heading emitted as `` #### Checklist: `chk.json` `` does not match a search for `#### Checklist: chk.json`. Caught only because the probe returned an **impossible** `-1` rather than a merely low count; a Mode-B predicate that under-counts plausibly ships silently.
- **Mechanic 4 — snapshot export text carries `&#160;` entities.** `pytest-textual-snapshot` SVG output spells spaces as `&#160;`, so a literal grep for a label that is plainly visible on screen matched **0 of 29** across the snapshot set while the emitted form matched **29 of 29**. Assert against the entity-decoded text, or against the widget's runtime value — never against the raw export bytes.
- **Mechanic 5 — use an AST census, not a regex, for any predicate over source lines.** An implicitly-concatenated f-string is **one assembled template**, not the two physical lines it occupies, so a line-oriented regex census both over- and under-counts. The AST structural census is also the form CI can run when the behavioural difference is platform-specific — and it is the check a consolidation dropped in batch-63, which is how this project learned that a structural census and a behavioural mutation test are complementary, never substitutes.

**Discharge for any new predicate on these paths:** run the producer over a real fixture, paste the emitted bytes for the exact field, write the predicate against the paste — then apply C-40 and confirm the predicate can go RED. (Origin: five instances across batches 60-63, four of them false-failing a **correct** artifact: the entity-bearing snapshot grep, reproduced live in this repo at 0/29 vs 29/29; `"](" not in note` (`.dev-flow/2026-07-25-batch-62/04-validation.md:191-192`); the `-1` code-span heading probe (`.dev-flow/2026-07-26-batch-63/00-measurements.md:96-98`); a `startswith("| 0x00001")` row counter reporting 4 rows where 400 were emitted (`.dev-flow/2026-07-26-batch-63/01-requirements-architect.md:1044-1049`); and the `&vert;` forged-table finding (`.dev-flow/2026-07-25-batch-62/02-review-security.md:68`). Two of the five were caught only because their value was *impossible* rather than merely wrong.)
```

### §3.4 — The `VERIFY.md` extension, appended INSIDE the existing section

*(**CHANGED — fold 1 labelled this "Unchanged" and that was false, and this one moved a requirement
(A-16).** Executed diff vs architect `:169-183`: `9a10,13` — the **false-FAIL-direction paragraph was
added**, and `LLR-B64-4.3` was rewritten to require it (architect `:110` *"…satisfied the pre-existing
rule in full"* → `:129` *"…**and a false fail**, the direction the section does not cover"*). Fold 1
then compounded the error by crediting that same paragraph as the `[travels]` justification while
calling it unchanged. The paragraph stays — the QA reviewer independently rates the direction argument
**DECISIVE** where the label argument is only **a draw** (§4.6) — but it is declared. QA §AT-B64-09
proved separation from a paraphrase draft; the counterexample reproduces at 0/29 vs 29/29.)*

```markdown
**And a runtime value is still not enough — pin it in the form the producer EMITS it.** The rule
above is necessary and not sufficient, and the counterexample is the one authors reach for: searching
a snapshot export's source text for a label you can plainly see on screen. That search reads a real
runtime value, it satisfies everything above, and it can still return **zero matches against a
completely correct app** — because the exporter spells a space as `&#160;`, and colour never lived in
the string at all; it lives in the render spans. Same shape for a rail label wrapped by a
truncation ellipsis, a menu entry the compositor clipped, and any text that passed through an
escaper on its way out.

Note the direction: this is a **false FAIL**, not a false pass. Everything above is about a check that
cannot go red; this one goes red against a correct implementation, which is worse, because it looks
like a real defect and invites "fixing" something that was never broken.

So: identify the **producer** of the thing you are asserting on, run it, and **look at what it
actually emitted** before writing the predicate. Then assert against that — the decoded text, the
span's style object, the widget's reactive — not against the spelling a human reads. The
tell that you got this wrong is a predicate that returns an *impossible* value (zero matches for
something visibly on screen, a negative index for something present). Treat that as luck: the same
mistake that under-counts by a plausible margin passes review and ships.
```

**`[travels]` — RETAINED.** The mechanism is *source form ≠ rendered form at a producer boundary*,
true of any HTML export, ANSI stream, XML/SVG serializer, JSON-escaped payload, or markup escaper.
Illustrations are generic (a snapshot export, a rail label, a menu entry). **The added
false-fail-direction paragraph is what earns the tag**, and it is also QA's third separation test:
`VERIFY.md:36-38` defines the defect as a false *pass* and is silent on the opposite direction.

### §3.5 — The lineage-memory entry (NEW, A-32), appended to `…/memory/project_devflow_control_lineage.md`

*(**NEW this fold.** `LLR-B64-5.1/5.2/5.3` had normative text in §2.3 and **no paste block**, so `D-11`'s
restored cross-reference obligation — *"for three of four legs this is the only external reviewer they
get — there is no PR, no CI, and no diff"* — was undischargeable for exactly the destination that needs
it most. Appended after the file's final entry, in the house `**NEW C-NN (batch, date,
operator-approved → destination):**` form. **Not stack-scoped:** `AT-B64-05`'s stack-free constraint
binds the C-35 rider's normative body alone (`LLR-B64-2.2`); this is a project memory and names
project artifacts deliberately.)*

```markdown
**2026-07-27 update (batch-64 = the encoding batch for batch-63's control candidates; 2 controls + 1 rider encoded + 1 back-registration, all operator-approved via AskUserQuestion; lineage now C-1..C-40 + C-42 — C-41 NOT CONSUMED, the id stays FREE):**
- **NEW C-40 (batch-64, 2026-07-27, operator-approved → GLOBAL `/dev-flow` Phase 1, after the C-39 bullet):** *"can this predicate go RED?" is a gate question SEPARATE from "is this predicate correct?", and it is answered at AUTHORING time, by EXECUTION* — every acceptance-bearing predicate (`AT`, `LLR` acceptance clause, `TC`, and any measurement probe a gate is keyed on) MUST name the subject **the predicate itself declares** and confirm that subject appears in the predicate's own expression (**limb 1**; where the syntactic and the semantic test DISAGREE the semantic one governs **and its domain includes the platform**; a declared subject that is not the subject of the change makes the predicate a labelled **regression PIN, not a gate**), MUST draw any set it quantifies over from the **rule** it states rather than from the implementation it certifies (**limb 2**), and MUST paste an **executed** reddening transcript for both limbs — run where no other session is reading, and RESTORED before the next gate. DISTINCT from C-10 (mutates the CODE) / C-31 (mutates the INPUT SET) / C-39 (executes the THRESHOLD); **NOT orthogonal to C-35**, which does catch the round-trip-identity form, and the block says so. **P-6 and P-7 are ABSORBED as limb 2's two named instances, not encoded separately** (operator ruling: all three fail from one cause — *the predicate does not touch what it claims to touch* — and three controls where one suffices is the friction that makes controls get ignored). Origin: batch-63 — five vacuous acceptances authored for ONE defect, three of them *after* vacuity was already that batch's identified theme and three the orchestrator's; each related two pure functions of the same input while the writer, the declared subject, never appeared in the expression. A sixth was then found **by applying this control** and is live on `main` (`AT-172b`, `tests/test_report_document_bytes.py:217` — an identity for every valid UTF-8 string, missed by C-10, C-31 **and** C-39). Detail: [[project-batch-log-2026-07]].
- **NEW C-42 (batch-64, 2026-07-27, operator-approved → s19_app `docs/engineering-rules.md`, new `##` section after C-38; stack-specific per the batch-45 placement policy):** *assert against the EMITTED form of this stack's producers* — extends C-32/C-37 from the widget render path to the **document, export and source-inspection** paths, and names FIVE mechanics, each with its own discharge: (1) assert markup token TYPES, not substring presence, including `&`-entity spoofing of a structural delimiter; (2) the escaped form of a character is not the character; (3) a heading emitted inside a Mode-B code-span wrapper is unfindable by its bare form; (4) snapshot export text carries `&#160;` entities; (5) use a language-aware source parse, not a line regex. Origin: five instances across batches 60-63, **four of them false-failing a CORRECT artifact**, and two caught only because the value returned was *impossible* rather than merely wrong. Detail: [[project-batch-log-2026-07]].
- **NEW rider on C-35 (batch-64, 2026-07-27, operator-approved → GLOBAL `/dev-flow` Phase 1, inside the existing C-35 bullet; NO new control id consumed):** *executing the producer is not enough if the predicate is then written against the RENDERED form* — the run MUST end with the producer's **actual emitted output pasted into the artifact** and the predicate written against that paste, never against a character list, the human-readable rendering, or the spec's own vocabulary; the failure is quiet and symmetric, returning a *plausible* number, and an **impossible** value is luck rather than detection. Stack-specific emitted-form traps belong in the project's `docs/engineering-rules.md`, not in the global command. **Also EXTENDS C-36** — from the *source-side definition* of a constant to the *output-side encoding* of that same constant; the two fail independently. Origin: batch-63 P-3 (`.dev-flow/2026-07-26-batch-63/00-measurements.md:96-98` — a heading probe that returned an impossible `-1`), same family enumerated across batches 60-63. **Encoded as a RIDER, not as C-41** — operator ruling taken against a stated alternative (a ~2 000 B standalone control at ~70 % overlap with C-35).
- **REGISTERED, no new text — C-29 (two-axis geometry-budget measurement, Phase 1, extends C-23; encoded at `docs/engineering-rules.md:64`, never registered here):** back-registered by batch-64 after its bidirectional census found C-29 **encoded but unregistered**. The census's *other* direction found **C-1 registered here with no id-bearing text anywhere** — a narrative label, carried as a named known-RED exception and NOT closed by this batch (sibling of OB-2). `C-2 … C-9` are absent from **both** sides and carry no signal in either direction, so the exception is `C-1` alone.
- **P-3 DECOMPOSED across four destinations, not encoded as one control (operator ruling 2026-07-27):** leg 1 → the **C-35 rider** above (global, portable principle only); leg 2 → **C-42** (project `docs/engineering-rules.md`, stack-bound mechanics); leg 3 → the **`tui-design` skill's `VERIFY.md`**, EXTENDING the existing `## Pin the truth, not a string  [travels]` section with the *pin it in the form the producer EMITS it* step — general terminal-UI knowledge only, illustrations de-identified, `[travels]` retained; leg 4 → the **TUI course**, plan durable and self-contained at `G:/My Drive/Courses/textual/PENDING-UPDATES.md`, **OUT of batch-64** per operator ruling. **P-6 / P-7 ABSORBED into C-40** (above). **C-41 is NOT CONSUMED — the id remains FREE**; recorded here so the next control-minting batch does not assume it is taken.
```

### §3.6 — The `.dev-flow/BACKLOG.md` reconciliation text (NEW, A-33)

*(**NEW this fold.** `LLR-B64-5.4` and the Phase-6 reconciliation had no paste text. **This destination
takes FOUR spot edits, not one contiguous insert**, so the block is segmented by `⟪REPLACES …⟫` /
`⟪INSERT …⟫` anchor lines. **The anchors are part of the frozen bytes and are hashed with them; they
are NOT pasted into `BACKLOG.md`.** A reviewer diffing §3.6 against the POST file strips the anchor
lines first — that rule is normative and is restated in §3.0. `BACKLOG.md` is **in VCS**, so unlike the
lineage memory this leg does get a PR, CI and a diff; it is specified here because `LLR-B64-5.4` is
normative text with, until `PP-5` (A-38), no observer at all.)*

```markdown
⟪REPLACES `.dev-flow/BACKLOG.md:143-144` — the `## Controls encoded` footer (LLR-B64-5.4)⟫
## Controls encoded — do NOT re-encode
RC-1, plus the **measured encoded id space `C-10 … C-39`** — 32 ids across **three** declaration shapes, plus `C-13.1` and `C-15.1` — **∪ `{C-40, C-42}`** as of batch-64 (canonical: `project_devflow_control_lineage.md`). ⚠ **The previous `C-1..C-36` was wrong in BOTH directions and is superseded** (batch-64 §0 R-3 / §4.4, executed declaration-shaped census per destination): `C-2 … C-9` have **no id-bearing text anywhere** — the apparent hits were architecture-diagram node labels and a ruff rule code — while `C-37`/`C-38`/`C-39` were already encoded and outside the stated range. **`C-1` is registered in the lineage with no encoded text**, a narrative label carried as a named known-RED exception (sibling of OB-2), NOT closed. **`C-41` is FREE — NOT consumed:** batch-64 encoded P-3's global leg as a **rider on the existing C-35**, so the next control-minting batch may take `C-41`. Stack-specific controls (C-13 / C-13.1 / C-22 / C-23 / C-28 / C-29 / C-30 / **C-32** / **C-34** / **C-37** / **C-38** / **C-42**) live in `docs/engineering-rules.md`; global flows stay project-agnostic (`feedback_devflow_general_flows_project_agnostic`). **NEW 2026-07-20: backlog carry-over is a mandatory close step in both flows** (`feedback_backlog_carryover_enforced`).
⟪REPLACES the lead of the `(P1, OPERATOR DECISION 2026-07-27 — batch-63 control candidates RESOLVED)` bullet — mark it SHIPPED⟫
  - **▸ ✅ (was P1) batch-63 control candidates — ENCODED by batch-64, 2026-07-27.** The operator ruled *encode P-5 globally, absorb P-6 and P-7 into it, DECOMPOSE P-3 across four destinations*; batch-64 executed that ruling. **Shipped: `C-40`** (global `/dev-flow` Phase 1, P-5 with P-6/P-7 absorbed as limb 2's named instances) · **`C-42`** (`docs/engineering-rules.md`, P-3 leg 2) · **a RIDER on `C-35`** (global, P-3 leg 1 — `C-41` was cancelled as a control and **the id stays free**) · the **`VERIFY.md` extension** (P-3 leg 3, `tui-design` skill) · **`C-29` back-registered** in the lineage. **P-3 leg 4 (the TUI course) is OUT of batch-64** — plan durable at `G:/My Drive/Courses/textual/PENDING-UPDATES.md`, status NOT STARTED. Artifacts `.dev-flow/2026-07-27-batch-64/`. *(The full four-destination assignment below is retained verbatim as the spec that was executed.)*
⟪INSERT into the TOP section, immediately above the batch-63 entry — the batch-64 DONE line⟫
- **✅ batch-64 — encode the batch-63 control candidates — 2 controls + 1 rider + 1 back-registration.** `/dev-flow`. **Zero production code; four of the six edited files are outside this repo's PR flow**, so their evidence is `03-out-of-vcs-evidence.md` (PRE/POST lines + bytes + SHA256 per file, POST taken in the increment that edits it) plus the frozen paste manifest at `01-requirements-consolidated.md` §3.0 — which is the only diff three of those legs get. **Phase 1 took THREE folds and hit the soft cap**; the root cause is recorded rather than smoothed over: *the acceptance layer was measuring a moving target*, because every fold rewrote the normative text that every arm figure was keyed to. The fix is structural — §3 is now FROZEN under per-block SHA256, and measurement runs after the freeze, never concurrently with it. **`C-40` caught its own authors eight times inside one batch**, the most expensive being the discharge of `AT-B64-04` against a rider body that had been superseded by the same fold that discharged it.
⟪REPLACES the `**Last refresh: …**` clause in the header block at `.dev-flow/BACKLOG.md:5`⟫
**Last refresh: 2026-07-27 (batch-64 close — control encoding; the `## Controls encoded` footer corrected from the wrong `C-1..C-36` to the measured `C-10 … C-39` ∪ `{C-40, C-42}`, and the stack-specific list corrected to include C-32/C-34/C-37/C-38/C-42).**
⟪INSERT under the batch-64 entry — the eight carries this batch creates (§7)⟫
  - **▸ (P2, new — batch-64 §7.1) FOUR vacuous predicates live on `main`, one carry.** `V-6`/`AT-172b` (`tests/test_report_document_bytes.py:208-221`) — on the merge-gate platform **BOTH** clauses are inert, not only the named one, and `REQUIREMENTS.md:4849` cites `AT-172` as covering **R-TUI-097**, so the requirement record carries a **false coverage claim**; `V-7` (`tests/test_flow_report_service.py:496`), the same round-trip tautology one line above the sound `:497`; `S-6`'s second assert (`:266`), dead by entailment behind a docstring (`:250-252`) whose stated justification is measurably false. **Fix shape for all: compare the file against an INDEPENDENTLY COMPOSED document, not against its own decode.** batch-64 was forbidden to touch `tests/` (D-5).
  - **▸ (P2, new — batch-64 §7.2) a FALSE COUNTERFACTUAL in batch-63's VALIDATION RECORD.** `.dev-flow/2026-07-26-batch-63/04-validation-rescoped.md:34` (and `:36`) record a pre-fix **RED** for an observable measured **GREEN** in all four cells; the adjacent rows qualify where the authors knew, these two carry no qualifier. Squarely inside C-40's *"any measurement probe whose number a gate is keyed on"* — **and the gate layer had never been audited by any lane.**
  - **▸ (P3, new — batch-64 §7.3) `C-1` is registered in the lineage with no encoded text.** Corrected from the earlier "`C-1 … C-9`": `C-2 … C-9` are absent from **both** sides and carry no signal in either direction, so the exception is `C-1` alone. Sibling of **OB-2** (the missing AT/TC registry); park beside it. `C-29` is closed by batch-64.
  - **▸ (P3, new — batch-64 §7.4) the P-3 occurrence count disagrees across three registers** — `~7th` (lineage), `~9` (this file), `8+` (`MEMORY.md`) — **and the enumeration itself was under-drawn: 9, not 8.** Executing `AT-B64-04` found the missing occurrence (a `startswith("| 0x00001")` prefix guard reporting 4 rows where 400 were emitted). Reconcile all three registers or delete the totals; the encoded text deliberately carries **none**.
  - **▸ (P3, new — batch-64 §7.5) `PLAN.md:73-74`'s contiguity claim is REFUTED** and must be corrected in the living plan, visibly, as the orchestrator's own instance of this batch's defect class — **the census counted mentions, not encodings.**
  - **▸ (P3, new — batch-64 §7.6) `C-41` is FREE.** Recorded so the next control-minting batch does not assume the id is taken.
  - **▸ (P2, new — batch-64 §7.7) the R-c length check is NOT like-for-like.** It prices a 3-candidate absorbing control against a 1-candidate one, so it **will fire on every future absorbing control regardless of density**. Revise the check, or it becomes a gate everyone learns to wave through. Weight it, do not dismiss the breach.
  - **▸ (P3, new — batch-64 §7.8) the worktree-mutation hygiene rule at `.dev-flow/BACKLOG.md:50` is now a DEPENDENCY of an encoded control.** C-40's discharge mandates executing a reddening mutation, and its bound (*run where no other session is reading; RESTORE before the next gate*) is exactly that rule. Close the standing candidate or retire it explicitly — do not leave it open beneath a control that depends on it.
```

---

## §4 — Acceptance (the WHAT), with the folded scopes

> ### ⚠ NORMATIVE STALENESS BANNER (A-40) — read before using any figure in §4
>
> **Every arm figure in this document is `STALE — pending re-measure against the frozen manifest`.**
> That covers, without exception: `AT-B64-01`'s `8/9` · `9/9` · the superseded `6/6`; `AT-B64-02`'s
> `0/6` · `1/6` · `0/5` and the `1/6`/`2/6` mutant figures; `AT-B64-04`'s `8/8` · `9/9` and both `6/9`
> mutations; `AT-B64-05`'s `0/12`; `AT-B64-10`'s census verdict; and §4.5's four `RED/GREEN/RED`
> placement rows. **They are recorded, not deleted, and none of them may be cited as current.**
>
> **Why.** Each was measured against a §3 paste block that a later fold then changed, so the figure
> and its subject were never the same bytes at the same time. The proof is `AT-B64-04` (§4.3): its
> transcript was produced against the fold-1 **890 B** rider body while the shipping body is
> **1 975 B**, and the two clauses its mutations turn on live in **distinct spans ~1 000 B apart** in
> the shipping bytes, so one of its two published mutations is **impossible** against the text that
> ships. **`arch BLOCKER-1` is therefore NOT closed** — `AT-B64-04` remains the sole load-bearing
> acceptance for `US-B64-2`, and re-running it against the frozen §3.2 bytes, with mutations chosen
> from the *shipping* clause set, is a **blocking Inc-3 gate condition** (§9.2, §9.3 item 9).
>
> **What replaces them.** §3 is now FROZEN under §3.0's per-block SHA256. A separate measurement pass
> runs against those hashes, not concurrently with this fold, and its output supersedes this banner.
> **A re-measured figure is admissible only if it names the §3.0 block hash it was taken against.**

**AT ids and their observables are the QA lane's.** Reproduced here with the amended scopes so this
document is self-contained; the executed transcripts live in `01b-qa-catalog.md` §3/§5, in
`01c-arms-measurement.md`, and in this section for what fold 2 executed.

### §4.0 — Validation method per requirement (RESTORED — D-12, dropped by fold 1)

A required IEEE-830 element that fold 1 dropped entirely; `Inspection` and `Analysis` returned **0**
in the folded document, so the normative spec assigned **no verification method to any requirement**.
It is also the distinction that keeps `AT-B64-09` from being over-claimed as a test.

| story | deliverable | method | justification |
|---|---|---|---|
| **US-B64-1** (C-40) | control block in `dev-flow.md` | **Test** (scripted application of the encoded rule to a labelled corpus) + **Inspection** for limb 2 | limb 2 cannot be mechanised — deciding *"drawn from the rule or from the implementation?"* requires reading the rule — so each limb-2 verdict carries a `file:line` to the executed refutation that established it |
| **US-B64-2** (C-35 rider) | rider inside the C-35 block | **Test** (clause-coverage over the rider's actual bytes, §4.3) + **Test** (boundary grep over the added block) | fold 1 listed this as `Demo`; §4.3 upgraded it — the arm is now executable because clause presence is read from the bytes, so a deleted clause changes the verdict |
| **US-B64-3** (C-42) | new control in `docs/engineering-rules.md` | **Test** (mechanic-naming table) + **Test** (complement grep) | one mechanic has a live in-repo reproduction (0/29 vs 29/29). Do not settle for inspection where a reproduction exists |
| **US-B64-4** (`VERIFY.md`) | section extension | **Test** (de-identification grep, with a non-emptiness guard) + **Analysis** (discrimination against the pre-existing text) | `AT-B64-09` is an argument about what two texts do and do not cover. Labelled honestly rather than dressed as a test |
| **US-B64-6** (lineage) | memory record update | **Test** (bidirectional census, executed PRE and re-executed POST) | fully mechanical; it already found two real defects pre-batch |
| **all four placement clauses** | in-file position of each insert | **Test** (§4.5 placement predicates `PP-1…PP-4`) | added at fold 2; A-24 |
| **`LLR-B64-5.4`** (`BACKLOG.md` footer) | corrected id range **and** corrected stack-specific list | **Test** (§4.5 `PP-5`) — ⚠ **specified, NOT executed** | added this fold; A-38. It was the batch's residual orphan: `AT-B64-10` excludes `.dev-flow/**` by `A-6`, so nothing observed the file this clause edits. The unexecuted state is an open C-40 debt, discharged by the measurement pass and blocking at Inc-4 |
| **out-of-VCS files** | 3 files | **Inspection** (SHA256 + line count PRE/POST) | the only method available — no git history, no CI, no diff review. **Bookkeeping, not acceptance** |

| AT | observable | scope after this fold | status |
|---|---|---|---|
| **AT-B64-01** | C-40 as written flags the known-vacuous predicates | **corpus = 9** (was 6, was 5). **`8/9` full-domain · `9/9` CI-only — STALE (A-40)**, measured §4.2 against a §3.1 block later changed. `V-8` is the member the two domains disagree on, and that disagreement is ruled in the control text (A-23) | **LOAD-BEARING. STALE — re-measure against §3.0 `§3.1` at Inc-3** |
| **AT-B64-02** | C-40 flags none of the sound controls | **the figure is meaningless without its domain, and stating it without one is what made it wrong (A-37).** Under the **CI-inclusive domain `A-23` makes normative: `1/6`** — `S-3` is flagged, and per `02b` §0(4) that is a **TRUE positive**, because `S-3` is inert on `ubuntu-latest`. Under the full `{LF, CRLF}` domain: **`0/6`**. Reclassify `S-3` out of the control group and it is **`0/5`** — a figure that appeared **zero times** in this document before this fold. **The defect is in the control GROUP, not in C-40.** Mutant *"key limb 1 on the writer"* → `1/6` full · `2/6` CI-only. ⚠ **Only 5 of 6 controls are fully sound** (A-22): `S-3` CI-dead, `S-5` not a shipped test, `S-6`'s second assert dead by entailment. **All four figures STALE (A-40)** | **LOAD-BEARING, with disclosed corpus defects. STALE — and the domain MUST be named alongside whatever the re-measure returns** |
| **AT-B64-03** | per C-10/C-31/C-39, a named case C-40 catches that it does not | unchanged, **plus** the honest C-35 row: C-35 *does* catch V-6, stated in §3.1's text (A-11) | **LOAD-BEARING** |
| **AT-B64-04** | the rider's clauses flag each recorded occurrence | ⚠ **EXECUTED AGAINST THE WRONG BYTES — the discharge is WITHDRAWN (A-31/A-40).** §4.3's `8/8` · `9/9` · two `6/9` mutations were produced against the fold-1 **890 B** body; the shipping body is **1 975 B**. The *never-a-character-list* clause (block offset **245**) and the `startswith`/prefix guard (offset **1241**) are **distinct spans**, so *"delete the character-list clause → 6/9, losing #5/#7/#9"* is **impossible against the shipping bytes** — deleting offset 245 cannot remove the rider's ability to flag occurrence #9, and #5's hand-listed character class is independently carried at offset 1379. Against the shipping bytes that mutation loses **at most #7**. **A-18's finding (the enumeration is 9, not 8) survives** — it is a fact about the occurrence set, not about the rider's bytes | **LOAD-BEARING, and `arch BLOCKER-1` is NOT CLOSED.** Re-run against §3.0 `§3.2` with mutations drawn from the **shipping** clause set — **blocking Inc-3 gate condition** |
| **AT-B64-05** | the added text is stack-free | **the rider's normative body only** — **1 975 B** (A-36), excluding `(Measured: …)`; **`AST` dropped** from the term list — A-5. Prior `0/12`-terms result **STALE (A-40)** | **WEAK — boundary complement only. STALE** |
| **AT-B64-06** | each s19_app instance flagged **with its mechanic named** | **five** mechanics — A-9. One has a live in-repo reproduction (0/29 vs 29/29) | **LOAD-BEARING** |
| **AT-B64-07** | the mechanics are present in the project doc and absent from the global command | unchanged; QA notes it is vacuous pre-encoding and meaningful only post-encoding | **WEAK — meaningful only paired with AT-B64-05** |
| **AT-B64-08** | zero s19_app identifiers in the extended section | unchanged | **WEAK — a constraint check, not acceptance** |
| **AT-B64-09** | the extension discriminates against `VERIFY.md`'s own pre-existing rule | unchanged; QA proved satisfiable by separating two candidate drafts | **LOAD-BEARING — carries US-B64-4** |
| **AT-B64-10** | bidirectional lineage census | **subject set RE-DERIVED FROM THE RULE** (A-19): *every encoded control id* = **32** ids over **three** declaration shapes ∪ `{C-40, C-42}` ∪ `{C-41: expect absent}`; `.dev-flow/**` excluded. **`C-41` is IN the set now** (A-20). ⚠ **`C-29` and `C-1` are the two pre-batch RED carriers and MUST NOT be removed from the set** — with the old `{C-29, C-40, C-42}` set, dropping C-29 returned the AT to green-by-construction; with the rule-derived set it does not (§4.4) | **LOAD-BEARING — strongest mechanical AT** |
| **AT-B64-11** | out-of-VCS SHA256 + line counts | unchanged | **BOOKKEEPING, NOT ACCEPTANCE** — A-10. Counts toward no story |

### §4.1 — Layer A: the `N/A` declaration is WITHDRAWN (A-24)

**Three parties declared Layer A `N/A` on the same argument and all three were wrong.** Both Phase-1
lanes argued *"for a documentation deliverable the artifact IS the observable, so there is no internal
mechanism a TC could verify"*, and the Phase-2 architect reviewer independently looked for a white-box
layer and agreed none existed. The QA reviewer **did not argue — they built the layer the argument
said could not exist, and it runs** (§4.5).

The gap it exposes is not cosmetic. **Four `shall` clauses state within-file placement —
`LLR-B64-1.1`, `-2.1`, `-3.1`, `-4.1` — and nothing observed any of them.** Fold 1's *"Zero orphans"*
claim was shaped to what held: it asserted `US→HLR`, `HLR→LLR` and `US→AT`, and **omitted the
`LLR→AT` edge**. With Layer A declared N/A *and* Layer B not reaching the LLRs, those clauses had **no
verification layer at all** — which is the batch's own subject matter committed against its own
requirements.

**What is added: four placement predicates (§4.5). They are deliberately NOT minted as `TC-NNN` ids.**
Minting ids to complete a matrix remains the template-filling the flow forbids; the objection was
never to *verification*, it was to *decoration*. These predicates are RED pre-batch, GREEN on a
correct insert, and RED on a mis-placed insert — they earn their place by discriminating, not by
occupying a row.

### §4.1.1 — Traceability, with the LLR→AT edge stated

| US | HLR | LLRs | ATs | load-bearing | LLR-level observer |
|---|---|---|---|---|---|
| US-B64-1 | HLR-B64-1 | 1.1 – 1.5 | 01, 02, 03 | 01 + 02 | **PP-1** (LLR-B64-1.1) |
| US-B64-2 | HLR-B64-2 | 2.1 – 2.3 | 04, 05 | **04** | **PP-2** (LLR-B64-2.1) |
| US-B64-3 | HLR-B64-3 | 3.1 – 3.3 | 06, 07 | 06 | **PP-3** (LLR-B64-3.1) |
| US-B64-4 | HLR-B64-4 | 4.1 – 4.4 | 08, 09 | **09** (08 weak) | **PP-4** (LLR-B64-4.1) |
| US-B64-6 | HLR-B64-5 | 5.1 – 5.4 | 10 | 10 | **PP-5** (LLR-B64-5.4) — ⚠ specified, not executed |
| US-B64-1, -2, -4, -6 | HLR-B64-6 | 6.1 – 6.4 | 11 | — *(bookkeeping)* | — |

**Zero orphans — and the claim is now stated with the shape that made it wrong.** Through fold 2 it
read *"all four edges … for every LLR carrying a **placement** `shall`"*, and that qualifier was doing
the work: `LLR-B64-5.4` carries a **content** `shall` over `.dev-flow/BACKLOG.md`, `AT-B64-10` excludes
`.dev-flow/**` by `A-6`, and so the batch's only unobserved `shall` sat exactly in the gap the
qualifier opened. **`PP-5` (§4.5, A-38) closes it — as declared expectations, not as a run.** The four
edges `US→HLR`, `HLR→LLR`, `US→AT`, `LLR→AT` now hold over **every** LLR carrying a `shall` of either
kind. `LLR-B64-6.1…6.4` are observed only by `AT-B64-11`, which this document declares *"BOOKKEEPING,
NOT ACCEPTANCE … counts toward no story"* — disclosed (A-10), not hidden. HLR-B64-6's four parents are
named in the US column; it is the batch's only many-to-one edge and IEEE 830 permits it provided each
parent is named — **and the stale `*(cross-cutting)*` gloss beside them, which the same paragraph said
it no longer prints, is deleted here (audit §1.3).** **US-B64-5** (course leg) remains **OUT** per operator
ruling, plan durable at `G:/My Drive/Courses/textual/PENDING-UPDATES.md`.

### §4.2 — Corpus expansion, EXECUTED (A-21) — **arm figures STALE per A-40**

> The **corpus membership** below is a fact about `tests/` and survives the freeze. The **arm figures**
> (`8/9`, `9/9`) are keyed to a §3.1 block that has since changed and are stale; re-measure against
> §3.0 `§3.1`. `02b-trimc-measurement.md` §2 reproduced this table row for row and independently, so
> the *invariance* column is corroborated by two parties even though the arms must be re-run.

The corpus was hand-assembled, and per C-31 and C-40's own limb 2 a hand-assembled set is an oracle
in its own right. The QA reviewer attacked it and it did not hold. **Worst case: `V-7` sits one line
above the predicate the Phase-1 catalog harvested as sound negative control `S-3`** — the lane quoted
line 497 as the sound contrast, wrote *"rather than against its own decode"*, and did not add line
496, which is byte-for-byte the same round-trip tautology as `V-6`.

Re-executed this fold over the real text-mode→byte-mode writer change:

```
member host    pre-fix(text)  post-fix(byte)   invariant?
V-6    LF               True            True   INVARIANT
V-6    CRLF             True            True   INVARIANT
V-7    LF               True            True   INVARIANT      tests/test_flow_report_service.py:496
V-7    CRLF             True            True   INVARIANT
V-8    LF               True            True   INVARIANT      tests/test_report_document_bytes.py:221
V-8    CRLF            False            True   moves
S-3    LF               True            True   INVARIANT      << CI-DEAD negative control
S-3    CRLF            False            True   moves

POSITIVE ARM, domain=FULL     -> 8/9   missed=['V-8']
POSITIVE ARM, domain=CI-ONLY  -> 9/9   missed=none
```

**A consequence this fold must state, because `A-23` created it and no lane carried it into the
normative text (A-37, `02b` §0(4)).** `S-3` is a listed member of the **negative** control group and it
is **INVARIANT on LF** — visible in the transcript above. Limb 1's semantic test, under the
CI-inclusive domain `A-23` makes normative, therefore **flags `S-3`**, which makes the negative arm
**`1/6`** on the merge-gate domain and `0/6` only on the full domain `A-23` has demoted. Per `02b` that
flag is a **true positive**: the defect is in the control **group**, not in C-40. **The fold's flagship
domain ruling and its flagship negative-arm figure contradicted each other, and the contradiction was
published.** Reclassifying `S-3` gives `0/5`. All three figures are STALE (A-40); what is **not** stale
is the obligation that **whatever the re-measure returns must name its domain.**

**Three consequences, and the first is the one that matters.** (1) **The control is stronger than
claimed and the acceptance's number was wrong** — `6/6` is superseded. (2) **`V-8` is the member on
which the two domains disagree**, which is precisely the semantic/syntactic divergence A-23 now rules
in the encoded text; without that ruling the arm's own figure is ambiguous. (3) **`V-9` is at the
validation-record layer** (`.dev-flow/2026-07-26-batch-63/04-validation-rescoped.md:34` records a
pre-fix RED for an observable measured GREEN in all four cells) — a false counterfactual in a *gate
record*, squarely inside C-40's *"any measurement probe whose number a gate is keyed on"*, and **no
batch-64 lane had looked at that layer.**

### §4.3 — `AT-B64-04` — the fold-2 transcript, WITHDRAWN as a discharge (A-31 / A-40)

> ⚠ **This transcript is retained as a record and is NOT a discharge of `arch BLOCKER-1`.** It was
> executed against the rider's **fold-1 890 B** normative body; the shipping body is **1 975 B**
> (§3.0 `§3.2`, A-36). Its own four-clause model (`C1-paste`, `C2-not-charlist`, `C3-exists-vs-
> readable`, `C4-structured`) is the fold-1 clause set — the shipping body has ten segments — and the
> second mutation below is **impossible against the shipping bytes** (audit §3.4). Retained rather
> than deleted because *"how the wrong subject produced a plausible number"* is the batch's own
> subject matter: **this is `C-40` limb 1 committed by the discharge of `C-40` limb 1's own blocker.**
> **Re-run is a blocking Inc-3 gate condition, against §3.0's frozen bytes, with mutations drawn from
> the shipping clause set.**

```
rider normative body read from 01-requirements-consolidated.md §3.2

AT-B64-04 as SPECIFIED (QA's 8-item enumeration):        -> 8/8  GREEN
   #1 FLAG via C4-structured        b60 linkify autolinked a bare URL / ~~x~~ struck a row
   #2 FLAG via C1-paste             b60 asserted the doc's vocabulary (write_out vs WRITE-OUT)
   #3 FLAG via C3-exists-vs-readable b61 snapshot predicate 0/19, entity-bearing export
   #4 FLAG via C4-structured        b62 &vert; forges a table fragment, every token still text
   #5 FLAG via C2-not-charlist      b62 Cc/Cf amendment missed U+2028 (Zl)
   #6 FLAG via C4-structured        b62 source-line regex vs implicitly-concatenated f-string
   #7 FLAG via C2-not-charlist      b62 '](' not in note failed a CORRECT impl; emitted form \](
   #8 FLAG via C3-exists-vs-readable b63 chk_rows=-1, heading inside a code-span wrapper

AT-B64-04 over 9 (adding the occurrence the enumeration omits):  -> 9/9  GREEN
   #9 FLAG via C2-not-charlist      b63 startswith("| 0x00001") -> 4 rows where 400 emitted

[MUTATION] delete the 'structured output' clause      -> 6/9  RED   (loses #1, #4, #6)
[MUTATION] delete the 'never a character list' clause -> 6/9  RED   (loses #5, #7, #9)
```

**Both mutations bite, on disjoint occurrence sets** — so the arm is a function of which clauses are
present in the rider's bytes, not of the rider's existence. **And executing it produced a finding
against its own input set (A-18):** occurrence #9 is absent from QA's enumeration of 8; the reviewer
had flagged it as *"occurrence #?"*, unable to place it. **The 8 was itself a hand-shaped set** — C-40
limb 2 applied to the acceptance for the rider, one level up from where anyone was looking.

### §4.4 — `AT-B64-10`'s subject set, RE-DERIVED FROM THE RULE (A-19)

Fold 1's `{C-29, C-40, C-42}` was **implementation-shaped** — it was the set of ids the batch touches.
That is C-40 limb 2 violated by the fold whose purpose was closing limb-2 defects, and it left the
pre-batch RED resting **1/3** on `C-29` alone. The rule is *every encoded control id*, so:

```
  S1 "## C-NN --"           -> 11 ids
  S2 bullet bold (C-NN)     -> 20 ids
  S3 bold "**C-NN --"       ->  1 ids     <- QA m-1's false negative (C-33), now covered
ENCODED (union of 3 shapes): 32
   dev-flow.md            C-10..C-12 C-14..C-21 C-24..C-27 C-31 C-33 C-35 C-36 C-39  (+C-15.1)
   engineering-rules.md   C-13 C-13.1 C-22 C-23 C-28 C-29 C-30 C-32 C-34 C-37 C-38
   VERIFY.md              []
REGISTERED in lineage: 32
encoded but NOT registered : ['C-29']
registered but NOT encoded : ['C-1']
PRE-BATCH verdict: RED   carriers = 1 + 1
drop C-29 from the set -> still RED? True     (old {C-29,C-40,C-42} set: False)
C-41: encoded=False registered=False   -> both expected False
```

**Two independent carriers, so the green-by-construction relocation is closed** rather than moved one
amendment further on. `C-1` is a narrative label in the lineage with no id-bearing text — a *named
known-RED exception*, carried rather than excluded by narrowing the quantifier. **This also corrects
§7.2:** the exception is `C-1` alone, not `C-1…C-9`, because `C-2…C-9` are absent from both sides and
so cannot carry a signal in either direction.

**A defect I introduced and am reporting as mine:** my first census regex omitted `re.MULTILINE`, so
`^## C-NN` matched only at file start and the whole `engineering-rules.md` set vanished — 21 ids
instead of 32. It is the same false-negative class as QA's m-1, committed while fixing m-1. Caught
because the union was *implausibly* small, not because the predicate announced it — which is exactly
the impossible-value corollary now restored to the rider.

### §4.5 — The four placement predicates (A-24), built and EXECUTED

Not `TC` ids. ~10 lines each, over the destination files.

```
predicate  PRE-BATCH   CORRECT  MIS-PLACED   separates?
PP-1        False      True       False       YES     LLR-B64-1.1  C-40 after the C-39 bullet, before the UI-geometry pointer
PP-2        False      True       False       YES     LLR-B64-2.1  rider INSIDE the C-35 bullet, before its (Origin:
PP-3        False      True       False       YES     LLR-B64-3.1  C-42 after '## C-38', before '## C-34'
PP-4        False      True       False       YES     LLR-B64-4.1  extension inside '## Pin the truth', before '## Mutation-test', no new '##'

CONTROL - do the existing content ATs separate correct from mis-placed?
   correct     AT-B64-08 identifiers=0 (GREEN)   AT-B64-09 content-present=True (GREEN)
   misplaced   AT-B64-08 identifiers=0 (GREEN)   AT-B64-09 content-present=True (GREEN)
```

**All four discriminate; both existing content ATs are identical on a correct and a mis-placed
insert.** That is the refutation of `N/A` in one table: a mis-placed C-40 — appended at end-of-file
instead of inside the Phase-1 section — would satisfy every acceptance fold 1 carried. **The four
`RED/GREEN/RED` rows are STALE per A-40** — `PP-1` and `PP-2` read `dev-flow.md` positions that are
functions of §3.0's frozen blocks, so they are re-run at Inc-3 with the arms.

**`PP-5` — the fifth predicate, ADDED this fold (A-38), and it is NOT yet executed.**

`LLR-B64-5.4` was the batch's **residual orphan**: it states a `shall` over `.dev-flow/BACKLOG.md`'s
`## Controls encoded` footer, and `AT-B64-10` excludes `.dev-flow/**` from **both** directions by
`A-6`, so **nothing in the batch observed the file that clause edits.** §4.1.1's *"Zero orphans"* claim
was again shaped to what held — its own qualifier is *"for every LLR carrying a placement `shall`"*,
and `LLR-B64-5.4` carries a **content** `shall`, which fell outside the shape.

| predicate | subject | PRE-BATCH | CORRECT | MIS-APPLIED | status |
|---|---|---|---|---|---|
| **PP-5** | `.dev-flow/BACKLOG.md:143-144` — the footer's declared id range **and** its stack-specific list | **expect RED** (reads `C-1..C-36` vs a measured `C-10 … C-39` ∪ `{C-40, C-42}`; stack list omits C-32/C-34/C-37/C-38) | **expect GREEN** on §3.6 segment 1 | **expect RED** on a range-only fix that leaves the stack list short — the two clauses of `LLR-B64-5.4` must be separable | ⚠ **SPECIFIED, NOT EXECUTED** |

> ⚠ **This is an open `C-40` debt and it is stated as one rather than dressed as a result.** C-40
> mandates that a predicate's reddening mutation be **executed at authoring time**; `PP-5` is
> authored here with its three expected values declared and **none of them run**, because this fold's
> operator ruling is *freeze, do not measure* — executing `PP-5` now would re-create the moving-target
> defect, since its GREEN arm is a function of §3.6's bytes, which this fold is still writing.
> **Discharge: the measurement pass executes `PP-5` against §3.0's frozen `§3.6` hash, and Inc-4 blocks
> on it.** Recorded in §9.2 and §10 as debt, not as coverage. *(Not minted as a `TC` id, consistent
> with `PP-1…PP-4` per A-24.)*

### §4.6 — `AT-B64-09` re-weighted (qa M-3)

The QA reviewer re-ran the three separation tests independently and rates them **draw · DECISIVE ·
DECISIVE**, not three wins. **Test 1 is contestable and the Phase-1 catalog over-claimed it**: `:37`'s
*"never on the presence of a label"* plainly covers a label search, and the *label*/*docstring*
pairing rebuttal is reasonable but not decisive. **The leg survives on tests 2 and 3** — the direction
argument (false FAIL vs false pass) and the structural blindness of the neighbouring mutation-test
section, which presumes the assert is currently GREEN. The write-up is re-weighted accordingly; the
leg is **not** withdrawn.

---

## §5 — Increment plan (re-derived for two controls + one rider)

| inc | files | contents |
|---|---|---|
| **Inc-0** | 1 new + 3 backups | PRE rows + backups (§6). Edits no destination. |
| **Inc-1** | `docs/engineering-rules.md` (1) | **C-42.** The only leg a PR, CI, and diff review can see — bank it first. |
| **Inc-2** | `~/.claude/skills/tui-design/VERIFY.md` (1) | The section extension. Fully independent. **Records `VERIFY.md`'s POST row + runs PP-4 at its own boundary** (A-26). |
| **Inc-3** | `~/.claude/commands/dev-flow.md` (1) | **C-40 (§3.0 `§3.1`) + the C-35 rider (§3.0 `§3.2`, in-place edit to `:145`) in ONE atomic write** — including the mutation-hygiene clause (A-25), which must not ship a gate later than the mandate it bounds. **Records `dev-flow.md`'s POST row + runs PP-1/PP-2 + re-runs AT-B64-01/02/04/05 against the *pasted* bytes.** ⚠ **BLOCKING: `AT-B64-04` against the 1 975 B shipping body with shipping-clause mutations** (A-31) — the increment does not close without it. |
| **Inc-4** | lineage memory, `.dev-flow/BACKLOG.md`, `03-out-of-vcs-evidence.md` (3) | C-40/C-42/rider/**C-29** registration from **§3.0 `§3.5`**; ABSORBED/DECOMPOSED/**C-41-not-consumed** records; the `BACKLOG.md` footer fix + reconciliation from **§3.0 `§3.6`** (**strip the `⟪…⟫` anchors — they are hashed, not pasted**). **Records the lineage POST row, consolidates the table, re-runs `AT-B64-10` AFTER the edit** — the run that closes the strongest AT's loop — **and runs `PP-5`** (A-38), which blocks. |

**POST rows are per-increment, not end-of-batch (A-26 / sec F3).** Fold 1 put all three in Inc-4,
three increments after the first out-of-VCS write, which converted `LLR-B64-6.3`'s blocking predicate
from a per-increment gate into an end-of-batch audit: a truncating Inc-2 write would not surface until
two increments had landed on top of it, when attribution is harder and the restore is coarser. Same
three rows, moved earlier, no new work. **The `AT-B64-10` post-edit re-run is mandatory and belongs to
Inc-4** — without it the census is a pre-batch observation, not an acceptance.

**R-d unchanged and still argued:** the running instance is not live-reloaded, so the hazard is the
**half-edited window a resume sees** (`dev-flow.md:108-111`), not self-modification. Inc-3 now touches
**two regions** of the same file (the new C-40 bullet and the in-place C-35 edit) — which
*strengthens* the atomic-write ruling, because a partial application would leave the rider referencing
a C-42 that exists while C-40 does not.

---

## §6 — Out-of-VCS evidence (bookkeeping, per A-10)

PRE values measured this session and cross-confirmed by the QA lane (`01b-qa-catalog.md` §AT-B64-11):

| file | lines | bytes | SHA256 |
|---|---|---|---|
| `~/.claude/commands/dev-flow.md` | 275 | 59 259 | `44660d7cfede148746ac27dcbb8cccabd11c9a420de94b6351b2c7e7ad10b883` |
| `~/.claude/skills/tui-design/VERIFY.md` | 182 | 10 142 | `23cf75e6ae8d0a2c04489f99954ab7d6e976ae3eb93846cba9c8fb25ca9588ed` |
| `…/memory/project_devflow_control_lineage.md` | 89 | 36 401 | `d9f84f9e614100d2dddf612b65ec8a2c156c3679efbfe7b75a1f41b28a0386ee` |
| `docs/engineering-rules.md` *(in VCS, for symmetry)* | 125 | 15 127 | `278b808d9438a7291c31f8965e6eb20313989a77c7535c9c7a9fae8fa49947cf` |

Backups to `.dev-flow/2026-07-27-batch-64/backup-pre/`. Three properties that make this a check
rather than a log: **change proof** (LLR-B64-6.3 — an unchanged hash on a claimed edit blocks the
gate); **bounded delta**; **restorability** (backup SHA256 = PRE SHA256).

**Expected deltas — ALL SIX EDITED FILES, every figure re-derived from §3.0's frozen blocks
(RESTORED D-10; CORRECTED and COMPLETED this fold, A-34 / A-35).**

> **What was wrong, stated plainly because §6 calls bounded delta one of *"three properties that make
> this a check rather than a log"*.** The `dev-flow.md` row read *"**+8 630** — C-40 **6 219 B** … plus
> **+1 522 B** … (rider 2 411 B less the 889 B fold-1 body it replaces)"*. **`6 219 + 1 522 = 7 741`,
> not `8 630`** — the decomposition missed its own total by **exactly 889 B**, and there is no *"889 B
> fold-1 body"* on disk to subtract: `dev-flow.md:145` is 1 774 B and contains no rider (§0.2 of the
> audit; security lane `S-1`). **The subtraction was against fold 1's PLAN, not against the file.** It
> is `arch MINOR-1`'s defect class (`59 259` vs `59 260`) at **889× the magnitude**, sitting inside the
> table raised to fix `MAJOR-10`. Fold 2 also left **3 of 6** edited files with no expected delta at
> all, two of the three it did state as `~`-estimates.
>
> **Method, so a reader can re-derive rather than trust:** every Δbytes below is `§3.0 block bytes`
> plus **named framing terms** — a line terminator, a separating blank line — never absorbed silently.
> `C-39` applies to this table: these are executed derivations over §3.0's hashes, not predictions.

| file | expected Δlines | expected Δbytes, decomposed from §3.0 | what an out-of-band delta means |
|---|---|---|---|
| `~/.claude/commands/dev-flow.md` | **+1** (C-40 is one bullet; the rider lengthens `:145` **in place** and adds no line) | **+8 631** = `§3.1` **6 219** + **1** its line terminator + `§3.2` **2 411** in place. **The `6 219 + 2 411 = 8 630` block-content sum is the corrected decomposition (A-34); the third term is the newline the new bullet line carries, named here rather than lost.** ⚠ **`+8 630` is still printed at §9.1 and §9.2** — the two differ by that one byte and the measurement pass settles which the file shows; `+14.6 %` of 59 259 B is unchanged either way (14.563 % vs 14.564 %) | a multi-line delta means the bullet was split or the file was reformatted; a delta of `+8 631 − 2 411` means the rider did not land |
| `docs/engineering-rules.md` *(in VCS)* | **+13** = `§3.3`'s **11** lines + **2** framing blank lines | **+4 308** = `§3.3` **4 306** + **2** framing newlines. **NEW ROW — fold 2 priced 3 of 6 files and this was one of the three missing**, despite being the only leg a PR, CI and a diff review can see | a `##`-count delta ≠ +1 means C-42 was split or landed at the wrong nesting level — `PP-3` also catches this |
| `~/.claude/skills/tui-design/VERIFY.md` | **+21** = `§3.4`'s **19** lines + **2** framing blank lines | **+1 542** = `§3.4` **1 540** + **2** framing newlines *(was `+~1 540`, an estimate)* | a `##`-count change means a new heading was introduced, which `LLR-B64-4.1` forbids — `PP-4` also catches it |
| `…/memory/project_devflow_control_lineage.md` | **+7** = `§3.5`'s **6** lines + **1** preceding blank line | **+5 963** = `§3.5` **5 962** + **1** framing newline. *(Was `+~2 000` — an estimate written before the block existed, low by ~3×.)* | the file is 89 lines / 36 401 B of long lines; a line delta > +7 means the entry was wrapped against house style |
| `.dev-flow/BACKLOG.md` *(in VCS)* | **+11 … +13** — `§3.6` has **13** payload lines, of which **3** replace existing lines rather than add them | **gross insert +6 751 B** (13 payload lines with terminators). **Segment 1 is exact: `+905 B` net** (footer `1 327 B` replacing `:143-144`'s `422 B`). **The other three segments are REPLACEMENTS inside long composite lines, so their net is DERIVED AT INC-4, not predicted here** — stating a number I cannot derive is the defect this table exists to catch | this is the batch's **declared collision point** (`PLAN.md:217`): a delta far from the range means a parallel session also edited the file — **re-read before reconciling, do not re-apply** (§9.2) |
| *(anchors, not pasted)* | — | `§3.6`'s **5** `⟪…⟫` anchor lines total **515 B** and are **hashed with the block but never pasted**. Gross paste ≠ block size for this file alone: `6 751 + 515 = 7 266`, vs the block's **7 265 B** + its own final newline | a POST file containing the string `⟪` means the anchors were pasted — an immediate Inc-4 failure |

**Cross-reference obligation (RESTORED D-11; now DISCHARGEABLE for all six legs, A-32/A-33).** The
exact inserted text is in §3, so a reviewer can diff §3 against the POST file **without access to the
pre-edit state**. The evidence artifact must cite **the §3.0 block hash** by name for each file — not
just the section number, because a section number does not pin bytes and pinning bytes is the whole
point of the freeze.

| destination | §3 block | §3.0 hash cited in the evidence artifact |
|---|---|---|
| `~/.claude/commands/dev-flow.md` | **§3.1** + **§3.2** | both |
| `docs/engineering-rules.md` | **§3.3** | yes |
| `~/.claude/skills/tui-design/VERIFY.md` | **§3.4** | yes |
| `…/memory/project_devflow_control_lineage.md` | **§3.5** | yes |
| `.dev-flow/BACKLOG.md` | **§3.6** | yes, **and the anchor-stripping rule (§3.0) must be restated in the evidence row**, or a reviewer diffing raw will report five spurious deletions |

**Through fold 2 this obligation was undischargeable for two of the six files** — the lineage memory
and `BACKLOG.md` had normative `shall` clauses (`LLR-B64-5.1…5.4`) and **no §3 text to diff against**.
**The lineage memory is one of the legs with no PR, no CI and no diff review**, i.e. precisely the leg
for which *"§3 is the only external reviewer they get"* was written. That is now closed.

**Honest limit, per A-10:** none of this verifies the *right* change happened. A hash proves *a*
change, never the right one. It discharges risk R-a and nothing more — the placement predicates
(§4.5) and the re-run arms are what verify correctness.

---

## §7 — Backlog carries (Phase-6 reconciliation)

1. **Four vacuous predicates live on `main`, one carry.** **D-5 forbids touching `tests/` this batch.**
   - `V-6` / `AT-172b`, `tests/test_report_document_bytes.py:208-221`. **Severity restated (qa §2.3):
     on the merge-gate platform BOTH clauses are inert**, not only the named one — line 217 is a
     tautology in all four cells and line 221's right disjunct is a constant `True` on
     `ubuntu-latest`. The earlier *"not wholly inert"* framing is true only on a developer's Windows
     box. `REQUIREMENTS.md:4849` cites `AT-172` as covering `R-TUI-097`, so **the requirement record
     carries a false coverage claim** (RESTORED, D-15) — a future fixer needs that line.
   - `V-7`, `tests/test_flow_report_service.py:496` — the same round-trip tautology, one line above
     the sound `:497`.
   - `S-6`'s second assert, `tests/test_report_document_bytes.py:266` — dead by entailment behind a
     docstring (`:250-252`) whose stated justification is measurably false: under the `+1 → +2` mutant
     it claims to catch, line 266 is GREEN.
   - **Fix shape for all**: compare the file against an **independently composed** document, not
     against its own decode (the sound form at `:497`).
2. **A false counterfactual in batch-63's VALIDATION RECORD** — `.dev-flow/2026-07-26-batch-63/04-validation-rescoped.md:34`
   (and `:36`) record a pre-fix **RED** for an observable measured **GREEN** in all four cells. The
   adjacent rows qualify where the authors knew (`:37` *"RED on every platform incl. CI"*, `:40`
   *"skipped on CI"*); these two carry no qualifier. **New carry — the gate layer had never been
   audited by any lane.**
3. **`C-1` is registered with no encoded text** (§4.4). **Corrected from fold 1's "`C-1 … C-9`":**
   `C-2 … C-9` are absent from *both* sides and carry no signal in either direction, so the exception
   is `C-1` alone — a narrative label in the lineage. Sibling of **OB-2**; park beside it. `C-29` is
   closed by this batch (A-14).
4. **The P-3 occurrence count disagrees across three registers** — `~7th` (lineage `:11`), `~9`
   (`BACKLOG.md:36`), `8+` (`MEMORY.md`) — **and the enumeration itself was under-drawn: 9, not 8**
   (A-18). Reconcile all three registers or delete the totals; the encoded text carries none (A-12).
5. **`PLAN.md:73-74`'s contiguity claim is refuted** (A-8) and must be corrected in the living plan,
   visibly, as the orchestrator's own instance of this batch's defect class.
6. **`C-41` is free.** Record it so the next control-minting batch does not assume it is taken.
7. **The R-c length check is not like-for-like** (`01c` B-2): it prices a 3-candidate absorbing
   control against a 1-candidate one and **will fire on every future absorbing control regardless of
   density**. Revise the check, or it becomes a gate everyone learns to wave through.
8. **`BACKLOG.md:50`'s worktree-mutation hygiene rule is an unencoded candidate** that C-40 now makes
   routine and mandatory. A-25 lands the bound inside C-40; the standing candidate should be closed or
   explicitly retired rather than left open beneath a control that depends on it.
9. **NEW (A-39) — the batch's two `D-` registers collide from `D-10` onward.** Operator decisions run
   `D-1 … D-11`; fold-2 restoration ids run `D-01 … D-20`. `D-10` now names both *"re-affirm C-40 at
   2.56×"* and *"expected deltas, all three"*, and `D-11` names both a withdrawn batch-62 ruling and
   the cross-reference obligation. **Not renumbered inside batch-64** — both are already cited across
   `PLAN.md`, `01d-union-ledger.md` and three reviews, so renaming mid-batch would break more citations
   than it fixes. Fix at the source in the next batch: give restoration ids a distinct prefix. This is
   the **same class as OB-2** (no AT/TC registry → id collisions recur); park beside it.
10. **NEW (A-40) — `TRIM-C` was offered as *"the cheapest form"* for one fold while being
    disqualified by a mandated security clause, and nobody reading only this document could tell.**
    The general lesson is not about TRIM-C: **a costed alternative menu must be re-validated against
    every mandate added since the menu was written**, or it silently invites a ruling that reverts one.
    Candidate shape, not raised for encoding here.

---

## §8 — Final encoded-control list

| # | id | destination | status |
|---|---|---|---|
| 1 | **C-40** | `~/.claude/commands/dev-flow.md`, Phase-1 section | **NEW control** |
| 2 | **C-42** | `docs/engineering-rules.md`, after `## C-38` | **NEW control** |
| 3 | *(no id)* | `~/.claude/commands/dev-flow.md:145`, inside the C-35 block | **RIDER on C-35** |
| 4 | **C-29** | already encoded at `docs/engineering-rules.md:64` | **REGISTERED** (no new text) |
| — | ~~C-41~~ | — | **NOT CONSUMED — the id stays free** |

Plus: the `VERIFY.md` section extension (skill, no control id — `VERIFY.md` carries none; §0 R-3
measured **0** `C-NN` ids in that file).

---

## §9 — Evidence checklist

**Merged: the architect-role 8 rows PLUS the QA lane's 10 (RESTORED, D-13 — fold 1 silently replaced
one checklist with the other, which turned a declared deviation into an undeclared one).** *(A-42: an
empty table header + separator stood here and rendered as a blank table; removed.)*

| item | ✓/✗ | evidence |
|---|---|---|
| Constraints stated | ✓ | zero-code surface honored; ≤5 files/increment (§5); stack-free scoped (LLR-B64-2.2 — the `0/12 terms` result over the **1 975 B** body is **STALE per A-40**, re-run against §3.0 `§3.2`); de-identification (LLR-B64-4.2) |
| ≥2 alternatives considered | ✓ | C-41-as-control **vs** C-35-rider (A-1, operator ruled against a stated alternative); limb-1 wordings compared by application to S-6 (§2.2); **three** trims priced at §9.1, not two (RESTORED, D-08) |
| Recommendation tied to constraints | ✓ | §5 order from R-d + the in-VCS/out-of-VCS split; §3.2's citation scoping from the upheld F-1 ruling |
| Risks listed | ✓ | §7 carries **10** items (was 8; +the `D-` register collision, +the stale-alternative-menu lesson); §6 states the bookkeeping limit; A-8 and §4.4 record two of the orchestrator's own defect instances, and A-31/A-34/A-36/A-37 record four more of this document's |
| Cost estimated | ✓ | measured, not estimated — and §9.1 records that **three** successive estimates missed |
| Diagram | ✗ | deliberate — no runtime flow; §5 is a linear table and §1.1/§4.3/§4.4 carry the structure |
| What would change it | ✓ | §10 |
| Two-layer requirements | ✓ **and the `N/A` is WITHDRAWN** | behavioral chain complete; **Layer A refuted by execution — four placement predicates added (§4.1, §4.5), `TC` ids deliberately not minted** |
| **(qa) Acceptance criteria use Given/When/Then** | ⚠ **partial — DEVIATION DECLARED** (RESTORED, D-13) | stated as *observable + reddening mutation + executed result*, per `01-requirements.md:13-16`. G/W/T is the wrong shape for *"does this rule discriminate over a corpus"*. **Declared, not silent** |
| **(qa) Explicit Expected, not vague "works"** | ✓ **for form; the VALUES are STALE (A-40)** | every arm states its expected before the transcript: `8/9`·`9/9`·`0/6` **(now `1/6` on the normative CI domain — A-37)**·`9/9`·`6/9`·`0/29 vs 29/29`·`RED/GREEN/RED`. **Each is `STALE — pending re-measure against the frozen manifest`**; §4's banner states the admissibility rule (a re-measured figure names the §3.0 hash it was taken against). `0/29 vs 29/29` is a fact about the snapshot corpus, not about a §3 block, and survives the freeze |
| **(new) Every acceptance-bearing figure is keyed to a HASHED subject** | ✓ | §3.0 — six block hashes + a concatenation hash; §3 declared FROZEN. **This is the control the batch lacked**: three folds measured against text that changed under them, and `AT-B64-04` was discharged against bytes that no longer exist |
| **(new) Unexecuted predicates are declared as debt, not as coverage** | ✓ | `PP-5` (§4.5) carries ⚠ **SPECIFIED, NOT EXECUTED** in §4.0, §4.1.1, §4.5, §9.2, §9.3 item 12 and §10 item 1b — six places, no place where it reads as run |
| **(qa) Edge cases: empty, boundary, invalid, error** | ✓ | empty = `no_new_h2` on the pre-batch tree (§4.5) and `N=0` in the corpus; boundary = `S-3`/`V-8`, the CRLF-only pair; invalid = the mis-placed-insert simulation; error = the entailed-dead assert at `:266` |
| **(qa) Regression checklist exists** | ✓ | §9.2 (RESTORED, D-14) |
| **(qa) Exit criteria stated** | ✓ | §9.3 |
| **(qa) No real PII / secrets** | ✓ | inputs are repo docs, `~/.claude` command/skill text, and git blobs; no credentials read or printed |
| **(qa) Results left blank unless actually run** | ✓ | every transcript in §0/§4.2/§4.3/§4.4/§4.5 is command output from this session; cited figures are attributed to their lane and **not** restated as mine (A-29) |
| **(qa) Layer B observed through the SHIPPED surface** | ✓ | the shipped surface of a control is the file a future agent reads. §4.3 reads the rider's bytes (deleting a clause changes the verdict); §4.4 reads the destination files; §4.5 reads the insert's position |
| **(qa) Bidirectional surface-reachability** | ✓ | §4.4 runs both directions (encoded→registered, registered→encoded) with **two independent carriers**; AT-B64-05/07 are the two directions of the placement boundary |
| **(qa) No unfilled template** | ✓ | no `<…>`, no `TC-NNN` placeholders, no empty required rows |

### §9.2 — Regression checklist (RESTORED — D-14; fold 1 dropped 4 of 6 rows)

Two of the four dropped rows were load-bearing: without them the batch's **strongest** AT never closes
its loop, and the batch's **declared** collision point has no mitigation in the governing document.

- [ ] **`AT-B64-10` is re-run AFTER the lineage edit, not only before** — the lineage memory is read by
      `/dev-flow-sync`. Without the post-edit run the census is a pre-batch observation, not an
      acceptance. **A simulation over proposed text is not the post-edit run.** Widen `encoded()` to
      all **three** declaration shapes (§4.4).
- [ ] **`.dev-flow/BACKLOG.md` — re-read before reconciling; do not re-apply.** `PLAN.md:217` marks it
      *"the one real collision point"* with parallel work, and `LLR-B64-5.4` edits exactly that file.
- [ ] **`VERIFY.md`'s `[travels]` tag retained and `AT-B64-08` = 0 post-edit** — *and if the
      de-identification constraint cannot be met, **the tag is dropped rather than the constraint**.*
- [ ] **R-d: the SHA record is taken immediately before AND after** the `dev-flow.md` write, not at
      end-of-batch (A-26).
- [ ] `dev-flow.md` is read at every batch kickoff; **+8 630 B of block content (+8 631 B with the new
      bullet's line terminator, §6/A-34) is +14.6 % of the file** — the one-byte term does not move the
      percentage (14.563 % vs 14.564 %). Check against the `D-10` ruling's basis (§9.1).
- [ ] `docs/engineering-rules.md` is the only leg CI can see. `pytest -q` must be **re-derived**, not
      copied from `PLAN.md:162`; `A = 0`, `D = 0`. A docs-only change must not move it.
- [ ] **BLOCKING (A-31/A-40) — `AT-B64-04` re-run against the 1 975 B SHIPPING rider body, with
      mutations drawn from the *shipping* clause set.** The fold-2 transcript measured the superseded
      890 B body and its character-list mutation is **impossible** against the shipping bytes (the
      prefix guard at block offset 1241 independently carries occurrence #9). `AT-B64-04` is the sole
      load-bearing acceptance for `US-B64-2`, so **Inc-3 does not close without it.**
- [ ] `AT-B64-01/02/04/05` re-run against the **final pasted bytes** in `dev-flow.md`, not against §3's
      fenced blocks — **and each re-measured figure names the §3.0 block hash it was taken against.**
- [ ] **The negative arm is reported WITH ITS DOMAIN NAMED** (A-37). `0/6` alone is not an admissible
      result; state `1/6` on the normative CI domain, or `0/5` if `S-3` is reclassified out of the
      control group, and say which.
- [ ] The four placement predicates (§4.5) run against the four edited regions.
- [ ] **`PP-5` executed against `.dev-flow/BACKLOG.md:143-144`** — RED pre-batch, GREEN on §3.6's
      segment 1, RED on a range-only fix that leaves the stack-specific list short. **Inc-4 blocks on
      it** (A-38); it is currently an undischarged C-40 debt.
- [ ] **No POST file contains the string `⟪`** — §3.6's five anchor lines are hashed with the block and
      **must not be pasted** (§3.0). Their presence in `BACKLOG.md` is an immediate Inc-4 failure.
- [ ] **Every §3 block's SHA256 re-verified against §3.0 immediately before its paste.** A block whose
      hash has moved invalidates every measurement keyed to it; **stop and re-measure, do not paste.**

### §9.3 — Exit criteria for the Phase-1 re-gate

1. Union ledger complete: every one of the 163 items dispositioned `CARRIED` / `RETIRED` /
   `RESTORED-THIS-FOLD`, with unplaceable rows reported rather than omitted.
2. Both false *"Unchanged"* labels deleted and replaced by executed diffs (A-16). ✅ done
3. `AT-B64-04` executed with a reddening mutation (A-17). ✅ done
4. `AT-B64-10`'s set re-derived from the rule; `C-41` covered (A-19/A-20). ✅ done
5. Corpus restated and arms re-run (A-21); negative-control defects disclosed (A-22). ✅ done
6. Layer A withdrawn; placement predicates added (A-24). ✅ done
7. D-9 recorded in `PLAN.md` + `state.json`; §9.1/§10 closed against it (A-27). ⚠ **the PLAN/state
   write is the orchestrator's, not this lane's** — see §10.
8. No AT presented as acceptance that any review marks blind to its subject (`AT-B64-08`,
   `AT-B64-11`). ✅ both labelled.
9. **§3 is FROZEN and the manifest is complete** — six blocks, six hashes, one concatenation hash, and
   **paste text for all six edited files** (A-31/A-32/A-33). ✅ done, §3.0.
10. **Every arm figure marked STALE and none restated as current** (A-40). ✅ done, §4 banner.
11. **`AT-B64-04` re-executed against §3.0's frozen `§3.2`** with mutations from the shipping clause
    set. ⚠ **NOT DONE — blocking Inc-3 gate condition** (A-31; `arch BLOCKER-1` re-opened). This fold
    does not measure, by operator ruling; the measurement pass owns it.
12. **`PP-5` executed.** ⚠ **NOT DONE — blocking Inc-4** (A-38). Open C-40 debt.
13. **`02b-trimc-measurement.md` folded in**: `D-10` recorded as settled, the negative arm's domain
    named, and TRIM-C's double disqualification stated in the trim menu (A-37/A-39). ✅ done, §9.1.

### §9.1 — Reader cost, MEASURED. **Both length rulings are now SETTLED — `D-9` at 2.07×, `D-10` at 2.56×.**

> **Reader note (A-42):** this section is numbered `9.1` but sits **after** `§9.2` and `§9.3`. The
> ordering is left as-is deliberately — renumbering would break every `§9.x` cross-reference across
> five artifacts to fix a cosmetic defect. Read §9.1 → §9.2 → §9.3 by number, not by position.

**Operator ruling `D-9` (settled, A-27): C-40 ships as V-FULL, the R-c breach accepted on arm 2.** Fold
1 presented this as open — *"the one open item that can change the deliverable's text"* — and that was
stale; the ruling had been made and recorded in `state.json` but not in `PLAN.md` (fixed as `D-9a`).

**Operator ruling `D-10` (SETTLED this fold, A-39): the ruling is RE-AFFIRMED at 2.56×.** `D-9` was
ruled against the **5 015 B** text; the review-mandated discharges took the block to **6 219 B**, and
fold 2 correctly refused to absorb that silently — *"re-affirming the ruling at the new figure is the
operator's call, not this lane's."* **The operator ruled on `02b-trimc-measurement.md`'s evidence, and
that evidence is what makes the re-affirmation a decision rather than an assumption.** Written in here
as settled, the way `D-9` was. **§10's open item 1 is CLOSED.**

> ⚠ **Id collision, disclosed rather than renamed:** operator ruling **`D-10`** and union-ledger
> restoration **`D-10`** (*"expected deltas, all three"*, §6) are **different registers sharing a
> string**. The registers are `D-1…D-11` (operator decisions, no leading zero) and `D-01…D-20`
> (fold-2 restoration ids); they collide from `D-10` onward. Not renumbered here because both ids are
> already cited across `PLAN.md`, `01d-union-ledger.md` and the three reviews — **always qualify which
> register.** Carried to §7 for the next batch to fix at the source.

**What `02b` measured, and why it decides the ruling — the normative document was written at 15:57 and
`02b` at 16:05, so this document cited it ZERO times until this fold (A-39, audit §3.6).** This is the
same staleness pattern `arch BLOCKER-4` raised against `01c`, recurring one lane later.

| variant | bytes | ×C-39 | positive arm | negative arm | **corpus members LOST** |
|---|---|---|---|---|---|
| **V-FULL-2** — §3.1 as frozen | **6 219 B** | **2.56×** | 9/9 CI · 8/9 full | 1/6 CI · 0/6 full | **none** |
| V-FULL-1 — the 5 015 B text `D-9` ruled on | 5 015 B | 2.07× | 8/9 | 0/6 | **`V-8`** |
| TRIM-C — *shape only, no text exists* | *see the trim menu below* | — | 6/9 | 0/6 | **`V-4`, `V-5`, `V-8`** |

*(These are `02b`'s figures, cited as **its** measurements and not restated as this document's. They
are subject to A-40 like every other arm figure; `02b`'s own harness-integrity mutation — corrupting
the `**LIMB n` markers takes it `9/9 → 0/9` — is what shows the harness reads the bytes.)*

**The load-bearing column is the last one.** `V-FULL-2` is the only variant that loses nothing, and
`A-23`'s 440 B is what converts `8/9` into `9/9` by catching `V-8`, a predicate live on `main` whose
writer is *syntactically present* in its expression — so only the semantic-plus-platform reading
catches it. Of the +1 204 B of growth, **440 B are arm-priced and 764 B are not**: `A-25`'s 496 B is a
mandated security clause whose value is not detection, and the Origin rewrite's 268 B removed encoded
counts. **That is the decomposition the R-c conversation needs, and it is the one the arms can supply.**

| quantity | fold-1 estimate | fold-1 measured | **after Phase-2 discharge** |
|---|---|---|---|
| C-40 block | ≈ 4 300 B | 5 015 B | **6 219 B** |
| C-40 ÷ C-39 (2 427 B) | — | 2.07× *(the D-9 basis)* | **2.56×** |
| C-35 rider, normative body | ≈ 890 B | 889 B | **1 975 B** (**1 976 B** counting the space before `(Measured:`; D-01…D-04 restored). A-36 |
| C-35 rider, whole block | — | 1 325 B | **2 411 B** = `1 975 + 1 + 435` (§3.0 `§3.2`) |
| saving vs the cancelled C-41 (3 863 B) | ~1 100 B | 2 538 B | **1 452 B** — D-7's rationale still holds |
| total added to `dev-flow.md` | — | 6 340 B / 59 260 B | **8 630 B of block content into 59 259 B → +14.6 %** (**+8 631 B** with the new bullet's line terminator — §6/A-34; the term does not move the percentage) |

**Where the 1 204 B of C-40 growth went — decomposed, because "it grew" is not a reason:**

```
  +  496 B   A-25 mutation-hygiene bound          MANDATED by security F1 (it predicted ~200 B)
  +  440 B   A-23 semantic/syntactic ruling       MANDATED by qa M-2
  +  268 B   Origin rewrite, net                  dropped the encoded counts per qa B-1
  ------
  + 1204 B   5 015 -> 6 219
```

**All three are review-mandated; none is elective.** Two of them *strengthen* the detection axis the
R-c check cares about (A-23 rules a divergence on which the arms themselves were ambiguous; A-25 is a
security mitigation the reviewer requires before ship). **The operator ruled at 2.07× and the honest
figure is 2.56× — that is a re-affirmation the operator should make knowingly, not an assumption this
lane may carry.** It is listed in §10.

**Three trims, priced (RESTORED, D-08 — fold 1 offered two, so D-9 was ruled against an incomplete
menu), and one correction:** (a) drop the `(Origin: …)` narrative to its first two sentences —
**−888 B, not the −~1 400 B fold 1 stated. That estimate charged the whole Origin (1 386 B) while the
trim keeps its first two sentences (497 B): mispriced 1.58×, and it was the third estimate in this
section to miss.** `01c` measured V-TRIM-1 at 6/6 · 0/6 · 1.70× with **zero** corpus members lost, but
it costs the block its only worked instance, making C-40 the first control in the repo without one.
(b) Move instances (i)/(ii) to `docs/engineering-rules.md` — **reverses the absorption ruling; not
without one.** (c) **TRIM-C — encode C-40 as an amendment to the `## Objective exit criteria`
*Certainty* clause plus the one new static subject-naming sentence, *"roughly one third the bytes"*.**

> ⚠ **TRIM-C IS DISQUALIFIED — TWICE OVER — AND FOLD 2 STILL OFFERED IT AS *"the cheapest form"* WITH
> NO WARNING (A-37, `02b` §0(1)/§4/§5).** This is an operator-facing hazard, not a bookkeeping one: the
> trim menu as it stood **invited a ruling that would silently revert a mitigation the security lane
> required before ship.**
>
> 1. **It drops security `F1`'s mutation-hygiene bound.** `A-25`'s clause lives entirely inside C-40's
>    **DISCHARGE** span. TRIM-C names the *Certainty* clause and one static sentence — **neither is the
>    DISCHARGE span** — and the Certainty clause on disk carries **0 of 4** needles
>    (`restore-before-next-gate`, the where-it-runs bound, the contamination rationale, the
>    mutation-actually-applied confirmation). **Disqualifying regardless of its arm figures:** a form
>    that drops the restore obligation lets a mutation stay applied in a tree other sessions are
>    reading, which is indistinguishable from a real defect to everyone else — the exact hazard `F1`
>    raised, and the exact incident `BACKLOG.md:50` records.
> 2. **It is a ONE-LIMB form.** Limb 2 has no carrier in either named component (`drawn from the rule`,
>    `quantifies over`, `positive control shaped`, `consolidation that drops` — all **absent**). Measured
>    against the corrected 9-member corpus it is **6/9**, losing `V-4`, `V-5` (the limb-2 members, i.e.
>    the P-6/P-7 absorption content the operator ruled must live *inside* C-40) and `V-8`.
> 3. **It has no text, and its stated components price at a quarter of its stated total.** `02b` §4:
>    the two named components measure **535 B = 0.22×**, while *"one third"* of V-FULL-2 implies
>    **2 073 B**. **A shape whose named components price at a quarter of its claimed total is not a
>    costed option; it is an intention** — which is the honest reason it could not have been a third
>    menu item at `D-9` without being drafted first.
>
> **Consequence for the menu:** the length question is decided by `D-10` (2.56×, re-affirmed), and
> trim (c) is **not available** without re-opening a security mandate. Trims (a) and (b) stand as
> stated, with (b) still requiring the absorption ruling to be reversed.

**The R-c check itself is not like-for-like** (`01c` B-2, carried at §7.7): it prices a 3-candidate
absorbing control against a 1-candidate one, so it **will fire on every future absorbing control
regardless of density**. That is a defect in the gate, not in C-40 — but it is a reason to weight the
arm-2 justification, not to dismiss the breach.

---

## §10 — What I could not discharge

**Closed since fold 1, so the gate reader sees the real remaining surface** (qa m-5): items 1 and 5
below were fold 1's open items and are now shut. `AT-B64-01/02/03` **were** run — `01c` M-1…M-4 and
the QA reviewer's independent `rq_arms.py` both read C-40's actual bytes (`M-D`: corrupting the limb
markers takes the arm `6/6 → 0/6`, so the harness is a function of the text). `AT-B64-04` was run this
fold (§4.3). `SKILL.md` was read by the QA reviewer: **no overlap** (A-30). The R-c question is
**settled** by D-9 (A-27).

**Also closed this fold (fold 3), so the gate reader again sees the real remaining surface:**

- **Item 1 — the 2.07× vs 2.56× re-affirmation — is CLOSED** by operator ruling `D-10` on
  `02b-trimc-measurement.md`'s evidence (§9.1, A-39). It is retained below struck rather than deleted,
  because the *reason* it was open is the reason the ruling is a decision and not an assumption.
- **`U-3`(b) is CLOSED and was misreported as open** (A-41, audit §1.4). `01d` §U-3 lists two dropped
  lane observations; the second — QA §3.1's `subject(D)` being the M-1 mutant, with `A-3` blaming the
  architect draft alone — **is discharged by §10.2's first bullet**, which quotes `subject(D)`, cites
  `01b-qa-catalog.md:218-220`, and states the defect was in **both** lanes. `U-3`(b) was closed by the
  same +32 063 B that closed `U-2`; the read/write-race correction was applied to `U-2` and `U-1` and
  **not** to `U-3`, which was snapshotted under the identical condition. **Only `U-3`(a) stands** —
  QA §6's naive-AT self-application (`grep "can it go RED"` → 0, `grep "naive"` → 0), which is in no
  restoration set. `U-4` also stands and is **unclosable by any fold**: it is a finding about
  `02-review-architect.md`'s output format, and `01d`'s per-row format is its correct successor.

**Open, and honestly so:**

1. ~~**D-9 was ruled at 2.07×; the block is now 2.56×**~~ — **CLOSED by `D-10`** (§9.1, A-39). Every
   byte of the growth was review-mandated and decomposed, and the operator re-affirmed knowingly at the
   new figure on `02b`'s evidence. This was the last open item that could change shipped text.
1a. **`arch BLOCKER-1` is RE-OPENED: `AT-B64-04` has still never been executed against the bytes that
   ship** (A-31/A-40, audit §3.4 **FINDING B**). Its fold-2 discharge measured the superseded 890 B
   rider body, and one of its two published mutations is **impossible** against the 1 975 B shipping
   body. `AT-B64-04` is the **sole load-bearing acceptance for `US-B64-2`**, so re-running it against
   §3.0's frozen `§3.2` hash — with mutations drawn from the *shipping* clause set — is a **blocking
   Inc-3 gate condition**, not a checklist line. **This is the only item on this list that leaves a
   story uncovered.**
1b. **`PP-5` is specified and NOT executed** (A-38) — an open `C-40` debt on the batch's own control.
   Declared expectations only; the measurement pass runs it and Inc-4 blocks on it.
1c. **Every arm figure in this document is STALE** (A-40) and the measurement pass owns them. The
   admissibility rule is stated at §4's banner: **a re-measured figure must name the §3.0 block hash it
   was taken against.**
2. **Recording D-9 in `PLAN.md` §10 and `state.json` is the orchestrator's write, not this lane's**
   — my write surface is this document plus `01d-union-ledger.md`. §9.3 item 7 stays ⚠ until that
   lands. The batch's own authorization commitment (`PLAN.md:43-45`) requires it.
3. **The arms must be re-run against the PASTED bytes at Inc-3, not against §3's fenced blocks.**
   Everything executed so far reads the fence. A paste that mangles a limb marker would pass every
   check in this document and fail only at the destination. §9.2 carries it.
4. **`AT-B64-05`'s scan of the rider is still partly self-scan.** I re-ran it over the **grown**
   1 976 B body (0/12 terms), but the author scanning their own text is P-6 in miniature; the QA lane
   re-ran the 889 B version independently and must re-run the grown one.
5. **The `2201 passed` baseline is now carried by four lanes and re-derived by none.** Phase-3 gate
   item. It is the oldest un-re-derived number in the batch and it has survived every fold that
   demanded numbers be re-derived — worth naming as such.
6. **`[travels]` has no formal definition** found in the skill; three lanes now infer it from usage.
7. **Limb 2 remains inspection, not test** — deciding *"drawn from the rule or from the
   implementation?"* requires reading the rule. Each limb-2 verdict carries a `file:line` to the
   executed refutation that established it; that is the strongest available form, not a mechanised one.
8. **The union ledger's own completeness is a claim about a claim.** It is built from the reviewer's
   163-item enumeration; if that enumeration missed a union item, the ledger inherits the miss and
   cannot detect it. The reviewer's method (audit the SOURCES, not the amendment table) is the right
   one, and it is still one pass by one party.

### §10.1 — Discrimination findings restored from the architect lane (D-05, D-06, D-07, D-09)

Fold 1 dropped these; they are the reasoning behind rulings the operator is asked to make, and a
ruling made with its reasoning removed is not the same ruling.

- **D-05 — the idea pre-exists in THREE places, not one.** C-40's EXTENDS clause names the *Certainty*
  clause (`dev-flow.md:99`). It also pre-exists at **`dev-flow.md:177`** (C-19, *"the RED
  counterfactual"* as gate evidence) and at **`VERIFY.md:40-49`** (the complete mutation loop, whose
  parenthetical C-40's own Origin reuses nearly verbatim). **Stated three times, and batch-63 produced
  a growing corpus of vacuous predicates anyway** — which is the strongest argument that the novelty
  is the *binding*, not the idea, and understating the overlap weakens rather than strengthens the case.
- **D-06 — LLR-B64-1.5's rationale.** The recommendation is to apply it: without a cross-reference at
  `:99`, the flow states the same requirement twice, in two registers, at two enforcement points, **and
  they will drift.** C-40's EXTENDS clause closes it from one side only. Fold 1 kept the LLR as a bare
  `*(OPTIONAL — operator call)*` row with the reasoning deleted.
- **D-07 — the working behind C-42's distinctness claim.** *Apply C-32 to `"](" not in note`: C-32 asks
  whether you read the painted surface instead of the pre-layout proxy; the report has no painted
  surface and no compositor. **C-32 has no purchase; the case is untouched.*** The claim is true and
  was unverified — the reviewer raises this as MAJOR-3, since `AT-B64-03` exists for exactly this
  purpose on C-40 and C-42 has no equivalent. **Recorded as a known asymmetry, not closed.**
- **D-09 — the alternative F-1 ruling and its consequence.** If the operator decides a global control
  may cite **no** project identifier at all — stricter than the file currently follows — then
  **C-35's existing `(Origin: …)` is already in violation** (it carries `ASAP2_Demo_V161.a2l`,
  `parse_a2l_file`, `parse_characteristic_header`, `CHARACTERISTIC`, `char_type`) and that is a
  separate cleanup item, not a batch-64 blocker. The current draft assumes the house precedent:
  identifiers permitted in Origins only.
- **D-19/D-20, restored inline:** LLR-B64-2.2's forbidden class includes **"or fixture"** — material,
  because `chk.json` is precisely a `tests/` fixture name (§0 R-4), and fold 1 narrowed the class
  without an amendment row. And `dev-flow.md:202`'s `Textual` is **normative** (*"Layer B … exercise
  the system as the user — Textual Pilot end-to-end"*), not an Origin example — so it could not be
  removed even if the stricter F-1 reading were adopted.
- **D-16/D-17/D-18, restored:** `AT-B64-01`'s **second** reddening mutation (move S-6 into the positive
  corpus → the arm drops → RED, proving the arm is not one-sided); `AT-B64-05`'s **"note against
  myself"** (the QA lane's first harness lacked word boundaries and reported `Rich = 1`/`AST = 11`,
  reproduced and recorded rather than quietly fixed — the same shape as my own `re.MULTILINE` defect
  at §4.4); and the caveat that **`S-5`/`TC-441` was never shipped** — a valid negative-control
  *predicate*, not a running test, which matters because it is 1 of the 6 (A-22).

### §10.2 — Two residual weaknesses carried openly rather than closed

- **The QA catalog's own formal statement of limb 1 still carries the defect A-23 repairs.**
  `01b-qa-catalog.md:218-220` defines *"`subject(D)` = the artifact or symbol `D` modifies"* — which is
  the writer, i.e. exactly the M-1 mutant that false-positives `S-6`. A-3 attributed the defect to the
  architect draft alone; it was in **both** lanes. The catalog remains on disk as the harness's
  specification, so **a future re-run against §3.1's definition rather than against the encoded
  control text will reproduce the S-6 false positive.** Flagged here because the fix belongs to the
  catalog's author, not to this document.
- **`AT-B64-05` has no non-emptiness guard**, asymmetric with `AT-B64-08`, which `01c` §7 gave one. A
  grep for forbidden terms over an **empty** region returns 0 and reads as GREEN, so the arm cannot
  distinguish *"the rider is stack-free"* from *"the rider is absent"*. PP-2 (§4.5) covers the absence
  case at Inc-3, which is why this is carried rather than blocking — but the two checks must be run as
  a pair, and that dependency is now stated instead of implicit.
