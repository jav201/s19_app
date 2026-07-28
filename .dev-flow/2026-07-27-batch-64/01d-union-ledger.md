# batch-64 — UNION LEDGER (`01d`)

> **What this file is.** One row per union item enumerated from the two Phase-1 source lanes
> (`01-requirements-architect.md`, `01b-qa-catalog.md`), each with an explicit disposition drawn from
> exactly three tokens — `CARRIED`, `RETIRED`, `RESTORED-THIS-FOLD`. There is no fourth category.
> A union item that cannot be placed in one of the three is reported in **§U — Unplaceable rows**,
> never omitted.
>
> **Why it exists.** The Phase-2 architect review (`02-review-architect.md` §1.1) audited fold 1
> against the source lanes and found **163 union items · 136 carried · 7 retired with reason ·
> 20 DROPPED with no retirement line**. The fold that encodes *"a consolidation that drops observables
> … an id-range table is a container, not evidence of preservation"* dropped twenty observables. This
> ledger is the structural repair: preservation becomes a per-item claim with a per-item evidence
> cell, not a summary line.

---

## §M — Method, and three things the reader must know before reading a count

**M-1 — the fold target moved twice while this ledger was being built, and the citations are pinned
to a snapshot.** `01-requirements-consolidated.md` was 398 lines / 45 377 B at 14:58 when this task
began; it was 430 lines / 53 281 B when first re-tested; it was **441 lines / 55 593 B at
2026-07-27 15:50:02 -0600** when snapshotted. Command output:

```
$ sha256sum consolidated.snapshot.md
a0868db7ba0313876b67be3ba54fa0241cbf760cfdd02a2a25c556db92d3e129
$ wc -l -c consolidated.snapshot.md
  441 55593
$ ls -la --time-style=full-iso 01-requirements-consolidated.md
-rw-r--r-- 1 jjgh8 197609 55593 2026-07-27 15:50:02.360498800 -0600
```

**Consequence, and it is a deliberate design choice:** every `CARRIED` cell cites a **section**
(`§3.1`, `§2.3 LLR-B64-1.1`), **not a `:line`**. Line numbers in this document are not stable across
a fold in progress — three of them shifted by 32 lines mid-task. A section cite survives an
in-place amendment; a line cite does not. The snapshot is preserved at
`…/scratchpad/consolidated.snapshot.md` so any cell here is re-checkable against a fixed byte string.

**M-2 — the granularity of this ledger is the BRIEF's, and it is strictly finer than the review's.**
The review states **163** but publishes only its 20 drops (§1.2); the 136 carried and the 7 retired
are **never enumerated anywhere**, so the 163 is not reproducible from the artifact. This ledger
enumerates at the granularity the ledger brief specifies — *each named clause group inside a control
block counts separately; each AT's sub-claims (observable, executed result, reddening mutation,
subject-in-expression verdict, verdict label) count separately*. Applied honestly, that definition
yields **more** items than 163, not fewer. **The review's 163 is not re-derived here and is not
disputed; it is a coarser count of the same material.** Both numbers are stated in §T so neither is
laundered into the other. See §U-4.

**M-3 — `RESTORED-THIS-FOLD` means "dispositioned by this fold", not "already on disk".** At snapshot
time D-01…D-04 had landed in §3.2's rider body; D-05…D-20 and R-8 had **not**. Executed:

```
D-01 "Also EXTENDS C-36"    hits=1  line 184   LANDED
D-02 "prefix guard"         hits=2  lines 85 184  LANDED (184 = rider body)
D-03 "quiet and symmetric"  hits=1  line 184   LANDED
D-04 "luck, not detection"  hits=1  line 184   LANDED
D-05 "C-19"                 hits=0             NOT LANDED
D-06 "will drift"           hits=0             NOT LANDED
D-07 "no purchase"          hits=0             NOT LANDED
D-08 "one third"            hits=0             NOT LANDED
D-09 "already in violation" hits=0             NOT LANDED
D-10 "VERIFY.md` gains"     hits=0             NOT LANDED
D-12 "Inspection"           hits=0             NOT LANDED
D-13 "unfilled template"    hits=0             NOT LANDED
D-14 "collision"            hits=0             NOT LANDED
D-15 "R-TUI-097"            hits=0             NOT LANDED
D-16 "6/7"                  hits=0             NOT LANDED
D-17 "word-boundary"        hits=0             NOT LANDED
D-18 "TC-441"               hits=0             NOT LANDED
D-19 "class, or fixture"    hits=0             NOT LANDED
D-20 ":202"                 hits=0             NOT LANDED
R-8  "placement predicate"  hits=1  line 91    AMENDMENT TABLE ONLY — no body section
```

The `LANDED` / `NOT LANDED` flag is recorded per row. **§U-2 reports what that flag exposes.**

**Legend.** `L-A` = lane architect (`01-requirements-architect.md`). `L-B` = lane QA
(`01b-qa-catalog.md`). `CONS §x` = `01-requirements-consolidated.md`, snapshot of 15:50:02.
`DUP-n` = cross-lane duplicate, counted once (§X).

---

## §A — LANE A: `01-requirements-architect.md` (482 lines)

### §A.0 — Executed-evidence rows (§0, E-1…E-11)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 1 | L-A `:31` E-1 | PRE line/byte/SHA256 for the three out-of-VCS files | CARRIED | `CONS §6` table, rows 1-3 — all three SHAs reproduced verbatim |
| 2 | L-A `:32` E-2 | `docs/engineering-rules.md` = 125 lines | CARRIED | `CONS §6` table row 4 (125 / 15 127 / `278b808d…`) — **DUP-7** |
| 3 | L-A `:33` E-3 | `C-40/41/42` boundary-correct id census = 13/10/11, resolving to batch-64's own proposal only; the ids are free | CARRIED | `CONS §1 A-6` ("My F-2 (green by construction)") + `§1.1 A-19` |
| 4 | L-A `:34` E-4 | stack-token baseline over the whole `dev-flow.md` (`Textual` 3, `AST` 1, rest 0) | CARRIED | `CONS §1 A-5` ("`Textual` ×3, `AST` ×1 pre-existing") |
| 5 | L-A `:35` E-5 | token locations `:57 :149 :177 :194 :202` — and the record that **`:202`'s `Textual` is NORMATIVE**, not an Origin example | RESTORED-THIS-FOLD | **D-20** — restored as a noted item. `A-5` carries only the count. NOT LANDED at snapshot. **DUP-5** |
| 6 | L-A `:36` E-6 | precedent: C-35's `(Origin: …)` carries five s19_app identifiers, so "no project identifier in a global control" is not the house rule | CARRIED | `CONS §3.2` prose — *"exactly as C-35's own `(Origin: …)` carries `ASAP2_Demo_V161.a2l`"* |
| 7 | L-A `:37` E-7 | `BACKLOG.md:143-144` footer stale at `C-1..C-36`; stack list omits C-32/C-34/C-37/C-38 | CARRIED | `CONS §2.3 LLR-B64-5.4` |
| 8 | L-A `:38` E-8 | the five vacuous predicates, `05-postmortem.md:59-65`, 3 of 5 the orchestrator's | CARRIED | `CONS §3.1` C-40 `(Origin: …)` |
| 9 | L-A `:39` E-9 | executed counterfactual `RED cases against the WRONG implementation: 0` | CARRIED | `CONS §3.1` `(Origin: …)`, quoted verbatim |
| 10 | L-A `:40` E-10 | diagnosis: *"both are pure functions of `lines`. The writer never appears in the expression"* | CARRIED | `CONS §3.1` `(Origin: …)` — **DUP-6** |
| 11 | L-A `:41` E-11 | P-3 running total disputed across three registers (`~7th` / `~9` / `8+`); ≥5 verifiable at `file:line` | CARRIED | `CONS §1 A-12` + `§7` carry 3 — **DUP-8** |

### §A.1 — Layer A N/A argument (§A.0)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 12 | L-A `:56-58` | ground 1 — there is no internal mechanism; the producer is the editing agent and the deliverable IS the file | CARRIED | `CONS §4` by explicit citation (*"both lanes concurring on independent arguments (`01-requirements-architect.md` §A.0…)"*) |
| 13 | L-A `:59-62` | ground 2 — every candidate TC collapses to `"<substring>" in <file>`, the form `VERIFY.md:36` condemns | CARRIED | `CONS §4`, same citation |
| 14 | L-A `:63-68` | ground 3 — the near-miss: HLR-B64-6's SHA/line reconciliation is the closest thing to Layer A and is still not it (double-counting = P-7) | CARRIED | `CONS §4`, same citation; `A-10` demotes AT-B64-11 to bookkeeping |
| 15 | L-A `:51-73` | **the `TC` layer declared N/A with reason** | RETIRED | Legitimate retirement 7 of 7 (review §1.1). **SUPERSEDED — see restoration set item R-8** (`CONS §1.1 A-24`: *"REFUTED BY EXECUTION … Layer A N/A is NO LONGER in this list"*). **DUP-1** |
| 16 | L-A `:70-73` | consequence — the batch carries ONE chain `US → HLR → LLR → AT → observed outcome` | CARRIED | `CONS §4` closing paragraph, verbatim |

### §A.2 — HLR register (§A.1)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 17 | L-A `:79` | HLR-B64-1 — C-40 in the global command | CARRIED | `CONS §2.1` HLR-B64-1 (amended, A-3/A-4) |
| 18 | L-A `:80` | HLR-B64-2 — C-41 stack-free normative body | CARRIED | `CONS §2.1` HLR-B64-2 (rewritten to the C-35 rider, A-1) |
| 19 | L-A `:81` | HLR-B64-3 — C-42 in `docs/engineering-rules.md` | CARRIED | `CONS §2.1` HLR-B64-3 (count fixed to five, A-9) |
| 20 | L-A `:82` | HLR-B64-4 — the `VERIFY.md` section extension | CARRIED | `CONS §2.1` HLR-B64-4, unchanged |
| 21 | L-A `:83` | HLR-B64-5 — lineage registers the ids; P-6/P-7 ABSORBED, P-3 DECOMPOSED | CARRIED | `CONS §2.1` HLR-B64-5 (+C-29, +C-41-free) |
| 22 | L-A `:84` | HLR-B64-6 — out-of-VCS PRE/POST record, event-driven | CARRIED | `CONS §2.1` HLR-B64-6 |
| 23 | L-A `:86-89` | traceability note: HLR-B64-6 has **four** parent stories; IEEE 830 permits a cross-cutting requirement provided each parent is named; the only many-to-one edge | ~~UNPLACEABLE~~ → **CARRIED** *(re-dispositioned at fold 3)* | **`CONS` §4.1.1** names all four parents in the US column and states the IEEE-830 justification; needles `IEEE 830` **2** / `many-to-one` **1** / `four parents` **1**. The `UNPLACEABLE` verdict was taken against this ledger's **15:50:02 snapshot**, before the +32 063 B that landed it — see **§U-1**, refuted and retained. The residual `*(cross-cutting)*` gloss is deleted at fold 3 (`CONS` A-42) |

### §A.3 — LLR register (§A.2)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 24 | L-A `:98` | LLR-B64-1.1 — C-40 inserted after the C-39 bullet | CARRIED | `CONS §2.3` LLR-B64-1.1 |
| 25 | L-A `:99` | LLR-B64-1.2 — two labelled example clauses, each a rule with its own discharge | CARRIED | `CONS §2.3` LLR-B64-1.3 (promoted to limb 2, A-4) |
| 26 | L-A `:100` | LLR-B64-1.3 — DISTINCT from C-10/C-31/C-39 + EXTENDS Certainty on three axes | CARRIED | `CONS §2.3` LLR-B64-1.4 (+ NOT-orthogonal-to-C-35, A-11) |
| 27 | L-A `:101` | LLR-B64-1.4 — *(OPTIONAL)* Certainty clause gains a cross-reference to C-40 | CARRIED | `CONS §2.3` LLR-B64-1.5, still `*(OPTIONAL — operator call)*` |
| 28 | L-A `:102` | LLR-B64-2.1 — C-41 block inserted immediately after C-40 | CARRIED | `CONS §2.3` LLR-B64-2.1, re-homed inside the C-35 bullet (A-1) |
| 29 | L-A `:103` | LLR-B64-2.2 — normative body free of the six tokens | CARRIED | `CONS §2.3` LLR-B64-2.2 (`AST` removed, A-5) |
| 30 | L-A `:103` | LLR-B64-2.2's forbidden-identifier class includes **"or fixture"** (*"module, function, class, or fixture identifier"*) | RESTORED-THIS-FOLD | **D-19** — restored as a noted item. `CONS §2.3` reads *"module/function/class identifier"*; material because `chk.json` is a `tests/` fixture name (§0 R-4). NOT LANDED |
| 31 | L-A `:104` | LLR-B64-2.3 — the control states its own placement boundary | CARRIED | `CONS §2.3` LLR-B64-2.3 |
| 32 | L-A `:105` | LLR-B64-3.1 — C-42 placed after `## C-38`, before `## C-34` | CARRIED | `CONS §2.3` LLR-B64-3.1 |
| 33 | L-A `:106` | LLR-B64-3.2 — enumerate six mechanics, each with its own discharge | CARRIED | `CONS §2.3` LLR-B64-3.2, count normalised to **five** (A-9) |
| 34 | L-A `:107` | LLR-B64-3.3 — C-42 opens by declaring the extension and the differing axis | CARRIED | `CONS §2.3` LLR-B64-3.3 |
| 35 | L-A `:108` | LLR-B64-4.1 — appended inside the existing section, no new `##` | CARRIED | `CONS §2.3` LLR-B64-4.1 |
| 36 | L-A `:109` | LLR-B64-4.2 — de-identification term list + generic illustration | CARRIED | `CONS §2.3` LLR-B64-4.2 |
| 37 | L-A `:110` | LLR-B64-4.3 — counterexample distinguishes from the pre-existing rule (*"read a genuine runtime value and therefore satisfied the pre-existing rule in full"*) | CARRIED | `CONS §2.3` LLR-B64-4.3 — **rewritten** to *"a genuine runtime value **and a false fail**"*; the rewrite is now declared at `§1.1 A-16` (review BLOCKER-2b discharged) |
| 38 | L-A `:111` | LLR-B64-4.4 — `[travels]` retained + the justifying test recorded | CARRIED | `CONS §2.3` LLR-B64-4.4 |
| 39 | L-A `:112` | LLR-B64-5.1 — one lineage entry in the house `**NEW C-NN …:**` form | CARRIED | `CONS §2.3` LLR-B64-5.1 |
| 40 | L-A `:113` | LLR-B64-5.2 — P-6/P-7 ABSORBED, P-3 DECOMPOSED, all four destinations named | CARRIED | `CONS §2.3` LLR-B64-5.2 (+ C-41 NOT CONSUMED) |
| 41 | L-A `:114` | LLR-B64-5.3 — `BACKLOG.md` footer corrected | CARRIED | `CONS §2.3` LLR-B64-5.4 (renumbered; 5.3 now registers C-29) |
| 42 | L-A `:115` | LLR-B64-6.1 — byte-identical backup before the first write | CARRIED | `CONS §2.3` LLR-B64-6.1 |
| 43 | L-A `:116` | LLR-B64-6.2 — PRE and POST rows with deltas | CARRIED | `CONS §2.3` LLR-B64-6.2 |
| 44 | L-A `:117` | LLR-B64-6.3 — POST SHA == PRE SHA on a claimed edit blocks the gate | CARRIED | `CONS §2.3` LLR-B64-6.3 |

### §A.4 — §B.1, the C-40 draft: named clause groups

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 45 | L-A `:130` | header rule — falsifiability is a SEPARATE gate question, answered at AUTHORING time by EXECUTION | CARRIED | `CONS §3.1`, opening clause verbatim |
| 46 | L-A `:130` | scope enumeration — `AT` · `LLR` acceptance clause · `TC` · **any measurement probe whose number a gate is keyed on** | CARRIED | `CONS §3.1`, verbatim |
| 47 | L-A `:130` | clause (a) — name the component under test and confirm it appears in the predicate's own expression | CARRIED | `CONS §3.1` **LIMB 1**, re-keyed to *"the subject the predicate itself declares"* (A-3) |
| 48 | L-A `:130` | clause (b) — name the concrete mutation that turns the predicate RED | CARRIED | `CONS §3.1` **DISCHARGE for both limbs** |
| 49 | L-A `:130` | clause (c) — execute the mutation, paste the transcript, confirm the mutation actually applied | CARRIED | `CONS §3.1` DISCHARGE, incl. *"a typo'd mutation also 'fails', for the wrong reason"* |
| 50 | L-A `:130` | *"inert: rewrite it, do not re-argue it"* | CARRIED | `CONS §3.1`, verbatim |
| 51 | L-A `:130` | the static half — *read the expression and ask which symbol in it the implementation could move*; two pure functions of the same input certify arithmetic | CARRIED | `CONS §3.1`, verbatim |
| 52 | L-A `:130` | DISTINCT from C-10 (code) / C-31 (input set) / C-39 (threshold) | CARRIED | `CONS §3.1` DISTINCT clause |
| 53 | L-A `:130` | EXTENDS the Certainty clause on three named axes (gate-exit→authoring; `AT-NNN`→every predicate; shown→executed) | CARRIED | `CONS §3.1` EXTENDS clause, all three axes intact |
| 54 | L-A `:130` | named instance (i) — a positive control shaped to the IMPLEMENTATION not the RULE | CARRIED | `CONS §3.1` *(i)*, promoted to a limb-2 instance (A-4) |
| 55 | L-A `:130` | named instance (ii) — a consolidation that drops observables; the union is the subject; carry forward **or** print a retirement line | CARRIED | `CONS §3.1` *(ii)*, verbatim — and the clause this ledger discharges |
| 56 | L-A `:130` | `(Origin: batch-63 …)` — the five predicates, the executed `0`, `AT-193b`, the revision-3 fold's 8 of ~18 | CARRIED | `CONS §3.1` `(Origin: …)`, extended with V-6 |

### §A.5 — §B.2, the C-41 draft: named clause groups

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 57 | L-A `:135-138` | the deliberate-circumlocution note (name the technique, not the tool) as the mechanism that keeps the constraint | CARRIED | `CONS §3.2` prose — *"the 'structured output' clause is the half that carries C-42's placement boundary"* + stack-free scan |
| 58 | L-A `:141` | rule sentence — a predicate about produced output is written against the bytes/tokens the PRODUCER emits | CARRIED | `CONS §3.2` rider, opening clause |
| 59 | L-A `:141` | *"Producers escape, encode, wrap and substitute"* → a search for the readable form **false-fails a CORRECT implementation** | CARRIED | `CONS §3.2` rider, verbatim |
| 60 | L-A `:141` | *"The failure is quiet and symmetric … it returns a plausible number, so a predicate that under-counts by two orders of magnitude reads as a measurement rather than as a bug"* | RESTORED-THIS-FOLD | **D-03** — restored into the C-35 rider's normative body. **LANDED** (snapshot `:184`, verbatim) |
| 61 | L-A `:141` | discharge, mechanically — run the producer → paste the emitted bytes → write the predicate against the paste | CARRIED | `CONS §3.2` rider |
| 62 | L-A `:141` | prefer the producer's own **structured** output (token stream, language-aware parse) over a substring search | CARRIED | `CONS §3.2` rider, verbatim |
| 63 | L-A `:141` | rider spelling 1 — a `startswith`/**prefix guard** over a formatted line (widths/separators/padding are the producer's choice) | RESTORED-THIS-FOLD | **D-02** — restored into the C-35 rider's normative body. **LANDED** (snapshot `:184`) |
| 64 | L-A `:141` | rider spelling 2 — a hand-listed character class standing in for *"this field is inert"* | CARRIED | `CONS §3.2` rider (*"never against a character list"*); the full three-spellings form is now restored alongside D-02 |
| 65 | L-A `:141` | rider spelling 3 — a predicate written from the requirement's wording instead of from the output | CARRIED | `CONS §3.2` rider (*"the spec's own vocabulary for the thing"*) |
| 66 | L-A `:141` | corollary — *"an **impossible** value is luck, not detection"*; an under-counting predicate that stays plausible ships | RESTORED-THIS-FOLD | **D-04** — restored as a normative clause (was demoted to a parenthetical inside `(Measured: …)`, where the F-1 ruling puts it out of normative scope). **LANDED** (snapshot `:184`) |
| 67 | L-A `:141` | EXTENDS **C-35** — from *existence* to *exact emitted form* | CARRIED | `CONS §3.2` — the whole leg is now a rider **on** C-35 (A-1), which is the strongest possible form of this relation |
| 68 | L-A `:141` | EXTENDS **C-36** — from the source-side definition to the output-side encoding; a literal can satisfy C-36 completely and still be unfindable in the output. Plus §C.2's working (`:260-266`) that C-41 catches a case C-36 satisfies in full | RESTORED-THIS-FOLD | **D-01** — restored into the C-35 rider's normative body. **LANDED** (snapshot `:184`: *"Also EXTENDS C-36 … so C-36 and this rider fail independently"*) |
| 69 | L-A `:141` | placement clause — stack-specific traps belong in `docs/engineering-rules.md`, never here | CARRIED | `CONS §3.2` rider, verbatim |
| 70 | L-A `:141` | `(Origin: …)` — ≥5 occurrences verified at `file:line`; cite the enumeration, never the total | CARRIED | `CONS §3.2` `(Measured: …)`; total suppressed per A-12 |

### §A.6 — §B.3, the C-42 draft

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 71 | L-A `:150-151` | heading + opening declaration: extends C-32/C-37, differing on the producer under test | CARRIED | `CONS §3.3`, verbatim |
| 72 | L-A `:153` | mechanic — assert markup token TYPES, not substring presence; baseline subtraction is blind by construction | CARRIED | `CONS §3.3` Mechanic 1 |
| 73 | L-A `:154` | mechanic — `&`-entity spoofing forges a structural delimiter while every token stays `text` | CARRIED | `CONS §3.3` "Mechanic 1, second face" |
| 74 | L-A `:155` | mechanic — the escaped form of a character is not the character (`"](" not in note` → `\](`) | CARRIED | `CONS §3.3` Mechanic 2 |
| 75 | L-A `:156` | mechanic — Mode-B code spans make a heading unfindable by its bare form; caught only by an impossible `-1` | CARRIED | `CONS §3.3` Mechanic 3 |
| 76 | L-A `:157` | mechanic — snapshot export text carries `&#160;` entities; a literal grep matched **0 of 19** | CARRIED | `CONS §3.3` Mechanic 4 — the figure is now **0 of 29 / 29 of 29** (live in-repo reproduction), declared at `§1.1 A-16` (review BLOCKER-2a discharged) |
| 77 | L-A `:158` | mechanic — use an AST census, not a regex, for any predicate over source lines | CARRIED | `CONS §3.3` Mechanic 5 |
| 78 | L-A `:106`,`:153-154` | the **sixth** C-42 mechanic | RETIRED | Legitimate retirement 3 of 7 — `A-9`: *"a presentation split inside one mechanic, not a sixth"*, ruled so that AT-B64-06's 5-row table does not false-fail on a bullet count |
| 79 | L-A `:160` | discharge for any new predicate on these paths — run, paste, write against the paste, then apply C-40 | CARRIED | `CONS §3.3` discharge paragraph, verbatim |
| 80 | L-A `:160` | `(Origin: five instances across batches 60-63, four false-failing a correct artifact …)` | CARRIED | `CONS §3.3` `(Origin: …)`, verbatim |

### §A.7 — §B.4, the `VERIFY.md` extension

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 81 | L-A `:169-176` | paragraph 1 — a runtime value is not enough; the snapshot-export search returns zero against a completely correct app | CARRIED | `CONS §3.4` para 1, verbatim |
| 82 | L-A `:178-183` | paragraph 2 — identify the producer, run it, look at what it emitted; the impossible-value tell | CARRIED | `CONS §3.4` para 3, verbatim |
| 83 | L-A `:186-190` | the `[travels]` test applied rather than asserted — the mechanism holds for HTML/ANSI/XML/SVG/JSON/escapers | CARRIED | `CONS §3.4` closing prose, verbatim |
| 84 | L-A `:191-192` | de-identification check — no `CRC Designer`, `s19`, `a2l`, `mac`, no repository path | CARRIED | `CONS §2.3 LLR-B64-4.2` + `§3.4` |

### §A.8 — §C.1, the C-40 discrimination argument

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 85 | L-A `:211` | C-10 applied to predicate #1 → stays GREEN; measured `RED … : 0` | CARRIED | `CONS §3.1` DISTINCT clause + `§4` AT-B64-03 |
| 86 | L-A `:212` | C-31 applied → not applicable, the assertion quantifies over nothing | CARRIED | `CONS §3.1` DISTINCT clause |
| 87 | L-A `:213` | C-39 applied → satisfied and still vacuous | CARRIED | `CONS §3.1` DISTINCT clause |
| 88 | L-A `:214` | C-40 applied → RED at authoring time; the static half fails without running anything | CARRIED | `CONS §3.1` "The static half is free" |
| 89 | L-A `:220-223` | the idea pre-exists at `dev-flow.md:99`, the Certainty exit criterion (*"No pass that cannot fail"*) | CARRIED | `CONS §3.1` EXTENDS clause, quoting `:99` |
| 90 | L-A `:224`,`:226-227` | the idea **also** pre-exists at `dev-flow.md:177` (C-19, *"the RED counterfactual"*) and at `VERIFY.md:40-49` (the full mutation loop) | RESTORED-THIS-FOLD | **D-05** — restored as spec prose. `grep -c "C-19"` → `CONS` **0**; the block currently claims to EXTEND the Certainty clause **alone**, understating the restatement. NOT LANDED |
| 91 | L-A `:233-236` | binding 1 — enforcement point relocated from gate to per-predicate authoring time, the same move C-39 made for thresholds | CARRIED | `CONS §3.1` EXTENDS axis 1 |
| 92 | L-A `:237-239` | binding 2 — scope widened past `AT-NNN` to LLR/TC/probe, because the defects were not `AT-NNN`s | CARRIED | `CONS §3.1` EXTENDS axis 2 |
| 93 | L-A `:240-243` | binding 3 — the static subject-naming test; C-40's one genuinely new sentence | CARRIED | `CONS §3.1` "The static half is free" |
| 94 | L-A `:245-250` | the recommendation to apply LLR-B64-1.4, **plus its drift argument** (*"the flow states the same requirement twice … and they will drift"*) | RESTORED-THIS-FOLD | **D-06** — restored as spec prose. `CONS §2.3 LLR-B64-1.5` survives as a bare `*(OPTIONAL — operator call)*` row with the rationale removed, so the operator is asked to rule with the reasoning deleted. NOT LANDED |
| 95 | L-A `:252-258` | absorption check — both P-6 and P-7 are caught by the same subject-naming clause, which is the operator's stated reason for absorbing rather than tripling | CARRIED | `CONS §1 A-4` + `§3.1` instances (i)/(ii) |

### §A.9 — §C.2, C-41 vs C-35 / C-36

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 96 | L-A `:268-274` | against C-35 the margin is thin and is one sentence wide — executing the producer passes the code-span case while the predicate stays unfindable | CARRIED | `CONS §3.1` *"NOT orthogonal to C-35"* + `§3.2` rider's opening delta |
| 97 | L-A `:276` | verdict: **C-41 is ~70 % C-35**; not a pure restatement, but not worth a free-standing peer's prose | CARRIED | `CONS §1 A-1`, quoted (*"~70 % C-35 … the cheaper form"*) |
| 98 | L-A `:279-283` | the stated alternative — encode as a rider on C-39/C-35 at ~600 B instead of ~2 000 B, recorded so the ruling is made against a stated alternative | CARRIED | `CONS §1 A-1` — the operator ruled **for** this alternative; `§9` "≥2 alternatives considered" |

*(§C.2's working that C-41 catches a case C-36 provably does not is union item **68** — D-01 — counted once, not twice.)*

### §A.10 — §C.3, C-42 and the `VERIFY.md` extension vs their neighbours

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 99 | L-A `:287-295` | the working that C-42 is distinct from C-32/C-37 — *"apply C-32 to `"](" not in note`: the report has no painted surface and no compositor; **C-32 has no purchase; the case is untouched**"* | RESTORED-THIS-FOLD | **D-07** — restored as spec prose (discrimination finding). Only C-42's own self-declaration survives; `grep "no purchase"` → `CONS` **0**. Review MAJOR-3: the `extends C-32/C-37` claim has no AT either. NOT LANDED |
| 100 | L-A `:297-302` | the `VERIFY.md` extension refutes its own section — the pre-existing rule has a measured counterexample inside its own scope; verdict NOVEL, ship first | CARRIED | `CONS §3.4` closing prose + `§4` AT-B64-09 (**LOAD-BEARING — carries US-B64-4**) |

### §A.11 — §C.4, the two blocking findings

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 101 | L-A `:308-315` | **F-1 BLOCKING** — the AT-B64-05 stack-free predicate is RED against the current, correct `dev-flow.md` (`Textual` ×3, `AST` ×1) | CARRIED | `CONS §1 A-5` |
| 102 | L-A `:318-322` | F-1's fix — scope the predicate to the **normative body**, explicitly excluding the `(Origin: …)` parenthetical, and state the whole-file baseline so the exclusion is visibly a boundary decision | CARRIED | `CONS §2.3 LLR-B64-2.2` + `§3.2` prose |
| 103 | L-A `:313-316` | the house-precedent contradiction — C-35's own block carries five s19_app identifiers, so the stricter rule is contradicted by the house's own precedent | CARRIED | `CONS §3.2` prose, naming `ASAP2_Demo_V161.a2l` |
| 104 | L-A `:325-329` | self-check of the §B.2 draft — all terms 0 — **and the honest caveat that a scan of one's own text is not a gate** | CARRIED | `CONS §3.2` + `§10.2` (*"treating the author's own scan as the gate is P-6 committed inside the batch encoding P-6"*) |
| 105 | L-A `:331-337` | **F-2 BLOCKING** — the AT-B64-10 census is GREEN by construction; 13/10/11 hits resolve to batch-64's own proposal artifacts | CARRIED | `CONS §1 A-6` |
| 106 | L-A `:338-342` | F-2's fix — scope the census to the encoding destinations for "encoded" and the lineage record for "registered", with `.dev-flow/**` excluded from both | CARRIED | `CONS §1 A-6` + `§4` AT-B64-10 |
| 107 | L-A `:344-346` | positive note — with that scoping the census can fail in **both** directions (encode and forget → RED; register and skip the paste → RED) | CARRIED | `CONS §4` AT-B64-10 (*"bidirectional … strongest mechanical AT"*); strengthened at `§1.1 A-19`/`A-20` |

### §A.12 — §D, the increment plan

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 108 | L-A `:355` | Inc-0 — PRE rows + backups; edits no destination; must precede the first write | CARRIED | `CONS §5` Inc-0 |
| 109 | L-A `:356` | Inc-1 — C-42 first, the only leg a PR/CI/diff review can see | CARRIED | `CONS §5` Inc-1 |
| 110 | L-A `:357` | Inc-2 — the `VERIFY.md` extension, fully independent | CARRIED | `CONS §5` Inc-2 |
| 111 | L-A `:358` | Inc-3 — the global command in ONE atomic write | CARRIED | `CONS §5` Inc-3 (now two regions of the same file) |
| 112 | L-A `:359` | Inc-4 — lineage + BACKLOG + POST rows | CARRIED | `CONS §5` Inc-4 — POST rows since re-homed per `§1.1 A-26` |
| 113 | L-A `:366-367` | R-d observation 1 — the running instance is not live-reloaded, so the risk is not self-modification | CARRIED | `CONS §5` R-d paragraph, verbatim |
| 114 | L-A `:368-371` | R-d observation 2 — the real exposure is a resume or interruption; the hazard is the **half-edited window** | CARRIED | `CONS §5` R-d paragraph, verbatim |
| 115 | L-A `:372-375` | R-d observation 3 — minimise the window; one atomic write beats two writes at any position | CARRIED | `CONS §5` R-d paragraph, strengthened by the two-region argument |
| 116 | L-A `:377-378` | Inc-1 before Inc-3 means an interrupted batch has already banked its most reviewable leg | CARRIED | `CONS §5` Inc-1 (*"bank it first"*) |

### §A.13 — §E, the out-of-VCS evidence design

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 117 | L-A `:389` | the artifact `03-out-of-vcs-evidence.md` is named as the destination | CARRIED | `CONS §2.3 LLR-B64-6.1` + `§5` Inc-0/Inc-4 |
| 118 | L-A `:394-403` | the PRE capture command + backup copy loop | CARRIED | `CONS §6` (*"Backups to `.dev-flow/2026-07-27-batch-64/backup-pre/`"*) |
| 119 | L-A `:407-414` | the PRE/POST table shape — one row per file per state, with backup path | CARRIED | `CONS §6` table + `§2.3 LLR-B64-6.2` |
| 120 | L-A `:418-421` | property 1, **change proof** — an unchanged hash on a claimed edit is a failed increment, not a note | CARRIED | `CONS §6` (*"change proof (LLR-B64-6.3 …)"*) |
| 121 | L-A `:422-427` | property 2, **bounded delta** — record Δlines/Δbytes and state the expected magnitude **before** the edit; `dev-flow.md` gains 2 lines | CARRIED | `CONS §6` — expected delta stated for `dev-flow.md` only |
| 122 | L-A `:424` | the expected deltas for **`VERIFY.md`** (the extension paragraph block) and the **lineage memory** (1 entry) | RESTORED-THIS-FOLD | **D-10** — restored into the out-of-VCS evidence section. 2 of 3 bounded-delta checks are otherwise unarmed while `§6` claims bounded delta as one of *"three properties that make this a check rather than a log"* (review MAJOR-10). NOT LANDED at the 15:50:02 snapshot → **LANDED, verified by the discharge audit §2** → ⚠ **LANDED BUT DEFECTIVE, and REPAIRED at fold 3:** the restored `dev-flow.md` row's decomposition read `6 219 + 1 522 = 8 630`, missing its own total by **exactly the phantom 889 B fold-1 rider that is not on disk** (audit §5.3 FINDING C). **`CONS` §6 now carries 6 rows — one per edited file — every Δbytes re-derived from `CONS` §3.0's frozen block hashes with framing terms named** (`CONS` A-34/A-35). *(Register note: this `D-10` is a restoration id; operator ruling `D-10` — re-affirm C-40 at 2.56× — is a different register sharing the string. See `CONS` §7.9.)* |
| 123 | L-A `:428-429` | property 3, **restorability** — the backup path is recorded and its SHA equals the PRE hash | CARRIED | `CONS §6` (*"restorability (backup SHA256 = PRE SHA256)"*) |
| 124 | L-A `:431-433` | the obligation to **cross-reference the pasted text from the evidence artifact** so a reviewer can diff §3 against the POST file — *"the only external reviewer these legs get"* | RESTORED-THIS-FOLD | **D-11** — restored into the out-of-VCS evidence section. NOT LANDED at the 15:50:02 snapshot → **LANDED, verified by the discharge audit §2** → ⚠ **LANDED BUT UNDISCHARGEABLE for 2 of 6 destinations, and CLOSED at fold 3:** `CONS` §3 carried paste text for four files; the **lineage memory** and **`.dev-flow/BACKLOG.md`** had none, and the lineage memory is precisely a leg with no PR, no CI and no diff (audit §5.2). **`CONS` §3.5 and §3.6 now exist** (A-32/A-33), and the obligation is re-stated to cite **the §3.0 block hash** per file, not the section number — a section number does not pin bytes. *(Register note: operator ruling `D-11` — batch-62 host-path redaction, WITHDRAWN — is a different register sharing the string.)* |

### §A.14 — §F, the architect evidence checklist (8 rows)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 125 | L-A `:441` | constraints stated explicitly (zero-code surface, ≤5 files/increment, stack-free boundary, de-identification, `shall` discipline) | CARRIED | `CONS §9` row 1 |
| 126 | L-A `:442` | ≥2 alternatives considered (C-41 as control vs rider; C-40 as drafted vs amending `:99`; C-42 placement) | CARRIED | `CONS §9` row 2 — but see item **131** (D-08): only two of the three alternatives survive |
| 127 | L-A `:443` | recommendation tied to constraints (Inc order derived from R-d + the in-VCS/out-of-VCS split) | CARRIED | `CONS §9` row 3 |
| 128 | L-A `:444` | risks listed (F-1, F-2, control bloat quantified, registry drift, the half-edited window) | CARRIED | `CONS §9` row 4 |
| 129 | L-A `:445` | cost estimated — reader cost measured as bytes added to a file read every batch | CARRIED | `CONS §9` row 5 + `§9.1` (measured, and two estimates recorded wrong) |
| 130 | L-A `:446` | diagram omitted deliberately, recorded as a considered omission | CARRIED | `CONS §9` row 6 |
| 131 | L-A `:447` | what would change the recommendation → §G | CARRIED | `CONS §9` row 7 → `§10` |
| 132 | L-A `:448` | two-layer requirements ✓ with a declared N/A the reviewer must accept or reject explicitly | CARRIED | `CONS §9` row 8 — the N/A itself is item **15** (RETIRED / superseded by R-8) |

### §A.15 — §G, what would change these recommendations

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 133 | L-A `:452-456` | alternative: C-40 as an **amendment to the Certainty clause + the one new static sentence — "roughly one third the bytes"** | RESTORED-THIS-FOLD | **D-08** — restored as spec prose (a stated alternative). Dropped at exactly `§9.1`, where the operator must rule on length; ruling D-9 was therefore made against **two** stated trims, not three (review MAJOR-5). NOT LANDED |
| 134 | L-A `:457-459` | alternative: fold C-41 into C-35 as a rider and free the id — the single largest length saving available | CARRIED | `CONS §1 A-1` — this is the ruling that was taken |
| 135 | L-A `:460-463` | the alternative F-1 ruling and its consequence: if a global control may cite **no** project identifier, then **C-35's `(Origin: …)` is already in violation** and that is a separate cleanup item | RESTORED-THIS-FOLD | **D-09** — restored as spec prose (a stated alternative). `grep "already in violation"` → `CONS` **0**. NOT LANDED |
| 136 | L-A `:464-465` | the course leg **US-B64-5** is OUT per operator ruling; if it returns, HLR-B64-6's parent set grows and the M13 harness gap must be resolved first | RETIRED | Legitimate retirement 5 of 7 — operator ruling. Recorded at `CONS §4.1` (*"**US-B64-5** (course leg) remains **OUT** per operator ruling, plan durable at `G:/My Drive/Courses/textual/PENDING-UPDATES.md`"*) |

### §A.16 — §H, what the architect lane could not verify

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 137 | L-A `:469-472` | the P-3 running total is unresolved; **the encoded text must not carry a total** | RETIRED | Legitimate retirement 6 of 7 — *any P-3 total in encoded text* (A-12). `CONS §1 A-12`: *"the encoded text carries **no** occurrence total; it enumerates"* |
| 138 | L-A `:473-474` | `~/.claude/skills/tui-design/SKILL.md` was never read; the extension could be redundant with it | CARRIED | `CONS §10.5`; since **CLOSED** at `§1.1 A-30` (QA reviewer read it: no overlap) |
| 139 | L-A `:475-477` | `[travels]` has no formal definition found in the skill; inferred from usage | CARRIED | `CONS §10.6`, verbatim |
| 140 | L-A `:478-479` | the course leg's `PENDING-UPDATES.md` was not opened, so its cross-references are unconfirmed | CARRIED | `CONS §4.1` names the durable plan path; the leg is out of scope (item **136**) |
| 141 | L-A `:480-482` | the author's own stack-free scan is evidence, not a gate; QA must re-run it against the final pasted bytes | CARRIED | `CONS §10.2`, verbatim |

---

## §B — LANE B: `01b-qa-catalog.md` (830 lines)

### §B.0 — BLUF claims (§0)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 142 | L-B `:12-19` | the corpus is **SIX**, not five — `V-6` found by *executing* the candidate control, not by reading summaries | CARRIED | `CONS §1 A-2` + `§0 R-1` (independently re-derived) |
| 143 | L-B `:22-25` | C-40 discriminates **only with two limbs**; a one-limb C-40 flags 4 of 6 and misses the two the operator ruled must be ABSORBED | CARRIED | `CONS §1 A-4` + `§3.1` LIMB 2 |
| 144 | L-B `:27-29` | three findings block the Phase-1 gate as specified | CARRIED | `CONS §1 A-5`, `A-6`, `A-7` |
| 145 | L-B `:31-34` | the AT classification — load-bearing {01,02,03,09,10} · weak {05,07,08} · bookkeeping {11} · unsatisfiable {04} | CARRIED | `CONS §4` status column, all eleven rows |

### §B.1 — Positive corpus, V-1…V-6, and its findings (§1)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 146 | L-B `:43-49` | **V-1** — qa lane's `len(join) == _line_bytes - 1` | CARRIED | `CONS §3.1` `(Origin: …)` (*"Five related an accounting helper to a string join"*); transcript cited at `§0` |
| 147 | L-B `:51-59` | **V-2** — architect lane's `_line_bytes >= len(join)` | CARRIED | `CONS §3.1` `(Origin: …)`; transcript cited at `§0` |
| 148 | L-B `:61-68` | **V-3** — the M-7 replacement keyed on `report_bytes` | CARRIED | `CONS §3.1` `(Origin: …)` + `§2.2` row 3 (worked in full against the amended wording) |
| 149 | L-B `:77-99` | **V-4** — `AT-165`, shaped to the concatenation rather than to the evidence; refuted by execution | CARRIED | `CONS §1 A-4` names it explicitly (*"missing exactly `AT-165` and `AT-193b`"*); `§4` AT-B64-01 asserts all six |
| 150 | L-B `:101-133` | **V-5** — `AT-193b`, the positive control shaped to the DETECTOR; delta 5→11 offending, 4→7 clean | CARRIED | `CONS §3.1` instance *(i)*, incl. the omitted `p.open("w")` idiom |
| 151 | L-B `:135-178` | **V-6** — `AT-172b`, a tautology, live on `main`; NEW, found by this lane | CARRIED | `CONS §0 R-1` (re-derived), `§1 A-2`, `§7` carry 1 |
| 152 | L-B `:70-75` | V-3's in-place refutation — *"'cannot bind pre-fix' is a property of the SYMBOL, not of the DEFECT"* | CARRIED | `CONS §3.1` `(Origin: …)` + `§2.2`'s V-3 row |
| 153 | L-B `:162-172` | V-6's executed 4-cell table — `AT-172b RED cases over {pre,post} × {LF,CRLF}: 0`; only reddening path is invalid UTF-8 | CARRIED | `CONS §0 R-1`, re-derived over three writer states; `§3.1` `(Origin: …)` states the 4-cell result |
| 154 | L-B `:180-186` | the contrast with `AT-173b`'s second clause (sound, because it compares against an **independently composed** document) | CARRIED | `CONS §7` carry 1 (*"Fix shape (by analogy with the sound `tests/test_flow_report_service.py:497`)"*) |
| 155 | L-B `:187-188` | V-6 is a live defect on `main`, out of batch-64's scope, carried forward | CARRIED | `CONS §7` carry 1, incl. the D-5 constraint on touching `tests/` |

### §B.2 — Negative control group, S-1…S-6 (§2)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 156 | L-B `:199` | **S-1** — `AT-172`, monkeypatched encoder sentinel | CARRIED | `CONS §4` AT-B64-02 (*"flags none of the six sound controls"*); transcript cited at `§0` |
| 157 | L-B `:200` | **S-2** — `AT-173`, the same seam for `write_flow_report` | CARRIED | `CONS §4` AT-B64-02, same citation |
| 158 | L-B `:201` | **S-3** — `AT-173b` clause 2, compares against an independently composed document | CARRIED | `CONS §4` AT-B64-02 + `§7` carry 1 (named as the fix shape); re-classified at `§1.1 A-22` as CI-dead |
| 159 | L-B `:202` | **S-4** — `AT-193`, AST census with an import-graph-derived set and a non-emptiness guard | CARRIED | `CONS §4` AT-B64-02, by citation |
| 160 | L-B `:203` | **S-5** — `TC-441` / `LLR-100.2`, the counting-iterable probe | CARRIED | `CONS §4` AT-B64-02, by citation; re-classified at `§1.1 A-22` (*"not a shipped test"*) |
| 161 | L-B `:204` | **S-6** — `AT-174b`, partition-invariance; *"the sharpest control"*, sound although the writer is absent | CARRIED | `CONS §2.2`, worked in full across three wordings |
| 162 | L-B `:206-207` | S-6 exists specifically to falsify a lazy C-40 keyed on *"the writer must appear"* | CARRIED | `CONS §2.2` row 1 (*"FLAG → false positive. Matches QA's executed mutant exactly"*) + `§4` AT-B64-02 |

### §B.3 — The discriminator, built and executed (§3)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 163 | L-B `:216-220` | `subject(D)` defined as *"the artifact or symbol `D` modifies"* | CARRIED | `CONS §3.1` LIMB 1, **amended** to the predicate's *declared* subject (A-3). See **§U-3** — QA's own §3.1 wording is the M-1 mutant and remains uncorrected on disk |
| 164 | L-B `:218-220` | **LIMB 1 — subject-reference**: FLAG if `P`'s value is invariant under `D` | CARRIED | `CONS §3.1` LIMB 1, incl. the semantic/syntactic divergence ruling at `§1.1 A-23` |
| 165 | L-B `:221-223` | **LIMB 2 — domain-shape**: FLAG if the quantified set was drawn from the implementation rather than the rule | CARRIED | `CONS §3.1` LIMB 2 (promoted to normative, A-4) |
| 166 | L-B `:224` | discharge for both limbs — name the mutation and **execute it** | CARRIED | `CONS §3.1` DISCHARGE; bounded by the restore clause at `§1.1 A-25` |
| 167 | L-B `:235-241` | limb 1 executed (`c40_probe.py`) — V-1/V-2/V-3 all `T->T` on both LF and CRLF hosts | CARRIED | `CONS §0` (cited, not re-derived) + `§3.1` `(Origin: …)` |
| 168 | L-B `:243-245` | the methodological claim — re-derived independently here rather than copied, per *a carried number is re-derived, not copied* | CARRIED | `CONS §0` opening, verbatim as the fold's own governing rule |
| 169 | L-B `:250-257` | positive arm `6/6 → GREEN` | CARRIED | `CONS §4` AT-B64-01 (expected `6/6`); superseded upward to 9 members at `§1.1 A-21` |
| 170 | L-B `:259-266` | the limb-2-deleted mutant → `4/6 → RED` | CARRIED | `CONS §1 A-4` + `§3.1` `(Origin: …)` |
| 171 | L-B `:269-272` | *"the single most important number"* — `BACKLOG.md:34`'s one-limb form would miss `AT-165` and `AT-193b` | CARRIED | `CONS §1 A-4`, verbatim reasoning |
| 172 | L-B `:276-284` | negative arm `false positives 0/6 → GREEN` | CARRIED | `CONS §4` AT-B64-02 (expected `0/6`) |
| 173 | L-B `:286-288` | the negative-arm mutant — key limb 1 on *"the writer"* → S-6 flagged → `1/6 → RED` | CARRIED | `CONS §2.2` row 1 + `§4` AT-B64-02 |
| 174 | L-B `:297` | C-10's missed case — V-1/V-2/V-3/V-6, by executed code mutation | CARRIED | `CONS §3.1` DISTINCT clause + `§4` AT-B64-03 |
| 175 | L-B `:298` | C-31's missed case — V-1/V-2/V-3; *"a derived set over the wrong expression is still the wrong expression"*; C-31 **does** catch V-5 | CARRIED | `CONS §3.1` DISTINCT clause |
| 176 | L-B `:299` | C-39's missed case — V-4/V-6; neither carries a threshold | CARRIED | `CONS §3.1` DISTINCT clause |
| 177 | L-B `:301-303` | **no existing control catches V-6** — the discrimination arm's empirical evidence | CARRIED | `CONS §3.1` `(Origin: …)` (*"missed by C-10, C-31 **and** C-39"*) |

### §B.4 — Validation method per requirement (§4) — the six-row table

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 178 | L-B `:311` | **US-B64-1** → `Test` (`c40_arms.py` over the labelled corpus) **+ `Inspection` for limb 2**, because *"deciding 'drawn from the rule or from the implementation?' requires reading the rule"* | RESTORED-THIS-FOLD | **D-12**, row 1 of 6 — restored as a table. `grep -c "Inspection"` → `CONS` **0**. NOT LANDED |
| 179 | L-B `:312` | **US-B64-2** → `Demo` (walkthrough per recorded occurrence) + `Test` (boundary grep over the added block) | RESTORED-THIS-FOLD | **D-12**, row 2 of 6 — restored as a table. NOT LANDED |
| 180 | L-B `:313` | **US-B64-3** → `Test` + `Test`; *"Do **not** settle for inspection where a reproduction exists"* | RESTORED-THIS-FOLD | **D-12**, row 3 of 6 — restored as a table. NOT LANDED |
| 181 | L-B `:314` | **US-B64-4** → `Test` (de-identification grep) + **`Analysis`** for AT-B64-09, *"labelled honestly rather than dressed as a test"* | RESTORED-THIS-FOLD | **D-12**, row 4 of 6 — restored as a table. `grep -c "Analysis"` → `CONS` **0**; this is the distinction that keeps AT-B64-09 from being over-claimed. NOT LANDED |
| 182 | L-B `:315` | **US-B64-6** → `Test` (bidirectional census, executed at RC-1 and re-executed post-batch) | RESTORED-THIS-FOLD | **D-12**, row 5 of 6 — restored as a table. NOT LANDED |
| 183 | L-B `:316` | **all out-of-VCS files** → `Inspection` (SHA + line count); *"the only method available … bookkeeping, not acceptance"* | RESTORED-THIS-FOLD | **D-12**, row 6 of 6 — restored as a table. NOT LANDED |

### §B.5 — AT catalog (§5), by AT and sub-claim

#### AT-B64-01 — C-40 positive arm

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 184 | L-B `:329` | observable — C-40 applied to V-1…V-6 flags all six | CARRIED | `CONS §4` AT-B64-01 |
| 185 | L-B `:330` | executed result — `6/6 → GREEN` | CARRIED | `CONS §4` AT-B64-01 (expected `6/6`), cited at `§0` |
| 186 | L-B `:331-332` | reddening mutation — delete limb 2 → `4/6 → RED` | CARRIED | `CONS §1 A-4` + `§3.1` `(Origin: …)` |
| 187 | L-B `:333-334` | **second** reddening mutation — move S-6 into the positive corpus → `6/7 → RED`, since C-40 correctly does not flag it | RESTORED-THIS-FOLD | **D-16** — restored as a noted item. `grep "6/7"` → `CONS` **0**. NOT LANDED |
| 188 | L-B `:335-337` | subject-in-expression verdict — **Yes**; the subject is the encoded C-40 text and the arm's value is a function of that text | CARRIED | `CONS §4` AT-B64-01 status **LOAD-BEARING**; verified independently in review §3 limb-1 column |
| 189 | L-B `:338` | verdict label — **LOAD-BEARING**; it already went RED once during authoring | CARRIED | `CONS §4` AT-B64-01 status cell |
| 190 | L-B `:339-340` | dependency — cannot be run until the architect lane's C-40 text exists | CARRIED | `CONS §10.1` (*"cannot be RUN until §3.1's text is applied … Phase-1 exit criterion 2 is OPEN"*) |

#### AT-B64-02 — C-40 negative arm

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 191 | L-B `:343` | observable — C-40 applied to S-1…S-6 flags none | CARRIED | `CONS §4` AT-B64-02 |
| 192 | L-B `:344` | executed result — `false positives 0/6 → GREEN` | CARRIED | `CONS §4` AT-B64-02 (expected `0/6`) |
| 193 | L-B `:345-347` | reddening mutation — key limb 1 on *"the writer"* → S-6 flagged → `1/6 → RED` | CARRIED | `CONS §4` AT-B64-02, quoted; worked at `§2.2` |
| 194 | L-B `:348` | subject-in-expression verdict — **Yes** | CARRIED | `CONS §4` AT-B64-02 status **LOAD-BEARING** |
| 195 | L-B `:349` | verdict label — **LOAD-BEARING**; S-6 is a genuine trap and the mutant hits it | CARRIED | `CONS §4` AT-B64-02 status cell |

#### AT-B64-03 — discrimination against C-10 / C-31 / C-39

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 196 | L-B `:353-354` | observable — for each of C-10/C-31/C-39, a **named** corpus member it does not catch, with evidence | CARRIED | `CONS §4` AT-B64-03 |
| 197 | L-B `:355-358` | executed result — the §3.5 table; **V-6 is missed by all three** and is the strongest single item | CARRIED | `CONS §3.1` DISTINCT clause + `(Origin: …)` |
| 198 | L-B `:359-363` | reddening mutation — attempt the same table for **C-35**; the row cannot be filled and the arm goes RED, which is the arm behaving correctly | CARRIED | `CONS §1 A-11` (*"the C-35 row went RED, which is the arm working"*) |
| 199 | L-B `:364-368` | the honest consequence — state in the control text that C-40 is **not orthogonal to C-35**; *"do not claim C-40 is orthogonal to C-35 when it is not"* | CARRIED | `CONS §3.1` NOT-orthogonal clause, verbatim; `§2.3 LLR-B64-1.4` makes it normative |
| 200 | L-B `:369` | verdict label — **LOAD-BEARING, and it produced a finding against its own batch** | CARRIED | `CONS §4` AT-B64-03 status cell |

#### AT-B64-04 — C-41 positive arm over the recorded occurrences

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 201 | L-B `:373-374` | observable as specified — *"applied to the ~9 recorded occurrences across batches 61-63, each one flagged"* | CARRIED | `CONS §4` AT-B64-04 (BEFORE half of A-7) |
| 202 | L-B `:377-387` | the enumerated occurrence set — **8 occurrences spanning batches 60-63**, each with a `file:line` cite | CARRIED | `CONS §1 A-7` + `§3.2` `(Measured: …)`; re-opened to **9** at `§1.1 A-18` (*"the 8 was itself a hand-shaped set"*) |
| 203 | L-B `:396-398` | required re-scope — the AT must read *"the 8 enumerated occurrences across batches 60-63"*; as written it excludes batch-60, which holds 2 of the 8 | CARRIED | `CONS §1 A-7` |
| 204 | L-B `:399-403` | reddening mutation (executed on the corpus) — drop occurrence 7 (`'](' not in note`) and C-41's character-list clause loses its only supporting case → RED | CARRIED | `CONS §4` AT-B64-04 scope cell; executed against the rider's bytes at `§1.1 A-17` |
| 205 | L-B `:404-405` | subject-in-expression verdict — **Yes, once re-scoped**; a function of C-41's clauses against a fixed set | CARRIED | `CONS §4` AT-B64-04 (*"Subject is now the C-35 rider's clauses"*); the never-executed gap is closed at `§1.1 A-17` |
| 206 | L-B `:406` | verdict label — **UNSATISFIABLE AS WRITTEN. Blocker, §9.3** | CARRIED | `CONS §4` AT-B64-04 status `re-scoped`; `§1.1 A-17` records the execution (`8/8`, `9/9`, two mutations at `6/9`) |

#### AT-B64-05 — C-41 stack-free boundary

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 207 | L-B `:410-411` | observable as specified — the encoded global text contains no stack-specific identifier | CARRIED | `CONS §4` AT-B64-05 (BEFORE half of A-5) |
| 208 | L-B `:412-437` | executed baseline — the whole-file predicate is RED before batch-64 writes a word (`Textual` ×3, `a2l` ×3, `AST` ×1) | CARRIED | `CONS §1 A-5` |
| 209 | L-B `:438-439` | required re-scope (a) — scope the predicate to the added block, not the file | CARRIED | `CONS §2.3 LLR-B64-2.2` + `§4` AT-B64-05 |
| 210 | L-B `:439-441` | required re-scope (b) — **remove `AST`** from the forbidden list; `dev-flow.md:57` already uses it as a stack-free technique term | CARRIED | `CONS §2.3 LLR-B64-2.2` (*"`AST` is not a forbidden term"*) |
| 211 | L-B `:442-444` | **"Note against myself"** — the first harness lacked word boundaries and reported `Rich = 1`, `AST = 11`; the same defect `PLAN.md:76` records for the `TC-401` census, **reproduced and recorded rather than quietly fixed** | RESTORED-THIS-FOLD | **D-17** — restored as a noted item. `grep "word-boundary"` → `CONS` **0**. NOT LANDED |
| 212 | L-B `:445-447` | reddening mutation — paste the project leg's content into a scratch copy → 2 hits → RED; scoped to the C-41 region → 0 → GREEN | CARRIED | `CONS §4` AT-B64-05 scope cell + `§3.2` stack-free scan |
| 213 | L-B `:448-450` | subject-in-expression verdict — **Weakly**; it cannot detect a C-41 that is stack-free *and useless* | CARRIED | `CONS §4` AT-B64-05 status **WEAK — boundary complement only** |
| 214 | L-B `:451` | verdict label — **WEAK. Keep as a boundary complement to AT-B64-07, never as C-41's acceptance** | CARRIED | `CONS §4` AT-B64-05 status cell, verbatim intent |

#### AT-B64-06 — C-42 positive arm

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 215 | L-B `:455-456` | observable — each recorded instance is flagged **with the specific mechanic named**, not merely flagged | CARRIED | `CONS §4` AT-B64-06, verbatim |
| 216 | L-B `:458-460` | the count discrepancy inside batch-64's own Phase-0 artifact (five mechanics named vs *"four instances"* asserted); **the correct number is five** | CARRIED | `CONS §1 A-9` |
| 217 | L-B `:461-472` | executed reproduction of mechanic 4, live in this repo — `0 / 29` rendered form vs `29 / 29` emitted form | CARRIED | `CONS §3.3` Mechanic 4 + `§4` AT-B64-06; the `0/19 → 0/29` substitution is now declared at `§1.1 A-16` |
| 218 | L-B `:473-478` | reddening mutation — drop the "name the mechanic" requirement and the arm goes GREEN on a control that gives the reader nothing actionable | CARRIED | `CONS §2.3 LLR-B64-3.2` (each mechanic *"with its own discharge"*) + `§4` AT-B64-06 |
| 219 | L-B `:479-480` | subject-in-expression verdict — **Yes**, keyed on C-42's content, not its existence | CARRIED | `CONS §4` AT-B64-06 status **LOAD-BEARING** |
| 220 | L-B `:481-482` | verdict label — **LOAD-BEARING**, stronger than 05/07 because one instance has an executed in-repo reproduction | CARRIED | `CONS §4` AT-B64-06 status cell |

#### AT-B64-07 — C-42 boundary complement

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 221 | L-B `:486-488` | observable — the mechanics are present in `docs/engineering-rules.md` and absent from the global command; falsifiable in both directions | CARRIED | `CONS §4` AT-B64-07 |
| 222 | L-B `:489-496` | executed pre-batch baseline over `docs/engineering-rules.md` (`markdown-it` 0, `&#160;` 0, `&vert;` 0, `AST` 5) | CARRIED | `CONS §4` AT-B64-07 (by citation to `01b` §3/§5) |
| 223 | L-B `:497-500` | the honest note — pre-batch the pair is **symmetric-empty**, so the assertion is vacuous until C-42 is written; *"stated rather than glossed"* | CARRIED | `CONS §4` AT-B64-07 (*"QA notes it is vacuous pre-encoding and meaningful only post-encoding"*) |
| 224 | L-B `:501-503` | reddening mutation — copy the mechanics into a scratch global file → the "absent" leg goes RED while the "present" leg stays GREEN; **both legs move independently** | CARRIED | `CONS §4` AT-B64-07 (paired-arm framing) |
| 225 | L-B `:504-506` | verdict label — **WEAK individually, MEANINGFUL as a pair with AT-B64-05**; it cannot detect a wrong mechanic, only a misplaced one | CARRIED | `CONS §4` AT-B64-07 status cell, verbatim |

#### AT-B64-08 — `VERIFY.md` de-identification

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 226 | L-B `:510` | observable — zero s19_app identifiers in the extended section | CARRIED | `CONS §4` AT-B64-08 |
| 227 | L-B `:511-519` | executed pre-batch baseline over the whole file (all five terms 0), taken so the post-batch delta is attributable | CARRIED | `CONS §4` AT-B64-08 (by citation) |
| 228 | L-B `:521-523` | reddening mutation — substitute the real batch-61 string `CRC Designer` → 1 hit → RED; substitute back → 0 → GREEN | CARRIED | `CONS §2.3 LLR-B64-4.2` term list + `§4` AT-B64-08 |
| 229 | L-B `:524-527` | subject-in-expression verdict — **No, and this is the honest weakness**; the grep is blind to whether the extension teaches anything | CARRIED | `CONS §4` AT-B64-08 status **WEAK — a constraint check, not acceptance** |
| 230 | L-B `:528` | verdict label — **WEAK. AT-B64-09 carries US-B64-4** | CARRIED | `CONS §4` AT-B64-09 (*"LOAD-BEARING — carries US-B64-4"*) + `§4.1` traceability |

#### AT-B64-09 — `VERIFY.md` discrimination against its own pre-existing text

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 231 | L-B `:530-533` | observable + verdict — **SATISFIABLE. The extension is not a restatement** | CARRIED | `CONS §4` AT-B64-09 |
| 232 | L-B `:535-543` | the pre-existing section quoted verbatim from `VERIFY.md:34-38` as the thing being discriminated against | CARRIED | `CONS §3.4` closing prose cites `VERIFY.md:36-38` |
| 233 | L-B `:550-555` | separation test 1 — the rule's own dichotomy classifies the bad predicate as **GOOD**; an SVG export *is* a runtime value | CARRIED | `CONS §3.4` (by citation to QA §AT-B64-09) |
| 234 | L-B `:556-561` | separation test 2 — the stated failure mode is the **opposite direction**; the 0/29 predicate is a **false fail**, the expensive one | CARRIED | `CONS §3.4` added paragraph (*"Note the direction: this is a **false FAIL**, not a false pass"*) + `§2.3 LLR-B64-4.3`; the addition is now declared at `§1.1 A-16` |
| 235 | L-B `:563-568` | separation test 3 — the neighbouring mutation-test section is **structurally blind** to a predicate that is red for the wrong reason | CARRIED | `CONS §3.4` closing prose (*"it is also QA's third separation test"*) |
| 236 | L-B `:570-577` | the honest counter-argument — line 37's *"never on the presence of a label"* read in isolation covers it; refuted by the *label/docstring* pairing fixing the referent as source-side prose | CARRIED | `CONS §4` AT-B64-09 (by citation to `01b` §5) |
| 237 | L-B `:579-585` | reddening mutation — draft the extension as a paraphrase of line 36 → the arm goes **RED**; draft it as the emitted-form rule → **GREEN**; the arm separates two candidate drafts | CARRIED | `CONS §4` AT-B64-09 (*"QA proved satisfiable by separating two candidate drafts"*) |
| 238 | L-B `:586-587` | subject-in-expression verdict — **Yes**; a function of the added text's content against a fixed counterexample | CARRIED | `CONS §4` AT-B64-09 status **LOAD-BEARING** |
| 239 | L-B `:588-589` | verdict label — **LOAD-BEARING and satisfiable**; *"if the architect lane's draft cannot separate the two drafts above, the leg should be withdrawn"* | CARRIED | `CONS §4` AT-B64-09 status cell |

#### AT-B64-10 — lineage registry, bidirectional

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 240 | L-B `:593-594` | observable — every encoded control id present in the lineage record, and zero id registered with no encoded text | CARRIED | `CONS §4` AT-B64-10; re-derived from the rule at `§1.1 A-19` |
| 241 | L-B `:595-609` | executed pre-batch, both directions — 30 registered ids; encoded union `C-10 … C-39` contiguous; `VERIFY.md` carries none | CARRIED | `CONS §0 R-3` (independently re-derived) |
| 242 | L-B `:609-610` | **`C-29` is encoded at `docs/engineering-rules.md:64` and not registered** — a live reverse-direction miss | CARRIED | `CONS §0 R-2` + `§1 A-14` + `§2.3 LLR-B64-5.3` |
| 243 | L-B `:612-631` | the forward direction over `C-1 … C-9` — every apparent hit is a false positive (diagram node labels, a ruff rule code, backlog shorthand) | CARRIED | `CONS §0 R-3` + `§7` carry 2 |
| 244 | L-B `:627-631` | **`PLAN.md:73-74` is REFUTED** — the encoded space is `C-10 … C-39`; correct at the top end, wrong at the bottom | CARRIED | `CONS §1 A-8` + `§7` carry 4 |
| 245 | L-B `:632-636` | the consequence/blocker — run as specified the AT is RED pre-batch on 9 ids batch-64 cannot fix; re-scope to `{C-29, C-40, C-41, C-42}`, carry `C-1…C-9`; *"do not silently relax it"* | CARRIED | `CONS §1 A-6` + `§7` carry 2; re-derived from the rule at `§1.1 A-19`, and `C-41` re-admitted at `§1.1 A-20` |
| 246 | L-B `:637-640` | reddening mutation — remove `C-38` from a scratch lineage → RED; add a fictitious `C-43` → RED; **both directions move independently** | CARRIED | `CONS §4` AT-B64-10 (*"bidirectional"*); mutation restated at `§1.1 A-20` |
| 247 | L-B `:641-642` | subject-in-expression verdict — **Yes**, and it already found two real defects before batch-64 encoded anything | CARRIED | `CONS §4` AT-B64-10 status **LOAD-BEARING — strongest mechanical AT** |
| 248 | L-B `:643` | verdict label — **LOAD-BEARING. Strongest mechanical AT. Blocks on re-scoping** | CARRIED | `CONS §4` AT-B64-10 status cell, verbatim |

#### AT-B64-11 — out-of-VCS hash record

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 249 | L-B `:647` | observable — SHA256 + line count recorded before and after for each out-of-VCS file | CARRIED | `CONS §4` AT-B64-11 + `§2.3 LLR-B64-6.2` |
| 250 | L-B `:648-655` | the executed BEFORE table (four files, SHA/lines/bytes) | CARRIED | `CONS §6` table, all four rows — **DUP-4** |
| 251 | L-B `:657-658` | `VERIFY.md`'s **182 lines** recorded because `PLAN.md:69` omitted the line count R-a requires | CARRIED | `CONS §6` table row 2 (182 / 10 142) |
| 252 | L-B `:659-660` | reddening mutation — append one newline to a scratch copy → SHA changes and 182 → 183 → RED | CARRIED | `CONS §2.3 LLR-B64-6.3` (the blocking predicate) + `§6` change-proof property |
| 253 | L-B `:661-663` | subject-in-expression verdict — **No**; a hash proves *a* change happened, never that the *right* change happened | CARRIED | `CONS §1 A-10`, quoted verbatim; `§6` "Honest limit" |
| 254 | L-B `:664-666` | verdict label — **AT-B64-11 as acceptance** | RETIRED | Legitimate retirement 4 of 7 — `A-10`: *"bookkeeping, not acceptance … not counted toward any story"*. `CONS §4` status cell + `§4.1` traceability row shows `— *(bookkeeping)*` |

### §B.6 — Self-application (§6)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 255 | L-B `:689-694` | the verdict — C-40 is operable on its own encoding batch; it demoted 08 and 11, forced 05/07 to be labelled weak, and drove the negative group that produced the S-6 trap | CARRIED | `CONS §4` status column carries all four demotions (`WEAK` ×3, `BOOKKEEPING` ×1) |
| 256 | L-B `:696-698` | *"the one place it bit hardest"* — the naive AT (*"the string `can it go RED` appears in `dev-flow.md`"*) fails limb 1 outright; **none of the 11 ATs is that predicate** | **UNPLACEABLE** | See **§U-3**. `grep "naive"` → `CONS` **0**. Not in the review's §1.2 drop table, so it is in no restoration set |

### §B.7 — Layer A N/A (§7)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| — | L-B `:702-719` | QA's independent concurrence that the `TC` layer is N/A | — | **DUP-1**, counted once at item **15** (RETIRED, superseded by R-8) |
| 257 | L-B `:713-715` | *"I looked for a genuine white-box layer and did not find one"* — the nearest candidate is the delivery mechanism, which is bookkeeping | CARRIED | `CONS §4` (*"both lanes concurring on independent arguments"*); **refuted by execution** at `§1.1 A-24` |
| 258 | L-B `:717-719` | **no `TC-NNN` ids are minted** — manufacturing them to complete a matrix is the template-filling the flow's hard rules forbid | CARRIED | `CONS §4` (*"No `TC` ids are minted"*); preserved through R-8 (`A-24`: *"Added; explicitly NOT minted as `TC` ids"*) |

### §B.8 — QA evidence checklist (§8) — the ten rows

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 259 | L-B `:727` | row 1 — Given/When/Then ⚠ **partial**, with the **deviation declared, not silent** (*"G/W/T is the wrong shape for 'does this rule discriminate over a corpus'"*) | RESTORED-THIS-FOLD | **D-13**, row 1 of 10 — restored. A declared deviation that disappears at the fold becomes an undeclared one (review BLOCKER-5). NOT LANDED |
| 260 | L-B `:728` | row 2 — every AT states a numeric or set-valued Expected (`6/6`, `0/6`, `0/29 vs 29/29`, an id set) | RESTORED-THIS-FOLD | **D-13**, row 2 of 10 — restored. NOT LANDED |
| 261 | L-B `:729` | row 3 — **edge cases include empty, boundary, invalid, error** (`N=0`; S-6; the limb-1 mutant; V-6's invalid-UTF-8 path) | RESTORED-THIS-FOLD | **D-13**, row 3 of 10 — restored. NOT LANDED |
| 262 | L-B `:730` | row 4 — a regression checklist exists (§9.7) | RESTORED-THIS-FOLD | **D-13**, row 4 of 10 — restored. NOT LANDED |
| 263 | L-B `:731` | row 5 — exit criteria stated (§9.8) | RESTORED-THIS-FOLD | **D-13**, row 5 of 10 — restored. NOT LANDED |
| 264 | L-B `:732` | row 6 — **no real PII / secrets**; no credentials, no tokens, no host paths beyond the declared destinations | RESTORED-THIS-FOLD | **D-13**, row 6 of 10 — restored. NOT LANDED |
| 265 | L-B `:733` | row 7 — results left blank unless actually run; arms depending on unwritten text are marked **pending**, and only their harnesses were executed | RESTORED-THIS-FOLD | **D-13**, row 7 of 10 — restored. NOT LANDED |
| 266 | L-B `:734` | row 8 — **Layer B observed through the SHIPPED surface**; the shipped surface of a control is the file a future agent reads; V-6 was found by executing the **product** | RESTORED-THIS-FOLD | **D-13**, row 8 of 10 — restored. NOT LANDED |
| 267 | L-B `:735` | row 9 — **bidirectional surface-reachability**; AT-B64-10 runs both directions and 05/07 are the two directions of the placement boundary, each mutated independently | RESTORED-THIS-FOLD | **D-13**, row 9 of 10 — restored. NOT LANDED |
| 268 | L-B `:736` | row 10 — **no unfilled template**; no `<...>`, no `TC-NNN` placeholders, every AT row populated | RESTORED-THIS-FOLD | **D-13**, row 10 of 10 — restored. NOT LANDED |

### §B.9 — Blockers and carries (§9.1–§9.6)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 269 | L-B `:742-748` | **§9.1 BLOCKER** — C-40 must be drafted with two limbs or AT-B64-01 cannot pass | CARRIED | `CONS §1 A-4` + `§3.1` LIMB 2 |
| 270 | L-B `:750-755` | **§9.2 BLOCKER** — the corpus is six and the sixth is a live defect on `main`; *"do not quietly adopt 'five' from the postmortem"* | CARRIED | `CONS §1 A-2` + `§0 R-1` |
| 271 | L-B `:757-762` | **§9.3 BLOCKER** — AT-B64-04's corpus scope and count are both wrong; the *"5 in batch-63 alone"* figure double-counts | CARRIED | `CONS §1 A-7` + `§7` carry 3 |
| 272 | L-B `:764-770` | **§9.4 BLOCKER** — AT-B64-10 is RED pre-batch on 9 ids batch-64 cannot fix; re-scope and carry `C-1…C-9` | CARRIED | `CONS §1 A-6` + `§7` carry 2 |
| 273 | L-B `:772-776` | **§9.5 BLOCKER** — AT-B64-05 is unsatisfiable as written | CARRIED | `CONS §1 A-5` |
| 274 | L-B `:778-785` | **§9.6 CARRY** — `AT-172b` on `main`, with its fix shape and the D-5 constraint | CARRIED | `CONS §7` carry 1, in full |
| 275 | L-B `:782` | §9.6's traceability link — **`R-TUI-097`'s validation line (`REQUIREMENTS.md:4849`) cites `AT-172` as covering this** | RESTORED-THIS-FOLD | **D-15** — restored as a noted item. `grep` → `CONS` **0** for both tokens; a future fixer of `AT-172b` needs the requirement that falsely claims coverage. NOT LANDED |

### §B.10 — Regression checklist (§9.7) — the six rows

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 276 | L-B `:789-791` | row 1 — the global command is read at every batch kickoff; **check:** added lines ≤ the length of C-39, **or** the discrimination arm justifies the excess explicitly (risk R-c) | CARRIED | `CONS §9.1` — quoted verbatim as the gate the fold measures itself against (`C-40 = 2.07× C-39`) |
| 277 | L-B `:792-793` | row 2a — editing the global command mid-batch changes the command this batch runs under; **check:** the edit is the LAST increment | CARRIED | `CONS §5` Inc-3 + the R-d paragraph |
| 278 | L-B `:793-794` | row 2b — **check:** the SHA record (AT-B64-11) is taken **immediately before and after** | RESTORED-THIS-FOLD | **D-14**, row 1 of 4 — restored into a §-level regression checklist. Partly addressed by `§1.1 A-26` (POST rows moved into the editing increment) but the checklist row itself is absent. NOT LANDED |
| 279 | L-B `:795-796` | row 3 — the target section is tagged `[travels]`; **check:** AT-B64-08 = 0 hits; **if it cannot be met, the tag is dropped rather than the constraint** | RESTORED-THIS-FOLD | **D-14**, row 2 of 4 — restored. The fallback ruling has no equivalent in `CONS`; `§2.3 LLR-B64-4.4` mandates retention with no failure branch. NOT LANDED |
| 280 | L-B `:797-798` | row 4 — `docs/engineering-rules.md` is the only leg CI can see; **check:** `pytest -q` still reports 2201 passed, `A = 0`, `D = 0` | CARRIED | `CONS §10.4` (the `2201` baseline and the obligation to re-derive it at the Phase-3 gate) |
| 281 | L-B `:799-800` | row 5 — **`.dev-flow/BACKLOG.md` is the one real collision point with parallel work**; **check:** re-read before reconciling; do not re-apply | RESTORED-THIS-FOLD | **D-14**, row 3 of 4 — restored. `grep -c "collision"` → `CONS` **0**, while `LLR-B64-5.4` edits exactly that file in Inc-4 (review BLOCKER-6). NOT LANDED |
| 282 | L-B `:801-802` | row 6 — the lineage memory is read by `/dev-flow-sync`; **check:** the bidirectional census (AT-B64-10) is re-run **AFTER** the edit, not only before | RESTORED-THIS-FOLD | **D-14**, row 4 of 4 — restored. Without it the batch's strongest AT is a pre-batch observation, not an acceptance (review BLOCKER-6). NOT LANDED |

### §B.11 — Exit criteria (§9.8)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 283 | L-B `:806-808` | criterion 1 — §9.1–§9.5 resolved (two limbs; `6/6`; 8 occurrences over 60-63; `{C-29,C-40,C-41,C-42}`; AT-B64-05 scoped with `AST` removed) | CARRIED | `CONS §1` A-2/A-4/A-5/A-6/A-7, one amendment per sub-clause |
| 284 | L-B `:809-810` | criterion 2 — AT-B64-01/02/03 re-executed against the **actual** C-40 text and their outputs pasted | CARRIED | `CONS §10.1` (declared **OPEN**, not claimed) |
| 285 | L-B `:811` | criterion 3 — AT-B64-09's two candidate drafts run through the three-test separation and the winner pasted | CARRIED | `CONS §4` AT-B64-09 (*"QA proved satisfiable by separating two candidate drafts"*) |
| 286 | L-B `:812` | criterion 4 — AT-B64-11's AFTER record taken and diffed against the BEFORE table | CARRIED | `CONS §2.3 LLR-B64-6.2` + `§6`; re-homed per `§1.1 A-26` |
| 287 | L-B `:813-814` | criterion 5 — no AT presented as acceptance that §6 marks ❌ (AT-B64-08, AT-B64-11) | CARRIED | `CONS §4` statuses **WEAK — a constraint check, not acceptance** and **BOOKKEEPING, NOT ACCEPTANCE**; `§4.1` gives HLR-B64-6 no load-bearing AT |

### §B.12 — What QA could not verify (§9.9)

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 288 | L-B `:818-820` | the positive arms of AT-B64-01…07 **cannot be run** until the control text exists; what is executed is the corpus, the harness and the mutations — *"the arms are pending, not claimed"* | CARRIED | `CONS §10.1`, in the same terms |
| 289 | L-B `:821-824` | **limb 2 of C-40 is not mechanisable**; V-4 and V-5 are flagged by `inspection` with a `file:line` citation to the executed refutation that established each | RESTORED-THIS-FOLD | **D-12** (the `Inspection` justification, row 1) — restored as a table. `CONS §3.1` states limb 2 normatively with the mechanisability caveat removed. NOT LANDED |
| 290 | L-B `:825-827` | **`TC-441` (S-5) was never shipped** — D1 was returned to the backlog; *"a valid negative-control predicate; it is not a running test"* | RESTORED-THIS-FOLD | **D-18** — restored as a noted item. Matters because S-5 is 1 of 6 negative controls; partly re-derived at `§1.1 A-22`, but the caveat itself is absent. NOT LANDED |
| 291 | L-B `:828-830` | the full suite was not run; the `2201 passed` baseline is carried from `PLAN.md:162` and must be re-measured at the Phase-3 gate | CARRIED | `CONS §10.4`, verbatim |

---

## §A.17 / §B.13 — Addendum: two retirements the first pass mis-dispositioned

**Disclosed rather than silently renumbered.** The first pass of this ledger marked only five of the
seven mandated retirements as `RETIRED`, mis-filing two of them as `CARRIED` because their
*amendments* are carried while the *items themselves* are retired. The count command caught it
(`grep -c "| RETIRED |"` → 6, against a required 7). The two rows are added here with numbers
**293–294**; they are not in document order, and that is stated rather than hidden by a renumber.

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 293 | L-A `:80`, `:102-104`, `:141`; L-B `:371-406` | **`C-41` as a free-standing global control** — a new peer id in `~/.claude/commands/dev-flow.md` with its own ~2 000 B block | RETIRED | Legitimate retirement 1 of 7 — **operator ruling**, taken against the alternative the architect lane stated (`CONS §1 A-1`: *"a rider appended to the existing C-35 block … **`C-41` is NOT consumed and stays free**"*). `CONS §8` records `~~C-41~~ — NOT CONSUMED — the id stays free`. Distinct from item **98** (the *stated alternative*, CARRIED) and items **57–70** (C-41's *clauses*, re-homed into the rider) |
| 294 | L-A `:103`, `:310-313`; L-B `:411`, `:439-441` | **`AST` as a member of the forbidden stack-specific term list** | RETIRED | Legitimate retirement 2 of 7 — ruled on QA's measurement that `dev-flow.md:57` already uses *"walk the AST"* inside C-31 as a **stack-free technique term**, so keeping it would forbid the rider its own discharge (*"prefer a structural parse over a substring match"*). `CONS §1 A-5` (*"**`AST` REMOVED** from the term list"*) + `§2.3 LLR-B64-2.2` (*"**`AST` is not a forbidden term**"*). Distinct from item **210** (QA's re-scope *finding*, CARRIED) |

---

## §R — Restoration set item R-8

| # | source | item | disposition | evidence |
|---|---|---|---|---|
| 292 | `02-review-qa.md` Charge 4; L-A §A.0 / L-B §7 | The **Layer-A `N/A` declaration is replaced by four placement predicates** — each RED pre-batch, GREEN on a correct insert, RED on a mis-placed insert, while `AT-B64-08`/`AT-B64-09` return **identical** values on both. Four `shall` clauses had no observer | RESTORED-THIS-FOLD | **R-8**. Declared at `CONS §1.1 A-24` (*"REFUTED BY EXECUTION … Added; explicitly NOT minted as `TC` ids"*). **NOT LANDED** — `grep "placement predicate"` returns 1 hit, at line 91, inside the amendment table; the cited body section `§4.5` **does not exist** (see §U-2). This is the supersession annotated on item **15** |

---

## §X — Cross-lane duplicates (counted once)

Eight items appear in both lanes. Each is numbered once above; this table records the second cite so
the dedup is auditable rather than asserted.

| dup | item | lane A cite | lane B cite | counted at |
|---|---|---|---|---|
| DUP-1 | the `TC` / Layer A layer declared N/A with reason | `§A.0` `:51-73` | `§7` `:702-719` | **15** (RETIRED, superseded by R-8) |
| DUP-2 | AT-B64-05's stack-free predicate is unsatisfiable against the whole file | F-1 `:308-315` | `§9.5` `:772-776` | **101** and **208** — *retained as two rows*: A's finding is the whole-file baseline, B's is the term-list correction. See note below |
| DUP-3 | the AT-B64-10 census cannot distinguish encoded from proposed / is RED pre-batch | F-2 `:331-342` | `§9.4` `:764-770` | **105** and **272** — *retained as two rows*: A's defect is green-by-construction, B's is red-pre-batch. See note below |
| DUP-4 | the out-of-VCS PRE table (SHA / lines / bytes, four files) | E-1 `:31` | AT-B64-11 `:648-655` | **250** |
| DUP-5 | `dev-flow.md:202`'s `Textual` is NORMATIVE, not an Origin example | E-5 `:35` | AT-B64-05 `:435-437` | **5** (RESTORED, D-20) |
| DUP-6 | *"the writer never appears in the expression"* as the diagnosis | E-10 `:40` | V-3 `:70-75` | **10** |
| DUP-7 | `docs/engineering-rules.md` baseline (125 lines / 15 127 B / `278b808d…`) | E-2 `:32` | AT-B64-11 `:655` | **2** |
| DUP-8 | the P-3 total disputed across three registers | E-11 `:41` | AT-B64-04 `:388-395` | **11** |

**Note on DUP-2 and DUP-3.** These are the two cases where the lanes reached the *same conclusion by
different measurements*, and the two measurements are separately load-bearing: the architect's F-1
measured the whole-file baseline (which is what makes the predicate RED), while QA's §9.5 measured
the term list (which is what removes `AST`). Collapsing them would drop one of the two amendments
that `A-5` actually carries. **They are therefore counted as four rows, not two, and this is
disclosed rather than folded in silently** — collapsing them to hit a target number would be the
exact defect this ledger exists to prevent.

---

## §T — Tally

Produced by command over this file, not asserted. Counts are restricted to **numbered union rows**
(`^| <n> |`) so that prose mentions of a disposition token cannot inflate them:

```
$ grep -cE '^\| [0-9]+ \|.*\| CARRIED \|'            01d-union-ledger.md
246
$ grep -cE '^\| [0-9]+ \|.*\| RETIRED \|'            01d-union-ledger.md
7
$ grep -cE '^\| [0-9]+ \|.*\| RESTORED-THIS-FOLD \|' 01d-union-ledger.md
39
$ grep -cE '^\| [0-9]+ \|.*\| \*\*UNPLACEABLE\*\* \|' 01d-union-ledger.md
2
$ grep -cE '^\| [0-9]+ \|'                           01d-union-ledger.md
294
```

Numbering integrity, executed — no gap, no duplicate, contiguous `1…294`:

```
$ grep -oE '^\| [0-9]+ \|' 01d-union-ledger.md | grep -oE '[0-9]+' | sort -n > n.txt
$ seq 1 294 > s.txt
count=294  distinct=294
missing:
duplicated:
```

| disposition | count at the 15:50:02 snapshot | **count at fold 3** |
|---|---|---|
| **CARRIED** | **246** | **247** *(+1: item 23, re-dispositioned — §U-1 REFUTED)* |
| **RETIRED** (with reason) | **7** | **7** |
| **RESTORED-THIS-FOLD** | **39** | **39** |
| **UNPLACEABLE** (reported in §U, not omitted) | **2** | **1** *(item 256 only — `U-3`(a))* |
| **TOTAL ROWS** | **294** | **294** |

`246 + 7 + 39 + 2 = 294` at the snapshot; **`247 + 7 + 39 + 1 = 294` at fold 3.** **The four-way count
sums in both columns, and the total is unchanged** — the correction moves one row between categories
rather than adding or dropping any. It does **not** sum to 163 — see below.

> **Two re-dispositions at fold 3, both in the same direction and from the same cause** (`CONS`
> A-41; `02c-discharge-audit.md` §1.3/§1.4). Item **23** moves `UNPLACEABLE → CARRIED` (§U-1 refuted),
> and **`U-3`(b)** — which is *not* a numbered row, being the narrower half of item 163's already-
> `CARRIED` disposition — is marked **discharged** by `CONS` §10.2. **Both were scored against a
> snapshot taken mid-write, and the read/write-race correction had been applied to `U-2`/`U-1` but not
> to `U-3`.** No row's disposition moved because the *rules* changed; they moved because the subject
> did, after it was measured. That is the defect `CONS` §3.0 now freezes out.

**One process note, recorded because this ledger's own rule is that a check must be able to bite.**
The first pass of this file asserted `215 / 7 / 38 / 3 = 263` from estimation. Running the count
command refuted every figure and additionally exposed that only **5** of the 7 mandated retirements
had been marked `RETIRED` — the other two (`C-41` as a control, `AST` in the term list) had been
mis-filed as `CARRIED` because their *amendments* are carried. Both were added as rows **293–294**
(§A.17/§B.13) rather than quietly renumbered. **The predicted tally was wrong on all four axes; the
executed one is above.**

**Reconciliation against the review's 163 — stated plainly, because the whole point of this file is
that a preservation claim must be checkable.**

- The review's tally is **163 = 136 + 7 + 20**. This ledger's is **294 = 246 + 7 + 39 + 2**.
- **The 7 RETIRED agree exactly**, item for item — all seven named in the review's §1.1 prose are
  present as rows **15, 78, 136, 137, 254, 293, 294**. That is the one axis where the two
  enumerations are the same object, and it is the axis that most needed to agree.
- **The 39 RESTORED vs the review's 20** is arithmetic, not disagreement. Review rows `D-12`, `D-13`
  and `D-14` are each a *multi-item* row (*"6 rows"*, *"10 rows"*, *"4 of 6 rows"*). Expanded as the
  ledger brief requires, `20 − 3 + 6 + 10 + 4 = 37`, plus `R-8` = **38** chartered restorations. The
  39th row is item **289** — QA §9.9's *"limb 2 of C-40 is not mechanisable"* — a separate source-lane
  union item that the same `D-12` restoration discharges. **The substantive point: the review's own
  §1.1 tally says 20 where its §1.2 body describes 37 — the summary integer undercounts the review's
  own drop table by 17 observables.** Reported, not corrected: the drop table is the authority and it
  is complete; only the summary integer is low.
- **The 246 CARRIED vs 136** is granularity. The ledger brief defines a union item finely — *each
  named clause group inside a control block counts separately*; *each AT's sub-claims (observable,
  executed result, reddening mutation, subject-in-expression verdict, verdict label) count
  separately*. That yields 11 rows for the C-40 block alone and 5–9 rows per AT. The review's 163
  is a coarser count of the same material, and **it publishes no enumeration** — §1.2 lists the 20
  drops; the 136 carried and the 7 retired are never listed anywhere. **The 163 is therefore not
  reproducible from the artifact.** This ledger does not dispute it, does not re-derive it, and does
  not pad or merge rows to reach it.
- **No row was added, removed, merged or split to move the total toward 163.** Two rows were added
  (**293–294**) to correct a mis-disposition the count command caught; that moves the total *away*
  from 163, which is the direction that tells you it was not target-fitting. `DUP-2`/`DUP-3` were
  likewise kept as four rows rather than collapsed to two, with the reason disclosed (§X). The
  instruction was explicit that a fabricated 163 is worse than an honest number with an explanation,
  and this file exists because a prior fold asserted a preservation it had not performed.

---

## §U — Unplaceable rows

Four findings. Two are numbered union rows that fit none of the three dispositions (items **23** and
**256**, counted in §T as `UNPLACEABLE`); two are findings about the *audit and repair machinery*
rather than about a union item, and are therefore not numbered. Each is reported with what was tried.

### §U-1 — **REFUTED. Retained in full below, because the reason it was wrong is the finding.**

> ⚠ **`U-1` DOES NOT STAND.** Everything below is true of the **15:50:02 snapshot** this ledger was
> pinned to (§M-1) and **false of the shipping document**: `+381 lines / +32 063 B` were written after
> the snapshot. Re-run on the shipping file, the three needles this section reports as **0 each** now
> return `IEEE 830` **2**, `many-to-one` **1**, `four parents` **1**, and `CONS` §4.1.1 states it
> outright — *"HLR-B64-6's four parents are named in the US column … it is the batch's only
> many-to-one edge and IEEE 830 permits it provided each parent is named."* Independently confirmed by
> `02c-discharge-audit.md` §1.3. **Union item 23 is re-dispositioned `CARRIED`; §T's count is updated
> accordingly.** The one cosmetic residue the audit noted — the row still printing `*(cross-cutting)*`
> beside the four named parents, which the same paragraph says it no longer does — **is deleted at
> fold 3** (`CONS` A-42), so the `grep -c "cross-cutting"` figure below no longer reproduces either.
>
> **Kept rather than deleted because this is the batch's own defect class, committed by its own
> ledger:** a measurement taken against a subject that then changed, published without a mechanism to
> detect that it had. That is precisely what `CONS` §3.0's frozen manifest now prevents.

#### §U-1 (superseded text, retained verbatim) — HLR-B64-6's four-parent traceability note is dropped and is in no restoration set

**Item.** `01-requirements-architect.md:86-89` — *"HLR-B64-6 has **four** parent stories, because the
out-of-VCS obligation is a property of the *destination*, not of any one story. IEEE 830 permits a
cross-cutting requirement provided each parent is named; they are named. It is the only many-to-one
edge in the batch."*

**Why not CARRIED.** `CONS §4.1`'s traceability table shows `*(cross-cutting)*` in the US column and
does not name `US-B64-1/-2/-4/-6`. The justification paragraph is absent.

**Why not RETIRED.** No retirement line anywhere in `CONS`.

**Why not RESTORED-THIS-FOLD.** It is **not** one of `D-01…D-20`. The review found it — §6 MINOR-5,
*"the architect's note explaining the four-parent edge (`:86-89`) was dropped"* — but filed it as a
minor finding rather than a drop-table row, so no restoration is chartered for it.

**Tried.** `grep -c "cross-cutting"` → `CONS` 2 (both the bare label, `§2.1` HLR-B64-6 and `§4.1`);
searched `CONS` for `IEEE 830`, `many-to-one`, `four parent` — 0 each.

**What this exposes.** The review's §1.2 drop table is not closed over the review's own findings.
At least one dropped observable is recorded only in §6, where nothing acts on it.

### §U-2 — the amendment table A-15…A-30 cites five body sections that do not exist

**Item.** Not a source-lane union item — a **defect in the repair itself**, surfaced because this
ledger had to locate the restorations.

`CONS §1.1` (added between 15:41 and 15:50) asserts sixteen amendments and cites `§4.0`, `§4.2`,
`§4.3`, `§4.4`, `§4.5` and `§9.2` as the places they landed. Executed against the 15:50:02 snapshot:

```
heading census (grep -n "^#\{2,4\} "):
§0 §1 §1.1 §2 §2.1 §2.2 §2.3 §3 §3.1 §3.2 §3.3 §3.4 §4 §4.1 §5 §6 §7 §8 §9 §9.1 §10

§4.0  -> line 82  (inside the A-15 row)     no such section
§4.2  -> line 88  (inside the A-21 row)     no such section
§4.3  -> lines 84, 85 (A-17, A-18 rows)     no such section
§4.4  -> line 86  (inside the A-19 row)     no such section
§4.5  -> line 91  (inside the A-24 row)     no such section
§9.2  -> line 82  (inside the A-15 row)     no such section
```

Every token asserted by A-17/A-19/A-21/A-24 — `V-7`, `V-8`, `V-9`, `8/9`, `rq_arms`, `placement
predicate` — occurs **exactly once each, on lines 84–96, i.e. inside the amendment table itself**,
and nowhere in the document body.

**Why unplaceable.** It is not a disposition of a union item; it is the observation that the
amendment table currently asserts restorations the body does not contain.

**Why it matters and is not a nitpick.** This is instance (ii) of C-40 recurring one layer up: an
amendment table is a container, and a green amendment count over the rows cannot see whether the
rows landed. A reader auditing `§1.1` rather than the body would conclude the repair is complete.
**Four of the twenty drops (D-01…D-04) genuinely did land in `§3.2`'s rider and were verified byte
by byte for this ledger; the other sixteen plus R-8 had not, at snapshot time.** The `LANDED` /
`NOT LANDED` flag on every `RESTORED-THIS-FOLD` row above is the per-item form of this check.

### §U-3 — **CORRECTED at fold 3: ONE lane observation stands, not two**

> **This section over-reported by one, and the cause is the race this ledger documents in §M-1.** Both
> items below were scored against the **15:50:02 snapshot** (441 lines / 55 593 B / sha `a0868db7…`);
> the shipping document is 821+ lines and **+32 063 B were written after this ledger read it**. The
> read/write-race correction was applied to `U-2` and `U-1` and **not** to `U-3`, which was snapshotted
> under the identical condition. **`U-3`(b) is DISCHARGED. Only `U-3`(a) stands.**
> Source: `02c-discharge-audit.md` §1.4, independently re-verified.

| item | source | status |
|---|---|---|
| **`U-3`(a)** — QA §6's *"the one place it bit hardest"*: the naive AT (*"the string `can it go RED` appears in `dev-flow.md`"*) fails limb 1 outright, and **none of the 11 ATs is that predicate**. It is the batch's own self-application evidence | `01b-qa-catalog.md:696-698` | **STANDS.** Absent from `CONS`, no retirement line, not in `D-01…D-20`. `grep "can it go RED"` → **0**; `grep "naive"` → **0** |
| **`U-3`(b)** — QA §3.1's `subject(D)` definition (*"the artifact or symbol `D` modifies"*) is itself the M-1 mutant the fold corrects and remains on disk as the harness's specification; `A-3` attributes the defect to the architect draft **only** | `01b-qa-catalog.md:218-220` | ⚠ **DOES NOT STAND — DISCHARGED by `CONS` §10.2.** Its first bullet quotes `subject(D)`, cites `01b-qa-catalog.md:218-220`, and states *"A-3 attributed the defect to the architect draft alone; it was in **both** lanes."* Verified: `subject(D)` ×1, `01b-qa-catalog.md:218-220` ×1, `both** lanes` ×1. **Scored open here only because this ledger was pinned to a snapshot taken before §10.2 was written** |

Union item **163** (QA's `subject(D)` definition) remains dispositioned `CARRIED` above, and correctly
so: the limb-1 *rule* survives in amended form **and** the narrower observation — that the source
lane's own wording was never corrected — is now carried openly at `CONS` §10.2, with the fix assigned
to the catalog's author. **The unplaceable set is therefore `U-3`(a) alone.**

### §U-4 — the review's 163 cannot be reproduced from the review

Stated here rather than in §T because it is a finding, not a count.

`02-review-architect.md` §1.1 asserts `163 / 136 / 7 / 20`. §1.2 enumerates the 20. **The 136 carried
and the 7 retired are enumerated nowhere** — the 7 appear as a prose list in §1.1 (which is enough to
place them, and they are placed here), but the 136 have no listing at all. A reader cannot check the
136 against the sources, which is precisely the property the review indicts fold 1 for lacking:
*"an id-range table is a container, not evidence of preservation, and a green traceability count over
the survivors cannot see the casualties."*

**This is not an accusation that the audit was not performed** — its 20 drops are specific, cited and
independently re-verified by grep for this ledger, which is strong evidence it was. It is the
observation that the audit's *output format* is a summary integer, and that this ledger, whose
output format is one checkable row per item, is the correct successor artifact. **From this fold on,
the union tally should be read off `01d`, not off a tally line.**

---

## §V — Evidence checklist (QA gate obligation)

| item | ✓/✗ | evidence |
|---|---|---|
| Every union item carries exactly one of three dispositions | ✓ | 294 numbered rows, each with `CARRIED` / `RETIRED` / `RESTORED-THIS-FOLD`; **at fold 3 the 1 that fits none** (item 256, `U-3`(a)) is reported in §U rather than omitted, and is counted. *(Was 2; item 23 re-dispositioned `CARRIED` — §U-1 refuted.)* |
| The four-way count sums | ✓ **in both columns** | `246 + 7 + 39 + 2 = 294` at the 15:50:02 snapshot; **`247 + 7 + 39 + 1 = 294` at fold 3**, the correction moving one row between categories and adding none. All figures pasted from grep in §T; numbering verified contiguous `1…294` with no gap or duplicate |
| **Re-dispositions are stated as corrections, not silently applied** | ✓ | §T carries both columns side by side and names the cause (a mid-write snapshot, §M-1); §U-1's superseded text is **retained verbatim under a refutation banner** rather than deleted, so the reversal stays auditable — the same rule `CONS` applies to its own §4.3 |
| All 7 mandated retirements are present as `RETIRED` | ✓ | rows **15, 78, 136, 137, 254, 293, 294** — the count command refuted the first pass at 5 and the two misses were added, not renumbered away (§A.17/§B.13) |
| `CARRIED` cites a location in the consolidated | ✓ | every `CARRIED` cell names a `CONS §x` section; sections used rather than `:line` because the file moved 3× mid-task (§M-1) |
| `RETIRED` states the reason and who ruled it | ✓ | 7 rows, items **15**, **78**, **136**, **137**, **254**, and the two operator rulings; each names the amendment id or the ruling |
| `RESTORED-THIS-FOLD` names which restoration it is | ✓ | every one cites `D-01…D-20` or `R-8`, plus its landed/not-landed status against the 15:50:02 snapshot |
| Counts produced by command, not predicted | ✓ | §M-3 and §T paste the grep output; the snapshot SHA is recorded so every cell is re-checkable |
| The four-way count is reconciled against the authority | ✓ | §T reconciles 263 against 163 term by term; the 7 RETIRED agree exactly; the other two deltas are attributed to multi-item drop rows (+17) and to the brief's finer union-item definition |
| No padding, no merging to hit a target | ✓ | §T final bullet; DUP-2/DUP-3 kept as four rows with the reason disclosed (§X note) |
| No real PII / secrets | ✓ | no credentials, no tokens; the only host paths are the declared worktree, the `~/.claude` destinations already named in `PLAN.md` §11, and the scratchpad snapshot |
| Results left blank unless actually run | ✓ | every `LANDED` / `NOT LANDED` flag is a grep executed this session (§M-3); nothing is predicted |
| No unfilled template | ✓ | no `<...>`, no `TC-NNN` placeholders, no empty required cell |
