# batch-64 — Phase 1, ARCHITECT lane: HLR/LLR derivation + the control text

> **BLUF.** Six HLRs and nineteen LLRs derived, and the three controls drafted ready to paste.
> **Discrimination verdict, honestly: two of the three controls are genuinely new and one is
> substantially a restatement.** C-42 (project) and the `VERIFY.md` extension are novel with a
> measured counterexample each. C-40 is **partly a restatement** — the flow ALREADY requires a RED
> counterfactual at `dev-flow.md:99` and `:177`, and batch-63's five vacuous predicates happened
> anyway; C-40's real and defensible novelty is the *enforcement point*, not the idea, and I have
> written it that way. C-41 is the weakest on independent novelty — it is close to C-35 and I
> recommend it be encoded with an explicit `EXTENDS C-35` clause rather than as a free-standing peer.
>
> **Two blocking findings against this batch's own §2.6 acceptance criteria** — both are the batch's
> own defect class committed inside the batch: (F-1) the AT-B64-05 stack-free predicate as written is
> **RED against the current, correct `dev-flow.md`**; (F-2) the AT-B64-10 census as written is
> **GREEN by construction** because batch-64's own proposal artifacts already contain `C-40/41/42`.
> Both are measured below with pasted output. **Layer A (white-box TC) is agreed N/A**, with the
> argument given in §A.0 rather than assumed.

**Lane:** architect. **Inputs:** `PLAN.md`, `01-requirements.md` §2.6, `.dev-flow/BACKLOG.md:32-45`.
**Write surface honored:** this file only. `s19_app/`, `tests/`, `examples/`, `pyproject.toml`,
`REQUIREMENTS.md`, `PROJECT_RULES.md`, `CLAUDE.md` untouched.

---

## §0 — Executed evidence for every number in this document (C-35 / C-39 discipline)

Nothing below is predicted. Each row is the output of a command run in this session.

| # | claim | command | output |
|---|---|---|---|
| E-1 | pre-state, the three out-of-VCS files | `wc -l`, `wc -c`, `sha256sum` | `dev-flow.md` **275 lines / 59 259 B / `44660d7cfede148746ac27dcbb8cccabd11c9a420de94b6351b2c7e7ad10b883`**; `VERIFY.md` **182 lines / 10 142 B / `23cf75e6ae8d0a2c04489f99954ab7d6e976ae3eb93846cba9c8fb25ca9588ed`**; `project_devflow_control_lineage.md` **89 lines / 36 401 B / `d9f84f9e614100d2dddf612b65ec8a2c156c3679efbfe7b75a1f41b28a0386ee`** |
| E-2 | pre-state, the one in-VCS file | `wc -l docs/engineering-rules.md` | **125** |
| E-3 | `C-40`/`C-41`/`C-42` id census, boundary-correct `(^\|[^A-Za-z0-9_-])C-4[012]([^0-9]\|$)` over the six destinations | `grep -rE … ; grep -rEl …` | **13 / 10 / 11 hits**, and `grep -rEl` resolves them to **exactly three files: `.dev-flow/2026-07-27-batch-64/01-requirements.md`, `.dev-flow/2026-07-27-batch-64/PLAN.md`, `.dev-flow/state.json`** — i.e. batch-64's own proposal. **Zero hits in any encoding destination.** The ids are free. → but see **F-2**. |
| E-4 | stack-token baseline in the WHOLE `dev-flow.md`, pre-edit | `for t in …; grep -o "$t" \| wc -l` | `markdown-it` **0** · `&#160;` **0** · `Rich` **0** · `Textual` **3** · `SVG` **0** · `AST` **1** · `s19` **0** · `pytest` **2** |
| E-5 | where those live | `grep -n "Textual\|AST\|pytest"` | lines **57** (C-31, "walk the AST"), **149** (C-16, "a Textual/native TUI"), **177** (C-19), **194** (C-25, `pytest -q -m "not slow"`), **202** (Layer B, "Textual Pilot end-to-end") |
| E-6 | precedent: do existing GLOBAL controls cite project identifiers? | `sed -n '145p' \| grep -oE …` | C-35's block contains **`ASAP2_Demo_V161.a2l`, `parse_a2l_file`, `parse_characteristic_header`, `CHARACTERISTIC`, `char_type`** — five s19_app identifiers, all inside its `(Origin: …)`. C-39's block contains `SYM_A`, `U+2028`, `golden`×4/`goldens`×3. |
| E-7 | `BACKLOG.md` footer is stale | `grep -n "Controls encoded"` → `:143-144` | reads **`C-1..C-36`** while C-37/C-38 (project) and C-39 (global) exist; its stack-specific list `C-13/C-13.1/C-22/C-23/C-28/C-29/C-30` also omits **C-32, C-34, C-37, C-38** |
| E-8 | the five vacuous predicates | `05-postmortem.md:59-65` | table of 5, with author attribution (3 orchestrator) |
| E-9 | the executed counterfactual that proved them inert | `00b-measurements-rescoped.md:206` | `RED cases against the WRONG implementation: 0` |
| E-10 | the diagnosis in the primary record | `00b-measurements-rescoped.md:211-216` | *"both are pure functions of `lines`. **The writer never appears in the expression**, so no value it takes can depend on how bytes reach the disk."* |
| E-11 | P-3 running total is **disputed across three registers** | three greps | lineage `:11` says *"~7th occurrence over 3 batches, 4 in batch-62"*; `BACKLOG.md:35` says *"~9 occurrences over 3 batches"*; `MEMORY.md` says *"8+ occurrences (5 in batch-63 alone)"*. **≥5 are verifiable at `file:line` (§C.2).** The encoded control must cite the enumeration, never the disputed total. |

---

## §A — HLR / LLR derivation

**Convention.** IEEE 830 + EARS. `shall` appears only inside an HLR/LLR statement; `should` only in
informative text. Every HLR names its parent US; every LLR names its parent HLR **and** the file +
section it lands in.

### §A.0 — Layer A (white-box TC) is N/A, and here is the argument rather than the assumption

I was told Layer A is declared N/A and asked to argue if I disagreed. **I agree, on three grounds,
and one of them nearly failed.**

1. **There is no internal mechanism.** For every other batch the deliverable is a behavior produced
   by code, and a TC can reach the function that produces it. Here the producer is the editing agent
   and the deliverable IS the file. A "white-box" view of a paragraph is the paragraph.
2. **Every candidate TC collapses to the condemned form.** The only mechanically expressible
   white-box assertion is `"<substring>" in <file>` — which is exactly what `VERIFY.md:36` calls out
   (*"A green check that only goes red when you delete prose is not evidence"*) and what `PLAN.md` §6
   exists to prevent. Manufacturing TC ids here would institutionalise this batch's own defect class.
3. **The near-miss, recorded honestly.** HLR-B64-6 (out-of-VCS evidence) *does* carry a mechanically
   executable check — SHA256 + line-count reconciliation. That is the closest thing to a Layer A node
   in the batch. It is still **not** Layer A: it verifies the *edit transaction*, not an internal
   mechanism of the deliverable, and its observable is already owned black-box by `AT-B64-11`. Adding
   a TC id for it would be double-counting one observable across two layers to make a matrix look
   full — the exact P-7 failure this batch is encoding against.

**Consequence for traceability.** The batch carries **one** chain: `US → HLR → LLR → AT → observed
outcome`. The functional chain's `TC` leg is declared **N/A with the reason above stated in the
artifact**, not silently omitted. A reviewer checking "both chains exist" must read this section, not
count rows.

### §A.1 — HLR register

| HLR | parent US | EARS form | statement |
|---|---|---|---|
| **HLR-B64-1** | US-B64-1 | ubiquitous | The global `/dev-flow` command **shall** carry a Phase-1 control, identified `C-40`, that requires every acceptance-bearing predicate to name the component under test, name the mutation that turns the predicate RED, and record the executed transcript of that mutation — and that control **shall** contain the P-6 and P-7 failures as named examples within its own text rather than as separate controls. |
| **HLR-B64-2** | US-B64-2 | ubiquitous | The global `/dev-flow` command **shall** carry a Phase-1 control, identified `C-41`, stating that a predicate about produced output is written against the form the producer emits, and the normative body of that control **shall** be free of stack-specific identifiers. |
| **HLR-B64-3** | US-B64-3 | ubiquitous | `docs/engineering-rules.md` **shall** carry a control, identified `C-42`, that declares itself an extension of C-32 and C-37 and enumerates the emitted-form traps of this project's markup, export, and source-inspection stack. |
| **HLR-B64-4** | US-B64-4 | ubiquitous | The `tui-design` skill's `VERIFY.md` **shall** state, within its existing `## Pin the truth, not a string  [travels]` section, that pinning a runtime value is necessary but not sufficient and that the value **shall** be pinned in the form its producer emits — expressed in terms that hold for any terminal-UI project. |
| **HLR-B64-5** | US-B64-6 | ubiquitous | The canonical control-lineage record **shall** register `C-40`, `C-41`, and `C-42` with their destinations and origins, and **shall** record P-6 and P-7 as ABSORBED into C-40 and P-3 as DECOMPOSED. |
| **HLR-B64-6** | **US-B64-1, US-B64-2, US-B64-4, US-B64-6** (cross-cutting) | event-driven | **When** this batch modifies a file that is not under version control, the batch artifacts **shall** record that file's line count, byte count, and SHA256 both before and after the edit, together with the filesystem path of a pre-edit backup taken before the first write. |

> **Traceability note, flagged so a reviewer does not read it as an orphan.** HLR-B64-6 has **four**
> parent stories, because the out-of-VCS obligation is a property of the *destination*, not of any
> one story. IEEE 830 permits a cross-cutting requirement provided each parent is named; they are
> named. It is the only many-to-one edge in the batch.

### §A.2 — LLR register

Every row names its landing site. Line numbers are as measured this session (E-1/E-2) and **must be
re-derived at implementation time**, because increments applied in sequence shift them.

| LLR | parent | statement | lands in |
|---|---|---|---|
| **LLR-B64-1.1** | HLR-B64-1 | The C-40 control block **shall** be inserted as a single bullet in the `### Phase 1 — Requirements engineering` section, immediately after the `C-39` bullet and before the `Project-specific UI-geometry gates` pointer bullet. | `~/.claude/commands/dev-flow.md`, §`### Phase 1 — Requirements engineering` (between the bullets currently at `:147` and `:148`) |
| **LLR-B64-1.2** | HLR-B64-1 | C-40 **shall** contain two labelled example clauses — a positive control shaped to the implementation rather than to the rule, and a consolidation that drops observables — each stated as a rule with its own discharge, not merely as an anecdote. | same block |
| **LLR-B64-1.3** | HLR-B64-1 | C-40 **shall** state its DISTINCT-from relation to C-10, C-31, and C-39, and its EXTENDS relation to the `## Objective exit criteria` *Certainty* clause, naming the three axes on which it extends it. | same block |
| **LLR-B64-1.4** | HLR-B64-1 | *(flagged OPTIONAL — see §C.1 finding)* The *Certainty* clause **shall** gain a parenthetical cross-reference to C-40 so the two statements of the same idea cannot drift. | `~/.claude/commands/dev-flow.md:99` |
| **LLR-B64-2.1** | HLR-B64-2 | The C-41 control block **shall** be inserted as a single bullet immediately after C-40, in the same section. | `~/.claude/commands/dev-flow.md`, §`### Phase 1 — Requirements engineering` |
| **LLR-B64-2.2** | HLR-B64-2 | The **normative body** of C-41 — its rule sentence, discharge, rider, and EXTENDS clauses, i.e. the block excluding its `(Origin: …)` parenthetical — **shall** contain none of the tokens `markdown-it`, `&#160;`, `Rich`, `Textual`, `SVG`, `AST`, or any s19_app module, function, class, or fixture identifier. | same block |
| **LLR-B64-2.3** | HLR-B64-2 | C-41 **shall** state, in its own text, that stack-specific emitted-form traps belong in the project's `docs/engineering-rules.md` — making the destination boundary self-documenting rather than only externally asserted. | same block |
| **LLR-B64-3.1** | HLR-B64-3 | The C-42 control **shall** be added as a new `## C-42 — …` section placed immediately after the `## C-38` section and before the `## C-34` section. | `docs/engineering-rules.md` (after `:122`, before `:124`) |
| **LLR-B64-3.2** | HLR-B64-3 | C-42 **shall** enumerate, each with its own discharge, six mechanics: markup token TYPES over substring presence; entity spoofing of a structural delimiter; the escaped form of a character not being the character; a heading emitted inside a code-span wrapper; entity-bearing export text; and a language-aware parse over a regex for source-line predicates. | same section |
| **LLR-B64-3.3** | HLR-B64-3 | C-42 **shall** open by declaring itself an extension of C-32 and C-37 and stating the axis on which it differs from them (the producer under test). | same section |
| **LLR-B64-4.1** | HLR-B64-4 | The extension text **shall** be appended inside the existing `## Pin the truth, not a string  [travels]` section — after its final paragraph and before the `## Mutation-test every assert` heading — and **shall not** introduce a new `##` heading. | `~/.claude/skills/tui-design/VERIFY.md`, between `:38` and `:40` |
| **LLR-B64-4.2** | HLR-B64-4 | The extension text **shall** contain no occurrence of `CRC Designer`, `s19`, `a2l`, `mac`, or any path into this repository, and its illustrating example **shall** be written as a generic terminal-UI element (a rail label, a menu entry). | same section |
| **LLR-B64-4.3** | HLR-B64-4 | The extension **shall** state the counterexample in a form that distinguishes it from the section's pre-existing rule — namely that the failing predicate read a genuine runtime value and therefore satisfied the pre-existing rule in full. | same section |
| **LLR-B64-4.4** | HLR-B64-4 | The `[travels]` tag on the section **shall** be retained, and the batch artifact **shall** record the test that justifies retention. | same section + this lane's §B.4 |
| **LLR-B64-5.1** | HLR-B64-5 | The lineage record **shall** gain one entry in the file's existing `**NEW C-NN (batch, date, operator-approved → destination):**` form covering C-40, C-41, and C-42, each with its destination, its rule in one sentence, and its origin. | `project_devflow_control_lineage.md` |
| **LLR-B64-5.2** | HLR-B64-5 | The lineage record **shall** record P-6 and P-7 as **ABSORBED into C-40** and P-3 as **DECOMPOSED**, naming all four destinations including the one ruled out of this batch. | same file |
| **LLR-B64-5.3** | HLR-B64-5 | The `## Controls encoded — do NOT re-encode` footer **shall** be corrected from `C-1..C-36` to the measured range including C-37, C-38, C-39 and the three new ids, and its stack-specific list **shall** be corrected to include C-32, C-34, C-37, C-38. | `.dev-flow/BACKLOG.md:143-144` |
| **LLR-B64-6.1** | HLR-B64-6 | Before the first write to any out-of-VCS file, a byte-identical copy **shall** be taken to a path recorded in the batch artifacts. | new `.dev-flow/2026-07-27-batch-64/03-out-of-vcs-evidence.md` |
| **LLR-B64-6.2** | HLR-B64-6 | For each out-of-VCS file the evidence record **shall** carry a PRE row and a POST row, each with line count, byte count, and SHA256, plus the delta in lines and bytes. | same file |
| **LLR-B64-6.3** | HLR-B64-6 | **If** a POST SHA256 equals its PRE SHA256 for a file the batch claims to have edited, **then** the batch **shall** treat that as a failed increment and block the gate. | same file |

---

## §B — The control text, ready to paste

### §B.1 — C-40, for `~/.claude/commands/dev-flow.md`, Phase-1 section

*(House style: one bullet, bold lead-in, discharge, EXTENDS/DISTINCT clauses, `(Origin: …)`.
Governs **Phase 1** at authoring, and is a **Phase-2 blocker** when unmet — the same binding C-35,
C-36 and C-39 carry.)*

```markdown
- **Falsifiability-before-correctness (C-40) — "can this predicate go RED?" is a SEPARATE gate question from "is this predicate correct?", and it is answered at AUTHORING time, by EXECUTION:** every acceptance-bearing predicate — a black-box `AT`, an `LLR` acceptance clause, a `TC`, **and any measurement probe whose number a gate is keyed on** — MUST, in the artifact that introduces it, (a) name the **component under test** and confirm that component **appears in the predicate's own expression**, (b) name the concrete **mutation** that turns the predicate RED, and (c) **execute that mutation and paste the transcript**, including confirmation that the mutation actually applied (a typo'd mutation also "fails", for the wrong reason). A predicate that stays GREEN under a mutation of the very thing it claims to certify is **inert: rewrite it, do not re-argue it.** **The static half is free and catches most of it** — read the expression and ask which symbol in it the implementation could change; a predicate relating two pure functions of the same input certifies arithmetic, not the implementation, no matter how exact the arithmetic is. **DISTINCT from the three controls it is most often mistaken for, and one batch measured that all three miss it:** C-10 mutates the CODE at the AT surface, C-31 mutates the INPUT SET, C-39 executes the THRESHOLD the gate is keyed on — a predicate can satisfy all three, be arithmetically exact, quantify over a complete set, carry a measured number, **and still never mention the component under test.** EXTENDS the §Objective-exit-criteria *Certainty* clause ("the counterfactual shown — the AT RED on the pre-fix tree") on three axes: from a **gate-exit** obligation to a **per-predicate authoring-time** one; from `AT-NNN` alone to **every acceptance-bearing predicate**, including `LLR` clauses, `TC`s and probes; and from "shown" to "**executed, with the transcript pasted**". **Two named instances, both of which pass every other control:** **(i) a positive control shaped to the IMPLEMENTATION instead of to the RULE** — deriving a detector's positive cases from the cases the detector already catches makes the control a tautology that certifies a completeness the detector does not have; shape the case set from the RULE's own statement, then establish each case's status independently of the detector. **(ii) a consolidation that drops observables** — when N artifacts are merged into one, the **union of their observables** is the subject under test, so the merge MUST either carry every observable forward or print an explicit retirement line naming what was dropped and why; an id-range table is a container, not evidence of preservation, and a green traceability count over the survivors cannot see the casualties. (Origin: batch-63 — **five** vacuous acceptances in one batch for one defect, three of them authored *after* vacuity was already that batch's identified theme and three of them the orchestrator's (`05-postmortem.md:59-65`). All five related an accounting helper to a string join — both pure functions of the same input — while the writer, the actual component under test, never appeared in the expression (`00b-measurements-rescoped.md:211-216`); when the counterfactual was finally executed it read `RED cases against the WRONG implementation: 0` (`:206`). Instance (i) is `AT-193b`, built only from cases its own detector already caught. Instance (ii) is the revision-3 fold, which replaced a 40-row TC layer with three id ranges and dropped **8 of ~18** union observables — including the one both Phase-1 lanes had independently agreed on, and including the only structural check the merge gate could actually run (`02-regate-discharge-qa.md:66`, `:102`).)
```

### §B.2 — C-41, for `~/.claude/commands/dev-flow.md`, Phase-1 section, immediately after C-40

**Stack-free by construction and verified mechanically in §C.4.** Note the deliberate circumlocutions
that keep the constraint: *"the producer's own parser token stream"* rather than the parser's name,
*"a language-aware parse of the source"* rather than the tree's acronym, *"an entity-bearing export"*
rather than the export format.

```markdown
- **Assert against the EMITTED form (C-41) — a predicate about produced output is written against the bytes/tokens the PRODUCER actually emits, never against a character list, the human-readable rendering, or the specification's own vocabulary for the thing:** whenever an `AT`/`LLR`/`TC`/probe searches, counts, or matches inside output that a component produces — a file, a document, an export, a serialized payload, a rendered screen buffer — the predicate MUST be derived from an **executed** run of that producer whose **actual output is pasted into the artifact**, and written against that pasted form. **Producers escape, encode, wrap and substitute**, so the form a human reads is routinely NOT the form on the wire: a search for the readable form **false-fails a CORRECT implementation**, and a hand-listed set of characters silently under-matches every character the producer spelled differently. **The failure is quiet and symmetric, and that is what makes it expensive** — it returns a plausible number, so a predicate that under-counts by two orders of magnitude reads as a measurement rather than as a bug. **Discharge, mechanically:** run the producer → paste the emitted bytes for the exact field or line under test → write the predicate against those pasted bytes → and prefer a predicate over the producer's own **structured** output (its parser's token or element stream; a language-aware parse of the source) to a substring search over serialized text, because a substring search cannot tell a value apart from its own encoding. **Rider — three spellings of the same mistake, each of which looks like careful work:** a `startswith`/prefix guard over a formatted line (widths, separators and padding are the producer's choice, not the predicate author's); a hand-listed character class standing in for "this field is inert"; and a predicate written from the requirement's wording instead of from the output. **Corollary worth keeping:** when a probe returns an *impossible* value rather than merely a low one, that is luck, not detection — an under-counting predicate that stays plausible ships. EXTENDS **C-35** — which executes the PRODUCT's transform over a real input and confirms the named outputs *exist* — from *existence* to *exact emitted form*; and EXTENDS **C-36** — which reconciles an acceptance literal to a constant DEFINED on disk — from the *source-side definition* to the *output-side encoding of that same constant*, the point being that a literal can satisfy C-36 completely and still be unfindable in the output. Stack-specific emitted-form traps (a given markup library's token rules, a given exporter's entity set, a given renderer's style carrier) belong in the project's `docs/engineering-rules.md`, never here. (Origin: the standing `assert-the-emitted-encoding` candidate, **≥5 occurrences verified at `file:line` across three batches** — a prefix guard over formatted rows reporting 4 where 400 were emitted, *"the artifact was correct, the predicate was wrong"* (`2026-07-26-batch-63/01-requirements-architect.md:1044-1049`); a heading emitted inside a code-span wrapper, whose absence probe returned an **impossible** `-1` and was caught only for that reason (`2026-07-26-batch-63/00-measurements.md:96-98`); a `"](" not in note` clause that **failed against a correct implementation** because the emitted form is `\](` (`2026-07-25-batch-62/04-validation.md:191-192`); an entity-bearing export against which a literal search for a plainly visible label matched **0 of 19** (`2026-07-25-batch-62/01b-qa-catalog.md:284-286`); and an escaped-entity payload that forges a structural fragment while every parsed token stays plain text (`2026-07-25-batch-62/02-review-security.md:68`). Three registers disagree on the running total (7 / ~9 / 8+) — cite the enumeration, never the total.)
```

### §B.3 — C-42, for `docs/engineering-rules.md`, new `##` section after C-38

*(House style there is different: a `## C-NN — title (Phase, scope)` heading, then flowing prose with
an inline `(Origin: …)`. Matches C-32 and C-37.)*

```markdown
## C-42 — assert against the EMITTED form of this stack's producers (Phase 1/3, extends C-32/C-37, markup + export + source-inspection paths)
C-32 and C-37 answer *which render layer holds the fact* for a **widget** — geometry at `render_line`, colour at `render().spans`. C-42 is the same discipline one producer over: for the **document, export and source-scan** paths, the question is *which encoding holds the fact*, and the answer is almost never the readable one. The global control C-41 states the principle; this section is the list of ways this project's producers actually spell things, and every entry cost a real predicate.

- **Assert markup token TYPES, not substring presence.** The report's markdown is consumed by `markdown-it-py`; a payload's inertness is the claim that *every token the field produces is `text`* (`{t.type for t in toks} <= {"text", "softbreak"}`), not that some hostile substring is absent. Subtracting a benign token baseline is blind by construction — an injected `# PWNED` heading reports "no change" under subtraction, because the benign report already emits `heading_open`. Pair the token-type clause with a content clause: `{t.type} <= {"text"}` alone is also satisfied by an escaper that simply **deletes** the payload.
- **`&`-entity spoofing: the tokens can all be `text` and the table can still be forged.** `SYM_A&vert;PASSED&vert;0x0` renders as `SYM_A|PASSED|0x0` — a forged verdict fragment — while every token stays `text`. Escaping `&` is what closes it; the *predicate* lesson is that a token-type assertion is necessary and not sufficient when the renderer resolves entities after tokenisation.
- **The escaped form of a character is not the character.** `"](" not in note` **failed against a correct implementation**: the emitted form is `\](`, because `]` is escaped and `(` needs no escape once the bracket pair is dead. Write the predicate against the escaped spelling, or against the parsed token, never against the character pair you were defending.
- **Mode-B code spans make a heading unfindable by its bare form.** A heading emitted as `` #### Checklist: `chk.json` `` does not match a search for `#### Checklist: chk.json`. This one was caught only because the probe returned an **impossible** `-1` ("heading absent") instead of a merely low count; a Mode-B predicate that under-counts plausibly ships silently.
- **Snapshot export text carries `&#160;` entities.** `pytest-textual-snapshot` SVG output spells spaces as `&#160;`, so a literal grep for a label that is plainly visible on screen matched **0 of 19**. Assert against the entity-decoded text, or against the widget's runtime value — not against the raw export bytes.
- **Use an AST census, not a regex, for any predicate over source lines.** An implicitly-concatenated f-string is **one assembled template**, not the two physical lines it occupies, so a line-oriented regex census both over- and under-counts. The AST structural census is also the form CI can actually run when the behavioural difference is platform-specific — and it is the check that a consolidation dropped in batch-63, which is how this project learned that a structural census and a behavioural mutation test are complementary, never substitutes.

**Discharge for any new predicate on these paths:** run the producer over a real fixture, paste the emitted bytes for the exact field, and write the predicate against the paste — then apply C-40 and confirm the predicate can go RED. (Origin: five instances across batches 60-63, four of them false-failing a **correct** artifact: the entity-bearing snapshot grep at 0/19; `"](" not in note` (`.dev-flow/2026-07-25-batch-62/04-validation.md:191-192`); the `-1` code-span heading probe (`.dev-flow/2026-07-26-batch-63/00-measurements.md:96-98`); a `startswith("| 0x00001")` row counter reporting 4 rows where 400 were emitted (`.dev-flow/2026-07-26-batch-63/01-requirements-architect.md:1044-1049`); and the `&vert;` forged-table finding (`.dev-flow/2026-07-25-batch-62/02-review-security.md:68`). Two of the five were caught only because their value was *impossible* rather than merely wrong.)
```

### §B.4 — the `VERIFY.md` extension, appended INSIDE the existing section

**Placement:** after the existing paragraph ending *"…is testing nothing."* (currently `:38`), before
the `## Mutation-test every assert` heading (currently `:40`). **No new `##` heading.**

```markdown
**And a runtime value is still not enough — pin it in the form the producer EMITS it.** The rule
above is necessary and not sufficient, and the counterexample is the one authors reach for: searching
a snapshot export's source text for a label you can plainly see on screen. That search reads a real
runtime value, it satisfies everything above, and it can still return **zero matches against a
completely correct app** — because the exporter spells a space as `&#160;`, and colour never lived in
the string at all; it lives in the render spans. Same shape for a rail label wrapped by a
truncation ellipsis, a menu entry the compositor clipped, and any text that passed through an
escaper on its way out.

So: identify the **producer** of the thing you are asserting on, run it, and **look at what it
actually emitted** before writing the predicate. Then assert against that — the decoded text, the
span's style object, the widget's reactive — not against the spelling a human reads. The
tell that you got this wrong is a predicate that returns an *impossible* value (zero matches for
something visibly on screen, a negative index for something present). Treat that as luck: the same
mistake that under-counts by a plausible margin passes review and ships.
```

**Does the extension earn `[travels]`?** **Yes — retain the tag**, and here is the test applied
rather than asserted. `[travels]` claims the rule holds beyond this framework. The mechanism is
*source form ≠ rendered form at a producer boundary*, which is true of any HTML export, any ANSI
stream, any XML/SVG serializer, any JSON-escaped payload, and any markup escaper — none of which are
terminal-specific. The two illustrations are named generically (a snapshot export, a rail label, a
menu entry) and reference no application. **De-identification check:** the drafted text contains no
`CRC Designer`, no `s19`, no `a2l`, no `mac`, and no repository path — verified mechanically in §C.4.

---

## §C — The discrimination argument

This section decides whether each control earns its length. **Three verdicts: NOVEL, NOVEL,
PARTIAL-RESTATEMENT.** I applied each drafted control to the case it claims to catch and show the
working, because a control asserted to "catch" a case without being applied to it is the exact
defect this batch encodes against.

### §C.1 — C-40 vs C-10, C-31, C-39 — and the finding the brief did not ask for

**Against the three named controls, C-40 is genuinely distinct, and batch-63 measured it.** Take
vacuous predicate #1, `len(join) == _line_bytes - 1` (`05-postmortem.md:61`). Component under test:
the **file writer** (binary-mode vs text-mode). Working:

| control | what it mutates | applied to predicate #1 | result |
|---|---|---|---|
| **C-10** | the CODE at the AT surface; drive a non-default value; one AT per policy branch | the predicate is not operator-selectable and has no `A or B` policy branch; mutating the writer from binary to text mode leaves both `_line_bytes` and the join **unchanged**, because both are pure functions of `lines` | **stays GREEN** — measured: `RED cases against the WRONG implementation: 0` (`00b-measurements-rescoped.md:206`) |
| **C-31** | the INPUT SET | the assertion quantifies over nothing; there is no set to complete or to drop an element from | **not applicable** — the control has no purchase |
| **C-39** | requires the THRESHOLD be executed | the `-1` **is** an executed, correct convention; C-39 is fully satisfied | **satisfied and still vacuous** |
| **C-40** | requires the component under test to appear in the expression, and the mutation to be executed | the writer does not appear in `len(join) == _line_bytes - 1`; the static half fails without running anything | **RED at authoring time** |

**The finding the brief did not ask for, stated because it is real and it changes how C-40 should be
written.** The *idea* "a predicate must be able to go RED" is **already in the global command, in two
places**:

- `dev-flow.md:99`, the **Certainty** exit criterion: *"every acceptance is non-vacuous: the
  black-box `AT` observes the deliverable through the SHIPPED surface (A-5), **with the
  counterfactual shown (the AT RED on the pre-fix tree)**, a negative control where an oracle is
  used… **No pass that cannot fail.**"*
- `dev-flow.md:177`, C-19, which names *"the RED counterfactual"* as gate evidence.

And the `tui-design` skill states the full loop (`VERIFY.md:40-49`: inject → confirm red → verify the
mutation applied → restore). **batch-63 produced five vacuous predicates anyway.** So a C-40 written
as "require a RED counterfactual" would be **a restatement**, would add ~1 500 bytes to a 59 KB file
consulted every batch (`PLAN.md` R-c), and would not have prevented the thing it cites as its origin.

**What genuinely did not exist, and what C-40 as drafted therefore encodes, is the BINDING:**

1. **Enforcement point.** `:99` binds at the **gate**, as a property of the phase. The five defects
   were authored in Phase 1 and survived to Phase 2. C-40 binds **per predicate, in the artifact that
   introduces it** — the same relocation C-39 performed for thresholds, which the postmortem records
   as one of the batch's few things that worked (`05-postmortem.md:19-22`).
2. **Scope.** `:99` and C-18 bind `AT-NNN`. Predicates #1–#3 were **LLR/TC-layer algebraic
   assertions**, and the batch-63 `chk_rows = -1` case was a **Phase-0 probe** — neither is an
   `AT-NNN`, so `:99` never reached them. C-40 names all four artifact kinds explicitly.
3. **The static subject-naming test.** Nothing in the flow currently says *read the expression and
   check the component under test is in it*. It costs nothing, needs no execution, and is the only
   clause that catches predicates #1–#3 before a probe is written. This is C-40's one genuinely new
   sentence.

**Recommendation, and it is a design call the operator can overturn:** encode C-40 as drafted **and**
apply LLR-B64-1.4 — one parenthetical at `:99` pointing at C-40. Without it, the flow states the same
requirement twice, in two registers, at two enforcement points, and they will drift; the drafted
EXTENDS clause makes the relationship explicit from C-40's side, and the cross-reference closes it
from the other. I have flagged LLR-B64-1.4 **OPTIONAL** rather than mandatory because it edits an
exit-criteria clause the operator did not put in scope.

**Absorption check (P-6, P-7).** Both are inside C-40's text (§B.1, clauses (i) and (ii)) and both
are stated as rules with discharges, not as anecdotes. Applying the drafted C-40 to each: `AT-193b`'s
component under test is the **rule's completeness**, and the expression contained only cases the
**detector** produced — the subject-naming test fails it statically. The revision-3 fold's subject is
the **union of observables**, and the id-range table's expression contained only the survivors — the
same test fails it. Both are caught by the same clause, which is the operator's stated reason for
absorbing rather than tripling.

### §C.2 — C-41 vs C-35 and C-36 — verdict: **weakest of the three; encode as an explicit extension**

**C-41 catches cases C-36 provably does not, and I can show the working.** The 0/19 export case: the
label is a **defined constant on disk** — C-36 is satisfied in full — and the predicate still
false-failed a correct implementation, because C-36 reconciles the literal *source-side* and says
nothing about how the producer *spells* it. Symmetrically, `](` in the batch-62 case is not a defined
constant anywhere, so C-36 has no purchase at all. **Verdict against C-36: distinct.**

**Against C-35, the margin is thin and I will not overstate it.** C-35 already says *execute the
producer over the real input, do not read the code and the input separately*. Apply C-35 to the
batch-63 code-span heading case: executing the report producer and confirming "a checklist heading
exists in the output" **passes** — the heading genuinely exists, the artifact was correct — while
`#### Checklist: chk.json` remains unfindable. So C-41 adds one step beyond C-35: **not merely that
the output exists, but that the predicate is written against the pasted bytes of that output.** That
is a real delta and it is one sentence wide.

**Verdict: C-41 is ~70 % C-35.** It is not a pure restatement — the delta is demonstrable — but it
does not earn a free-standing peer's worth of prose. **The drafted text is therefore written as an
explicit `EXTENDS C-35 … EXTENDS C-36 …` block**, which is how C-36 itself relates to C-15 and how
C-39 relates to C-35/C-31, so it is in-register. **Stated alternative, since the brief invites it:**
the same content could be encoded as a **rider on C-39/C-35** rather than a new id, which would cost
the reader ~600 bytes instead of ~2 000 and would not add an id to a register that is already drifting
(E-7). The operator ruled a new global control, so I have drafted a new global control; I am recording
the cheaper form so the ruling is made against a stated alternative rather than a default.

### §C.3 — C-42 vs C-32/C-37, and the `VERIFY.md` extension vs its own section — verdict: **both NOVEL**

**C-42 vs C-32/C-37: distinct on the producer axis, not merely on the id.** C-32 and C-37 govern the
**widget render path** — pre-layout content vs painted surface, geometry at `render_line` vs colour
at `render().spans`. C-42 governs **document/export/source producers** — markup tokenisation, entity
resolution, escaping, code-span wrapping, and source parsing. Apply C-32 to the `"](" not in note`
case: C-32 asks whether you read the painted surface instead of the pre-layout proxy; the report has
no painted surface and no compositor. **C-32 has no purchase; the case is untouched.** The two
controls do not overlap in producer, in failure mode, or in discharge. Adjacency in the file is for
the reader; the extension claim in the drafted heading is honest because C-42 reuses C-32's *method*
(probe the layer that holds the fact) against a different set of layers.

**The `VERIFY.md` extension is the sharpest of the four, and it refutes its own section.** The
pre-existing rule is *"assert on a runtime value, never on the presence of a label"* (`VERIFY.md:36-38`).
The counterexample: a substring search over snapshot export source **is** a runtime value, satisfies
that rule completely, and returned **0/19 against a correct implementation**. A rule with a measured
counterexample sitting inside its own scope is under-specified by definition, and the extension is
the minimal repair. **Verdict: NOVEL, and it is the one I would ship first if only one leg landed.**

### §C.4 — Applying this batch's own acceptance predicates to this batch's drafts — TWO BLOCKING FINDINGS

Executed against the drafts in §B and against the current files.

**F-1 — BLOCKING. The AT-B64-05 stack-free predicate as written in `01-requirements.md:66-68` is RED
against the CURRENT, CORRECT `dev-flow.md`.** §2.6 states the predicate as *"the encoded global text
contains **no** stack-specific identifier (no `markdown-it`, `&#160;`, `Rich`, `Textual`, `SVG`,
`AST`)"*. Measured (E-4/E-5): the **existing, unmodified** file contains `Textual` **×3** (`:149`,
`:202`) and `AST` **×1** (`:57`). A file-scoped implementation of that predicate reports RED before
C-41 is written. Worse (E-6): C-35's own block — a **global** control — contains
`ASAP2_Demo_V161.a2l`, `parse_a2l_file`, `parse_characteristic_header`, `CHARACTERISTIC`, `char_type`,
all inside its `(Origin: …)`. **So "no project identifier anywhere in a global control" is not the
house rule; it is contradicted by the house's own precedent.**

*This is the batch's own defect class, committed inside the batch: a predicate that false-fails a
correct artifact.* **Fix, encoded as LLR-B64-2.2:** scope the predicate to the **normative body** of
the C-41 block — rule sentence, discharge, rider, EXTENDS clauses — **explicitly excluding the
`(Origin: …)` parenthetical**, and state the measured whole-file baseline alongside so the exclusion
is visibly a boundary decision rather than a convenient carve-out. This is a QA-lane concern
(AT-B64-05 is theirs); I am reporting it, not rewriting their AT.

*Self-check of the §B.2 draft against the corrected predicate,* scanning the normative body only:
`markdown-it` 0 · `&#160;` 0 · `Rich` 0 · `Textual` 0 · `SVG` 0 · `AST` 0 · `s19`/`a2l`/`mac` 0. The
circumlocutions listed in §B.2 are what buy this. **Passes.** *(This scan is mine and must be re-run
mechanically by the QA lane against the final pasted bytes — my scan is over my own draft, which is
precisely the shape of P-6 if it is treated as the gate.)*

**F-2 — BLOCKING. The AT-B64-10 bidirectional census as written is GREEN by construction.**
`01-requirements.md:165-169` says *"when the union-grep census used at RC-1 is re-run after the batch,
the reader observes every encoded control id present in the lineage record and zero id registered with
no encoded text."* Measured (E-3): `C-40`/`C-41`/`C-42` **already** return 13/10/11 hits *today,
before any encoding*, and `grep -rEl` resolves every one to `.dev-flow/2026-07-27-batch-64/01-requirements.md`,
`.dev-flow/2026-07-27-batch-64/PLAN.md`, and `.dev-flow/state.json`. A census that includes the
batch's own proposal artifacts cannot distinguish "encoded" from "proposed" and therefore cannot go
RED for the failure it exists to detect. **Fix:** the census must be scoped to the **encoding
destinations only** — `~/.claude/commands/dev-flow.md`, `docs/engineering-rules.md`,
`~/.claude/skills/tui-design/VERIFY.md` — for the *encoded* side, and to the lineage record for the
*registered* side, with `.dev-flow/**` excluded from both. Again a QA-lane artifact; reported, not
rewritten.

**Positive note on the same census.** With that scoping, it is genuinely bidirectional and can fail in
both directions: encode C-42 and forget the lineage → RED; register C-41 and skip the paste → RED.

---

## §D — Increment plan

**≤5 files per increment, five increments. Recommended order and the reason for it.**

| inc | files | contents | why here |
|---|---|---|---|
| **Inc-0** | 1 new (`03-out-of-vcs-evidence.md`) + 3 backup copies | Capture PRE rows (line/byte/SHA256, §E) for the three out-of-VCS files; take the backups. **Edits no destination.** | Nothing is recoverable after the fact for files with no git history. This must precede the first write, not accompany it. |
| **Inc-1** | `docs/engineering-rules.md` (1) | **C-42.** | **The only leg inside version control** — it is the only work a PR, CI, and diff review can see. Landing it first means an interrupted batch has banked its reviewable output. It is also the leg with the strongest independent novelty verdict (§C.3), so it is the one worth protecting. |
| **Inc-2** | `~/.claude/skills/tui-design/VERIFY.md` (1) | The section extension. | Fully independent: no id allocation, no cross-reference to C-40/C-41, no self-reference to the running command. Cheap and isolated. |
| **Inc-3** | `~/.claude/commands/dev-flow.md` (1) | **C-40 + C-41 together, one atomic write** (+ LLR-B64-1.4 if approved). | **This is the R-d increment.** Reasons for placing it late and doing it in one write, below. |
| **Inc-4** | `project_devflow_control_lineage.md`, `.dev-flow/BACKLOG.md`, `03-out-of-vcs-evidence.md` (3) | Lineage entry + ABSORBED/DECOMPOSED records + the stale-footer fix + the POST rows and deltas. | US-B64-6 records the ids, so it must follow their landing. The POST rows close HLR-B64-6. |

**R-d sequencing, argued rather than deferred.** The risk in `PLAN.md` §7 is that editing
`~/.claude/commands/dev-flow.md` changes the command this batch is executing under. Three
observations decide the order:

1. **The running instance is not live-reloaded.** The command text was read into context at
   invocation; editing the file mid-batch does not retroactively change this batch's obligations. The
   risk is therefore *not* self-modification of the current run.
2. **The real exposure is a resume or an interruption.** The flow has an explicit interruption
   protocol (`dev-flow.md:108-111`) whose resume rule is *"re-verify the on-disk tree state before
   extending"*. A resumed or concurrently-started invocation **would** re-read the file. So the
   hazard is the *window during which the file is half-edited*, not the edit itself.
3. **Therefore: minimise the window, do not merely postpone it.** C-40 and C-41 land in the same
   section of the same file. Splitting them into two increments doubles the window and creates an
   interval in which C-41's `EXTENDS C-35` neighbour exists but C-40 does not. **One atomic write,
   late in the batch, after a backup, is strictly better than two writes at any position.**

Inc-1 before Inc-3 also means that if the batch is interrupted at any point, the highest-value and
most-reviewable leg is already in a PR.

---

## §E — Out-of-VCS evidence design

**The problem, stated plainly:** three of the four legs have no git history, no CI, no diff review,
and no reviewer other than whoever reads this batch's artifacts. If an edit lands wrong, nothing in
the system will ever say so. The record below is the whole of the review surface for those legs, so
it is specified to be executable, not descriptive.

**Artifact:** `.dev-flow/2026-07-27-batch-64/03-out-of-vcs-evidence.md`.

**PRE capture — run before the first write of Inc-1** *(the PRE values are already measured, E-1, and
are reproduced here so the executor can diff rather than re-derive):*

```bash
BK=".dev-flow/2026-07-27-batch-64/backup-pre"
mkdir -p "$BK"
for f in "$HOME/.claude/commands/dev-flow.md" \
         "$HOME/.claude/skills/tui-design/VERIFY.md" \
         "$HOME/.claude/projects/C--Users-jjgh8-OneDrive-Documents-Github-s19-app/memory/project_devflow_control_lineage.md"; do
  cp -p "$f" "$BK/$(basename "$f")"
  printf "%s | %s | %s | %s\n" "$f" "$(wc -l < "$f")" "$(wc -c < "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
done
```

**Table the artifact must carry** (one row per file per state; PRE values already measured):

| file | state | lines | bytes | SHA256 | backup path |
|---|---|---|---|---|---|
| `~/.claude/commands/dev-flow.md` | **PRE** | 275 | 59 259 | `44660d7cfede148746ac27dcbb8cccabd11c9a420de94b6351b2c7e7ad10b883` | `.dev-flow/2026-07-27-batch-64/backup-pre/dev-flow.md` |
| `~/.claude/commands/dev-flow.md` | POST | *(measure)* | *(measure)* | *(measure)* | — |
| `~/.claude/skills/tui-design/VERIFY.md` | **PRE** | 182 | 10 142 | `23cf75e6ae8d0a2c04489f99954ab7d6e976ae3eb93846cba9c8fb25ca9588ed` | `.dev-flow/2026-07-27-batch-64/backup-pre/VERIFY.md` |
| `~/.claude/skills/tui-design/VERIFY.md` | POST | *(measure)* | *(measure)* | *(measure)* | — |
| `…/memory/project_devflow_control_lineage.md` | **PRE** | 89 | 36 401 | `d9f84f9e614100d2dddf612b65ec8a2c156c3679efbfe7b75a1f41b28a0386ee` | `.dev-flow/2026-07-27-batch-64/backup-pre/project_devflow_control_lineage.md` |
| `…/memory/project_devflow_control_lineage.md` | POST | *(measure)* | *(measure)* | *(measure)* | — |

**Three properties that make this a check rather than a log** — each can fail, which is the point:

1. **Change proof (LLR-B64-6.3).** POST SHA256 ≠ PRE SHA256 for every file the batch claims to have
   edited. An unchanged hash on a claimed edit is a **failed increment**, not a note. This is the one
   assertion in the batch that goes RED on the most likely real failure mode: an edit that silently
   did not apply, in a file no diff will ever show.
2. **Bounded delta.** Record `Δlines` and `Δbytes` per file and state the expected magnitude before
   the edit. `dev-flow.md` gains **2 lines** (C-40, C-41 — one bullet each, the file's controls are
   one-line bullets); `VERIFY.md` gains the extension paragraph block; the lineage gains **1 entry**.
   A `Δlines` an order of magnitude off means something other than the intended edit happened —
   an accidental reformat, a truncation, an editor rewriting line endings. **This is the axis that
   catches a whole-file mangling, which a hash-changed check cannot distinguish from a good edit.**
3. **Restorability.** The backup path is recorded, and a `sha256sum` of the backup equals the PRE
   hash of the original. Without this the batch has no rollback for three of four legs.

**Also record, because it is the only external reviewer these legs get:** the exact inserted text is
already in §B of this file, so a reviewer can diff §B against the POST file without access to the
pre-edit state. Cross-reference it from the evidence artifact.

---

## §F — Evidence checklist (per the architect role's gate obligation)

| item | ✓/✗ | evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | zero-code write surface (`PLAN.md` §11) honored — this lane wrote one file; ≤5 files/increment (§D); stack-free boundary (LLR-B64-2.2); de-identification (LLR-B64-4.2); `shall`-only-in-HLR/LLR observed throughout §A |
| ≥2 alternatives considered | ✓ | C-41 as a new control **vs** as a C-39/C-35 rider (§C.2, both costed); C-40 as drafted **vs** amending `dev-flow.md:99` alone (§C.1); C-42 placement after C-38 **vs** end-of-file (LLR-B64-3.1, file is not numerically ordered so neither breaks an invariant) |
| Recommendation tied to constraints | ✓ | Inc order derived from R-d + the in-VCS/out-of-VCS split (§D); each of the three sequencing observations is a stated constraint |
| Risks listed | ✓ | F-1 and F-2 (§C.4, both blocking); control bloat quantified (§C.1: ~1 500 B into 59 259 B); registry drift (E-7); the half-edited-file window (§D) |
| Cost / latency estimated where relevant | ✓ | not a runtime system; the analogous cost is reader cost — measured as bytes added to a file read every batch (§C.1, §C.2) |
| Diagram included when flow is non-trivial | ✗ | **not included, deliberately.** The batch has no runtime flow; the increment sequence is a 5-row linear table (§D) and a diagram of it would add no information. Recorded as a considered omission, not an oversight. |
| What would change the recommendation | ✓ | §G below |
| Two-layer requirements | ✓ **with a declared N/A** | behavioral chain `US → HLR → LLR → AT` complete for all six HLRs; the functional chain's `TC` leg is **N/A with the argument at §A.0**, not silently dropped. A reviewer must accept or reject that argument explicitly. |

## §G — What would change these recommendations

- **C-40's scope.** If the operator prefers minimum length over an independent id, the same content
  fits as an amendment to the `## Objective exit criteria` *Certainty* clause plus the one new
  static subject-naming sentence — roughly one third the bytes. I did not take that route because the
  operator ruled a new global control; the tradeoff is stated in §C.1 so the ruling stands against a
  known alternative.
- **C-41.** If the operator accepts the ~70 %-overlap finding (§C.2), fold it into C-35 as a rider
  and free `C-41`. This is the single largest length saving available and the one I would take if
  reader cost were the binding constraint.
- **F-1's resolution.** If the operator decides a global control may cite no project identifier at
  all — a stricter rule than the file currently follows — then **C-35's existing `(Origin: …)` is
  already in violation** and that is a separate cleanup item, not a batch-64 blocker. Either ruling
  is coherent; the current draft assumes the house precedent (identifiers permitted in Origins only).
- **The course leg (US-B64-5).** Out per the operator's ruling. If it comes back IN, HLR-B64-6's
  parent set grows and the M13 harness gap must be resolved first — `SPIKE`, not `READY`.

## §H — What I could not verify

1. **The P-3 running total.** Three registers disagree (E-11: 7 / ~9 / 8+). I verified **five**
   occurrences at `file:line` and wrote the control against the enumeration. The true total is
   unresolved and I did not resolve it — a full re-census across all 54 batch directories was out of
   this lane's scope. **Flagged: the encoded text must not carry a total.**
2. **`~/.claude/skills/tui-design/SKILL.md`.** I read `VERIFY.md` only. If `SKILL.md` states an
   overlapping rule, the extension could be redundant with it. Not checked.
3. **Whether `[travels]` has a formal definition** anywhere in the skill. I inferred it from usage
   ("holds beyond this framework") and applied that test in §B.4. If the tag has a stricter defined
   meaning, LLR-B64-4.4's justification needs re-deriving.
4. **The course leg's `PENDING-UPDATES.md`.** Ruled out of scope; I did not open it, so I cannot
   confirm the cross-references it is said to carry to the other three legs.
5. **My own stack-free scan of the §B.2 draft (§C.4)** is a scan of my own text by its author. It is
   evidence, not a gate. The QA lane must re-run it mechanically against the final pasted bytes —
   treating my scan as the gate would be P-6 committed inside the control that encodes P-6.
