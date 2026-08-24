# Handoff — the derived Atlas, and the one property it must never lose: MATCH WITH THE IFC

> **Written 2026-08-22. Operator ruling this session: the Atlas goes ahead, it is primordial that
> it works, and it must ALWAYS match the IFC.**
>
> **Re-derive every figure below.** The commands are named beside them. If a number here disagrees
> with what the command prints, **the command is right and this document is wrong.** Two sessions
> running have now found a hand-written figure that its own command contradicts, and the previous
> handoff carried a claim that was false *in the commit that wrote it*. Assume this one does too.
>
> **Read §3 and §5 first.** §3 is what the IFC is. §5 is the only hard part of the whole design.

---

## 0 · Verify the ground before trusting anything here

```bash
cd <worktree>                                              # dev-flow-68a67d
python ~/.claude/docs/tools/devflow-validate.py            # expect: 0 block · 231 notice · 12 n/a
python ~/.claude/docs/tools/devflow-validate.py --map --fetch   # V7 V15 V16 V17 green
#   V7 expects a54f4289184bd018. If V15 BLOCKs, somebody edited skills/dev-flow/ - see 10.2
python ~/.claude/docs/tools/devflow-validate.py --selftest      # expect exit 0, 152 arms
python tools/address_origin.py                             # A 14 · B 0 · C 14 · D 13 · U 0
python -m pytest tests/test_address_origin.py -q           # 21 passed
find .dev-flow -name "01-requirements.md" | wc -l          # 62  — NOT 61, see §6 N2
grep -rl "^COMPONENT" .dev-flow --include=01-requirements.md    # exactly ONE file
```

State at the cut:

| | |
|---|---|
| `s19_app` `main` | `a112eeb` — unchanged; **nothing merged this session** |
| working branch | `claude/batch-82-lane-a-scoping`, **PR #199 open** |
| also open | **PR #198** (D4 — the `AT-B83-06` contradiction) |
| flow | **`2026.08.23-rev41`**, `flow_hash a54f4289184bd018` — rev40 and rev41 both shipped and pushed |
| all four repos | clean, `0/0` (`~/.claude`, `~/.claude/skills`, `~/kimi/agent-skills`, worktree) |
| batch-85 | `current_station: P5`, `phase_status: approved` — **CLOSED UNFINISHED** |

> ⚠️ **The previous handoff's §0 said batch-85 was `P2 / iterating`. It is not, and never was after
> that document existed:** commit `7cc0390` wrote the handoff and moved `state.json` to
> `P5 / approved` **in the same commit**. Verified: `git show 7cc0390 -- .dev-flow/state.json`.
> The two readings give opposite instructions to an opening session — *resume the requirements
> iteration* versus *the batch is closed*. **CORRECTED 2026-08-23** — that row now reads
> `P5 / approved`, with a note in that document recording what it said and why it was wrong.
> The `flow` row there is deliberately NOT corrected: `rev39` was true at that cut.

---

## 1 · What shipped this session

| Work | Where its detail lives |
|---|---|
| **flow rev40** — `V18` (state.json's four failure modes) + `V19` (duplicate `COMPONENT` id), 140 → **152 arms** | `~/.claude/docs/FLOW-VERSION.md` changelog rev40 · `claude-config 2c6b9b3` · mirror `agent-skills 202cda5` |
| **Adversarial verification of the batch-85 handoff** — 13 of 15 defects confirmed, 2 mis-described, **7 new** | §6 below |
| **flow rev41** — `IEEE 830` → `ISO/IEC/IEEE 29148` at all 5 citation sites | changelog rev41 · `claude-config ca23e4f` · mirror `agent-skills 98b8cc7` |
| **Design proposal for the human Atlas (D-I)** | §4 below |

**rev40 came out of attacking rev38/rev39, which the previous handoff nominated as target #2 with the
words "Neither has an arm." It was right.** Both defects were found by *executing synthetic
instances the tree does not contain*, never by reading the code — and both kill mutations were
executed on copies before the arms were trusted.

---

## 2 · Reading order for whoever opens this

1. **§3** — what the IFC is. Everything else is meaningless without it.
2. **§5** — what "always matches the IFC" costs mechanically. This is the design.
3. **§4** — the Atlas proposal and the one-way door inside it.
4. **§6 / §7** — the open defects and decisions, if you are continuing batch-85 rather than starting
   the Atlas.

---

## 3 · What the IFC is — the glossary this handoff kept assuming

**IFC = Information Flow Contract.** It is control **C-54** of the `/dev-flow` system, and it exists
because of one measured failure:

> A requirement declares the **VALUE** a surface carries. It must ALSO declare the **ADDRESS** by
> which consumers reach it.

The origin, from batch-79: `LLR-120.2` said *"shall NOT alter the existing three artifact slots"*,
with the threshold *"the three slot rows' text unchanged (set equality)"*. **Apply that threshold as
written and it HOLDS. Six shipped tests broke anyway.** The requirement had declared the value; the
change moved the address. Set equality discarded the order, and the failure *was* the order.

The contract has two parts:

- **PART A — always owed.** `SOURCE → NODES → SINK`, each node naming the `owner` LLR that asked for
  it. Information flows exist in every system whatever the stack. *A node nobody owns is work no
  requirement asked for; an LLR claiming a transform with no node is unimplemented.*
- **PART B — conditional** on one deliberately stack-free question: *does the system's boundary have
  components a consumer can address independently?* A TUI with panels: yes. A headless library with
  one entry point: no — Part A and nothing else. When yes, each component declares `PARENT`,
  `INPUTS ⊆ PARENT.INPUTS` (**balancing** — the 45-year-old DFD term; do not invent another), and
  per output an `address`, a `cardinality`, an explicit `consumers` list, and an `owner`.
  **`consumers : none` is legal and MUST be written.**

**Where it physically lives:** as fenced `COMPONENT:` and `FLOW:` blocks inside
`.dev-flow/<batch>/01-requirements.md`. There is no separate IFC file. The template is
`~/.claude/templates/dev-flow/ifc-template.md`.

**What reads it:** mechanised rules in `~/.claude/docs/tools/devflow-validate.py` —

| Rule | What it checks |
|---|---|
| `V10` | every `FLOW` node names an owner, and that requirement exists |
| `V11` | every `OUTPUT` declares an address and a consumer list |
| `V12` | balancing — a component consumes and emits only what its parent declares |
| `V13` | who reaches a declared literal address and is **not** in its consumers (NOTICE) |
| `V14` | every declared consumer resolves to a file, and its `::symbol` is in it |
| `V19` *(new, rev40)* | one `COMPONENT` id, one declaration, across the merged corpus |

**The corpus they read is MERGED across all batches** (`_ifc_corpus`, rev38) — because a component
declared in one batch may be the PARENT of one declared three batches later. That merge is the point
of the staged retrofit, not a convenience.

> **The number that governs everything below: the IFC corpus today holds exactly ONE `COMPONENT`,
> `loaded_panel`, in `.dev-flow/2026-08-21-batch-85/01-requirements.md` — the record that two
> independent reviews returned BLOCK on.** Anything validated against the IFC today is validated
> against **n = 1, and that one is known bad.**

---

## 4 · The Atlas — where the design stands

**Operator ruling, already made and not reopenable:** the IFC is the **machine's** consolidated view
and is not to be touched. A **human** consolidated view is owed, **DERIVED BY COMMAND, never
hand-maintained**, covering not only the IFC but requirements, AT/TC and HLR/LLR. Registered P1 at
`.dev-flow/BACKLOG-CODE.md:290`, owed **before surface #2**.

**Ruling added this session: the Atlas is primordial, it must WORK, and it must ALWAYS MATCH THE
IFC.** That last clause is §5, and it is the whole engineering problem.

### 4.0 ⚠️ The model this design must serve — and §4.2's proposal assumed the WRONG one

**Operator declaration, 2026-08-23, recorded as an IN-PROGRESS change to `/dev-flow`:**

> Beyond the IFC, the artifacts for **requirements, test cases, checklists and traceability stop
> living per batch and become LIVING, INCREMENTAL documents.**
>
> Design rule: **the IFC is for MACHINE reading; the others are for HUMAN reading and audit — and
> both planes must be kept COHERENT.** When touching `/dev-flow` or writing those artifacts, **do
> not assume the old model in which the spec dies with the batch.**

**This is materially bigger than an index, and §4.2 below was designed against the old model.** The
proposal treats the per-batch corpus as fixed and adds a derived *report* over it. The declared
change moves the artifacts themselves: requirements, AT/TC, checklists and traceability become
standing documents that accumulate, with the batch record becoming their **increment** rather than
their **home**. **The consolidation IS the artifact, not a report about the artifact.**

**Requirements are the centre-piece of that human plane**, and the other three hang off them —
AT/TC discharge them, checklists gate them, traceability links them.

**The tension this opens, and it is NOT resolved — do not let a session paper over it:**

| | |
|---|---|
| `D-I`'s ruling says | the human view is **DERIVED by command, never hand-maintained** |
| the 2026-08-23 declaration says | requirements / TC / checklists / traceability are **LIVING documents for human audit** |

Those are compatible under exactly two readings, and **they lead to different machinery:**

- **(a) Derived.** The living documents are *generated* from the batch increments, and authoring
  happens only in the increments. Then `V20`'s digest guard (§5.2) is the whole design, and §4.3's
  "no sentences" rule holds.
- **(b) Authored and CHECKED.** The living documents are hand-authored — `REQUIREMENTS.md` already
  is, at 6,074 lines — and the machinery *verifies coherence with the IFC* rather than generating
  them. Then §4.3's non-duplication rule is **wrong**, §5.2's digest guard is **impossible**, and
  what is owed is a **coherence rule**, not a builder.

**Reading (b) is what "both planes must be kept coherent" most naturally says**, and it is what the
project already does with `REQUIREMENTS.md`. **Reading (a) is what `D-I` says.** Resolve this BEFORE
writing a line of `--atlas`, because the two readings do not share code.

**Everything in §4.2, §4.3 and §5.2 is written for reading (a) and must be treated as provisional
until this is ruled.** §5.1, §5.3 and §5.4 survive both readings — a coherence checker needs the same
corpus access, the same `UNPARSED` census and the same per-declaration rendering.

### 4.1 The reframing that must happen first

> **The one-way door is not the Atlas's format. It is the FIELD SET that surfaces #2…#27 must carry
> for the Atlas to be derivable at all.**

A derived document can be regenerated in any shape at any time — fully reversible. What is *not*
reversible is the shape of the 26 records that feed it. If the Atlas needs a per-output `surface`
tag, a stable id namespace, or a batch tag on every id, and 26 records were authored without them,
**those 26 records must be re-authored.**

**So the deliverable of this decision is a frozen minimum derivable field set, discovered by
EXECUTING a derivation over the one record that exists — not asserted on paper.** Choosing a layout
is the cheap half and can follow. This is `C-39` applied to a design decision.

### 4.2 The shape recommended

Four derived files under a declared derived-only home `.dev-flow/_derived/`, each answering one
question, generated by `devflow-validate.py --atlas [--write]`:

| File | Question | Source |
|---|---|---|
| `ATLAS-IFC.md` | how is the application addressed? | `_ifc_corpus` — **the existing merge, unmodified** |
| `ATLAS-TRACE.md` | where does every id live, and what is its state? | `.dev-flow/**`, registry, `tests/**` |
| `ATLAS-BATCHES.md` | what happened, batch by batch? | batch `state.json` + postmortem headers |
| `ATLAS-ORPHANS.md` | where are the holes? **plus the `UNPARSED` census** | the joins of the above |

**Written at Phase 6. Verified at every gate by a digest rule.** The precedent is exact and already
in the flow: `sync_bundle()` writes `skills/dev-flow/` as a declared duplicate and `V15` guards it by
digest equality in both directions. The Atlas rule is `V15`'s sibling over a different pair.

> ⚠️ **RENUMBER.** The proposal called that rule `V18`. **`V18` and `V19` were taken this session by
> rev40.** The Atlas rule is **`V20`**. Two rules sharing a number is the failure this flow has spent
> five revisions deleting.

### 4.3 The non-duplication rule that keeps it out of `REQUIREMENTS.md`'s way

`REQUIREMENTS.md` (6,074 lines, 149 `R-*`) is the product **canon**: normative prose, hand-authored.
The Atlas is an **index**: where things live and where the holes are. The discriminating rule, and it
is mechanically checkable:

> **Every line the Atlas emits is a heading, an id, a filesystem path, a URL, or a computed number.
> If a sentence from any source document appears in it, the build is wrong** — grep any 8-word
> sequence of the Atlas against the corpus; a hit is a build defect.

The Atlas **points into** `REQUIREMENTS.md` (`R-014 → REQUIREMENTS.md:5890`) exactly as it points
into a batch folder. And it gives `REQUIREMENTS.md` something that file cannot report about itself:
**which `R-*` no batch references, and which batch ids no `R-*` references** — the two orphan sets
that are the actual measure of *"the weave is complete, there are no holes."*

---

## 5 · "ALWAYS MATCHES THE IFC" — what that costs mechanically

**This is the operator's primary requirement, and it decomposes into four obligations. Three have
working precedents in this flow. The fourth is new and is where the design can still fail.**

### 5.1 Derive from the validator's own corpus, never a second parser

`--map` already solved this and stated the principle: *"its STATUS section calls the actual rule
functions and prints their actual findings, so it CANNOT disagree with the validator, because it IS
the validator. A map that recomputed its own verdicts would be the duplicate-oracle defect it exists
to end."*

**Therefore: `ATLAS-IFC.md` is rendered from `_ifc_corpus()` and the `_vNN_outcome()` cores — the
same functions `V10`–`V14` and `V19` call. Not a reimplementation. Not a regex over markdown.** A
second parser is a second source of truth and would make "always matches" unprovable by construction.

### 5.2 Guard the materialised copy by digest, both directions

`V20`: regenerate in memory, compare to what is committed, **BLOCK on difference**. Files carry a
`DERIVED — DO NOT EDIT` banner plus `flow_version`, `flow_hash`, corpus file count and digest.

**Why a guard and not a convention — measured, not argued:** the vault at
`G:\My Drive\...\s19_app\dev-flow-batches\` already holds 61 copies of `01-requirements.md`, also
"derived by command", and **6 of 61 have drifted from the repo original** (batch-14, 19, 32, 35, 47,
52; CRLF-normalised SHA-256). Nothing detects it. *The guard is the design; the file is incidental.*

### 5.3 The `UNPARSED` census — the risk that kills the design

A batch author writes a non-conforming heading. The parser cannot classify it. **That record then
silently vanishes from the Atlas, and the Atlas reads *complete*.**

This is the same species as `D-IV` (a control green because it has nothing to read) and as the
pilot's own `V13` defect. **Mitigation must be structural, not procedural:** `ATLAS-ORPHANS.md`
carries a mandatory census of every file and block the parser could not classify, counted and
listed, and `V20` BLOCKs when that count rises against the committed Atlas.

> **An Atlas that cannot state what it failed to read is not accepted.**

### 5.4 ⚠️ NEW, and it comes straight out of rev40: do not key the Atlas by `COMPONENT` id

**rev40 measured this, and it directly constrains the Atlas.** `_ifc_corpus` merges by
*concatenation*. When two batches declare the same `COMPONENT` id:

- `V11` counts the OUTPUTS of **both** declarations;
- `_v12_outcome` resolves parents through `{c["id"]: c for c in components}` and keeps only the
  **LAST**;
- the resulting message asserts an absence that is **false of the corpus**.

**Any Atlas renderer that builds `{id: component}` reproduces exactly this collapse, and it would do
so in the artifact whose entire purpose is to be the human's trustworthy view.** The Atlas must
render **one row per declaration**, carrying `(id, batch, file:line)`, the same way `ATLAS-TRACE` is
specified to carry one row per `(id, batch)` — and must surface `V19`'s NOTICE inline rather than
silently choosing a winner.

**This is untestable on today's tree.** The corpus holds one component and zero duplicates — a
`C-55` limb-2 load-bearing emptiness. **Discharge it the way rev40 discharged `V19`: build a
synthetic two-batch corpus with a colliding id and assert the Atlas renders both.** Do this *before*
surface #2 exists, because after it exists the case is no longer synthetic and a wrong Atlas is
already shipped.

---

## 6 · Open defects — 13 confirmed, 2 mis-described, 7 new

**Do not trust these as written. Each is a claim to re-execute.** All were verified by execution this
session with positive controls.

### The two that leave the batch with ZERO live gates

| # | Defect | Measured |
|---|---|---|
| **4** | `TC-B85-07`'s invariant (*"no `styles.tcss` comment contains a brace"*) is **RED on the unmodified tree** | 130 comment blocks scanned, 1 hit — at **`styles.tcss:992`**, NOT `:985` as the previous handoff states. `git diff --stat main -- styles.tcss` empty |
| **3** | `HLR-85.3` / `LLR-85.6` cite `pytest -k "b85"` | `no tests collected (2735 deselected)`. Positive control: same probe with `-k "origin"` → `21 tests collected` |

### The one that survived two corrections

| # | Defect | Measured |
|---|---|---|
| **1** | `HLR-85.1`'s `V13` threshold is projected over FILES; the signal lives in `(output_id, file)` PAIRS | Kill mutation executed in memory against `_v13_outcome`: add `.loaded-detail` to `screens_directionb.py` — **the edit `LLR-85.5` mandates** — and `findings=3` is UNCHANGED, `UNION=4` is UNCHANGED, only `pairs` moves 4 → 5. **The corrected threshold is still blind to the regression its own sub-requirement forbids.** State it over the pair set and paste the mutant transcript as a RED arm |

### The rest, confirmed

**#15** §6.3 lost *"0 BLOCK attributable"* → the batch has **no BLOCK criterion**; and the substitute
is a strict subset of **`V6` + `V1`**, *not* of `V4` — the previous handoff's fix direction is
mis-founded. · **#2** `tools/stale_consumer_census.py` and `tools/statement_modal_check.py` are cited
as executed and **do not exist** (positive control: `tools/address_census.py` does). · **#7**
`HLR-85.2`'s Statement vs threshold is unsatisfiable — the batch-79 site at
`03-increments/increment-011-merge-gate-response.md:39-41` is frozen and is a hit. · **#6** the site
population is stated **8** different ways, not six. · **#9** the document self-hits its own census
(4 hits inside address-scope) with no exclusion rule. · **#5** reacher union 3 vs 4 — executed:
3 findings / 4 files / 4 pairs. · **#12** `slot_rows`' annotation false for row 5 — see §8. · **#11**
`ifc_pilot_authoring`'s `fn` entries are process verbs with no `def` anywhere (but the handoff's
*"grep → 0 hits"* is wrong — it is 1 hit each, their own declaration). · **#13** `F-10` marked FOLDED
while `styles.tcss:197` and `:225-226` appear in no site list. · **#14** `P-2` declares rev38 — **two
sites** (`:12` and `:112`), and both are now **doubly** stale at rev40.

### Mis-described — a defect exists, but not the one described

**#8** `C-54-ENCODING-RECORD.md` correctly says the tree has four readers; what is stale is its
**site census** (says 2, the batch measured 5). Different fix. · **#10** *"the named false positive"*
**is** named — `PLAN.md:105`, which is the document's own reference R6. The real defect is that it is
resolvable only by leaving the document.

### New this session

**N1 — the most expensive.** §6.3's base ledger `2684 passed / 21 deselected` is **batch-83's**, not
batch-84's, and `BACKLOG-CODE.md:45` **already warns in writing that this figure is not comparable**
because the runs used different invocations. Today's tree: 2735 collected, 2714 not-slow. Δ **25**.
The batch's whole `post = base − D + A` arithmetic starts from a number its own backlog marks as not
a measurement. · **N2** corpus 61 → **62** (independently corroborated by rev40). · **N3** declared
ids 508 → **519** (P-10's conclusion survives). · **N4 / N5** two line-number contradictions inside
one document. · **N6** a **second** split-line instance at `styles.tcss:252-253`, unmarked, invisible
to a single-line grep for the same reason as the first. · **N7** the C-40 incident of §10.

---

## 7 · Open decisions

| # | Decision | State |
|---|---|---|
| **D-I** | The human Atlas | **RULED: goes ahead, primordial, must always match the IFC.** Design in §4 / §5. Field set not yet frozen — that is the next action |
| **D-II** | Is the pilot's record salvageable, or does surface #2 start clean? | **OPEN, and the evidence now leans hard.** The three worst defects (#1, #12, #7) are **format** failures, not authoring failures: projections that erase signal, an `address` uniting heterogeneous populations, a repo-wide Statement with no scope rule. Fixing the author does not fix those |
| **D-III** | `V1`–`V9` (active batch) vs `V10`–`V14` (merged corpus) use different artifact-selection semantics | **OPEN and now BLOCKING.** The Atlas needs a **third** semantics (whole corpus, all artifact classes). D-III asked whether a third rule class would want a third selector; **the Atlas design returns YES.** Do not adopt the Atlas without ruling D-III |
| **D-IV** | `docs/ARCHITECTURE.md` declares no `path/**` prefixes, so `V8` cannot check it and the **A-family of triggers has no oracle** | **CONFIRMED by execution** — 0 hits, positive control 1 hit. Untouched |
| **D-V** | The public-repo question | Untouched as instructed. Measured: `.dev-flow` **47,088** lines + `.fast-dev-flow` **3,732** = **50,820** in 994 files. The handoff's *"~47,400"* excludes `.fast-dev-flow/` — the directory `F-3` flags as visible to `V13`. **The Atlas raises the stakes of D-V without changing its content** |
| **D-VI** *(new)* | `/dev-flow-sync` step 4 orders copying `01-requirements.md` to the vault, **after its own step 0 says never copy an artifact whose declared home is the repo** | The command contradicts the homes rule it cites, and those copies are the 6 that drifted (§5.2) |
| **D-VII** *(new, and it GATES D-I)* | **Are the living human artifacts DERIVED, or AUTHORED-AND-CHECKED?** — §4.0 | **RULED 2026-08-23: HYBRID, two planes** — the Atlas (index) is DERIVED per D-I; the living canon (REQUIREMENTS.md, TC/checklists/traceability) stays AUTHORED with a coherence rule owed as separate scope. See `DECISION-D-VII-2026-08-23.md`. *(As written 2026-08-22 this row read BLOCKING — kept for the record.)* |

---

## 8 · `D-A`, the five-output decision — attacked, and it is three layers, not two

The previous handoff framed it as *either* the output is right and the annotation wrong, *or* the
decomposition is wrong. **Measured: all three, and the worst one is unnamed.**

1. **The output is real.** `query("#loaded_slots > Horizontal")` is literally what
   `tests/test_tui_variants.py::_project_label` uses.
2. **The annotation is false twice.** *(a)* the one the handoff names — row 5
   (`_build_unload_all_row`) has no kind or detail cell, arity 1↔2 by load state. *(b)* **the one it
   does not, and it is worse: `INDEXED POSITIONALLY` is false for the only declared consumer.**
   `_project_label` does a **linear sweep with a content predicate** (`cells[0].render() ==
   _PROJECT_KIND`), not an index over rows. Reordering the rows does not break it. What breaks it is
   the index *within* the row and the **value** of `_PROJECT_KIND` — which §1.3 puts outside the
   contract by definition. **The declared contract is stricter than the real coupling on one axis and
   blind on the other. That is the misaddressed-observable class, inside the record written to close
   it.**
3. **The decomposition is wrong.** The address unites two structurally distinct populations: 4 rows
   `.loaded-slot` (arity 2↔3) and 1 footer `.loaded-allrow` (arity 1↔2). And `cardinality : 5`
   collapses two independent invariants — *"1 + len(`_SLOTS`)"*, which moves if a fourth artifact is
   added (**the origin defect of `LLR-120.2`**), and *"exactly one footer"*, which never moves.
   **The union of 5 erases which one moved — defect #1's projection, one level down.**

**Recommendation: split into `artifact_row_set` (`query(".loaded-slot")`, cardinality 4) and
`unload_all_row` (`query(".loaded-allrow")`, cardinality 1). That is SIX outputs, not four.**

---

## 9 · Suggested next actions, in order

0. **Rule `D-VII` first (§4.0).** Derived, or authored-and-checked? Every action below assumes an
   answer, and the two readings do not share code.
1. **Freeze the field set by execution, not on paper.** Write the `--atlas` parser, run it over the
   corpus as it stands (n=1 IFC record, 62 requirement files, 1,372 registry rows), and **publish
   what it CANNOT produce.** That list *is* the minimum derivable field set, discovered rather than
   asserted. **Until this is executed, §4 and §5 are a hypothesis and must be labelled one.**
2. **Rule D-III.** The Atlas cannot be adopted before it (§7).
3. **Discharge §5.4 with a synthetic colliding-id corpus** before surface #2 exists.
4. **Time the regeneration** (§5.2's guard cost is an unmeasured estimate). If full regeneration
   exceeds ~10 s, `V20` must degrade to a file-list / mtime check — a weaker guard, and that trade
   should be decided explicitly rather than discovered at the first slow gate.
5. **Rule D-II** — the format evidence is in, and it argues for a clean start on surface #2.
6. ~~Fix the false `P2 / iterating` row in the previous handoff's §0.~~ **DONE 2026-08-23** —
   corrected with its record kept, per rev36. Nothing left here.

---

## 10 · The C-40 lesson, and this session repeated it

The previous handoff carried a warning: *"Two review agents were dispatched concurrently and one was
instructed to mutate a file the other was reading. Run mutations where no other session is reading."*

**This session made the same mistake, in a new shape.** The orchestrator declared an isolation plan —
*"agents read-only in `s19_app`; I mutate only `~/.claude`; no overlap"* — and it was **false**: the
agents verify by running `python ~/.claude/docs/tools/devflow-validate.py`, so the validator being
edited was a file both were reading. A reviewer detected it by timestamp (writes at 22:08:06 and
22:10:55, mid-review) and correctly declared its measurements in that window suspect.

**What limits it, measured rather than argued:** the reviewer re-ran its projection probe under rev40
and got an identical result, so finding #1 is stable across both revisions; and rev40 changed no
existing rule's verdict — s19_app reports **231 notices before and 231 after**, the only movement
being `+2 not-applicable` from `V18` / `V19` passing.

**The generalisation, which is the part worth carrying:** *"different repo"* is not isolation. The
unit of isolation is **the set of files the other party's commands READ**, and for anything running
the flow that set always includes `~/.claude`. The correct plan was to freeze the validator until the
reviewers finished, or to hand them a pinned copy.

---

### 10.2 A third shape: the revision that reached the mirror before the canon

**rev41 was authored directly in `skills/dev-flow/`, which is a BUILD OUTPUT of `--sync-bundle`, not
a source.** The canon kept `IEEE 830` at all five sites, and the mirror's own header still stamped
`rev40` while its changelog row claimed `rev41` — so the revision was incomplete on both sides at
once, and the *only* reason it was not silently erased is that nobody ran `--sync-bundle` in between.

**`V15` caught it — 4 BLOCKs naming the four drifted files.** That is exactly the copy-vs-copy drift
it was written for at rev13, and it is the one time in this session's record that a guard caught a
defect *before* a human noticed rather than after. Resolved by porting the five substitutions into
the canon, bumping there, and regenerating: `--sync-bundle` then wrote **exactly one file**, because
the other three already matched.

**Edit the source, never the copy.** The flow spent rev15, rev16 and rev20 each deleting one
duplicated list; this is the same defect wearing a different hat — a duplicated *file*, edited on the
generated side.


## 11 · Working-file reconciliation (C-44)

| Repo | State |
|---|---|
| `s19_app` worktree `dev-flow-68a67d` | clean `0/0` on `claude/batch-82-lane-a-scoping` (**PR #199**), this handoff included |
| `s19_app` worktree `flow-diagrams-rescued-11aacc` | clean `0/0` |
| `~/.claude` | ✅ clean `0/0` — rev40 `2c6b9b3`, rev41 `ca23e4f`, both **pushed** |
| `~/.claude/skills` | ✅ clean `0/0` — `202cda5`, `98b8cc7`, **pushed**. `3892357` here is the mirror-first rev41 of §10.2 |
| `~/kimi/agent-skills` | ✅ clean `0/0` — pulled to match |
| `C:\Users\jjgh8\flow-diagrams-rescued-2026-08-18\` | 📋 staging, 50 MB. The 11 editable sources are safely in `claude-config` at `docs/diagrams/`, **verified byte-identical by md5 this session**. The PNGs + PDF are derivable. **Delete when satisfied** |

**Two PRs open and unmerged, deliberately: #198 and #199.**

---

## 12 · One thing to carry forward

The Atlas exists to be the view a human **trusts**. Every failure catalogued in this document is the
same shape: *a projection that erases the signal it was chosen to carry.* Set equality erased the
order in `LLR-120.2`. The union over files erases the pair in `V13`. The cardinality of 5 erases
which of two invariants moved. `{id: component}` erases the losing declaration.

**An Atlas is a projection by definition — that is what an index IS.** So the discipline that makes
it safe is not care, and it is not review. It is that **every projection the Atlas takes must be
executed against a case that would move it, before it is trusted** — which is `C-39` and `C-55`
together, applied to a document rather than to a threshold.

**Encode nothing new from this.** Both controls already exist. What this session added is the two
arms that make them mechanical for `state.json` and for the merge — and the Atlas will need its own.
