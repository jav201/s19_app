# Design proposal — s19_app — Batch 2026-10-19-batch-97

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language
> The normative rules below are language-independent. **Where that language is declared:**
> `state.json`'s `language` key in `core` and `full`.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Design proposal` · `7 · Forward-applicability table` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **Why a HEADING is reserved here and a FIELD NAME everywhere else:** `C-49`'s artifact is the §7 TABLE, and a rule that read a summary bullet instead of the rows would be reading a claim about the table rather than the table. `V52` therefore keys on this document's own H1 and on the §7 heading, which is why both are on the machine plane. **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`.

> **Owed in.** `core` by trigger · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

> **Where this lives: the VAULT + Drive**, not the repo — it is deliberation, and its traceability to
> code is weak. It is **cited by id** from the repo (`PDR-<batch_id>#D<n>`), never copied.
> What binds code — a frozen interface, a design characteristic — also lands in the **repo**, in the
> requirement or in `docs/ARCHITECTURE.md`. *The vault keeps the deliberation; the repo keeps the commitment.*

> **The forward-applicability rule (ISO/IEC/IEEE 15288).** Everything below must be NAMED as the input
> of a later activity. **If a section of this proposal is nobody's input, delete it — it does not belong
> in the PDR.** That rule is what allows this document to cost half the batch without being waste.

| Field | Value |
|---|---|
| Id | `PDR-<batch_id>` |
| Requirements covered | `<R-NNN vN · …>` |
| Modules touched (from `docs/ARCHITECTURE.md`) | `<…>` |
| Triggers that fired | `<A1 · A3 · D1 …>` |
| Author / reviewers | `architect` · `qa-reviewer` · `<ux-reviewer if D fired>` |

---

## 1 · Objective and scope

*(What this design must achieve, in the requirement's own terms. And explicitly: what it will NOT do.)*

## 2 · Modules and boundaries

| Module | What it owns here | What it exposes | What it must NOT reach into |
|---|---|---|---|

- Boundaries respected as declared in `docs/ARCHITECTURE.md`: ✓ / ⚠ *(if a boundary must move, that is an ARQ change, not a design decision — go back)*

## 3 · Diagrams

*(Only the viewpoints that apply. IEEE 1016's other eight live here, not in the module map:
Logical · Information · Patterns · Structure · Interaction · State Dynamics · Algorithm · Resource.)*

## 4 · Interfaces that change — and which ones FREEZE

| Interface | Current | After | Consumers | **Frozen for the fork?** |
|---|---|---|---|---|

**A frozen interface is not touched inside a lane.** If a lane needs to change one, the work returns to
the trunk — that is trigger **A3**.

## 5 · Proposed test cases

| Id | Layer (0 unit / A white / B black / UX) | What it asserts | **The mutation that would turn it RED** |
|---|---|---|---|

**Declared here, at authoring time, not at execution time.** A proposed case whose reddening mutation
cannot be named is not yet a test case — it is a hope. Layer 0 applies where the unit has cyclomatic
complexity ≥3 **or** transforms data crossing a declared module boundary.

## 6 · Risks and rejected alternatives

> **Rejected alternatives are owed WHERE A REAL DECISION EXISTS**, otherwise `n/a — <the decision already made, and by what>` — an existing pattern, a frozen interface, a prior ADR. **Do not fabricate a second design to fill this section:** two invented options make an arbitrary pick look deliberated, which is worse than one honest constraint. (the same ruling as `agents/architect.md` §Evidence checklist and the PDR row — one obligation, three stations, and closing it at one of them is `C-14`.)

| Alternative considered | Why it was rejected |
|---|---|

*(Recording the rejection is what stops the same option being re-proposed in three batches.)*

## 7 · Forward-applicability table — **the section that makes this document honest**

| Output of this PDR | Named consumer downstream | Where the consumer will read it |
|---|---|---|
| design characteristics | the Phase-3 increments | `<…>` |
| enablers (fixtures, data, scaffolding, env) | Phase 3 and validation | `<…>` |
| proposed test cases | layers 0/A/B and the DDR | `<…>` |
| design → requirement traceability | the matrix and the DDR | `<…>` |

- ⚠ Any row whose consumer column is empty: **remove the output, or explain why it is being produced.**

## 8 · Parallelisation plan *(only if the batch forks)*

| Lane | Modules / layer | Files it owns | Agent |
|---|---|---|---|

- `modules(lane_i) ∩ modules(lane_j) = { }` — or same domain / different layers with the interface frozen: ✓
- **File sets are disjoint** (not just modules — two lanes may not edit the same file, not even different regions): ✓
- Family-B reverse census run **per lane and shared** before forking: ✓
- Trunk-only artifacts (requirements · traceability · backlog · SPEC) are written **only** by the trunk: ✓
