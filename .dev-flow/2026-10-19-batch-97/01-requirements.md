# Requirements Document — s19_app — Batch 2026-10-19-batch-97

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development language (`state.json` `language`). For Spanish batches, translate the **prose** — section headers and guidance — **and never a label**, and use `deberá` as the normative keyword (≡ `shall`). The normative RULES in this preamble are **language-independent** and enforced regardless of artifact language.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/req-template.md` and its part 2, `templates/guides/req-template.part2.md`, explain each field below and the rules that read it. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Validation` · `Acceptance test(s)` · `Boundary catalog` · `Negative control` · `Premise evaluation` · `Fork preconditions` · `Ledger` · `Requirement` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

---

## 1. Introduction

### 1.1 Purpose
*(Informative text. Describes the document's objective.)*

### 1.2 Scope
*(What this batch covers and what it does NOT cover.)*

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| | |

### 1.4 References
*(Related documents, standards, external tickets.)*

### 1.5 Document overview
*(How this document is structured.)*

---

## 2. Overall description

### 2.1 Product perspective
*(How the change fits into the larger system.)*

### 2.2 Product functions
*(High-level list of functional capabilities.)*

### 2.3 User characteristics
*(Roles, permissions, expected experience levels.)*

### 2.4 Constraints
*(Technological, regulatory, business.)*

### 2.5 Assumptions and dependencies
*(What we take for granted. If an assumption fails, the batch is invalidated.)*

### 2.6 Source user stories

Source for every story: the operator-approved prototype round `prototypes/b94_polish/` (verdict
`veredicto-b94-polish.md`, final section: **A on all four screens**, confirmed in chat 2026-10-19
"Sí, cambié de opinión") and its implementation brief `.dev-flow/design/HANDOFF-b94-polish-2026-10-20.md`
(§1 verdict, §3 R-1..R-9). The handoff file carries the next calendar day in its name (written
past midnight UTC); the batch dates are local days.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-134 | As the calibration engineer editing a change-set, I want the Patch Editor as a full-height entries ledger beside an inspector (before→after hex strip, labelled entry form, chips) whose JSON tab shows the current document on demand, so that I see my whole document and can consult the JSON without a permanently empty panel. | verdict pe_A + the operator's JSON condition (handoff R-1) | READY |
| US-135 | As the calibration engineer assembling a check spec, I want the Check Editor as a full-height A2L parameter ledger with the address always visible beside a report-fields card (fields / JSON / addendum tabs), with Validate and Write on one docked row, so that I pick parameters by address and see what the report will hold. | verdict ce_A (handoff R-2) | READY |
| US-136 | As the engineer composing a flow, I want the Flow Builder as one horizontal pipeline of block cards joined by cables, with a contextual add form showing only the inputs the chosen kind needs and Run reachable without scrolling, so that the chain reads as one object and no input runs off screen. | verdict fb_A (handoff R-3, R-5) | READY |
| US-137 | As the engineer running flow sets, I want Flow Execution as one pipeline per lane with each cable carrying its block's run status, the rebind input inside the source card, the batch-96 waiting-human doctrine kept, and an English run log, so that I read a whole set's state at a glance and know exactly which lane waits for me. | verdict fx_A (handoff R-4, R-5) | READY |
| US-138 | As an engineer new to the tool, I want every one of the four screens to carry a visible open-folder chip for the folder its files live in and a help chip whose entry names every control and glyph on that screen, so that I never guess where files are or what a mark means. | operator round-2 answer: "es un problema adivinar y buscarlos, sobre todo para usuarios nuevos"; verdict note: "No olvides las leyendas y ayudas en cada ventana" (handoff R-6, R-7) | READY |
| US-139 | As an engineer who scales the terminal to taste (≈220x60, variable), I want the four screens to use the width they get — no horizontal overflow at 118x54, no half-screen voids from fixed widths at 220x60, and no row ever wrapping onto a second line — so that information density follows the window. | operator round-2 answer + the 220x60 pass (handoff R-8) | READY |

**Ledger pairing:** stories live in this table (the batch-91 shape); the P1 derivation entry in the
ledger names the HLR/LLR they trace to.

#### Refinement log (one block per story)

**US-134 — Patch Editor ledger + inspector, consultable JSON**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the calibration engineer · outcome = entries table full height beside an inspector with tabs Inspector / JSON / Checks; the JSON tab shows the document the editor holds (after Load and after edits); Load from the patches folder keeps populating table + tab · why = the baseline shows 2 of 6 rows and a ~40-row empty JSON frame (handoff §5 E-6: the JSON editor never receives the loaded document) · out of scope = a new change-set format, apply semantics.
- **Feasibility (E, S):** path = re-compose `PatchEditorPanel` at its shipped ids, remove the double geometry work (handoff §5 E-1..E-3), feed the JSON view from the editor state · unknowns = live refresh vs an explicit `Update JSON` action — the operator accepts either; decided at PDR with its reason · fits one batch? = yes (one increment).
- **Evaluability (T):** "When the engineer loads `calib_hotfix.json` from the patches folder and opens the JSON tab, the user observes that document's entries in the tab and all six rows in the ledger; after adding an entry, the tab shows the new entry (live, or after `Update JSON` with its stamp)."
- **Open questions:** live vs explicit refresh — a design-step decision, not a DoR blocker (operator: "No se si se pueda actualizar en tiempo real o poner algún botón").
- **Classification:** `READY`.

**US-135 — Check Editor ledger + inspector**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the calibration engineer · outcome = parameter table full height, Address never truncated; REPORT FIELDS card with Fields / JSON / Addendum tabs; one docked row Validate · Write .chk.json · struck APPLY ghost (the no-apply doctrine stays) · why = baseline Address truncated to one glyph, a 9-item unranked right column · out of scope = the `Fmt · Unit` column of ce_C (offered, not chosen).
- **Feasibility (E, S):** path = re-compose `CheckEditorPanel` at its ids; the 1-row chip shape the Patch Editor already has · unknowns = none blocking · fits one batch? = yes.
- **Evaluability (T):** "When the engineer opens the Check Editor with `calib.a2l` loaded, the user observes every visible row's address in full at 118x54, and the field count on the docked row changes when a parameter is included."
- **Open questions:** none.
- **Classification:** `READY`.

**US-136 — Flow Builder pipeline rail**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the engineer composing a flow · outcome = one pipeline of cards with cables; kind chip strip + only the chosen kind's inputs (EXT-STEP on two measured rows); copy/paste strip; `Variables (n)` chip; foot Run · Clear · Save… · Load… with Run the second bright element; CRC accent burnt orange · why = baseline Run below the fold, a wrapped canvas band, a duplicated numbered list, a surviving variant-scope selector · out of scope = a new block kind, flow model or persistence changes.
- **Feasibility (E, S):** path = re-compose `FlowBuilderPanel`; the six-kind palette is already accepted by the shipped handler (handoff §5 F-5); fb_A hides the grid canvas, so `_CANVAS_COLS` (F-2/F-3) matters only if the canvas stays reachable — decided at PDR · fits one batch? = yes.
- **Evaluability (T):** "When the engineer opens the Builder with `patch_chain` loaded at 118x54, the user observes all four cards joined by cables on one row and the Run chip on screen without scrolling; selecting EXT-STEP shows its command, log and output inputs, and pressing Add appends the card."
- **Open questions:** none blocking.
- **Classification:** `READY`.

**US-137 — Flow Execution pipeline rail**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the engineer running a set · outcome = per-lane pipeline; status glyph on each cable; rebind input in the SOURCE card; paused lane = amber card + `□` cable + two red pending lines + Confirm inside the lane + `log + output file: REQUIRED`; two-row header without overflow; English run log · why = baseline set row overflows (Save/Load Set off screen), ~13 dead rows, a detached rebind input, a 70-cell mode selector · out of scope = run semantics and the waiting-human doctrine itself (batch-96, kept as is).
- **Feasibility (E, S):** path = re-compose `FlowExecutionPanel`; per-block status from the retained record (handoff §5 F-8) · unknowns = `render_run` assumes outcome i belongs to lane i (F-8) — confirmed at PDR · fits one batch? = yes.
- **Evaluability (T):** "When the engineer runs `flash_q4`, the user observes the first lane's cables marked done, the second lane paused at block 3 with its Confirm in the lane row, and the run log's lines in English."
- **Open questions:** none blocking.
- **Classification:** `READY`.

**US-138 — open-folder chip + help chip on the four screens**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the new engineer · outcome = Patch Editor (`patch`, shipped), Check Editor (`checks`, shipped family), Flow Builder (`flows`, new family = the project's flows folder), Flow Execution (`session`, new family = the session dir) each carry the chip, dimmed with no project as the shipped chips are; each carries a help chip whose entry names every control, tab and glyph · why = the operator's round-2 answer (quoted in the table) · out of scope = chips on other screens (the all-screens review), the batch-96 `d`-key help follow-up.
- **Feasibility (E, S):** path = two families through `folder_open_service` (`CHIP_FAMILY_*` at `s19_app/tui/services/folder_open_service.py:57-60`; the flows folder is `project_dir / FLOWS_SUBDIR`, `flow_persistence_service.py:973`) and `titled_header` for the two bare headers (the Check Editor's `Label`, Flow Execution's `titled_header` with no chip, both in `app.py`) · fits one batch? = yes.
- **Evaluability (T):** "When a project is open, pressing the Flow Builder's folder chip opens the project's flows folder; with no project the chip is dimmed; pressing each screen's help chip shows an entry that names that screen's controls."
- **Open questions:** none.
- **Classification:** `READY`.

**US-139 — width-adaptive layouts, no wrapped rows**
- **INVEST:** I ✗ (cuts across US-134..137) · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the engineer at variable sizes · outcome = column widths and panel splits derived from the available width at mount and on resize; 118x54 = no horizontal overflow, Run / Validate / document controls on screen; ≈220x60 = no half-screen void caused by a fixed width; no table / ledger / log row wraps · why = the 220x60 pass (review page §7): fixed 118 widths in every chosen variant and in main · out of scope = the hex-viewer no-wrap rule on A2L viewer / Hex View (routed to the backlog for the all-screens review).
- **Feasibility (E, S):** path = each screen increment derives its own widths; a final sweep increment measures both sizes · fits one batch? = yes.
- **Evaluability (T):** "When each of the four screens renders at 118x54 and at 220x60, the user observes no horizontal scrollbar, every ledger row on one line, and the primary action on screen."
- **Open questions:** none. Not Independent by nature (a quality bar over the other four); kept as its own story so its acceptance is one node per size, not four buried clauses.
- **Classification:** `READY`.

**Not taken in (OUT, with where it lives):** the `Fmt · Unit` column (ce_C) and the matrix density mode (fx_C) — offered by the prototyping session, not chosen by the operator; the hex-viewer no-wrap rule outside these four screens — a backlog item for the all-screens review; the eight Code-Wire pilot findings — already in `BACKLOG-CODE.md` (`51ee191`), a separate lane; the batch-96 follow-ups — untouched.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

| # | Premise, as a truth-apt proposition | Tier (axiom · hypothesis · premise) | Verdict | Executed evidence (command output / `file:line` — **NOT** a citation of another document) | Disposition |
|---|---|---|---|---|---|
| `<one row per premise this batch relies on>` | | | | | |

- **Premise evaluation:** `<the table's roll-up: N premise(s) · ✅ TRUE / ❌ FALSE / ❓ UNDECIDABLE — or: none — this batch relies on no premise>`

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

| # | Condition (`C-52`) | Discharged? | The executed evidence |
|---|---|---|---|
| 1 | **Frozen contract** — no shared interface is touched inside a lane; one that must change returns to the trunk (trigger A3) | ✅ \| ❌ \| ❓ | `<the interface list and where it is frozen>` |
| 2 | **Disjoint FILE sets**, not just modules — two lanes may not edit the same file, not even different regions | ✅ \| ❌ \| ❓ | `<the per-lane file sets and the intersection test>` |
| 3 | **Crossed reverse census** — family B run per lane and **shared before starting**; the trunk's act, impossible from inside a lane | ✅ \| ❌ \| ❓ | `<the per-lane symbol sets, the cross-grep and its output>` |
| 4 | **One owner of the trunk** — requirements, traceability, backlog and spec are never written from a lane | ✅ \| ❌ \| ❓ | `<who owns the trunk>` |

- **Fork preconditions:** `<N lane(s) · the four conditions, each with its verdict — or: none — this batch runs one lane>`

---

## 3. High-level requirements (HLR)

### HLR-001 — `<Short title>`
- **Traceability:** US-001
- **Ledger:** none
- **Statement:** When `<trigger>`, the system shall `<response>`. *(Current state only. If you are about to write "because measured …", stop: the obligation belongs here, the measurement belongs in a ledger entry.)*
- **Rationale (informative):** *(why this requirement exists — `should` may technically be used here informally, but avoid it to prevent confusion.)*
- **Validation:** `test` | `demo` | `inspection` | `analysis`
- **Executed verification:** *(required if `test`/`analysis`. e.g. `npm run typecheck`, `vitest run TC-001`, `worst-case gain-staging sum analysis`.)*
- **Numeric pass threshold:** *(required if `test`/`analysis`. e.g. `0 errors`, `peak post-limiter ≤ −6 dBFS`.)*
- **Priority:** high | medium | low
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** *(what the user observes)*
  - **Shipped surface:** *(the handler / screen / CLI that produces it)*
  - **Acceptance test(s):** AT-001
  - **Boundary catalog (QC-3):** `<☐ empty ☐ boundary ☐ invalid ☐ error — tick each class that gets an AT/TC, or: none — and the reason no input class applies>`
  - **Negative control:** `<the executed input on which this verification GOES RED, or: none — and why it has no executed RED side>`

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same regime: EARS syntax owed in `full`, recommended in `core`. ID format: `LLR-<HLR>.<M>`.

### LLR-001.1 — `<Short title>`
- **Traceability:** HLR-001
- **Ledger:** none
- **Statement:** The `<component>` shall `<verifiable technical response>`.
- **Validation:** `test (unit)` | `test (integration)` | `test (e2e)` | `inspection` | `analysis`
- **Executed verification:** *(required if `test`/`analysis`. e.g. `vitest run src/lib/audio/masterBus.test.ts -t TC-001`; `gain-sum analysis vs the compressor threshold`.)*
- **Numeric pass threshold:** *(required if `test`/`analysis`. e.g. `assert exit code 0`; `peak ≤ −6 dBFS`; `RMS error < 0.01`.)*
- **Negative control:** `<the executed input on which this verification goes RED, or: none — and why it has no executed RED side>`
- **Boundary catalog:** `<☐ empty ☐ boundary ☐ invalid ☐ error — tick each class that gets an AT/TC, or: none — and the reason no input class applies>`

### Information Flow Contract (IFC) — C-54

> Part A in every batch; Part B when the system's boundary has components a consumer can address independently. The block syntax, its fields and the rules that read them are in `templates/ifc-template.md`, which ships with the flow and is not copied into this batch.

- **Part A — flows:** `<one fenced FLOW block per information flow: SOURCE, NODES (each node with exactly one owner, an LLR above — split a node two LLRs own), SINK>`
- **Part B — boundary decomposition:** `<yes — one fenced COMPONENT block per component | no — and why no component of the boundary is addressable on its own>`

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-NNN`):** validates the HLR/LLR mechanism (the HOW). Methods: `test`, `inspection`, `analysis`.
> - **Layer B — black-box / behavioral acceptance (`AT-NNN`):** validates the user story's outcome through the shipped surface (the WHAT). Method: `acceptance`.

### 5.2 Batch acceptance criteria
- *(e.g.: 100% of LLRs covered by at least one TC with pass result.)*
- *(e.g.: 0 blocker fails in validation.)*
- *(e.g.: test coverage >= X% where applicable.)*
- *(e.g.: no requirement without an assigned validation method.)*
- *(e.g.: every user story has ≥1 passing `AT-NNN` black-box acceptance test observing its outcome through the shipped surface — with boundary + negative evidence.)*

---

## 6. Appendices (optional)

### 6.1 Extended glossary
### 6.2 Relevant design decisions
### 6.3 Open risks
### 6.4 Phase-1 reconciliation log — moved to the ledger (§7)

### 6.5 Requirement amendments — moved to the ledger (§7)

---

## 7. The ledger — authored as a SEPARATE FILE

The fence below is the ledger's seed: `devflow-init.py` writes it to `01-requirements-ledger.md`. The shape of an entry is in the field guide.

```markdown
# Requirements ledger — s19_app — Batch 2026-10-19-batch-97

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```
