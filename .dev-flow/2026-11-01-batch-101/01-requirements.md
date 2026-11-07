# Requirements Document — s19_app — Batch 2026-11-01-batch-101

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

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-001 | As a `<role>`, I want `<goal>`, so that `<benefit>`. | `<ticket / conversation / client>` | READY \| REFINE \| SPIKE \| OUT |

#### Refinement log (one block per story)

**US-001 — `<short title>`**
- **INVEST:** I · N · V · E · S · T  (mark ✓/✗ each)
- **Functionality (V, N):** user = … · outcome = … · why = … · out of scope = …
- **Feasibility (E, S):** implementation path = … · dependencies/unknowns = … · fits one batch? = yes/no (split or spike if no)
- **Evaluability (T) — behavioral, black-box:** ≥1 observable acceptance criterion at the behavior level = "When `<input>`, the user observes `<outcome through the shipped surface>`" (becomes an `AT-NNN` in Phase 1). A story phrased as a mechanism (implementation spec) is mis-captured → REFINE.
- **Open questions:** …
- **Classification:** `READY` / `REFINE` / `SPIKE` / `OUT` — `<reason / next action>`

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

### HLR-001 — Ship 1.0.0 with every non-UI user-guide finding fixed or ruled
- **Traceability:** US-101.1 … US-DOC-HYG-3 (the batch-101 user-story index below)
- **Ledger:** none
- **Statement:** The system shall ship as version 1.0.0 with every non-UI user-guide finding fixed or ruled, the help and README describing the app as shipped, the Save project margin measured and fixed or re-ruled, the test suite running reliably in parallel with the timing arms run apart, batch-100's deferred CI confirmation recorded, and the requirement base as the strict-EARS canon with the test-case records.
- **Rationale (informative):** the batch objective, taken from `PLAN.md` §Objective — make v1.0.0 releasable on its non-UI defects.
- **Validation:** inspection
- **Executed verification:** the batch-end gate battery on the final tree (`evidence/close/full-suite-final.txt`; lane 1 and the `serial_timing` lane both green with the known failures named).
- **Numeric pass threshold:** 0 blocker fails at the close gate.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** v1.0.0 ships with the non-UI findings fixed or ruled and the help/README describing the shipped app.
  - **Shipped surface:** the release tag `v1.0.0`.
  - **Acceptance test(s):** AT-101 (the batch-end battery and the doc-pass guards).
  - **Boundary catalog (QC-3):** none — the batch's acceptance is a whole-tree gate, not a per-input class.
  - **Negative control:** the same battery on the base tree goes RED (the canon guards and doc-pass guards fail before the increments).

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same regime: EARS syntax owed in `full`, recommended in `core`. ID format: `LLR-<HLR>.<M>`.

### LLR-001.1 — the user guide's findings table marks exactly the batch's fixed findings
- **Traceability:** HLR-001
- **Ledger:** none
- **Statement:** The user guide's findings table shall mark every finding fixed in this batch `fixed in 1.0.0`, and only those.
- **Validation:** test (unit)
- **Executed verification:** `python -m pytest tests/test_b101_help_legend_docs.py -q`
- **Numeric pass threshold:** 0 failed (the `_FIXED` tuple of 17 findings is exactly the marked set).
- **Negative control:** adding a finding to `_FIXED` that the table does not mark goes RED.
- **Boundary catalog:** none — the verification is a pinned-set equality, not an input class.

### Information Flow Contract (IFC) — C-54

> Part A in every batch; Part B when the system's boundary has components a consumer can address independently. The block syntax, its fields and the rules that read them are in `templates/ifc-template.md`, which ships with the flow and is not copied into this batch.

- **Part A — flows:** three flows — (a) shipped in Inc 1, (b) and (c) planned (Inc 2 and Inc 4) — one fenced FLOW block each below. Batch-101's requirements are canon-hosted: every increment writes its rows into `REQUIREMENTS.md` (R-ids) and keeps its increment-level record in `inc-<n>/01-requirements.md` (see *Batch-101 increments — requirement homes* below), so this skeleton's headings are the only `HLR-`/`LLR-`/`US-` ids the contract declares. The owner-existence check (`V10`) reads only those headings; every node therefore names `LLR-001.1`, the one LLR id this contract declares, and puts the canon rows (or the planned increment) that actually govern the transform in its `fn`.

**(a) — shipped (Inc 1, governed by R-DOC-CANON.1 … R-DOC-CANON.11):** the requirements canon `REQUIREMENTS.md` → the registry/canon guard tests.

```
FLOW: canon_to_guard_tests
  SOURCE : `REQUIREMENTS.md` — the strict-EARS requirements canon (2623 rows, modules S0 … S17)
  NODES  :
    - fn    : parse the canon rows (`tests/test_requirements_canon.py::_rows`; governed by R-DOC-CANON.1 … R-DOC-CANON.11)
      owner : LLR-001.1
      in    : the `REQUIREMENTS.md` bytes
      out   : the 2623 rows, each with id, form, sentence
    - fn    : guard the canon's form — one guard test per R-DOC-CANON row (`tests/test_requirements_canon.py`)
      owner : LLR-001.1
      in    : the parsed rows
      out   : 11/11 GREEN on the new canon · 11/11 RED on the base `e273181`
  SINK   : the registry/canon guard tests (`tests/test_requirements_canon.py`) that gate every later canon edit
```

**(b) — PLANNED (Inc 2, not yet implemented; its R-rows are written when the increment lands):** the test suite's timing-arm margins → the gate report / junit properties.

```
FLOW: timing_margins_to_gate_report
  SOURCE : the test suite's timing arms — each `serial_timing` arm's alone time and its margin
  NODES  :
    - fn    : measure each timing arm's alone time and margin, under the 20 % floor (QC-TM; PLANNED — Inc 2)
      owner : LLR-001.1
      in    : the arm's product-emitted stamp
      out   : the arm's alone time and margin
    - fn    : publish the margins to the gate report and the junit properties (QC-TM; PLANNED — Inc 2)
      owner : LLR-001.1
      in    : the measured margins
      out   : the gate report margin table and the junit properties the TC-record generator reads
  SINK   : the merge-gate report and the junit properties (`-m serial_timing` runs apart)
```

**(c) — PLANNED (Inc 4, not yet implemented; its R-rows are written when the increment lands):** change/check documents → symbol resolution through the loaded A2L.

```
FLOW: change_check_documents_to_symbol_resolution
  SOURCE : a change document or a check document opened against the loaded A2L
  NODES  :
    - fn    : resolve each document symbol through the loaded A2L (PLANNED — Inc 4)
      owner : LLR-001.1
      in    : the document's symbol reference
      out   : the resolved A2L symbol or an unresolved-symbol finding
  SINK   : the symbol resolution the change/check document surfaces present
```

- **Part B — boundary decomposition:** no — batch-101's changes address no component of the boundary independently: the three flows above are file- and document-level (a canon file, transcripts, a gate report, change/check documents), and every UI row was routed to the backlog at P0 (PLAN.md, *Key decisions*), so no panel, channel or entry point is addressable on its own by this batch's changes.

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
# Requirements ledger — s19_app — Batch 2026-11-01-batch-101

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```


## Batch-101 user stories — the requirement index

> One block per user story the increments declare, with the Statement copied verbatim from the increment's `### US-…` heading and the increment file named.

### Rows of US-101.1 — As the engineer who changes s19_app, I read and change one requirements file in which every requirement is a single strict EARS sentence with a stable id, so that each requirement can be tested on its own and traced to its tests.
- **Statement:** As the engineer who changes s19_app, I read and change one requirements file in which every requirement is a single strict EARS sentence with a stable id, so that each requirement can be tested on its own and traced to its tests.
- **Increment:** `inc-1/01-requirements.md`

### Rows of US-TST-1 — a release gate without false timing failures
- **Statement:** a release gate without false timing failures
- **Increment:** `inc-2/01-requirements.md`

### Rows of US-TST-2 — CI runs what the local gate runs
- **Statement:** CI runs what the local gate runs
- **Increment:** `inc-2/01-requirements.md`

### Rows of US-TST-3 — wait and timing rules that a guard enforces
- **Statement:** wait and timing rules that a guard enforces
- **Increment:** `inc-2/01-requirements.md`

### Rows of US-TST-4 — no unread CI result in the v1.0.0 baseline
- **Statement:** no unread CI result in the v1.0.0 baseline
- **Increment:** `inc-2/01-requirements.md`

### Rows of US-TST-5 — a version bump keeps the report goldens
- **Statement:** a version bump keeps the report goldens
- **Increment:** `inc-2/01-requirements.md`

### Rows of US-PROJ-SAVE-1 — Save project keeps its time bound with room to spare
- **Statement:** Save project keeps its time bound with room to spare
- **Increment:** `inc-3/01-requirements.md`

### Rows of US-PROJ-SYNC-1 — a deleted project folder is not silently brought back
- **Statement:** a deleted project folder is not silently brought back
- **Increment:** `inc-3/01-requirements.md`

### Rows of US-TST-PAINT-1 — the panel and append timing arms measure what the app paints
- **Statement:** the panel and append timing arms measure what the app paints
- **Increment:** `inc-3/01-requirements.md`

### Rows of US-SYM-1 — documents I open resolve their symbols through the A2L I loaded
- **Statement:** documents I open resolve their symbols through the A2L I loaded
- **Increment:** `inc-4/01-requirements.md`

### Rows of US-SYM-2 — a variant run uses the project's A2L and nothing implicit
- **Statement:** a variant run uses the project's A2L and nothing implicit
- **Increment:** `inc-4/01-requirements.md`

### Rows of US-SYM-3 — the per-entry JSON edit works on a symbol entry and says plainly when it cannot
- **Statement:** the per-entry JSON edit works on a symbol entry and says plainly when it cannot
- **Increment:** `inc-4/01-requirements.md`

### Rows of US-CRC-FRESH-2 — the CRC Designer's coverage follows bytes written into the image
- **Statement:** the CRC Designer's coverage follows bytes written into the image
- **Increment:** `inc-5/01-requirements.md`

### Rows of US-CHK-KEEP-1 — my included parameters survive a Write and a return to the Check Editor
- **Statement:** my included parameters survive a Write and a return to the Check Editor
- **Increment:** `inc-5/01-requirements.md`

### Rows of US-CHK-SPEC-1 — a spec I load back is the spec I wrote
- **Statement:** a spec I load back is the spec I wrote
- **Increment:** `inc-5/01-requirements.md`

### Rows of US-PE-LIFE-1 — no report offer I cannot use
- **Statement:** no report offer I cannot use
- **Increment:** `inc-6/01-requirements.md`

### Rows of US-PE-LIFE-2 — what I save in a project is in the lists
- **Statement:** what I save in a project is in the lists
- **Increment:** `inc-6/01-requirements.md`

### Rows of US-PE-LIFE-3 — the Checks views show the run I have now
- **Statement:** the Checks views show the run I have now
- **Increment:** `inc-6/01-requirements.md`

### Rows of US-PE-LIFE-4 — a new document starts clean
- **Statement:** a new document starts clean
- **Increment:** `inc-6/01-requirements.md`

### Rows of US-BAR-1 — the before/after report names itself and its inputs
- **Statement:** the before/after report names itself and its inputs
- **Increment:** `inc-7/01-requirements.md`

### Rows of US-HEXWIN-1 — a written report carries every hex window whole
- **Statement:** a written report carries every hex window whole
- **Increment:** `inc-7/01-requirements.md`

### Rows of US-MDESC-1 — names and paths stay plain text in the Markdown report
- **Statement:** names and paths stay plain text in the Markdown report
- **Increment:** `inc-7/01-requirements.md`

### Rows of US-I8-1 — a Designer template given to a Flow CRC block is named as such (F-28)
- **Statement:** a Designer template given to a Flow CRC block is named as such (F-28)
- **Increment:** `inc-8/01-requirements.md`

### Rows of US-I8-2 — a CRC config error names its field (D13-23)
- **Statement:** a CRC config error names its field (D13-23)
- **Increment:** `inc-8/01-requirements.md`

### Rows of US-I8-3 — one CRC for one set of parameters (D13-20)
- **Statement:** one CRC for one set of parameters (D13-20)
- **Increment:** `inc-8/01-requirements.md`

### Rows of US-I8-4 — a later block reads this run's external output (F-49, D15-17)
- **Statement:** a later block reads this run's external output (F-49, D15-17)
- **Increment:** `inc-8/01-requirements.md`

### Rows of US-I9-1 — a confirm re-run's report says what ran (F-45)
- **Statement:** a confirm re-run's report says what ran (F-45)
- **Increment:** `inc-9/01-requirements.md`

### Rows of US-I9-2 — a saved flow keeps its own name (F-46)
- **Statement:** a saved flow keeps its own name (F-46)
- **Increment:** `inc-9/01-requirements.md`

### Rows of US-I9-3 — flow and chain-set saves stay in the work area (D15-18)
- **Statement:** flow and chain-set saves stay in the work area (D15-18)
- **Increment:** `inc-9/01-requirements.md`

### Rows of US-HEXNAV-1 — a jump shows me its target
- **Statement:** a jump shows me its target
- **Increment:** `inc-10/01-requirements.md`

### Rows of US-UNLOAD-1 — the status line describes what is loaded
- **Statement:** the status line describes what is loaded
- **Increment:** `inc-10/01-requirements.md`

### Rows of US-FOCUS-2 — the keys reach the window I see
- **Statement:** the keys reach the window I see
- **Increment:** `inc-10/01-requirements.md`

### Rows of US-FRESH-3 — views over the image follow bytes written into it
- **Statement:** views over the image follow bytes written into it
- **Increment:** `inc-10b/01-requirements.md`

### Rows of US-I11-1 — a valid A2L raises no "unrecognized block" (F-02, D3-12)
- **Statement:** a valid A2L raises no "unrecognized block" (F-02, D3-12)
- **Increment:** `inc-11/01-requirements.md`

### Rows of US-I11-2 — the Issues screen shows each issue under its own severity, errors first (F-03, F-39)
- **Statement:** the Issues screen shows each issue under its own severity, errors first (F-03, F-39)
- **Increment:** `inc-11/01-requirements.md`

### Rows of US-I11-3 — a CURVE without axis points says so once (F-21)
- **Statement:** a CURVE without axis points says so once (F-21)
- **Increment:** `inc-11/01-requirements.md`

### Rows of US-I11-4 — every MEMORY_SEGMENT that states a base and a size is read (F-29)
- **Statement:** every MEMORY_SEGMENT that states a base and a size is read (F-29)
- **Increment:** `inc-11/01-requirements.md`

### Rows of US-I12-1 — every dialog opens and every action runs from somewhere (F-33, F-34)
- **Statement:** every dialog opens and every action runs from somewhere (F-33, F-34)
- **Increment:** `inc-12/01-requirements.md`

### Rows of US-I12-2 — every widget of the Check Editor is shown in some state (F-35, the Check Editor half)
- **Statement:** every widget of the Check Editor is shown in some state (F-35, the Check Editor half)
- **Increment:** `inc-12/01-requirements.md`

### Rows of US-I12-3 — Escape closes the Reports dialog (F-51)
- **Statement:** Escape closes the Reports dialog (F-51)
- **Increment:** `inc-12/01-requirements.md`

### Rows of US-I12b-1 — every widget of the Flow Builder and Flow Execution is shown in some state (F-35, the `#flow_kind` half; D16-6)
- **Statement:** every widget of the Flow Builder and Flow Execution is shown in some state (F-35, the `#flow_kind` half; D16-6)
- **Increment:** `inc-12b/01-requirements.md`

### Rows of US-CRC-RESP-1 — the CRC Designer stays usable with the 10 MB demo image
- **Statement:** the CRC Designer stays usable with the 10 MB demo image
- **Increment:** `inc-13/01-requirements.md`

### Rows of US-CRC-FRESH-1 — the CRC Designer's coverage follows the loaded image
- **Statement:** the CRC Designer's coverage follows the loaded image
- **Increment:** `inc-13/01-requirements.md`

### Rows of US-SEG-RESP-1 — the Split/Join preview stays usable with the 10 MB demo image
- **Statement:** the Split/Join preview stays usable with the 10 MB demo image
- **Increment:** `inc-13/01-requirements.md`

### Rows of US-HELP-1 — each help window describes what its window does
- **Statement:** each help window describes what its window does
- **Increment:** `inc-14/01-requirements.md`

### Rows of US-LEGEND-1 — the Memory Map legend names the keys the map handles
- **Statement:** the Memory Map legend names the keys the map handles
- **Increment:** `inc-14/01-requirements.md`

### Rows of US-README-1 — the README describes the shipped app
- **Statement:** the README describes the shipped app
- **Increment:** `inc-14/01-requirements.md`

### Rows of US-SEC-1 — a security policy says how to report a vulnerability
- **Statement:** a security policy says how to report a vulnerability
- **Increment:** `inc-14/01-requirements.md`

### Rows of US-REL-1 — the 1.0.0 release notes state what changed in written results
- **Statement:** the 1.0.0 release notes state what changed in written results
- **Increment:** `inc-14/01-requirements.md`

### Rows of US-GUIDE-1 — the user guide describes 1.0.0
- **Statement:** the user guide describes 1.0.0
- **Increment:** `inc-14/01-requirements.md`

### Rows of US-TST-15 — a Windows run reports the product, not the host's clock
- **Statement:** a Windows run reports the product, not the host's clock
- **Increment:** `inc-15/01-requirements.md`

### Rows of US-TST-16 — a no-op arm proves the press was handled
- **Statement:** a no-op arm proves the press was handled
- **Increment:** `inc-15/01-requirements.md`

### Rows of US-DOC-HYG-1 — a contributor finds only paths, links and commands that exist
- **Statement:** a contributor finds only paths, links and commands that exist
- **Increment:** `inc-16/01-requirements.md`

### Rows of US-DOC-HYG-2 — the developer documents describe the shipped app
- **Statement:** the developer documents describe the shipped app
- **Increment:** `inc-16/01-requirements.md`

### Rows of US-DOC-HYG-3 — finished notes leave the living documents, with their history kept
- **Statement:** finished notes leave the living documents, with their history kept
- **Increment:** `inc-16/01-requirements.md`


## Batch-101 increments — requirement homes

- **Inc 1 (canon swap):** US-101.1 and R-DOC-CANON.1 … R-DOC-CANON.11, recorded in `inc-1/01-requirements.md` and folded into the strict-EARS canon `REQUIREMENTS.md` (group S0.3) by the increment itself. From Inc 1 on, every increment writes its rows straight into `REQUIREMENTS.md` in the strict format and keeps its increment-level record in `inc-<n>/01-requirements.md`.
