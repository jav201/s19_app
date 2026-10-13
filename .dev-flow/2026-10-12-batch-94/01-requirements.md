# Requirements Document — s19_app — Batch 2026-10-12-batch-94

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

Source of all nine stories: the operator's note
`G:\My Drive\ConsultIA\Obsidian_Vaults\AI-Consulting-Brain\01 - Proyectos\s19_app\assets\Refactor_10_11_2026\Refactor, Cambios.md`
(= the lane-A coordination note's declared intake, COORDINACION-batch92.md §*Siguiente batch*), plus the
four annotated images in `G:\My Drive\dev-flow-radiografia\Refactor_10_11_26\Imagenes\` (copied into this
record's `evidence/`, `-text`-marked). Story quotes stay verbatim in Spanish; the commissioned scope is
Cambio1–7 (US-001..US-007). Cambio8/9 are recorded as OUT — outside the commission.

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-001 | Cambio1: «Patch Editor debe dividirse en Patch Editor y Check Editor … separar las ventanas que son sólo para ver, las que son predominantemente para construir y las que son para ejecutar acciones.» | Cambios.md §Cambio1 + `evidence/Ventanas_1.png` | READY |
| US-002 | Cambio2: rework the Patch Editor window per the annotated image (expand the text-edit space; left pane reflects JSON edits via an Edit-JSON + validate flow; dirty-guard popup on Load; remove the variant selector; Apply → Apply loaded changes; Load/Refresh button semantics). | Cambios.md §Cambio2 + `evidence/PatchEditor1.png` | READY |
| US-003 | Cambio3: «Check Editor debe ser una copia de Patch Editor … no se editan cambios, sólo se agregan parámetros del A2L o localidades de memoria para agregar en el reporte … un archivo JSON … cargarse para los reportes A2L Diff en dropdown … sólo se leen los de check … no se podrá aplicar el archivo, sólo escribirse y validarse.» | Cambios.md §Cambio3 | READY |
| US-004 | Cambio4: «en issues report … contemplar si lo que se reporta como warnings realmente es un warning … Investigar y resolver» — the `A2L_UNRECOGNIZED_BLOCK` class (4 489 warnings on the operator's file) is the exhibited case. | Cambios.md §Cambio4 + `evidence/Issues_Report1.png` + `evidence/Archivos_1.png` | READY |
| US-005 | Cambio5: «Flow builder debe ser una ventana para crear los flujos de cambios … bloques (como en un diagrama de acciones)» — patch block (S19/HEX + patch JSON in), CRC block (S19 + CRC JSON), A2B diff block (two S19: from the flow or a file, never cross-flow); flows saveable as templates; separate Flow Execution window. The operator's prototyping request is already discharged by the completed spike (fb_a/fx_a approved). | Cambios.md §Cambio5 | READY |
| US-006 | Cambio6: «en CRC designer hay un apartado de test vector, pero no sé de qué sirve exactamente … si es para hacer un check de un CRC esperado … falta un botón de run … Antes de hacer el cambio creo que debemos explicar como funciona … di una descripción detallada de un algoritmo CRC que quería probar … crea el archivo JSON para poder correrlo.» | Cambios.md §Cambio6 | REFINE |
| US-007 | Cambio7: «En la nueva ventana de flows execution … importar desde los templates creados en flow builder … varias cadenas o flows a los que se les puedan cambiar los inputs … ejecutar varias cadenas con varios archivos de entrada distintos (especial para cuando se trabaja en proyectos con variantes, por eso ya no queremos referencia a variantes en los builders) … guardar el set de cadenas de flujo junto con sus inputs y outputs.» | Cambios.md §Cambio7 | READY |
| US-008 | Cambio8: «una nueva ventana que se llame algo como BlockTags … los flujos creados para check, patch y CRC puedan aceptar tags … en flow execution acepten valores para estos tags.» | Cambios.md §Cambio8 | OUT — outside the Cambio1–7 commission; candidate for a later batch (filed to lane A at close) |
| US-009 | Cambio9: «El README del repo está desactualizado … Corregir, actualizar y aumentar.» | Cambios.md §Cambio9 | OUT — docs-only change (no product code) and outside the commission; candidate for a later batch (filed to lane A at close) |

#### Refinement log (one block per story)

**US-001 — Split Patch Editor into Patch Editor + Check Editor (build vs view vs execute)**
- **INVEST:** I ✓ (own panels, own rail entries) · N ✓ (operator-ruled split is the negotiated shape) · V ✓ · E ✓ (design input pe_a/ce_b) · S ✓ (one panel split + rail entry) · T ✓
- **Functionality (V, N):** user = calibration engineer · outcome = the left rail separates build windows (Patch Editor) from view/report windows (Checks, Issues) and execute windows (Flow Execution) — Check Editor becomes the build side of check specs · why = mixed functionality makes the tool hard to learn and risky to operate · out of scope = no behavior change to what a patch/check file IS (schema ruling: changeset schema unchanged); variant machinery leaves the editors entirely (→ Flow Execution).
- **Feasibility (E, S):** path = `PatchEditorPanel` splits into a patch twin (pe_a) and a check twin (ce_b: report-oriented, content panel shows `.chk.json`); per the approved decisions · dependencies = none (spike resolved) · fits one batch = yes (as increment 001 together with US-003's panel).
- **Evaluability (T):** When the user opens the rail, they observe Patch Editor and Check Editor as distinct build windows and Checks/Issues as view-only — AT to drive the rail and assert the two editors open their respective panels with the ce_b report orientation.
- **RC-1(b) already-shipped probe:** `grep PatchEditor screens_directionb.py` → exists (to be split); `grep -ri "checkeditor\|check_editor"` → no hits. Not shipped.
- **Open questions:** none.
- **Classification:** `READY`

**US-002 — Patch Editor rework per the annotated image**
- **INVEST:** I ✓ · N ✓ (the six annotations are the negotiated spec) · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = calibration engineer · outcome = the window edits ONE change-set JSON: text space expanded, JSON edits flow through an Edit-JSON + validate step into the entries table, unsaved work is guarded on Load, the variant selector is gone, Apply applies the loaded changes listed at top · why = the current window is confusing (operator's annotations) and variant handling moves to Flow Execution · out of scope = variant application (removed, not relocated here), no check-spec writing (US-003).
- **Feasibility (E, S):** path = the six annotations map to concrete panel edits (see evidence/PatchEditor1.png annotations 1–6) · dependencies = none · fits = yes.
- **Evaluability (T):** When the user types an address+value and confirms, the entry appears in the top-left table; when they edit raw JSON with an error and save, they observe a validation error (not a silent table); when they Load with unsaved edits, they observe a warning popup with accept-loss/cancel. ≥3 observable criteria → ATs.
- **RC-1(b) probe:** panel exists; annotations unimplemented (no Edit JSON button, variant selector present). Not shipped.
- **Open questions:** none.
- **Classification:** `READY`

**US-003 — Check Editor + `.chk.json` spec files**
- **INVEST:** I ✓ · N ✓ (operator ruled: write/validate only, no apply) · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = calibration engineer · outcome = a Check Editor builds a check-spec JSON listing A2L parameters / memory locations to report; A2B Diff's file dropdown lists `.chk.json` specs distinguished from patch files; loading one adds those items to the diff report · why = repeatable, reviewable check sets without editing patches · out of scope = applying a check file (explicitly forbidden by the operator); check EXECUTION (that's Flow Execution, later batch or later increment as declared).
- **Feasibility:** path = approved decisions: `.chk.json` distinguished by suffix; ce_b panel is report-oriented with a `.chk.json` content panel; provenance of inputs recorded in the report · dependencies = US-001 split · fits = yes.
- **Evaluability (T):** When the user saves a check spec and loads it in A2B Diff, the diff report contains the declared parameters/locations; when they attempt apply, no apply path exists. AT through the shipped surface (A2B Diff dropdown → report contents).
- **RC-1(b) probe:** `grep -ri "chk.json"` → no hits. Not shipped.
- **Open questions:** none.
- **Classification:** `READY`

**US-004 — Issues Report warnings triage (`A2L_UNRECOGNIZED_BLOCK`)**
- **INVEST:** I ✓ · N ✓ (resolution shape is open: recognize, reclassify, or suppress — operator leans "not really a problem") · V ✓ · E ✓ (bounded: the exhibited class + the parser's block table) · S ✓ · T ✓
- **Functionality:** user = calibration engineer · outcome = the Issues Report stops flooding warnings that represent no real problem (4 489 `A2L_UNRECOGNIZED_BLOCK` rows on a standard A2L), either by recognizing the standard blocks or by reclassifying them with a stated justification the report shows · why = warning fatigue hides real issues · out of scope = A2L parsing correctness for blocks that DO affect addresses/data.
- **Feasibility:** path = audit `A2L_UNRECOGNIZED_BLOCK` emitters against the A2L keyword table; each hit gets recognize-or-reclassify with justification · dependencies = a real operator A2L fixture (the 13 990-tag `software_a_2.a2l`) · fits = yes.
- **Evaluability (T):** When the user loads the operator's A2L and opens Issues, they observe the unrecognized-block warnings resolved (recognized or reclassified with visible justification) and any genuinely unrecognized block still warned. AT: fixture load → Issues surface.
- **RC-1(b) probe:** the warnings exist (subject of the story, image evidence); no resolution on origin/main. Not shipped.
- **Open questions:** resolution direction per block family (recognize vs reclassify) — decided at P1/P2 with the audit evidence.
- **Classification:** `READY`

**US-005 — Flow Builder redesign (block diagram) + templates**
- **INVEST:** I ✓ (own surface) · N ✓ (fb_a approved from the spike) · V ✓ · E ✓ · S ~ (the largest story; the spike bounded it) · T ✓
- **Functionality:** user = calibration engineer · outcome = Flow Builder becomes a block-diagram editor: a patch block (S19/HEX + patch JSON in → patched S19 out), a CRC block (S19 + CRC-designer JSON → CRC-applied S19), an A2B diff block (two S19, each either a flow output or an external file, never a cross-flow smuggle); a flow saves as a template · why = the current window is "inservible o incompleta" (operator) · out of scope = executing flows (US-007), variant references in any builder (operator ruling — variants live in Flow Execution inputs).
- **Feasibility:** path = fb_a (PLC-style builder: palette, canvas, cable routing refined per approved decision); block semantics reuse existing services (patch apply, CRC apply, A2B diff) · dependencies = US-001/US-002 land first (patch JSON shape stable) · fits = yes as increment 002.
- **Evaluability (T):** When the user places a patch block, wires a file + a patch JSON, and runs the flow (in Flow Execution), the output S19 carries the patch; the A2B block's report states each input's provenance. ATs drive block placement + run through the shipped surface.
- **RC-1(b) probe:** `FlowBuilderPanel` exists (rail-8, R-TUI-059 tracer, partial CRC block: `tests/test_flow_crc_block.py`); the redesign outcome not shipped.
- **Open questions:** none (spike discharged the prototyping question; operator decisions D1–D5 recorded in `prototypes/flow_bench.NOTES.md`).
- **Classification:** `READY`

**US-006 — CRC Designer test-vector (Run + explanation + algorithm JSON)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✗ (purpose unconfirmed) · S ✓ · T ✗ (no observable outcome statable until purpose is fixed)
- **Functionality:** user = calibration engineer · outcome = (hypothesis) the Custom test vector section checks an expected CRC against the current design's output, with a Run button · why = the operator cannot tell what it does today (`crc_designer_view.py:384` shows the group with no run affordance) · out of scope = redesigning CRC Designer beyond this section (lane A carries the design-pass item separately).
- **Feasibility:** path = explain-back → confirm → implement run · dependencies = operator answers.
- **Evaluability (T):** cannot be stated black-box yet — blocked on purpose confirmation.
- **RC-1(b) probe:** section exists, run button absent. Not shipped (nor specifiable).
- **Open questions:** (1) confirm the section's purpose (expected-CRC check?); (2) produce the detailed CRC algorithm description the operator references ("en algún punto di una descripción detallada") so its JSON can be authored.
- **Classification:** `REFINE` — parked from the P1 derivation until the operator answers; does not block US-001..005/007.

**US-007 — Flow Execution: template import, chains, input rebinding, save sets**
- **INVEST:** I ✓ · N ✓ (fx_a approved; sequential-default/parallel-per-chain ruling) · V ✓ · E ✓ · S ~ · T ✓
- **Functionality:** user = calibration engineer · outcome = Flow Execution imports builder templates; several chains run with per-run input files (the variant workflow that replaces in-editor variant handling); a set of chains + inputs + outputs saves and reloads · why = repeatable multi-variant operations · out of scope = variant references inside patch/check/CRC builders (explicit operator ruling); block tags (Cambio8, OUT).
- **Feasibility:** path = fx_a (carriles + run-log); control sequential by default, parallel per chain per approved decision; input provenance recorded in reports · dependencies = US-005 · fits = yes as increment 003.
- **Evaluability (T):** When the user imports a template, binds two different input files to two chains, runs, and saves the set; then reloads the set and re-runs — they observe both chains' outputs regenerate. ATs through the shipped surface.
- **RC-1(b) probe:** `grep -ri "flowexecution\|flow_execution"` → no hits. Not shipped.
- **Open questions:** none.
- **Classification:** `READY`

**US-008 / US-009 — OUT**
- US-008 (BlockTags): outside the Cambio1–7 commission; functionality depends on US-005/007 shipping first. Next action: file to lane A at this batch's close as a chartered candidate.
- US-009 (README refresh): docs-only (no product code) and outside the commission; per the routing matrix it needs no /dev-flow batch. Next action: file to lane A at close.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

| # | Premise, as a truth-apt proposition | Tier (axiom · hypothesis · premise) | Verdict | Executed evidence (command output / `file:line` — **NOT** a citation of another document) | Disposition |
|---|---|---|---|---|---|
| 1 | The batch tree sits on the current `origin/main` tip (RC-1). | axiom | TRUE | `git ls-remote origin main` → `1a0eff6bad2fa84db96f0a8ec1fe273a57a77a5a`; ff merge `ae0ef4f..1a0eff6` clean; `state.json` base_ref re-stamped to it | Re-run at P4 (RC-1 limb b) |
| 2 | `origin` answers with live refs (RC-2). | axiom | TRUE | `git ls-remote --exit-code --heads origin` exit 0, `refs/heads/main` at `1a0eff6`; newest commit 2026-10-13 06:49 −0600 | stands |
| 3 | The suite baseline is 2 796 passed + 35 pre-existing fails (batch-93 close census); this batch adds 0 new fails. | premise | TRUE as recorded | batch-93 record `evidence/c25-failure-census.txt` (35-fail census); re-derived from this tree at P4 | Re-derive at P4 |
| 4 | The design input (4 approved SVG variants + NOTES) exists at the declared path. | premise | TRUE | `ls …/Prototipos/` → `flow_bench.fb_a.svg`, `flow_bench.fx_a.svg`, `editor_bench.pe_a.*.svg`, `editor_bench.ce_b.*.svg`, both `.NOTES.md` present | stands |
| 5 | The four images copied into `evidence/` are the operator's current spec for Cambio1/2/4. | premise | TRUE | Images read 2026-10-13; annotations in Spanish, consistent with the Cambios.md text | stands |
| 6 | Batch-93 is closed, so the `screens_directionb.py` overlap is resolved by rebase (batch-94 edits second, on top). | premise | TRUE | `git log ae0ef4f..origin/main` → batch-93 inc-002/003 + close + operator visual verdict `1a0eff6` ("Me parece todo correcto") | stands; re-check before Inc-001 edits |

- **Premise evaluation:** 6 premise(s) · ✅ TRUE / ❌ FALSE / ❓ UNDECIDABLE — all six TRUE at P0; none undecidable. Premises 1 and 3 carry an explicit re-verification at P4.

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

| # | Condition (`C-52`) | Discharged? | The executed evidence |
|---|---|---|---|
| 1 | **Frozen contract** — no shared interface is touched inside a lane; one that must change returns to the trunk (trigger A3) | ✅ | n/a — one lane: the A3 finding (US-001's panel message contract) is owned by THIS trunk batch and tracked via trigger A3 → PDR |
| 2 | **Disjoint FILE sets**, not just modules — two lanes may not edit the same file, not even different regions | ✅ | n/a — one lane: no parallel lane is open (batch-93 closed 2026-10-13 before this batch derived anything); the historical two-lane overlap (`screens_directionb.py`) was resolved by the RC-1 rebase, not by forking |
| 3 | **Crossed reverse census** — family B run per lane and **shared before starting**; the trunk's act, impossible from inside a lane | ✅ | n/a — one lane; family B is evaluated per increment inside this batch and recorded in each packet |
| 4 | **One owner of the trunk** — requirements, traceability, backlog and spec are never written from a lane | ✅ | this batch IS the trunk batch (single worktree, single lane) |

- **Fork preconditions:** none — this batch runs one lane; the four conditions are each answered n/a with the reason above.

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
# Requirements ledger — s19_app — Batch 2026-10-12-batch-94

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```
