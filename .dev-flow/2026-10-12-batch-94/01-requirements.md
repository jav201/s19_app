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

This document is the Phase-1 requirements contract for dev-flow batch
`2026-10-12-batch-94` of `s19_app`. It derives high-level requirements (HLR) and
low-level requirements (LLR) from the READY source stories US-001…US-005 and
US-007 (§2.6), defines each story's black-box acceptance block, declares the
validation strategy, and carries the Information Flow Contract (IFC, C-54) for
the information flows the new requirements introduce. It is the live contract:
current state only, no history. The append-only ledger
(`01-requirements-ledger.md`) records how it came to say what it says.

### 1.2 Scope

In scope — derivation for exactly the six READY stories:

- **US-001** — split Patch Editor into Patch Editor + Check Editor (build vs
  view vs execute separation on the rail).
- **US-002** — Patch Editor rework per the six annotations in
  `evidence/PatchEditor1.png`.
- **US-003** — Check Editor + `.chk.json` check-spec files (write/validate
  only), consumed by A2B Diff.
- **US-004** — Issues Report warnings triage for the `A2L_UNRECOGNIZED_BLOCK`
  class.
- **US-005** — Flow Builder redesign (block diagram fb_a) + flow templates.
- **US-007** — Flow Execution: template import, multiple chains, per-chain
  input rebinding, sequential(default)/parallel-per-chain control, chain-set
  save/load.

Out of scope — nothing is derived from these stories:

- **US-006** (CRC Designer test-vector) — REFINE-parked at Phase 0; no
  requirement, acceptance, or flow in this contract derives from it.
- **US-008** (BlockTags) / **US-009** (README refresh) — OUT per the
  commission; candidates for a later batch.

Standing constraints carried into the derivation (from the ARQ map,
`docs/architecture.md` §10): flow surfaces live in the new module
`s19_app/tui/flow_screens.py` (R8); editors stay in `screens_directionb.py`
(R9); `.chk.json` is a suffix distinction on the existing v2 grammar with
`kind="check"` (R10); the rail grows 10→12 with the key binding **open to
PDR** (R11 — this contract states the constraint and records the question, it
does not decide it); US-004's seam is decided here at P1 (§6.2, HLR-013). The
change-set schema is unchanged — no `from`/`to` fields (operator ruling, spike
decision D-set).

### 1.3 Definitions, acronyms, abbreviations

| Term | Definition |
|------|------------|
| A2L | ASAP2 ECU description file parsed by `s19_app/tui/a2l.py` into sections/tags. |
| S19 / HEX image | Motorola S-record (or Intel HEX) firmware image loaded into the tool's memory map. |
| Change document | A v2-grammar JSON document (`format="s19app-changeset"`, `version="2.0"`, `io.py:110-113`) with `kind="change"` (modifications) or `kind="check"` (expected values); `DOCUMENT_KINDS` at `s19_app/tui/changes/io.py:120-123`. |
| Check spec / `.chk.json` | A change document with `kind="check"`, distinguished from patch files by the `.chk.json` suffix (R10); write/validate only, never applied. |
| Flow | An ordered sequence of typed blocks (source/patch/CRC/A2B-diff/write-out…) executed by the flow services; today serialized as `{"schema_version": 1, "name", "blocks"}` (`flow_persistence_service.py:175-245`). |
| Template | A named flow saved by Flow Builder and importable by Flow Execution (builder template). |
| Chain | One runnable flow instance inside Flow Execution, with its own pinned inputs. |
| Chain set | A persisted set of chains plus their bound inputs and recorded outputs (US-007 save/load artifact). |
| Rail | The left activity rail of the Direction-B shell; `RAIL_ENTRIES` at `s19_app/tui/rail.py:80-91` (10 entries at base). |
| Workspace chrome | App chrome around the workspace: rail width 5 (icon regime, <120 cols) / 23 (fixed regime), top bar 2 rows, footer 1 row — measured in `evidence/p1-pilot-measurements.txt`. |
| Boxed budget | The workspace region available to one screen at a given terminal size: 74×12 @80×24, 96×18 @120×30, 136×28 @160×40 (`evidence/p1-pilot-measurements.txt`). |
| AT-B94-NN / TC-B94-NN | Batch-scoped acceptance / white-box test ids (per `docs/engineering-rules.md:48`); ungoverned by `AT-TC-REGISTRY.jsonl`; provisional until Phase 3 per V-5. |
| EARS | Easy Approach to Requirements Syntax — the `shall` statement patterns of §3 (owed in `full` mode). |
| C-NN | dev-flow draft-time verification controls (e.g. C-12 output-then-consume, C-17 markup-safety, C-35 draft-time execution probe, C-39 pre-executed threshold, C-42 emitted-form assertion). |
| Shipped surface | The user-facing handler / panel / CLI through which an acceptance observes its outcome (Layer B). |

### 1.4 References

- Station rules: `C:/Users/jjgh8/.claude/skills/dev-flow/stations/p1-requirements.md` (core path steps 1–8, C-54, draft-time controls C-15/C-15.1/C-35/C-36/C-39/C-40/C-42/C-16/C-17).
- Field guides: `templates/guides/req-template.md`, `req-template.part2.md`, `templates/ifc-template.md` (same bundle).
- Batch plan: `.dev-flow/2026-10-12-batch-94/PLAN.md` (R8–R12, roadmap Inc-001…004, operator grant).
- Architecture map: `docs/architecture.md` §10 (batch-94 declarations, R8–R12) and §11 (interface rows; frozen Part B contracts; batch-94 pending rows).
- Operator rulings from the spike: `G:/My Drive/dev-flow-radiografia/Refactor_10_11_26/Prototipos/flow_bench.NOTES.md` and `editor_bench.NOTES.md` (D1–D5; fb_a/fx_a/pe_b/ce_b graduation calls).
- Operator spec images (copies, `-text`-marked): `evidence/PatchEditor1.png` (six annotations), `evidence/Ventanas_1.png`, `evidence/Issues_Report1.png`, `evidence/Archivos_1.png`.
- Pilot measurements: `evidence/p1-pilot-measurements.txt` (boxed budgets; rail 5/23, top 2, footer 1).
- Phase-1 executed probes (scripts + transcripts, same directory): `p1_probe_rail_census.py/.txt`, `p1_probe_chk_roundtrip.py/.txt`, `p1_probe_a2l_unrecognized.py/.txt`, `p1_probe_a2l_negative.py/.txt`, `p1_probe_diff_report_emitted.py/.txt`.
- Id scheme: `docs/engineering-rules.md:48` (batch-scoped ids preferred); no registry writes.
- Project rules: `docs/engineering-rules.md:190` (C-34 full guard-host run for render increments).
- Runtime state: `.dev-flow/state.json` (`language: "en"`, `mode: "full"`, `artifact_homes.tests: "repo:tests/"`).
- Security pattern scan: `devflow-scan-spec.py` over this contract, run at this gate 2026-10-13 — exit 1 with all 5 self-controls ok, `security_required: true`; fired flags `hash`, `schema change`, `form`, `escape`, `expose`, each answered in §6.3.

### 1.5 Document overview

§2 restates the product context and carries the Phase-0 story table, refinement
log, premise evaluation (§2.7) and fork preconditions (§2.8) — §2.6–§2.8 are
Phase-0 content preserved verbatim, with premise rows 7–9 appended at P1 for
the pilot measurements, the id scheme, and the A2L stand-in fixture. §3 holds
the HLRs and each story's acceptance block. §4 holds the LLR decomposition and
the Information Flow Contract (Part A flows, Part B components). §5 declares
the two-layer validation strategy and batch acceptance criteria. §6 carries
design decisions, open risks (including the OPEN rail key-binding question,
R11) and the scan verdict. §7 seeds the separate ledger.

**Agent declaration (§Agents of the station file):** the two Phase-1 lenses —
`architect` (HLR/LLR derivation, ISO/IEC/IEEE 29148 + strict EARS) and
`qa-reviewer` (validation method per requirement) — were **both executed by a
single agent** in this run, sequentially: every HLR/LLR below was first derived
under the architect lens and then re-read under the qa-reviewer lens for its
validation method, executed verification, numeric threshold, boundary catalog
and negative control before being written.

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
| 7 | The boxed workspace budgets available to the new screens are 74×12 @80×24, 96×18 @120×30, 136×28 @160×40 (rail 5/23, top chrome 2, footer 1); the spike's full-screen prototype sizes (94×26 body @120×30 etc.) are NOT transferable to the boxed surfaces. | premise | TRUE | `evidence/p1-pilot-measurements.txt` (executed 2026-10-13 by `evidence/p1_pilot_probe.py`; workspace `Region` dumps per screen/size) — the non-transfer trap of C-29 recorded | stands; every layout/visibility acceptance in §3 keys on these ceilings or is authored reachable-under-scroll |
| 8 | Batch-scoped ids `AT-B94-NN` / `TC-B94-NN` are preferred for every new test and are ungoverned by `AT-TC-REGISTRY.jsonl` (spec 2.3): no registry writes, no reservation rows; global AT-2xx/TC-6xx ids are not minted. | premise | TRUE | `docs/engineering-rules.md:48` ("Prefer a batch-scoped id … the global pool never has to carry them"); `.dev-flow/AT-TC-REGISTRY.jsonl` does not exist in this repo (executed `ls` 2026-10-13) — nothing to write to | stands |
| 9 | `examples/case_00_public/software_a.a2l` (5 193 091 bytes, 13 990 tags) is the closest in-repo stand-in for the operator's `software_a_2.a2l` (13 990 tags, 4 489 exhibited warnings — not in the repo); it exercises the same `A2L_UNRECOGNIZED_BLOCK` emitter. | premise | TRUE | `evidence/p1_probe_a2l_unrecognized.txt` (executed 2026-10-13): the loader+`validate_a2l_structure` run headless over the fixture returns 13 990 tags and 1 023 `A2L_UNRECOGNIZED_BLOCK` findings, per-block tally pasted | stands; US-004 thresholds key on this measured count |

- **Premise evaluation:** 9 premise(s) · ✅ TRUE / ❌ FALSE / ❓ UNDECIDABLE — premises 1–6 all TRUE at P0 (Phase-0 rows preserved); rows 7–9 appended at P1, all TRUE with executed evidence; none undecidable. Premises 1 and 3 carry an explicit re-verification at P4.

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

### HLR-001 — Check Editor as a distinct build surface
- **Traceability:** US-001
- **Ledger:** none
- **Statement:** When the user selects the Check Editor rail entry, the system shall mount the Check Editor panel in the workspace as a build surface separate from the Patch Editor panel.
- **Rationale (informative):** Cambio1 separates build windows from view and execute windows. The check twin of the editor (ce_b per the approved spike set, folded into the ce_a collector with the live addendum preview per the `editor_bench.NOTES.md` graduation call) becomes the build side of check specs; the existing Checks and Issues surfaces remain view-only. Base probe: `grep -ri "checkeditor\|check_editor" s19_app/` → 0 hits 2026-10-13 (P0 RC-1(b), §2.6) — the panel is new work.
- **Validation:** `test`
- **Executed verification:** AT-B94-01 through the shipped rail+panel at 120×30 (`pytest tests/test_tui_directionb.py -k check_editor`, node minted at Phase 3 — provisional per V-5); full guard host per C-34 (`engineering-rules.md:190`) at the render increment's gate.
- **Numeric pass threshold:** exactly 1 panel mounted per rail selection, identified as the Check Editor, exposing write/validate actions and 0 apply actions; base-state probe reads 0 `checkeditor` hits.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** The rail lists "Check Editor" as its own entry; selecting it mounts a panel identified as the Check Editor whose actions offer writing and validating a check spec (no Apply affordance); selecting "Patch Editor" mounts the Patch Editor instead.
  - **Shipped surface:** the rail (`s19_app/tui/rail.py:80-91`) + `CheckEditorPanel` — NEW, created in Phase 3 in `s19_app/tui/screens_directionb.py` (R9), mounted by `S19TuiApp` routing, emitting a message family sibling to `PatchEditorPanel.ActionRequested` (`screens_directionb.py:5266`; A3 contract, consumer set enumerated in §4 IFC Part B).
  - **Acceptance test(s):** AT-B94-01
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: rail driven at the 80×24 icon regime (rail width 5, pilot-measured `evidence/p1-pilot-measurements.txt`): the entry is reachable and mounts the panel.
  - **Negative control:** the base census probe `evidence/p1_probe_rail_census.txt` (10 entries, no Check Editor) is the executed RED side — the AT's subject is verifiably absent at base.

### HLR-002 — The rail presents twelve ordered surfaces (key binding OPEN)
- **Traceability:** US-001, US-007
- **Ledger:** none
- **Statement:** The system shall present the activity rail with twelve ordered surfaces, including Check Editor and Flow Execution.
- **Rationale (informative):** R11 (`docs/architecture.md:413`): the rail grows 10→12; the digit key space `1`–`0` is exhausted at 10 entries (`app.py:1362-1371` binds `1`…`0`), so the key binding of the two new surfaces is an OPEN question decided at PDR with measured Textual `Binding` mechanics — recorded in §6.3, not decided here. Ordering: existing entries keep their order; Check Editor follows Patch Editor; Flow Execution follows Flow Builder.
- **Validation:** `test`
- **Executed verification:** full guard host `pytest tests/test_tui_directionb.py` at each landing increment (census constants `SCREEN_IDS`/`SCREEN_KEYS`/`EXPECTED_RAIL`, `test_tui_directionb.py:137-169`, `:468-479`, move with the increment per `docs/architecture.md:392` — never before); executed base probe `evidence/p1_probe_rail_census.txt` (10 entries, keys `workspace`…`crc_designer`).
- **Numeric pass threshold:** `len(RAIL_ENTRIES) == 12` with `len(SCREEN_IDS) == len(SCREEN_KEYS) == 12` at the landing increment's gate; at 80×24 all 12 entries render inside the rail's 21-row chrome budget (24 − top 2 − footer 1, pilot-measured).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** The rail shows twelve entries in a stable order; Patch Editor and Check Editor are two distinct build entries; Flow Execution appears as an execute entry; every entry mounts its panel.
  - **Shipped surface:** `RAIL_ENTRIES` (`rail.py:80-91`) + `S19TuiApp` rail bindings and routing (`app.py:1362-1371`, `action_show_screen` `:5881`).
  - **Acceptance test(s):** AT-B94-02
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☒ error — boundary arm: smallest regime 80×24 (12 entries ≤ 21 rows); invalid arm: a rail entry whose screen id is absent fails the census loudly; error arm: binding collision on the new surfaces is impossible by construction until PDR decides the keys (census asserts one binding per entry).
  - **Negative control:** `evidence/p1_probe_rail_census.txt` (10 entries at base) — the AT goes RED if the batch lands 11 entries or the order drifts from the declared sequence.

### HLR-003 — Expanded JSON text-editing space in the Patch Editor
- **Traceability:** US-002
- **Ledger:** none
- **Statement:** The Patch Editor shall provide an expanded text-editing surface for the change-set JSON that occupies the primary editing area of the panel.
- **Rationale (informative):** Annotation 1 of `evidence/PatchEditor1.png` ("Expandir en la ventana el espacio de edición de texto."). The pe_b graduation call makes the entries table the source of truth and demotes the hex strip and JSON preview to on-demand inspectors — the expanded JSON text editor is the primary edit surface. Base state: the JSON window is `patch_win_json` (`screens_directionb.py:6150`, border title "³JSON EDIT") hosting `patch_paste_text` (`:6078-6080`) — a capped side pane, not the primary area.
- **Validation:** `test`
- **Executed verification:** AT-B94-03 through the shipped panel under a Textual pilot at 120×30 and 160×40 (node minted at Phase 3, provisional per V-5); full guard host run at the render increment (C-34).
- **Numeric pass threshold:** at 120×30 (boxed workspace 96×18, pilot-measured) the entries table and the expanded JSON editor are both visible without scroll; at 80×24 (boxed 74×12) both are reachable by panel scroll; the exact inner split is `assumed — verify in Phase 3` (the pilot measured workspace boxes only, not inner pane splits; the pe_b idiom is table top-anchored, editor beneath).
- **Priority:** medium
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** The JSON text-editing area is the panel's primary editing space (expanded relative to the current capped side pane) and accepts multi-line editing of the change-set JSON.
  - **Shipped surface:** `PatchEditorPanel` (`screens_directionb.py:5054`), reworked in place per R9; editor widget reuses the existing `JsonHighlightTextArea` idiom (`patch_paste_text`, `:6078-6080`).
  - **Acceptance test(s):** AT-B94-03
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: the two measured regimes 120×30 and 80×24 (visible vs reachable-under-scroll, reason authored above per C-29).
  - **Negative control:** base render of `patch_win_json` — the AT goes RED if the expanded surface is absent (the capped side pane is the executed pre-state).

### HLR-004 — Edit-JSON + validate flow merges into the entries table
- **Traceability:** US-002
- **Ledger:** none
- **Statement:** When the user confirms JSON edits, the system shall validate the edited text; when the text is valid, the system shall merge the declared changes into the entries table, and when the text is invalid, the system shall display the validation errors and leave the entries table unchanged.
- **Rationale (informative):** Annotation 2: the left side must show the changes added; edits happen through an explicit "Edit JSON" action; on save the validator adds new changes to the top-left table or shows the JSON errors. The mechanism exists today (`EditJsonRequested` `:5366` → `ChangeSetJsonScreen` `screens.py:223`); this HLR pins the validate-merge/error-display outcome. Validator: `parse_change_document` (`io.py:440`) collects issues on the document (`ChangeDocument.issues`, `model.py:249`) instead of aborting.
- **Validation:** `test`
- **Executed verification:** AT-B94-04 (valid arm) and AT-B94-05 (invalid arm) through the shipped Edit-JSON flow; unit arms TC-B94-01 over `parse_change_document` (`io.py:440`); executed probe `evidence/p1_probe_chk_roundtrip.txt` demonstrates the shipped reader's collected-issues error surface over invalid input classes.
- **Numeric pass threshold:** valid arm — entries added to `patch_doc_entries_table` (`:5749-5750`) equal the valid entries declared in the text (count equality, order preserved); invalid arm — 0 rows added and ≥1 validation error displayed.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Confirming valid JSON adds the declared changes to the top-left entries table; confirming invalid JSON shows the validation errors and the table keeps its prior rows.
  - **Shipped surface:** `PatchEditorPanel` Edit-JSON action (`patch_edit_json_button`, `:6094-6098`) + `ChangeSetJsonScreen` (`screens.py:223`) + `refresh_entries` (`:6639`).
  - **Acceptance test(s):** AT-B94-04, AT-B94-05
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☒ error — invalid arms: malformed JSON text; unknown `kind`; address outside the `^0x[0-9A-Fa-f]+$` wire grammar (`io.py:198-199`); empty arm: valid JSON with zero entries merges as a no-op, not an error.
  - **Negative control:** invalid-text arm (AT-B94-05) — RED the moment an invalid text lands rows in the table or fails silently.

### HLR-005 — Dirty guard on Load offers accept-loss and cancel
- **Traceability:** US-002
- **Ledger:** none
- **Statement:** When the user activates Load while unsaved changes exist, the system shall display a warning popup offering to accept the loss and continue the load or to cancel and retain the unsaved changes.
- **Rationale (informative):** Annotation 3: Load must warn when the change editor or the text editor carry unsaved changes, with accept-loss and cancel options. C-10: the popup's two branches are two policy arms — each gets its own AT driving the explicit branch and asserting the resulting state.
- **Validation:** `test`
- **Executed verification:** AT-B94-06 (accept-loss) and AT-B94-07 (cancel) driving the real Load key path (`patch_doc_load_button`, `:5880`) under a Textual pilot (nodes minted at Phase 3, provisional per V-5).
- **Numeric pass threshold:** accept-loss arm — the target document is loaded, the entries table shows the loaded document's rows, the dirty flag is clear; cancel arm — the current document and its dirty flag are retained and the target document is not mounted.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Load with unsaved edits pops a warning; accepting loses the edits and loads; canceling keeps the edits and aborts the load.
  - **Shipped surface:** `PatchEditorPanel` Load control + dirty-state tracking (writers census per C-15.1 owed at Phase 3) + popup screen (NEW — created in Phase 3, `screens.py` modal idiom).
  - **Acceptance test(s):** AT-B94-06, AT-B94-07
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: Load with a clean (saved) document pops nothing and loads directly.
  - **Negative control:** the clean-document arm — RED if the popup appears with nothing to lose (popup-always implementation).

### HLR-006 — Variant selector removed; single-document editing
- **Traceability:** US-002
- **Ledger:** none
- **Statement:** The Patch Editor shall not present variant selection, and shall bind editing to a single change-set document.
- **Rationale (informative):** Annotation 4: the variant selector is eliminated; only single-file hex/S19 content editing stays; variant application moves to Flow Execution inputs (US-007) — the operator ruling behind "ya no queremos referencia a variantes en los builders". Retires `patch_variant_select` (`:5910-5916`), `VariantSelected` (`:5417`), `VariantHelpRequested` (`:5442`), and the app routing `_variant_selected` (`app.py:4659`); the A3 message contract is amended accordingly (`docs/architecture.md:463`, freezes at Inc-001's PDR).
- **Validation:** `test` + `inspection`
- **Executed verification:** AT-B94-08 drives the reworked panel and asserts 0 variant controls; inspection: panel source carries no `patch_variant*` widget id and `PATCH_ACTIONS_V2` (`app.py:176-190`) carries no variant action.
- **Numeric pass threshold:** 0 variant-selection widgets rendered; 0 variant actions routed; all eleven retained actions still route.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** The Patch Editor shows no variant selector and no variant help; the panel edits one change-set document.
  - **Shipped surface:** `PatchEditorPanel` (`screens_directionb.py:5054`) + `S19TuiApp` routing.
  - **Acceptance test(s):** AT-B94-08
  - **Boundary catalog (QC-3):** ☐ empty ☐ boundary ☒ invalid ☒ error — error arm: a stale `VariantSelected` message posted to the panel is a no-op, not a crash; invalid arm: the retired widget ids resolve to nothing.
  - **Negative control:** base state — `patch_variant_select` exists at `:5910-5916` (executed read 2026-10-13); the AT goes RED if any variant control renders.

### HLR-007 — Apply applies the loaded changes
- **Traceability:** US-002
- **Ledger:** none
- **Statement:** When the user activates Apply, the system shall apply the loaded change-set document to the loaded image and present the action as applying the loaded changes.
- **Rationale (informative):** Annotation 5: Apply becomes "apply loaded changes" — the changes listed at the top when added. The apply machinery is the existing `apply_change_document` (`apply.py:226`, gate at `:320`); this HLR changes the presentation and pins the applied-set semantics.
- **Validation:** `test`
- **Executed verification:** AT-B94-09 through the shipped Apply path (`patch_doc_apply_button`, `:5891`); unit arm TC-B94-02 over `apply_change_document`.
- **Numeric pass threshold:** `ChangeSummary.counts["applied"]` equals the count of the loaded document's applicable entries and every applied entry is one listed in the top entries table; with no document loaded, 0 writes and a no-image notice (`counts["skipped-no-image"]` arm).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** The Apply action is presented as applying the loaded changes (label/action census) and applying changes exactly the entries shown in the top table.
  - **Shipped surface:** `PatchEditorPanel` Apply control + `apply_change_document` (`apply.py:226`).
  - **Acceptance test(s):** AT-B94-09
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☐ invalid ☒ error — empty arm: Apply with no loaded document applies nothing; error arm: a document with blocking errors is refused by the gate (`blocked` disposition, `apply.py:320`).
  - **Negative control:** no-document arm — RED if Apply with nothing loaded writes anything.

### HLR-008 — Load and Refresh file semantics
- **Traceability:** US-002
- **Ledger:** none
- **Statement:** When the user activates Load, the system shall load the change-set document named by the path input adjacent to the Load control, and when the user activates Refresh, the system shall refresh the file dropdown's folder listing.
- **Rationale (informative):** Annotation 6 defines the buttons: Load loads the file given in the text path below the dropdown, with the button beside that text; Refresh repopulates the dropdown from the folder holding the `.json` files ("Refresh Files in Folder" per the operator's wording). Base machinery: path input `patch_doc_path_input` (`:5800-5806`), folder scan `_scan_patch_change_files` (`app.py:4413`, glob `*.json` under `workarea/patches/`).
- **Validation:** `test`
- **Executed verification:** AT-B94-10 through the shipped controls; unit arm TC-B94-03 over `read_change_document` (`io.py:296`).
- **Numeric pass threshold:** Load with a valid path input mounts the named document (table rows == file's entries); Load with an empty or unresolved path surfaces one collected issue and loads nothing; Refresh changes the dropdown options to match the folder scan (count equality) and never mutates the loaded document.
- **Priority:** medium
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Load loads exactly the document named in the adjacent path input; Refresh updates the dropdown from the patches folder; both controls sit beside the path input/dropdown per the annotation.
  - **Shipped surface:** `patch_doc_controls` (`:5893`) + `read_change_document` (`io.py:296`) + `_scan_patch_change_files` (`app.py:4413`).
  - **Acceptance test(s):** AT-B94-10
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☐ error — invalid arms: path names a nonexistent file (`MF-PATH-UNRESOLVED`, `io.py:165-166`); path names a non-JSON file (`MF-JSON-PARSE`, `io.py:159`).
  - **Negative control:** Refresh-with-loaded-document arm — RED if Refresh alters the loaded document.

### HLR-009 — Check Editor assembles a `kind="check"` spec (write/validate only)
- **Traceability:** US-003
- **Ledger:** none
- **Statement:** The Check Editor shall assemble a check-spec document with `kind="check"` that lists A2L parameters or memory locations, and shall offer write and validate actions and no apply action.
- **Rationale (informative):** Cambio3: changes are not edited; only A2L parameters or memory locations to include in the report are collected; the file can only be written and validated — "la ausencia de Apply es la declaración de diseño" (`editor_bench.NOTES.md`). Same entry shape as changes — no `from`/`to` fields (operator ruling; `ChangeEntry` at `model.py:79-140`). The v2 grammar already discriminates `"change"`/`"check"` (`DOCUMENT_KINDS`, `io.py:120-123`), so no schema change is needed (R10).
- **Validation:** `test`
- **Executed verification:** AT-B94-11 through the shipped Check Editor surface; executed probe `evidence/p1_probe_chk_roundtrip.txt` — the shipped v2 writer/reader round-trip a `kind="check"` document today (315 emitted bytes, form pasted), `run_check_document` (`check.py:194`) executes it, and `apply_change_document` over the same document returns `counts["blocked"] == 2` with zero writes.
- **Numeric pass threshold:** the written file re-reads with `kind == "check"` and the declared entry count; validate produces one verdict per entry (`pass`/`fail`/`uncheckable`, `check.py:194-260`); the panel exposes 0 apply controls.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** The Check Editor collects A2L parameters and memory locations into a check spec; Write saves a `.chk.json` document; Validate runs the check and shows per-entry verdicts; no Apply affordance exists anywhere in the surface.
  - **Shipped surface:** `CheckEditorPanel` — NEW, created in Phase 3 (`screens_directionb.py`, R9) — over the existing v2 machinery: `write_change_document` (`io.py:1285`), `parse_change_document` (`io.py:440`), `run_check_document` (`check.py:194`).
  - **Acceptance test(s):** AT-B94-11
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty arm: a spec with zero entries writes and validates as an empty document; invalid arms: bad address grammar, unknown `kind`; error arm: a write outside the work area is refused with one `MF-WRITE-CONTAINMENT` issue (`io.py:1364-1374`).
  - **Negative control:** the executed apply-gate probe (`p1_probe_chk_roundtrip.txt`: `blocked: 2`, `mem_map` untouched) — RED if any apply path over a check spec performs a write.

### HLR-010 — A2B Diff consumes `.chk.json` by suffix (output-then-consume)
- **Traceability:** US-003
- **Ledger:** none
- **Statement:** When the user opens the A2B Diff file dropdown, the system shall list `.chk.json` check specs distinguished from patch files by suffix, and when the user loads one, the system shall add the declared parameters and memory locations to the diff report.
- **Rationale (informative):** Cambio3: the spec "cargarse para los reportes A2L Diff en dropdown … sólo se leen los de check". C-12 output-then-consume: the acceptance observes a `.chk.json` through the shipped producer chain — Check Editor writes it, A2B Diff loads THAT file, the report carries the declared items — never a hand-written artifact fed to the consumer. The dropdown idiom exists for patch files (`patch_doc_file_select` at `:5794-5799`, scan at `app.py:4413`); the A2B Diff report dropdown + check addendum are NEW — created in Phase 3, following the existing report addendum security precedent (`services/report_addendum.py` scrub + `markdown_safety.md_safe`, batch-19/62).
- **Validation:** `test`
- **Executed verification:** AT-B94-12 through the shipped chain (Check Editor write → A2B Diff dropdown → load → report); C-35/C-42 emitted-form evidence: the diff report producer's actual header form is pasted in `evidence/p1_probe_diff_report_emitted.txt` (`- Image A: prg [external] path=\`…\` parse-errors=0`); the check addendum's emitted form is NEW — pasted at the Phase-3 increment, predicate written against the producer's own text (provisional per V-5).
- **Numeric pass threshold:** the dropdown lists the written `.chk.json` with a suffix-distinguished label (patch files still listed and loadable); the produced report contains every declared parameter/location name (count equality with the spec's entries).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** A check spec written in Check Editor appears in the A2B Diff file dropdown distinguished by its `.chk.json` suffix; loading it adds the declared parameters and memory locations to the diff report.
  - **Shipped surface:** the A2B Diff surface (`AbDiffPanel`, `screens_directionb.py:7443`) + report producer `generate_diff_report` (`diff_report_service.py:1216`) + the check-spec listing/addendum — NEW, created in Phase 3.
  - **Acceptance test(s):** AT-B94-12
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty arm: a folder with no `.chk.json` lists none (no error); boundary arm: folder holding both patch and check files lists both, distinguished; invalid arm: a `.chk.json` failing the read path surfaces its collected issues instead of producing a report.
  - **Negative control:** a spec written by hand and injected into the consumer is NOT the acceptance surface (C-12) — the AT goes RED if it cannot re-derive the report input from the shipped writer's output; the executed base form (`p1_probe_diff_report_emitted.txt`) carries no check vocabulary — RED if the addendum emits against any other spelling than its own pasted form.

### HLR-011 — Markup safety of file-derived text in the new editor surfaces (C-17)
- **Traceability:** US-003
- **Ledger:** none
- **Statement:** The new editor surfaces shall render file-derived text — check-spec file names, A2L parameter names, labels — only through the explicit-style safety primitive, never through markup-parsed construction.
- **Rationale (informative):** C-17 mandate: the new surfaces render file-derived strings (loaded A2L symbols reach the Check Editor picker; spec file names reach dropdowns and reports), so a markup-safety LLR + hostile-input AT is owed at Phase 1. The primitive exists and is load-bearing: `safe_text` (`s19_app/utils.py:44-99`, `_CONTROL_SCRUB` byte class at `:41`, literal `Text` — never `Text.from_markup`), already consumed by the sibling surfaces (`issues_view.py:40`, entries table at `screens_directionb.py:6658-6678`); markdown reports render through `markdown_safety.md_safe` (`services/markdown_safety.py`).
- **Validation:** `test`
- **Executed verification:** AT-B94-13 (hostile arm) + guard-host source scan `test_tc_042_10` (`from_markup` census over the touched render modules, `engineering-rules.md:190`); hostile payload mirrors the batch-77 precedent `tests/test_tui_hostile_map.py:105-107`.
- **Numeric pass threshold:** the hostile payload `b77hostilemark\x1b[31m_evil[red]\x9b1m\x9d8;;u\x07\x00\x7f` (as an A2L symbol name and as a spec file name) renders with the sentinel visible and 0 markup spans / 0 hyperlinks / 0 control bytes in the rendered cells; no parse error.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** File-derived hostile text renders literally in the Check Editor and its dropdown/report paths — brackets and ANSI visible as text, no style leak.
  - **Shipped surface:** `CheckEditorPanel` (NEW) + `utils.safe_text` (`utils.py:44`) + `markdown_safety.md_safe` for the report path.
  - **Acceptance test(s):** AT-B94-13
  - **Boundary catalog (QC-3):** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: the hostile payload above in both file-derived fields.
  - **Negative control:** plain printable names render unchanged (the scrub is identity on printable text — the preserved-arm of the hostile census); RED if the hostile sentinel acquires a style or disappears.

### HLR-012 — `A2L_UNRECOGNIZED_BLOCK` warnings triage (seam: view-level reclassification)
- **Traceability:** US-004
- **Ledger:** none
- **Statement:** When the Issues surface presents `A2L_UNRECOGNIZED_BLOCK` findings whose block name belongs to the curated ASAP2 standard-keyword set, the system shall present them as informational findings with a stated justification and shall not present them as warnings, and findings whose block name is not in the set shall remain warnings.
- **Rationale (informative):** Cambio4: contemplate whether what is reported as warnings really is a warning — the exhibited class (4 489 rows on the operator's file) is standard ASAP2 vocabulary the parser's section tree surfaces as unrecognized. The seam decision owed at P1 (R12) is made here: **view-level reclassification in the Issues surface** — `s19_app/validation/rules.py` and `s19_app/tui/a2l.py` stay frozen (the §7 engine stability list is untouched; the parser-level alternative — extending `RECOGNIZED_A2L_BLOCKS`, `rules.py:9-25` — is recorded as the rejected candidate in §6.2 with its freeze consequence and re-open condition). The curated set constant is NEW — created in Phase 3 in `issues_view.py`, seeded from the executed 2026-10-13 tally (21 families pasted in `evidence/p1_probe_a2l_unrecognized.txt`); per-family recognize-vs-reclassify mechanics inside the set are a Phase-2/3 detail — this HLR pins the observable outcome, not the mechanism.
- **Validation:** `test`
- **Executed verification:** AT-B94-14 loads the stand-in fixture through the app and reads the Issues surface; executed baseline probe `evidence/p1_probe_a2l_unrecognized.txt` (1 023 `A2L_UNRECOGNIZED_BLOCK` warnings on `examples/case_00_public/software_a.a2l`, per-block tally); executed negative control `evidence/p1_probe_a2l_negative.txt` (`FROBNICATE` warns, `MODULE` does not).
- **Numeric pass threshold:** on the stand-in fixture, WARNING-severity `A2L_UNRECOGNIZED_BLOCK` count goes 1 023 → 0; the reclassified rows remain visible as INFO (1 023 rows — none dropped, the consolidation rule's union of observables); a synthetic unknown block still warns (negative control); the justification text is displayed alongside the reclassified class.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Loading a standard A2L no longer floods the Warnings group with `A2L_UNRECOGNIZED_BLOCK`; the same rows appear as informational with a visible justification; genuinely unknown blocks still warn.
  - **Shipped surface:** the Issues surface (`GroupedIssuesPanel`, `issues_view.py:307`; severity groups `SEVERITY_LABELS`, `:64-68`) + the curated-set policy constant (NEW, Phase 3). The engine emitter (`rules.py:482-493`) is untouched.
  - **Acceptance test(s):** AT-B94-14
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty arm: an A2L with no sections shows the empty state; invalid arm: synthetic unknown block (`FROBNICATE`); error arm: parse errors still surface as `A2L_STRUCTURE_ERROR` errors (`rules.py:441-449`).
  - **Negative control:** the executed `FROBNICATE` probe (`p1_probe_a2l_negative.txt`) — RED if the reclassification ever swallows a genuinely unknown block; the 1 023-count baseline probe is the RED side for a silent no-op implementation.

### HLR-013 — fb_a block-diagram Flow Builder with patch, CRC, and A2B-diff blocks
- **Traceability:** US-005
- **Ledger:** none
- **Statement:** The Flow Builder shall present a block-diagram editor — a block palette, a canvas with refined cable routing, and typed blocks for patch, CRC, and A2B diff — in place of the current list-based builder.
- **Rationale (informative):** Cambio5 + the fb_a graduation call (`flow_bench.NOTES.md`: connectivity is the builder's job — explicit `in`/`out` stubs and `─│└┐` cable runs; the fb_c audit precision folds in as an inspector pane). Block semantics reuse the existing services (patch apply, CRC apply, A2B diff). The fb_a palette/canvas/cable widgets, the A2B diff block, and its block-type constant are NEW — created in Phase 3 in `s19_app/tui/flow_screens.py` (R8); reused constants: `BLOCK_PATCH="patch"`, `BLOCK_CRC="crc"` (`flow_model.py:25-33`). `FlowBuilderPanel`'s address moves `screens_directionb.py` → `flow_screens.py` (B2 reader census owed at Inc-002, `docs/architecture.md:402`; known consumers enumerated there).
- **Validation:** `test`
- **Executed verification:** AT-B94-15 drives block placement + wiring through the shipped surface; base probes: `FlowBuilderPanel` exists as a list-based tracer (`screens_directionb.py:4257`, kind options `:4289-4295`, no A2B block — executed reads 2026-10-13); `run_flow` executes headless (`flow_execution_service.py:86`).
- **Numeric pass threshold:** the palette exposes the three block types; a patch block wired to an S19 image and a patch JSON, run through Flow Execution, writes a patched image whose changed bytes equal the patch's entries; the canvas + cables render inside the boxed 96×18 workspace at 120×30; canvas overflow is reachable by scroll (C-29).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** The Flow Builder shows a palette and a canvas; placed patch/CRC/A2B-diff blocks carry typed `in`/`out` stubs; cables run from an output stub to the next block's input row; running the flow produces the patched image.
  - **Shipped surface:** `FlowBuilderPanel` reworked in `s19_app/tui/flow_screens.py` (R8; B2 move) + the flow services (`run_flow`, `flow_execution_service.py:86`).
  - **Acceptance test(s):** AT-B94-15
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — empty arm: a flow with no blocks renders the empty canvas; invalid arm: an unwired block or a missing input file renders the block's invalid state (RED border + `✗` row, fb_a idiom) and halts its chain; error arm: placing an A2B block with no flow output available is refused at wiring time (HLR-014).
  - **Negative control:** cross-flow wiring attempt (HLR-014's rule) — RED if the canvas ever accepts a cable whose source is another flow.

### HLR-014 — A2B block inputs: flow-output-or-file, at least one from the current flow, provenance in the report
- **Traceability:** US-005
- **Ledger:** none
- **Statement:** Where an A2B diff block is included in a flow, the system shall let each of its two image inputs be bound either to a flow output or to an external file, shall require at least one input to come from the current flow, and shall state each input's provenance in the A2B diff report.
- **Rationale (informative):** Operator decision D1 (A2B configurable per block with input provenance in the report) + the intake rule "para no falsear reportes" — never a cross-flow smuggle. The report producer exists (`generate_diff_report`, `diff_report_service.py:1216`); the per-block input binding model and the flow-provenance emission are NEW — created in Phase 3.
- **Validation:** `test`
- **Executed verification:** AT-B94-16 through the shipped builder+report; C-35/C-42 emitted-form evidence: the external-file arm's actual emitted line is pasted from `evidence/p1_probe_diff_report_emitted.txt` — `- Image A: prg [external] path=\`C:\…\prg.s19\` parse-errors=0`; the flow-output arm's emitted form is NEW — pasted at the Phase-3 increment and the predicate written against that paste (provisional per V-5).
- **Numeric pass threshold:** the produced report contains one provenance line per A2B input; the external arm matches the executed emitted form verbatim in shape; a binding with both inputs external, or any cross-flow input, is refused at wiring time (0 reports produced).
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Each A2B input is bound to a flow output or a file; the rule "at least one input from this flow" is enforced while wiring; the generated diff report states each input's provenance.
  - **Shipped surface:** the A2B diff block (NEW, `flow_screens.py`) + `generate_diff_report` (`diff_report_service.py:1216`) driven by the flow run.
  - **Acceptance test(s):** AT-B94-16
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☒ error — boundary arm: exactly one flow output + one external file (the minimum legal binding); invalid arms: both inputs external; a cross-flow source; error arm: an upstream block failure leaves the A2B block unrunnable (no report).
  - **Negative control:** the pasted base report form (`p1_probe_diff_report_emitted.txt`) carries only `[external]` provenance vocabulary — RED if the flow-output arm emits any shape other than its own Phase-3 paste, or if a cross-flow report is ever produced.

### HLR-015 — Flow templates save and reload
- **Traceability:** US-005
- **Ledger:** none
- **Statement:** When the user saves a flow, the system shall persist it as a named template retrievable by Flow Execution import.
- **Rationale (informative):** "flows saveable as templates". Reuse over invention: `save_flow_json`/`load_flow_json`/`list_saved_flows` (`flow_persistence_service.py:522/:463/:570`, `flows/*.json` under the work area, 1 MiB cap `:64`); the builder-template contract beyond today's `{"schema_version": 1, "name", "blocks"}` envelope (`flow_to_dict`, `:175-245`) is a §11 pending row that freezes at Inc-002's PDR.
- **Validation:** `test`
- **Executed verification:** AT-B94-17 + unit arms TC-B94-04 over `save_flow_json`/`dict_to_flow` (hardened fail-closed read path, `:248`).
- **Numeric pass threshold:** a saved template reloads with equal block count and per-block kinds; the template appears in the Flow Execution import listing.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Saving a built flow names it; the name appears when Flow Execution lists importable templates; importing reconstructs the flow.
  - **Shipped surface:** `save_flow_json`/`list_saved_flows` (`flow_persistence_service.py:522/:570`) + the builder save control (fb_a idiom).
  - **Acceptance test(s):** AT-B94-17
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty arm: a zero-block flow saves and reloads; invalid arm: corrupt template JSON is refused fail-closed (`dict_to_flow` issues, no partial flow); boundary arm: duplicate template names are dedup-suffixed, never silently clobbered.
  - **Negative control:** corrupt-template arm — RED if a malformed template loads as a partial flow.

### HLR-016 — Markup safety of file-derived text in the flow surfaces (C-17)
- **Traceability:** US-005
- **Ledger:** none
- **Statement:** The flow surfaces shall render file-derived text — block labels carrying input file names, provenance lines, template names — only through the explicit-style safety primitive or the markdown escaper, never through markup-parsed construction.
- **Rationale (informative):** C-17 for the new `flow_screens.py` module: block chips and report lines carry names of operator files. The module's allowed dependencies already name the sink (`flow_screens → utils.safe_text`, `docs/architecture.md:375`); report paths render through `markdown_safety.md_safe` (`services/markdown_safety.py`).
- **Validation:** `test`
- **Executed verification:** AT-B94-18 (hostile arm through the shipped flow surfaces) + `test_tc_042_10` source census over `flow_screens.py`.
- **Numeric pass threshold:** hostile payload (HLR-011's) rendered literally in block labels and the flow report — 0 markup spans, 0 control bytes; no parse error.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** A hostile file name bound to a block input renders literally on the canvas and in the report.
  - **Shipped surface:** `flow_screens.py` (NEW) via `utils.safe_text` (`utils.py:44`) and `markdown_safety.md_safe`.
  - **Acceptance test(s):** AT-B94-18
  - **Boundary catalog (QC-3):** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: the hostile payload in a bound file name and in a template name.
  - **Negative control:** plain names render unchanged; RED on any style leak.

### HLR-017 — Flow Execution imports templates and presents chains side by side
- **Traceability:** US-007
- **Ledger:** none
- **Statement:** When the user imports a builder template into Flow Execution, the system shall present the template's chain in its own lane, and shall present multiple imported chains side by side.
- **Rationale (informative):** Cambio7 + the fx_a graduation call (carriles + run-log; "especial para cuando se trabaja en proyectos con variantes"). Base probe: `grep -ri "flowexecution\|flow_execution"` → 0 hits at base (P0, §2.6) — `FlowExecutionPanel` is NEW, created in Phase 3 in `flow_screens.py` (R8).
- **Validation:** `test`
- **Executed verification:** AT-B94-19 through the shipped surface at 120×30 and 160×40 (provisional per V-5); base probe recorded in §2.6.
- **Numeric pass threshold:** two imported chains are visible side by side at 120×30 within the boxed 96×18 workspace; lanes beyond the budget are reachable by scroll (C-29); each lane's block list equals its template's blocks.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Importing a template adds a lane; importing a second shows both chains side by side, each with its pinned inputs.
  - **Shipped surface:** `FlowExecutionPanel` (NEW, `flow_screens.py`) over `list_saved_flows`/`load_flow_json` (`flow_persistence_service.py:570/:463`).
  - **Acceptance test(s):** AT-B94-19
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☐ error — empty arm: zero lanes renders the empty state; boundary arm: one-lane import; invalid arm: importing a corrupt or foreign file is refused with a notice.
  - **Negative control:** the base 0-hits probe (§2.6) — RED if the surface exists without lanes mounting, or a corrupt import mounts a partial chain.

### HLR-018 — Per-chain input rebinding
- **Traceability:** US-007
- **Ledger:** none
- **Statement:** The user shall be able to rebind each chain's input files independently of the other chains.
- **Rationale (informative):** Cambio7: chains get their inputs changed per run — the variant workflow that replaces in-editor variant handling (the reason the builders lost variant references). Per-chain isolation follows the existing fused-run precedent (`run_flow_over_variants`, `flow_execution_service.py:608-714`).
- **Validation:** `test`
- **Executed verification:** AT-B94-20 (bind chain A to file X, chain B to file Y, run, read provenance) — node minted at Phase 3.
- **Numeric pass threshold:** after rebinding, chain A's run reads X and chain B's run reads Y — the report's provenance lines show X for A and Y for B; rebinding A leaves B's binding unchanged.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Each lane offers input binding; changing one lane's inputs does not touch the others; the run uses each chain's own files.
  - **Shipped surface:** `FlowExecutionPanel` lane bindings (NEW) + the execution service's per-chain input plan.
  - **Acceptance test(s):** AT-B94-20
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary arm: rebind to the same file (no-op); invalid arm: binding a missing file fails that chain with an inline log line while the other chains run.
  - **Negative control:** cross-lane contamination arm — RED if rebinding A alters B's bound inputs or report provenance.

### HLR-019 — Sequential default with a parallel-per-chain run control
- **Traceability:** US-007
- **Ledger:** none
- **Statement:** When the user runs a chain set, the system shall run the chains sequentially by default, and the run controls shall offer a per-run mode that runs the chains in parallel.
- **Rationale (informative):** Operator ruling D4: sequential by default, parallel per chain. C-10: the control is operator-selectable, so the AT drives the NON-DEFAULT value (parallel) and asserts the captured mode changed; a second AT pins the untouched-default (sequential). Base state: `run_flow` is strictly sequential (`flow_execution_service.py:133`); no parallel machinery exists — the parallel mode is NEW, created in Phase 3, with per-chain failure isolation.
- **Validation:** `test`
- **Executed verification:** AT-B94-21 (parallel arm, non-default per C-10) and AT-B94-22 (default arm); unit arm TC-B94-05 on the mode capture in the run record.
- **Numeric pass threshold:** default arm — chain B starts only after chain A finishes (run-log order); parallel arm — both chains execute concurrently (overlapping elapsed windows in the run-log) and the persisted run record states the selected mode; the mode field's captured value differs between the two arms.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Running untouched executes chains one after another; selecting the parallel mode runs the chains side by side; the run record shows which mode ran.
  - **Shipped surface:** `FlowExecutionPanel` run controls (NEW) + the execution service's mode dispatch.
  - **Acceptance test(s):** AT-B94-21, AT-B94-22
  - **Boundary catalog (QC-3):** ☐ empty ☒ boundary ☒ invalid ☒ error — boundary arm: a single-chain set (mode irrelevant, runs identically); error arm: a mid-run chain failure in parallel mode is isolated to its lane (the other lanes complete).
  - **Negative control:** the default arm — RED if an untouched run ever overlaps chains (a parallel-always implementation); the parallel arm — RED if the captured mode never changes from the default.

### HLR-020 — Run log with per-chain status; input provenance recorded per run
- **Traceability:** US-007
- **Ledger:** none
- **Statement:** While a chain set runs, the system shall show a run log with per-chain status and mid-chain failures visible inline, and the run's report shall record each chain's input provenance.
- **Rationale (informative):** Operator suggestion #1 (mid-chain failure visible inline) is the fx_a graduation reason; D1 requires per-run input provenance. The flow report's existing headings (`# Flow report — <name>`, `## Pipeline ledger`, `flow_report_service.py:320/:331`) are the emitted-form baseline; the chain-set report's provenance lines are NEW — pasted at the Phase-3 increment (provisional per V-5).
- **Validation:** `test`
- **Executed verification:** AT-B94-23 runs the bench scenario (chain with a missing CRC config fails mid-run) and reads the log + report.
- **Numeric pass threshold:** the run log shows one start and one terminal status line per chain plus the failing block's inline `✗` line naming the block and the missing config; the report carries one provenance line per chain input.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** During and after a run, each chain shows its status; a mid-chain failure appears inline with the block and reason; the report states what each chain consumed.
  - **Shipped surface:** the fx_a run-log strip (NEW, `flow_screens.py`) + the chain-set report (NEW, `services/flow_*`).
  - **Acceptance test(s):** AT-B94-23
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — error arm: the missing-config mid-run failure (bench scenario); empty arm: an all-clean run shows 0 `✗` lines; boundary arm: chain failing on its first block.
  - **Negative control:** all-clean arm — RED if the log invents failures; the error arm — RED if a failure is not visible inline without opening another surface.

### HLR-021 — Chain-set save and reload for re-run
- **Traceability:** US-007
- **Ledger:** none
- **Statement:** The user shall be able to save a chain set — its chains with their bound inputs and recorded outputs — to disk, and reload it to re-run or edit.
- **Rationale (informative):** Cambio7: "guardar el set de cadenas de flujo junto con sus inputs y outputs". The persisted set envelope is NEW — created in Phase 3 (`services/flow_*`, §11 pending row freezes at Inc-002/003's PDR), reusing the containment-checked persistence idiom (`import_flow_file`, `flow_persistence_service.py:601`).
- **Validation:** `test`
- **Executed verification:** AT-B94-24 — the §2.6 evaluability scenario end to end: import template, bind two chains to two input files, run, save the set, reload, re-run, both outputs regenerate.
- **Numeric pass threshold:** the reloaded set restores chain count, per-chain input bindings, and last outputs equal to the saved state; the re-run regenerates both chains' outputs.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** Save Set persists the whole set; reloading restores chains, inputs, and outputs; re-running works without re-binding.
  - **Shipped surface:** the chain-set save/load in `FlowExecutionPanel` + `services/flow_*` (NEW).
  - **Acceptance test(s):** AT-B94-24
  - **Boundary catalog (QC-3):** ☒ empty ☒ boundary ☒ invalid ☒ error — invalid arm: a corrupt set file is refused fail-closed; error arm: reloading a set whose input files moved produces a per-chain provenance-mismatch notice, not a silent stale run (state-lifetime provenance rule).
  - **Negative control:** moved-input arm — RED if a reloaded set runs against stale or silently-dropped inputs.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same regime: EARS syntax owed in `full`, recommended in `core`. ID format: `LLR-<HLR>.<M>`.

### LLR-001.1 — CheckEditorPanel class and composition
- **Traceability:** HLR-001
- **Ledger:** none
- **Statement:** The system shall provide a `CheckEditorPanel` class in `s19_app/tui/screens_directionb.py` that composes a collector for A2L parameters and memory locations, a `.chk.json` content preview, and write/validate actions with no apply action.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-06 over the panel composition (widget census; node minted at Phase 3, provisional per V-5); pre-state probe executed 2026-10-13: `grep -ri "checkeditor\|check_editor" s19_app/` → 0 hits.
- **Numeric pass threshold:** composition exposes ≥1 parameter collector, ≥1 memory-location table, exactly 1 write action, exactly 1 validate action, 0 apply actions.
- **Negative control:** none — the class does not exist at base (executed grep above); the RED side is the pre-state absence itself, and the widget-census TC goes RED if an apply action is added.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: compose at 80×24 raises no exception (smallest measured regime, workspace 74×12).

### LLR-001.2 — Check Editor rail mounting and message routing
- **Traceability:** HLR-001
- **Ledger:** none
- **Statement:** When the Check Editor rail entry is selected, `S19TuiApp` shall mount `CheckEditorPanel` in the workspace and route its write/validate messages to the change service.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-07 driving rail selection under a Textual pilot (provisional per V-5); routing idiom verified at `app.py:2529` (`on_patch_editor_panel_action_requested`) and mounting idiom at `app.py:2245` (`_compose_screen_flow`).
- **Numeric pass threshold:** selecting the entry mounts exactly 1 `CheckEditorPanel`; its write message reaches the service handler (captured call count 1).
- **Negative control:** selecting Patch Editor mounts the Patch Editor, not the check twin — RED on cross-mounting.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: rail selection at the 80×24 icon regime.

### LLR-002.1 — Rail data carries twelve entries
- **Traceability:** HLR-002
- **Ledger:** none
- **Statement:** `RAIL_ENTRIES` shall declare twelve entries, preserving the existing order and inserting Check Editor after Patch Editor and Flow Execution after Flow Builder.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-08 over `rail.py` `RAIL_ENTRIES`; executed base probe `evidence/p1_probe_rail_census.txt` (10 entries, order `workspace…crc_designer`).
- **Numeric pass threshold:** `len(RAIL_ENTRIES) == 12`; the guarded equality `len(SCREEN_IDS) == len(SCREEN_KEYS) == len(RAIL_ENTRIES)` (`test_tui_directionb.py:169`) holds at the landing increment.
- **Negative control:** the executed base census (10 entries) — RED at 11 or on order drift.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: duplicate screen keys across entries are rejected by the census.

### LLR-002.2 — Rail census constants move with the landing increments
- **Traceability:** HLR-002
- **Ledger:** none
- **Statement:** The guard-host census constants `SCREEN_IDS`, `SCREEN_KEYS`, and `EXPECTED_RAIL` shall be updated in the same commit that lands each new surface, never before.
- **Validation:** `inspection`
- **Executed verification:** inspection of the landing increment's diff: `test_tui_directionb.py:137-169`, `:468-479` change in the same commit as the rail entry (per `docs/architecture.md:392` — an early census green-lights nothing).
- **Numeric pass threshold:** 0 census updates in commits that do not land a surface.
- **Negative control:** n/a — inspection method; no executed RED side (declared none per the field's rule: an inspection arm has no failing input by construction).
- **Boundary catalog:** none — inspection method, no input classes to generate arms for.

### LLR-003.1 — Expanded JSON editor is the panel's primary edit surface
- **Traceability:** HLR-003
- **Ledger:** none
- **Statement:** The Patch Editor shall compose the JSON text editor as a first-class panel region fed by `JsonHighlightTextArea`, with the entries table remaining the source of truth above it.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-09 widget census over the reworked panel (provisional per V-5); base widgets verified at `screens_directionb.py:6078-6080` (`patch_paste_text`) and `:5749-5750` (`patch_doc_entries_table`).
- **Numeric pass threshold:** 1 `JsonHighlightTextArea` instance in the panel composition; 1 entries table; inner split geometry `assumed — verify in Phase 3` against the pe_b idiom (pilot measured the 96×18/136×28 workspace boxes only, `evidence/p1-pilot-measurements.txt`).
- **Negative control:** base composition (capped side pane `patch_win_json`, `:6150`) — RED if the rework keeps the editor inside the capped gauge pane.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: compose at 120×30 and 80×24 raises no exception.

### LLR-004.1 — Valid JSON edits merge into the entries table
- **Traceability:** HLR-004
- **Ledger:** none
- **Statement:** When edited JSON text parses valid, the system shall convert the declared entries into table rows through `refresh_entries` in document order.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-01 over the validate-merge path (parse via `parse_change_document`, `io.py:440`; merge via `refresh_entries`, `:6639`).
- **Numeric pass threshold:** 100% of the valid entries appear as table rows (row count after merge == valid entry count, 0 dropped, 0 duplicated) in document order; 0 table errors.
- **Negative control:** valid text with zero entries adds zero rows (no-op, not an error) — RED if an empty valid document clears or errors the table.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — boundary arm: the largest entry count the editor accepts without truncation of the table view (scrollable).

### LLR-004.2 — Invalid JSON edits surface errors and leave the table unchanged
- **Traceability:** HLR-004
- **Ledger:** none
- **Statement:** When edited JSON text fails validation, the system shall display the document's collected issues and leave the entries table byte-identical.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-01 invalid arms (malformed JSON; unknown `kind` → `CHG-KIND-UNKNOWN`, `io.py:182-183`; junk entry declaration → `CHG-DECL-STRUCTURE`, `io.py:191-197`); error surface idiom: `ChangeDocument.issues` (`model.py:249`), demonstrated end-to-end in `evidence/p1_probe_chk_roundtrip.txt`.
- **Numeric pass threshold:** displayed issues ≥ 1; table rows before == table rows after (count equality).
- **Negative control:** the malformed-JSON arm — RED if any row changes or no error renders.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arms as listed.

### LLR-005.1 — Dirty state tracking across both editor regions
- **Traceability:** HLR-005
- **Ledger:** none
- **Statement:** While unsaved edits exist in the entries table or the JSON text editor, the panel shall hold a dirty flag that any save clears.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-10 over the dirty flag (writers census per C-15.1 executed at Phase 3: every writer of the flag's assignment sites is enumerated and guarded; the flag's writers today: none — the flag is NEW, created in Phase 3).
- **Numeric pass threshold:** all 4 dirty transitions assert (edit-table→set, edit-text→set, save→cleared, load-success→cleared); 0 inconsistent flag reads across the 2 regions; test exit code 0.
- **Negative control:** save-then-check arm — RED if the flag survives its own save.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: dirty in the text region while the table is clean (and vice versa) still guards the Load.

### LLR-005.2 — Load warning popup with accept-loss and cancel branches
- **Traceability:** HLR-005
- **Ledger:** none
- **Statement:** If the dirty flag is set when Load activates, the system shall present a warning popup whose accept control continues the load and whose cancel control aborts it.
- **Validation:** `test (e2e)`
- **Executed verification:** AT-B94-06 / AT-B94-07 arms through the real Load key path (`patch_doc_load_button`, `:5880`; provisional per V-5).
- **Numeric pass threshold:** popup shown in exactly 1 of 1 dirty-load drives and in 0 of 1 clean-load drives; the accept arm mounts 100% of the target document's rows; the cancel arm retains 100% of the prior rows and the dirty flag (0 rows lost); exit code 0.
- **Negative control:** clean-load arm — RED if the popup appears with nothing dirty.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty arm: dirty flag set but the target path unresolved — the guard still asks before refusing the load.

### LLR-006.1 — Variant controls and messages retire from the editor
- **Traceability:** HLR-006
- **Ledger:** none
- **Statement:** The Patch Editor shall not compose `patch_variant_select`, and the `VariantSelected` / `VariantHelpRequested` messages and their app routing shall be removed.
- **Validation:** `inspection` + `test (unit)`
- **Executed verification:** inspection of the Inc-001 diff (widgets `:5910-5925`, messages `:5417-5456`, routing `app.py:4659`/`:2846` absent); unit TC-B94-11: posting a stale `VariantSelected`-shaped message to the panel is a no-op.
- **Numeric pass threshold:** 0 occurrences of `patch_variant` in `screens_directionb.py`; 0 variant actions in `PATCH_ACTIONS_V2` (`app.py:176-190`); the 11 retained actions still route.
- **Negative control:** the pre-state file itself (selector present at `:5910-5916`, executed read 2026-10-13) — RED if any variant control renders.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: the stale-message no-op.

### LLR-006.2 — Single-document editing binding
- **Traceability:** HLR-006
- **Ledger:** none
- **Statement:** The Patch Editor shall bind all edit, validate, and apply operations to the one loaded change-set document.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-11: two consecutive Load operations leave exactly one document bound; undo/redo stacks (`UndoRequested`/`RedoRequested`, `:5459`/`:5476`) reference the bound document only.
- **Numeric pass threshold:** exactly 1 bound document after any operation sequence; cross-document residue (orphaned entries) == 0.
- **Negative control:** load-A-then-load-B arm — RED if entries from A survive into B's table.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: Load of the same document twice.

### LLR-007.1 — Apply executes the loaded document through the existing gate
- **Traceability:** HLR-007
- **Ledger:** none
- **Statement:** When Apply activates with a loaded document, the system shall call `apply_change_document` and present the applied set as the entries listed in the entries table.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-02 over the Apply path (`apply_change_document`, `apply.py:226`; gate `blocked = document.has_errors or document.kind != "change"` at `apply.py:320`); gate behavior executed in `evidence/p1_probe_chk_roundtrip.txt` (`blocked: 2`, zero writes).
- **Numeric pass threshold:** `counts["applied"]` == applicable entries of the loaded document; a document with blocking errors yields `counts["blocked"] == len(entries)` and 0 writes.
- **Negative control:** blocking-errors arm — RED if any byte is written for a blocked document.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☒ error — empty arm: no document loaded → 0 writes + `skipped-no-image` census; error arm: the gate's blocked disposition.

### LLR-007.2 — Apply presentation as apply-loaded-changes
- **Traceability:** HLR-007
- **Ledger:** none
- **Statement:** The Apply control shall be labeled and described as applying the loaded changes.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-12 label census over the reworked controls (`patch_doc_apply_button`, `:5891`).
- **Numeric pass threshold:** control label/describe text matches the apply-loaded-changes wording; census 1 matching control, 0 legacy bare-"Apply" labels in the panel.
- **Negative control:** RED on the legacy bare label surviving the rework.
- **Boundary catalog:** none — presentation census; no input classes apply.

### LLR-008.1 — Load reads the adjacent path input
- **Traceability:** HLR-008
- **Ledger:** none
- **Statement:** When Load activates, the system shall resolve the path input adjacent to the Load control and read that document through `read_change_document`.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-03 over `read_change_document` (`io.py:296`) driven by the path input (`patch_doc_path_input`, `:5800-5806`).
- **Numeric pass threshold:** valid path → document rows mounted == file entries; empty/unresolved path → 1 collected issue (`MF-PATH-UNRESOLVED`, `io.py:165-166`), nothing loaded.
- **Negative control:** empty-path arm — RED if an empty input loads the dropdown's first file instead.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — invalid arms: nonexistent path; non-JSON content (`MF-JSON-PARSE`, `io.py:159`).

### LLR-008.2 — Refresh repopulates the dropdown from the folder scan
- **Traceability:** HLR-008
- **Ledger:** none
- **Statement:** When Refresh activates, the system shall re-run the patches-folder scan and replace the dropdown options with its result, leaving the loaded document untouched.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-03 refresh arm against `_scan_patch_change_files` (`app.py:4413`, glob `*.json` under `workarea/patches/`).
- **Numeric pass threshold:** dropdown option count == folder-scan result count (100% set equality, sorted); the loaded document is 1 unchanged document (identity hash identical before/after); 0 documents remounted or reloaded by the refresh.
- **Negative control:** loaded-document-unchanged arm — RED if Refresh remounts or reloads anything.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty arm: folder with no `.json` files → empty dropdown, no error.

### LLR-009.1 — Check-spec assembly and `.chk.json` write
- **Traceability:** HLR-009
- **Ledger:** none
- **Statement:** The Check Editor shall assemble a `ChangeDocument` with `kind="check"` from the collected A2L parameters and memory locations and write it through `write_change_document` under a `.chk.json` name.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-13 round-trip (write via `io.py:1285`, re-read via `io.py:296`); executed probe `evidence/p1_probe_chk_roundtrip.txt` (the shipped writer/reader round-trip `kind="check"` today; `_safe_name('baseline.chk.json')` → `'baseline.chk.json'` at `io.py:1406-1411`).
- **Numeric pass threshold:** 1 written file whose name ends with `.chk.json`; the re-read document has `kind == "check"`, `has_errors == False` (0 blocking errors), and entry count == collected count (100% round-trip).
- **Negative control:** name-mangling arm — RED if the writer reduces a `.chk.json` name to `.json` (the executed `_safe_name` probe is the pre-state guarantee).
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☒ error — empty arm: zero collected items still writes a valid empty check document; error arm: work-area containment refusal (`MF-WRITE-CONTAINMENT`, `io.py:1364-1374`).

### LLR-009.2 — Validate runs the check document through the shipped runner
- **Traceability:** HLR-009
- **Ledger:** none
- **Statement:** When Validate activates, the system shall run `run_check_document` over the assembled spec and display one verdict row per entry.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-14 over `run_check_document` (`check.py:194`); runner behavior executed in `evidence/p1_probe_chk_roundtrip.txt` (verdicts `pass` / `uncheckable`, reason code `outside`).
- **Numeric pass threshold:** verdict row count == entry count (100% coverage, 0 missing, 0 extra rows); 100% of rows carry exactly 1 of `pass`/`fail`/`uncheckable`.
- **Negative control:** wrong-kind arm — a `kind="change"` document fed to the runner is run-blocked with reason code `doc-kind` (`check.py:14-16`, `:213-216`).
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — boundary arm: entries outside the loaded image read `uncheckable`.

### LLR-009.3 — No apply path exists for check specs
- **Traceability:** HLR-009
- **Ledger:** none
- **Statement:** The Check Editor shall expose no apply control, and any apply call over a check document shall produce zero writes through the existing kind gate.
- **Validation:** `test (unit)`
- **Executed verification:** executed probe `evidence/p1_probe_chk_roundtrip.txt` — `apply_change_document` over `kind="check"` returns `counts == {'applied': 0, 'skipped-partial': 0, 'skipped-outside': 0, 'skipped-no-image': 0, 'blocked': 2}` and the memory map is untouched; TC-B94-13 asserts 0 apply controls in the panel composition.
- **Numeric pass threshold:** 0 apply controls; `counts["blocked"] == len(entries)`; 0 bytes written.
- **Negative control:** the gate probe itself — RED if a check document ever yields `counts["applied"] > 0`.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: a hand-crafted apply call over a check spec (the gate refuses).

### LLR-010.1 — A2B Diff dropdown lists check specs by suffix
- **Traceability:** HLR-010
- **Ledger:** none
- **Statement:** The A2B Diff file dropdown shall list `.chk.json` files and patch `.json` files from the same directory, displaying the check specs with a suffix-distinguished label.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-15 over the dropdown population (scan idiom `app.py:4413-4457`, suffix branch NEW in Phase 3); label distinction mirrors the ce_a idiom (`baseline.chk.json CHECK` green suffix vs `hotfix.pch.json PATCH`, `editor_bench.NOTES.md`).
- **Numeric pass threshold:** dropdown set == directory scan set; every `.chk.json` entry's label carries the CHECK distinction; 0 entries lose their suffix label.
- **Negative control:** mixed-folder arm — RED if a check spec renders indistinguishable from a patch file.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☐ error — invalid arm: a `.chk.json` that fails the read path is listed but surfaces its issues on load (never silently loaded).

### LLR-010.2 — Loading a check spec adds the declared items to the diff report
- **Traceability:** HLR-010
- **Ledger:** none
- **Statement:** When the user loads a `.chk.json` into the A2B Diff, the report producer shall append the declared parameters and memory locations to the emitted report.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-16 through the shipped chain; C-42 discipline: the addendum predicate is written against the Phase-3 increment's paste of the producer's own emitted text (the report producer's current header form is pasted in `evidence/p1_probe_diff_report_emitted.txt`); report-side text renders through `markdown_safety.md_safe`.
- **Numeric pass threshold:** 100% of the declared parameter/location names appear in the emitted report (found == declared, 0 missing); the report file is non-empty (> 0 bytes) and parses as the same markdown structure as the pasted base form (0 structural deviations).
- **Negative control:** C-12 arm — a hand-written spec injected at the consumer is not the acceptance input; RED if the AT cannot chain writer→reader→report from the shipped producer.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☐ error — empty arm: an empty check spec adds an empty addendum section, not an error.

### LLR-011.1 — New editor surfaces render file-derived text via the safety primitive
- **Traceability:** HLR-011
- **Ledger:** none
- **Statement:** The Check Editor shall construct every rendered string that originates in a loaded file or document through `safe_text`, and the report addendum shall escape file-derived values through `markdown_safety.md_safe`.
- **Validation:** `inspection` + `test (unit)`
- **Executed verification:** inspection: 0 `Text.from_markup` / 0 bare-`Text(file_string)` constructions in the new module (guard `test_tc_042_10` per `engineering-rules.md:190`); unit TC-B94-17: `safe_text` over the hostile payload deletes every control byte and keeps brackets literal (primitive contract at `utils.py:41-99`).
- **Numeric pass threshold:** hostile payload → 0 control bytes in `.plain`, bracket characters preserved verbatim; source scan: 0 markup-parsed constructions.
- **Negative control:** primitive unit arm with the payload — RED if any control byte survives.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: the HLR-011 payload in a symbol name and in a file name.

### LLR-011.2 — Hostile-input acceptance through the shipped Check Editor
- **Traceability:** HLR-011
- **Ledger:** none
- **Statement:** When a loaded A2L carries a hostile symbol name, the Check Editor shall render it literally in the parameter collector, the dropdown, and the report addendum.
- **Validation:** `test (e2e)`
- **Executed verification:** AT-B94-13 (payload shape from `tests/test_tui_hostile_map.py:105-107`: ESC-CSI `"\x1b[31m"` + Rich markup `"_evil[red]"` + C1 CSI `"\x9b1m"` + C1 OSC + NUL + DEL, sentinel `b77hostilemark`).
- **Numeric pass threshold:** sentinel visible in all three surfaces; 0 markup spans / hyperlinks / style leaks; no exception.
- **Negative control:** plain-name arm — RED if a printable name is altered.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: the full payload in both file-derived fields.

### LLR-012.1 — Curated standard-keyword set (policy constant)
- **Traceability:** HLR-012
- **Ledger:** none
- **Statement:** The Issues surface shall classify `A2L_UNRECOGNIZED_BLOCK` findings whose block name is in the curated ASAP2 standard-keyword set through a named constant owned by the view layer.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-18 over the constant's membership (seed set pasted from the executed tally, `evidence/p1_probe_a2l_unrecognized.txt`: A2ML, MOD_COMMON, MOD_PAR, SEGMENT, PAGE, PROTOCOL_LAYER, PAG, DAQ, STIM, TIMESTAMP_SUPPORTED, EVENT, XCP_ON_CAN, CAN_FD, AXIS_DESCR, FORMULA, COMPU_VTAB_RANGE, SUB_GROUP, SUB_FUNCTION, REF_CHARACTERISTIC, REF_MEASUREMENT, DEF_CHARACTERISTIC — 21 families); constant NEW — created in Phase 3 (`issues_view.py`).
- **Numeric pass threshold:** every seeded family is a member; every member is uppercase A2L vocabulary; the engine's `RECOGNIZED_A2L_BLOCKS` (`rules.py:9-25`) is byte-unchanged (frozen-layer check in the same TC).
- **Negative control:** `FROBNICATE` is not a member (executed probe `p1_probe_a2l_negative.txt`) — RED if the set ever swallows a non-standard name without a ledger entry.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: the empty set renders nothing reclassifiable (degenerate no-op).

### LLR-012.2 — Reclassification to informational with visible justification
- **Traceability:** HLR-012
- **Ledger:** none
- **Statement:** When an `A2L_UNRECOGNIZED_BLOCK` finding's block name is in the curated set, the Issues surface shall render it under the INFO severity with the reclassification justification displayed at the group.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-19 through `GroupedIssuesPanel` (`issues_view.py:307`; severity sections `SEVERITY_ORDER`/`SEVERITY_LABELS`, `:57-68`; rendering via `safe_text`, `:273-293`).
- **Numeric pass threshold:** on the stand-in fixture: WARNING `A2L_UNRECOGNIZED_BLOCK` == 0, INFO rows == 1 023 (baseline probe count; no row dropped), justification text rendered at the INFO group.
- **Negative control:** executed `FROBNICATE` probe — RED if an unknown block renders as INFO or disappears.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☐ error — empty arm: no A2L loaded → empty state; boundary arm: a file mixing curated and unknown blocks splits them across INFO and WARNING.

### LLR-013.1 — fb_a palette, canvas, and cable widgets
- **Traceability:** HLR-013
- **Ledger:** none
- **Statement:** The reworked Flow Builder shall compose a block palette rail, a framed canvas with grid dots, and box-drawn blocks carrying `in`/`out` IO rows with cable runs routed between stubs.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-20 widget census over the reworked panel (widgets NEW — created in Phase 3 in `flow_screens.py`; fb_a layout doctrine: `flow_bench.NOTES.md` fb_a — header bar, IO rows, `┤├` stubs, `─│└┐` runs, refined cable routing per operator decision D5).
- **Numeric pass threshold:** composition: 1 palette, 1 canvas, 3 placeable block types (patch/CRC/A2B-diff); a two-block flow renders ≥1 cable run connecting an out-stub to an in-row at 120×30 inside the boxed 96×18 workspace.
- **Negative control:** base panel (`FlowBuilderPanel` list tracer, `screens_directionb.py:4257-4404`) — RED if the list-based UI survives the rework.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: empty canvas renders the fb_a empty state without exception.

### LLR-013.2 — Block-type registry including the A2B diff block
- **Traceability:** HLR-013
- **Ledger:** none
- **Statement:** The flow model shall carry an A2B diff block type alongside the existing source, patch, CRC, check, and write-out types, with per-kind serialization fields for its two input bindings.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-21 over `flow_to_dict`/`dict_to_flow` (`flow_persistence_service.py:175/:248`) round-trip with an A2B block; reused constants verified at `flow_model.py:25-33` (`BLOCK_PATCH`, `BLOCK_CRC`); the A2B block type constant is NEW — created in Phase 3.
- **Numeric pass threshold:** serialized flow with one of each block type round-trips with kind equality and per-kind fields intact; `schema_version` unchanged (1).
- **Negative control:** unknown-kind arm — a foreign `kind` in the payload is refused fail-closed by `dict_to_flow` (executed hardened path, `:248`).
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — invalid arm: an A2B block missing both bindings fails validation at load.

### LLR-013.3 — Block run semantics reuse the existing services
- **Traceability:** HLR-013
- **Ledger:** none
- **Statement:** When a flow runs, the patch, CRC, and A2B diff blocks shall execute through the existing patch-apply, CRC-apply, and diff-report services.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-22 headless run of a two-block flow (patch → write-out) asserting the written image; existing CRC-block precedent `tests/test_flow_crc_block.py` (AT-123…AT-127 arms over `run_flow`, `flow_execution_service.py:86`).
- **Numeric pass threshold:** 100% of the patch's declared addresses hold the declared new bytes in the output image (0 mismatches); 1 CRC block output carrying the configured CRC; per-block results recorded for all blocks in the flow (0 missing).
- **Negative control:** CRC-block-invalid arm (missing config, `tests/test_flow_crc_block.py:316-335`) — RED if a missing config ever applies.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☒ error — error arm: an upstream failure skips downstream blocks (`BLOCK_STATUS_SKIPPED`, `flow_execution_service.py:143`).

### LLR-014.1 — A2B input binding model enforces the flow-output-or-file rule
- **Traceability:** HLR-014
- **Ledger:** none
- **Statement:** The A2B block shall bind each image input to either a named flow output or an external file path, and wiring validation shall require at least one input bound to a flow output of the current flow.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-23 over the binding validation (binding model NEW — created in Phase 3); rule per intake brief: "≥1 input must come from the current flow, para no falsear reportes" (`flow_bench.NOTES.md`).
- **Numeric pass threshold:** accepted bindings: (flow-output, flow-output), (flow-output, file), (file, flow-output); refused: (file, file) and any cross-flow source — 0 reports produced for refused bindings.
- **Negative control:** both-external arm — RED if a both-file binding reaches the runner.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — boundary arm: exactly one flow output + one external file (the minimum legal).

### LLR-014.2 — Provenance lines in the A2B report
- **Traceability:** HLR-014
- **Ledger:** none
- **Statement:** The A2B report for a flow-run block shall emit one provenance line per input, stating the external path in the existing emitted form and the producing block for flow outputs.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-24 + C-42: external arm predicate matches the executed base form pasted in `evidence/p1_probe_diff_report_emitted.txt` (`- Image A: prg [external] path=\`…\` parse-errors=0`); flow-output arm's emitted form is pasted at the Phase-3 increment (provisional per V-5).
- **Numeric pass threshold:** 2 provenance lines per A2B report; the external arm's line matches the pasted shape character-for-character in its fixed parts; the flow arm names the producing block.
- **Negative control:** the pasted base form — RED if the external arm drifts from its own emitted shape (widths/separators are the producer's choice, C-42).
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☒ error — error arm: an input whose source block failed yields no report and a block-level error.

### LLR-015.1 — Template save through the existing persistence service
- **Traceability:** HLR-015
- **Ledger:** none
- **Statement:** Saving a flow template shall serialize through `save_flow_json` into the work-area `flows/` folder with a sanitized, dedup-suffixed name.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-04 over `save_flow_json` (`flow_persistence_service.py:522`; containment idiom `import_flow_file`, `:601`).
- **Numeric pass threshold:** saved file parses as `{"schema_version": 1, "name", "blocks"}`; a name collision dedup-suffixes instead of clobbering.
- **Negative control:** collision arm — RED if a second save with the same name overwrites the first.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☒ error — empty arm: zero-block template saves; error arm: a name escaping the work area is refused by containment.

### LLR-015.2 — Template import reconstructs the flow fail-closed
- **Traceability:** HLR-015
- **Ledger:** none
- **Statement:** Importing a template shall parse it through `dict_to_flow` and mount the flow only when the parse yields no blocking issue.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-04 over `dict_to_flow` (`flow_persistence_service.py:248`, hardened V1-V7 fail-closed whole-flow).
- **Numeric pass threshold:** valid template → mounted block list == serialized block list; corrupt/foreign payload → 0 blocks mounted + ≥1 issue surfaced.
- **Negative control:** corrupt-payload arm — RED if a partial flow mounts.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — invalid arm: oversized payload over the 1 MiB cap (`FLOW_SIZE_CAP_BYTES`, `:64`).

### LLR-016.1 — Flow surfaces render file-derived text via the safety primitive
- **Traceability:** HLR-016
- **Ledger:** none
- **Statement:** `flow_screens.py` shall construct every rendered string originating in a file name, template name, or provenance value through `safe_text`, and the flow reports shall escape such values through `markdown_safety.md_safe` or `md_code` per the mode truth table.
- **Validation:** `inspection` + `test (unit)`
- **Executed verification:** inspection: 0 markup-parsed constructions in `flow_screens.py` (allowed dependency declared at `docs/architecture.md:375`: `flow_screens → utils.safe_text`); unit TC-B94-25 over `md_safe`/`md_code` mode selection (`services/markdown_safety.py` truth table).
- **Numeric pass threshold:** hostile file name → 0 markup spans in the canvas label and the report; 0 control bytes.
- **Negative control:** payload unit arm — RED if any structural character survives unescaped in a Mode-A context.
- **Boundary catalog:** ☐ empty ☐ boundary ☒ invalid ☐ error — invalid arm: a path-valued name in a report cell is FORBIDDEN by the truth table (Mode B inside a code span only) — RED if emitted raw in a cell.

### LLR-017.1 — Template import mounts one lane per chain
- **Traceability:** HLR-017
- **Ledger:** none
- **Statement:** When the user imports a template, `FlowExecutionPanel` shall append one lane rendering the template's chain with its pinned inputs.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-26 through the shipped panel (provisional per V-5) over `list_saved_flows`/`load_flow_json` (`flow_persistence_service.py:570/:463`).
- **Numeric pass threshold:** lane count == imported count (e.g. 2 imports → 2 lanes, 0 missing, 0 duplicates); 100% of lanes' block lists equal their templates' block lists; 0 lanes mounted on a cancelled import; exit code 0.
- **Negative control:** cancel-import arm — RED if a cancelled import adds a lane.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☐ error — invalid arm: corrupt template refused with a notice (LLR-015.2 path).

### LLR-017.2 — Lanes render side by side within the boxed budgets
- **Traceability:** HLR-017
- **Ledger:** none
- **Statement:** The Flow Execution lanes shall render side by side at 120×30 and 160×40 within the measured boxed workspaces, with overflow reachable by scrolling.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-26 render census at (120,30) and (160,40) under `run_test` (boxed budgets 96×18 / 136×28 from `evidence/p1-pilot-measurements.txt`, premise 7).
- **Numeric pass threshold:** 2 lanes fully visible at 120×30; each lane shows its chain name, pinned inputs, and status region without overlap.
- **Negative control:** 80×24 arm — RED if the layout errors rather than scrolling (reachable-under-scroll is the authored fallback, reason: 74×12 cannot host two full lanes).
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arms: the three measured regimes.

### LLR-018.1 — Per-chain input bindings are independent state
- **Traceability:** HLR-018
- **Ledger:** none
- **Statement:** Each lane shall hold its own input bindings, and an edit to one lane shall not write another lane's bindings.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-27 over the lane state (writers census per C-15.1 at Phase 3; per-chain isolation precedent `run_flow_over_variants`, `flow_execution_service.py:690-714`).
- **Numeric pass threshold:** editing lane A's binding changes exactly 1 binding record (A's); lane B's bound path is byte-identical before/after (0 fields changed); exit code 0.
- **Negative control:** cross-lane write arm — RED if editing A touches B.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: rebinding to the same path is a no-op.

### LLR-018.2 — The run consumes each chain's own bindings
- **Traceability:** HLR-018
- **Ledger:** none
- **Statement:** When the set runs, each chain shall execute against its own bound input files, and the report shall state those bindings.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-28 run + report read (provenance predicate per LLR-020.2's emitted-form paste).
- **Numeric pass threshold:** chain A's provenance lines name A's file, B's name B's; 0 cross-mentions.
- **Negative control:** swapped-inputs arm — RED if A's report lines ever name B's file.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☐ error — invalid arm: a missing input file fails that chain only (other chains complete).

### LLR-019.1 — Sequential execution is the default mode
- **Traceability:** HLR-019
- **Ledger:** none
- **Statement:** When the run control is activated without a mode selection, the system shall execute the chains one at a time in lane order.
- **Validation:** `test (integration)`
- **Executed verification:** AT-B94-22 default arm; sequential executor precedent executed at `flow_execution_service.py:133` (single block loop).
- **Numeric pass threshold:** run-log shows chain N+1 starting only after chain N's terminal status; 0 elapsed overlap between chains.
- **Negative control:** default arm — RED if an untouched run overlaps chains.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☐ error — empty arm: single-chain set is trivially sequential.

### LLR-019.2 — Parallel-per-chain mode with per-lane failure isolation
- **Traceability:** HLR-019
- **Ledger:** none
- **Statement:** When the user selects the parallel mode, the system shall execute the chains concurrently, isolate a chain's failure to its own lane, and record the selected mode in the run record.
- **Validation:** `test (integration)`
- **Executed verification:** AT-B94-21 (C-10: drives the non-default value and asserts the captured mode changed); parallel machinery NEW — created in Phase 3.
- **Numeric pass threshold:** parallel arm — 2 chains' elapsed windows overlap (while the default arm shows 0 overlap); the persisted run record's mode field reads `parallel` in 1 of 1 driven runs and differs from the default arm's record; when 1 chain fails, ≥1 sibling lane still completes (0 siblings halted).
- **Negative control:** the C-10 captured-value assertion — RED if the run record ever reads sequential after the parallel control was driven.
- **Boundary catalog:** ☐ empty ☒ boundary ☒ invalid ☒ error — error arm: mid-run chain failure isolated to its lane (fx_a `✗` inline idiom).

### LLR-020.1 — Run log emits per-chain status and inline failures
- **Traceability:** HLR-020
- **Ledger:** none
- **Statement:** During and after a run, the run log shall show one status line per chain transition and an inline failure line naming the failed block and reason.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-29 over the run-log emission (run-log strip NEW — created in Phase 3; bench scenario: missing `crc_regions.json` fails the CRC block mid-run, `flow_bench.NOTES.md` sample data).
- **Numeric pass threshold:** per chain: ≥2 status lines (start, terminal); the failed chain's log line names the block and the missing config; the failing chain halts, later blocks in that chain read skipped.
- **Negative control:** all-clean arm — RED if any `✗` line appears without a failure.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☒ error — error arm: the bench's missing-config scenario; boundary arm: failure on the chain's first block.

### LLR-020.2 — Per-run input provenance in the chain-set report
- **Traceability:** HLR-020
- **Ledger:** none
- **Statement:** The chain-set report shall record, per chain, the input files the run consumed.
- **Validation:** `test (integration)`
- **Executed verification:** TC-B94-30 + C-42: the provenance line form is NEW — pasted at the Phase-3 increment and the predicate written against that paste (flow-report headings baseline at `flow_report_service.py:320-331`); report text renders through `markdown_safety.md_safe`.
- **Numeric pass threshold:** provenance line count == chain-input count (1 line per input, 0 missing, 0 duplicates); 100% of lines resolve to the bound path (name equality with the binding record, 0 stale names).
- **Negative control:** rebind-then-rerun arm — RED if the report names a stale input after rebinding.
- **Boundary catalog:** ☐ empty ☒ boundary ☐ invalid ☐ error — boundary arm: a chain with a single input.

### LLR-021.1 — Chain-set save persists chains, bindings, and outputs
- **Traceability:** HLR-021
- **Ledger:** none
- **Statement:** Saving a chain set shall persist every chain's template reference, its bound inputs, and its last recorded outputs in one document inside the work area.
- **Validation:** `test (unit)`
- **Executed verification:** TC-B94-31 over the set serializer (set envelope NEW — created in Phase 3; containment idiom per `import_flow_file`, `flow_persistence_service.py:601`).
- **Numeric pass threshold:** 1 saved document: chain count == lane count (100%); every chain carries 1 template ref, ≥1 input, and ≥1 output (0 chains missing a field); 0 empty sets written as non-empty; the file lands inside the work area (1 containment check passes).
- **Negative control:** empty-set arm — RED if saving with zero chains writes a document claiming otherwise.
- **Boundary catalog:** ☒ empty ☒ boundary ☐ invalid ☒ error — error arm: a set write failing containment is refused with one issue.

### LLR-021.2 — Reload restores the set and re-runs without re-binding
- **Traceability:** HLR-021
- **Ledger:** none
- **Statement:** When the user reloads a saved set, the system shall restore its chains with their bindings and outputs, and a re-run shall regenerate every chain's outputs.
- **Validation:** `test (e2e)`
- **Executed verification:** AT-B94-24 (the §2.6 evaluability scenario: import → bind two chains → run → save → reload → re-run → both outputs regenerate).
- **Numeric pass threshold:** the reloaded set restores 100% of chains, input bindings, and outputs (0 field diffs vs the saved state); the re-run regenerates both chains' 2 output files (mtime/content change on 2 of 2).
- **Negative control:** moved-input arm — reloading a set whose input file moved yields a per-chain provenance-mismatch notice, not a silent stale run.
- **Boundary catalog:** ☒ empty ☒ boundary ☒ invalid ☒ error — invalid arm: corrupt set file refused fail-closed; error arm: the moved-input notice.

### Information Flow Contract (IFC) — C-54

> Part A — one FLOW block per information flow the new requirements introduce; every node owned by exactly one LLR. Part B — the TUI panels are independently addressable components (a consumer selects a panel and indexes its children), so the new surfaces are declared as components. Block syntax per `templates/ifc-template.md`.

- **Part A — flows:**

```
FLOW: check_spec_to_diff_report
  SOURCE : the .chk.json file on disk written by the Check Editor (workarea/patches/)
  NODES  :
    - fn    : write_change_document (Check Editor write action)
      owner : LLR-009.1
      in    : ChangeDocument(kind="check")
      out   : .chk.json file bytes in the work area
    - fn    : parse_change_document + read_change_document (A2B Diff load)
      owner : LLR-010.1
      in    : .chk.json file bytes
      out   : ChangeDocument with declared parameters/locations
    - fn    : generate_diff_report addendum (check-spec append)
      owner : LLR-010.2
      in    : ChangeDocument entries + comparison state
      out   : emitted report section carrying the declared items
  SINK   : the A2B diff report markdown consumed by the operator (and report_filter/report_service downstream)
```

```
FLOW: a2l_file_to_issues_triage
  SOURCE : the loaded A2L file parsed by parse_a2l_file (a2l.py:1633)
  NODES  :
    - fn    : validate_a2l_structure section classification (engine, frozen)
      owner : LLR-012.1
      in    : parsed sections
      out   : A2L_UNRECOGNIZED_BLOCK findings with block names
    - fn    : curated-set reclassification policy (view layer)
      owner : LLR-012.2
      in    : findings + curated standard-keyword set
      out   : INFO-severity rows with justification (WARNING for non-set names)
  SINK   : the Issues surface groups (GroupedIssuesPanel) read by the operator
```

```
FLOW: flow_template_to_execution
  SOURCE : the builder template JSON in workarea/flows/ (save_flow_json)
  NODES  :
    - fn    : save_flow_json (builder template save)
      owner : LLR-015.1
      in    : Flow (name + typed blocks)
      out   : {"schema_version": 1, "name", "blocks"} JSON
    - fn    : load_flow_json + dict_to_flow (execution import)
      owner : LLR-017.1
      in    : template JSON
      out   : mounted lane with the template's chain
  SINK   : the Flow Execution lanes (FlowExecutionPanel) operated by the operator
```

```
FLOW: chain_set_save_load
  SOURCE : the operator's Save Set action in Flow Execution
  NODES  :
    - fn    : chain-set serializer (chains + input bindings + outputs)
      owner : LLR-021.1
      in    : lane states (template refs, bound inputs, last outputs)
      out   : chain-set JSON document in the work area
    - fn    : chain-set loader (reload + provenance rebind)
      owner : LLR-021.2
      in    : chain-set JSON
      out   : restored lanes; regenerated outputs on re-run
  SINK   : the Flow Execution lanes and their output files
```

```
FLOW: block_input_provenance_to_report
  SOURCE : the A2B block's input bindings in the flow model (flow output name or external path)
  NODES  :
    - fn    : binding validation (flow-output-or-file, >=1 from current flow)
      owner : LLR-014.1
      in    : two input bindings
      out   : validated binding pair
    - fn    : provenance line emission in the A2B report
      owner : LLR-014.2
      in    : validated binding pair + comparison result
      out   : one provenance line per input ("- Image A: <label> [external] path=`...`" form; flow-output form pasted at Phase 3)
  SINK   : the A2B diff report markdown read by the operator
```

```
FLOW: rail_selection_to_panel_mount
  SOURCE : the operator's rail selection (key or pointer)
  NODES  :
    - fn    : RAIL_ENTRIES census + key/click routing (app.py action_show_screen)
      owner : LLR-002.1
      in    : rail entry identity
      out   : screen id to mount
    - fn    : panel mounting for the two new surfaces
      owner : LLR-001.2
      in    : screen id (check_editor / flow_execution)
      out   : mounted CheckEditorPanel / FlowExecutionPanel
  SINK   : the workspace region rendering the mounted panel
```

- **Part B — boundary decomposition:** yes — the TUI panels are independently addressable components. Parent: `workspace_shell`, the outermost declared boundary (`docs/architecture.md` §11); the shell is a containment fact, not a COMPONENT, and these rail screens are siblings of the workspace inside it. `workspace_shell` is not declared as a COMPONENT here or in any batch record, so `V12` balancing reports *could not be tested* for these blocks — the honest NOTICE per C-54's could-not-be-tested form (batch-87 precedent), not a pass. The earlier parenting of these blocks at `screen_workspace` was a drafting error: batch-88's frozen contract cannot declare the new surfaces' flow names, so containment structurally failed. Components are declared only for the new/reworked surfaces a consumer addresses independently:

```
COMPONENT: check_editor_panel
  PARENT : workspace_shell
  SURFACE: Check Editor (rail surface, Inc-001)
  INPUTS : selected_a2l_tags: list[dict] ; check_spec_entries: list[ChangeEntry] ; spec_file_listing: list[str]
  OUTPUTS:
    - id          : collector_rows
      value       : the collected A2L parameters and memory locations
      address     : query("#check-editor-panel parameter-collector"), INDEXED POSITIONALLY
      cardinality : per declared spec entries
      consumers   : none
      owner       : LLR-001.1
    - id          : spec_write_path
      value       : the .chk.json path written by the write action
      address     : query("#check-editor-panel write-action result")
      cardinality : 1
      consumers   : tests/test_tui_directionb.py
      owner       : LLR-009.1
```

> Parenting — `check_editor_panel`: rail screens live in the app shell alongside the workspace; `workspace_shell` is the shell boundary and not itself a COMPONENT (`docs/architecture.md` §11), so V12 balancing is untestable — declared per C-54's *could not be tested* form (batch-87 precedent, NOTICE).

```
COMPONENT: patch_editor_panel
  PARENT : workspace_shell
  SURFACE: Patch Editor (reworked, Inc-001)
  INPUTS : change_document: ChangeDocument|None ; folder_listing: list[str] ; loaded_image: mem_map|ranges|None
  OUTPUTS:
    - id          : entries_table_rows
      value       : the loaded change-set's entries (Kind/Address/Value/Status/Linkage)
      address     : query("#patch_doc_entries_table"), INDEXED POSITIONALLY
      cardinality : per loaded document entries
      consumers   : tests/test_tui_directionb.py
                    s19_app/tui/app.py
      owner       : LLR-004.1
    - id          : json_editor_region
      value       : the expanded JSON text-editing surface
      address     : query("#patch-editor-json-region")
      cardinality : 1
      consumers   : none
      owner       : LLR-003.1
    - id          : load_guard_popup
      value       : the dirty-guard warning with accept-loss/cancel
      address     : query("#patch-load-guard-popup")
      cardinality : 1
      consumers   : none
      owner       : LLR-005.2
```

> Parenting — `patch_editor_panel`: rail screens live in the app shell alongside the workspace; `workspace_shell` is the shell boundary and not itself a COMPONENT (`docs/architecture.md` §11), so V12 balancing is untestable — declared per C-54's *could not be tested* form (batch-87 precedent, NOTICE).

```
COMPONENT: flow_builder_panel
  PARENT : workspace_shell
  SURFACE: Flow Builder (fb_a redesign; address moves screens_directionb -> flow_screens, B2)
  INPUTS : template_listing: list[str] ; loaded_artifacts: list[str]
  OUTPUTS:
    - id          : canvas_blocks
      value       : placed blocks with in/out stubs and cable runs
      address     : query("#flow-builder-canvas .flow-block"), INDEXED POSITIONALLY
      cardinality : per placed blocks
      consumers   : s19_app/tui/app.py
      owner       : LLR-013.1
    - id          : template_save_name
      value       : the saved template's name
      address     : query("#flow-builder-save-result")
      cardinality : 1
      consumers   : none
      owner       : LLR-015.1
```

> Parenting — `flow_builder_panel`: rail screens live in the app shell alongside the workspace; `workspace_shell` is the shell boundary and not itself a COMPONENT (`docs/architecture.md` §11), so V12 balancing is untestable — declared per C-54's *could not be tested* form (batch-87 precedent, NOTICE).

```
COMPONENT: flow_execution_panel
  PARENT : workspace_shell
  SURFACE: Flow Execution (fx_a, Inc-003)
  INPUTS : template_listing: list[str] ; chain_input_files: list[str] ; run_mode: "sequential"|"parallel"
  OUTPUTS:
    - id          : run_lanes
      value       : per-chain lane (chain, pinned inputs, progress, status glyph)
      address     : query("#flow-execution-lanes .flow-lane"), INDEXED POSITIONALLY
      cardinality : per imported chains
      consumers   : s19_app/tui/app.py
      owner       : LLR-017.1
    - id          : run_log
      value       : per-chain status lines and inline failure lines
      address     : query("#flow-run-log")
      cardinality : 1
      consumers   : none
      owner       : LLR-020.1
    - id          : chain_set_save_result
      value       : the saved chain-set path
      address     : query("#flow-set-save-result")
      cardinality : 1
      consumers   : none
      owner       : LLR-021.1
```

> Parenting — `flow_execution_panel`: rail screens live in the app shell alongside the workspace; `workspace_shell` is the shell boundary and not itself a COMPONENT (`docs/architecture.md` §11), so V12 balancing is untestable — declared per C-54's *could not be tested* form (batch-87 precedent, NOTICE).

> `consumers : none` is written where no file reaches the address today: the new surfaces' addresses exist only after Phase 3, and the batch-scoped ATs that will drive them (AT-B94-01…24, provisional until Phase 3 per V-5) become their consumers through the traceability matrix rather than through invented file paths. `tests/test_tui_directionb.py` is declared where the guard host already consumes the surface family (rail/screen census).

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-B94-NN`):** validates the HLR/LLR mechanism (the HOW). Methods: `test`, `inspection`, `analysis`.
> - **Layer B — black-box / behavioral acceptance (`AT-B94-NN`):** validates the user story's outcome through the shipped surface (the WHAT). Method: `acceptance`.

- **Layer A (white-box):** every LLR above carries its validation method. `test (unit|integration|e2e)` arms run under the project's pytest strategy (runtime pinned per `pyproject.toml:73`; suite home `repo:tests/` per `state.json`). `inspection` arms name the file/diff to inspect. White-box ids are batch-scoped `TC-B94-NN` (provisional until Phase 3 per V-5; reconciled at Phase 4). Render-increment gates additionally run the FULL `tests/test_tui_directionb.py` guard host per C-34 (`engineering-rules.md:190`) — the rail/screen census, `from_markup` source scans, and chrome/footer censuses all live there.
- **Layer B (black-box):** every story owes ≥1 `AT-B94-NN` observing its outcome through the shipped surface — the rail+panel under a Textual pilot (`run_test` at 120×30 and 160×40; 80×24 where the acceptance says so), artifact-on-disk inspection for producer chains (`.chk.json` round-trip, A2B report markdown), and headless service runs where the surface is a service. ATs are provisional until Phase 3 (V-5); each names its boundary arm and its negative control.
- **`demo` (auxiliary):** not used as a gate method in this batch; the spike prototypes already discharged the perceptual design question (fb_a/fx_a/pe_b/ce_b approved) and their layouts are validated as rendered censuses, not demos.

### 5.2 Batch acceptance criteria

- 100% of LLRs (LLR-001.1 … LLR-021.2) carry a validation method, an executed verification, and a numeric pass threshold; 0 requirements without an assigned method.
- Every user story (US-001…US-005, US-007) has ≥1 passing `AT-B94-NN` black-box acceptance observing its outcome through the shipped surface, with boundary + negative evidence.
- Dual traceability holds both ways: every HLR traces to a READY US; every LLR to a parent HLR; every AT appears in its HLR's `Acceptance test(s)` field (derived by `V10`/`V21` into the Atlas).
- Every C-17 surface (HLR-011, HLR-016) passes its hostile-input AT and the `from_markup` source census.
- Every gate-keyed threshold is pre-executed: rail census 10→12 (`p1_probe_rail_census.txt`), A2L triage 1 023→0 WARNING with 1 023 INFO rows (`p1_probe_a2l_unrecognized.txt`), the apply-gate zero-write refusal (`p1_probe_chk_roundtrip.txt`), and the A2B report's emitted form (`p1_probe_diff_report_emitted.txt`).
- Render increments: 0 new snapshot failures over the inherited baseline (premise 3), with the full guard host run as the gate's own evidence.

---

## 6. Appendices (optional)

### 6.1 Extended glossary

See §1.3. Batch-specific terms (boxed budget, chain set, template) are defined there.

### 6.2 Relevant design decisions

| # | Decision | Recorded in |
|---|---|---|
| D-1 | US-004's seam is **view-level reclassification** in the Issues surface: the curated standard-keyword set is a view-owned constant (LLR-012.1); `s19_app/validation/rules.py` and `s19_app/tui/a2l.py` stay frozen — the §7 engine stability list is untouched. | HLR-012 rationale; LLR-012.1/.2 |
| D-2 | Rejected candidate for D-1: parser-level recognition by extending `RECOGNIZED_A2L_BLOCKS` (`rules.py:9-25`). It crosses the §7 freeze and changes the engine's stability story, so it is not picked. Re-open condition (per R12): if the view-level seam is found to falsify a real warning class — a genuinely malformed block read as benign — the seam moves parser-ward, the freeze crossing is stated in the increment packet, and the curated set lands in the engine with a ledger entry. | §6.3 open risk R-2 |
| D-3 | The rail key binding for the two new surfaces is **OPEN to PDR** (R11): this contract obliges the surfaces, their order, and the census; the digit key space `1`–`0` is exhausted at 10 (`app.py:1362-1371`), and Textual `Binding` mechanics are measured at PDR, not invented here. | HLR-002 rationale; §6.3 open risk R-1 |
| D-4 | C-12 output-then-consume for US-003: the acceptance chains Check Editor write → A2B Diff load of THAT file → report contents; a hand-written artifact fed to the consumer is not the acceptance surface. | HLR-010 |
| D-5 | C-17 sinks: TUI surfaces render via `safe_text` (`utils.py:44`); markdown reports via `markdown_safety.md_safe` / `md_code` per its mode truth table (paths in cells are FORBIDDEN raw — Mode B inside a code span only). | LLR-011.1, LLR-016.1 |
| D-6 | Reclassification, never suppression: triaged rows stay visible as INFO with justification (1 023 rows on the stand-in, none dropped); the executed `FROBNICATE` negative control pins the unknown-block WARNING. | HLR-012; `p1_probe_a2l_negative.txt` |

### 6.3 Open risks

- **R-1 — Rail key binding (OPEN, decision owner: PDR).** Two new surfaces, no free digit keys. Question recorded for PDR: which Textual `Binding` keys (or alternate chrome) carry Check Editor and Flow Execution, measured against Textual 8.x mechanics and the operator's muscle memory. Until decided, no acceptance in this contract depends on the specific keys — ATs drive rail entries by identity/position, and HLR-002's census asserts one binding per entry once PDR lands it.
- **R-2 — US-004 view-level seam.** Risk: a future standard block outside the curated set floods INFO rows instead of WARNING rows (operator blindness by classification). Mitigation: the curated set is a named, reviewable constant; additions are ledger entries; the D-2 re-open condition stands. Residual: accepted for this batch.
- **R-3 — Boxed-geometry transfer (C-29).** The spike measured full-screen prototypes (94×26 body @120×30); production boxes are 96×18 @120×30 (`p1-pilot-measurements.txt`). All layout acceptances key on the pilot ceilings; inner pane splits are flagged `assumed — verify in Phase 3` where the pilot did not measure them (LLR-003.1).
- **R-4 — B2 move census (Inc-002).** `FlowBuilderPanel`'s address change triggers the reader census (`docs/architecture.md:402`); known consumers today: `tests/test_flow_builder_render.py`, `tests/test_flow_crc_block.py`, `tests/test_flow_crc_ribbon.py`, the guard host, `app.py` routing. The census re-runs at the increment cut and lands in the packet.
- **R-5 — Parallel execution (LLR-019.2).** New concurrency in the execution service; failure isolation is pinned by AT-B94-21's error arm; the sequential default is the untouched-path regression pin.
- **Security scan (family C — trigger C6/C8, `security_required: true`):** run at this gate 2026-10-13 — `python -B devflow-scan-spec.py 01-requirements.md` → **exit 1, all 5 self-controls ok**; 123 921 bytes of sections 1–4 read. Fired flags: `hash`, `schema change`, `form`, `escape`, `expose`. Each flag's security question is answered here:
  - **`hash`** (LLR-008.2, "hash equality before/after"): no hashing of sensitive data is introduced — the phrase is an identity check of the loaded document across a Refresh. No crypto, no PII surface (tool processes local ECU firmware artifacts; triggers C1–C5/C7 not fired, PLAN trigger table).
  - **`schema change`** (HLR-009 rationale, "no schema change is needed"): the sentence states the negative — `.chk.json` reuses the existing v2 grammar (`kind="check"` already in `DOCUMENT_KINDS`, `io.py:120-123`; operator ruling, schema unchanged). No migration, no destructive data operation.
  - **`form`** (§3/§4 C-42 vocabulary, "emitted form"): denotes the producer's literal output shape for predicate discipline (C-42); no HTML/user-input form surfaces are introduced by this batch.
  - **`escape`** (LLR-011.1/LLR-016.1): escaping is the security control itself — file-derived text is rendered inert via `markdown_safety.md_safe`/`md_code` (reports) and `safe_text` (TUI), pinned by hostile-input AT-B94-13/AT-B94-18 and the `from_markup` source census.
  - **`expose`** (LLR-009.3, "shall expose no apply control"): states the absence of an apply path for check specs; no network exposure, no public endpoint — the app is a local TUI.
  - Verdict: no unresolved security question; the fired patterns are vocabulary collisions with the batch's own safety controls, each answered above and traced to its AT/LLR.

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
