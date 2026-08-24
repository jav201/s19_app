# The living human corpus, and the IFC ↔ requirements mirror — measured 2026-08-23

> Continues `DECISION-D-VII-2026-08-23.md` (hybrid: Atlas derived / canon authored) toward the
> operator's directive of 2026-08-23: *certainty about which artifact families form the living
> human-audit corpus; assurance that the IFC and the requirements are reflections of each other
> in content; only then regenerate (seed) the living documents for s19_app; then trial the new
> flow with one increment.*
>
> Every figure re-derives with `python tools/coherence_probe.py` (deterministic, verified
> byte-identical across two processes). If a figure disagrees, **the command is right.**

## 1 · The corpus — every family, measured, with its living home named

The operator listed: requirements, test cases, validation, validation evidence, checklists —
and asked what was missing. Measured against the tree:

| Family | Per-batch home (count) | Living home today | Verdict |
|---|---|---|---|
| **Requirements** | `01-requirements.md` (61) | `REQUIREMENTS.md` — 6,074 lines, hand-authored | **EXISTS**, behind by 287 ids (§3 C3) |
| **Test cases (AT/TC definitions)** | AT/TC sections of `01-requirements.md` + `tests/` code | **NONE** — `AT-TC-REGISTRY.jsonl` is machine-plane id-state, not human definitions | **MISSING — to seed** |
| **Validation + evidence** | `04-validation.md` (58) + `03-out-of-vcs-evidence.md` (2) | **NONE** | **MISSING — to seed** |
| **Traceability** ⚠ *the family the list missed* | `06-docs/traceability-matrix.md` (**57**) | **NONE** | **MISSING — to seed** |
| **Checklists** | none — per-batch *runs* are recorded in reviews/state | `~/.claude/templates/dev-flow/phase-checklists.md` — an instrument of the FLOW, not of the project | **NOT a project living doc** — the definitions are flow canon; the runs belong to the batch record. **Operator to confirm** |
| *Also found, unlisted:* functionality narrative | `06-docs/functionality.md` (**52**) | none | candidate |
| *Also found, unlisted:* executive summaries | `06-docs/executive-summary.md` (**55**) | none | candidate |
| *Also found, unlisted:* decisions | `decisions_log` in state.json (4) + `design/` D-* records + `BACKLOG-CODE.md` | partial (`BACKLOG-CODE.md`) | candidate |
| *Also found, unlisted:* architecture | `06-docs/architecture.md` (6) | `docs/ARCHITECTURE.md` — exists, but **D-IV**: declares no path prefixes, so V8 cannot check it | exists, unguarded |

## 2 · The mirror contract — four obligations, each now a number

**"IFC and requirements are basically reflections of each other (in content)"** decomposes into:

| # | Obligation | Direction | Measured today |
|---|---|---|---|
| **C1** | every IFC `owner` resolves to a declared requirement id AND appears in the living canon | IFC → REQ | 14/14 owner sites resolve in the **batch corpus** (0 broken) — and **14/14 are ABSENT from `REQUIREMENTS.md`**. The pilot's entire ownership chain is invisible to the human canon |
| **C2** | every LLR claiming a transform has a node/output owning it | REQ → IFC | batch-85: 7 LLR headings, 6 used as owner, **`LLR-85.4` never** — a question, not automatically a defect; the rule needs an exemption convention |
| **C3** | every batch-declared requirement id is reflected in the living canon | batches → REQ | **287 of 519 absent** (HLR 79 · LLR 200 · US 8). **This absence set IS the seeding backlog** |
| **C4** | every AT/TC the canon cites is alive in the registry | REQ → registry | 426 cited: 372 LIVE, 21 RETIRED — of which 15 sit correctly in the `## Retired ids` ledger and **6 are body citations = real staleness** (`AT-033a, AT-062a, AT-195, TC-324, TC-326, TC-496`); 33 not in registry (32 batch-scoped by design) |

Two gaps in today's *rules* that the shipped coherence rule must close:

- **OUTPUT `owner` is enforced by NOTHING.** V10 covers flow nodes only; V11 never reads
  `owner`. The 5 output-owner sites run unguarded — and one of them is the field that absorbed
  801 chars of prose (`ATLAS-FIELD-SET` §4 P1). Same fix family.
- **Scope rules are load-bearing.** C4 unscoped read 21; scoped by the `## Retired ids` ledger
  it reads 6. A coherence rule shipped without declared scopes re-creates handoff defect #7.

## 3 · Verdict — is the mirror standing?

**No, and now it is quantified.** The machine plane (IFC internal consistency: C1 corpus half,
V10/V11/V14) holds. The human plane is behind it: the living canon reflects neither the pilot's
ownership chain (C1: 14 sites) nor a third of batch history (C3: 287 ids), and carries 6 stale
test citations (C4). **The coherence rule (flow-side, rev42+) and the seeding pass
(project-side) are the two halves of the fix, and they are separable.**

## 4 · The seeding plan (Inc B) — NOT executed, awaiting operator approval

Proposed order, cheapest-reversible first, each with the probe as its acceptance oracle:

1. **`REQUIREMENTS.md` catch-up:** author the missing sections for the ids C3 names — starting
   with batch-85's 14 (closes C1 for the pilot) and the 6 stale citations (closes C4 body debt).
   Hand-authored per D-VII; the probe's C1/C3/C4 figures are the before/after oracle.
2. **Seed `TRACEABILITY.md`** (living) from the 57 per-batch matrices — bootstrap generation,
   then authored. Richest existing per-batch source.
3. **Seed `TEST-CASES.md`** (living AT/TC definitions, human plane) from batch AT/TC sections +
   registry join.
4. **Seed `VALIDATION.md`** (living validation ledger) from the 58 `04-validation.md`.
5. Flow-side: the coherence rule (C1–C4 mechanised, scoped, with arms) enters
   `devflow-validate.py` at rev42+ alongside `--atlas`/V20 — same revision or the next.

Open for the operator: (a) checklists — confirm they stay flow-side instruments; (b) do
functionality/executive-summary/decisions join the living corpus; (c) C2's exemption
convention; (d) seeding scope — all 287 or batch-85-first.

## 5 · Probe inventory

`tools/coherence_probe.py` — same contract as `atlas_probe.py`: imports the canon validator
(never a second parser), deterministic, DELETE when the coherence rule ships. Runtime ~1.5 s.
