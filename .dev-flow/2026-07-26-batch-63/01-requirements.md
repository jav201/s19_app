# batch-63 — Requirements

> **Status:** §2.6 (Phase-0 story refinement) COMPLETE. §3–§6 are derived in Phase 1.

---

## 2.6 — Story refinement (INVEST + Definition of Ready)

Source: `.dev-flow/BACKLOG.md` → TOP § "**(MAJOR, new — sec F4) the modifications and checklist
tables are UNBOUNDED, and the constant's comment used to claim otherwise**" — raised at the
batch-62 merge gate, carried at MAJOR.

Every acceptance criterion below is stated at the **behavior** level (the WHAT observed through the
shipped surface), never as a mechanism. Each becomes an `AT-NNN` in Phase 1.

---

### US-B63-1 — the modifications table is bounded, and any cut is stated

> **As** an engineer reading a project report for an image with a very large number of applied
> changes, **I want** the per-variant Modifications table to stop at a stated limit and say
> exactly how many rows it withheld, **so that** the report stays a usable, openable evidentiary
> document instead of a multi-megabyte file that silently claims a size cap it broke.

**Why it matters.** Measured: 20 000 entries → 20 000 rows and a 3.29 MB document, 1.57× the
declared 2 MiB budget, while the document itself prints `report size cap: 2097152 bytes`
(`00-measurements.md` M-1, M-2).

**Out of scope:** changing what the table renders per row; the variant-count axis (M-5);
host-path redaction (batch-62 D-11, withdrawn).

**Acceptance (black-box, through `generate_project_report` → the written `.md` re-read from disk):**
- **AC-1** — Given a variant whose change summaries carry provably **more** entries than the cap,
  when a report is generated, then the Modifications table contains exactly the cap's number of
  data rows.
- **AC-2** — …and the document states the cut with the **exact** withheld count and the cap that
  caused it, in the shipped `> TRUNCATED: N of M …` form, plus its truncation-appendix entry.
  A silent cut fails this story.
- **AC-3** — Given a variant **at or under** the cap, the document is **byte-identical** to today's
  output. The bound must not disturb any report that was never pathological.

| INVEST | verdict |
|---|---|
| Independent | ✔ separable from US-B63-2 (different emitter, different section) |
| Negotiable | ✔ cap shape/value open — ruled in Phase 1 **by execution** (PLAN D-4) |
| Valuable | ✔ the document currently asserts a bound it violates |
| Estimable | ✔ the pattern is already shipped twice in this module (`REPORT_MAX_REGIONS_PER_VARIANT`, `MAX_REPORT_ISSUES_PER_VARIANT`) |
| Small | ✔ one emitter + its constant + tests |
| Testable | ✔ black-box: generate → re-read from disk → count rows, assert marker text |

**Status: `READY`.**

---

### US-B63-2 — the checklist table is bounded, and any cut is stated

> **As** the same engineer, **I want** the per-variant Checklist table bounded on the same terms,
> **so that** a check run over a very large change document cannot blow up the report either.

**Why it matters.** Measured identically — `chk_rows == N` at every N (M-1). The checklist is the
*larger* risk of the two: `_checklist_lines` loops over `check.entries` **per check result**, so a
variant with several check runs multiplies the row count again.

**Acceptance:** AC-1 / AC-2 / AC-3 as above, against the Checklist section.
Additionally:
- **AC-4** — the bound holds **per variant across multiple check results**, not per individual
  check run. Two check runs of ¾-cap each shall not yield 1.5× the cap in one document.
  *(This is the story's real trap and the reason it is not merely a copy of US-B63-1.)*

| INVEST | verdict |
|---|---|
| Independent | ✔ |
| Negotiable | ✔ same open cap ruling |
| Valuable | ✔ strictly larger blow-up surface than US-B63-1 |
| Estimable | ✔ |
| Small | ✔ |
| Testable | ✔ black-box, incl. the multi-check fixture for AC-4 |

**Status: `READY`.**

---

### Considered and NOT taken into this batch

| item | classification | reason |
|---|---|---|
| Bound the **variant-count** axis | `OUT` → BACKLOG carry | No `MAX_VARIANTS` exists (M-5). Affects every per-variant section, not these tables. Fixing it here is scope creep; recording it is mandatory. |
| Make the byte-cap marker's claim true **document-wide** | `OUT` → folded into the Phase-1 ruling + BACKLOG | Once both tables are capped, a *single-variant* document should sit well inside 2 MiB. **`assumed` — to be executed in Phase 1**; if the measurement refutes it, this returns as a story rather than being quietly dropped. |
| D-11 host-path redaction redesign | `OUT` | Withdrawn at the batch-62 merge gate after 3 failed revisions; needs its own design pass. Untouched here. |
| `diff_report_service._md_cell` promotion (RR-4 / D-8) | `OUT` | Unrelated surface, own goldens. |

---

### Phase-0 gate — exit-criteria assessment

| axis | assessment |
|---|---|
| **Coverage** | MET — both stories carry behavior-level acceptance criteria observable through the shipped surface; the excluded items are each classified with a reason and a destination. |
| **Certainty** | MET — the defect is measured RED on the current tree by an executed probe over the real composer (M-1…M-4), not cited from the backlog. Two backlog claims were corrected against disk in the process (the `_ByteBudget` framing, M-4; and the per-row cost regime, M-3). |
| **Evidence** | MET — every claim above cites a probe transcript section or a `file:line`. |

**No axis is unmet → `approve`.** Both stories proceed to Phase 1.
