# batch-63 — Phase 2 cross-review (consolidated)

> **GATE OUTCOME: `iterate-to-refine` → Phase 1. All three lanes BLOCKED — 11 blockers total.**
> Lane artifacts: `02-review-architect.md` · `02-review-qa.md` · `02-review-security.md`.
> Three independent reviewers, none of whom authored the spec.

---

## BLUF

**The reviewed design does not achieve the batch's own thesis, and all three lanes proved it
independently by execution.** The batch exists because the report *asserts a size bound it
violates*. The reviewed design — per-cell and per-row caps — **still asserted a false bound**:
simulated post-fix at **2 variants** the document measured **2 918 330 B = 1.39× budget with the
size-cap marker FIRING**. Two variants is the ordinary case; the module exists to compare variants.

Root cause of the design failure: **capping cells is whack-a-mole against an unbounded document.**
Every review round discovered a new unbounded axis. Six are now known:

| # | axis | found by | measured |
|---|---|---|---|
| 1 | modification rows | Phase-0 probe | 20 000 → 20 000 rows |
| 2 | checklist rows | Phase-0 probe | same, and multiplies per check run |
| 3 | byte-run cells | architect (A-1) | 1 row = **6 293 988 B = 3.00× budget** |
| 4 | **address cells** | security (F3) | `_parse_address` = `^0x[0-9A-Fa-f]+$`, **no digit limit** → 1 row = 1 000 055 B, both caps inert |
| 5 | **addendum hit lines** | architect (B-5) | 1 line per entry **per declared region**, downstream of the pre-cap population → **3 813 695 B = 1.82× budget** with both caps active |
| 6 | variant count | Phase-0 (M-5) | no `MAX_VARIANTS` exists |

**Operator ruling (2026-07-26): PIVOT.** Enforce the document byte budget that already exists,
with per-variant fair share, instead of capping cells and rows. → REV 5.

---

## Blockers by lane

### architect — 5 blockers
- **B-5** the "guaranteed single-variant bound = 78.3 %" **is not a bound.** The 195 487 B remainder
  is modelled as a constant, but `_addendum_lines` (`report_service.py:1467`) emits one hit line per
  entry per declared region and is downstream of the population the batch caps. At 20 000 entries
  the addendum alone is 724 698 B = **3.7× the entire claimed remainder**; with 8 regions,
  5 797 343 B = 276 % of budget.
- **B-4** the **"index vs evidence" reframing is FALSE for 3 of the 4 bounded cells**, measured by
  parsing the hexdump back into an address→byte map: `applied.after_bytes` 200/200 recoverable ·
  `applied.before_bytes` **0/200** (the map is post-change) · `skipped.after_bytes` **0**
  (`_applied_regions` filters to `applied`) · `check.expected_bytes` **0** (check regions are never
  dumped). LLR-091.3 obliged the code to *print* "full bytes in the Memory regions section" — a
  false statement, in the batch whose thesis is that documents must not assert what they don't honour.
- **B-1 / B-2 / B-3** §3 mandates the mechanism R-TUI-091(a) forbids; the two Phase-1 artifacts
  specify **different, partly unsatisfiable systems**; `R-TUI-079/080/081` are **live batch-48 ids**;
  no qa TC names an architect LLR, so the `US→HLR→LLR→TC` chain marked ✓ does not close.

### qa — 5 blockers
- **B-1** the at-cap boundary is a **phantom**: the matrix credited it to AT-171, whose text asserts a
  document *size* and nothing else. All 24 nodes walked — **none has a fixture at `M == CAP`**. The
  mutation `>=` emits a spurious `> TRUNCATED: 0 of 500` and **survives the entire catalog**.
- **B-5** independently corroborated the evidence-deletion finding at source.
- **B-3 / B-4** the catalog validates the **withdrawn** in-cell indicator, so a *correct* REV-4
  implementation fails AT-172; TC-406 pins `CELL_BYTES >= 256` against a normative 64.
- **M-5** the only at-cap node is `@pytest.mark.slow` while `tui-ci.yml:47` runs `-m "not slow"` on
  pull requests — **the merge gate would never execute it.**

### security — 1 blocker, 5 majors, 3 minors
- **B-1** REV 4 still mandates the withdrawn in-cell indicator in **four** places while §4 is
  normative-by-reference — an implementer resolving toward §4 breaks R-TUI-077's
  inertness-by-construction premise.
- **F3** the unbounded address cell (axis 4 above).
- **F4** appendix forgery gets *worse*: R-TUI-092 promotes the appendix to the authoritative
  "nothing was cut" oracle, and a file-derived `variant_id` can forge a second plausible truncation
  statement in the rendered view (`\.` renders as `.`). The complementary direction is safe — a
  hostile cell cannot forge an in-section marker (verified).
- **F5** enforcement is itself a DoS if read naively: format-then-slice measured **155.91 ms and a
  3 MB transient per cell** vs 0.02 ms / 192 B for `islice` — ~312 s CPU for one at-cap variant,
  **with identical output**, so no output assertion can distinguish the two.
- **F9** first-N-in-document-order truncation is **attacker-selectable**: failures can be pushed past
  the cut while N benign rows render.

**What survived adversarial re-derivation:** the D-15 option-(b) ruling (indicator outside the cell,
preserving R-TUI-077's soundness) — called "the strongest passage in the artifact" by the architect
lane and verified end-to-end across 19 input classes by security. It carries into REV 5.

---

## Convergence, and what it says about the gate

Two or three lanes independently reached the same finding **three** times: the evidence-deletion
refutation (architect B-4 + qa B-5), the withdrawn-indicator contradiction (architect B-1 +
security B-1), and the id/traceability collapse (architect B-2/B-3 + qa B-2/B-3/B-4). Independent
convergence is the signal that these are real defects rather than reviewer taste.

**None of the six unbounded axes was in the original backlog carry**, which described only
"one row per entry with no cap". The batch's measured value so far is the discovery that the
document was unbounded on six axes and lied about it on one.

## Process findings recorded against the reviewers and the orchestrator

- **Orchestrator (me):** the "index vs evidence" reframing was mine, I pushed it, the Phase-1
  architect made it load-bearing, and it is false for 3 of 4 cells. It was asserted from the
  *shape* of the code and never executed. Had qa and the architect not independently gone to
  measure it, it would have shipped as a printed false statement.
- **Architect lane:** its first evidence probe used *ascending* byte runs and false-positived on all
  four cells; replaced with random runs plus a parsed hexdump reconstruction, and the false result
  was **recorded rather than discarded**.
- **Fifth occurrence this batch of the same family** (assert the emitted encoding / the predicate
  must test what its label claims): the Phase-0 `chk_rows = -1` probe · the `CAP=400 interior?`
  column that computed only the ceiling · the ascending-runs probe · plus the two inherited from
  batch-61/62. This is now the strongest-evidenced un-encoded control candidate in the project.
