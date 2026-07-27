# batch-63 — PLAN (living compendium)

> **Objective:** bound the two unbounded per-variant tables in `report_service`
> — `_modifications_lines` and `_checklist_lines` — closing the **F4 (MAJOR)**
> carry raised at the batch-62 merge gate.

**Where we are:** Phase 1 CLOSED → **Phase 2 IN FLIGHT** (three independent reviewers over the spec).

**Normative pair (derived jointly, verified by execution):**
`REPORT_CELL_BYTES = 64` · `MAX_REPORT_*_ROWS_PER_VARIANT = 500` (both tables).
Guaranteed single-variant bound **78.3 %** of budget; **measured end-to-end 61.0 %**; drift set **∅**
(headroom 3.76× over the real-suite maximum of 133); 0 of 2 000 byte cells non-hex.

**Scope — OPERATOR-APPROVED at the Phase-1 gate (2026-07-26):** all three — the two row caps **plus
A-1** (byte-run cell bound) **plus A-2** (truncation-appendix repair). Approved after being told the
scope had roughly doubled versus Phase 0 and why: without A-1 a single row can weigh 3× the whole
document budget and the row cap never fires; without A-2 the cut is declared into an appendix that
is not emitted.

---

## 1. Authorization (per-batch — NEVER inherited)

| item | value |
|---|---|
| date | 2026-07-26 |
| operator phrasing | "Autónomo + self-merge" (AskUserQuestion, backlog-review session) |
| autonomy | **AUTONOMOUS end-to-end**; self-approve each gate with a named Coverage/Certainty/Evidence axis; packets presented in-conversation |
| merge authority | **GRANTED** — gated on a final independent `qa-reviewer` **and** `security-reviewer` pass, 0-HIGH over the whole diff vs `main`, plus green CI. A HIGH finding blocks and returns to the operator |
| decision recording | assumed GRANTED under the standing pattern (batch-60/61/62). Every un-asked decision lands in this PLAN's decision log + `state.json.decisions_log` + `05-postmortem.md`, and rides to the vault at sync |

## 2. RC-1 — base currency gate

**PASS @ `031ca8d`** (2026-07-26). `git fetch origin`; `origin/main` tip = `031ca8d`
(batch-62 vault-sync record #138); working merge-base == that tip, verified. Branch
`claude/batch-63-report-table-caps` cut off it. Tree clean at cut.

**Already-shipped check:** the two emitters are **live and uncapped on `origin/main`** —
`_modifications_lines` (`report_service.py:985`) and `_checklist_lines`
(`report_service.py:1163`) each run `for entry in …:` with no bound. `REPORT_MAX_REGIONS_PER_VARIANT`
is consumed by `_hexdump_section` ONLY; `MAX_REPORT_ISSUES_PER_VARIANT` caps
`_declaration_error_lines` ONLY. Nothing on `main` closes this. The carry is genuinely open.

## 3. The defect — MEASURED, not cited (C-35 / C-39)

Phase-0 execution probe over the real composer (`generate_project_report`), realistic
`VariantExecutionResult` fixtures, reports written to disk and re-read.

**Finding 1 — both tables are strictly unbounded.** N entries in → exactly N rows out, linear,
both tables, every N tested:

| N entries | modification rows | checklist rows | report size | vs 2 MiB budget |
|---:|---:|---:|---:|---|
| 200 | 200 | 200 | 51 876 B | ok |
| 1 000 | 1 000 | 1 000 | 182 286 B | ok |
| 5 000 | 5 000 | 5 000 | 838 288 B | ok |
| 20 000 | 20 000 | 20 000 | **3 291 816 B** | **1.57× OVER** |

**Finding 2 — the truncation marker asserts a bound the document violates.** At N=20 000 the
document emits `> TRUNCATED: … (report size cap: 2097152 bytes).` **while being 3 291 816 bytes.**
The marker fires because hexdump blocks were omitted; the tables that actually blew the budget
were never consulted. In an evidentiary document, a truncation notice that fires while the stated
bound is violated is worse than no bound at all.

**Finding 3 — per-row cost varies 3.7×, so a row cap cannot bound bytes.**

| regime | symbol | cost / entry | N where the budget blows |
|---|---|---:|---:|
| realistic | 63-char A2L name | 163.6 B | ~12 700 |
| pathological | 512 chars (the `REPORT_CELL_CHARS` ceiling) | 610.9 B | ~3 400 |

*Design consequence:* a fixed row cap is **predictable and per-variant fair** but does not bound
bytes; the `_ByteBudget` bounds bytes but is **not fair across variants** (variant 1 would eat the
whole budget). This is the batch's central design question — ruled in Phase 1 **by measurement**,
per C-39, not by taste.

**Mechanism note (corrects the backlog's framing).** `emit()` **does** charge these tables to
`_ByteBudget` — `budget.consume(...)` runs on every section. What is missing is the **check**:
`budget.fits(...)` is consulted *only* inside `_hexdump_section`. So the budget is accounted and
never enforced on the tables; they grow without limit and additionally starve the hexdumps.

**Probe transcript:** `.dev-flow/2026-07-26-batch-63/00-measurements.md`.

**Probe self-correction (recorded, per the project's recurring lesson).** The first probe reported
`chk_rows = -1` — the checklist heading is emitted as `` #### Checklist: `chk.json` `` (Mode B code
span), not the bare form the predicate searched for. The predicate was wrong, not the artifact.
Same family as the batch-61 NBSP-entity false-failure and the batch-62 `"](" not in note` case:
**assert against the emitted encoding.** Caught here by the probe returning an impossible value
rather than a plausible one.

## 4. Scope

**IN**
- **US-B63-1** — the per-variant **modifications** table is bounded, and any cut is stated in the document.
- **US-B63-2** — the per-variant **checklist** table is bounded, and any cut is stated in the document.

**OUT (recorded as carries, not silently dropped)**
- **The variant axis is separately unbounded.** No `MAX_VARIANTS` exists anywhere in `s19_app/`
  (grepped). With per-variant caps in place, document size still scales with variant count — as
  does every other per-variant section (inventory, overview, entropy). Pre-existing, a different
  axis, and widening into it would be scope creep. → **new BACKLOG carry.**
  *Claim to verify in Phase 1 (`assumed`):* with the tables capped, a **single-variant** document
  sits well inside 2 MiB in both regimes.
- **D-11 host-path redaction redesign** — withdrawn at the batch-62 merge gate; untouched here.
- Everything else in the batch-62 carry list.

## 5. Roadmap

| phase | status | note |
|---|---|---|
| 0 — intake / DoR | **CLOSED** (self-approved) | 2 stories READY, defect measured RED on the current tree |
| 1 — requirements | next | cap shape + value ruled **by execution**; §3 acceptance blocks; AT ids |
| 2 — cross-review | pending | architect + qa + security in parallel |
| 3 — implementation | pending | ≤5 files/increment; each AT shown RED pre-fix |
| 4 — validation | pending | orchestrator owns the gate suite run (C-25) |
| 5 — post-mortem | pending | control candidates → operator AskUserQuestion, never self-encoded |
| 6 — docs + PR + merge | pending | 2 independent reviewers 0-HIGH → self-merge → `/dev-flow-sync` |

## 6. Risks / watch-items

1. **A cap in an evidentiary document deletes evidence.** The whole point of these tables is
   correlating symbols to addresses. Any cut must be **stated in the document** with the exact
   omitted count (the shipped `> TRUNCATED: N of M …` + truncation-appendix pattern), never silent.
2. **Byte-identity goldens (C-24).** The composer feeds report goldens. A cap that changes output
   for *existing* fixtures would drift them. Pre-measure the drift set (C-39) — do not predict it.
   Existing fixtures are far under any plausible cap, so the expected drift is **zero**; that
   expectation gets executed, not asserted.
3. **`test_measure_report_caps_on_large_s19`** already asserts `size <= REPORT_MAX_TOTAL_BYTES`
   when the byte-cap marker did not fire. Confirm the new behavior keeps it green.
4. **C-31 on the fixtures.** A cap test whose fixture sits under the cap proves nothing. Every cap
   AT drives a fixture provably **over** the cap, with the count stated in its docstring
   (the batch-62 lesson, where a budget test sat 2.8× under its own limit).
5. **Reviewer-tree hygiene (batch-62 process finding).** Run counterfactuals in a `git archive`
   export, never in a worktree a reviewer is reading.

## 7. Conventions honored

`≤5 files/increment` · docstring section order · type hints · `AT-NNN` black-box + `TC-NNN`
white-box dual traceability · `shall` only inside HLR/LLR · frozen-file **dual** guard
(C-27: source *and* test guards) · REQUIREMENTS.md `R-*` update · BACKLOG reconciliation as a
mandatory close step.

## 8. Decision log

| # | phase | decision | why |
|---|---|---|---|
| D-1 | 0 | **Route = full `/dev-flow`** (not `/fast-dev-flow`) | Resource bound in an evidentiary document with derivable requirements and real black-box ATs. Same module and risk class where batch-62's independent reviewers found 3 production defects that two prior gates had cleared. |
| D-2 | 0 | **Both stories READY**; defect measured RED before any spec text | C-35/C-39: the probe ran the real composer over real fixtures. Nothing here is cited from the backlog. |
| D-3 | 0 | **The variant axis is OUT of scope**, recorded as a carry | Pre-existing, different axis, affects every per-variant section. Fixing it here is scope creep; dropping it silently is a carry-over violation. |
| D-4 | 0 | **Cap shape deferred to Phase 1, to be ruled by execution** | The 3.7× per-row spread means neither a row cap nor the byte budget is obviously right. Deciding it now would be taste; C-39 requires the measurement first. |
| D-5 | 0 | Decision-recording ack **assumed granted** rather than re-asked | Standing pattern across batch-60/61/62; the flow's own default is to record. Flagged here so the assumption is visible and correctable. |
| D-6 | 1 | **Subagent gates confirmed with the operator** before dispatching | This session carries an instruction not to invoke subagents unasked, while `/dev-flow` delegates its gates. The two readings produce materially different assurance: batch-62's independent reviewers found 3 production defects that two prior gates had cleared. Operator ruled "con subagentes, como siempre" — so author↔reviewer independence is preserved. |
| D-7 | 1 | **A-1 ACCEPTED into scope** — bound the byte-run cell length | The architect refuted my ruling's *sufficiency* with a measurement: `_format_bytes` (`report_service.py:430`) bounds none of its 4 cells, so one entry at `MF_RUN_LENGTH_CEILING = 1 048 576` (`changes/io.py:232`) emits a **6 291 604 B row = 3.00× the whole budget**, and at 10 000-byte runs **35 rows exhaust the budget before a 200-row cap fires**. Shipping the row cap alone would re-commit M-2 — a bound that does not bound. My Phase-0 probe used 2-byte runs, so the axis was invisible: **C-31 against my own probe, the input set was blind.** |
| D-8 | 1 | **A-2 ACCEPTED into scope**, minimal | `_declaration_error_lines` emits its cap marker but registers no truncation-appendix note, so a reader finding the appendix absent concludes nothing was cut. My AC-2 cited that as the precedent to mirror. The appendix cannot stay half-trustworthy while AC-2 depends on it. |
| D-9 | 1 | **Cap value re-derived** after obtaining a field datum from the operator | Both agents flagged that `examples/` holds no change/check document at all, so the cap had no field anchor. Operator: a real campaign is **"tens to ~200 entries"**. CAP=200 therefore sits at the TOP of the legitimate range and would cut a real 205-entry campaign — violating the module's own `REPORT_CELL_CHARS = 512` discipline ("≥ the largest legitimate field value"), which is the architect's own argument turning back on the value we had both settled on. Re-derivation executed, not estimated. |
| D-11 | 1 | **A-2 upgraded from consistency fix to correctness fix** | qa reproduced it one degree worse than the architect reported: when only the declaration-error cap fires, the `## Truncation appendix` **heading is absent from the document entirely** — the appendix is emitted `if notes:` and `notes` is fed *exclusively* by `_hexdump_section`. A reader checking for cuts finds no appendix and concludes none happened. |
| D-12 | 1 | **The two constants are derived as a PAIR, not in sequence** | qa measured that they are not independent: post-A-1 at `CELL_BYTES=256`, `CAP=500` → 0.873× budget but `CAP=1000` → **1.744× with ONE variant**. So the single-variant constraint ceilings the row cap at ≈570, while the field datum floors it at ~200 + headroom — a narrow window that *widens* at a smaller `CELL_BYTES`. Choosing them independently would have produced an infeasible pair. |
| D-13 | 1 | **Orchestrator misattribution corrected in the open** | I credited the architect's 1147-call `_format_bytes` census to qa when relaying A-1. qa caught it; its own census is 1 196 calls over a *named* file set. Recorded rather than quietly fixed, because the whole point of the finding is that a bound must rest on a census whose scope someone can state. |
| D-14 | 1 | Increment order: **A-2 first** (pending the architect's dependency check) | qa's argument: the other two amendments register appendix notes *through* the machinery A-2 repairs, so fixing it first avoids building on a surface known to be broken. |
| D-15 | 1 | **Truncation indicator goes OUTSIDE the byte cell** (architect option (b)) | Not a test-amendment question. `test_report_field_census.py:836` is the pin that makes **R-TUI-077's escaping exclusion sound** — `_format_bytes` is excluded from escaping because its alphabet is *closed*, i.e. inert by construction. An in-cell indicator destroys that proof, so a locked requirement would need a brand-new safety argument where today it needs none. Option (b) costs nothing: 0 of 1 600 byte cells non-hex end-to-end, the batch-62 pin stays green, no locked requirement is amended, and the `>` vs `>=` boundary trap dissolves. The `Length` column already carries the true run length, so nothing goes silent. |
| D-16 | 1 | **The tables are an INDEX; `_hexdump_section` is the EVIDENCE** — made load-bearing | This reframing (mine, adopted and hardened by the architect) is what redefines "legitimate value" for the byte bound: not the largest schema-legal run (1 048 576) but the largest run a reader consumes *inline in a table row* — which the field puts at 1–4 bytes for 1 192 of 1 193 calls. Without it, the bound has no principled anchor. |
| D-17 | 1 | **Orchestrator REJECTED the architect's headline pair** — `CAP=400` violates its own derived floor of 401 | Stated as verified in four places including a ✓ evidence-checklist row. Provenance visible in the artifact: `CAP=400` was carried "unchanged from §11.4" while the floor was derived later in §12, so an **inherited** number met a **newly derived** constraint by assertion instead of arithmetic — C-39's exact failure mode, committed inside the artifact that encodes C-39's lesson. Returned for re-derivation with a full literal sweep, not a patch. |
| D-18 | 1 | Architect's tail-cut caveat **accepted and will ship in the docstring**, unsoftened | `CAP` stays ~250× below `MF_ENTRY_COUNT_CEILING = 100 000`, so it *can* cut legitimate data at the tail. Unavoidable — even the cheapest row makes 100 000 rows unrenderable inside 2 MiB. Stated in the constant, not hidden; the honest answer for a 5 000-entry campaign is a full-fidelity sidecar, not a bigger cap → BACKLOG carry. |
| D-10 | 1 | Both tables' constants ruled **separately**, not shared | Measured: modifications 139→590 B/row (4.24× spread); checklist a flat **54 B/row** because its only text cell is the closed `CHECK_RESULT_DOMAIN`. The "3.7× spread" in M-3 belongs to the modifications table alone — attributing it to both is precisely what made one shared constant look reasonable. |

## 9. Test ledger

**Base MEASURED on this tree, from ONE complete run, evidence read from that run's own output
(C-19) — the inherited batch-62 figure is deliberately NOT used.**

```
$ python -m pytest -q -m "not slow"          # branch claude/batch-63-report-table-caps @ 031ca8d
2192 passed, 2 skipped, 21 deselected, 3 xfailed in 1670.64s (0:27:50)
29 snapshots passed
exit code 0
```

| quantity | value |
|---|---|
| **base** | **2192 passed** (`-m "not slow"`; 21 deselected = the `slow` marker) |
| snapshots | 29 passed — batch-61's canonical regen still holds |
| wall time | 27:50 (matters: the harness tool cap is 10 min, so this MUST run backgrounded — C-19/C-25) |

*Note on the inherited number:* batch-62's close recorded 2213/2218 without the marker selection
stated. Rather than reconcile two figures whose selections differ, this batch keys its ledger to
its own measured run, per C-19.

Ledger `post = base − D + A` opens at Phase 3. qa reserves **A = 24** (12 AT + 12 TC), `D = 0`
→ projected `post = 2216`.
