# batch-64 — PLAN (living compendium)

> Updated at every gate and significant checkpoint. The operator reads THIS, not `state.json`.

## Where we are

**Phase 0 — APPROVED 2026-07-27** (2 stories `READY`, 0 `REFINE`/`SPIKE`/`OUT`). **Phase 1 IN PROGRESS**:
architect + qa lanes dispatched in parallel. No code touched yet.

### Stories through Definition of Ready

| id | story | status |
|---|---|---|
| **US-B64-1** | As an operator generating a project report over a manifest with declared regions, I get the report without the tool consuming memory proportional to (regions × variants × entries), so a large or hostile change document cannot exhaust my machine. | `READY` |
| **US-B64-2** | As an operator reading an evidentiary report, when the addendum was truncated I can see WHICH hit classes (and which variants) were cut, so I can distinguish "there is no evidence" from "the evidence did not fit". | `READY` |

US-B64-2 is the story batch-63 never wrote, and it is the reason that batch's security gate did not
close: the real control is **the notice naming what was cut**, not a predicate asserting that each
class is merely represented.

### Evaluability problem found and resolved at Phase 0 (enters Phase 1 as a proposal, not a fact)

US-B64-1's outcome is memory, which is not observable in the report file. Worse, the entries feeding
`_addendum_lines` are the **same** `summary.entries` that feed `_modifications_lines`, so growing `E`
grows both and a whole-report peak measurement is dominated by the unbounded tables (988 B/entry) —
which is exactly security finding **F2**, the one that returned D1.

**Proposed isolation:** measure the addendum's **MARGINAL** cost by difference — identical fixture
with `options.declared_regions` non-empty vs empty — and assert the delta stops tracking `V×E`. This
drives the real shipped surface, isolates D1 without touching the tables, and permits a bound
**without claiming DoS closure**. Flagged to both Phase-1 lanes as a proposal to validate or replace.

## Objective

Bound the **producer** in `_addendum_lines` (`s19_app/tui/services/report_service.py:1514`) so the
declared-region addendum stops consuming resident memory proportional to `R × V × E`.

This is backlog item **D1**, the top of `.dev-flow/BACKLOG-CODE.md` (Lane A). It was specced during
batch-63, **BLOCKED at that batch's Phase-2 re-gate**, and RETURNED to the backlog; batch-63 shipped
D3 only. batch-64 starts from that record rather than re-deriving it.

**Scope is D1 ONLY.** Explicitly OUT: OB-4/F4 (the two unbounded tables `_modifications_lines` /
`_checklist_lines`) and D2 (the schema-legal address `ValueError`). Both stay as carries in
`BACKLOG-CODE.md`. batch-63 blocked by over-scoping; this batch does not repeat it.

## The defect, in one paragraph

`_addendum_lines` builds a local `hits: List[str]` (`:1560`) and appends one **fully formatted**
string — each paying an `md_safe` call — per matching *(region × variant × entry/issue)* at `:1565`,
`:1571` and `:1579`, extending `lines` only at `:1584`. The entire cost is therefore paid **before any
output exists**, so every byte-budget or row-cap design is structurally blind to it. Measured on
`031ca8d`: **87–94 B resident per hit**, product law confirmed independently on all three axes
(R ×1.91/×1.95 · V ×2.01/×1.98 · E ×2.01/×1.98). Most likely cause of the host RAM exhaustion that
killed the operator's machine mid-batch-63.

## RC-1 (base currency) — verified 2026-07-27

| check | result |
|---|---|
| `git fetch origin` | done |
| `origin/main` tip | `082ada9` |
| `HEAD` | `082ada9` |
| `merge-base HEAD origin/main` | `082ada9` — equal, no rebase needed |
| working tree | clean |
| branch | `claude/batch-64-addendum-producer-bound` |
| frozen-source guard | `tests/test_engine_unchanged.py` → 1 passed |
| already-shipped check | `grep "R-TUI-095\|MAX_ADDENDUM_HITS_PER_REGION" REQUIREMENTS.md s19_app/` → 0 hits; D1 is **not** shipped |

## Standing authorization (per-batch, NEVER inherited)

- **Autonomy + merge:** AUTONOMOUS end-to-end **+ SELF-MERGE**, granted by the operator at this
  kickoff (2026-07-27), operator's phrasing: *"Autónomo + self-merge"*. Merge remains gated on the
  final independent PR-level `qa-reviewer` pass over the whole diff vs `main`; a HIGH finding blocks
  the merge and returns to the operator.
- **Decision recording:** every decision taken instead of asking is logged in the Decision log below,
  in `state.json.decisions_log`, and in `05-postmortem.md`, and carried to the vault at sync.

## Identifier allocation — EXECUTED census, not estimated

The project has no AT/TC registry (backlog OB-2), so "next free id" is subset-dependent. Measured
across all three subsets on this tree:

| family | `REQUIREMENTS.md` | `tests/` | `.dev-flow/` | union max | allocated to batch-64 |
|---|---|---|---|---|---|
| `AT`    | max 193 | max 193 | max 193 | **193** | **AT-194+** |
| `TC`    | max 345 | max 477 | max 479 † | **479** | **TC-480+** |
| `R-TUI` | max 97 | max 97 | max 97 | **97** | **R-TUI-098** |
| `HLR`   | max 102 | max 102 | max 102 | **102** | **HLR-103** |

† A raw scan reports `TC-1728`, which is a stray reference in
`.dev-flow/2026-07-08-batch-29/_qa-acceptance-validation.md:252`, not an allocation. Excluded after
inspection; the true `.dev-flow` max is `TC-479`. **The TC spread across subsets is 1383 raw / 134
real — that is OB-2 measured again, and it is why this table is executed rather than assumed.**

**RETIRED, explicitly (P-7 — consolidation preserves the union or names what it drops):** batch-63's
never-implemented D1 identifiers `AT-164..167`, `TC-440..454`, `R-TUI-095`, `HLR-100`, `LLR-100.1..4`
are **retired, not reused**. They collide with REV-5 lane A's claim on `AT-164..178` and reusing them
would bind two different observables to one id. Their *content* is carried forward; only the numbers
are dropped.

## Inherited findings — designed for, NOT re-discovered

Paid for at batch-63's Phase-2 re-gate. Any design that re-opens one of these is wrong by construction.

1. **A per-REGION cap is attacker-selectable across classes.** Producer order puts the
   100 %-attacker-supplied modification class first → 200 crafted entries evict **0 of 5** validation
   issues (executed). KILLED.
2. **A per-HIT-CLASS cap fixes the cross-class case (5/5 survive) but NOT intra-class nor
   cross-variant.** 200 attacker-authored `CHG-ADDRESS-SYNTAX` warnings still evict the
   ERROR-severity `CHG-COLLISION` (**0/1**); one flooded variant suppresses two other variants'
   collisions (**{'v1':0,'v2':0,'v3':0}**, expected 0/1/1). All three hit classes are document-derived
   (`changes/apply.py:363`, `changes/check.py:399`), so the attacker owns every class's cardinality.
   **The real control is the NOTICE NAMING THE CUT CLASSES (and variants), not a predicate asserting
   each class is merely represented.**
3. **`AT-165` looked right and was not.** *"Every producing hit-class is represented"* was GREEN in all
   three attacks. It tests the concatenation **shape**, not the evidence. batch-63's postmortem lists
   it as vacuous acceptance #4 — and it survived while the author was actively hunting vacuity.
4. **Bounding output does not bound traversal.** cap-and-break vs cap-and-continue are
   indistinguishable by peak memory (19019/19019, ratio 1.00) and wall time (1.00 vs 1.04). The ONLY
   falsifiable oracle is an **injected counting iterable** (201 consumed vs 2000).
5. **That counting fixture must be RE-ITERABLE and its bound is `R × 3K + ε`, not `3K + ε`** — the
   region loop is outer, measured `R=1 → 201`, `R=2 → 402`. A one-shot generator breaks at `R ≥ 2`.
6. **The `<1.5` R-axis peak-ratio threshold FALSE-FAILS a correct fix** (measured **1.89**, because a
   per-region cap materialises `R × CAP` by construction). And do **not** "fix" it by widening to 2.0
   — that stops the threshold failing the shipped code (1.98 / 2.01).
7. **A tracemalloc AT whose fixture is built INSIDE `tracemalloc.start()/stop()` can never go green
   for any implementation.** Fixture construction must precede `start()`.
8. **`~559.7 GB` / `~1283 min` must NOT be used as a threshold** — batch-63 ruled it non-re-derivable.
   Use the executed 87–94 B/hit constant with printed inputs.
9. **`_addendum_lines` has ZERO direct tests today** (C-26 reverse census). Nothing protects it; any
   structural rewrite drifts silently unless a byte-identity arm is written.
10. **The in-domain maximum is 2 hits per region** (executed over the real corpus: 14 calls, max R=2,
    max hits in one region 2). A cap of 200 gives 100× margin, which means **every in-domain test is
    green whether or not the cap works** — boundary fixtures at `CAP−1 / CAP / CAP+1` are mandatory.

## The design — DECIDED at the Phase-0 gate (operator, 2026-07-27)

**Option 2 — single-pass, region-indexed.** Walk `result → summary → entry/issue` **once**, decide
region membership via `range_index.py`'s binary-search primitives, and append into per-(region, class)
**bounded** buckets. `O(V×E·log R + R×3K)` instead of today's `O(R×V×E)`.

Chosen over the alternative (batch-63's per-hit-class cap, `O(R × 3K)`) because it additionally closes
the **B-3(b)** residual: under a cap-only design a region matching FEWER than the cap still traverses
the full `O(V×E)`, so an attacker declares R narrow regions matching nothing, feeds `V×E` entries and
pays the full product for zero output — the same attacker-selectable class of defect the batch exists
to remove. batch-63's architect explicitly assigned that residual to batch-64 and named `range_index`
as the primitive. `range_index.py` is engine-FROZEN but **consuming it needs no unfreeze** — verified,
`report_service.py` imports it 0 times today.

**Highest-risk unknown, sent to Phase 1 as a mandatory probe (P-1):** whether `range_index`'s API
lets the caller recover WHICH region an address fell into, or only WHETHER it fell into any. The
single-pass design needs per-region attribution to fill per-region buckets. If the API is
boolean-only, the frozen-safe fallback is to use it as a fast reject pre-filter and `bisect` locally
inside `report_service.py`. This probe can force a design revision, so it runs before anything else.

## Risks / watch-items

- **R-1 (highest) — batch-64 must NOT claim to close the memory-exhaustion DoS.** Security F2 is why
  D1 was returned: the neighbouring tables dominate at **988 B/entry** and are untouched by D1, so any
  AT keyed to `generate_project_report`'s whole-report peak is **unsatisfiable**. Key every memory
  acceptance to `_addendum_lines` alone, and state the residual with its numbers in the requirement
  and the PR. If the requirement never asserts closure, F2 has nothing to attach to.
- **R-2 — every `report_service.py` line number in the batch-63 artifacts is stale by +47.** Re-derived
  ones are in this plan; anything else must be re-derived, not copied.
- **R-3 — no notice wording is specified anywhere.** batch-63 never settled whether the truncation
  notice is one line per region or one per class, nor its text. Phase 1 owes it.
- **R-4 — a structural rewrite of an untested function.** Mitigated by a byte-identity arm below the
  cap (`canonical_report_bytes`), which batch-63 DROPPED from its own acceptance set (its D-2) and
  which this batch must restore.

## Out-of-scope carries (stay in `BACKLOG-CODE.md`)

OB-4/F4 (the two unbounded tables, 988 B/entry) · D2 (schema-legal address `ValueError`) · OB-3
(`diff_report_service` text-mode writers) · OB-2 (the AT/TC registry) · the `M-2` truncation-marker
claim, which D1 does not discharge.

## Test ledger

| gate | base | deleted | added | post |
|---|---|---|---|---|
| Phase-0 | 2201 (batch-63 close) | — | — | — |

## Decision log

| # | date | decision | taken by | rationale |
|---|---|---|---|---|
| D-1 | 2026-07-27 | Scope fixed to D1 only; OB-4/F4 and D2 stay carries | operator | batch-63 blocked by over-scoping |
| D-2 | 2026-07-27 | Autonomous + self-merge for this batch | operator | asked at kickoff, never inherited |
| D-3 | 2026-07-27 | Allocate `AT-194+` / `TC-480+` / `R-TUI-098` / `HLR-103` from an EXECUTED union census; RETIRE batch-63's `AT-164..167` / `TC-440..454` / `R-TUI-095` / `HLR-100` rather than reuse them | agent | the ids are contested between batch-63's D1 spec and REV-5 lane A; reuse would bind two observables to one id |
