# batch-75 — PLAN (living compendium)

**Objective.** Close **F4** (the report document is not byte-bounded and `_ByteBudget` as built cannot
bound it) and **D2** (the inline `Length` cell + the `app.py` error re-attribution), split out of
batch-74 at its 3-iteration cap.

**Route.** `/dev-flow` full V-model, operator-invoked ("completo"). Language: **English** (inherited
from `state.json.language = "en"`, unchanged).

---

## Where we are

| Phase | Status |
|---|---|
| **0 — intake** | ✅ approved |
| **1 — requirements** | ✅ approved at **revision 2** (1 iteration) |
| **2 — cross-review** | ✅ approved after a **BLOCK** + re-gate (1 iteration) |
| 3 — implementation | 🚫 **DESCOPED by operator ruling** — owed, registered P0 in `BACKLOG-CODE.md` |
| 4 — validation | 🚫 N/A — no code changed. **Declared, not omitted.** |
| 5 — post-mortem | 🚫 folded into `02-review.md` §5 + `01-requirements.md` §9 |
| 6 — docs | 🚫 N/A — no shipped behaviour changed. **Declared, not omitted.** |

> **Outcome: SPEC ONLY.** Operator ruled mid-batch (*"solo enmiendas, para antes de Inc-1"*) that
> implementation moves to a fresh session with a full context window — this area hit the 3-iteration cap
> in b63 and b74 partly by running out of room mid-increment. **Every non-produced artifact is declared
> above with its reason** (non-negotiable #6: batch-74 reached MERGE missing two artifacts and
> `/dev-flow-sync` caught it, not the gate).

## RC-1 + flow revision

- `origin/main` tip = **`232eb0a`**; merge-base == tip; branch `claude/batch-75-s19-app-a6fd1e` fresh; tree clean. ✅
- **Flow revision `2026.07.28-rev1`**, controls C-1…C-45. Aggregate hash **mismatches** the manifest
  (`896dcca6…` vs `0127a276…`) — **scoped and non-blocking**: all 11 control-bearing command/template
  files are byte-exact; only the untracked `dev-flow-lessons/SKILL.md` diverges (641 local vs 620
  stamped, local AHEAD). → Lane B carry. Detail: `00-measurements.md` §2.
- **Id range: AT-250…AT-279, TC-552…TC-599.** High-water re-derived independently on main =
  AT-249 / TC-551. No id outside the range (the AT/TC registry build may be running in parallel).

## Scope

### IN
| # | Item | Source |
|---|---|---|
| **F4** | The document is not budget-bounded; `emit()` accounts and never gates | charter, MAJOR/HIGH |
| **F4c** | `V` (variants) and `F` (check files/variant) uncapped — `O(V × F × structural)` | charter, MAJOR |
| **D2** | Inline `Length` cell (2 disjoint sites) + `app.py:4164` error re-attribution | charter, MAJOR |

### DISPOSITION REQUIRED (charter: "NOT sin disposición")
| # | Item | Phase-1 decision |
|---|---|---|
| **D2b** | `_applied_regions` — a THIRD unbounded producer (peak 16,128 → 160,992 B at N=2000→4000) | ⏳ **IN or explicitly FENCED — decided in Phase 1, never left silent** |

### OUT (stated, not dropped)
- Truncation-notice routing to `## Truncation appendix` (charter P2 hygiene) — candidate if it rides free.
- `R-TUI-101` wording carve-outs (4 items, charter P3) — **owed**; discharge at close or state openly.
- Everything in the engine-frozen set.

## Non-negotiables (operator, this batch)

1. **Authorization asked at kickoff, never inherited** — ⏳ *pending, blocking Inc-1*.
2. **Re-derive every number before gating on it** (C-39) — done for Phase 0; `00-measurements.md`.
3. **Every line number re-derived** — done; uniform **+330** drift vs the charter. Cite symbols.
4. **Budget iterations** — this area hit the cap in Phase 1 AND Phase 2 across b63 and b74. On a cap, **escalate, do not loop**.
5. **Vacuous acceptance is the house defect** — every AT answers *"can it go RED?"* separately from
   *"is it correct?"*, and **the mutation is EXECUTED** (C-40). Watch the new Lane-B class: **vacuous
   FIXTURES** (a correct predicate that cannot fail because the fixture does not exercise its claim).
6. **Produce every phase artifact** or declare in writing why it does not apply. batch-74 reached
   MERGE without `04-validation.md`/`06-docs/` and `/dev-flow-sync` caught it, not the gate.
7. **Frozen set off-limits**: `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
   `tui/mac.py`, `tui/color_policy.py` + `_ENGINE_TEST_FILES`. Dual-guard (C-27) every increment.
8. **Reconcile `BACKLOG-CODE.md` at close**, including the owed `R-TUI-101` carve-outs.

## Key findings so far (all executed)

- ✅ **F4 confirmed and sharper.** Exactly **1** gate (`.fits`, `:1785`, hexdump blocks only) vs **2**
  accounting sites. `emit()` never gates. Six emissions bypass any byte gate.
- 🆕 **`md_safe(limit=)` bounds the INPUT, not the emitted form** — measured **2.03×** expansion.
  Not in the charter. Any byte bound written from `REPORT_CELL_CHARS` arithmetic is wrong unless it
  measures the emitted form. (The project's own C-42 lesson, on the sizing axis.)
- ⚠️ **My own numbers differ from the charter's by ~1.4%** (311,625 vs 315,912 B/variant). Shape holds,
  figures do not. Re-derived govern.
- 🚫 **An over-claim of mine, struck before it reached the spec:** `related_artifacts` looked like an
  uncapped cardinality axis worth 5.04× budget from one variant — it is engine-generated from short
  literals and **not wire-reachable**. Recorded in `00-measurements.md` §4.5 so it is not rediscovered.
- ✅ **D2 headline confirmed FALSE** as the charter states: a huge address renders in 45 chars; the
  `raise` is on `Length`'s decimal digits. `_format_length` does not exist — **it must be created**.

## Risks / watch-items

| # | Risk | Mitigation |
|---|---|---|
| R-1 | An honest per-row gate on 2 producers while 6 stay ungated = **a bound in name only**. batch-74 withdrew `HLR-106`/`AT-227` for exactly this over-claim, found independently by all 3 lanes. | The requirement must state **what it does not close**, explicitly, before Phase 2. |
| R-2 | `_applied_regions` unbounded ⇒ a whole-report residency acceptance is **unsatisfiable** (batch-74 P-23). | Decide D2b in Phase 1: bound it, or fence it and scope the acceptance to what IS bounded. |
| R-3 | Iteration cap — this area hit 3 in two separate batches. | Escalate at the cap. Budget: Phase 1 ≤2, Phase 2 ≤2. |
| R-4 | `report_service.py` is 2592 lines and has grown 2 batches running; every inherited address is stale. | Symbols only, never addresses. Verified +330 uniform drift. |
| R-5 | Vacuous fixtures (new Lane-B class). | Each AT's fixture must be shown to exercise the claimed axis, not merely to pass. |

## Decision log

| # | Date | Decision | Rationale |
|---|---|---|---|
| D-1 | 2026-07-31 | Flow-hash mismatch ruled **non-blocking**, carried to Lane B | Divergence is confined to the untracked lessons catalog; all 11 control-bearing files byte-exact |
| D-2 | 2026-07-31 | `related_artifacts` cardinality axis **struck** from scope | Measured, then found not wire-reachable — engine-generated literals |
| D-3 | 2026-07-31 | Charter's B/variant figures **superseded** by re-derived ones | C-39 — a carried number is re-derived, never copied |

## Test ledger

| Point | Base | −D | +A | Post |
|---|---|---|---|---|
| Phase 0 | ⏳ to be measured at Inc-1 | — | — | — |

## Out-of-scope carries (running)

- Lane B: re-stamp `FLOW-VERSION.md` for the 641-line `dev-flow-lessons/SKILL.md`, or record the catalog as deliberately outside the hash.
