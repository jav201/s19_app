# Post-mortem — s19_app — Batch 2026-06-26-batch-18

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. Structured for cross-batch sweeping — keep the section order.

## 🔑 At a glance (read first)

- **Outcome:** closed clean  /  closed with carry-over  /  needed `<N>` iterations
- **Top 3:** ① `<what worked>`  ② `<what didn't>`  ③ `<key root cause, if any>`
- **New control this batch:** `<one line, or "none">`
- **Open items → next batch:** `<N>` — `<headline of the biggest>`
- **Metrics:** iterations `<sum>` · findings `<closed>`/`<opened>` · ledger `<base>`→`<post>`

> Enough to know the batch's health and what carries forward. Detail below only for the why.

---

## Detail (reference)

### What worked
- `<…>`

### What didn't / friction
- `<…>`

### Scope drift (planned vs actual)
| Planned | Actual | Note |
|---------|--------|------|
| | | |

### Metrics (full)
| Metric | Value |
|--------|-------|
| Iterations per phase | `{0:_,1:_,2:_,3:_,4:_,5:_,6:_}` |
| Findings opened / closed | `<N>` / `<N>` |
| Findings by severity (blocker/major/minor) | `<N>/<N>/<N>` |
| Where caught (Phase 2 / P3 gate / P4) | `<N>/<N>/<N>` |
| Test ledger (base − D + A = post) | `<…>` |
| Files touched · increments (cap trips) | `<N>` · `<N>` (`<N>`) |

### Root causes (only if a phase took ≥2 iterations)
- `<iteration trigger → root cause>`

### Process / workflow findings
> About the dev-flow itself (phases, gates, templates, agents, controls). Feeds workflow improvement — keep separate from product.
- `<finding → suggested workflow change>`

### Product findings
> About the code/product under development.
- `<finding>`

### Control lineage
- **New control proposed this batch:** `<control + origin finding>` (status: propose / adopt-next-batch)
- **Prior controls exercised:** `<which held · which were stress-tested · near-misses>`

### Open / deferred items → next batch
| Item | Type (process/product) | Reason deferred | Trigger / owner |
|------|------------------------|-----------------|-----------------|
| | | | |

### Evidence checklist — architect + qa-reviewer
> Attach both co-authors' completed evidence checklists (items in their agent files), each ✓/✗ with one-line evidence.
