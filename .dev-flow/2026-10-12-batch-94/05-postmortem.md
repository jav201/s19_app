# Post-mortem — s19_app — Batch 2026-10-12-batch-94

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. Structured for cross-batch sweeping — keep the section order.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Gated tree` · `Found before the batch` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.

## 0 · Gate record — which tree this close gated

| Field | Value |
|---|---|
| Gate record | `<the validator command, its exit code, and 0 block · date>` |
| Gated tree | `<the 40-hex HEAD at the gate · clean — or: dirty — the files>` |

> **This is `full`'s copy of the two rows `close-template.md` §0 carries for `core`, and that
> file's §0 note is the rule's one home** — `full` is not seeded `05-close.md`, so `V57` reads
> the record here instead. Write it at the close gate from that run's own `git rev-parse HEAD`
> and `git status --porcelain`.

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
| Iterations per station | `{P0:_,P1:_,P2:_,P3:_,P4:_,P5:_,P6:_}` |
| Findings opened / closed | `<N>` / `<N>` |
| Findings by severity (blocker/major/minor) | `<N>/<N>/<N>` |
| Where caught (P2 / P3 gate / P4) | `<N>/<N>/<N>` |
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

### Working-file reconciliation (C-44) — MANDATORY, every file this batch touched
> **Run it as a sweep, never from memory:** `git status --short` in **every repository touched, auxiliary repos outside the project tree included** (skills / commands / config are where this hides) · `git log @{u}..HEAD` for commits that exist but were never pushed · an open-PR check for any branch other work depends on. **Report pre-existing uncommitted changes as FOUND, never fold them into this batch's commit.** A tracked file already modified when the batch began goes in the `Found before the batch` field below the table, not in it (`templates/guides/close-template.md` §3 holds the rule).
>
> **A commit that never lands is NOT a terminal state.** Work that is finished but unlanded is indistinguishable from work never done — and it makes the state files the next batch reads assert something false, which that batch then inherits as a premise (**C-43 §2.7**).

| Repo | File(s) | Terminal state | Landing / backlog ref |
|------|---------|----------------|-----------------------|
| `<repo>` | `<path>` | ✅ committed + landed \| 🗑️ discarded \| 📋 in backlog | `<PR # / merge SHA / backlog line>` |

- **Found before the batch:** `none — no tracked file was modified when the batch began`

**Conditional gate verdicts:** if any gate this batch ran closed as *"once items 1–N land this is a PASS/MERGE"*, list each item and its discharge **verified by re-reading the artifact** — not by trusting that the corrective pass ran.

| Conditional item | Discharged? | Verified how |
|---|---|---|
| | ✅ / ❌ | `<file:line re-read>` |

### Evidence checklist — architect + qa-reviewer
> Attach both co-authors' completed evidence checklists (items in their agent files), each ✓/✗ with one-line evidence.
