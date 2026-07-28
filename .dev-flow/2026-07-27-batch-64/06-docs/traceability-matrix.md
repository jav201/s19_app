# batch-64 — Traceability matrix

**Dual traceability: behavioural `US → AT` and functional `US → HLR → LLR → PP`. Zero gaps, zero
orphans. Layer A is realised by placement predicates (`PP-*`), not by minted `TC` ids — see §3.**

## 1. Behavioural chain (Layer B, black-box)

| US | outcome | HLR | AT | result | node |
|---|---|---|---|---|---|
| **US-B64-1** | C-40 encoded globally, absorbing P-6 + P-7 | HLR-B64-1 | AT-B64-01 / -02 / -03 | 9/9 CI · 8/9 full; 1/6 CI-normative negative; discrimination confirmed | `01c` §arms, `04-measurement-frozen.md` |
| **US-B64-2** | P-3 leg 1 as a rider on C-35 (C-41 cancelled) | HLR-B64-2 | AT-B64-04 / -05 | **9/9**, four mutations on disjoint *occurrence* sets (clause sets overlap; occurrence #2 unmutated); 0/17 stack-free | `04-measurement-frozen.md` |
| **US-B64-3** | C-42 in the project rules, five mechanics | HLR-B64-3 | AT-B64-06 / -07 | five mechanics confirmed; boundary complement holds | `02c`, code review §3 |
| **US-B64-4** | `VERIFY.md` section extended, general-only | HLR-B64-4 | AT-B64-08 / -09 | 0/12 identifiers; 0/29 vs 29/29 direction gap | `04-measurement-frozen.md` |
| **US-B64-6** | lineage registry consistent both directions | HLR-B64-5 | AT-B64-10 | PRE RED / POST GREEN, two independent carriers | `04-measurement-frozen.md` |
| *(cross-cutting)* | out-of-VCS edits recorded | HLR-B64-6 | AT-B64-11 | **bookkeeping, not acceptance** — counts toward no story | `03-out-of-vcs-evidence.md` |

**US-B64-5** (TUI course leg) — **OUT** by operator ruling; plan durable at
`G:/My Drive/Courses/textual/PENDING-UPDATES.md`, carried in `BACKLOG.md`. No chain owed.

## 2. Functional chain (Layer A, white-box)

| LLR | requirement | observer | result |
|---|---|---|---|
| LLR-B64-1.1 | C-40 after the C-39 bullet, before the UI-geometry pointer | **PP-1** | `31606 < 34013 < 40153` ✅ |
| LLR-B64-2.1 | rider **inside** the C-35 bullet, before its `(Origin:` | **PP-2** | same line, one space ✅ |
| LLR-B64-2.2 | rider's normative body stack-free (`AST` exempt) | AT-B64-05 | 0/17 ✅ |
| LLR-B64-3.1 | C-42 between `## C-38` and `## C-34` | **PP-3** | `11928 < 13440 < 17724` ✅ |
| LLR-B64-3.2 | five mechanics, each with a discharge | AT-B64-06 | 5 named ✅ |
| LLR-B64-4.1 | extension inside `## Pin the truth`, **no new `##`** | **PP-4** | new headings **0**; heading string-list byte-identical PRE/POST ✅ |
| LLR-B64-5.1/.2/.3 | lineage: C-40/C-42/rider + ABSORBED/DECOMPOSED/C-41-free + C-29 | AT-B64-10 | all present ✅ |
| LLR-B64-5.4 | BACKLOG footer id range **and** stack list | **PP-5** | both clauses; stack list exact 12/12 set match ✅ |
| LLR-B64-6.1…6.4 | PRE/POST hash rows, per-increment, POST ≠ PRE | `03-out-of-vcs-evidence.md` | 5/5 files, no POST == PRE ✅ |

## 3. Why Layer A is `PP-*` and not `TC-NNN`

Three parties independently declared Layer A `N/A` — *"for a documentation deliverable the artifact IS
the observable"* — and the Phase-2 QA reviewer **refuted that by execution**: a placement predicate is
RED pre-batch, GREEN on a correct insert and **RED on a mis-placed insert**, while `AT-B64-08` and
`AT-B64-09` return **identical values on both**. Four `shall` clauses fixed within-file position and
nothing observed them.

`TC` ids were deliberately **not minted**: manufacturing white-box ids to fill a matrix is the
template-filling the flow's hard rules forbid. Four ~10-line predicates were built instead, and
`LLR-B64-5.4` gained a fifth after the discharge audit found it orphaned.

## 4. Coverage summary

- Stories in scope: **5** · with an executed black-box AT: **5** · orphan ATs: **0**
- LLRs: **19** · with an observer: **19** · unobserved `shall` clauses: **0**
- ATs excluded by explicit label: **1** (`AT-B64-11`, bookkeeping) — excluded visibly, not silently
- Every figure names the `§3.0` block hash it was measured against (normative admissibility rule)
