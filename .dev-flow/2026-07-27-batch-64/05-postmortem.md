# batch-64 — Post-mortem

**BLUF: the control this batch encoded caught its own authors nine times while being written, including
twice on the orchestrator and once on the reviewer auditing it. That is not embarrassment — it is the
only evidence available that the control is operable, and it is the batch's single most reusable
output. The process cost was disproportionate to four paragraphs of text, and that is stated plainly
rather than absorbed.**

---

## 1. What the batch did

Encoded the control candidates the operator resolved at batch-63's postmortem. Final shipped set:

| deliverable | destination | in VCS |
|---|---|---|
| **C-40** — falsifiability-before-correctness, two limbs, P-6/P-7 absorbed as named instances | global `/dev-flow` | ❌ |
| **C-35 rider** — assert against the producer's emitted form (replaced the cancelled C-41) | global `/dev-flow` | ❌ |
| **C-42** — the stack-bound emitted-form mechanics, five of them | `docs/engineering-rules.md` | ✅ |
| **`VERIFY.md` extension** — general-only, inside the existing section | `tui-design` skill | ❌ |
| **Registrations** — C-40/C-42/rider, plus **C-29 back-registered**, P-6/P-7 ABSORBED, P-3 DECOMPOSED, **C-41 free** | lineage memory | ❌ |

**+26 334 B across five files. Zero production code.**

## 2. The nine self-catches — the batch's primary output

Every one was found by applying the control under encoding to the work encoding it.

| # | what | who |
|---|---|---|
| 1 | Phase-0 census counted **mentions, not encodings** — `C-1..C-39` claimed, `C-10..C-39` true | orchestrator |
| 2 | `AT-B64-05` as specced was **RED against the correct file** (`Textual`×3, `AST` already present) | orchestrator |
| 3 | `AT-B64-10` was **green by construction** — the census included the batch's own proposal | orchestrator |
| 4 | limb 1 keyed on "the writer" → **1/6 false positives** against a sound predicate | architect draft |
| 5 | the run-1 arms harness **never opened any C-40 text** — invariant under every wording | qa lane |
| 6 | the fold **dropped 20 union observables** and printed two false "Unchanged" lines | fold 1 |
| 7 | `AT-B64-04` measured an **890 B body that ships at 1 975 B** | fold 2, caught by the audit |
| 8 | the discharge auditor mis-scoped the census a **fourth** way, and committed a C-42 mechanic **inside its audit of C-42** | auditor |
| 9 | the orchestrator used **`write_text`** applying the review folds — batch-63's own **D3** defect — inside the batch encoding *assert against the emitted encoding* | orchestrator |

Plus: `V-6` and `V-7`, **two tautological assertions live on `main`**, found only by executing the
candidate control against batch-63's corpus. Both passed three 0-HIGH gates. C-10, C-31 and C-39 all
miss them.

**The pattern, stated once:** *"is this predicate correct?"* and *"can this predicate go RED?"* are
different questions, and every gate that asked only the first passed something that verified nothing.

## 3. What worked

- **Fixing ids with per-id SEMANTICS before dispatch.** batch-63 fixed ranges, claimed the collision
  was "removed by construction", and was falsified. Fixing semantics produced **zero collisions** and
  two lanes that converged independently on the C-40 draft.
- **Briefing the audit against the SOURCE reviews, not the amendment table.** That single choice
  surfaced the 20 dropped observables. An audit against the discharge matrix would have passed it.
- **Converting size questions into measurements before asking the operator.** Twice. Both times the
  measurement dissolved the question: first showing all variants measured 6/6 so bytes could not be
  decided on detection, then showing the gradient had reversed and the originally-ruled text had
  become measurably weaker.
- **The freeze-then-measure structure.** `§3.0`'s manifest plus *"a figure is admissible only if it
  names the block hash it was measured against"* is what turned "measured against shipping bytes" from
  an assertion into a provable claim. Three parties reproduced the manifest independently.
- **Scripting the pastes instead of delegating them.** An agent asked to reproduce a 6 219-byte block
  may reflow it; the script copied bytes. Byte fidelity came back **6/6**.

## 4. What did not

- **Three Phase-1 iterations**, hitting the soft cap. Root cause named at the cap and structural: **the
  acceptance layer was measuring a moving target.** Every fold changed the text; every arm figure was
  measured against that text; each fold silently invalidated the prior measurements. The fix was the
  freeze, and it should have been the *first* move, not the fourth.
- **The orchestrator's own fold repeated the defect class it was closing** — dropping observables while
  encoding "do not drop observables". Cause was structural: it **rewrote where it should have amended.**
- **A read/write race I created** by dispatching a ledger-builder and a fold against the same file
  concurrently, producing a phantom finding (`U-2`) that would have blocked the gate on the claim that
  the whole fold never landed. **Second measured occurrence** of batch-62's `sec F5`, which sits in the
  backlog **unencoded**.
- **Proportionality.** ~14 agent runs for four paragraphs. `/fast-dev-flow` was flagged as the better
  route at intake; the operator kept `/dev-flow` and that is their call, but the ceremony/deliverable
  ratio is the honest headline cost.

## 5. Metrics

| | |
|---|---|
| Phase iterations | 0:0 · **1:3 (soft cap)** · 2:1 · 3:1 · 4:0 |
| Phase-2 findings | architect 6B/10M/8m · qa 2B/4M/5m · security 0B/1M/2m |
| Discharge audit | 38 source findings · 31 closed · 4 carried · 3 not closed |
| Union ledger | 294 rows: 247 carried / 7 retired / 39 restored / 1 unplaceable |
| Code review | **0 HIGH** / 4 MEDIUM / 3 LOW; byte fidelity **6/6**, placement **5/5** |
| Operator rulings | 4 (course leg OUT · C-41→rider · V-FULL at 2.07× · re-affirm at 2.56×) |
| Suite | 2201 passed, 29 snapshots, exit 0 — **re-derived**, not carried |

## 6. Scope drift

**Controlled.** One leg (the TUI course) ruled OUT by the operator with its plan left durable. C-41 was
**cancelled** on measured evidence (~70 % overlap with C-35) rather than encoded by default — the
architect surfaced the cheaper alternative specifically so the ruling would stand against a known
option. C-40 grew 2.07× → 2.56×, entirely from review-mandated discharges, and was re-affirmed
knowingly.

## 7. Items proposed for the next batch

All are in `.dev-flow/BACKLOG.md §7.1–7.8`. The four worth naming here:

1. **Four vacuous predicates live on `main`** — `V-6`/`V-7` and two others; carry, not fix (D-5).
2. **The worktree read/write hygiene rule** now has **two measured occurrences** and is a dependency of
   an encoded control (C-40 mandates mutations). Strongest un-encoded candidate in the project.
3. **A fix to one finding can disarm another finding's test.** Restoring `D-01…D-04` gave three clauses
   independent carriers, so the mutation `AT-B64-04`'s discharge relied on stopped biting entirely — a
   re-run with the old mutation would read GREEN and conclude all was well. **No encoded control covers
   this.** New candidate.
4. **`OB-2`, the missing AT/TC registry** — this batch derived control ids by union-grep across six
   destinations, the same manual procedure OB-2 says does not scale, and **four agents mis-scoped that
   census in four different ways**, each caught only by implausible size.

## 8. Deviations recorded

- **D-12** — the orchestrator executed the pastes rather than delegating to `software-dev`. Safety
  argument: a regenerated block breaks its hash, which is the failure the freeze exists to detect.
  Independent review preserved in full.
- **Phases 4 and 5 were authored by the orchestrator** rather than co-authored by `qa-reviewer` and
  `architect` sub-agents. Both are syntheses of evidence produced independently by other parties;
  every figure in them is cited to an executed transcript. Recorded as a deviation, not absorbed.
