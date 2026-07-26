# 05 — Post-mortem — batch-62 · `report_service` markdown escaping

> Base `8d3c504` → `b479d2a`. 9 commits. Phases 0–4 closed; Phase 2 needed one refinement iteration,
> Phase 4 needed one closing increment. Language: English.

## BLUF

The batch shipped what it set out to ship, and its **gates did the work rather than its plan**.
Phase 2 failed on 14 blockers, four of which were my own false acceptance thresholds. Phase 4 failed
on a normative ruling that never reached any increment. In both cases the failure was found by
*executing* a claim someone had written down — and in both cases the claim was mine.

The single most reusable sentence this batch produced:

> **A threshold that can be executed before the code exists must be executed before it is promoted
> to an acceptance criterion.**

Three of the four Phase-2 gate failures were predictions. Every threshold in the refined spec was
executed instead — and doing so caught a *fresh* false threshold inside the fold itself (A-26 named
`Cc`/`Cf` and missed `U+2028`, which is `Zl`). Re-measuring only the *inherited* thresholds would
have shipped it.

## Shape of the work

| | |
|---|---|
| Production | 4 files, +504 / −141 — one new leaf module (`markdown_safety.py`, 350 lines) |
| Tests | 9 files, +1666 / −46 — two new files (census 641, battery 639) |
| Docs | `REQUIREMENTS.md` +52 (R-TUI-077/078), `.dev-flow/` artifacts |
| Suite | 2168 → **2207** (+39), 0 regressions, 29 snapshots green throughout |
| Increments | 6 (Inc-1, 2, 3a, 3b, 4, 5), every one ≤5 files |
| ATs | 7 (AT-157…163), one named node each, each shown RED pre-fix |
| Gates | Phase 2: FAIL → refine → PASS · Phase 4: FAIL → Inc-5 → PASS |

## What actually worked

- **Adversarial Phase 2 with three independent reviewers.** It found 14 blockers on a spec I
  considered ready, and the two FAIL reviewers converged *independently* on five of them. Both also
  self-corrected inside their own reports. This is the highest-value phase in the flow and it is not
  close.
- **The fold measured instead of patching.** The golden drift went from a predicted "exactly 2 lines"
  to a measured `{14, 15, 51}`, and Inc-2 hit that set exactly, with no unpredicted line. The
  flow-report blast radius was measured at 1 test / 0 goldens — which also **corrected the security
  review's own cost estimate** ("the goldens move"; they do not, and the repo has no flow-report
  golden).
- **Tests carrying their own anti-vacuity assertions.** AT-161 asserts backticks are actually present
  before asserting the fence holds; TC-389 asserts the region cap actually fired. The second one
  *caught its own first fixture*, which had no `mem_map` and therefore no regions.
- **Counterfactuals as the acceptance evidence.** 29/157 RED against the pre-batch escaper, 13/19 RED
  with the escaper neutralised at the composer, 300-vs-200 lines with the cap removed. None of these
  is a claim; each is a transcript.
- **Splitting an increment on a measured seam.** Inc-3 came in at 7 files against a ≤5 limit, so it
  split into 3a/3b on the filter-surface boundary — which was also the origin of 8 of its 11 test
  failures. The alternative was quietly exceeding the budget.

## What failed, and why

### F-1 — Four false acceptance thresholds reached a gate (Phase 2, E-1…E-4)

Root cause: **I wrote thresholds from probes I had not exhausted.** The sharpest instance: a
"drift is exactly 2 lines" prediction, elevated to *the* acceptance criterion, derived from a probe
that sampled `descriptor.path.name` **once** for a field the fixture emits **twice**. A *correct*
implementation would have tripped my own gate.

Adjacent: I adopted an AT id set on a semantic match marked "to be confirmed", and the adopted
predicate — a closed 7-type token enumeration — **could not see the registry's own top-listed
blocker** (an injected `hr`).

### F-2 — The oracle was structurally unable to fail on its own class (Phase 2, security F1)

`&` was unescaped, so `SYM_A&vert;PASSED` renders a forged table fragment while **every token stays
`text`** — and the batch's whole assertion apparatus was token-type-based. `assert_field_inert`
scored the attack GREEN.

Fixing it needed **both** directions: escape `&` so the attack fails, *and* add a fidelity clause so
the oracle can fail on it. Either alone leaves one side open. That pairing is the transferable part.

### F-3 — A normative ruling died between the fold and the increment cut (Phase 4, B-1)

`D-20` ruled `MAX_REPORT_ISSUES_PER_VARIANT` as `shall`, it was recorded in §6.5 with a
Before/After, and then it **appeared in no increment's file list**. Inc-3a and Inc-3b both edited the
exact function and neither carried it — while the batch *doubled* that section's per-issue cost by
raising `issue.message`'s limit from 240 to 500. The one section outside `_ByteBudget` was the one
section the batch grew.

Root cause: **nothing in the flow checks that every normative ruling has an implementing increment.**
The §6.5 amendment log is write-only. C-18 gives every AT a node; no control gives every *ruling* an
owner.

### F-4 — Character-membership assertions, four more times

The class is old and it recurred four times in this batch alone:

1. `&` unescaped → the token-type oracle cannot see entity spoofing (F-2 above).
2. A-26 as first drafted named `Cc`/`Cf` and claimed to close a survivor list containing `U+2028`,
   which is **`Zl`** — it passed both that filter and the newline collapse.
3. The census's column-0 guard, written as a regex over *source lines*, false-positived on
   `report_service.py:1022` — the third chunk of an implicitly-concatenated f-string whose assembled
   line begins `- [`. Rewritten over the **AST**, where Python merges adjacent literals into one
   `JoinedStr`.
4. TC-389's first draft asserted `"](" not in note` and **failed against a correct implementation**:
   the escaped form is `\](`, since `]` is escaped and `(` needs no escape once the brackets are dead.

Counting prior batches (b60 wrong-grammar sink, b60 doc-vocabulary asserts, b61 NBSP-entity
predicate), this is now roughly the **seventh** occurrence across three batches. It is the standing
un-encoded candidate.

### F-5 — Two under-counted site lists, twice

The Phase-2 review declared 2 affected sites in `test_report_service.py`; there were **5**. The
kickoff's field list was short by **4** fields. Neither miss cost anything, because the census keys
on the *emitted document* rather than on a list — which is exactly why the census exists.

## Operator decision on the candidates (2026-07-25)

**P-1 ENCODED as `C-39`** in the global `/dev-flow` command (Phase 1, beside C-35/C-36) — *pre-execute
every executable threshold*, with the symmetric-failure framing (a predicted threshold false-fails a
correct implementation just as readily as it passes a wrong one) and the rider to re-measure the
fold's **own** new thresholds, not only the disputed ones.

**P-2, P-3 and P-4 DECLINED this round** — carried to `.dev-flow/BACKLOG.md`, not dropped. Worth
saying plainly which one I would raise again: **P-2**. It is the only candidate covering a gap no
existing control touches — a `shall`-statement can be ruled, recorded in §6.5, and never reach an
increment, which is exactly how B-1 shipped past five increments into the validation gate. P-3 has the
strongest occurrence count (~7 over 3 batches) but is at least *visible* every time it fires; P-2 is
invisible until something greps for the symbol.

## Controls earned — candidates as raised

Per the standing rule, no control is encoded without an explicit operator decision, and placement is
classified first: project-agnostic controls belong in the global `/dev-flow` command, stack-specific
ones in this project's `docs/engineering-rules.md`.

| # | Candidate | Root-cause gap | Placement | Evidence |
|---|---|---|---|---|
| **P-1** | **Pre-execute every executable threshold.** Any acceptance threshold that can be computed before the implementation exists (a golden's drift set, a blast radius, a file count, a cap's boundary) **shall** be executed and its transcript recorded *before* it is written into the spec. | F-1 — thresholds written from unexhausted probes. Generalises C-22's per-cell prediction and C-31's input-set-is-an-oracle to *all* thresholds, in both directions: a correct implementation must not trip the gate either. | **project-agnostic** → global `/dev-flow` | 3 of 4 Phase-2 failures; and it caught a fresh one inside the fold (A-26/`Zl`) |
| **P-2** | **Every normative ruling gets an owning increment, checked at the validation gate.** The increment cut **shall** map each `shall`-statement / amendment to the increment that implements it, and the Phase-4 gate **shall** fail on any ruling with no owner. | F-3 — `D-20` was ruled, recorded, and never implemented. **No existing control covers this**; C-18 covers ATs only. Subsumes the backlog's open code↔requirement reverse-index candidate (item 1c) rather than adding a parallel one. | **project-agnostic** → global `/dev-flow` | B-1, found only because Phase 4 grepped for the symbol |
| **P-3** | **Assert the emitted encoding, never a character list or the rendered form.** An assertion over untrusted text **shall** compare against the encoding the code emits — a parser's token stream plus an explicitly-computed expected display — never `ch in text` membership, never a rendered string. | F-4 — ~7 occurrences across 3 batches, 4 in this one. The general form is language-agnostic; the markdown/Textual specifics are not. | **split**: general form → global `/dev-flow`; the markdown-it / Rich-vs-Textual grammar specifics → `docs/engineering-rules.md` | `&vert;`, `U+2028`/`Zl`, the f-string AST guard, `\](` |
| **P-4** | **A guard must be shown able to fail.** A guard that fires nowhere on install **shall** additionally be driven to failure in a test, so "silent" is distinguishable from "inert". | The A-16 residue guard: it fires at zero real call sites *by design*, which is indistinguishable from a guard that cannot fire. Handled ad hoc here (`test_a16_*`). Complements C-32. | **project-agnostic** → global `/dev-flow` | A-16 measured in both directions at Inc-4 |

**Declined, deliberately:** a control mandating that every TC id appear in a node name. Seven now do,
sixteen do not, and the mapping lives in `04-validation.md` §3. That is a project-wide convention
question — the reverse-index item the backlog has carried since batch-48 — and inventing it inside
one batch would be the wrong place. Folded into **P-2** instead.

## Carries out of this batch

| # | Carry | Severity |
|---|---|---|
| RR-1 | Reader extensions (`:emoji:`, `$…$`, `==mark==`) are out of the modelled grammar; escape-set extension declined (D-22) | P2, declared |
| RR-2 | Project reports still disclose host paths in the three Mode-B path fields where flow reports do not — operator-ruled divergence (D-11) | **MAJOR**, inherited from batch-60 |
| RR-3 | Mode B is lossy on backticks (declared, visible U+FFFD marker) | note |
| RR-4 | `diff_report_service`'s own escapers remain (D-8), now carried inside HLR-097 itself | P2 |
| C-1 | Known-flaky `test_at002_name_strip_glyph_dirty_then_saved` (`NoMatches '#flow_panel'`) — passed alone, beside every neighbour, and on an identical-tree re-run | P3 |
| C-2 | `ruff check s19_app/` is red on `main` (pre-existing, verified with this branch stashed) | P3 |
| C-3 | 16 of 23 TC ids are not traceable to a node — see P-2 | P2 |

## One honest note on process

The **evidence run** for Phase 4 was the Inc-4 full-suite run rather than a fresh one, because
nothing had changed on the tree. Stating that is better than presenting a second run over identical
bytes as new evidence — and the same instinct is why the `2205 → 2207` correction in
`04-validation.md` was left visible instead of quietly overwritten.
