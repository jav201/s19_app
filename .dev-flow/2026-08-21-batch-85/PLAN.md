# PLAN — 2026-08-21-batch-85 · IFC pilot on `LoadedArtifactsPanel`

**Living compendium. Updated at every gate and checkpoint.** Mode `core` · language English ·
autonomous + merge authority (merge gated behind a clean final PR-level review).

> **This batch EXECUTES the charter that every existing citation calls "batch-82."** The charter
> keeps its name; the executing batch is **85**. Stated here because a reader who greps `batch-82`
> must be able to find the batch that ran it.

---

## 1 · Where we are

**Station P0 — awaiting gate.** Intake, RC-1, trigger evaluation and scaffolding are done. Nothing
has been implemented; no IFC record exists yet.

| | |
|---|---|
| Base | `origin/main` `a112eeb`, merge-base equal — **RC-1 ✓** |
| Flow | `2026.08.21-rev38`, `flow_hash 004ec303f6ca9dbb` — V7/V15/V16/V17 ✓ |
| Branch | `claude/batch-82-lane-a-scoping` (carries the scoping + the promoted spec; PR #199 open) |
| Prior art landed this session | PR #198 (D4), PR #199 (scoping + spec), flow rev38 |

---

## 2 · Objective, and the one number this pilot exists to produce

Author the C-54 **Part B** record for **one** surface, `LoadedArtifactsPanel`, and **measure what it
cost**. The retrofit's remaining surfaces are currently sized by an estimate that has three
disagreeing values; this pilot replaces the estimate with a measurement.

**The deliverable is the findings, not the file** — per the design's own D-2 ruling. Authoring an
`address` and a `consumers` list for a surface that never declared one forces the question *"who
depends on this, and how do they reach it?"*, and this batch already has three stale consumer lists
as evidence that the question has never been asked here.

---

## 3 · Decisions — why, and what each one costs

> Operator instruction 2026-08-21: *"raise the decisions in table form so I know why the decision was
> taken and the consequences of each."* This table is maintained for the life of the batch.

| # | Decision | Alternative rejected | Why this one | Consequence — including what it costs | Who |
|---|---|---|---|---|---|
| **D-1** | Batch id **85** | `82`, the charter's own name | Monotonic allocation matches the project's id philosophy (`AT-TC-REGISTRY-SPEC` §4: no gap-fill, no reuse). 83 and 84 already shipped. | ⚠ **Every existing citation says "batch-82."** Each artifact must state that 85 executes the 82 charter, or a later reader finds a charter with no executing batch. | operator |
| **D-2** | Mode **`core`** | `full` | Proportionate to one surface. Keeps ids, dual traceability, the RED counterfactual, the `code-reviewer` gate, living PLAN. LLR headings still exist, which `V10` needs. | No `06-docs/`, no executive summary, no full post-mortem; closes with `05-close.md`. **If the pilot reopens the C-54 design, the mode must RAISE to `full`** — modes only raise. | operator |
| **D-3** | **Autonomous + merge authority** | Gate-by-gate | Operator ruling, asked fresh at kickoff. | Gates self-approve, so this log is the only reconstruction path. **Merge stays blocked** behind a clean final PR-level review; a HIGH finding returns to the operator. | operator |
| **D-4** | **Promote** fast→core rather than finish in the fast lane | Finish under `/fast-dev-flow` | Part B's declared home is `.dev-flow/<batch>/01-requirements.md`, a Phase-1 artifact the fast lane has no phase for. | Continuing in fast would have meant **inventing a second home** for the artifact, against C-50's one-home rule. Cost: the heavier flow. | operator |
| **D-5** | Fix the loader **before** opening this batch | Author the record anyway | `V10`–`V14` read 1 of 61 `01-requirements.md` (first-wins by walk order), so the record would have been **invisible** and the rules green. | Shipped as flow **rev38** — a change to a **shared asset** every project running this flow inherits. Bounded: no project has COMPONENT blocks today, so nothing green goes red. | operator |
| **D-6** | D3's assertion lands in the **existing** `tests/test_address_origin.py` | A new test file | `test_id_registry.py:73` pins `EXPECTED_SCANNED_TEST_FILES` at 155. A new file drifts an unrelated lane's guard into this batch. | Guard untouched, no bump owed. **If a later increment does need a new test file, that count must be re-derived, not assumed.** | agent |
| **D-7** | ~~Review lenses inline~~ → **REVERSED: lenses run as spawned sub-agents** | Running them inline | Initially withheld because this session's configuration said not to use the `Agent` tool unless requested, while `/dev-flow` mandates it — conflict **surfaced, not averaged**. **Operator said "spawn them" 2026-08-21**, which is the explicit request that was missing. | ✅ **Risk R-4 CLOSES** — the `code-reviewer` gate is independent as the flow intends, and the author no longer reviews the author. Cost: tokens and wall-clock per gate. | operator |

---

## 4 · Trigger evaluation (probes executed, non-activation recorded too)

| id | Verdict | Probe + output |
|---|---|---|
| **B1** | ✗ **FIRED** | `grep -rl address_origin tests/` → `test_address_origin.py`, **`test_id_registry.py`** — a test owned by a *different* requirement (the AT/TC registry lane). Reverse census owed. `:73` is a docstring pinning `EXPECTED_SCANNED_TEST_FILES` 154→155. |
| **B2** | ✓ not fired | No file changes location. Edits are comments + one assertion + a new `.dev-flow/` artifact. |
| **B3** | ✗ **FIRED** | `grep -rn styles.tcss tests/*.py` → **`test_legend_two_pane.py:634` parses `styles.tcss` into `(selector, declarations)` blocks**, and `test_tui_commandbar.py:1572` (`TC-B79-02`) parses it for a specific rule. **A comment edit in that file is NOT automatically inert** and must be verified, not assumed. |
| **B4** | ✗ **FIRED** | This batch produces an artifact another component consumes: the IFC record is read by `V10`–`V14`. Output-then-consume discipline (C-12) applies — the acceptance must observe the *validator* over the *authored* record, not a hand-built fixture. |
| **C** (all 7 families) | ✓ not fired | Diff is comments + one set-membership assertion + a requirements document. No auth, secrets, external integration, sensitive data, destructive DB, input surface, or network exposure. "Address" here means a widget selector. |
| **D1** | ✓ not fired | Nothing the user sees or touches changes. The `.tcss` edit is a comment; no rule, no declaration. |
| **F1 / F2** | ✓ not fired | `flow_hash` matches the manifest (rev38, shipped this session). Backlog refreshed at batch-84 close. |
| **A2** | ❓ undecided at intake | Touches `tools/`, `s19_app/tui/` and `tests/`. Whether that is "≥2 modules" needs the module map, and `V8` reports `docs/ARCHITECTURE.md` **declares no `path/**` prefixes so it cannot be checked**. Recorded as undecided rather than guessed. |
| **E1** | ❓ undecided at intake | Increment count not yet fixed (2–3 planned). Re-evaluate at the P1 gate. |

---

## 5 · Stories and status

| id | Story | INVEST | Status |
|---|---|---|---|
| **US-85-1** | As the flow's validator, I observe a declared contract for `LoadedArtifactsPanel`, so that a change to *how consumers reach* its cells is a contract change rather than an accident. | Testable through `V10`–`V14`'s own output | `READY` |
| **US-85-2** | As a maintainer reading any of the three "two shipped readers" notes, I find the measured consumer set rather than a count that was accurate when written. | Observable by grep | `READY` |
| **US-85-3** | As the address census, I fail loudly the day a selector form outside `{literal, name, fstring}` appears, instead of being silently incomplete. | Observable — synthetic instance goes RED | `READY` |
| **US-85-4** | As the operator sizing the remaining retrofit, I read a measured per-surface cost instead of an estimate with three disagreeing values. | Observable — the number exists or it does not | `READY` |

---

## 6 · Roadmap — RE-CUT at the P1 gate (C-21)

> **Why re-cut.** The original Inc-1 ("author `01-requirements.md` with the Part B record") **landed
> inside Phase 1** — the IFC record IS the Phase-1 artifact. And the AT set changed when the two
> lenses folded. C-21 says a cut is STALE the moment the AT set changes, so it is re-derived here
> rather than left to orphan an AT.

| Inc | Content | Source files | Obligations |
|---|---|---|---|
| ~~old Inc-1~~ | ~~author the record~~ | — | ✅ **absorbed into Phase 1**, verified by the shipped validator |
| **Inc-1** | Correct the 3 in-repo stale sites; append errata to the design record. | 2 source (`screens_directionb.py`, `styles.tcss`) + 1 test (`test_tui_commandbar.py`, message only) | **B3** differential block parse is the GATE |
| **Inc-2** | D3 membership assertion over `Census.sites` + the synthetic-instance RED arm. | 1 source (`tools/address_origin.py`) + existing test file | **C-55** discharge · **B1** reverse census |

### The stale-site census — measured, with its false positive named

| # | Site | Nature | Treatment |
|---|---|---|---|
| 1 | `s19_app/tui/styles.tcss:252` | stale phrase | correct in place |
| 2 | `s19_app/tui/screens_directionb.py:1954` | stale phrase | correct in place |
| 3 | `tests/test_tui_commandbar.py:1302` | **split f-string** — invisible to a single-line grep | correct in place (assertion *message*, not the predicate) |
| 4 | `.dev-flow/design/C-54-…md:19` | historical narrative of the original defect | **errata block — do NOT rewrite**; it describes what was true then |
| 5 | `.dev-flow/design/C-54-…md:155-156` | live 2-entry `consumers` sketch | **errata block** |
| ⚠ | `tests/test_tui_legend.py:458` | **FALSE POSITIVE** — "two shipped overlay-style constants", about Hex colours, nothing to do with `.loaded-detail` | **DO NOT TOUCH.** A naive "fix every `two shipped`" corrupts an unrelated comment |

### ⚠ Two of my own probes broke while taking this census, and both returned plausible results

Recorded because the batch's own subject is measurement honesty:

1. `--include=*.py` was **expanded by the shell** against the repo root (`setup.py` exists), so the
   filter matched only files named `setup.py`. The probe returned **empty**, which reads exactly like
   *"the tree is already clean."*
2. A `head -12` truncated the result set **before** it reached `s19_app/`, hiding the two sites that
   matter.

Neither was caught by a guard. Both were caught by contradicting an earlier direct read of
`styles.tcss:252`. **That is the C-55 rider in the wild, for the third time this session.**

## 7 · Risks / watch-items

| id | Risk | Status |
|---|---|---|
| **R-1** | A `.tcss` comment edit drifts a structural parser test (**B3**). | **Constraint DERIVED by reading the parser, 2026-08-21.** `tests/test_legend_two_pane.py:651-658` does `text.split("}")` → `partition("{")` → `selector.split("*/")[-1]`. A preceding comment is stripped correctly, **but any `{` or `}` inside a comment shifts EVERY block boundary in the file.** So Inc-2's corrected comment MUST contain no brace and exactly one terminating `*/`. **Pre-edit baseline captured green:** `test_legend_two_pane.py` 9 passed, `TC-B79-02` 1 passed. Re-run both after the edit — verified by running, not by reasoning. |
| **R-2** | The Part B record's `consumers` list goes stale the same way the three copies did. `V13` is the control that notices; this batch is its first real application. | Open by design |
| **R-3** | **C-55 — load-bearing emptiness.** D3's assertion is green only because the tree has zero `other:Attribute` bindings today. Mutating it changes nothing. **Discharge owed: a synthetic module the tree lacks.** | Open — discharge is a deliverable |
| **R-4** | ~~Author reviews author~~ | ✅ **CLOSED 2026-08-21** — operator reversed D-7; lenses are spawned sub-agents. |
| **R-5** | The CSS-consumer question was recorded as "open" in the scoping doc and is in fact **already settled** by the shipped control (`_V13_EXT` includes `.tcss`; `V14`'s symbol check is conditional). Two of my own claims were wrong. | ✅ Closed — corrected in the promoted spec's premise table |

---

## 8 · Conventions honored

Docstring section order · type hints · AT/TC ids from `AT-TC-REGISTRY.jsonl` (**batch-scoped `AT-B85-*`
preferred — they cannot collide and stay outside the global pool**) · engine-frozen set untouched ·
`.dev-flow/**` outside the source-file budget · backlog Lane A = `BACKLOG-CODE.md`.

---

## 9 · Out-of-scope carries

- The other surfaces of the retrofit — this is one, deliberately.
- **D1**, the public-repo question. Untouched.
- The `V1`/`V2`/`V4`/`V6` half of the loader defect — registered in rev38's changelog. **Symptom is live:** `V4` currently BLOCKs 14× against batch-01's frozen May LLRs.
- No `dev-flow-lessons` catalog entry for rev38 — no *control* changed, so procedure step 2 did not require one. Arguably a real lesson; registered for the close.

---

## 10 · Test ledger

`base = 2684 passed / 2 skipped / 21 deselected / 3 xfailed` (batch-84 close). `post = base − D + A`,
reconciled at every gate. **D = 0, A = TBD** — nothing written yet.

---

## 11 · Decision log

See §3. Entries mirror `state.json.decisions_log` and are carried to the close and the vault at sync.
