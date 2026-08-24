# PLAN · batch-87 — D-II re-author (pilot IFC record) + IFC surface #3 (`workspace_body`)

**Living compendium. Updated at every gate and significant checkpoint.**

## Where we are

- **Station: P2 (cross-review) — P1 approved (D-87-3), reviewers dispatched.**
- P1 outcome: full record authored (Opus 5 architect + qa 01b plan, parallel). D-87-A ruled **(a)
  in-place** by two executed measurements (`_ifc_corpus` extends, census keyed to the pilot's own
  path/line). **Three records edited, forced by balancing** (pilot §5.3→pointer + §8 six-output
  block; batch-86 re-export block updated; batch-87 full record). `workspace_body` declared with
  42 outputs (31 re-exports; PARENT `workspace_shell`, SYSTEM refuted at app.py:1919). Premises
  9 TRUE / 6 FALSE (all load-bearing FALSEs recorded; the D-86-E-resolution intake observable
  WITHDRAWN — the duplication is structural, V13 greps each literal once per declaration).
  Validator `0 block · 284 notice · 15 n/a` (+29 V13 surface-#3 addresses, +1 V22, all accounted);
  UNPARSED census 2→1 ([IFC] GONE, BATCHES negative control survives). G-87: 8 GREEN, G8 OPEN
  (P3-owed canon seeding). Orchestrator re-verified: validator line, census, file set, source pin,
  six-output ids — all confirmed.
- **Scope growth, measured and declared (not creep):** the brief anticipated 1 record edit; the
  balancing rule forces 3, and the honest surface-#3 declaration is 42 outputs. Both stories
  unchanged; the mechanism cost more than anticipated. Headline R-87-2 (re-export compounding,
  39% of corpus stray pairs at depth 3) is a corpus-wide convention question deliberately NOT
  decided unilaterally — routed to close/backlog, to be ruled before surface #4.

### Earlier (P0)
- Scaffold cut, gate packet presented, approved D-87-1.
- Branch `claude/batch-87-ifc-reauthor-surface-3` off `origin/main` tip **`943e54a`** (RC-1 PASS,
  executed 2026-08-24: merge-base == tip; fetch clean).
- Flow **2026.08.24-rev45 · `09bea075fc183f8b`** — C-45 PULL verified (V7 green in the ground-check
  validator run; selftest exit 0, 192 arms).
- Gate env: conda **s19env** (collection verified this session: 2714/2735, 21 deselected).

## Objective

Discharge **D-II** (operator-ruled 2026-08-24: **re-author**) and declare **surface #3** in one
batch: re-author the batch-85 pilot contract for `loaded_panel` to the batch-86 exemplar format with
the D-A six-output split, clearing the last `[IFC]` UNPARSED census item and the D-86-E duplication;
declare the shell `workspace_body`'s Part B contract, retiring the last undeclared PARENT V12 names.
Zero source files. Exemplar: `.dev-flow/2026-08-24-batch-86/` (format) + its `05-close.md` §6
(method verdict). Discipline: **execute-first (C-39)** — probes run before thresholds are written;
the pilot's seven orchestrator defects all came from the reverse order
(`HANDOFF-batch85-ifc-pilot-2026-08-21.md` §4).

## Standing authorization (asked at kickoff, per-batch)

- **Operator (2026-08-24, this session, via gate question):** D-II/scope: *"Re-autorar + superficie
  #3 juntos"*; authorization: *"Como batch-86: autónomo — gates auto-aprobados CON evidencia; merge
  lo concedes tú [el operador] explícitamente al cierre."*
- Effect: autonomous end-to-end; every gate self-approved WITH evidence and recorded; **stop at
  "PR opened, CI green"** — merge only on explicit post-close operator grant (batch-86 pattern).
- **Subagents on Opus 5** (standing operator directive, batch-86 P3).
- Artifact language: **English** (conversation Spanish).

## Mode

**core** — same C-50 ruling as batch-85/86: the IFC record's declared home is
`.dev-flow/<batch>/01-requirements.md`, a Phase-1 artifact `/fast-dev-flow` has no phase for.

## Stations & status

| Station | Status | Artifact |
|---|---|---|
| P0 intake | **at gate** | `01-requirements.md` §2.6 (this commit) |
| P1 requirements | pending | full record per exemplar, probes-first |
| P2 cross-review | pending | `02-review.md` |
| P3 increment(s) | pending | canon mirror seeding + record finalization |
| P4 validation | pending | `04-validation.md`, one complete gate run (C-25) |
| P5 close | pending | `05-close.md` (core mini-close) |

ARQ / PDR / DDR: **not activated** — no trigger in their families fired (see below).

## Triggers (evaluated 2026-08-24 at intake; families C & F re-run at every gate, B at every cut)

| id | Verdict | Probe (executed) |
|---|---|---|
| B1 | **not fired** | ids the batch edits: `grep -rl "R-TUI-113" tests/` → 0 files; `R-TUI-114` → 0. (`loaded_panel` 12 / `workspace_body` 24 test files are CONSUMER-census input for the contracts, not touched symbols — batch changes no code.) |
| B2 | not fired | no file moves planned (spec-only; plan = record + canon mirror edits) |
| B3 | not fired | goldens capture app output (`tests/goldens/batch35|64|71`), none reads `.dev-flow` (`grep -rl "dev-flow" tests/goldens/` → 0) |
| B4 | **FIRED** | the record is consumed by `devflow-validate.py` (V10–V23) + the Atlas id-scanner (corpus: 63 requirement files, `ATLAS-ORPHANS.md:2`) → **C-12**: the black-box AT drives the validator over the authored record (batch-86 pattern) |
| A1–A4 | not fired | no module/boundary/interface change; no parallel increments planned |
| C (security) | not fired | no auth/secrets/integration/markup-mode change; spec-only. Re-check over the diff at every gate |
| D (interaction) | not fired | nothing the user sees or touches changes |
| E (size/risk) | not fired | 2 stories, ≤2 increments planned, not a client deliverable |
| F (flow currency) | not fired | rev45 == manifest (`flow_hash 09bea075fc183f8b` verified); backlog refreshed at batch-86 close (2026-08-24) |

## Key decisions log (mirrors `state.json`)

| id | Date | Decision |
|---|---|---|
| D-II | 2026-08-24 | **Operator ruled: re-author** the pilot record (evidence: 3 format defects solved by exemplar; last IFC UNPARSED item; D-86-E duplication; D-A prescribes the shape). Measurements stay valid history. |
| D-87-scope | 2026-08-24 | Operator: one batch for both stories (re-author + surface #3). |
| D-87-A | 2026-08-24 (P1) | **Ruled (a) in-place** — two executed measurements (synthetic two-batch corpus: `_ifc_corpus` extends, no removal, V19 collision NOTICE, no parent set balances both declarations; census keyed to the pilot file's own path/line). Full evidence in batch-87 record §2.8/§5. |
| D-87-B…G | 2026-08-24 (P1) | Ruled in-record (bimodal outputs → 42-output superset; registry question D-87-F recorded, not silently assumed; see record §5 decisions table). P2 attacks D-87-B/D-87-C hardest per author's own flag. |
| D-87-2 | 2026-08-24 | qa fold relayed to the in-flight author as hypotheses-to-verify (C-43); author confirmed items 1–3, 5 by execution, executed 4 and 6 independently. |
| D-87-3 | 2026-08-24 | **P1 approved (autonomous)** — no nameable gap: Coverage (both stories realized in the record, dual chains planned, G8 explicitly P3-owed), Certainty (12 live RED arms raised+discharged on the real corpus; 6 FALSE premises caught and dispositioned), Evidence (validator line + census + pin re-verified by orchestrator). Scope growth measured and declared above. |

## Risks / watch-items

1. **`_ifc_corpus` same-COMPONENT merge is unarmed** — probe before any authoring touches
   `COMPONENT : loaded_panel` (D-87-A). A wrong guess forks the contract, the exact failure D-86-E
   avoided.
2. **Editing a closed batch's artifact** (if D-87-A → in-place): must not disturb what batch-85's
   record MEASURED — the re-author replaces the contract sections only; `05-close.md`/PLAN stay
   frozen. Any edit is cited from this batch's record (traceable, not silent).
3. **C-56 discipline** — this batch's own packets/close are corpus input: mutations described by
   position+operation, never pasted; no dotted-range shorthand; enumerate ids.
4. **Foreign WIP in the primary checkout** (memmap2 prototype, `build/`, `prototypes$f.png` —
   another session's, untracked): REPORT only, never sweep (C-44). Explicit adds only.
5. **V22 debt must not grow** — canon mirror seeded in the same increment that mints ids
   (batch-86 closed at 276; batch-87 target ≤276 post-close).
6. **6 pre-existing order-dependent flaky nodes** (lane-A carry): expected in the P4 whole-suite
   run; dispositioned as pre-existing per batch-86 diagnosis if they recur — NOT this batch's
   regressions (batch touches 0 source files; pin verified at every gate).

## Conventions honored

Exemplar format (pair-based thresholds over `(output_id, file)` pairs · split heterogeneous
populations · scoped statements · `SURFACE:` field · M-10 search-width guard class) · C-39
execute-first · C-19/C-25 one complete gate run, never piped through `tail`, ANSI stripped before
any `grep "FAILED"` · C-40 mutations on copies, restore proven by hash · notice convention (⚠/✗/✓
with citations).

## Test ledger

Baseline (batch-86 close): 2702 passed · 6 failed (pre-existing order-dependent, dispositioned) ·
3 skipped · 3 xfailed / 2714 selected. Batch-87 expected delta: 0 code tests; record-level gates
(G-87) + validator/Atlas runs are the acceptance surface. Ledger reconciled at each gate.

## Out-of-scope carries (stated at open)

- Batch-51 matrix phantom dotted-range tokens (lane A carry — flow-side tokenizer fix landed rev45;
  the matrix's own cleanup stays queued).
- The 6 flaky nodes' diagnosis batch (lane A).
- Seeding tranches of the 276 unreflected ids beyond what this batch's stories touch.
- PDR/DDR id vault-side convention (needs a first real PDR).
- Stale worktree `dev-flow-68a67d` + foreign memmap2 WIP fate (housekeeping, operator).
