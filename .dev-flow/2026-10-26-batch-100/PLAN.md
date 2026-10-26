# PLAN — s19_app — Batch 2026-10-26-batch-100

> **Artifact language.** Canonical **English scaffold**; generate in the batch's language.
> **Owed in.** `core` ✓ · `full` ✓
> Seeded by `/dev-flow-init` step 4 at both levels; the living plan is owed at every gate
> that follows (`/dev-flow` §Living plan is the rule's home).

> **Field guide:** `templates/guides/plan-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.
> **Two header labels are read literally and are never translated:** `Standing authorization` and `Last updated`; the field guide names their readers.

The living compendium of this batch: where-we-are · objective · per-story/per-station status ·
roadmap + increment plan · key decisions · risks/watch-items · conventions honored ·
out-of-scope carries · test ledger · decision log (the human-readable mirror of `state.json`).
**Create at batch open and update at every gate and significant checkpoint** — the
orchestrator presents the full plan in-conversation at each phase gate.

## Header

| Field | Value |
|---|---|
| Project | s19_app |
| Batch | 2026-10-26-batch-100 |
| Objective | The Load + projects batch: one Load dialog that offers what is already loaded and opens projects, and a project that restores what was saved or says what it could not. Scope: the project round-trip findings of INVESTIGATION-project-roundtrip-2026-10-23 still open (PH-1 Save project drops a pending patch, PH-2 load over a project leaks its A2L/MAC/patches, PH-4 save-back opens the unpatched original, PH-5 manifest problems ignored; M-1..M-7, L-2..L-4), the Load dialog requests (a picker of work-area files and recent sources, Load opens projects, Enter-to-load D10), the G-005 save naming (byte-identical reuse, tests re-pinned), the Code-Wire UI items CW-U-2, CW-U-5, CW-U-12, CW-U-13, the reserved project name, and the progress indicator for long actions (N5 reopened). UI changes go through a prototype round with the operator's verdict before implementation. |
| Last updated | P0 · 2026-10-26 |
| Standing authorization | Asked at the kickoff, 2026-10-26; the operator chose, quoted from the answers: autonomy "Igual que b99" (autonomous with exceptions: stop on a HIGH finding or an operator decision; the orchestrator plans and Kimi K2.8 implements in an isolated worktree; commit and push to main at each close; max 4 source files per increment; the prototype round waits for the operator's verdict before implementation); merge "Push directo a main" (each increment lands on main after independent review, no PR); G-005 "Reusar + re-pinear tests"; the 13 local `b99-*` branches "Borrarlas" (done, after checking their content is on main). Carried batch rules from the operator's standing instructions: chat in Spanish, records in English; no operator name in the repo; region extraction described only as memory-region extraction; do not commit `prototypes/`. Every decision the orchestrator takes instead of asking is recorded in this plan's decision log, `state.json.decisions_log` and the post-mortem, and reaches the vault at sync. |
| First gate | `devflow-validate.py --brief .` at P0 open → exit 0, `0 block · 609 notice · 43 not applicable`; `V7` reports the bundle identical to its manifest at `2026-10-12-rev102`. |
| Premises / RC-1 | RC-1 (a): `git fetch origin`; `origin/main` = `HEAD` = merge-base = `1d677ba39d2c6aaf09f1ca7e623197065f0b8958`, so `base_ref` is that commit. RC-2: `git ls-remote --exit-code --heads origin main` answered `1d677ba…`. RC-1 (b): every finding in scope is re-executed at `1d677ba` before it becomes a story (`evidence/p0-premises/`), because batch-99 closed some neighbours (PH-3, L-1, CW-U-1, CW-U-3). |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not.

| Id | Verdict | Probe output |
|---|---|---|
| <A1 / B1 / …> | <fired / not fired> | <the probe run and what it printed> |

## Where we are

P0 intake (2026-10-26). The batch was opened by rollover from batch-99 (`rollover_batch100.py`), and the kickoff answers are in the header. The P0 premises were re-executed at `1d677ba` on a `git archive` snapshot by qa-reviewer (`evidence/p0-premises/`). PH-3, L-1 and L-3 are already closed by batch-99. PH-1, PH-2, PH-4, PH-5, M-1..M-7 (M-5 partly), L-2, L-4, CW-U-2/5/12/13, the Load-dialog request, the reserved project name and the G-005 pins all still reproduce. The plan and its decisions page are `design/plan-b100.html`: 12 increments. 1–4 are free, 5–8 wait for D1–D7, and 9–12 wait for the prototype round (P-A Load dialog, P-B confirm before losing work, P-C Save project dialog, P-D progress). Owed next: the operator's verdict on D1–D7, the prototype round (built in `prototypes/load_projects/`, not committed), then ARQ and P1.

## Objective

<the batch objective, restated>

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| <US-NNN / station> | <status> | <notes> |

## Roadmap + increment plan

<the increments this batch expects, in order>

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-26 | <decision> | <reason> |

## Risks / watch-items

- <risk · likelihood · mitigation>

## Conventions honored

- <convention>

## Out-of-scope carries

- <what this batch deliberately does not do, and where it is tracked>

## Gate notices and runtime absences

<per gate: each NOTICE it printed and why it stands (`stations/core-runbook.md` §*Expected NOTICEs*); once: each mechanism `SKILL.md`'s gate step 5 found unavailable on this runtime, and each rule recorded `not-run`, with the reason>

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| <command> | <date> | <result> |
