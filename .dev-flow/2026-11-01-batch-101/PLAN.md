# PLAN — s19_app — Batch 2026-11-01-batch-101

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
| Batch | 2026-11-01-batch-101 |
| Objective | Release hardening for v1.0.0: fix the user-guide findings that block a release (F-01..F-51, docs/user-guide/DOSSIER.md section 5), the 5 UX majors of batch-100's expert inspection (UX-I-01, -06, -10, -12, -13) and the UX-I-17 emphasis rule, R1-P1 (the Save project margin), the in-app help and README text that describes absent features, the deferred post-close CI confirmation of batch-100, and the serial marking of timing-bound tests (G-015); performance with ~10 MB images (F-15, F-23) gets an explicit in-scope or deferred decision. UI changes go through a prototype round with the operator's verdict before implementation. |
| Last updated | <the station id at this update, then the day: P2 · YYYY-MM-DD> |
| Standing authorization | <none — every gate is asked; or the commission, quoted or cited (runtime cannot prompt)> |
| First gate | <the first gate run's exit code and what its `V7` line reported> |
| Premises / RC-1 | <the verified `origin/main` tip, or: no origin — RC-1 not possible, local tip SHA; then each premise the batch rests on> |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not.

| Id | Verdict | Probe output |
|---|---|---|
| <A1 / B1 / …> | <fired / not fired> | <the probe run and what it printed> |

## Where we are

<one paragraph: station, what the last gate decided, what is owed next>

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
| 2026-11-01 | <decision> | <reason> |

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
