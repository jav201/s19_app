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
| A1 | not fired | judged — the Load picker, the confirmations and the progress indicator are planned as screens/widgets inside the existing `screens.py` / `app.py`; no module is created and no boundary moves. Re-evaluated at ARQ if the recent-sources store needs a module |
| A2 | fired | judged — the increments touch `app.py`, `workspace.py`, `screens.py`, `services/change_service.py`, `services/manifest_writer.py`, `services/variant_execution_service.py`: ≥2 modules |
| A3 | fired | probe `grep -rln "project.json\|read_project_manifest" s19_app` → `app.py`, `screens.py`, `flow_persistence_service.py`, `manifest_writer.py`, `report_addendum.py`, `report_service.py`, `variant_execution_service.py`. D3 (per-file digests), D2 (active variant after save-back) and D4 (active document) add `project.json` keys that these readers consume |
| A4 | not fired | judged — increments are planned sequential, one worktree each, merged in order (batch-99 lesson: parallel lanes conflicted on the test-id registry) |
| B1 | fired | probe `grep -rl "LoadFileScreen\|SaveProjectScreen\|LoadProjectScreen\|copy_into_workarea\|_handle_load_project\|_handle_save_dialog" tests` → 116 files; G-005 re-pins `test_unified_write::test_tc018…` and `test_tui_patch_editor_v2::test_at031b…`, owned by older batches |
| B2 | not fired | judged — no file changes location; D7 narrows where a project may be saved, it moves nothing |
| B3 | not fired | probe `grep -rl <source> tests/goldens` for `workspace.py`, `manifest_writer`, `variant_execution_service`, `screens.py`, `app.py`, `change_service` → 0 files each (snapshot SVG cells are named in B1/D1, not goldens) |
| B4 | fired | `project.json` is written by Save project and read by Load project, the reports and flow persistence (A3 probe) — output-then-consume ATs owed |
| C1–C5, C7 | not fired | judged — no auth, secrets, external integration, sensitive data, database or network surface |
| C6 | fired | judged — typed paths, project names and manifest contents are untrusted input (names sanitised, paths contained, `project.json` parsed) |
| C8 | fired | judged — file and project names from disk are rendered in Textual widgets (markup injection in the picker and the result notice) |
| D1 | fired | judged — the Load dialog, Save project dialog, confirmations, focus and progress change what the user sees and touches |
| D2 | not fired | judged — the prototype round runs in the real Textual app (copy of the tree), the target technology |
| E1 | fired | judged — 12 planned increments |
| E2 | fired | judged — the defects lose or contaminate saved work silently (PH-1, PH-2, PH-4, PH-5) |
| E3 | not fired | judged — internal tool, not a client deliverable |
| F1 | not fired | `V7`: bundle identical to its manifest at `2026-10-12-rev102` |
| F2 | not fired | judged — `BACKLOG-CODE.md` refreshed at batch-99's close (2026-10-26) and on this batch's opening (F6 routing) |

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
