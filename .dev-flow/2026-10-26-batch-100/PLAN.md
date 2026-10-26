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
| Last updated | P2 · 2026-10-26 |
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

ARQ (2026-10-26). P0 closed on the operator's verdict (`design/veredicto-b100.json`). D1–D7 all took the recommended option. The D2 note, "the switch to the latest saved image must be announced", became prototype surface P-E.

ARQ (`design/ARQ-batch-100.md`, the batch-100 rows in `docs/architecture.md`) is approved with conditions:
- Increments 8, 9 and 12 are split, which gives 15 increments, run sequentially.
- P-E is in the round.
- The orchestrator ruled on O-1..O-11 (ARQ §10.1).

The prototype round (P-A..P-E) is being built in `prototypes/load_projects/`, which is not committed. Owed next: P1 requirements. The UI stories stay REFINE until the round's verdict.

## Objective

A project restores exactly what was saved, or names what it could not. Load offers what is already loaded and opens projects. Nothing the user has not saved is replaced without a question, and long actions show that they are working.

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| P0 | done | premises at `1d677ba`; verdict D1–D7 |
| ARQ | done | `design/ARQ-batch-100.md`; approve with conditions (splits, P-E, O-1..O-11 ruled) |
| P1 | done | `01-requirements.md` (3060d66): US-153..168, HLR-163..178, 58 LLR, 56 TC, 19 AT; Q-1..Q-7 ruled (decisions_log) |
| P2 | in review | architect, qa-reviewer, security-reviewer, ux-reviewer, round 1 |
| Prototype round | awaiting verdict (`prototypes/load_projects/load_projects.html`) | P-A Load dialog · P-B confirm · P-C Save project · P-D progress · P-E Load result |

## Roadmap + increment plan

Sequential, one Kimi K2.8 worktree per increment, ≤4 SOURCE files each (ARQ §8). The hard order is ARQ §8: 1→6, 2→11, 3→8a/10, 5→10→11, 6→7→8a, 9a→9b, 12a→12b. Inc 6 and Inc 7's display wait for the P-E verdict.

| Inc | What | Findings | Source files | Gate |
|---|---|---|---|---|
| 1 | byte-identical reuse in `copy_into_workarea`; G-005 re-pin tc018/at031b | M-1, G-005 | workspace (+ app) | free |
| 2 | Save project guards: sanitised-name clash refused with a notice, long name, reserved names case-folded, cleanup | M-4, M-7, reserved, L-3 rest | app, workspace | free |
| 3 | `_reset_project_session()` seam: a project load starts clean | PH-2 | app | free |
| 4 | focus lands on a visible window after a load | CW-U-2 | app | free |
| 5 | Save project writes the in-memory image (emitter + verify) | PH-1, D1, O-5, O-6 | app, change_service | D1 ✓ |
| 6 | save-back becomes `active_variant`; every project writer rewrites the manifest | PH-4, D2, O-1, O-10 | app, variant_execution_service | D2 ✓ + P-E |
| 7 | `files` digests, Load lists every problem, private manifest staging | PH-5, L-4, D3, O-2, O-11 | manifest_writer, variant_execution_service, app | D3 ✓ (+ P-E display) |
| 8a | active change document recorded and reopened | M-2, D4 | app, manifest_writer, variant_execution_service, project_gather_service | D4 ✓ |
| 8b | save-as copies every project sub-folder; A2L-only opens; save only inside the work area (handler) | M-3, M-6, M-5, D5–D7, O-4 | app, project_gather_service | D5–D7 ✓ |
| 9a | recent-sources store, shared work-area lister, project path routing | L-2 | workspace, app | free |
| 9b | the Load dialog | Load request, D10, CW-U-12/13, markup off | screens, app, styles | P-A |
| 10 | confirm before replacing unsaved work (image, project, dirty flow) | CW-U-5, O-3 | screens, app (+ styles) | P-B |
| 11 | Save project dialog: real name, clash/reserved/pending lines, no Browse… | M-4, D7 dialog, CW-U-12/13, O-9 | screens, app (+ styles) | P-C |
| 12a | progress indicator (begin/step/end, elapsed) | N5 | app, styles (+ screens) | P-D |
| 12b | project load, Save project, A2L parse on workers | N5, O-7 | app (+ flow_screens) | P-D |

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-10-26 | Kickoff: autonomy as batch-99, push to main, G-005 reuse, delete `b99-*` | operator answers (header) |
| 2026-10-26 | D1–D7 all recommended; D2 announcement → P-E | operator verdict `design/veredicto-b100.json` |
| 2026-10-26 | ARQ conditions accepted; O-1..O-11 ruled by the orchestrator | standing authorization; ARQ §10.1 gives each reason |
| 2026-10-26 | Sequential increments, no parallel lanes | batch-99 lesson (registry conflicts); A4 not fired |

## Risks / watch-items

- `app.py` is in 14 of 15 increments · certain · sequential merges, one worktree each.
- `project.json` gains keys read by 3 modules · medium · additive keys only, no `schema_version` bump, old projects open with a notice (ARQ §3).
- Whole-tree guards (import census, snapshot cells, id registry) missed at increment gates in batch-99 · high · run them at EVERY increment gate, plus `devflow-validate --brief` at every gate.
- `current_a2l_data` is never cleared (ARQ §2, code-read) · medium · covered by Inc 3's `vars(app)` comparison AT.

## Conventions honored

- Max 4 SOURCE files per increment; Kimi K2.8 implements, an independent reviewer checks.
- Chat in Spanish, records in English; no operator name in the repo; `prototypes/` never committed.
- Tests in a worktree run with `PYTHONPATH=<worktree>` (pip -e imports the main checkout).

## Out-of-scope carries

- Code-Wire F6 findings (diff report): `BACKLOG-CODE.md` §Routed 2026-10-26 F6, proposed for batch-98.
- Integrity mediums/lows and Code-Wire mediums: `BACKLOG-CODE.md`.

## Gate notices and runtime absences

- **P0 gate run** (`devflow-validate.py --brief .`, exit 0, 0 block · 609 notice). The NOTICEs are the template-placeholder families of artifacts not yet written (V34, V36–V38, V41, V43–V51, V54), each closed when its station writes the artifact. Also: V42 deferral markers in sealed historical records, V53 as a census count, and V62 for this section's seed text, which is now filled.
- **ARQ gate run:** exit 0, 0 block · 604 notice, the same families. The atlases were regenerated before the commit (batch-99 lesson, `BACKLOG-PROCESS.md`).
- **Every later gate runs the validator before its `--decision`.** This is the batch-99 carry: its close found 99 record BLOCKs, unread since P0.
- **Runtime absences:**
  - The named reviewer roles (`architect`, `qa-reviewer`, `security-reviewer`, `code-reviewer`, `ux-reviewer`) are available as sub-agents, so the reviews are independent.
  - The implementer is Kimi CLI (`kimi-code/kimi-for-coding`, K2.8), an external runtime. No Kimi session reviews its own work.
  - V15, V16 and V17 are `not-run`, because they cannot run from a bundle (no canon tree, no checkout table, no hook in a bundle `settings.json`). V30 runs half.

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| <command> | <date> | <result> |
