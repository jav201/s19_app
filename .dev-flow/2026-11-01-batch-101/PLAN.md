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
| Objective | Release hardening for v1.0.0: fix the user-guide findings that block a release (F-01..F-51, docs/user-guide/DOSSIER.md section 5), the 5 UX majors of batch-100's expert inspection (UX-I-01, -06, -10, -12, -13) and the UX-I-17 emphasis rule, R1-P1 (the Save project margin), the in-app help and README text that describes absent features, the deferred post-close CI confirmation of batch-100, and the serial marking of timing-bound tests (G-015); performance with ~10 MB images (F-15, F-23) gets an explicit in-scope or deferred decision. UI changes go through a prototype round with the operator's verdict before implementation. **Narrowed at P0 by the operator's rulings of 2026-11-01** (see Key decisions): every UI row goes to the backlog as a known failed check, and the strict-EARS canon swap enters as Inc 1. |
| Last updated | P3 · 2026-11-06 |
| Standing authorization | The operator's commission, quoted: «Quiero que continues hasta terminar los incrementos, las decisiones, tomalas con tus recomendaciones.» · «Si, sigue con (3), usa a kimi 2.8 para apoyarte con la carga de trabajo.» · «Por ahora pausa deepseek, está ya corto en tokens, usa sólo kimi.» (2026-11-01) |
| First gate | <the first gate run's exit code and what its `V7` line reported — owed by the orchestrator. An architect probe at P0 (`devflow-validate.py --brief .`) exited 1 with `4 block · 708 notice · 41 not applicable`; the 4 BLOCKs are V20 (`.dev-flow/_derived/ATLAS-{BATCHES,IFC,ORPHANS,TRACE}.md` differ from the corpus)> |
| Premises / RC-1 | **RC-1 (a):** `git ls-remote --exit-code --heads origin main` → `e273181aaa7692eaf6a1e40141120a92dad5097e` = worktree `HEAD`. `state.json` `base_ref` = `7717394` (the merge before the rollover commit; `e273181` changes `.dev-flow/` and `.gitattributes` only). **RC-2:** origin answered; its newest commit is dated 2026-11-01T22:48:42-06:00, under one day old. **RC-1 (b):** each in-scope finding was located in code at `e273181` by the triage, and spot-checked (`p0/PLAN-draft.md` §a). Each increment's E1 re-runs the already-shipped check against the new canon. **Premises:** (1) the strict-EARS canon (`s19w/review/S<n>-ears-strict.md`, 2612 rows, reconciled with batch-100 at `e279c8b`) replaces the canon in Inc 1; (2) Kimi K2.8 is the only worker model; (3) the LAN Linux host runs the full suite in about 1 h. |

## Triggers

The trigger evaluation `state.json`'s `triggers.record` points at: one row per trigger evaluated, fired or not.

| Id | Verdict | Probe output |
|---|---|---|
| A1 | fired | judged — Inc 1 adds the `docs/requirements/{history,review}/` tree and the junit → TC-record generator. No product module is created |
| A2 | fired | judged — the increments touch `tui/app.py`, `tui/services/{change_service,variant_execution_service,diff_report_service,before_after_service,flow_execution_service,flow_persistence_service}.py`, `validation/rules.py`, `tui/a2l.py`, `tui/issues_view.py` and other modules: ≥2 modules |
| A3 | fired | judged — F-02 changes the engine's issue output, consumed by `issues_view.py` and the synthetic release case. F-42 changes the diff generators' signature, consumed by `before_after_service.py`. F-46 changes the saved flow file's `name`, consumed by the loader. F-29 changes `extract_memory_segments` output, consumed by `segment_split_view.py` |
| A4 | fired | judged — parallel worktrees are planned: Inc 1 ∥ Inc 2, then Inc 3 ∥ 7 ∥ 8 ∥ 11 ∥ 13 ∥ 14 |
| B1 | fired | probe `grep -rl <symbol> tests \| wc -l` → `run_chain_set` 8, `WINDOW_HELP_SECTIONS` 5, `extract_memory_segments` 3, `_save_project_files` 3, `parse_crc_config` 3, `_patch_editor_load` 2, `VariantHelpScreen` 2, `MAP_KEYS_LINE` 2, `RECOGNIZED_A2L_BLOCKS` 1, `set_a2l_parameters` 1, `action_view_main` 1, `_conflict_marks` 0. These files belong to older batches |
| B2 | fired | judged — Inc 1 moves the old canon to `docs/requirements/history/`. Inc 8's recommended F-49 option moves the previous external-step copy to `_N`. Reader census owed for both |
| B3 | fired | probe `grep -rl "Diff report" tests/goldens` → `tests/goldens/batch35/at054b-before-after-report.md` and `.html`; Inc 7 (F-42, F6-1) changes them |
| B4 | fired | judged — the CRC Designer's template is read by the flow CRC block (F-28). The saved flow file is read by Load flow (F-46). The before/after report is read by the operator. junit is read by the TC-record generator (Inc 1). Output-then-consume ATs owed |
| C1–C5, C7 | not fired | judged — no auth, secrets, database or network surface. No external integration: F-50's Terminal-mode command execution is deferred (KF-101-F), and `gh` is used only by the process |
| C6 | fired | judged — change/check documents, A2L files, CRC templates and flow files are untrusted input parsed by the fixes (F-01, F-02, F-28, F-29) |
| C8 | fired | judged — file-derived names are painted or written: A2L names re-resolved into Check Editor rows (F-27); file names in the status line (F-13, SE5-12a-2); names in the before/after report's HTML (F-42) |
| D1 | fired | judged — the fixes change what the user sees or touches without changing layout: status text (F-13), dropdown contents (F-06), the before/after offer (F-05), scroll position (F-07), help and legend text (F-16, F-37), the `a2l(n)` count (F-29), `esc` on the Reports viewer (F-51). No prototype round (operator ruling); the UX lens checks against the approved design |
| D2 | not fired | judged — no prototype round in this batch |
| E1 | fired | judged — 14 planned increments |
| E2 | fired | judged — the v1.0.0 release baseline. F-49 makes a flow read stale evidence silently, F-01 refuses valid documents, F6-1 truncates every written diff report (HIGH), and Inc 1 replaces the requirement base |
| E3 | not fired | judged — internal tool, not a client deliverable or regulated context |
| F1 | not fired | judged (provisional) — the P0 architect probe `devflow-validate.py --brief .` printed no flow-identity finding. The orchestrator confirms with the first gate's `V7` line |
| F2 | not fired | probe `git log -1 -- .dev-flow/BACKLOG-CODE.md` → `e259b93 2026-11-01T21:38:23-06:00 batch-100 close: … backlog routing` (refreshed at the last close) |

## Where we are

- **Station:** P3 (increments), 2026-11-06.
- **Merged and pushed:** Incs 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12b, 13, 14, 15, 16 (decisions in `state.json`; merge evidence `evidence/merge/`).
- **In E4:** Inc 10a (`b101-inc10`; rulings E4-R1 … R5 being applied). **Ready for E4 (E1–E3 closed):** Inc 10b (`inc-10b/`); Inc 12 (`inc-12/`, `b101-inc12`; split at E3 from 12b, D-5 B). Merge order: 10a → 10b → 12. **Merge verification (operator order 2026-11-06):** partial sets only (new/edited files, QC-BC, other importers, law guards, serial_timing); the full suite runs once at batch end.
- **Next:** the serial `app.py` chain 5 → 6 → 9 → 10 → 12; before Inc 10's E1, the LAN check of Inc 5 ruling D-4 (A2L explorer value column and Split/Join after an in-place write).
- **Batch end:** full battery, canon fold, review page, v1.0.0 tag.

## Objective

Make v1.0.0 releasable on its non-UI defects:
- every non-UI finding of the user guide is fixed or ruled;
- the help and README describe the app as shipped;
- the Save project margin is measured, then fixed or re-ruled;
- the test suite runs reliably in parallel with the timing arms run apart;
- batch-100's deferred CI confirmation is recorded;
- the requirement base is the strict-EARS canon, with 29119-3 test-case records.

The UI rows are known failed checks for the next iteration.

## Per-story / per-station status

| Story / station | Status | Notes |
|---|---|---|
| P0 | in progress | triage verified; plan drafted; triggers evaluated (this file) |
| ARQ | in progress | this plan; app.py split ADR deferred (Key decisions) |
| Inc 1 … Inc 14 | planned | see Roadmap |
| 37 UI rows | known failed → backlog | `p0/known-failed.md`; rows KF-101-L/S/Q/V/M/P/F/K |

## Roadmap + increment plan

- **Pipeline (every increment):** E1 (strict EARS / 29148 rows in the **new** canon) → E2 (Code-Wire graph) → E3 (code-free design review) → E4 (Kimi K2.8 build ∥ independent tester) → E5 (change validation, with QC-BC).
- **Caps:** ≤ 4 source files under `s19_app/`; tests are uncapped.
- **Source of truth:** the full table, with canon rows and parallel-safety, is in `p0/PLAN-draft.md` §b.

| Inc | Title | Findings | Source files | Depends on |
|---|---|---|---|---|
| 1 | Canon swap and test-case records | strict-EARS canon replaces `REQUIREMENTS.md`; old canon → `docs/requirements/history/`; 29119-3 TC records; D0-8 | 0 (delivered by the requirements re-write session; merged by the orchestrator) | — |
| 2 | Test hygiene, timing arms and CI | G-015, SR12b-7, SR12b-7b, QC-TM, QC-OR, QC-BC, R2-CI, CI deferral, dwell flake `test_tc_b97_64` | 0 | merges after 1 |
| 3 | Save project margin; a vanished project folder | R1-P1, OBS-F2-1 (D11-72) | `app.py` | 1, 2 |
| 4 | Documents resolve symbols through the loaded A2L | F-01 (3 sites), T-03, T-04, T-12 | `app.py`, `change_service.py`, `variant_execution_service.py` | 3 |
| 5 | Check Editor keeps picks, names and expected bytes; **first:** CRC Designer coverage refreshes after an in-place apply (Inc 13 D-4 / SEC-3, integrity priority: designer CRC after the apply equals `zlib.crc32` of the new bytes) | F-26 (D9-12), F-27, D9-11, D-4 (Inc 13) | `app.py`, `screens_directionb.py` | 4 |
| 6 | Patch Editor document lifecycle | F-05 (D14-14), F-06 (D10-25, D9-15), F-40 (D9-10, D10-30), F-47 | `app.py`, `change_service.py`, `screens_directionb.py` | 5 |
| 7 | Before/after report names itself and its inputs; full hex windows in written reports | F-42 (D14-15), F6-1 (HIGH, co-located) | `diff_report_service.py`, `before_after_service.py` | 1 |
| 8 | Flow CRC block reads designer templates; external outputs stay current | F-28 (D13-23), F-49 (D15-17) | `flow_execution_service.py`, `crc_config.py`, `workspace.py`, `variant_execution_service.py`? | 1 (4 if the last file) |
| 9 | Confirm re-run writes no stray report; a saved flow keeps its name | F-45, F-46 | `app.py`, `flow_execution_service.py`, `flow_screens.py`, `flow_persistence_service.py` | 6, 8 |
| 10 | Hex navigation, unload state, Split/Join focus | F-07 (D4-2, D4-6), F-13 (D5-17, D5-19, D5-27), F-14 (D17-38, D6-21), F-18, SE5-12a-2 (co-located) | `app.py`, `segment_split_view.py` | 9, 13 |
| 11 | A2L validation and parsing | F-02 (D3-12), F-03, F-21, F-29, F-39 | `rules.py`, `issues_view.py`, `a2l.py` | 1 |
| 12 | Unreachable code; Reports viewer `esc` | F-33 (D7-10), F-34 (D6-12), F-35 (D9-8, D16-6), F-51 | `screens.py`, `app.py`, `screens_directionb.py`, `flow_screens.py` | 5, 6, 9, 10 |
| 13 | CRC Designer and Split/Join responsive at 10 MB | F-23, F-24 | `crc_designer_view.py`, `segment_split_view.py` | 1, 2 |
| 14 | Help, legend and README describe the shipped app | F-16, F-30, F-37 (D7-26), F-38 (D0-9..11), F-41 | `window_help.py`, `legend.py` (+ `README.md`, help census md) | 1 |
| 16 | Documentation hygiene (operator request 2026-11-05): stale, dead and duplicate docs | `p0/doc-inventory.md` groups D1 (CLAUDE.md, PROJECT_RULES.md, docs/engineering-rules.md, requirements.txt), D2 (docs/README.md, docs/overview.md, docs/diagrams/architecture.md), D3 (docs/architecture.md), D4 (archive four finished handoff/notes docs), D5 (REQ-crc.md + examples manifests), D6 (remove the retired `.fast-dev-flow/` and its 18 citations), D7 (comment-only fixes citing removed `prototypes/` files) | docs only; D7 touches comments in `legend.py`, `project_gather_service.py` | 14 (README/guide first); D7 after 14 |

**Order:**

| Step | What runs | Condition |
|---|---|---|
| 1 | Inc 1 ∥ Inc 2 | now |
| 2 | Inc 3 ∥ 7 ∥ 8 ∥ 11 ∥ 13 ∥ 14 | after Inc 1 and Inc 2 merge; at most 3 Kimi E4 lanes in flight |
| 3 | the `app.py` chain, serial: 3 → 4 → 5 → 6 → 9 → 10 → 12 | — |
| 4 | batch-end battery on the LAN host, CI, P4 | — |

**Prototype rounds:** none (operator ruling).

## Key decisions

| Date | Decision | Why |
|---|---|---|
| 2026-11-01 | **Operator:** the 37 "UI change = yes" rows leave scope. They are known failed checks in `p0/known-failed.md`, with one grouped backlog row per surface (KF-101-L/S/Q/V/M/P/F/K). No prototype round in batch-101 | Operator ruling (supersedes the a/b/c scope ruling; the a/b/c class stays as a note on each row) |
| 2026-11-01 | **Operator:** the strict-EARS canon replaces `REQUIREMENTS.md` as batch-101's first increment, together with the 29119-3 TC records. Every later defect increment cites and amends the new canon's rows | Operator-approved input from the requirements re-write session |
| 2026-11-01 | Help and README text that describes absent features is fixed by changing the text (F-16, F-30, F-37, F-38, F-41) | Operator ruling |
| 2026-11-01 | F-23 is **in scope** with measurable targets: 1 recompute per template load; 1 per 150 ms burst; recompute ≤ 3 s and Split/Join preview ≤ 2.5 s on the 10 MB demo image. Profile first, with no worker | The 10 MB image is the shipped demo case (`ch02-load.md:36`). A 2-min UI freeze blocks the task. The fix changes no render |
| 2026-11-01 | F-15 is **deferred** with the UI rows. Its target is recorded in `known-failed.md` | Operator ruling (F-15 is a UI row) |
| 2026-11-01 | R1-P1: profile `_save_project_files` first. Target ≤ 0.8 s alone (≥ 20 % margin, QC-TM); otherwise the bound is re-ruled with the profile cited | Backlog rule: the bound is not raised before the profile |
| 2026-11-01 | OBS-F2-1: refuse with the existing `Project sync NOT done …` / `A2L sync NOT done …` line and create no folder | Matches new-canon D11-72 (R-PROJ-002.12, .13). A silent re-created partial project is worse than a refusal |
| 2026-11-01 | F-27: re-resolve parameter names from the loaded A2L by address. No `.chk.json` grammar change | A grammar change is a one-way door for saved files. Re-resolving can be undone |
| 2026-11-01 | F-43 and F-44 are deferred past v1.0.0 as limitations; the help text is aligned in Inc 14 | Current behaviour is correct and documented (guide ch21.6, ch21.11). HTML twins and verdict columns are new report features (F-44 is L) |
| 2026-11-01 | F6-1 (HIGH, the written diff report cuts hex windows at 512 rows) is taken into Inc 7 | Co-located in `diff_report_service.py`. It is a wrong result in every written diff report, against R-CMP-004 |
| 2026-11-01 | The ADR on splitting `app.py` (batch-100 postmortem) is **deferred to before batch-102**, although this batch touches ≥ 4 `app.py` areas | A split inside release hardening is a large refactor. Mitigation: local edits, one `app.py` writer at a time, QC-BC at each E5 |
| 2026-11-01 | QC-TM, QC-OR and G-015 land in Inc 2 as test infrastructure. QC-BC is a standing E5 step in every increment | Later increments need the marker, the margin report and the oracle helper |

### Orchestrator rulings at P0 (2026-11-01)

- Plan accepted as drafted in `p0/PLAN-draft.md`: 14 increments, no prototype round; the 37 UI rows are known failed checks (`p0/known-failed.md`, BACKLOG-CODE KF-101-L/S/Q/V/M/P/F/K) for the next iteration, by the operator's ruling.
- **D13-20** (CRC engine mishandles `init` when `reverse` is true: a wrong result) joins **Inc 8** (same CRC files); **D14-10** (the Markdown diff report does not escape labels, paths, symbol names) joins **Inc 7** (same file). Both are non-UI correctness defects inside the batch's scope.
- The UI rows the architect flagged as wrong-result or blocked-task risks (UX-I-13, UX-I-10, UX-I-12, F-25, F-15, F-36, F-10/F-11) stay in the backlog per the operator's ruling; they are reported to the operator with their harm.
- Inc 1 (canon swap) is built by the requirements re-write session on branch `b101-canon` from e273181 (agreed 2026-11-01); its test-case records and status document come in a later increment from the same session. Defect increments cite the new canon's row ids (`s19w/review/S<n>-ears-strict.md` ids, unchanged at the swap) and report every added or changed row to that session.
- Worker model: Kimi K2.8 only (DeepSeek paused by the operator 2026-11-01); Opus designs, reviews, integrates. Pre-merge full suite on the LAN Linux host (pytest-xdist -n 8; timing arms serial).
- **D15-18** (a `flows/` or `flowsets/` junction lets a flow save land outside the work area; R-FLOW-FILE.11 / R-FLOW-SET.7; raised by Inc 1's security review) joins **Inc 9** with a RED arm; a **`SECURITY.md`** (reporting path, supported versions) joins **Inc 14**. Inc 1 owns TC-607's file-count constant and the registry guard files while it is open (2026-11-01).
- **Inc 15 (added 2026-11-02): Windows-only failures** reported by the requirements session's Windows run at e279c8b (serial, idle host, reproduce; pass on Linux): `tests/test_tui_patch_editor_v2.py::test_tc331_disable_guard_predicate_tracks_source_path` (NoMatches '#patch_editor_panel') and `tests/test_tui_flow_execution_b94.py::test_tc_b94_27_lane_binding_isolation_and_noop` (`{} == {0: 'variant_b.hex'}`). Diagnose first (test setup vs product); fix in the owning increment or as Inc 15. Evidence: s19w/test-cases/evidence/run-e279c8b-win-serial.log.
- `base_ref` 7717394 is correct: the rollover commit e273181 is the batch's own opening commit.

## Risks / watch-items

- **The canon swap changes the id space** under the flow validator and the registry guard. Likelihood: high. Mitigation: D0-8 in Inc 1; `devflow-validate --brief` after the merge, with no defect increment until no new BLOCK shows.
- **`app.py` is in 7 increments** (about 20,500 lines). Likelihood: certain. Mitigation: a serial chain and local edits; the ADR is owed before batch-102.
- **Inc 11 unfreezes `rules.py` / `a2l.py`** (TC-B94-18). Likelihood: medium. Mitigation: re-freeze at its close; B1 census.
- **Inc 7 re-pins the before/after goldens** (B3). Likelihood: certain. Mitigation: the re-pin is named in E1; diff-report goldens change only where F6-1 requires it.
- **F-49's fix changes what the project folder holds** (backlog A-01). Likelihood: medium. Mitigation: an E3 ruling, through the existing placement API.
- **The F-23 / R1-P1 targets may need a worker**, which would be UI. Likelihood: medium. Mitigation: profile first, re-rule with evidence, and send the worker variant to the KF review.
- **Kimi K2.8 is the only worker.** Likelihood: medium. Mitigation: at most 3 E4 lanes; Opus reviews every E4; Kimi records stay drafts until the V-check.
- **UI rows flagged above cosmetic** (F-15, F-25, F-36, UX-I-03, UX-I-10, UX-I-12, UX-I-13). This is an operator decision. Mitigation: the plan changes only on a ruling.
- **F-47 may not reproduce.** Likelihood: medium. Mitigation: no product change without a reproduced cause.
- **CI run 41372953464 may show new failures** beyond the 5 known ones. Likelihood: low–medium. Mitigation: Inc 2 routes each to its module's increment, or to a fix round before the first merge.

## Conventions honored

- At most 4 source files under `s19_app/` per increment; tests uncapped. `app.py` edits stay local.
- Design-first per increment (E1 → E5); the code-free design review (E3) comes before any code.
- New-canon row ids are cited in every E1. New or changed EARS rows go into the new canon (from Inc 1 on).
- TC records (`<R-id>/<n>`, status `verified` / `failed` / `not_run`) are generated from each merge gate's junit.
- **QC-BC at every E5:** when an increment changes the order or source of an observable, the gate greps `tests/` for every node that asserts it, and runs them.
- **QC-TM:** every timing arm reports its alone time and margin. A margin under 20 % is a gate finding. The clock stops on a product-emitted stamp.
- **QC-OR:** a status oracle collects every line painted since its trigger.
- Merge gate: the full suite on the LAN host (`-n 8 -m "not serial_timing"`, then `-m serial_timing` serially), then CI on push. Each CI run's FAILED set is compared with the previous run.
- Parallel worktrees only when the source files are disjoint. A4 is re-recorded when worktrees stack.
- English only. No personal names in code, tests or records ("the operator").

## Out-of-scope carries

- **37 UI rows:** known failed checks → `p0/known-failed.md`, rows KF-101-L, -S, -Q, -V, -M, -P, -F, -K.
- **F-43, F-44:** limitations, deferred past v1.0.0.
- **F-50's Terminal-mode command execution:** with KF-101-F.
- **Not taken:** every `s19w/review/CODE-CHANGES.md` item that neither coincides with an in-scope row nor is co-located with its fix. Two flagged for an early ruling: D13-20 (CRC engine `init` with `reverse`, a wrong result) and D14-10 (Markdown escaping in diff reports).

### Visible backlog — open `BACKLOG-CODE.md` rows that name batch-100, and where each lands

| Row(s) | Lands |
|---|---|
| R1-P1 · OBS-F2-1 | Inc 3 |
| SR12b-7 · SR12b-7b · G-015 · R2-CI · post-close CI confirmation (run 41372953464) · CI dwell flake `test_tc_b97_64` | Inc 2 |
| SE5-12a-2 (bidi control in the file-state line) | Inc 10 (co-located with F-13 in `_format_coexistence_status`) |
| UX backlog row (UX-I-02 … -20) · OBS-8b-2 (= UX-I-03) · OBS-9b-1 (= UX-I-16) | known failed → KF-101-L / -S / -Q |
| Validation gaps G-005, G-007, G-008, G-013 | batch-101 P4 re-check |
| T-03 · T-04 · T-12 (controlled audit; same root as F-01) | Inc 4 |
| F6-1 (HIGH, diff report 512-row cap) | Inc 7 |
| F6-2 · F6-3 · F6-4 | carry (not co-located trivially; F6-2 needs a real-flow integration TC) |
| Save into the open project that holds its own A2L is refused (pre-existing defect) | carry — flagged: it blocks a task |
| PR-6 (`load_selected_file`, 88 test calls) · SEC8a-2 · R19 / T-05 (`parse_change_document` raises) · T-06 · T-07 · T-08 · A-R14 · R-12 mutant | carry (candidates for v1.0.1; not in the objective) |
| SR12b-6 · R2-F2 (Save tail residuals) | carry (declared residual risks) |
| Inc 1 security / reviewer rows (`workarea_root`, R3-4, the three round-4 hardening items, SEC-3) · Inc 7 (SEC7-4 (b), R2-3) · Inc 8a (R2-1, R2-2) · Inc 8b (F7(b)/R-7, F4, F5 remainder, R2-1, R2-2, TOCTOU) · OBS-8b-1, OBS-8b-3, A3-15, A3-17, R12 cost · Inc 9a (CR9-1, CR9-2, CR9-5/SEC9-8, CR9-11, SEC9-5, OBS-9a-1) · Inc 9b/10/11 (Q6, S9b-5, A9b-R3-3, `_COLLIDING_PATH`, CR9b-05, UX loss, SEC9b-1 redirect, `architecture.md:670`, Q7, Q8, S10-04/SEC10-02, G-B F-4, A11-03, SE5-11-2, O-1) | carry — each keeps its own "What closes it". The 12 rows stranded on "the Inc 12a sweep" stay unrouted. The orchestrator flips the rows 12a fixed (postmortem Part A) |
| A-01 (writers into the open project bypass the manifest writer) · B-12 (device-name lists) · batch-99 D-3 (private staging seam) | carry. A-01 is read by Inc 8's E3 |
| Postmortem: `app.py` split ADR | deferred to before batch-102 |
| Postmortem: post-merge runs owed (CI of `66d1ea9`/`570b4b5`, TC-027 on `main`, `a2l.py` re-freeze, earlier-mutant re-runs) | the orchestrator, before the P0 gate. The `a2l.py` re-freeze is done at Inc 11's close |

## Gate notices and runtime absences

- **P0 architect probe:** `devflow-validate.py --brief .` → exit 1, `4 block · 708 notice · 41 not applicable`. The 4 BLOCKs are V20, the derived atlas files `.dev-flow/_derived/ATLAS-{BATCHES,IFC,ORPHANS,TRACE}.md`. They are owed a regeneration (`--atlas --write`) or a ruling before the P0 gate.
- **Runtime absence:** DeepSeek is paused by the operator (2026-11-01); Kimi K2.8 is the only worker model.

## Test ledger

| Suite / command | Last run | Result |
|---|---|---|
| `devflow-validate.py --brief .` (architect probe, P0) | 2026-11-01 | exit 1 · 4 block (V20) · 708 notice · 41 n/a |
| `gh run view 41372953464` (batch-100 deferred CI) | 2026-11-01 | `in_progress`; `tui-ci` pending; `snapshot` success |
| full suite (LAN host) | not-run at P0 | owed before Inc 2's merge |
