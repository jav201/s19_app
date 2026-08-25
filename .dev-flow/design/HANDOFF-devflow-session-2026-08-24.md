# Handoff — the living-artifacts programme after batch-86: four flow revs shipped, the trial passed, D-II is the decision that gates surface #3

> ## ⚠ SUPERSEDED 2026-08-24 (post-batch-87) — see [[HANDOFF-devflow-session-2026-08-24-post-batch-87]]
>
> **This document was written BEFORE batch-87.** Its §1, §4, §5 and §6 are now FALSE in named
> ways: D-II is ruled AND discharged, surface #3 (`workspace_body`) shipped, the flow is rev46 not
> rev45, and the six-flaky-node diagnosis recorded in §4 was **refuted by measurement** at batch-87
> P4 (three fail in isolation at N=10; the `n = 1` reading is recorded as vacuous, C-53). It is kept
> unedited as the record of that session — read the successor for current ground.

> **Written 2026-08-24, session "dev-flow updates" (background job, operator Javier).**
> **Re-derive every figure below; if a command disagrees, the command is right** — this
> project has now retired that lesson into four separate controls and this document still
> assumes it is wrong somewhere.
>
> **Reading order:** §0 (verify ground) → §2 (what shipped) → §5 (D-II, the gating
> decision) → §6 (next actions). §3/§4 are reference.

## 0 · Verify the ground before trusting anything here

```bash
cd <repo-root>                                            # C:\Users\jjgh8\Github\s19_app, branch main
python ~/.claude/docs/tools/devflow-validate.py .         # expect: 0 block · 254 notice · 15 n/a
#   V20 line: atlas current (4 files, census 2)
python ~/.claude/docs/tools/devflow-validate.py --selftest # expect exit 0, 192 arms
grep -E "flow_version|flow_hash" ~/.claude/docs/FLOW-VERSION.md | head -2
#   expect 2026.08.24-rev45 · 09bea075fc183f8b — if V7 BLOCKs, someone edited the canon: see rev43/rev45 changelog discipline
conda run -n s19env python -m pytest --collect-only -q -m "not slow" 2>&1 | tail -1
#   expect 2714/2735 collected (21 deselected) — s19env is the GATE ENV (see §4)
git log --oneline -3                                      # this handoff's landing PR at/near the tip
```

## 1 · State at the cut

| | |
|---|---|
| `main` | carries the FULL session: squash `3fbca82` (PR #199: batch-85 pilot record + Atlas design docs + Atlas adoption + batch-86 complete) + `c098541` (PR #200: sync landing + fold retractions) + this handoff's PR |
| flow | **`2026.08.24-rev45`**, `flow_hash 09bea075fc183f8b` — rev42/43/44/45 all shipped TODAY, all pushed to `claude-config` + `agent-skills`, kimi checkout pulled level |
| batch-86 | **CLOSED COMPLETE, merged, vault-synced** (`obsidian_synced: true` verified ON `origin/main`) — first end-to-end batch under the new machinery; its record is the FORMAT EXEMPLAR for every future IFC record |
| PRs | **#198 still OPEN, deliberate, operator's** (batch-83 D4 contradiction). #199/#200 merged |
| vault | `01 - Proyectos/s19_app/dev-flow-batches/2026-08-24-batch-86/` (core light-sync README with Dataview frontmatter). ⚠ batch-85 was never synced (closed unfinished) — a gap, not an error |
| hygiene | worktree `.claude/worktrees/dev-flow-68a67d` still checked out on the MERGED branch `claude/batch-82-lane-a-scoping` — decide keep/remove. **The primary checkout holds ~16 UNTRACKED items of foreign WIP** (a memmap2 prototype with its own HANDOFF, `prototypes/out/*.svg`, `build/`) — another session's work: REPORT, never sweep (C-44; a `git add -A` here already caused one incident this session, caught and force-with-lease-repaired within minutes) |

## 2 · What shipped this session (all pushed)

| Piece | Where |
|---|---|
| **rev42** — `--atlas [--write]` + **V20** digest guard + **D-III ruled** (selector taxonomy S0–S3) + §5.4 discharged synthetically + optional `SURFACE:` field | canon `23fdde6`; design basis frozen BY EXECUTION first: `.dev-flow/design/ATLAS-FIELD-SET-2026-08-23.md` |
| **rev43** — the Atlas must be blind to its own output (`_derived/` excluded from the id scan; found by the FIRST real adoption, minutes after rev42) | canon changelog rev43 |
| **rev44** — coherence rules **V21** (OUTPUT owner, BLOCK) · **V22** (canon-mirror censuses, NOTICE) · **V23** (PDR/DDR citation grammar, NOTICE) | measured first by probes (deleted once superseded); `CANON-CORPUS-AND-COHERENCE-2026-08-23.md` |
| **rev45** — **C-56 "an evidence transcript is corpus input"** (command + template ⚠ + catalog) · P0-scaffold rule · Atlas tokenizer fix (`(?![-.]\w)` — refuse whole, never truncate to a phantom stem) | all three born from batch-86; selftest **192 arms** |
| **D-VII ruled** (hybrid: Atlas DERIVED / canon AUTHORED + coherence) · corpus membership CLOSED (req · TC · validation+evidence · traceability · decisions-succinct · **PDR/DDR with unique traceable ids**) · checklists flow-side · C2/C4 = NOTICE censuses | `DECISION-D-VII-2026-08-23.md` + `CANON-CORPUS-AND-COHERENCE-2026-08-23.md` §4.1 |
| **Canon seeded**: `R-TUI-113` (batch-85 pilot, honest KNOWN-DEFECT status) + `R-TUI-114` (batch-86) — V22 debt **288 → 276**, one BELOW the batch-open baseline | `REQUIREMENTS.md` ~:6027/:6062 |
| **batch-86** — IFC surface #2 (`screen_workspace`, the pilot's undeclared PARENT): **V12 balances the pilot for the first time**; per-surface cost n=2 (dispersion ×2.5–×9, non-extrapolation restated) | `.dev-flow/2026-08-24-batch-86/` — read `05-close.md` §6 for the trial's verdict on the flow itself |

## 3 · Standing operator directives recorded this session

1. **Subagents on Opus 5** — every Agent dispatch passes `model: "opus"` (state.json batch-86 P3 entry + memory).
2. **Batch-86 authorization pattern**: autonomous, gates self-approved WITH evidence, merge granted post-close explicitly. Authorization is per-batch — re-ask at every batch open.
3. Artifact language English for dev-flow; conversation Spanish.

## 4 · Environment facts the next session needs

- **Gate env = conda `s19env`** (Python 3.11.15). This session installed `pytest` + `pytest-textual-snapshot==1.1.0` into it. Anaconda base CANNOT collect the suite (22 pre-existing `tests.conftest` import errors). Candidate: document in `docs/engineering-rules.md`.
- **6 order-dependent flaky nodes** (pre-existing, each passes ISOLATED on pristine `main`; one fails even in a 6-test group but passes alone — cross-test pollution). Ids + repro in batch-86 `04-validation.md` ledger; carried in `BACKLOG-CODE.md` header.
- Probe discipline reminders paid for in blood this session: never pipe a gate run through `tail` (C-19 — evidence destroyed once); pytest FAILED lines carry ANSI codes (a `grep "^FAILED"` silently returns nothing — strip first).

## 5 · D-II — the decision that gates surface #3, with the evidence now complete

**Question:** is the batch-85 pilot record salvageable, or is it re-authored?
**Evidence, all measured, all pointing the same way (re-author):**
1. The pilot's three worst defects are FORMAT failures the batch-86 exemplar has since solved (pair thresholds · split populations · scoped statements) — re-authoring to the exemplar costs less than patching 15 catalogued defects one by one.
2. The pilot's absorbed `owner` (801 chars of glued prose) is **the only IFC item left in the UNPARSED census** — re-authoring clears the census to pure BATCHES entries.
3. Its 4 stray V13 pairs are DUPLICATED verbatim by batch-86's re-export block (D-86-E) — re-authoring the pilot under `screen_workspace`'s already-declared parent boundary removes the duplication.
4. The D-A analysis (atlas handoff §8) already prescribes the shape: SIX outputs, not five — split the heterogeneous row population.
**What D-II does NOT decide:** the pilot's MEASUREMENTS (census, cost figures) stay valid history; re-authoring replaces the CONTRACT, not the record of what was measured.

## 6 · Suggested next actions, in order

1. **Rule D-II** (operator; the evidence above). If re-author: it is a small batch — batch-87 candidate A.
2. **batch-87 candidate B (or the same batch as D-II): surface #3 = `workspace_body`** — chosen by the SAME criterion that picked #2 (it is now the only undeclared PARENT V12 names). Use batch-86's record as the exemplar; expect the flow to run ~1h class, all six stations.
3. **Seeding tranches** of the remaining 276 unreflected ids (V22 aggregate) — per-id greps primary, one id per line (the M7 lesson).
4. **PDR/DDR id rule** — the corpus ruling wants unique, requirement-traceable ids; V23 watches the repo side; the vault-side convention needs its first real PDR to exist before more machinery is worth building.
5. **Test-hygiene batch** for the 6 flaky nodes (order-dependence diagnosis; ids in the backlog).
6. **The Dex Horthy questioning session** (operator-declared pending; vault note with 6 seed questions) — now with a full trial batch as evidence for/against the flow's cost.
7. Housekeeping when convenient: remove or re-point the stale worktree; decide the foreign memmap2 WIP's fate (its own HANDOFF is in `prototypes/`); batch-85 vault sync gap.

## 7 · Session incidents worth remembering (all resolved, all recorded)

- **C-44 self-inflicted**: `git add -A` in the primary checkout swept 126 files of foreign WIP into PR #200's first push; caught immediately, force-with-lease repaired to the 5 intended files, WIP restored untracked. Lesson: explicit adds ONLY in shared checkouts.
- **C-56's origin**: the Inc-1 packet's evidence transcript fed three phantom ids to the Atlas — including the RED-arm's corrupted token; ONE regeneration stood between it and the committed derived plane. The orchestrator then nearly repeated it in the close record. Now a control (rev45).
- The rev42 E2E arm passed spuriously (fixture added no ids to the union) — the vacuous-fixture shape; rev43's SELF-blind arm is the fix, and the same shape recurred in the M7 prediction (+2 not +1) and the agent's /tmp mutant split. **Four instances in one day of "the check that cannot fail": the tax is real and continuous.**
