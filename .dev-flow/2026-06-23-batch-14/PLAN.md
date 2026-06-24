# PLAN — s19_app — batch-14 (living compendium)

**Batch:** 2026-06-23-batch-14 · **Language:** en · **Worktree:** inspiring-payne-8d5395 (off main incl. batch-13 PRs #18/#19)

## Where we are
**Phase 3 — Inc 1 implemented, awaiting gate.** US-015 only (US-016 satisfied in main §20). Inc1 = emitter+S0 data layer: 4 files, code-reviewer APPROVE (0 HIGH), ledger 903→916, full non-slow 863/0, 0 frozen edits. Amendment B (RATIFY): "S0 adds 0 addresses" was false (get_memory_map folds all records) → oracle uses data-record-only map; integrity preserved. Next: Inc2 (save-flow wiring + {16,32} selector UI) on Inc1 approval.

## Objective
Cluster 1 (data fidelity / correctness):
- **US-015** — S19 emitter gains a 16/32 data-bytes-per-record selector (**default 32**) + a populated S0 header in 32-byte mode, wired through the TUI save flows.
- **US-016** — fix the A↔B compare false "no diff" for absolute-path inputs (`_diff_load_maps` swallows a re-load failure → empty maps) + harden the suite at the shipped surface.

## Per-story / per-phase status
| Item | Phase 0 | Notes |
|------|---------|-------|
| US-015 | READY | default 32 / surface=TUI saves / values {16,32} decided; header-capture feasibility = Phase-1 verify |
| US-016 | READY | diagnose→fix→regression at shipped handler; synthetic repro decided |

## Key decisions (operator)
1. Batch-14 = Cluster 1 only; legend features (Q1/Q2) → batch-15.
2. S19 default bytes-per-line → **32** (16 becomes opt-in). ⚠ flips every test asserting 16-byte emission — Phase-1 blast-radius budget.
3. Selector surface → **TUI save flows** (patch-editor save-back + project save); CLI unchanged.
4. A2B test-escape → add through-shipped-surface regression + encode a `/dev-flow` directive (global config, outside repo).

## Risks / watch-items
- **R1** Header preservation: `emit_s19_from_mem_map` has no header metadata; `core.py::S19File` is engine-frozen. Capture at load seam or synthesize — verify Phase 1.
- **R2** Default 16→32 flip: test blast-radius (e.g. `test_emit_s19_reparses_to_equal_mem_map`). Enumerate Phase 1.
- **R3** US-016 root cause assumed at `_diff_load_maps:2151` — confirm by repro before fixing.

## Conventions honored
- Engine-frozen set untouched (emit in `tui/changes/io.py`, compare fix in `app.py` — both outside).
- ≤5 files/increment; code-reviewer per gate; reader-as-oracle for emitted S19.
- b12 controls: consumer-input-contract citations (emit call-sites, CompareRequested) + facade/test blast-radius budget.

## Out-of-scope carries
Q1/Q2 legend; US-A/B/C/D/H/J/I/K (batch-15+); CLI format flags; S1/S2 forcing; resolve_input_path abs-path-not-found rework.

## Test ledger
Baseline: **903 collected** (re-measured on current `origin/main` 9169130; was 894 on stale main — +9 from batch-15 + PR#21 ATs). US-016 already satisfied in main §20 (no duplicate). US-015 confirmed unbuilt; 16→32 flip blast radius still nil.

## Decision log (human mirror of state.json)
- 2026-06-23 — batch-14 opened (Phase 0). Batch-13 confirmed merged (PRs #18/#19); its closing state snapshotted to `.dev-flow/2026-06-17-batch-13/state-snapshot-at-close.json`. 5 parallel Explore investigations grounded all functional-testing observations + answered Q1–Q4. Operator picked Cluster 1; legend → batch-15; BPL default 32; surface = TUI saves. US-015 + US-016 classified READY. Awaiting Phase-0 DoR gate.
