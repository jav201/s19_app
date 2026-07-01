# PLAN.md — batch-21 (living compendium)

> **#8 Patch-editor overhaul** (P1, largest open feature). **Scope-first Phase 0: decompose before any code.**
> Updated at every gate. Operator reads THIS. Inline-paste-at-gates protocol (worktree not editor-rooted).

## Where we are
- **Phase 6 — Documentation.** `awaiting-gate`. 06-docs (matrix/functionality/diagrams/exec-summary) written; REQUIREMENTS §27 added; BACKLOG refreshed (#8 slice-1 DONE, US-030 next); C-14 encoded (operator-approved Phase 5). Next: operator approval → commit/PR/sync.
- Phase 5 — Post-mortem `approved` (C-14 encoded). Phase 4 `approved` (953/0 fail). Phase 3 COMPLETE (974→985 +11). Phases 0-2 approved.
- Phase 2 — Cross-review `approved` (0 blockers; temp→root correction folded). Phase 1/0 `approved`.
- **Process correction (batch-21):** no hollow "approve or iterate?" at gates — resolved axis assessment + call; iterate only with a named gap ([[feedback_no_hollow_iterate_at_gates]]). Hooks: artifact-completeness reject-check → spawned task_2d3e38b5 (pre-commit hook); iterate-prose rule stays command+memory (not hook-enforceable).

## Test ledger (collected non-slow)
- Base (origin/main ec3a2a7): batch-20 closed 974.
- **Inc1: 974 → 977 (+3)** — TC-031 + AT-031a/b; 2 pre-existing e2e globs fixed in-place (net 0). 0 fail. Frozen 0.
- **Inc2: 977 → 983 (+6)** — AT-030a(+R2) / AT-030b / AT-030c / TC-030 / F1-symlink. 951 passed / 0 fail (post-F1-fold confirmed). Frozen 0.
- **Inc3: 983 → 985 (+2)** — AT-032a / AT-032b. 953 passed / 0 fail. Frozen 0.
- **Phase-3 total: 974 → 985 (+11)** across 3 increments (Inc1 +3, Inc2 +6, Inc3 +2). Frozen 0 throughout.
- NOTE: local `main` is stale (818a02b); use `git diff origin/main` for the true batch-21 diff.

## Carries
- **Post-mortem lesson:** Phase-2 supersession census missed 2 e2e placement globs (keyed on white-box tc018, not e2e save-observers). software-dev caught+fixed.
- N1 (LOW): pre-existing `write_change_document` docstring says "later increment" — stale, future touch.

## Roadmap / increment plan (Phase-1)
- **Inc1 — HLR-031 US-027 folder** (`workspace.py` + `changes/io.py`): `WORKAREA_PATCHES="patches"` + placement inside `write_change_document`. AT-031a/b.
- **Inc2 — HLR-030 US-026 dropdown** (`screens_directionb.py` + `app.py`, consumes Inc1): `Select(id=patch_doc_file_select)` + `set_change_files()` + scan `patches/*.json` + reuse `service.load`. AT-030a (C-12 gate)/030b/030c.
- **Inc3 — HLR-032 US-029 clarity** (`screens_directionb.py` + `styles.tcss`): description Label "Checks: runs the loaded change document's checks against the loaded image." AT-032a/b.

## Key decisions (Phase-1)
- Folder = GLOBAL `.s19tool/workarea/patches/` (save path already global; per-project deferred). Route placement inside `write_change_document` (zero call-site churn). US-029 = description Label row (not verbose button label → no geometry risk).

## Batch-21 scope (operator DoR)
- **IN:** US-026 (change-file dropdown) + US-027 (dedicated workarea folder). **US-029** (Checks clarity) READY — inclusion pending gate confirm.
- **DEFERRED:** US-028 (variant dropdown), US-030 (4-pane split, geometry SPIKE → own batch), US-031 (snapshots).

## Decomposition (spike-verified)
- **US-026 change-file dropdown** (Tier-1, NET-NEW, low) · **US-027 dedicated workarea folder** (MODIFY workspace.py) — coupled = "change-file management" slice.
- **US-028 inline variant dropdown** (Tier-1, NET-NEW, low, independent).
- **US-029 Checks-button fix** — REFINE (no bug found; needs observed-defect from operator).
- **US-030 4-pane split** — SPIKE (measure host width @80/120 first; depends on 026/027/028). **US-031 snapshots** — OUT (follows 030).
- **Recommended batch-21 slice:** US-026+US-027 (+ optionally US-028). Defer the geometry-heavy 4-pane split (030/031) to its own batch.

## Objective
Overhaul the patch editor. Candidate sub-features (BACKLOG #8): (1) 4-pane split of `PatchEditorPanel` (currently a single `ScrollableContainer` @`screens_directionb.py:335`); (2) change-file default `changes.json`; (3) change-file dropdown; (4) dedicated workarea folder; (5) variant dropdown; (6) Checks-button fix. **High blast radius — likely spans multiple batches.** Phase 0 decomposes into stories; operator selects the batch-21 slice.

## RC-1 base-currency gate (batch-21 open) — PASS
- `git fetch` → `origin/main` = **ec3a2a7** (batch-20 PR #32 merged).
- branch ff'd `45be027 → ec3a2a7` (HEAD == origin/main tip) → derive against latest tree. Clean.
- batch-20 closing state snapshotted to `state-snapshot-at-close.json` (rides batch-21 first commit).
- Per-story already-shipped checks: deferred to post-decomposition (per candidate story).

## Risks / watch-items (pre-spike)
- **C-13 geometry is THE central risk** — a 4-pane split must budget each pane at 80 AND 120 cols at draft time (don't assume the single-container width transfers). C-13.1 deficit-matched fallback for overflow. This is exactly the batch-17/18 failure class.
- **High blast radius / multi-batch** — resist pulling all 6 sub-features into one batch. Pick the smallest viable coherent slice.
- **Engine-frozen OFF-LIMITS**; TUI-side write logic → `tui/changes/io.py`. `screens_directionb.py` is editable.
- Worktree-not-editor-root → inline-paste at gates.

## Decomposition (pending spike)
- TBD — Explore maps current state → candidate stories with INVEST/DoR → operator picks scope.

## Test ledger
- Base (origin/main ec3a2a7): batch-20 closed at 974 collected non-slow; confirm exact base at Phase-3 entry. Reuse harness `tests/test_tui_patch_editor_v2.py` (`_write_v2_document`).
- R1 watch: a `tests/` test may assert the old `temp/` write path → updates in Inc1 (fail-loud).

## Decision log
- 2026-06-29 P0: batch-21 init, #8 scope, RC-1 PASS (ec3a2a7), decomposition spike dispatched.
