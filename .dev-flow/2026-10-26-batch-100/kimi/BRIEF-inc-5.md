# Kimi brief — batch-100 Increment 5 · Save project saves the image you see (PH-1, D1, R-PC)

Read `BRIEF-COMMON.md` first. The orchestrator gives you the worktree and the base commit at launch; the base is `main` with Inc 1–4 merged. Your packet is `.dev-flow/2026-10-26-batch-100/03-increments/increment-005.md`. If it is missing, copy the seed shape from `increment-001.md`.

**This is the largest increment so far, so work in two parts.** At the end of Part A, write `HANDOFF.md` with what is done, then continue. If you run out of time, the orchestrator resumes you from that checkpoint.

**Design authority:** `design/design-proposal-b100.md` §5.5.

**Contract (`01-requirements.md`):**
- HLR-167, LLR-167.1 to LLR-167.8.
- LED .45 (ARCH-PDR-1): `plan_project_save` takes the manifest-key list as an input.
- LED .56 (SEC-4).
- LED .50: unresolved paths; every placement passes `workarea_root`.
- LED .53: the failed-save rollback removes exactly what the save created. The Inc 2 code already does this, and the emit must report its placement into that list.
- PDR-QA-1: `SaveProjectScreen.plan` is a frozen dataclass, read after alt+s. The dialog itself is Inc 11, so here you only build the plan function.
- PDR-QA-2: the `image_differs_from_source` pre-check is only a fast path into the data comparison; it never decides "copy" on its own.

**Interfaces** (`docs/architecture.md` §11):
- Freezes: B100-I5 (as a fast path), I15, I17, I18.
- Consumes: I13, I22.

**SOURCE files (4, ⚠ at cap, LED .56):**
- `s19_app/tui/app.py`
- `s19_app/tui/services/change_service.py`
- `s19_app/tui/services/project_gather_service.py`
- `s19_app/tui/changes/apply.py`

The packet's §2 states why it cannot be smaller: `apply.py` holds the emit's staging, which SEC-4 fixes on the path this increment splits.

## Part A — the split, the emit decision, the saved state

1. **Split in `change_service.py`.**
   - `rederive_for_save(copy) -> (map, summary)` restores the journal on a COPY and applies the current **change** document to it. It never touches the session map.
   - `emit_and_verify(map, ranges, …)` places through `save_patched_image` and verifies.
   - `save_patched` stays their composition plus the in-place view update, so B99-I7 is unchanged.
2. **Emit decision in `app.py`'s Save project.** Re-derive onto a copy and compare the DATA with the source.
   - Emit only when the data differs. Otherwise byte-copy.
   - A check document never counts; it is gathered into `checks/`.
   - A blocked re-derive refuses the whole save and names the blocked entries.
3. **Saved-state record.** `mark_saved` / `differs_from_last_saved` are recorded at load, save-back and Save project. Save project also calls the panel's public `mark_saved` (LLR-167.8). Keep `differs_from_last_saved` (the question and pending line) separate from the source comparison (emit vs copy), per A-08.
4. **SEC-4 in `apply.py`.** `save_patched_image` takes its staging root from `_guarded_destination(dest_dir, workarea_root)` instead of resolving `dest_dir`, and the emit passes `workarea_root`. The emit's placement joins Inc 2's created list (LED .53).
5. **Tests for Part A:** TC-B100-14, -15, -16, -17, -58, -69, -70, plus the SEC-4 arm. The SEC-4 arm: with a junction project open, a save-back leaves 0 entries in the other work area.

**Checkpoint:** write `HANDOFF.md` before starting Part B.

## Part B — the save plan, and the AT

6. **`plan_project_save(...) -> SavePlan`** in `project_gather_service.py`. It is a frozen dataclass:
   - one row per top-level file, one per sub-folder with its file count, plus `project.json`;
   - each row carries a landing name from `predict_placement` and an action word (new / replace / keep / merge / rewrite);
   - it takes the manifest-key list and the digests the app computed as inputs, so the service gains no `changes` import.
7. **`_handle_save_dialog` executes the plan.** It checks each landed `PlacementResult` against its row; a mismatch is an error that names both paths.
8. **Tests for Part B:**
   - TC-B100-59, Inc 5 rows only: fresh, pending patch, refused. The rows for Inc 7 (`files`), 8a (document, merge) and 8b (save-as) come later.
   - AT-B100-05, black-box: a pending patch, then Save project by keys through the CURRENT dialog, then reopen. The reopened image equals the patched one by `independent_reader`.

**RED must be behavioural at base:**
- P-1: `== in-memory patched image? False`.
- P-37 / P-38 for the emit rule.
- The SEC-4 probe from `03-increments/security-increment-001.md` Round 2.

**Mutations:** follow §5.5's table, plus SEC-4 (staging resolves `dest_dir` again → RED).

**Reverse census:** `grep -rln "save_patched\|_handle_save_dialog\|gather_project_artifacts\|save_patched_image\|mark_saved" tests/ --include=*.py`. Snapshot cells must not change; if one does, STOP.

**Lessons from Inc 1–4** (`03-increments/review-increment-00*.md`):
- RED is behavioural, never a missing module.
- Test scenarios must SET every state they claim to check.
- Polling, never a single pause.
- Every §2 row carries a closed-six `Kind` and a real LLR/HLR `Traces to`.
- Evidence uses full repo paths, so `devflow-evidence --check` matches.
- Transcript headers name the command, the tree, `PYTHONPATH` and `NO_COLOR`.

Finish with the guards (`guards.txt`, `guards-census.txt`) and packet §1–§7 (§4b `pending — orchestrator`). End `HANDOFF.md` with `__KIMI_UNIT_DONE__` and the 5-line summary.
