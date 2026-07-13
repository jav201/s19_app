# fast-dev-flow spec — batch 40 — Small UX fixes

- **Status:** closed 2026-07-13 (AC-1.1..3.1 green; gate 1393 passed / 0 failed / 3 xfailed pre-existing; 0 frozen diffs; no security flags)
- **Created:** 2026-07-13
- **Branch:** `claude/batch-40-small-ux-fixes` @ `fbd8aaa` (= origin/main; RC-1 clean)
- **Route:** /fast-dev-flow (3 small UX polish fixes; each an independent AC)
- **Run mode:** autonomous + self-merge (operator-stated, batch-40 kickoff); decisions recorded in this spec + the closing artifact.
- **security_required:** FALSE — no sensitive patterns fire (state reset, key bindings, display-format only; no untrusted input / auth / secrets / external surface).

## 1. Objective

Close 3 small UX carries from the batch-38 review + the deferred-polish backlog. No new features, no untrusted-text surface. Engine-frozen set untouched.

## 2. User stories

- **S1 — Checks panel refreshes after undo/redo.** As a patch-editor user, after I run Checks and then Undo (or Redo) an edit, I want the Checks results to reflect the restored change-set rather than showing stale results for the pre-undo entries. (batch-38 Inc-4 F1.)
- **S2 — Undo/redo key bindings.** As a patch-editor user, I want `ctrl+z`/`ctrl+y` to undo/redo change-set edits (not only the on-screen buttons, which sit below the entries-pane fold), so the feature is discoverable and reachable without scrolling. (batch-38 Inc-4 F2.)
- **S3 — Clean coverage %.** As a user reading the Memory-Map stats strip, I want the coverage percentage shown to a clean precision (2 decimals, matching the A-view) instead of six noisy decimals. (deferred polish.)

## 3. Out of scope

- The A-01 data-loss guard semantics (undo/redo stay DISABLED for file-loaded docs, `source_path is not None`) — unchanged; the new key bindings MUST respect it.
- Item 6 (A2L-symbol region names + per-cell tooltips, R-TUI-041 R-3) — its own batch (operator, 2026-07-13).
- Any engine-frozen module (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) + frozen TEST files (`_ENGINE_TEST_FILES`) — C-27 dual-guard every increment.

## 4. Acceptance criteria (observable)

**S1 — Checks panel refresh after undo/redo:**
- **AC-1.1:** When a user runs Checks (populating the Checks panel), then edits an entry, then Undo — the Checks panel no longer shows the pre-undo result: either it clears (`last_check_result` reset) or it reflects the restored change-set. Asserted via Pilot: run checks → edit → undo → read the rendered Checks panel and assert it is NOT the stale pre-undo content. RED counterfactual: pre-fix the panel keeps the stale result.
- **AC-1.2:** Same for Redo (redo restores, Checks panel is not stale from the pre-redo state).

**S2 — Undo/redo key bindings:**
- **AC-2.1:** With a paste-authored change-set (`source_path is None`), pressing `ctrl+z` undoes the last edit (restores the prior change-set) and `ctrl+y` redoes it — asserted via real `await pilot.press("ctrl+z")` / `press("ctrl+y")` (C-16 real key), reading the entries table before/after, driving the SAME path as the `#patch_undo_button`/`#patch_redo_button`.
- **AC-2.2 (A-01 guard respected):** with a FILE-loaded change-set (`source_path is not None`), `ctrl+z`/`ctrl+y` are a safe no-op (no mutation, no clobber) — mirrors the button-disabled state. RED/negative: the binding must NOT bypass the A-01 guard.

**S3 — Clean coverage %:**
- **AC-3.1:** The Memory-Map stats strip (`screens_directionb.py:1186`) renders `Coverage: {pct:.2f}%` (2 decimals), not `.6f` — asserted by reading the rendered stats text for a known coverage value (e.g. exactly 2 decimals, no 6-decimal tail). RED counterfactual: pre-fix shows the 6-decimal form.

## 5. Design notes / seams (verified @ fbd8aaa)

- **S1:** `change_service.py` `undo` (:445) / `redo` (:474) reset `last_summary` but NOT `last_check_result` (:357, set at :1255); `app.py:_refresh_patch_history_view` (:1919) refreshes entries + issues + enable-guards but does NOT call `panel.refresh_check_results`. Fix: reset `last_check_result = None` in `undo`/`redo` AND call `refresh_check_results(service.check_rows(), "")` in `_refresh_patch_history_view` (the `refresh_check_results` seam already exists, app.py:1737). Keep the primary entries refresh intact.
- **S2:** app `BINDINGS` (app.py:784). Add `Binding("ctrl+z", "patch_undo", ...)` + `Binding("ctrl+y", "patch_redo", ...)` (show=False or shown). New `action_patch_undo`/`action_patch_redo` on the app that route to the SAME logic the `UndoRequested`/`RedoRequested` handlers use, guarded: no-op unless the patch editor is active AND undo/redo is enabled (`source_path is None` + non-empty stack). Must NOT double-fire or bypass the A-01 guard. *Exact guard/active-screen check — confirm at implementation.*
- **S3:** `screens_directionb.py:1186` `f"Coverage: {stats.coverage_pct:.6f}%  "` → `:.2f` (match `app.py:695`). `coverage_pct` is a float 0-100 (`screens_directionb.py:617`).
- **C-26:** touched symbols to reverse-grep across `tests/`: `last_check_result`, `_refresh_patch_history_view`, `refresh_check_results`, `action_patch_undo`/`action_patch_redo`, the `ctrl+z`/`ctrl+y` bindings, `coverage_pct` `.6f`.

## 6. Security flags (auto-detection)

**security_required: FALSE.** No pattern fires — S1 is in-process state reset, S2 is key bindings over an already-guarded action, S3 is a display-format change. No untrusted input, auth, secrets, external surface, or markup sink. (The A-01 data-loss guard is PRESERVED, not weakened — S2's AC-2.2 asserts it.)

## 7. Increment plan (≤5 files each)

1. **Inc-1 (S1 + S2 — undo/redo polish):** reset `last_check_result` + refresh checks in `_refresh_patch_history_view` (S1); add `ctrl+z`/`ctrl+y` bindings + actions routing to the existing undo/redo path with the A-01 guard (S2). Files: `change_service.py`, `app.py`, + test(s). AC-1.1/1.2 + AC-2.1/2.2.
2. **Inc-2 (S3 — coverage format):** `.6f`→`.2f` at `screens_directionb.py:1186` + AC-3.1 test.

(2 increments; well under the fast-flow ceiling.)
