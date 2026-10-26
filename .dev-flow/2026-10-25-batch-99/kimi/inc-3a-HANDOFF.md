# HANDOFF — batch-99 Increment 3a (HLR-155, private staging / atomic placement)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc3a` (branch `b99-inc3a`, base `a52e2be`).
Nothing committed — all changes are in the working tree for the orchestrator.

## What is done

- **Implementation (4 SOURCE files, CRLF preserved, syntax clean):**
  - `s19_app/tui/workspace.py` — `copy_into_workarea` rewritten per LLR-155.1/.2/.3:
    reparse checks for `temp` + `temp/.staging`, private `tempfile.mkdtemp` staging,
    `os.open(O_CREAT|O_EXCL|O_WRONLY)` claim (next free `_<N>`), `os.replace` fill with
    ≤5 retries in ≤1 s, 0-byte-never-reused + double-read race-closed B8 reuse,
    staging-home errors converted to `WorkareaContainmentError`; NEW
    `WorkareaPlacementError(WorkareaContainmentError)` with the UX-C4/C5 message;
    NEW `WORKAREA_STAGING_DIRNAME`.
  - `s19_app/tui/changes/apply.py` — `save_patched_image` stages privately; the
    `finally: staged.unlink()` re-derived-name delete (the TC-B99-39 RED site) is gone.
  - `s19_app/tui/changes/io.py` — `write_change_document` (the 14th placement path,
    PDR C2) converted identically through the injected `copy_fn`.
  - `s19_app/tui/app.py` — `_handle_save_dialog`: missing-source pre-flight before the
    project folder is created (failure severity, outcome first, no empty folder, app
    keeps running); `WorkareaPlacementError` painted at failure severity.
- **Tests:** `tests/test_b99_staging.py` (NEW, 12 nodes) — TC-B99-11/12/13/14/39,
  AT-B99-05, AT-B99-04 distinct-name parallel arm (regression guard, no RED claim),
  2 UX-C10 hostile-name TCs. All byte oracles use `tests/support/independent_reader.py`.
  **GREEN: 12 passed** (`green-all.txt`); per-test transcripts saved.
- **RED:** 10 failed / 2 passed at the unmodified tree (`red-all.txt`); TC-B99-12 shows
  the deterministic PQ-8 line `parallel mismatches: 140`; P-15 reproduced
  (`red-at_b99_05.txt`); census RED names `apply.py:779` (`red-tc_b99_39.txt`).
- **Mutations (C-40):** 4 applied, all KILLED, all reverted byte-identically
  (sha256-verified): shared staging (TC-11/39), check-then-copy (TC-12/13),
  no source verify (TC-13), re-derived unlink (TC-39, exact line named).
- **Reverse census** (23 files probed, 2 part-runs + targeted reruns):
  - Re-pinned (requirement-mandated): TC-1800 (`.staging` home persists, per-write
    dirs removed); `staging_block` + TC-B97-58/AT-B97-23 check_write arms (blocker at
    the private staging home after the A2L load; readonly arm is now a reparse point —
    a read-only file can no longer block a writer that never overwrites);
    `EXPECTED_SCANNED_TEST_FILES` 199 → 204 (drift 199→203 pre-exists at base).
  - Source seam fix from the census: staging-home preparation errors now raise
    `WorkareaContainmentError` (were an uncaught-`OSError` crash for app-level callers).
  - Pre-existing at base `a52e2be` (scratch-worktree-verified, NOT re-pinned):
    `test_tc018`, `test_at031b` (deterministic serializer + pre-existing B8 reuse),
    `test_tc707` ×2 (untracked `prototypes/cambios_10_12_2026/help_sections.md` absent
    from this worktree — environment).
  - Flakes under 22-min suite load, not reproduced standalone/on rerun: AT-038c,
    `test_save_back_prompt`, `test_verify_loud_mismatch_notice`, AT-030c/AT-064c/TC-344
    (`test_tui_patch_editor_v2.py` is non-deterministic at base too — disjoint failure
    sets, `baseline-patch-editor-v2-at-HEAD.txt`).
- **Packet:** `.dev-flow/2026-10-25-batch-99/03-increments/increment-003.md` filled
  (§4b left `pending — orchestrator`). PDR C1, C2, PQ-8, UX-C4, UX-C5, UX-C10
  discharged (detailed in packet §6). Caller census with the user-seen-text column is
  in packet §4 (15/15 handled via the subclass).
- Scratch worktree used for HEAD comparisons was removed; no mutants left in place;
  `prototypes/` untouched; no commits made.

## Final verification state

- `pytest tests/test_b99_staging.py tests/test_copy_into_workarea_content_dedup.py tests/test_id_registry.py -q` → **27 passed** (`green-final.txt`).
- Reverse census part 1 rerun: 369 passed (remaining failures = the 2 pre-existing + already-fixed re-pins); part 2: 458 passed, failures analyzed as 2 re-pins (fixed, 10-passed transcript), 2 pre-existing, 4 flakes.
- Worktree-import proof + CRLF counts for all 4 SOURCE files: `import-proof-crlf.txt`.

## Open questions / for the orchestrator

1. `test_tc018` / `test_at031b` fail identically at base `a52e2be` (deterministic
   serialization makes the pre-existing B8 reuse return the same path). They pin
   pre-B8 dedup-by-name semantics — a backlog decision, not an Inc-3a regression.
   Assign to a later increment or accept as declared RED.
2. `test_window_usage_help.py::test_tc707_*` fail because untracked
   `prototypes/cambios_10_12_2026/help_sections.md` is absent from this worktree
   (present in the main checkout). Environment/content issue.
3. `test_tui_patch_editor_v2.py` full-file runs are order-flaky at base and here
   (disjoint failure sets). Watch it in the full-suite run.
4. The `staging_block` readonly arm needs symlink privilege (fails loudly otherwise).
5. The CRC write site (`crc.py:1362`) is the declared single TC-B99-39 census
   exception until Inc 5 converts it (LLR-155.8).
__KIMI_UNIT_DONE__
Files changed: 4 SOURCE (workspace.py, changes/apply.py, changes/io.py, app.py) + 4 re-pinned test files + new tests/test_b99_staging.py + packet increment-003.md; CRLF preserved, no commits.
Tests added: 12 nodes in tests/test_b99_staging.py (TC-B99-11/12/13/14/39, AT-B99-05, AT-B99-04 parallel guard, 2 UX-C10 hostile-name TCs) — GREEN 12 passed (27 passed with the re-pinned files).
RED/GREEN: baseline RED 10 failed/2 passed (deterministic "parallel mismatches: 140", PQ-8); per-test RED and GREEN transcripts with sha256 in evidence/inc-3a.
Mutations: 4 run (shared staging, check-then-copy, no source verify, re-derived unlink) — all KILLED, all reverted byte-identically; PDR C1, C2, PQ-8, UX-C4, UX-C5, UX-C10 discharged.
Open questions: pre-existing at base a52e2be and NOT re-pinned: test_tc018, test_at031b (B8 reuse + deterministic serializer), test_tc707 x2 (untracked prototypes/ file absent in this worktree); test_tui_patch_editor_v2.py is order-flaky at base (disjoint failure sets); CRC write site is the declared census exception until Inc 5.
