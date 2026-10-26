# HANDOFF — batch-99 Increment 3a · review round 1 fixes (code-reviewer F1–F6)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc3a` (branch `b99-inc3a`, base `a52e2be`).
Nothing committed — all changes are in the working tree for the orchestrator.
Contract amendment read from the MAIN checkout per the brief: LLR-155.3 +
LED-2026-10-25-batch-99.7 (the immutability invariant; TC-B99-13 models
concurrent in-app placements; the double-read narrowing is retired).

## What was fixed (F1–F6)

- **F1** `s19_app/tui/workspace.py` — the claim loop treats a name taken by ANY
  type (file, directory or link) as taken: on Windows `os.open(O_CREAT|O_EXCL)`
  against an existing directory raises `PermissionError`, not `FileExistsError`
  (verified empirically on this host), so the `OSError` handler lstat-probes the
  candidate and moves to the next `_<N>`; any OTHER claim or fill `OSError` is
  wrapped in `WorkareaPlacementError` (two new raise sites: claim failure, fill
  failure). No raw `OSError` can reach a caller that catches only
  `WorkareaContainmentError`. New TC-B99-12 arms: directory squat → `_1`;
  forced non-`PermissionError` `OSError` in replace → `WorkareaPlacementError`,
  claim cleaned, no leftovers.
- **F2** `tests/test_b99_staging.py` — TC-B99-13 rewritten per the amended
  LLR-155.3: concurrent threads run `copy_into_workarea` on ONE name (all
  writers place the same `shared.s19` from per-writer source dirs — a
  contention bug in the first rewrite was caught and fixed), identical and
  differing bytes, 20 trials; every returned path holds its own bytes; a
  0-byte target is never reused. The double read was DROPPED from
  `workspace.py` (kept nowhere; the invariant carries race-freeness per
  LED .7); the source comment states this honestly.
- **F3** ONE private helper `workspace._private_stage_dir(workarea_root)`
  (reparse checks for `temp` + `temp/.staging`, then `mkdtemp` under
  `.staging`; failures convert to `WorkareaContainmentError`) is now used by
  all three placement paths: `copy_into_workarea`, `save_patched_image`
  (apply.py), `write_change_document` (io.py). Neither `save_patched_image`
  nor `write_change_document` stages under `temp/` directly anymore. New
  forced-failure arms: junction at `temp` → refused, nothing written through
  it (TC-B99-11 junction arm + TC-B99-44 junction arm; `mklink /J` via
  subprocess on Windows, skip with stated reason if not permitted).
- **F4** New TC-B99-44 drives the converted `io.py` path
  (`write_change_document`, the app-level callers being
  `S19TuiApp._on_check_editor_action`'s `write_doc` arm and `change_service`):
  a mkdtemp spy asserts staging under `temp/.staging`, the placed JSON
  round-trips, per-write staging dirs are removed; plus the junction arm.
  `write_change_document` joined the TC-B99-39 census (the census now also
  binds names assigned from `_private_stage_dir`, the one helper that owns the
  mkdtemp).
- **F5** AT-B99-05 and TC-B99-14 are fully black-box: rail keys (`l`, `6`,
  `s`), clicked inputs/buttons (`#load_path`, `#load_ok`,
  `#patch_entry_*`, `#patch_saveback_*`, `#project_parent_path`,
  `#project_name`, `#save_ok`), typed text (select-all first — the Save
  dialog pre-fills the parent), waits on the painted status (`#log_line_4`)
  or the painted screen (SVG export); assertions read the painted status and
  files on disk. No `load_from_path` / `request_action` / `.value=` /
  patched `set_status`. `red-at_b99_05.txt` re-recorded against the FINAL
  test on the unmodified base `a52e2be` via a scratch `git worktree add`
  (removed afterwards): FAILED with P-15's exact mechanism
  (`FileNotFoundError` on the deleted work copy). Note: this app mounts no
  `ToastRack`, so `notify` has no toast overlay to paint — TC-B99-14's
  notice threshold is observed through the painted status line, which
  carries the identical message text (declared in packet §5).
- **F6** (a) `_handle_save_dialog` removes exactly the project folder THIS
  call created when a placement failure lands after the mkdir
  (`_remove_created_project_dir`, app.py; `shutil` import added);
  (b) the 0-byte-claim risk is declared in packet §5; (c) the stale
  `staging_block` docstring now matches the code (readonly arm = symlink at
  `temp/.staging`); (d) the missing `f` prefix in tests/test_b99_staging.py
  was added; (e) the packet's `green-final.txt` digest corrected to the
  stored bytes' SHA-256.

## Verification state

- GREEN: `tests/test_b99_staging.py` 17 passed (`green-fix-all.txt`);
  re-pinned files 94 passed (`green-fix-repinned.txt`);
  `tests/test_address_census.py` 23 passed (`green-fix-census.txt`);
  `tests/test_changes_apply.py` 41 passed (`green-fix-changes-apply.txt`,
  reverse-census spot check on the `save_patched_image` seam);
  AT-B99-05 8/8 (`stability-at05.txt`). CRLF preserved in every edited
  source (`crlf-fix.txt`).
- RED at base `a52e2be` (scratch worktree, removed): new/changed arms
  6 failed / 2 passed (`red-fix-new-arms.txt`); the 2 arms GREEN at base
  (concurrent TC-B99-13, directory squat) are RED-proved by mutants — base
  had no O_EXCL claim / F2 machinery. `red-at_b99_05.txt` (P-15,
  black-box) and `red-fix-tc14.txt` re-recorded.
- Mutations: 5 fix-round mutants all KILLED and reverted (hashes back to the
  pre-mutation snapshot 20c24f…/f8b132…/b17441…/e41cf7…): shared staging
  (TC-11+39), check-then-copy (TC-12 + corrected concurrent TC-13, both
  arms), re-derived unlink (TC-39 census), no directory handling (F1 arm),
  staging under `temp/` (both junction arms). mut-155.3 (single-read) is
  SUPERSEDED by LED .7 — it is byte-identical to the fixed code; statement
  in `mut-155.3-superseded.txt`.
- Packet `increment-003.md` updated: "Review round 1 fixes" subsection in §1
  and §4 (RED/mutations/caller-census-rebuilt/evidence), §2 file table, §3
  commands, §4 layer table + signed-balance ledger (17 = 12 − 1 + 6), §5
  risks (invariant, F6(b) 0-byte claim, no-ToastRack note), evidence table
  +18 rows, checklist rows. §4b stays `pending — orchestrator`.

## Notes for the orchestrator

1. The Windows directory-squat behavior (PermissionError, not
   FileExistsError) was verified empirically; the F1 arm is GREEN at base
   `a52e2be` because base placement was check-then-copy (its collision path
   handled directories) — the F1 mutant is the arm's RED proof.
2. The concurrent TC-B99-13 arm is GREEN at base (no forced interleaving);
   its RED proof is the check-then-copy mutant (`mut-fix-155.2-tc13-
   concurrent.txt`, both arms FAILED).
3. `project_gather_service.py` was NOT touched (Inc 3b converts it, per the
   brief); it is the declared invariant violator until then.
4. Pre-existing base failures (`test_tc018`, `test_at031b`, `test_tc707` ×2)
   and the `test_tui_patch_editor_v2.py` order-flakiness stand as round 1
   recorded; none is touched by the fixes.
__KIMI_UNIT_DONE__
Files changed: 4 SOURCE (workspace.py — F1 claim/fill wrap + `_private_stage_dir` + double-read retired; changes/apply.py + changes/io.py — stage via the helper; app.py — `_remove_created_project_dir` F6a + shutil) + tests (test_b99_staging.py rewritten/extended 17 nodes, b97_fixtures.py docstring) + packet increment-003.md; CRLF preserved, no commits, scratch worktree removed.
Tests added: 6 new nodes in tests/test_b99_staging.py (TC-B99-11 junction arm, TC-B99-12 ×2 F1 arms, TC-B99-44 ×2 for the io.py path, TC-B99-13 rewritten concurrent) — file total 17 nodes, all GREEN; AT-B99-05/TC-B99-14 rewritten fully black-box.
RED/GREEN: GREEN 17 + 94 + 23 + 41 passed, AT-B99-05 8/8; RED at base a52e2be: 6 failed/2 passed (new arms) + black-box P-15 re-record (red-at_b99_05.txt) + TC-B99-14; all transcripts hash-stored in evidence/inc-3a.
Mutations: 5 fix-round mutants run — all KILLED, all reverted hash-verified (shared staging, check-then-copy ×2 witnesses, re-derived unlink, no-directory-handling F1, temp/ staging F3); round-1 mut-155.3 superseded by LED .7 (double read retired) with a written statement.
Open questions: `project_gather_service.py:290-299` remains the declared invariant violator until Inc 3b; TC-B99-14's notice is observed via the painted status (app mounts no ToastRack — declared in packet §5); the 2 arms GREEN at base are RED-proved by mutants, not by the base tree.
