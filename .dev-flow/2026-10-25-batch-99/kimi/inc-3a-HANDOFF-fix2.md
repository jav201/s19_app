# HANDOFF — batch-99 Increment 3a · review round 2 fixes (security S-F1..F6, code F6a + LOWs)

Worktree: `C:\Users\jjgh8\Github\s19_app-b99-inc3a` (branch `b99-inc3a`,
round-1-fixed working tree on `a52e2be`). Nothing committed — all changes
are in the working tree for the orchestrator.

## What was fixed

**Security (S-F1..S-F6) — `s19_app/tui/workspace.py` + `s19_app/tui/app.py`:**
- **S-F1 [MEDIUM]** the claim loop now `os.lstat`s each candidate BEFORE the
  `O_EXCL` claim — on Windows `os.open(O_CREAT|O_EXCL)` FOLLOWS a dangling
  symlink (verified empirically on this host: the bare claim created a
  0-byte file at the link's target outside the work area and `os.replace`
  then replaced the link). ANY existing entry (file, directory, link,
  dangling link or junction) is taken → next `_<N>`. After the claim the
  name is re-verified with `os.lstat` to be a regular file and no reparse
  point, else the claim is removed and `WorkareaPlacementError` raised.
  New TC-B99-12 arm: dangling symlink at the requested name → placed as
  `_1`, link and its target untouched. (Symlinks ARE permitted on this
  host — no skip needed.)
- **S-F2 [LOW]** `_private_stage_dir` now re-checks both `temp` and
  `temp/.staging` with lstat after `mkdtemp` and requires
  `os.path.realpath(new_dir)` to stay under the work area's real path;
  otherwise the created directory is removed and the write refused.
- **S-F3 [LOW]** the staging checks are `lstat`-based, not `exists()`-based,
  so a dangling junction is caught by the check itself and the refusal
  names the reparse point (before: the refusal came from the mkdir fallback
  with a generic message). New TC-B99-11 arm pins the message.
- **S-F4 [LOW]** B8 byte-identical reuse never returns a target that is a
  link or reparse point; such a target is skipped for dedup and counts as
  taken. New TC-B99-13 arm.
- **S-F5 [LOW]** `_handle_save_dialog`'s "this call created the folder"
  flag now comes from `mkdir(parents=True, exist_ok=False)` +
  `FileExistsError` — set only when the mkdir succeeded — instead of a
  racy `not exists()` probe.
- **S-F6 [LOW]** an `OSError` from the staging `copy2` (including a
  source that vanishes after the size check) is wrapped in
  `WorkareaPlacementError`, outcome first, naming the source. New TC-B99-12
  arm.

**Code (F6a + LOWs) — `tests/test_b99_staging.py`:**
- **F6a [MEDIUM]** `_remove_created_project_dir` is now tested through the
  real Save-project dialogs: arm 1 forces a placement failure after this
  call created the folder → the folder is gone, painted status leads with
  the outcome, app running; arm 2 pre-creates a folder with operator
  content and forces the same failure → the folder and its sentinel
  survive (pairs with S-F5). Both GREEN at the round-1 tree — the
  machinery landed with round 1 — so their RED proofs are the F6a and S-F5
  mutants.
- **LOW-1** TC-B99-13 gained the deterministic pause-on-shared-name hook
  (same idiom as TC-B99-12), so the restored check-then-copy mutant
  evidence carries real NONZERO mismatch counts: `parallel mismatches: 35`
  (TC-B99-12) and `68` (TC-B99-13) in `mut-fix2-155.2-check-then-copy.txt`.
- **LOW-2** AT-B99-05's wait and assertion are now consistent: the test
  waits for the final painted line (`Project saved…`) and reads the
  four-line painted log (`#log_line_1..4`) for the superseded
  `Saved project to … (variant 'firmware')` line, asserting the painted
  status names the image file. Root cause of the old inconsistency: the
  intermediate line is superseded within one tick, so the old "wait for
  `Saved project to`" silently timed out 200 pauses and the assertion
  passed only by accident on the second read. Viewport widened to 260x54
  so the success line is not clipped in the log strip.

## Verification state

- RED at the round-1 tree (final tests): 4 new arms FAILED with declared
  mechanisms (`red-fix2-new-arms.txt`; full-file intermediate state
  `red-fix2-full.txt`). The F6a arms + AT-B99-05 are GREEN at that tree by
  design (mutant RED proofs).
- GREEN: staging file **23 passed** (`green-fix2-staging.txt`); re-pinned
  files **94 passed** + address census **23 passed** + AT-B99-05 **8/8**
  (`green-fix2-repinned-census-at05.txt`); reverse-census batch **341
  passed / 4 failed** (`green-fix2-reverse-census.txt`) — the 4: 3
  environmental pins (`test_tc031_*`/`test_tc032_*` diff the frozen engine
  against the LOCAL `main` ref, which has already advanced to batch-99
  inc-9 `725d474` and changed `core.py`/`hexfile.py`/`a2l.py` between this
  worktree's base and `main` — no engine file is touched here) + 1
  documented pre-existing (`test_tc018`).
- Mutations: **6/6 KILLED, all reverted** — restores verified by SHA-256
  against `mut-fix2-pre-snapshot.txt` (workspace.py `c933f7…`, app.py
  `8bdc82…`): S-F1 (pre-claim lstat removed), S-F6 (copy2 unwrap), 155.2
  re-run (O_EXCL dropped), F3 re-run (`_private_stage_dir` bypassed, all
  three junction arms RED), F6a (cleanup no-op), S-F5 (flag forced True).
- CRLF pure on all four SOURCE files (`crlf-fix2.txt`). No commits.
- Packet `increment-003.md`: "Review round 2 fixes" subsections in §1 and
  §4, §2/§3/§5/§6 updates, signed-balance ledger `23 = 17 − 0 + 6`,
  reverse-census + caller-census notes, checklist rows 4/5/11/16, 14 new
  evidence rows with digests (61 total). §4b stays `pending —
  orchestrator`.

## Notes for the orchestrator

1. The two F6a arms and AT-B99-05 (LOW-2) are GREEN at the round-1 tree;
   their RED proofs are mutants, not the base tree — stated in the packet.
2. The 3 directionb failures are environmental (advanced local `main`
   ref), not regressions — evidence in the packet's reverse-census note.
3. `project_gather_service.py` remains the declared invariant violator
   until Inc 3b (unchanged).
__KIMI_UNIT_DONE__
Files changed: 2 SOURCE (workspace.py — S-F1 claim lstat+recheck, S-F2 post-mkdtemp verify, S-F3 lstat staging checks, S-F4 dedup skip, S-F6 copy2 wrap; app.py — S-F5 mkdir/flag) + tests/test_b99_staging.py (6 new arms, TC-B99-13 hook, AT-B99-05 LOW-2) + packet increment-003.md; CRLF preserved, no commits.
Tests added: 6 new nodes (TC-B99-11 dangling junction, TC-B99-12 dangling symlink + vanished source, TC-B99-13 symlink-target skip, TC-B99-14 ×2 F6a/S-F5) — file total 23 nodes, all GREEN; AT-B99-05 and TC-B99-13 modified in place (LOW-2/LOW-1).
RED/GREEN: GREEN 23 + 94 + 23 + 341 (4 env/pre-existing failures) and AT-B99-05 8/8; RED at round-1 tree: 4 new arms with declared mechanisms (2 TC arms GREEN-at-tree by design, mutant-proved).
Mutations: 6 fix2 mutants — all KILLED, all reverted hash-verified (S-F1, S-F6, 155.2 re-run with mismatches 35/68, F3+S-F2+S-F3 re-run, F6a, S-F5); none left in place.
Open questions: 3 directionb engine-pin failures are environmental (local main at inc-9, worktree base a52e2be) — flagged for the full-suite run; F6a/AT-B99-05 RED-proof rests on mutants since the behavior pre-dates round 2; §4b independent review pending the orchestrator.
