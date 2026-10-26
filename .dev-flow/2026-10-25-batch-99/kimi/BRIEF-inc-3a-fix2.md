# Kimi brief — batch-99 Increment 3a · review round 2 fixes (security S-F1..F6, code F6a + LOWs)

Read `BRIEF-COMMON.md` first: re-read it from the MAIN checkout (`C:\Users\jjgh8\Github\s19_app\.dev-flow\2026-10-25-batch-99\kimi\BRIEF-COMMON.md`), because it gained a test-id rule. Same worktree, `C:\Users\jjgh8\Github\s19_app-b99-inc3a`. Do not commit.

security-reviewer (round 2) — `changes required`:
- **S-F1 [MEDIUM] — a dangling file symlink at the final name is written through** (`workspace.py:511`): the `O_EXCL` claim followed the link and created a 0-byte file outside the work area, then `os.replace` replaced the link.
  - Fix: `os.lstat` each candidate name before `os.open`, and treat ANY existing entry (file, directory, link, dangling link, junction) as taken, moving to the next `_<N>`.
  - After the claim, `lstat` it again and require a regular file that is not a reparse point. Otherwise remove your claim and raise `WorkareaPlacementError`.
  - TC arm: a dangling symlink at the requested name → placed as `_1`, nothing created at the link's target. Skip with a stated reason if symlink creation is not permitted on this machine.
- **S-F2 [LOW] — the reparse check and `mkdtemp` race** (`workspace.py:324-344`). After `mkdtemp`, `lstat`-recheck both `temp` and `temp/.staging`, and verify `os.path.realpath(new_dir)` is under the work area's real path. Otherwise remove the dir you created and refuse.
- **S-F3 [LOW] — use `lstat`-based checks, not `exists()`** (`workspace.py:324,329`), so a dangling junction is caught by the check itself (LLR-155.1).
- **S-F4 [LOW] — B8 reuse must skip a target that is a link or reparse point** (`workspace.py:502`).
- **S-F5 [LOW] — `_handle_save_dialog`'s "this call created the folder" flag** (`app.py:≈8005`). Use `mkdir(exist_ok=False)`, catch `FileExistsError` (then the folder is not ours), and set the flag only when `mkdir` succeeded.
- **S-F6 [LOW] — an `OSError` from `copy2`** (including a vanished source) is not wrapped (`workspace.py:470`). Wrap it in `WorkareaPlacementError`, with an outcome-first message naming the source.

code-reviewer (round 2) — `OK to advance` with notes:
- **F6a [MEDIUM] — `_remove_created_project_dir` is untested** (`app.py:≈7943`). Add a TC: force a placement failure during Save project → the project folder this call created is gone. Add a second arm: a pre-existing folder of the same name survives untouched (this pairs with S-F5).
- **LOW-1:** TC-B99-13 has no interleaving hook, so its RED came from a mutant hitting `PermissionError`, not from a mismatch count. Give the mutant evidence a real mismatch: add a deterministic barrier/pause hook so the restored check-then-copy mutant shows a nonzero mismatch count.
- **LOW-2:** AT-B99-05 waits for `Saved project to` but asserts `Project saved`. Make the wait and the assertion consistent, and assert again that the painted status names the image file.

Test ids: no new numbers. Sub-arms of existing TCs use `test_tc_b99_NN_<arm>`.

After the fixes:
1. Run `tests/test_b99_staging.py`, the re-pinned files and `tests/test_address_census.py`. Run AT-B99-05 8 times.
2. Re-run the affected mutations, plus a new one for S-F1 (the claim without `lstat` → the dangling-link arm goes RED).
3. Update the packet with a "Review round 2 fixes" subsection.
4. Finish with `HANDOFF-fix2.md`, ending with `__KIMI_UNIT_DONE__` and the 5-line summary.
